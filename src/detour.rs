//! Installing a detour over *live* code: decode what is there, move it into a
//! stub, and branch.
//!
//! This is the crate's headline verb, and the thing that cannot be written
//! without a decoder. Patching a four-byte branch over an arbitrary address is
//! four ways wrong, and every one of them is silent:
//!
//! 1. **It cuts an instruction in half.** Four bytes at a site holding a 16-bit
//!    instruction followed by a 32-bit one destroys the first halfword of the
//!    second, and what executes afterwards is whatever the surviving halfword
//!    happens to mean. [`detour`] decodes forward from the site until at least
//!    four bytes are covered, so the displaced region is instruction-aligned by
//!    construction and is 4 *or 6* bytes, never 4-and-a-bit.
//! 2. **It moves an instruction out from under its `IT`.** The 1–4 instructions
//!    after an `IT` are conditional with nothing in their own encoding to say
//!    so (ARM DDI 0403E.e A7.3.2), so a displaced one runs *unconditionally* in
//!    the stub. Nothing about the bytes looks wrong. [`detour`] tracks
//!    `ITSTATE` through [`Decoder`] and refuses.
//! 3. **It relocates a pc-relative instruction as a byte copy.** A displaced
//!    branch or literal load means something different at its new address; see
//!    [`crate::relocate`], which this module is built on.
//! 4. **It half-applies.** A patch that writes a stub and then discovers the
//!    branch is out of range has corrupted an image that it also reports as
//!    unpatched. Every fallible step here happens before the first byte is
//!    written — see [Atomicity](#atomicity).
//!
//! # Worked example
//!
//! ```
//! use thumb_asm::detour::tramp;
//! use thumb_asm::{decode_bl, isa};
//!
//! // A flat image: code at 0x100, erased flash from 0x200 on.
//! let mut image = vec![0u8; 0x400];
//! for b in image[0x200..].iter_mut() {
//!     *b = 0xff;
//! }
//! // movs r0, #1 · movs r1, #2
//! image[0x100..0x104].copy_from_slice(&[0x01, 0x20, 0x02, 0x21]);
//!
//! let d = tramp(&mut image, 0x100, 0x80).unwrap();
//! assert_eq!(d.displaced, 4); // two 16-bit instructions, neither cut in half
//! assert_eq!(d.stub, 0x200); // the first 4-aligned free space
//! assert_eq!(decode_bl(&image, 0x100), Some(0x200)); // the site now calls it
//!
//! // And the stub: call the hook, re-run what was displaced, branch back.
//! assert_eq!(
//!     isa::disassemble(&image, d.stub as usize, d.stub, 4),
//!     [
//!         "00000200: bl 0x80",
//!         "00000204: movs r0, #1",
//!         "00000206: movs r1, #2",
//!         "00000208: b.w 0x104",
//!     ]
//! );
//! ```
//!
//! # Atomicity
//!
//! [`detour`] either applies completely or does not touch `image`. Everything
//! fallible — decoding, the IT checks, relocating every displaced instruction,
//! encoding all three branches, the free-space search, every bounds check —
//! happens in a planning phase that takes `&[u8]`. Only then are the two writes
//! issued, and neither *can* fail: the stub bytes are already built and already
//! known to fit, and the hook branch is four already-encoded bytes going into
//! four already-bounds-checked ones. There is no fallible step left to report,
//! which is why [`detour`] has no "the write went wrong" error: a write to a
//! `&mut [u8]` that does not land is not a thing this crate can be handed.
//!
//! The stub is written *first*, deliberately, and that still matters even
//! though neither write can fail: the two are separate stores, and a consumer
//! that flashes them incrementally — or dies between them — leaves an image
//! with an unreferenced blob in free space and an untouched site, which is
//! functionally unmodified. The other order would leave a live branch into
//! free space.
//!
//! # What this module cannot see
//!
//! * **An `IT` before the site.** Thumb cannot be decoded backwards, so by
//!   default the IT state *entering* the site is assumed inactive. Give
//!   [`DetourOptions::scan_from`] a known instruction boundary at or before the
//!   site and it is checked instead of assumed — which also catches a site that
//!   is not an instruction boundary at all.
//! * **A branch into the displaced region.** If some other instruction branches
//!   to `site + 2`, it now lands inside the installed branch. Finding that needs
//!   a whole-image control-flow pass, not a local decode.
//! * **A displaced literal load.** Its pool does not move and is almost never
//!   within ±1020 (or ±4095) bytes of free space, so it is refused rather than
//!   silently mis-pointed. See [`crate::relocate::Widen`].

use crate::isa::{Decoder, Insn};
use crate::relocate::{relocate_bytes, RelocateError, Widen};

/// How far `plan` walks when asking whether the condition flags are dead.
///
/// The walk stops early at the first branch or flag-clobbering instruction,
/// so this only bounds the pathological case of a long straight line that
/// touches no flags. Sixteen instructions is well past the point where a
/// `CBZ`'s flags could plausibly still matter, and the answer when the budget
/// runs out is "live", which refuses rather than rewrites.
const FLAG_WALK_LIMIT: usize = 16;
use crate::{encode_b_wide, encode_bl, BranchKind};

/// `push {lr}` — `PUSH` T1 with `M == 1` and an empty register list
/// (A7.7.101). One register is the minimum T1 allows.
const PUSH_LR: [u8; 2] = [0x00, 0xb5];

/// `ldr lr, [sp], #4` — `LDR (immediate)` T4 post-indexed, `P == 0`, `U == 1`,
/// `W == 1` (A7.7.43).
///
/// The counterpart to [`PUSH_LR`], and *not* `pop.w {lr}`: `POP` T2 makes a
/// register list of fewer than two registers UNPREDICTABLE (A7.7.99), so the
/// obvious pairing has no defined behaviour.
const LDR_LR_POP: [u8; 4] = [0x5d, 0xf8, 0x04, 0xeb];

/// `ldr.w r12, [pc, #4]` — `LDR (literal)` T2, `U == 1`, `Rt == r12`
/// (A7.7.44).
///
/// Reads the word at `Align(stub + 4, 4) + 4`, which is `stub + 8` because
/// every stub this module places is 4-byte aligned. The narrow literal form
/// cannot be used: its `Rt` field is three bits and cannot name `r12`.
const LDR_IP_CONTINUATION: [u8; 4] = [0xdf, 0xf8, 0x04, 0xc0];

/// `nop` — `NOP` T1 (A7.7.88), used only as alignment padding.
const NOP: [u8; 2] = [0x00, 0xbf];

/// Where [`Convention::HookDecides`] puts the continuation word, relative to
/// the start of the stub.
const CONTINUATION_WORD: usize = 8;

/// An installed detour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detour {
    /// File offset the hook branch was written at.
    pub site: usize,
    /// How many bytes at `site` the branch overwrote — always the length of a
    /// whole number of instructions, so 4 or 6, never 5.
    pub displaced: usize,
    /// Address of the stub, which is 4-byte aligned.
    pub stub: u32,
    /// Length of the stub in bytes.
    pub stub_len: usize,
    /// Which branch was installed at `site`; decides whether `lr` survived.
    pub kind: BranchKind,
}

impl Detour {
    /// The address the stub branches back to: the first instruction after the
    /// displaced region.
    pub fn resume(&self) -> u32 {
        (self.site + self.displaced) as u32
    }
}

/// Where the displaced code runs, and so what the hook is able to decide.
///
/// Both conventions re-execute the displaced instructions somewhere; the
/// difference is whether the hook gets a say.
///
/// # Registers
///
/// | convention | site branch | stub clobbers | `lr` seen by the hook |
/// |---|---|---|---|
/// | [`CallThenContinue`](Self::CallThenContinue) | [`BranchKind::Bl`] | `lr` (by the site branch) | `stub + 4`, i.e. back into the stub |
/// | [`CallThenContinue`](Self::CallThenContinue) | [`BranchKind::BWide`] | nothing — `lr` is saved and restored | the stub's `bl` return address |
/// | [`HookDecides`](Self::HookDecides) | [`BranchKind::BWide`] | `r12` | the *outer* function's return address |
/// | [`HookDecides`](Self::HookDecides) | [`BranchKind::Bl`] | `r12`, `lr` | `site + 4` — **inside the displaced region** |
///
/// The last row is a trap, and is the reason the table is here:
/// [`HookDecides`](Self::HookDecides) exists so the hook can return early
/// instead of running the original, and `lr` is how it would do that. Pair it
/// with [`BranchKind::BWide`].
///
/// Beyond that, neither convention saves any general-purpose register. The hook
/// is responsible for preserving whatever the displaced instructions and the
/// resumed function need — which at an arbitrary firmware site is more than
/// AAPCS requires, because `r0`–`r3` may well be live. That is deliberate: a
/// stub that saved and restored `r0`–`r3` would also make it impossible for a
/// hook to *change* them, which is most of the point of hooking a gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Convention {
    /// **Call the hook, then continue.** The ordinary detour, and the default.
    ///
    /// ```text
    /// stub:  push {lr}            ; only when the site branch preserved lr
    ///        bl   hook            ; the hook runs and returns here
    ///        ldr  lr, [sp], #4    ; ditto
    ///        <the displaced instructions, relocated>
    ///        b.w  site + displaced
    /// ```
    ///
    /// The hook is a plain function: it is called, it returns, and the original
    /// code then runs exactly as it would have. It cannot skip the original —
    /// use [`HookDecides`](Self::HookDecides) for that.
    ///
    /// The `lr` save appears only for [`BranchKind::BWide`], where `lr` is
    /// still the outer function's return address and the stub's own `bl` would
    /// destroy it. With [`BranchKind::Bl`] the site branch has already
    /// overwritten `lr`, so saving it would preserve nothing and cost two stack
    /// accesses.
    CallThenContinue,
    /// **The hook replaces the site and is told where to continue.**
    ///
    /// ```text
    /// stub:  ldr.w r12, [pc, #4]  ; r12 = continuation, with the Thumb bit set
    ///        b.w   hook           ; a jump, not a call: lr is untouched
    ///        .word continuation|1
    /// continuation:
    ///        <the displaced instructions, relocated>
    ///        b.w  site + displaced
    /// ```
    ///
    /// The hook is entered with the site's own register state, `r12` pointing
    /// at the displaced code, and `lr` untouched. It can `bx r12` to run the
    /// original and carry on, `bx lr` to return from the function without
    /// running it, or anything else — which is why this is the convention for a
    /// gate whose answer is "deny".
    HookDecides,
}

/// What the stub does with the instructions the patch displaced.
///
/// The two are genuinely different operations, not two spellings of one, which
/// is why the discarding variant says so in its name: an enum arm called
/// `JumpTo` reads like a destination choice and hides that the site's original
/// instructions stop running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DetourStyle {
    /// Relocate the displaced instructions into the stub and continue at
    /// `site + displaced`, so the patched function behaves as it did plus the
    /// hook. The default, and the only safe choice when you do not know what
    /// the displaced instructions were for.
    ResumeAfter,
    /// **Discard the displaced instructions** and branch to `to` instead.
    ///
    /// The instructions the patch overwrote are not relocated and never run.
    /// That is the point — this is the shape for replacing an OEM routine's
    /// entry with your own decision and tail-calling somewhere chosen
    /// (`ramp_exit`, `deny`, an alternate implementation) — but it means the
    /// original behaviour at the site is gone, and the crate cannot check that
    /// you meant it. Nothing else in this crate discards instructions.
    ///
    /// `to` is an absolute address with the Thumb bit ignored, as everywhere
    /// else here, and must be within `b.w` range of the stub.
    DiscardAndJumpTo(u32),
}

/// How to install a detour.
///
/// `#[non_exhaustive]`, so construct it through [`DetourOptions::new`] and the
/// `with_*` chain rather than a struct literal. That is what makes a new
/// option — like [`DetourOptions::with_style`], added in 0.11.0 — an addition
/// rather than a breaking change for everyone who wrote a literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DetourOptions {
    /// Which four-byte branch to install at the site. [`BranchKind::Bl`] by
    /// default, because a hook that wants to be called is the common case;
    /// [`BranchKind::BWide`] preserves `lr`, which is what a tail-call site
    /// needs (see [`crate::encode_b_wide`]).
    pub kind: BranchKind,
    /// Where the displaced code runs. [`Convention::CallThenContinue`] by
    /// default.
    pub convention: Convention,
    /// What happens to the displaced instructions. See [`DetourStyle`].
    pub style: DetourStyle,
    /// Byte offset to start the free-space search from. `0` by default.
    pub search_start: usize,
    /// Place the stub at this address instead of searching. Must be 4-byte
    /// aligned. For a consumer with its own allocator — one that knows which
    /// erased regions the image's checksum table actually covers, say — this is
    /// the hook to use; the built-in search only knows about runs of `0xff`.
    pub stub_at: Option<u32>,
    /// Rewrite a displaced `CBZ`/`CBNZ` as `CMP` + `B<cond>.W` when — and
    /// only when — every condition flag is provably dead at its original
    /// site.
    ///
    /// Off by default, because it is a behaviour change: `CBZ` writes no
    /// flags and `CMP` writes all four, so the rewrite is sound only where
    /// nothing observes them. With it off, a displaced `CBZ` that cannot
    /// reach its target is refused, which is what this crate did before.
    ///
    /// Turning it on does not make the rewrite unconditional. Liveness is
    /// computed from the image at the original site, across *both* the
    /// fall-through and the taken path, and a site where any flag survives is
    /// still refused — with [`RelocateError::FlagsLive`] naming which. Expect
    /// that to be `V` alone surprisingly often: every `S`-suffixed logical and
    /// shift operation writes N, Z and C and leaves V, so a nearby `ANDS`
    /// kills three of the four and looks as though it killed all of them.
    ///
    /// [`RelocateError::FlagsLive`]: crate::relocate::RelocateError::FlagsLive
    pub rewrite_compare_branches: bool,
    /// A known instruction boundary at or before the site, to decode from.
    ///
    /// Without it, the IT state entering the site is *assumed* inactive, and
    /// the site is *assumed* to be an instruction boundary — neither of which
    /// can be checked from the site alone, because a Thumb stream cannot be
    /// decoded backwards. With it, both are checked, and a site that is inside
    /// an IT block or in the middle of a 32-bit instruction is refused. Worth
    /// supplying whenever a function entry point is known.
    pub scan_from: Option<usize>,
}

impl Default for DetourOptions {
    fn default() -> Self {
        DetourOptions {
            kind: BranchKind::Bl,
            convention: Convention::CallThenContinue,
            style: DetourStyle::ResumeAfter,
            search_start: 0,
            stub_at: None,
            rewrite_compare_branches: false,
            scan_from: None,
        }
    }
}

impl DetourOptions {
    /// The defaults: a `BL` at the site, call-then-continue, search from 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set [`rewrite_compare_branches`](Self::rewrite_compare_branches).
    pub fn with_compare_branch_rewriting(mut self, yes: bool) -> Self {
        self.rewrite_compare_branches = yes;
        self
    }

    /// Set [`kind`](Self::kind).
    pub fn with_kind(mut self, kind: BranchKind) -> Self {
        self.kind = kind;
        self
    }

    /// Set [`convention`](Self::convention).
    pub fn with_convention(mut self, convention: Convention) -> Self {
        self.convention = convention;
        self
    }

    /// Choose what becomes of the displaced instructions.
    ///
    /// [`DetourStyle::DiscardAndJumpTo`] throws them away; read its
    /// documentation before using it.
    pub fn with_style(mut self, style: DetourStyle) -> Self {
        self.style = style;
        self
    }

    /// Set [`search_start`](Self::search_start).
    pub fn with_search_start(mut self, search_start: usize) -> Self {
        self.search_start = search_start;
        self
    }

    /// Set [`stub_at`](Self::stub_at).
    pub fn with_stub_at(mut self, stub: u32) -> Self {
        self.stub_at = Some(stub);
        self
    }

    /// Set [`scan_from`](Self::scan_from).
    pub fn with_scan_from(mut self, at: usize) -> Self {
        self.scan_from = Some(at);
        self
    }
}

/// Why a detour could not be installed.
///
/// Every variant carries the offsets involved and has a stable
/// [`reason`](Self::reason) string, for the same reason
/// [`RelocateError::reason`] does: a consumer deciding whether to fall back to
/// a hand-written stub should not have to parse prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DetourError {
    /// There are not four bytes at the site to put a branch in.
    OutOfBounds {
        /// The site that was asked for.
        site: usize,
        /// How many bytes were needed there.
        need: usize,
        /// The image's length.
        len: usize,
    },
    /// The decoder could not make an instruction of the bytes at this offset,
    /// so there is no way to know where the displaced region ends.
    Undecodable {
        /// Offset the decode stopped at.
        at: usize,
    },
    /// [`DetourOptions::scan_from`] is after the site, so it cannot be a
    /// starting point for reaching it.
    ScanStartAfterSite {
        /// The offset given.
        scan_from: usize,
        /// The site.
        site: usize,
    },
    /// Decoding from [`DetourOptions::scan_from`] steps *over* the site: it is
    /// in the middle of a 32-bit instruction, not at an instruction boundary.
    ///
    /// A branch installed there would leave the leading halfword of that
    /// instruction in place, and the result is not a patch, it is rubble.
    SiteNotAligned {
        /// The site.
        site: usize,
        /// Where the decode began.
        scan_from: usize,
    },
    /// The site is itself inside an IT block, so the instruction being
    /// displaced is conditional and the hook branch would not be.
    ///
    /// Only detectable when [`DetourOptions::scan_from`] is supplied.
    SiteInItBlock {
        /// The site.
        site: usize,
    },
    /// The displaced region ends inside an IT block: an `IT` at or before its
    /// end governs at least one instruction after it.
    ///
    /// Moving a governed instruction into the stub strips its condition — it
    /// has none of its own (A7.3.2) — so it would execute unconditionally
    /// there, and the instructions left behind would be governed by an `IT`
    /// that is no longer in front of them. This is the failure mode only a
    /// decoder that tracks `ITSTATE` can see.
    SplitsItBlock {
        /// The site.
        site: usize,
        /// How many bytes the displaced region covers.
        displaced: usize,
    },
    /// One of the displaced instructions cannot be moved. The wrapped
    /// [`RelocateError`] says why, and
    /// [`RelocateError::is_address_dependent`] says whether another stub
    /// address could help.
    Relocate {
        /// Address of the instruction that could not be moved.
        at: u32,
        /// The refusal.
        source: RelocateError,
    },
    /// No run of erased (`0xff`) bytes long enough for the stub, at or after
    /// [`DetourOptions::search_start`].
    NoFreeSpace {
        /// How many bytes were needed.
        need: usize,
    },
    /// [`DetourOptions::stub_at`] is not 4-byte aligned.
    ///
    /// The literal-pool arithmetic every stub layout here depends on is based
    /// on `Align(PC,4)`, and [`crate::Asm`] documents the same requirement.
    StubMisaligned {
        /// The address given.
        stub: u32,
    },
    /// The stub would be written over the site it is meant to be reached from.
    ///
    /// Only possible when the site is itself inside a run of erased bytes, or
    /// when [`DetourOptions::stub_at`] points at live code. Both write the stub
    /// and then overwrite part of it with the hook branch, which is a patch that
    /// cannot be detected afterwards by reading either location.
    StubOverlapsSite {
        /// The stub address.
        stub: u32,
        /// The site it overlaps.
        site: usize,
    },
    /// The stub does not fit in the image at the address chosen for it.
    StubOutOfBounds {
        /// The stub address.
        stub: u32,
        /// The stub's length.
        need: usize,
        /// The image's length.
        len: usize,
    },
    /// The four bytes at the site cannot encode a branch that reaches the
    /// stub — the two are more than ±16 MB apart.
    SiteUnreachable {
        /// The site.
        site: usize,
        /// The stub it could not reach.
        stub: u32,
        /// The branch kind that was tried.
        kind: BranchKind,
    },
    /// The stub cannot reach the hook.
    HookUnreachable {
        /// Address of the branch inside the stub.
        from: u32,
        /// The hook it could not reach.
        hook: u32,
    },
    /// The stub's tail branch cannot reach the instruction after the displaced
    /// region.
    ResumeUnreachable {
        /// Address of the tail branch.
        from: u32,
        /// The address it could not reach.
        resume: u32,
    },
}

impl DetourError {
    /// A stable, machine-readable reason: `"out-of-bounds"`, `"undecodable"`,
    /// `"scan-start-after-site"`, `"site-not-aligned"`, `"site-in-it-block"`,
    /// `"splits-it-block"`, `"relocate"`, `"no-free-space"`,
    /// `"stub-misaligned"`, `"stub-out-of-bounds"`, `"stub-overlaps-site"`,
    /// `"site-unreachable"`, `"hook-unreachable"`, `"resume-unreachable"`.
    pub fn reason(&self) -> &'static str {
        match self {
            DetourError::OutOfBounds { .. } => "out-of-bounds",
            DetourError::Undecodable { .. } => "undecodable",
            DetourError::ScanStartAfterSite { .. } => "scan-start-after-site",
            DetourError::SiteNotAligned { .. } => "site-not-aligned",
            DetourError::SiteInItBlock { .. } => "site-in-it-block",
            DetourError::SplitsItBlock { .. } => "splits-it-block",
            DetourError::Relocate { .. } => "relocate",
            DetourError::NoFreeSpace { .. } => "no-free-space",
            DetourError::StubMisaligned { .. } => "stub-misaligned",
            DetourError::StubOverlapsSite { .. } => "stub-overlaps-site",
            DetourError::StubOutOfBounds { .. } => "stub-out-of-bounds",
            DetourError::SiteUnreachable { .. } => "site-unreachable",
            DetourError::HookUnreachable { .. } => "hook-unreachable",
            DetourError::ResumeUnreachable { .. } => "resume-unreachable",
        }
    }

    /// Whether a different stub address could succeed where this one did not,
    /// which is what the free-space search uses to decide whether to keep
    /// looking.
    fn retryable(&self) -> bool {
        matches!(
            self,
            DetourError::StubOverlapsSite { .. }
                | DetourError::StubOutOfBounds { .. }
                | DetourError::SiteUnreachable { .. }
                | DetourError::HookUnreachable { .. }
                | DetourError::ResumeUnreachable { .. }
        ) || matches!(
            self,
            DetourError::Relocate { source, .. } if source.is_address_dependent()
        )
    }
}

impl core::fmt::Display for DetourError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            DetourError::OutOfBounds { site, need, len } => write!(
                f,
                "detour at {site:#x}: needs {need} bytes, image is {len:#x} long"
            ),
            DetourError::Undecodable { at } => {
                write!(f, "detour: no instruction decodes at {at:#x}")
            }
            DetourError::ScanStartAfterSite { scan_from, site } => write!(
                f,
                "detour at {site:#x}: scan_from {scan_from:#x} is past the site"
            ),
            DetourError::SiteNotAligned { site, scan_from } => write!(
                f,
                "detour at {site:#x}: decoding from {scan_from:#x} steps over it, \
                 so it is not an instruction boundary"
            ),
            DetourError::SiteInItBlock { site } => {
                write!(f, "detour at {site:#x}: the site is inside an IT block")
            }
            DetourError::SplitsItBlock { site, displaced } => write!(
                f,
                "detour at {site:#x}: the {displaced} displaced bytes end inside an IT block"
            ),
            DetourError::Relocate { at, source } => {
                write!(f, "detour: displaced instruction at {at:#x}: {source}")
            }
            DetourError::NoFreeSpace { need } => {
                write!(f, "detour: no free run of {need} bytes for the stub")
            }
            DetourError::StubMisaligned { stub } => {
                write!(f, "detour: stub address {stub:#x} is not 4-byte aligned")
            }
            DetourError::StubOverlapsSite { stub, site } => write!(
                f,
                "detour: a stub at {stub:#x} would overwrite the site at {site:#x}"
            ),
            DetourError::StubOutOfBounds { stub, need, len } => write!(
                f,
                "detour: a {need}-byte stub at {stub:#x} does not fit in {len:#x} bytes"
            ),
            DetourError::SiteUnreachable { site, stub, kind } => write!(
                f,
                "detour at {site:#x}: no {kind} reaches the stub at {stub:#x}"
            ),
            DetourError::HookUnreachable { from, hook } => {
                write!(
                    f,
                    "detour: no branch from {from:#x} reaches the hook {hook:#x}"
                )
            }
            DetourError::ResumeUnreachable { from, resume } => write!(
                f,
                "detour: no b.w from {from:#x} reaches the resume point {resume:#x}"
            ),
        }
    }
}

impl std::error::Error for DetourError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DetourError::Relocate { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Install a detour at `site` that runs `hook`.
///
/// The whole operation: decode what is at `site`, refuse if moving it would
/// break an IT block, find aligned free space, build a stub holding the
/// relocated displaced instructions and a branch back, write the stub, and
/// write the four-byte hook branch over the site. The branch is the same one
/// [`crate::install_branch`] would install — [`crate::verify_branch`] confirms
/// it — but it is encoded during planning, so that installing it is a store
/// and not a step that can fail.
///
/// `hook`'s bit 0 is masked off, so a Thumb-bit-carrying function pointer may
/// be passed directly, exactly as with [`crate::install_branch`].
///
/// Atomic: on any error `image` is byte-for-byte unchanged. See
/// [Atomicity](self#atomicity) for why, and [`DetourOptions`] for the choices —
/// in particular [`Convention`], whose documentation has the register-clobber
/// table.
///
/// ```
/// use thumb_asm::detour::{detour, Convention, DetourOptions};
/// use thumb_asm::{decode_b_wide, BranchKind};
///
/// let mut image = vec![0u8; 0x400];
/// for b in image[0x200..].iter_mut() {
///     *b = 0xff;
/// }
/// image[0x100..0x104].copy_from_slice(&[0x01, 0x20, 0x02, 0x21]);
///
/// // A tail-call site: `lr` must survive, so jump rather than call, and let
/// // the hook decide whether the original runs at all.
/// let opts = DetourOptions::new()
///     .with_kind(BranchKind::BWide)
///     .with_convention(Convention::HookDecides);
/// let d = detour(&mut image, 0x100, 0x80, opts).unwrap();
///
/// assert_eq!(decode_b_wide(&image, 0x100), Some(d.stub));
/// // r12 is loaded with the continuation, Thumb bit set.
/// assert_eq!(thumb_asm::read_u32(&image, d.stub as usize + 8), d.stub + 12 + 1);
/// ```
pub fn detour(
    image: &mut [u8],
    site: usize,
    hook: u32,
    opts: DetourOptions,
) -> Result<Detour, DetourError> {
    let plan = plan(image, site, hook & !1, &opts, None)?;
    Ok(commit(image, site, plan, &opts))
}

/// Write a decided [`Plan`] into the image.
///
/// Two stores of bytes that are already decided, into ranges that are already
/// bounds-checked. Nothing here can fail and nothing here decides anything,
/// which is the whole reason [`plan`] takes `&[u8]` and this takes
/// `&mut [u8]`. The stub goes first so that a half-applied *flash* — this
/// crate's images are firmware — leaves a functionally unmodified image
/// rather than a site branching into blank space.
fn commit(image: &mut [u8], site: usize, plan: Plan, opts: &DetourOptions) -> Detour {
    crate::write(image, plan.stub as usize, &plan.bytes);
    crate::write(image, site, &plan.hook_branch);
    debug_assert_eq!(
        opts.kind.decode(image, site),
        Some(plan.stub),
        "the site must read back as the branch that was planned"
    );

    Detour {
        site,
        displaced: plan.displaced,
        stub: plan.stub,
        stub_len: plan.bytes.len(),
        kind: opts.kind,
    }
}

/// The two-argument detour: `BL` at the site, call the hook, then run the
/// displaced code and continue.
///
/// Equivalent to [`detour`] with [`DetourOptions::default`], and the form to
/// reach for when the site is an ordinary instruction inside a function and the
/// hook is an ordinary function. When the site is a tail call, or the hook needs
/// to be able to skip the original, say so with [`DetourOptions`].
///
/// ```
/// use thumb_asm::detour::tramp;
/// use thumb_asm::{verify_branch, BranchKind};
///
/// let mut image = vec![0u8; 0x400];
/// for b in image[0x200..].iter_mut() {
///     *b = 0xff;
/// }
/// image[0x100..0x104].copy_from_slice(&[0x01, 0x20, 0x02, 0x21]);
///
/// let d = tramp(&mut image, 0x100, 0x80).unwrap();
/// assert_eq!((d.displaced, d.kind), (4, BranchKind::Bl));
/// assert!(verify_branch(&image, d.site, d.kind, d.stub).is_ok());
/// assert_eq!(d.resume(), 0x104);
/// ```
pub fn tramp(image: &mut [u8], site: usize, hook: u32) -> Result<Detour, DetourError> {
    detour(image, site, hook, DetourOptions::default())
}

/// [`detour`], with the stub confined to regions the caller says are writable.
///
/// The built-in search only knows about runs of `0xff`, which is a guess about
/// what is erased and says nothing about what is *safe to write* — a run
/// inside a region a checksum covers, or inside a block the bootloader
/// rewrites, looks identical to one that is genuinely spare. `within` is the
/// caller's answer to that, in image coordinates, and the stub is placed only
/// inside it.
///
/// This exists rather than a `DetourOptions` field because the option struct
/// would need a lifetime parameter to hold a borrowed slice, and because the
/// regions describe the *call*, not a default.
///
/// # Why not just allocate and pass `stub_at`
///
/// Because [`stub_at`](DetourOptions::stub_at) is one attempt with no retry.
/// A stub is only usable if the branch at the site reaches it, and whether it
/// does is not knowable until the whole patch is laid out; when it does not,
/// this keeps searching the remaining regions, exactly as the whole-image
/// search keeps walking runs. A caller doing its own
/// [`FreeSpace::alloc`](crate::FreeSpace::alloc) and passing the result gets
/// one shot, and a [`DetourError::SiteUnreachable`] it has to unpick itself.
///
/// ```
/// use thumb_asm::detour::{detour_in, DetourOptions};
/// use thumb_asm::Fit;
///
/// let mut image = vec![0u8; 0x400];
/// // A `push {r4, lr}` at the site, so there is something to displace.
/// image[0x100..0x104].copy_from_slice(&[0x10, 0xb5, 0x00, 0xbf]);
/// // Only the tail of the image is ours to write.
/// for b in image[0x200..].iter_mut() {
///     *b = 0xff;
/// }
/// let region = 0x200usize..0x400;
/// let regions = core::slice::from_ref(&region);
/// let d = detour_in(
///     &mut image,
///     0x100,
///     0x300,
///     regions,
///     Fit::First,
///     DetourOptions::default(),
/// )
/// .unwrap();
/// assert!((0x200..0x400).contains(&(d.stub as usize)));
/// ```
pub fn detour_in(
    image: &mut [u8],
    site: usize,
    hook: u32,
    within: &[core::ops::Range<usize>],
    fit: crate::Fit,
    opts: DetourOptions,
) -> Result<Detour, DetourError> {
    let plan = plan(image, site, hook & !1, &opts, Some((within, fit)))?;
    Ok(commit(image, site, plan, &opts))
}

/// Everything [`detour`] needs to know before it writes anything — including
/// both blocks of bytes, so that committing is two stores and no decisions.
struct Plan {
    stub: u32,
    bytes: Vec<u8>,
    /// The already-encoded hook branch for the site. Kept rather than
    /// re-encoded at commit time, because [`attempt`] had to encode it anyway
    /// to know it reaches, and because a commit that cannot fail is what makes
    /// [`detour`] atomic.
    hook_branch: [u8; 4],
    displaced: usize,
}

/// The read-only half of [`detour`]: decide the whole patch, touching nothing.
fn plan(
    image: &[u8],
    site: usize,
    hook: u32,
    opts: &DetourOptions,
    within: Option<(&[core::ops::Range<usize>], crate::Fit)>,
) -> Result<Plan, DetourError> {
    // The hook branch is four bytes wide whichever kind it is.
    if site.checked_add(4).map_or(true, |end| end > image.len()) {
        return Err(DetourError::OutOfBounds {
            site,
            need: 4,
            len: image.len(),
        });
    }

    let insns = displaced_at(image, site, opts.scan_from)?;
    // Liveness is measured here, against the image, at each instruction's
    // original address — the only place it can be. Once an instruction is
    // moved into the stub it has no successors yet, so the question "are the
    // flags dead after this" has no answer there.
    //
    // `addr` is the file offset in this crate's flat model, which is what
    // makes indexing the image by it correct.
    let live: Vec<crate::flags::Flags> = if opts.rewrite_compare_branches {
        insns
            .iter()
            .map(|i| {
                crate::flags::live_after(
                    image,
                    i.addr as usize,
                    crate::isa::Target::Union,
                    FLAG_WALK_LIMIT,
                )
            })
            .collect()
    } else {
        // Not asked for, so not computed: the walk is not free and its answer
        // would go unused. `ALL` is the conservative filler.
        vec![crate::flags::Flags::ALL; insns.len()]
    };
    let displaced: usize = insns.iter().map(|i| i.len()).sum();
    let resume = (site + displaced) as u32;

    if let Some(stub) = opts.stub_at {
        return attempt(
            image, site, hook, stub, &insns, &live, resume, displaced, opts,
        );
    }

    // The search has to ask for a size before the stub is laid out, and the
    // layout depends on the address it is laid out at — so ask for the worst
    // case: the longest prologue, two bytes of alignment padding, every
    // displaced instruction widened to four bytes, and the tail branch.
    // Whatever is left over stays erased.
    let need = prologue_len(opts) + 2 + 4 * insns.len() + 4;

    // `align` of 4, because every stub layout in this module — and
    // [`crate::Asm::finish`] — computes literal offsets against `Align(PC,4)`,
    // which matches a buffer-relative layout only at a word-aligned load
    // address. A misaligned stub is not diagnosed anywhere downstream: it
    // simply reads the wrong constants. Note that [`crate::find_free_space`]
    // tests an *aligned window* rather than aligning a run after finding it, so
    // asking for alignment here costs no reachable free space.
    let mut last: Option<DetourError> = None;
    let mut from = opts.search_start;
    // When the caller has said which regions are writable, the search is
    // confined to them and walks them in turn, exactly as the whole-image
    // search walks runs. The retry is the point: a stub that is out of branch
    // range from the first usable run may be in range from the next, and a
    // caller doing its own `FreeSpace::alloc` and passing `stub_at` gets one
    // attempt and no second chance.
    while let Some(found) = match within {
        Some((regions, fit)) => {
            let rest: Vec<core::ops::Range<usize>> = regions
                .iter()
                .filter_map(|r| {
                    let start = r.start.max(from);
                    if start < r.end {
                        Some(start..r.end)
                    } else {
                        None
                    }
                })
                .collect();
            if rest.is_empty() {
                None
            } else {
                crate::find_free_space_in(image, need, 4, &rest, fit)
            }
        }
        None => crate::find_free_space(image, need, 4, from),
    } {
        match attempt(
            image,
            site,
            hook,
            found as u32,
            &insns,
            &live,
            resume,
            displaced,
            opts,
        ) {
            Ok(plan) => return Ok(plan),
            // A branch that does not reach from *this* free run may reach from
            // the next one, so keep looking; a `cbz` that cannot be relocated
            // never will be, so do not.
            Err(e) if e.retryable() => {
                last = Some(e);
                from = end_of_run(image, found);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or(DetourError::NoFreeSpace { need }))
}

/// Try to build the whole patch with the stub at `stub`.
#[allow(clippy::too_many_arguments)]
fn attempt(
    image: &[u8],
    site: usize,
    hook: u32,
    stub: u32,
    insns: &[Insn],
    live: &[crate::flags::Flags],
    resume: u32,
    displaced: usize,
    opts: &DetourOptions,
) -> Result<Plan, DetourError> {
    if stub % 4 != 0 {
        return Err(DetourError::StubMisaligned { stub });
    }
    let bytes = build_stub(stub, insns, live, hook, resume, site, image.len(), opts)?;
    // The commit writes the stub and then the hook branch. If the two overlap,
    // the second write lands inside the first and the result is neither.
    let stub_end = (stub as usize).saturating_add(bytes.len());
    if (stub as usize) < site + displaced && site < stub_end {
        return Err(DetourError::StubOverlapsSite { stub, site });
    }
    if stub_end > image.len() {
        return Err(DetourError::StubOutOfBounds {
            stub,
            need: bytes.len(),
            len: image.len(),
        });
    }
    // Encoded here, not at commit time, because that is what makes the commit
    // phase infallible — and the bytes are kept rather than thrown away and
    // recomputed.
    let hook_branch = match opts.kind.encode(site, stub) {
        Some(bytes) => bytes,
        None => {
            return Err(DetourError::SiteUnreachable {
                site,
                stub,
                kind: opts.kind,
            })
        }
    };
    Ok(Plan {
        stub,
        bytes,
        hook_branch,
        displaced,
    })
}

/// The instructions the hook branch would overwrite, decoded in order.
///
/// Decoding forward until four bytes are covered is what makes the displaced
/// region instruction-aligned: it comes out 4 bytes (two 16-bit instructions,
/// or one 32-bit one) or 6 bytes (a 16-bit instruction followed by a 32-bit
/// one), and never cuts the second in half.
fn displaced_at(
    image: &[u8],
    site: usize,
    scan_from: Option<usize>,
) -> Result<Vec<Insn>, DetourError> {
    let start = scan_from.unwrap_or(site);
    if start > site {
        return Err(DetourError::ScanStartAfterSite {
            scan_from: start,
            site,
        });
    }

    let mut d = Decoder::at(image, start, start as u32);
    while d.pos() < site {
        if d.next().is_none() {
            return Err(DetourError::Undecodable { at: d.pos() });
        }
    }
    // A 32-bit instruction straddling the site is the reason this is `!=` and
    // not `>`: the decode lands at site + 2, never *on* the site.
    if d.pos() != site {
        return Err(DetourError::SiteNotAligned {
            site,
            scan_from: start,
        });
    }
    if d.it_state().active() {
        return Err(DetourError::SiteInItBlock { site });
    }

    let mut insns = Vec::new();
    while d.pos() < site + 4 {
        match d.next() {
            Some(insn) => insns.push(insn),
            None => return Err(DetourError::Undecodable { at: d.pos() }),
        }
    }
    // `ITSTATE` still live at the end of the displaced region means an `IT`
    // inside it governs instructions outside it. A *whole* IT block inside the
    // region is fine — it moves with its governed instructions — and lands
    // here with the state already advanced to inactive.
    if d.it_state().active() {
        return Err(DetourError::SplitsItBlock {
            site,
            displaced: d.pos() - site,
        });
    }
    Ok(insns)
}

/// The stub's fixed-size prologue, before any alignment padding.
fn prologue_len(opts: &DetourOptions) -> usize {
    match opts.convention {
        Convention::CallThenContinue => match opts.kind {
            // `bl hook` only: the site's own `bl` already destroyed `lr`.
            BranchKind::Bl => 4,
            // `push {lr}` · `bl hook` · `ldr lr, [sp], #4`.
            BranchKind::BWide => 10,
        },
        // `ldr.w r12, [pc, #4]` · `b.w hook` · the continuation word.
        Convention::HookDecides => 12,
    }
}

/// Assemble the stub that would live at `stub`.
#[allow(clippy::too_many_arguments)]
fn build_stub(
    stub: u32,
    insns: &[Insn],
    live: &[crate::flags::Flags],
    hook: u32,
    resume: u32,
    site: usize,
    image_len: usize,
    opts: &DetourOptions,
) -> Result<Vec<u8>, DetourError> {
    let mut out: Vec<u8> = Vec::new();
    // The running address of the byte after `out`. Every intermediate stub
    // address is `stub + out.len()`, and `stub` is the caller's `stub_at`, so
    // that add can overflow `u32` for a value near the top of memory — which
    // this crate's `offset == address` model already forbids, but a decoder
    // must refuse rather than panic. `attempt`'s `stub_end > image.len()`
    // check catches an oversized stub, but only after this function has run,
    // so the arithmetic here has to be total on its own.
    let addr = |len: usize| -> Result<u32, DetourError> {
        u32::try_from(len)
            .ok()
            .and_then(|l| stub.checked_add(l))
            .ok_or(DetourError::StubOutOfBounds {
                stub,
                need: len,
                len: image_len,
            })
    };
    let save_lr = opts.convention == Convention::CallThenContinue && opts.kind == BranchKind::BWide;

    match opts.convention {
        Convention::CallThenContinue => {
            if save_lr {
                out.extend_from_slice(&PUSH_LR);
            }
            // `out.len()` here is 0, or 2 with the optional `PUSH`, and `stub`
            // is 4-aligned (`attempt` rejects a misaligned one), so this sum
            // is at most `0xFFFF_FFFE` and cannot overflow — unlike the sites
            // below, whose offset depends on the displaced block, which is why
            // only they need `addr`.
            let at = stub + out.len() as u32;
            let call = encode_bl(at as usize, hook)
                .ok_or(DetourError::HookUnreachable { from: at, hook })?;
            out.extend_from_slice(&call);
            if save_lr {
                out.extend_from_slice(&LDR_LR_POP);
            }
        }
        Convention::HookDecides => {
            out.extend_from_slice(&LDR_IP_CONTINUATION);
            let at = addr(out.len())?;
            let jump = encode_b_wide(at as usize, hook)
                .ok_or(DetourError::HookUnreachable { from: at, hook })?;
            out.extend_from_slice(&jump);
            // The continuation address is not known until the padding below is
            // decided, so reserve the word and fill it in after.
            out.extend_from_slice(&[0; 4]);
        }
    }

    // Land the displaced block at the same address mod 4 it had at the site.
    //
    // `Align(PC,4)` is the base of every pc-relative literal access, and it is
    // 4-aligned while an instruction address is only 2-aligned — so moving an
    // instruction across a word boundary shifts its literal displacement by
    // four, and moving it *within* one does not shift it at all. Preserving the
    // site's alignment is therefore free and keeps the displacement of any
    // displaced `adr` or literal load exactly as it was, up to the constant
    // offset between stub and site. Two bytes of `nop` buy that.
    if (stub as usize).wrapping_add(out.len()) % 4 != site % 4 {
        out.extend_from_slice(&NOP);
    }

    let body = addr(out.len())?;
    if opts.convention == Convention::HookDecides {
        // Thumb bit set: the hook reaches this with `bx r12`.
        let word = (body | 1).to_le_bytes();
        out[CONTINUATION_WORD..CONTINUATION_WORD + 4].copy_from_slice(&word);
    }

    // Where the stub goes when the hook is done, and whether the displaced
    // instructions travel with it.
    let destination = match opts.style {
        DetourStyle::ResumeAfter => resume,
        DetourStyle::DiscardAndJumpTo(to) => to & !1,
    };

    // One forward pass. Widening instruction *n* moves only the instructions
    // after it, and those have not been placed yet — so no second pass and no
    // fixed point.
    //
    // Skipped entirely under `DiscardAndJumpTo`: the displaced instructions
    // are deliberately not carried into the stub, which is the whole of the
    // difference between the two styles.
    let mut at = body;
    if opts.style == DetourStyle::ResumeAfter {
        for (i, insn) in insns.iter().enumerate() {
            let bytes = match relocate_bytes(insn, at, Widen::IfNeeded) {
                Ok(b) => b,
                // A `CBZ`/`CBNZ` that cannot reach its target is the one
                // refusal a rewrite can answer — but only where the flags it
                // would clobber are dead. `live[i]` was measured at the
                // *original* site, which is the only place the question can be
                // asked: once moved, the instruction has no successors yet.
                Err(RelocateError::ForwardOnlyBranch { .. }) if opts.rewrite_compare_branches => {
                    crate::relocate::widen_compare_branch(
                        insn,
                        at,
                        live.get(i).copied().unwrap_or(crate::flags::Flags::ALL),
                    )
                    .map_err(|source| DetourError::Relocate {
                        at: insn.addr,
                        source,
                    })?
                }
                Err(source) => {
                    return Err(DetourError::Relocate {
                        at: insn.addr,
                        source,
                    })
                }
            };
            at = at.wrapping_add(bytes.len() as u32);
            out.extend_from_slice(&bytes);
        }
    }

    let tail = encode_b_wide(at as usize, destination).ok_or(DetourError::ResumeUnreachable {
        from: at,
        resume: destination,
    })?;
    out.extend_from_slice(&tail);
    Ok(out)
}

/// One past the last erased byte of the run containing `from`, and always
/// greater than `from`, so a search that walks runs terminates.
fn end_of_run(image: &[u8], from: usize) -> usize {
    let tail = &image[from.min(image.len())..];
    let n = tail.iter().position(|&b| b != 0xff).unwrap_or(tail.len());
    from + n.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::{self, Insn};
    use crate::{decode_b_wide, decode_bl, read_u32, verify_branch, Cond};

    /// Where the synthetic images below put their code, their erased flash and
    /// their hook.
    const SITE: usize = 0x100;
    const FREE: usize = 0x1000;
    const HOOK: u32 = 0x80;
    const LEN: usize = 0x2000;

    /// An image with `code` at [`SITE`] and erased flash from [`FREE`] on.
    fn image_with(code: &[u8]) -> Vec<u8> {
        let mut image = vec![0u8; LEN];
        for b in image[FREE..].iter_mut() {
            *b = 0xff;
        }
        image[SITE..SITE + code.len()].copy_from_slice(code);
        image
    }

    /// Every instruction in the stub, in order.
    fn walk(image: &[u8], d: &Detour) -> Vec<Insn> {
        Decoder::at(image, d.stub as usize, d.stub)
            .take_while(|i| (i.addr as usize) < d.stub as usize + d.stub_len)
            .collect()
    }

    /// The stub, disassembled.
    fn text(image: &[u8], d: &Detour) -> Vec<String> {
        walk(image, d).iter().map(|i| i.to_string()).collect()
    }

    // ----------------------------------------------- the displaced region

    /// Two 16-bit instructions: four bytes, two instructions, nothing cut.
    #[test]
    fn a_displaced_region_of_two_narrow_instructions() {
        // movs r0, #1 · movs r1, #2
        let mut image = image_with(&[0x01, 0x20, 0x02, 0x21]);
        let d = tramp(&mut image, SITE, HOOK).unwrap();

        assert_eq!(d.displaced, 4);
        assert_eq!(d.resume(), 0x104);
        assert_eq!(d.stub, FREE as u32);
        // bl (4) + both instructions (4) + b.w (4); no padding, because the
        // body lands at 0x1004 and the site is at 0x100 — both 0 mod 4.
        assert_eq!(d.stub_len, 12);
        assert_eq!(decode_bl(&image, SITE), Some(d.stub));
        assert_eq!(
            text(&image, &d),
            ["bl 0x80", "movs r0, #1", "movs r1, #2", "b.w 0x104"]
        );
    }

    /// One 32-bit instruction fills the window exactly.
    #[test]
    fn a_displaced_region_of_one_wide_instruction() {
        // mov.w r0, #1
        let mut image = image_with(&[0x4f, 0xf0, 0x01, 0x00]);
        let d = tramp(&mut image, SITE, HOOK).unwrap();

        assert_eq!(d.displaced, 4);
        assert_eq!(walk(&image, &d).len(), 3);
        assert_eq!(text(&image, &d)[1], "mov.w r0, #1");
        // The four bytes came across unchanged — nothing in them is
        // address-dependent.
        assert_eq!(
            &image[d.stub as usize + 4..d.stub as usize + 8],
            &[0x4f, 0xf0, 0x01, 0x00]
        );
    }

    /// The case that makes this a decoder's job: a four-byte window over a
    /// 16-bit instruction followed by a 32-bit one must *extend to six*, not
    /// truncate. Truncating would leave `mov.w`'s second halfword behind as
    /// whatever it happens to mean on its own.
    #[test]
    fn a_four_byte_window_that_would_split_an_instruction_extends_to_six() {
        // movs r0, #1 · mov.w r1, #2
        let code = [0x01, 0x20, 0x4f, 0xf0, 0x02, 0x01];
        let mut image = image_with(&code);
        let d = tramp(&mut image, SITE, HOOK).unwrap();

        assert_eq!(d.displaced, 6, "the window must cover whole instructions");
        assert_eq!(d.resume(), 0x106);
        assert_eq!(
            text(&image, &d),
            ["bl 0x80", "movs r0, #1", "mov.w r1, #2", "b.w 0x106"]
        );
        // Both halfwords of the wide instruction travelled together.
        assert_eq!(
            &image[d.stub as usize + 6..d.stub as usize + 10],
            &[0x4f, 0xf0, 0x02, 0x01]
        );
        // And the site's fifth and sixth bytes — the ones a four-byte-only
        // patcher would have left behind — are now part of the branch's
        // aftermath, not a stray halfword: the branch is four bytes, and the
        // two bytes after it are untouched OEM bytes that the stub's tail
        // branch skips by resuming at 0x106.
        assert_eq!(decode_bl(&image, SITE), Some(d.stub));
    }

    /// A 16-bit instruction at the site with nothing after it that decodes is
    /// reported rather than guessed at.
    #[test]
    fn an_undecodable_second_instruction_is_reported() {
        // movs r0, #1 · 0xf870, which the 32-bit dispatcher leaves UNDEFINED.
        let mut image = image_with(&[0x01, 0x20, 0x70, 0xf8, 0x00, 0x00]);
        let before = image.clone();
        let err = tramp(&mut image, SITE, HOOK).unwrap_err();
        assert_eq!(err.reason(), "undecodable");
        assert_eq!(err, DetourError::Undecodable { at: SITE + 2 });
        assert_eq!(image, before);
    }

    // -------------------------------------------------------- IT blocks

    /// The silent, catastrophic case. `itt eq` governs two instructions; the
    /// four-byte window covers the `IT` and only the first of them, so the
    /// second would be left behind under an `IT` that is no longer in front of
    /// it — and the first would run unconditionally in the stub.
    #[test]
    fn a_displaced_region_that_splits_an_it_block_is_refused() {
        // itt eq · movs r0, #1 · movs r1, #2
        let mut image = image_with(&[0x04, 0xbf, 0x01, 0x20, 0x02, 0x21]);
        let before = image.clone();

        let err = tramp(&mut image, SITE, HOOK).unwrap_err();
        assert_eq!(err.reason(), "splits-it-block");
        assert_eq!(
            err,
            DetourError::SplitsItBlock {
                site: SITE,
                displaced: 4
            }
        );
        assert_eq!(image, before, "a refusal must not touch the image");
    }

    /// A *whole* IT block inside the displaced region is fine: the `IT` and
    /// everything it governs move together, so the condition still applies.
    #[test]
    fn a_complete_it_block_moves_intact() {
        // it eq · movs r0, #1
        let mut image = image_with(&[0x08, 0xbf, 0x01, 0x20]);
        let d = tramp(&mut image, SITE, HOOK).unwrap();
        assert_eq!(d.displaced, 4);

        let stub = walk(&image, &d);
        assert_eq!(stub[1].mnemonic, "it");
        // Decoded through the stub, the governed instruction is still
        // conditional — which is the whole point — and, being inside an IT
        // block, no longer sets the flags.
        assert_eq!(stub[2].cond, Some(Cond::Eq));
        assert!(!stub[2].sets_flags);
        assert_eq!(
            text(&image, &d),
            ["bl 0x80", "it eq", "moveq r0, #1", "b.w 0x104"]
        );
    }

    /// With a known decode start, a site *inside* an IT block is caught.
    #[test]
    fn a_site_inside_an_it_block_is_refused_when_the_decode_start_is_known() {
        // itt eq · movs r0, #1 · movs r1, #2 — detoured at the first governed
        // instruction rather than at the `IT`.
        let mut image = image_with(&[0x04, 0xbf, 0x01, 0x20, 0x02, 0x21]);
        let before = image.clone();

        let opts = DetourOptions::new().with_scan_from(SITE);
        let err = detour(&mut image, SITE + 2, HOOK, opts).unwrap_err();
        assert_eq!(err.reason(), "site-in-it-block");
        assert_eq!(err, DetourError::SiteInItBlock { site: SITE + 2 });
        assert_eq!(image, before);
    }

    /// And without one it is *not* caught — the documented blind spot. A Thumb
    /// stream cannot be decoded backwards, so this module cannot see an `IT`
    /// that is behind the site unless it is told where to start looking.
    #[test]
    fn a_site_inside_an_it_block_is_invisible_without_a_decode_start() {
        let mut image = image_with(&[0x04, 0xbf, 0x01, 0x20, 0x02, 0x21]);
        // Succeeds, and produces a patch that is wrong in exactly the way
        // `scan_from` exists to prevent: the displaced `movs` was conditional
        // and the stub's copy is not.
        let d = tramp(&mut image, SITE + 2, HOOK).unwrap();
        assert_eq!(walk(&image, &d)[1].cond, None);
    }

    /// A site in the middle of a 32-bit instruction is not an instruction
    /// boundary, and decoding from a known start says so.
    #[test]
    fn a_site_that_is_not_an_instruction_boundary_is_refused() {
        // mov.w r0, #1 · movs r1, #2 — detoured at the second halfword.
        let mut image = image_with(&[0x4f, 0xf0, 0x01, 0x00, 0x02, 0x21]);
        let before = image.clone();

        let opts = DetourOptions::new().with_scan_from(SITE);
        let err = detour(&mut image, SITE + 2, HOOK, opts).unwrap_err();
        assert_eq!(err.reason(), "site-not-aligned");
        assert_eq!(
            err,
            DetourError::SiteNotAligned {
                site: SITE + 2,
                scan_from: SITE
            }
        );
        assert_eq!(image, before);

        // A start after the site is a caller error, not a decode result.
        let opts = DetourOptions::new().with_scan_from(SITE + 4);
        assert_eq!(
            detour(&mut image, SITE, HOOK, opts).unwrap_err().reason(),
            "scan-start-after-site"
        );
    }

    // ------------------------------------------------------- atomicity

    /// The atomicity test. A `cbz` cannot be relocated — it branches forward
    /// only, 0..126 bytes, and has no backward form — so the detour must be
    /// refused **with the image untouched**, not with a stub already written
    /// into free space.
    #[test]
    fn an_unrelocatable_displaced_instruction_leaves_the_image_untouched() {
        // cbz r0, 0x10c · movs r1, #2
        let mut image = image_with(&[0x20, 0xb1, 0x02, 0x21]);
        let before = image.clone();

        let err = tramp(&mut image, SITE, HOOK).unwrap_err();
        assert_eq!(err.reason(), "relocate");
        // The whole refusal, not just its class: the instruction that could not
        // be moved, and the stub address it was tried at — the body of a stub
        // at 0x1000 begins at 0x1004, after the `bl hook`.
        assert_eq!(
            err,
            DetourError::Relocate {
                at: SITE as u32,
                source: RelocateError::ForwardOnlyBranch {
                    mnemonic: "cbz",
                    from: SITE as u32,
                    to: FREE as u32 + 4,
                    target: 0x10c,
                },
            }
        );
        assert_eq!(image, before, "not one byte may change");
        // In particular the free space is still erased: no half-written stub.
        assert!(image[FREE..].iter().all(|&b| b == 0xff));
    }

    /// The other refusal `isa::encode` cannot make: a table branch's entries
    /// are offsets from its own pc, so moving it silently moves every
    /// destination.
    #[test]
    fn a_displaced_table_branch_leaves_the_image_untouched() {
        // tbb [r0, r1]
        let mut image = image_with(&[0xd0, 0xe8, 0x01, 0xf0]);
        let before = image.clone();

        let err = tramp(&mut image, SITE, HOOK).unwrap_err();
        assert_eq!(
            err,
            DetourError::Relocate {
                at: SITE as u32,
                source: RelocateError::TableBranch {
                    mnemonic: "tbb",
                    from: SITE as u32,
                    to: FREE as u32 + 4,
                },
            }
        );
        // Not retryable, unlike the `cbz` above: no stub address can host a
        // table branch, so the search stops at the first free run rather than
        // walking the image.
        assert!(!err.retryable());
        assert_eq!(image, before);
    }

    /// Every other refusal is atomic too, including the ones discovered last.
    #[test]
    fn every_refusal_leaves_the_image_untouched() {
        let code = [0x01, 0x20, 0x02, 0x21];

        // No erased space at all.
        let mut image = vec![0u8; LEN];
        image[SITE..SITE + 4].copy_from_slice(&code);
        let before = image.clone();
        assert_eq!(
            tramp(&mut image, SITE, HOOK).unwrap_err().reason(),
            "no-free-space"
        );
        assert_eq!(image, before);

        // A hook no branch can reach.
        let mut image = image_with(&code);
        let before = image.clone();
        let err = tramp(&mut image, SITE, 0x4000_0000).unwrap_err();
        assert_eq!(err.reason(), "hook-unreachable");
        assert_eq!(image, before);

        // An explicitly placed stub that is not word aligned.
        let mut image = image_with(&code);
        let before = image.clone();
        let opts = DetourOptions::new().with_stub_at(FREE as u32 + 2);
        assert_eq!(
            detour(&mut image, SITE, HOOK, opts).unwrap_err().reason(),
            "stub-misaligned"
        );
        assert_eq!(image, before);

        // An explicitly placed stub that runs off the end.
        let mut image = image_with(&code);
        let before = image.clone();
        let opts = DetourOptions::new().with_stub_at(LEN as u32 - 4);
        assert_eq!(
            detour(&mut image, SITE, HOOK, opts).unwrap_err().reason(),
            "stub-out-of-bounds"
        );
        assert_eq!(image, before);

        // A site with no room for a four-byte branch.
        let mut image = image_with(&code);
        let before = image.clone();
        assert_eq!(
            tramp(&mut image, LEN - 2, HOOK).unwrap_err().reason(),
            "out-of-bounds"
        );
        assert_eq!(image, before);

        // A stub placed on top of the site: the hook branch would be written
        // into the middle of the stub, and neither would survive.
        let mut image = image_with(&code);
        let before = image.clone();
        let opts = DetourOptions::new().with_stub_at(SITE as u32);
        assert_eq!(
            detour(&mut image, SITE, HOOK, opts).unwrap_err().reason(),
            "stub-overlaps-site"
        );
        assert_eq!(image, before);
        // And one that merely reaches back into it.
        let mut image = image_with(&code);
        let opts = DetourOptions::new().with_stub_at(SITE as u32 - 4);
        assert_eq!(
            detour(&mut image, SITE, HOOK, opts).unwrap_err().reason(),
            "stub-overlaps-site"
        );
        assert_eq!(image, before);
    }

    /// Decoding *towards* the site runs through whatever is in between, and
    /// data is in between more often than not. It is reported, rather than
    /// letting the walk lose phase and declare the site misaligned for the
    /// wrong reason.
    #[test]
    fn undecodable_bytes_before_the_site_are_reported() {
        // 0x100: `0xf870 0x0000`, UNDEFINED; 0x104: movs r0, #1 · movs r1, #2.
        let mut image = image_with(&[0x70, 0xf8, 0x00, 0x00, 0x01, 0x20, 0x02, 0x21]);
        let before = image.clone();

        let opts = DetourOptions::new().with_scan_from(SITE);
        let err = detour(&mut image, SITE + 4, HOOK, opts).unwrap_err();
        assert_eq!(err.reason(), "undecodable");
        assert_eq!(err, DetourError::Undecodable { at: SITE });
        assert_eq!(image, before);

        // Without a scan start there is nothing to walk through, and the same
        // site detours cleanly — which is what makes the refusal above a
        // statement about `scan_from`, not about the site.
        let mut image = image_with(&[0x70, 0xf8, 0x00, 0x00, 0x01, 0x20, 0x02, 0x21]);
        assert!(tramp(&mut image, SITE + 4, HOOK).is_ok());
    }

    // ------------------------------------------------ the three reach checks

    /// Each convention branches to the hook from a different place in the
    /// stub, so each has its own reach check. [`Convention::HookDecides`]
    /// jumps from `stub + 4`, after the `ldr.w r12`.
    #[test]
    fn the_hook_decides_jump_has_its_own_reach_check() {
        let mut image = image_with(&[0x01, 0x20, 0x02, 0x21]);
        let before = image.clone();

        let opts = DetourOptions::new()
            .with_kind(BranchKind::BWide)
            .with_convention(Convention::HookDecides);
        let err = detour(&mut image, SITE, 0x4000_0000, opts).unwrap_err();
        assert_eq!(err.reason(), "hook-unreachable");
        assert_eq!(
            err,
            DetourError::HookUnreachable {
                from: FREE as u32 + 4,
                hook: 0x4000_0000,
            },
            "the jump is the stub's second instruction, not its first"
        );
        assert_eq!(image, before);

        // The call-then-continue stub branches from the stub's own address,
        // which is the distinction this pair of assertions exists to pin.
        let mut image = image_with(&[0x01, 0x20, 0x02, 0x21]);
        assert_eq!(
            tramp(&mut image, SITE, 0x4000_0000).unwrap_err(),
            DetourError::HookUnreachable {
                from: FREE as u32,
                hook: 0x4000_0000,
            }
        );
    }

    /// A stub too far from the site to branch *back* from is refused while it
    /// is still a plan.
    ///
    /// The tail branch is a `B.W`, ±16 MB (A7.7.12), measured from the end of
    /// the relocated block — so a consumer with its own allocator can hand
    /// [`DetourOptions::stub_at`] an address in a region the site cannot be
    /// reached from, and gets told which branch it was.
    #[test]
    fn a_stub_that_cannot_branch_back_is_refused() {
        let mut image = image_with(&[0x01, 0x20, 0x02, 0x21]);
        let before = image.clone();

        // 64 MB above the site, with a hook next door so that the *hook*
        // branch is not the one that fails.
        let stub = 0x0400_0000u32;
        let opts = DetourOptions::new().with_stub_at(stub);
        let err = detour(&mut image, SITE, stub + 0x100, opts).unwrap_err();

        assert_eq!(err.reason(), "resume-unreachable");
        assert_eq!(
            err,
            DetourError::ResumeUnreachable {
                // `bl hook` (4) + the two displaced halfwords (4).
                from: stub + 8,
                resume: SITE as u32 + 4,
            }
        );
        assert!(err.retryable(), "a nearer stub could work");
        assert_eq!(image, before, "and nothing was written to find out");
    }

    /// The narrow window where the *site* branch is the one that does not
    /// reach.
    ///
    /// Both branches span ±16 MB, and the tail measures from a few bytes
    /// further into the stub than the site branch does — so for a handful of
    /// distances the stub can branch back although the site cannot call it.
    /// That window is the whole reason [`DetourError::SiteUnreachable`] is a
    /// separate refusal rather than a second `resume-unreachable`: it names
    /// the branch the caller would have to shorten.
    ///
    /// Needs a 16 MB image to exist at all, which is why there is one test of
    /// it and not a family.
    #[test]
    fn the_site_branch_can_be_the_one_that_does_not_reach() {
        // `BL`'s reach is `-(1 << 24) ..= (1 << 24) - 2` from `site + 4`
        // (A7.7.18), so a stub exactly 16 MB below the site is four bytes too
        // far for it …
        let stub = 0x1000u32;
        let site = stub as usize + (1 << 24);
        assert_eq!(crate::encode_bl(site, stub), None);
        // … while the tail branch, which starts eight bytes into the stub,
        // still reaches the resume point.
        assert!(encode_b_wide((stub + 8) as usize, site as u32 + 4).is_some());

        let mut image = vec![0u8; site + 0x10];
        image[site..site + 4].copy_from_slice(&[0x01, 0x20, 0x02, 0x21]);
        let before = image.clone();

        let opts = DetourOptions::new().with_stub_at(stub);
        let err = detour(&mut image, site, stub + 0x100, opts).unwrap_err();

        assert_eq!(err.reason(), "site-unreachable");
        assert_eq!(
            err,
            DetourError::SiteUnreachable {
                site,
                stub,
                kind: BranchKind::Bl,
            }
        );
        assert!(err.retryable(), "a stub four bytes nearer would do");
        // Atomic, like every other refusal: the stub was fully planned — it
        // encodes, it fits, it branches back — and still nothing was written.
        assert_eq!(image, before);

        // Four bytes nearer, and the same patch installs.
        let mut image = vec![0u8; site + 0x10];
        image[site..site + 4].copy_from_slice(&[0x01, 0x20, 0x02, 0x21]);
        let opts = DetourOptions::new().with_stub_at(stub + 4);
        let d = detour(&mut image, site, stub + 0x100, opts).unwrap();
        assert_eq!(d.stub, stub + 4);
        assert_eq!(decode_bl(&image, site), Some(stub + 4));
    }

    // -------------------------------------------- end-to-end verification

    /// Walk the whole patch the way a reviewer would: decode the installed
    /// branch, follow it, check every instruction in the stub, and confirm the
    /// tail branch lands on the first byte the detour did not displace.
    #[test]
    fn a_successful_detour_is_verifiable_end_to_end() {
        // movs r0, #1 · movs r1, #2, with a third instruction after the
        // displaced region to resume into.
        let mut image = image_with(&[0x01, 0x20, 0x02, 0x21, 0x03, 0x22]);
        let originals = isa::disassemble(&image, SITE, SITE as u32, 2);

        let d = tramp(&mut image, SITE, HOOK).unwrap();

        // 1. The site branches to the stub, and says so when decoded back.
        assert_eq!(decode_bl(&image, d.site), Some(d.stub));
        assert!(verify_branch(&image, d.site, BranchKind::Bl, d.stub).is_ok());
        // 2. The stub's first instruction calls the hook.
        let stub = walk(&image, &d);
        assert_eq!(stub[0].mnemonic, "bl");
        assert!(stub[0].is_call());
        assert_eq!(stub[0].branch_target(), Some(HOOK));
        // 3. The displaced instructions are there, meaning the same thing.
        let moved = isa::disassemble(&image, (d.stub + 4) as usize, d.stub + 4, 2);
        for (a, b) in originals.iter().zip(&moved) {
            // Same text after the address prefix.
            assert_eq!(a[10..], b[10..], "{a} vs {b}");
        }
        // 4. The tail branch returns to the first undisplaced byte.
        let tail = stub.last().unwrap();
        assert_eq!((tail.mnemonic, tail.encoding), ("b", "T4"));
        assert_eq!(tail.branch_target(), Some(d.resume()));
        assert_eq!(decode_b_wide(&image, tail.addr as usize), Some(d.resume()));
        // 5. And the instruction at the resume point is the one that was
        //    always there.
        assert_eq!(
            isa::decode_at(&image, d.resume() as usize)
                .unwrap()
                .to_string(),
            "movs r2, #3"
        );
        // 6. Nothing outside the site and the stub moved.
        assert!(image[..SITE].iter().all(|&b| b == 0));
        assert!(image[SITE + 4..FREE]
            .iter()
            .all(|&b| b == 0 || b == 0x22 || b == 0x03));
    }

    /// The shape the real consumer hand-writes seven times: a `cmp`/`b<cond>`
    /// gate, detoured **at the `cmp`**, so the stub has to re-execute both —
    /// and the conditional branch, which reached its target in eight bits from
    /// the original site, has to be widened to reach it from free space.
    ///
    /// This is the test that makes `build_speed_stub`'s hand-decoded `bhi`
    /// (sign-extend included) unnecessary.
    #[test]
    fn the_consumer_shape_a_cmp_and_a_conditional_branch() {
        // cmp r2, #0x32 · bhi 0x140
        //   imm8 = (0x140 - (0x102 + 4)) / 2 = 0x1d
        let mut image = image_with(&[0x32, 0x2a, 0x1d, 0xd8]);
        assert_eq!(
            isa::disassemble(&image, SITE, SITE as u32, 2),
            ["00000100: cmp r2, #0x32", "00000102: bhi 0x140"]
        );

        let d = tramp(&mut image, SITE, HOOK).unwrap();
        assert_eq!(d.displaced, 4);

        let stub = walk(&image, &d);
        // The `cmp` is address-independent: byte-identical, and still compares
        // against the same OEM band.
        assert_eq!(stub[1].to_string(), "cmp r2, #0x32");
        assert_eq!(
            &image[d.stub as usize + 4..d.stub as usize + 6],
            &[0x32, 0x2a]
        );
        // The `bhi` could not reach 0x140 from the stub in eight bits — the
        // displacement is -0xeca, and T1 spans -256..254 — so it was widened to
        // T3, which carries the same condition in its own encoding.
        assert_eq!((stub[2].mnemonic, stub[2].encoding), ("b", "T3"));
        assert_eq!(stub[2].cond, Some(Cond::Hi));
        assert_eq!(stub[2].branch_target(), Some(0x140));
        assert_eq!(stub[2].to_string(), "bhi.w 0x140");
        // And the fall-through is the instruction after the gate, exactly as
        // the OEM ramp expects.
        assert_eq!(stub[3].branch_target(), Some(0x104));
        // Widening cost two bytes, and the stub is sized for it.
        assert_eq!(d.stub_len, 4 + 2 + 4 + 4);
    }

    // ------------------------------------------------------- conventions

    /// `BranchKind::BWide` keeps `lr`, so the stub must keep it too: the
    /// `bl hook` in the middle would otherwise destroy the very thing the
    /// caller chose `b.w` to preserve.
    #[test]
    fn a_b_wide_site_makes_the_stub_preserve_lr() {
        let mut image = image_with(&[0x01, 0x20, 0x02, 0x21]);
        let opts = DetourOptions::new().with_kind(BranchKind::BWide);
        let d = detour(&mut image, SITE, HOOK, opts).unwrap();

        assert_eq!(d.kind, BranchKind::BWide);
        assert_eq!(decode_b_wide(&image, SITE), Some(d.stub));
        assert_eq!(decode_bl(&image, SITE), None, "a b.w is not a bl");
        assert_eq!(
            text(&image, &d),
            [
                "push {lr}",
                "bl 0x80",
                "ldr lr, [sp], #4",
                "nop", // alignment padding, see `build_stub`
                "movs r0, #1",
                "movs r1, #2",
                "b.w 0x104",
            ]
        );
        // The displaced block kept the site's alignment mod 4 …
        let body = d.stub as usize + 12;
        assert_eq!(body % 4, SITE % 4);
        // … and the whole stub is accounted for.
        assert_eq!(d.stub_len, 2 + 4 + 4 + 2 + 4 + 4);
    }

    /// With a `BL` at the site there is nothing left to preserve — the site
    /// branch already overwrote `lr` — so the stub does not pay for a save.
    #[test]
    fn a_bl_site_does_not_pay_to_preserve_a_dead_lr() {
        let mut image = image_with(&[0x01, 0x20, 0x02, 0x21]);
        let d = tramp(&mut image, SITE, HOOK).unwrap();
        assert_eq!(text(&image, &d)[0], "bl 0x80");
        assert_eq!(d.stub_len, 12);
    }

    /// `Convention::HookDecides`: the hook is *jumped* to, with the
    /// continuation address in `r12` and `lr` untouched, so it can run the
    /// original, skip it, or return.
    #[test]
    fn the_hook_decides_convention_hands_over_a_continuation() {
        let mut image = image_with(&[0x01, 0x20, 0x02, 0x21]);
        let opts = DetourOptions::new()
            .with_kind(BranchKind::BWide)
            .with_convention(Convention::HookDecides);
        let d = detour(&mut image, SITE, HOOK, opts).unwrap();

        let stub = d.stub as usize;
        // `ldr.w r12, [pc, #4]` reads the word at stub + 8 …
        let load = isa::decode_at_with(&image, stub, d.stub, isa::Target::Union).unwrap();
        assert_eq!(load.mnemonic, "ldr");
        assert_eq!(load.branch_target(), Some(d.stub + 8));
        assert_eq!(load.to_string(), "ldr.w r12, [pc, #4], 0x1008");
        // … which holds the continuation, Thumb bit set.
        let continuation = d.stub + 12;
        assert_eq!(read_u32(&image, stub + CONTINUATION_WORD), continuation | 1);
        // A jump, not a call: `lr` is whatever the site left, which with a
        // `b.w` at the site is the outer function's return address.
        assert_eq!(decode_b_wide(&image, stub + 4), Some(HOOK));
        assert!(
            !isa::decode_at_with(&image, stub + 4, d.stub + 4, isa::Target::Union)
                .unwrap()
                .is_call()
        );
        // The continuation is the displaced code and the branch back.
        assert_eq!(
            isa::disassemble(&image, continuation as usize, continuation, 3),
            [
                format!("{continuation:08x}: movs r0, #1"),
                format!("{:08x}: movs r1, #2", continuation + 2),
                format!("{:08x}: b.w 0x104", continuation + 4),
            ]
        );
        assert_eq!(d.stub_len, 12 + 4 + 4);
    }

    /// The padding is not cosmetic: the displaced block lands at the site's own
    /// alignment mod 4, so that `Align(PC,4)` arithmetic is disturbed by a
    /// constant and not by a constant-plus-two.
    #[test]
    fn the_displaced_block_keeps_the_sites_alignment() {
        for site in [SITE, SITE + 2] {
            for (kind, convention) in [
                (BranchKind::Bl, Convention::CallThenContinue),
                (BranchKind::BWide, Convention::CallThenContinue),
                (BranchKind::BWide, Convention::HookDecides),
            ] {
                let mut image = vec![0u8; LEN];
                for b in image[FREE..].iter_mut() {
                    *b = 0xff;
                }
                image[site..site + 4].copy_from_slice(&[0x01, 0x20, 0x02, 0x21]);
                let opts = DetourOptions::new()
                    .with_kind(kind)
                    .with_convention(convention);
                let d = detour(&mut image, site, HOOK, opts).unwrap();
                // Find the first displaced instruction: the last two
                // instructions of the stub are it and the tail branch.
                let stub = walk(&image, &d);
                let body = stub[stub.len() - 3].addr;
                assert_eq!(
                    body as usize % 4,
                    site % 4,
                    "site {site:#x}, {kind}, {convention:?}"
                );
            }
        }
    }

    // ------------------------------------------------- placement and search

    /// An explicit stub address skips the search, which is how a consumer with
    /// its own free-space allocator plugs in.
    #[test]
    fn an_explicit_stub_address_is_used_as_given() {
        let mut image = image_with(&[0x01, 0x20, 0x02, 0x21]);
        let opts = DetourOptions::new().with_stub_at(0x1800);
        let d = detour(&mut image, SITE, HOOK, opts).unwrap();
        assert_eq!(d.stub, 0x1800);
        assert_eq!(decode_bl(&image, SITE), Some(0x1800));
        // And the search's own choice is left alone.
        assert!(image[FREE..0x1800].iter().all(|&b| b == 0xff));
    }

    /// The search returns a 4-aligned address even when the erased run does not
    /// start on one — and, because it tests an aligned *window* rather than
    /// aligning a run after the fact, it does not lose the bytes that rounding
    /// up consumed.
    #[test]
    fn the_free_space_search_aligns_its_answer() {
        let mut image = image_with(&[0x01, 0x20, 0x02, 0x21]);
        // Make the run start at an odd-word offset.
        image[FREE] = 0x00;
        image[FREE + 1] = 0x00;
        assert_eq!(crate::find_free_space(&image, 4, 1, 0), Some(FREE + 2));
        assert_eq!(crate::find_free_space(&image, 4, 4, 0), Some(FREE + 4));

        let d = tramp(&mut image, SITE, HOOK).unwrap();
        assert_eq!(d.stub % 4, 0);
        assert_eq!(d.stub, FREE as u32 + 4);
    }

    /// A run too short for the stub is skipped, and the search moves on to the
    /// next one rather than stopping at the first.
    #[test]
    fn a_run_too_short_for_the_stub_is_skipped() {
        let mut image = image_with(&[0x01, 0x20, 0x02, 0x21]);
        // A four-byte island of erased flash well before the real free space.
        for b in image[0x800..0x804].iter_mut() {
            *b = 0xff;
        }
        let d = tramp(&mut image, SITE, HOOK).unwrap();
        assert_eq!(d.stub, FREE as u32, "the island cannot hold a 12-byte stub");
        assert!(image[0x800..0x804].iter().all(|&b| b == 0xff));
    }

    /// `search_start` skips free space the caller has already spoken for,
    /// which is how a consumer placing several detours stops them all landing
    /// on the same run.
    #[test]
    fn the_free_space_search_starts_where_it_is_told() {
        let code = [0x01u8, 0x20, 0x02, 0x21];
        let mut image = image_with(&code);
        let opts = DetourOptions::new().with_search_start(FREE + 0x40);
        let d = detour(&mut image, SITE, HOOK, opts).unwrap();

        assert_eq!(d.stub, FREE as u32 + 0x40);
        assert_eq!(decode_bl(&image, SITE), Some(d.stub));
        // The run below the given start is left erased, untouched …
        assert!(image[FREE..FREE + 0x40].iter().all(|&b| b == 0xff));
        // … and it is where the search would otherwise have gone.
        let mut default = image_with(&code);
        assert_eq!(tramp(&mut default, SITE, HOOK).unwrap().stub, FREE as u32);
    }

    /// The error chain. A refusal that wraps another error hands it back
    /// through [`std::error::Error::source`], so a consumer printing a cause
    /// chain — or downcasting to decide what to do — reaches the relocation
    /// refusal without matching on this enum.
    #[test]
    fn a_wrapped_refusal_is_reachable_as_an_error_source() {
        use std::error::Error;

        let inner = RelocateError::TableBranch {
            mnemonic: "tbb",
            from: 0x100,
            to: 0x1004,
        };
        let err = DetourError::Relocate {
            at: 0x100,
            source: inner,
        };
        let source = err.source().expect("a relocation refusal has a source");
        assert_eq!(source.to_string(), inner.to_string());
        assert_eq!(
            source
                .downcast_ref::<RelocateError>()
                .map(RelocateError::reason),
            Some("pc-relative-table")
        );

        // Every other variant is a leaf: it carries offsets, not a cause.
        assert!(DetourError::NoFreeSpace { need: 12 }.source().is_none());
        assert!(DetourError::SiteInItBlock { site: 0x100 }
            .source()
            .is_none());
    }

    /// `end_of_run` always advances, so the run-walking search terminates even
    /// at the end of an image.
    #[test]
    fn end_of_run_always_advances() {
        let image = [0xffu8, 0xff, 0x00, 0xff];
        assert_eq!(end_of_run(&image, 0), 2);
        assert_eq!(end_of_run(&image, 2), 3);
        assert_eq!(end_of_run(&image, 3), 4);
        assert_eq!(end_of_run(&image, 4), 5);
        assert_eq!(end_of_run(&image, 99), 100);
    }

    // ------------------------------------------------------ the constants

    /// The four hand-written halfwords in this module, decoded back through
    /// this crate's own decoder. A typo in any of them would be a stub that
    /// executes something else entirely, and no other test would catch it.
    #[test]
    fn the_hand_written_prologue_instructions_decode_as_intended() {
        assert_eq!(
            isa::decode_at_with(&PUSH_LR, 0, 0x1000, isa::Target::Union)
                .unwrap()
                .to_string(),
            "push {lr}"
        );
        assert_eq!(
            isa::decode_at_with(&LDR_LR_POP, 0, 0x1000, isa::Target::Union)
                .unwrap()
                .to_string(),
            "ldr lr, [sp], #4"
        );
        assert_eq!(
            isa::decode_at_with(&NOP, 0, 0x1000, isa::Target::Union)
                .unwrap()
                .to_string(),
            "nop"
        );
        // At a 4-aligned address, `[pc, #4]` resolves to address + 8 — which is
        // where `build_stub` puts the continuation word.
        let load =
            isa::decode_at_with(&LDR_IP_CONTINUATION, 0, 0x1000, isa::Target::Union).unwrap();
        assert_eq!(load.to_string(), "ldr.w r12, [pc, #4], 0x1008");
        assert_eq!(load.branch_target(), Some(0x1008));
    }

    /// Every reason string, in one place.
    #[test]
    fn reason_strings_are_stable() {
        let all = [
            (
                DetourError::OutOfBounds {
                    site: 0,
                    need: 4,
                    len: 2,
                },
                "out-of-bounds",
            ),
            (DetourError::Undecodable { at: 2 }, "undecodable"),
            (
                DetourError::ScanStartAfterSite {
                    scan_from: 4,
                    site: 2,
                },
                "scan-start-after-site",
            ),
            (
                DetourError::SiteNotAligned {
                    site: 2,
                    scan_from: 0,
                },
                "site-not-aligned",
            ),
            (DetourError::SiteInItBlock { site: 2 }, "site-in-it-block"),
            (
                DetourError::SplitsItBlock {
                    site: 2,
                    displaced: 4,
                },
                "splits-it-block",
            ),
            (
                DetourError::Relocate {
                    at: 2,
                    source: RelocateError::TableBranch {
                        mnemonic: "tbb",
                        from: 2,
                        to: 4,
                    },
                },
                "relocate",
            ),
            (DetourError::NoFreeSpace { need: 12 }, "no-free-space"),
            (DetourError::StubMisaligned { stub: 2 }, "stub-misaligned"),
            (
                DetourError::StubOverlapsSite { stub: 2, site: 0 },
                "stub-overlaps-site",
            ),
            (
                DetourError::StubOutOfBounds {
                    stub: 2,
                    need: 12,
                    len: 4,
                },
                "stub-out-of-bounds",
            ),
            (
                DetourError::SiteUnreachable {
                    site: 0,
                    stub: 2,
                    kind: BranchKind::Bl,
                },
                "site-unreachable",
            ),
            (
                DetourError::HookUnreachable { from: 0, hook: 2 },
                "hook-unreachable",
            ),
            (
                DetourError::ResumeUnreachable { from: 0, resume: 2 },
                "resume-unreachable",
            ),
        ];
        for (err, reason) in all {
            assert_eq!(err.reason(), reason);
            assert!(!err.to_string().is_empty());
        }
    }

    /// The retry predicate: only a refusal another address could fix.
    #[test]
    fn only_address_dependent_refusals_are_retried() {
        assert!(DetourError::SiteUnreachable {
            site: 0,
            stub: 2,
            kind: BranchKind::Bl
        }
        .retryable());
        assert!(DetourError::Relocate {
            at: 0,
            source: RelocateError::OutOfRange {
                mnemonic: "b",
                from: 0,
                to: 2,
                target: Some(4)
            }
        }
        .retryable());
        assert!(!DetourError::Relocate {
            at: 0,
            source: RelocateError::TableBranch {
                mnemonic: "tbb",
                from: 0,
                to: 2
            }
        }
        .retryable());
        assert!(!DetourError::SplitsItBlock {
            site: 0,
            displaced: 4
        }
        .retryable());
    }

    /// `tramp` is `detour` with the defaults, and nothing more.
    #[test]
    fn tramp_is_detour_with_the_defaults() {
        let code = [0x01, 0x20, 0x02, 0x21];
        let mut a = image_with(&code);
        let mut b = image_with(&code);
        let one = tramp(&mut a, SITE, HOOK).unwrap();
        let two = detour(&mut b, SITE, HOOK, DetourOptions::default()).unwrap();
        assert_eq!(one, two);
        assert_eq!(a, b);
    }

    /// A Thumb-bit-carrying hook pointer is accepted, as everywhere else in
    /// this crate.
    #[test]
    fn the_hooks_thumb_bit_is_masked_off() {
        let code = [0x01, 0x20, 0x02, 0x21];
        let mut a = image_with(&code);
        let mut b = image_with(&code);
        assert_eq!(
            tramp(&mut a, SITE, HOOK).unwrap(),
            tramp(&mut b, SITE, HOOK | 1).unwrap()
        );
        assert_eq!(a, b);
    }

    /// The stub prologue's size, per convention and branch kind.
    ///
    /// Mutation testing replaced this function's whole body with `0` and with
    /// `1` and no test noticed. It is the offset at which the displaced
    /// original instructions are copied into the stub, so a wrong value writes
    /// them over the prologue itself — a trampoline that corrupts the very
    /// registers it was meant to preserve, in code about to be flashed.
    #[test]
    fn the_stub_prologue_is_exactly_as_long_as_the_instructions_in_it() {
        let opts = |c: Convention, k: BranchKind| DetourOptions {
            convention: c,
            kind: k,
            ..DetourOptions::default()
        };
        // `bl hook` alone: the site's own `bl` already clobbered `lr`.
        assert_eq!(
            prologue_len(&opts(Convention::CallThenContinue, BranchKind::Bl)),
            4
        );
        // `push {lr}` (2) · `bl hook` (4) · `ldr lr, [sp], #4` (4).
        assert_eq!(
            prologue_len(&opts(Convention::CallThenContinue, BranchKind::BWide)),
            10
        );
        // `ldr.w r12, [pc, #4]` (4) · `b.w hook` (4) · continuation word (4).
        assert_eq!(
            prologue_len(&opts(Convention::HookDecides, BranchKind::Bl)),
            12
        );
        assert_eq!(
            prologue_len(&opts(Convention::HookDecides, BranchKind::BWide)),
            12
        );
    }

    // ------------------------------------------------- DetourStyle (0.11.0)

    /// `DiscardAndJumpTo` leaves the displaced instructions out of the stub.
    ///
    /// This is the one operation in the crate that throws instructions away,
    /// which is why the variant says so in its name. The test pins both halves
    /// of the difference: the displaced instructions are *not* in the stub,
    /// and the tail goes where the caller said rather than back to the site.
    #[test]
    fn discard_and_jump_to_omits_the_displaced_instructions() {
        // movs r0, #1 · movs r1, #2 — four bytes, both would normally be
        // relocated into the stub.
        let code = [0x01, 0x20, 0x02, 0x21];

        let mut resumed = image_with(&code);
        let r = detour(&mut resumed, SITE, HOOK, DetourOptions::new()).unwrap();
        let resumed_text = text(&resumed, &r);

        let elsewhere = (SITE + 0x40) as u32;
        let mut jumped = image_with(&code);
        let j = detour(
            &mut jumped,
            SITE,
            HOOK,
            DetourOptions::new().with_style(DetourStyle::DiscardAndJumpTo(elsewhere)),
        )
        .unwrap();
        let jumped_text = text(&jumped, &j);

        // The resuming stub carries the two displaced instructions; the
        // discarding one does not carry either.
        assert!(
            resumed_text.iter().any(|t| t == "movs r0, #1"),
            "resume stub should relocate the displaced instructions: {resumed_text:?}"
        );
        assert!(
            !jumped_text.iter().any(|t| t.starts_with("movs")),
            "discarding stub must not carry them: {jumped_text:?}"
        );
        assert!(
            j.stub_len < r.stub_len,
            "discarding four bytes of displaced code should make the stub shorter: \
             {} vs {}",
            j.stub_len,
            r.stub_len
        );

        // The site itself is patched identically either way — the style is
        // about the stub, not the site.
        assert_eq!(resumed[SITE..SITE + 4], jumped[SITE..SITE + 4]);

        // And the tail goes where it was told, not back to the site.
        let tail = walk(&jumped, &j).pop().expect("a tail branch");
        assert_eq!(tail.branch_target(), Some(elsewhere));
        assert_ne!(tail.branch_target(), Some(r.resume()));
    }

    /// The Thumb bit on the destination is ignored, as everywhere else here.
    #[test]
    fn discard_and_jump_to_ignores_the_thumb_bit_on_its_destination() {
        let code = [0x01, 0x20, 0x02, 0x21];
        let to = (SITE + 0x40) as u32;
        let mut a = image_with(&code);
        let mut b = image_with(&code);
        let da = detour(
            &mut a,
            SITE,
            HOOK,
            DetourOptions::new().with_style(DetourStyle::DiscardAndJumpTo(to)),
        )
        .unwrap();
        let db = detour(
            &mut b,
            SITE,
            HOOK,
            DetourOptions::new().with_style(DetourStyle::DiscardAndJumpTo(to | 1)),
        )
        .unwrap();
        assert_eq!(a, b, "the Thumb bit must not change a byte");
        assert_eq!(da.stub, db.stub);
    }

    /// An unreachable destination is refused rather than silently truncated.
    #[test]
    fn discard_and_jump_to_refuses_a_destination_out_of_branch_range() {
        let mut image = image_with(&[0x01, 0x20, 0x02, 0x21]);
        let err = detour(
            &mut image,
            SITE,
            HOOK,
            // Well past the ±16 MB a `b.w` can reach.
            DetourOptions::new().with_style(DetourStyle::DiscardAndJumpTo(0x7F00_0000)),
        )
        .expect_err("out of range must not encode");
        assert_eq!(err.reason(), "resume-unreachable");
        // Nothing was written: planning fails before the site is touched.
        assert_eq!(image, image_with(&[0x01, 0x20, 0x02, 0x21]));
    }

    #[test]
    fn with_style_defaults_to_resuming() {
        assert_eq!(DetourOptions::new().style, DetourStyle::ResumeAfter);
        assert_eq!(DetourOptions::default().style, DetourStyle::ResumeAfter);
        let o = DetourOptions::new().with_style(DetourStyle::DiscardAndJumpTo(0x200));
        assert_eq!(o.style, DetourStyle::DiscardAndJumpTo(0x200));
        // The other options are untouched by setting the style.
        assert_eq!(o.kind, DetourOptions::new().kind);
        assert_eq!(o.convention, DetourOptions::new().convention);
    }

    // ------------------------------------------------- patching-path guards
    //
    // Mutation testing found these unexercised. They are ranked here by what
    // goes wrong, not by how the code looks: this is the only place in the
    // crate that writes bytes into a live image, so a guard that stops
    // working here puts them somewhere they should not be.

    /// The space the search asks for must cover the stub that gets written.
    ///
    /// `need` is the only thing that guarantees the erased run is long enough.
    /// Nothing downstream re-checks it — `attempt` bounds the stub against the
    /// *image*, not against the run it was placed in — so an under-estimate
    /// puts the stub's tail on top of whatever lives after the run, and the
    /// write goes to flash.
    #[test]
    fn the_space_the_search_asks_for_covers_the_stub_that_gets_written() {
        let fixtures: [&[u8]; 3] = [
            &[0x01, 0x20, 0x02, 0x21],             // two narrow, no widening
            &[0x32, 0x2A, 0x1D, 0xD8],             // cmp · bhi — the bhi widens
            &[0x01, 0x20, 0x4F, 0xF0, 0x02, 0x01], // 16- then 32-bit: displaces 6
        ];
        for code in fixtures {
            // Both word parities, because one of them costs two bytes of
            // alignment padding and the other does not.
            for site in [SITE, SITE + 2] {
                for (kind, convention) in [
                    (BranchKind::Bl, Convention::CallThenContinue),
                    (BranchKind::BWide, Convention::CallThenContinue),
                    (BranchKind::BWide, Convention::HookDecides),
                ] {
                    let mut image = vec![0u8; LEN];
                    for b in image[FREE..].iter_mut() {
                        *b = 0xFF;
                    }
                    image[site..site + code.len()].copy_from_slice(code);
                    let opts = DetourOptions::new()
                        .with_kind(kind)
                        .with_convention(convention);
                    let insns = displaced_at(&image, site, None).unwrap();
                    let need = prologue_len(&opts) + 2 + 4 * insns.len() + 4;
                    let d = detour(&mut image, site, HOOK, opts).unwrap();
                    assert!(
                        d.stub_len <= need,
                        "site {site:#x} {kind} {convention:?}: stub {} exceeds the \
                         {need} bytes the search asked for",
                        d.stub_len
                    );
                }
            }
        }
    }

    /// And the consequence, end to end: when the only erased run is shorter
    /// than the stub, the detour is refused rather than written past it.
    #[test]
    fn a_run_shorter_than_the_stub_is_never_written_into() {
        let mut image = vec![0u8; LEN];
        // cmp r2, #0x32 · bhi — the `bhi` widens to four bytes in the stub.
        image[SITE..SITE + 4].copy_from_slice(&[0x32, 0x2A, 0x1D, 0xD8]);
        // Twelve erased bytes. The stub is fourteen: bl(4) cmp(2) bhi.w(4) b.w(4).
        for b in image[FREE..FREE + 12].iter_mut() {
            *b = 0xFF;
        }
        let before = image.clone();
        assert_eq!(
            tramp(&mut image, SITE, HOOK).unwrap_err().reason(),
            "no-free-space"
        );
        assert_eq!(image, before, "a refusal must leave every byte alone");
    }

    /// `scan_from == site` is the ordinary case, not a caller error.
    ///
    /// The site usually *is* the function entry, and supplying it is the
    /// documented way to turn off the IT-block blind spot. Rejecting it would
    /// make the one option that closes that hole unusable exactly where it is
    /// most wanted.
    #[test]
    fn a_decode_start_at_the_site_itself_is_accepted() {
        let mut image = image_with(&[0x01, 0x20, 0x02, 0x21]);
        let d = detour(
            &mut image,
            SITE,
            HOOK,
            DetourOptions::new().with_scan_from(SITE),
        )
        .expect("the site is a decode start like any other");
        assert_eq!(d.displaced, 4);

        // One halfword past it is still a caller error.
        let mut image = image_with(&[0x01, 0x20, 0x02, 0x21]);
        assert_eq!(
            detour(
                &mut image,
                SITE,
                HOOK,
                DetourOptions::new().with_scan_from(SITE + 2)
            )
            .unwrap_err()
            .reason(),
            "scan-start-after-site"
        );
    }

    /// Both overlap intervals are half-open.
    ///
    /// A stub beginning exactly where the displaced region ends does not
    /// overlap it — and that is the erased space *nearest* the site, which is
    /// the space a branch is most likely to reach. Refusing it throws away the
    /// placement a caller most wants.
    #[test]
    fn a_stub_that_abuts_the_displaced_region_does_not_overlap_it() {
        let mut image = vec![0u8; LEN];
        image[SITE..SITE + 4].copy_from_slice(&[0x01, 0x20, 0x02, 0x21]);
        for b in image[SITE + 4..].iter_mut() {
            *b = 0xFF;
        }
        let opts = DetourOptions::new()
            .with_stub_at(SITE as u32 + 4)
            .with_style(DetourStyle::DiscardAndJumpTo(0x200));
        let d = detour(&mut image, SITE, HOOK, opts)
            .expect("abutting the displaced region is not overlapping it");
        assert_eq!(d.stub, SITE as u32 + 4);
    }

    /// The planner's image-end bound admits a site with exactly four bytes
    /// after it, which is what `install_branch` already promises for the same
    /// offset. The two must not disagree about the same address.
    #[test]
    fn the_planner_admits_a_site_that_ends_at_the_image_end() {
        let mut image = vec![0u8; LEN];
        for b in image[0x10..0x80].iter_mut() {
            *b = 0xFF;
        }
        image[LEN - 4..].copy_from_slice(&[0x01, 0x20, 0x02, 0x21]);
        let d = detour(
            &mut image,
            LEN - 4,
            HOOK,
            DetourOptions::new().with_stub_at(0x10),
        )
        .expect("exactly four bytes of room is enough, as install_branch says");
        assert_eq!(d.resume(), LEN as u32);
    }
}

#[cfg(test)]
mod stub_address_tests {
    use super::*;

    /// A `stub_at` near the top of the address space is refused, not
    /// overflowed.
    ///
    /// `build_stub` computes intermediate addresses as `stub + out.len()`, and
    /// `stub` is the caller's `stub_at`. For a value near `u32::MAX` that add
    /// overflows — a panic in debug, a wrong address in release — and it runs
    /// before `attempt`'s `stub_end > image.len()` check, so the arithmetic
    /// has to be total on its own. The hook is placed near the stub so the
    /// `BL` is in range and execution reaches the overflowing add rather than
    /// stopping at `HookUnreachable` first.
    #[test]
    fn a_stub_at_the_top_of_memory_is_refused_not_overflowed() {
        for &(stub, hook) in &[(0xFFFF_FFFCu32, 0xFFFF_F800u32), (0xFFFF_F000, 0xFFFF_F800)] {
            let mut image = vec![0u8; 0x20];
            // movs r0, #1 / movs r1, #2 at the site, so there is code to displace.
            image[0..4].copy_from_slice(&[0x01, 0x20, 0x02, 0x21]);
            let err = detour(&mut image, 0, hook, DetourOptions::new().with_stub_at(stub))
                .expect_err("a near-top-of-memory stub cannot be written");
            assert_eq!(err.reason(), "stub-out-of-bounds", "stub {stub:#x}");
            // And nothing was written: the site still holds its original code.
            assert_eq!(&image[0..4], &[0x01, 0x20, 0x02, 0x21]);
        }
    }

    /// The same overflow through the `HookDecides` convention, whose first
    /// stub address is four bytes in (the continuation-word load) rather than
    /// at the stub base — so it is the hook-branch computation that overflows
    /// here, a different `addr` call than the `CallThenContinue` case above.
    #[test]
    fn a_top_of_memory_stub_overflows_the_hook_decides_layout_too() {
        let mut image = vec![0u8; 0x20];
        image[0..4].copy_from_slice(&[0x01, 0x20, 0x02, 0x21]);
        let err = detour(
            &mut image,
            0,
            0xFFFF_F800,
            DetourOptions::new()
                .with_stub_at(0xFFFF_FFFC)
                .with_convention(Convention::HookDecides),
        )
        .expect_err("the continuation-load offset pushes the hook branch past u32::MAX");
        assert_eq!(err.reason(), "stub-out-of-bounds");
        assert_eq!(&image[0..4], &[0x01, 0x20, 0x02, 0x21]);
    }
}

#[cfg(test)]
mod region_tests {
    use super::*;
    use crate::Fit;

    /// An image with a `push {r4, lr}` at `site` and two erased regions.
    fn image_with_two_runs() -> Vec<u8> {
        let mut image = vec![0u8; 0x600];
        image[0x100..0x104].copy_from_slice(&[0x10, 0xb5, 0x00, 0xbf]);
        for b in image[0x200..0x280].iter_mut() {
            *b = 0xff;
        }
        for b in image[0x400..0x500].iter_mut() {
            *b = 0xff;
        }
        image
    }

    /// The stub lands inside a declared region, and the run outside every
    /// declared region is not used even though it is erased and comes first.
    ///
    /// This is the property the whole-image search cannot offer: `0xff` means
    /// "looks erased", not "safe to write", and a run inside a checksummed or
    /// bootloader-owned block is indistinguishable from a spare one.
    #[test]
    fn the_stub_goes_only_where_the_caller_says_it_may() {
        let mut image = image_with_two_runs();
        // `from_ref` rather than `[a..b]`: a one-element array of `Range`
        // trips `clippy::single_range_in_vec_init`, which reads it as a
        // mistyped attempt to list the range's elements.
        let region = 0x400usize..0x500;
        let regions = core::slice::from_ref(&region);
        let d = detour_in(
            &mut image,
            0x100,
            0x300,
            regions,
            Fit::First,
            DetourOptions::default(),
        )
        .expect("a stub should fit in the declared region");
        assert!(
            (0x400..0x500).contains(&(d.stub as usize)),
            "stub at {:#x} is outside the declared region",
            d.stub
        );

        // The same image, searched without regions, uses the earlier run —
        // which is exactly the run a caller might have been protecting.
        let mut plain = image_with_two_runs();
        let p = detour(&mut plain, 0x100, 0x300, DetourOptions::default())
            .expect("the whole-image search should also succeed");
        assert!(
            (0x200..0x280).contains(&(p.stub as usize)),
            "unconstrained search should take the first run, got {:#x}",
            p.stub
        );
    }

    /// With no usable region, the failure is `NoFreeSpace` rather than a stub
    /// placed somewhere the caller did not sanction.
    #[test]
    fn no_declared_region_means_no_stub_rather_than_a_different_one() {
        let mut image = image_with_two_runs();
        // A region containing no erased run at all.
        let empty = 0x300usize..0x340;
        let deny = core::slice::from_ref(&empty);
        let err = detour_in(
            &mut image,
            0x100,
            0x300,
            deny,
            Fit::First,
            DetourOptions::default(),
        )
        .expect_err("there is no free space in the declared region");
        // Asserted through `reason()` rather than `matches!` with a
        // `{err:?}` message: a format argument is only evaluated when the
        // assertion fails, so it would be an uncovered region on every
        // passing run — and the reason string is the stronger claim anyway.
        assert_eq!(err.reason(), "no-free-space");
        // And nothing was written: the site still holds its original push.
        assert_eq!(&image[0x100..0x104], &[0x10, 0xb5, 0x00, 0xbf]);
    }

    /// An empty region list is a caller saying "nowhere is writable", and is
    /// answered as such rather than by falling back to the whole image.
    #[test]
    fn an_empty_region_list_places_nothing() {
        let mut image = image_with_two_runs();
        let err = detour_in(
            &mut image,
            0x100,
            0x300,
            &[],
            Fit::First,
            DetourOptions::default(),
        )
        .expect_err("no regions means no placement");
        assert_eq!(err.reason(), "no-free-space");
        assert_eq!(&image[0x100..0x104], &[0x10, 0xb5, 0x00, 0xbf]);
    }

    /// The hook's Thumb bit is masked off, as it is for [`detour`].
    ///
    /// A Thumb function pointer conventionally has bit 0 set — that is how the
    /// architecture distinguishes a Thumb entry point from an ARM one — so a
    /// caller passing a pointer it read out of a vector table or a symbol
    /// passes an odd address. The branch encoding has no room for that bit and
    /// the target must be halfword-aligned, so it is cleared. Without this
    /// test nothing distinguished `hook & !1` from `hook`, `hook | !1` or
    /// `hook ^ !1`, because every other test here passes an already-even hook.
    #[test]
    fn an_odd_hook_address_is_masked_to_its_halfword_boundary() {
        let region = 0x400usize..0x500;
        let regions = core::slice::from_ref(&region);
        let mut odd = image_with_two_runs();
        let from_odd = detour_in(
            &mut odd,
            0x100,
            0x301,
            regions,
            Fit::First,
            DetourOptions::default(),
        )
        .expect("an odd hook is a Thumb function pointer, not an error");

        let mut even = image_with_two_runs();
        let from_even = detour_in(
            &mut even,
            0x100,
            0x300,
            regions,
            Fit::First,
            DetourOptions::default(),
        )
        .expect("the same hook, already even");

        assert_eq!(
            from_odd.stub, from_even.stub,
            "the Thumb bit must not change where the stub goes"
        );
        assert_eq!(
            odd, even,
            "0x301 and 0x300 must produce byte-identical images"
        );
    }

    /// A region that lies entirely behind the search start is skipped, not
    /// clamped to it.
    ///
    /// `search_start` and the region list are two different statements — "do
    /// not look before here" and "these are writable" — and the intersection
    /// of them can be empty for a given region without being empty overall.
    /// Getting this wrong would either place a stub before the caller's start
    /// or drop the regions after it.
    #[test]
    fn a_region_behind_the_search_start_is_skipped_not_clamped() {
        let mut image = image_with_two_runs();
        let d = detour_in(
            &mut image,
            0x100,
            0x300,
            &[0x200..0x280, 0x400..0x500],
            Fit::First,
            DetourOptions::default().with_search_start(0x300),
        )
        .expect("the later region is still usable");
        assert!(
            (0x400..0x500).contains(&(d.stub as usize)),
            "stub at {:#x} should be in the region after the search start",
            d.stub
        );
    }

    /// `Fit::Largest` picks the bigger declared run, not the first.
    #[test]
    fn fit_largest_reaches_past_the_first_usable_run() {
        let mut image = image_with_two_runs();
        let d = detour_in(
            &mut image,
            0x100,
            0x300,
            &[0x200..0x280, 0x400..0x500],
            Fit::Largest,
            DetourOptions::default(),
        )
        .expect("a stub should fit");
        assert!(
            (0x400..0x500).contains(&(d.stub as usize)),
            "Fit::Largest should take the 0x100-byte run, got {:#x}",
            d.stub
        );
    }
}

#[cfg(test)]
mod compare_branch_rewrite_tests {
    use super::*;

    /// An image whose site begins with a `CBZ` that cannot reach its target
    /// from any stub, followed by code that clobbers every flag on both paths.
    fn image_with_a_dead_flag_cbz() -> Vec<u8> {
        let mut image = vec![0u8; 0x600];
        // 0x100: cbz r0, 0x108   (verified with the decoder, not by hand)
        // 0x102: adds r1, r2, r3
        // 0x104: adds r4, r5, r6
        // 0x106: nop
        // 0x108: adds r4, r5, r6
        // 0x10a: bx lr
        image[0x100..0x10c].copy_from_slice(&[
            0x10, 0xb1, 0xd1, 0x18, 0xac, 0x19, 0x00, 0xbf, 0xac, 0x19, 0x70, 0x47,
        ]);
        for b in image[0x400..0x500].iter_mut() {
            *b = 0xff;
        }
        image
    }

    /// Off by default: a displaced `CBZ` is still refused, exactly as before.
    ///
    /// This is the compatibility claim. The rewrite changes flag behaviour, so
    /// a caller who has not asked for it must not get it.
    #[test]
    fn a_displaced_compare_branch_is_refused_unless_rewriting_is_asked_for() {
        let mut image = image_with_a_dead_flag_cbz();
        let err = detour(&mut image, 0x100, 0x300, DetourOptions::default())
            .expect_err("cbz cannot reach a stub");
        // Asserted on the rendered message rather than by `matches!` with a
        // `{err:?}` note or a `panic!` arm. Both of those are only reached
        // when the test fails, so under this crate's 100% gate they are dead
        // regions on every passing run; `Display` is computed either way.
        assert_eq!(err.reason(), "relocate");
        let text = err.to_string();
        assert!(text.contains("forward-only-branch"));
    }

    /// Asked for, and the flags are dead, so the patch goes in.
    #[test]
    fn a_dead_flag_compare_branch_is_rewritten_when_asked() {
        let mut image = image_with_a_dead_flag_cbz();
        let d = detour(
            &mut image,
            0x100,
            0x300,
            DetourOptions::default().with_compare_branch_rewriting(true),
        )
        .expect("the flags are dead, so the rewrite is sound");

        // The stub holds a `cmp` where the `cbz` was.
        // Disassembled with the public walker rather than a hand-rolled loop:
        // a `None => break` arm never runs on a passing test and would be an
        // uncovered region under the 100% gate.
        let text = crate::isa::disassemble(&image, d.stub as usize, d.stub, 8).join("\n");
        assert!(text.contains("cmp r0, #0"));
        // ...and the branch it pairs with, carrying the condition `CBZ`
        // implied and the target the `CBZ` had.
        assert!(text.contains("beq"));
        // The `CBZ` itself is gone from the stub.
        assert!(!text.contains("cbz"));
    }

    /// Asked for, but a flag is live, so it is still refused — and the error
    /// says which flag rather than just "no".
    #[test]
    fn a_live_flag_still_refuses_even_when_rewriting_is_asked_for() {
        let mut image = image_with_a_dead_flag_cbz();
        // Replace the fall-through `adds` with `ands r1, r2` (leaves V) and
        // the next instruction with `bvs`, so V survives and is then read.
        image[0x102..0x106].copy_from_slice(&[0x11, 0x40, 0xfd, 0xd6]);
        let err = detour(
            &mut image,
            0x100,
            0x300,
            DetourOptions::default().with_compare_branch_rewriting(true),
        )
        .expect_err("V is live, so the rewrite is unsound");
        assert_eq!(err.reason(), "relocate");
        let text = err.to_string();
        assert!(text.contains("flags-live"));
        // The message names which flags, because "only V" is the common and
        // surprising answer — every `S`-suffixed logical op leaves V alone.
        assert!(text.contains("v: true"));
    }
}
