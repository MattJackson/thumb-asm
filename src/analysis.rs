//! Image analysis — the questions a Thumb patching session actually asks.
//!
//! [`crate`]'s four verbs (find / read / modify / create) are the primitives.
//! This module is the layer above them: the handful of derived questions that
//! every consumer of a Thumb patching library ends up writing by hand, each of
//! which has exactly one correct answer and several plausible wrong ones.
//!
//! * **Where can I put code?** — [`crate::find_free_space`], which takes the alignment
//!   [`crate::Asm::finish`] requires instead of leaving the caller to round up
//!   afterwards and hope the run is long enough.
//! * **Who references this address?** — [`xrefs`], instruction-accurate, over
//!   all four ways a Thumb image can name an address.
//! * **Where does this function start?** — [`function_start`], a documented
//!   heuristic rather than a promise.
//! * **What does this `ldr` load?** — [`literal_value`], which resolves
//!   `Align(PC,4)` through the decoder instead of by hand.
//! * **How do I blank code I am replacing?** — [`nop_fill`], because `0x0000`
//!   is `movs r0, r0` and writes the flags.
//! * **What does this function span, and where does it leave?** —
//!   [`reachable`].
//! * **The target is too far for any branch encoding** — [`veneer`].
//!
//! # On instruction-accuracy
//!
//! A Thumb stream has no self-synchronising structure: the only length rule is
//! `hw1[15:11]` (ARM DDI 0403E.e A5.1), so a scan that starts at the wrong
//! halfword stays wrong until it happens to fall back into phase. Every scan
//! here that asks a question *about instructions* therefore walks the stream
//! with [`isa::Decoder`] from a known start, resynchronising past undefined
//! encodings the way [`isa::disassemble`] does — never at a fixed stride. The
//! one deliberate exception is [`XrefKind::LiteralPool`], which asks a question
//! about *data*, where there is no decode to be accurate about; see [`xrefs`].
//!
//! # The Thumb bit
//!
//! A code address in a Thumb image is carried two ways: even, as a branch
//! encoding's halfword-aligned displacement, and odd, as a function pointer
//! whose bit 0 selects Thumb state for `bx`/`blx`/`LoadWritePC`. Everything in
//! this module that compares addresses masks bit 0 off **both** sides first, so
//! either form may be passed and a stored-odd handler pointer matches the
//! even entry address it names. Where a function *produces* a pointer that
//! hardware will branch through — [`veneer`] — it sets bit 0 instead, and says
//! so.

use crate::isa::{self, Decoder, Insn, ItState, Mem, Operand, Reg};

/// `NOP` T1 — `1011 1111 0000 0000` (ARM DDI 0403E.e A7.7.88).
const NOP_T1: u16 = 0xBF00;

/// How an image names an address.
///
/// Ordered so that a sort of [`Xref`]s by `(at, kind)` is deterministic; the
/// order itself carries no meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum XrefKind {
    /// A direct call — `bl <label>` or `blx <label>`. Control is expected back
    /// at the following instruction, so the reference is also a caller.
    Call,
    /// A direct branch — `b`, `b<cond>` in either width, or `cbz`/`cbnz`.
    /// Control is *not* expected back.
    Branch,
    /// A 4-byte data word equal to the address: a literal-pool constant, a
    /// dispatch-table handler pointer, an interrupt-vector entry. Compared with
    /// bit 0 masked, since a code pointer is conventionally stored odd.
    LiteralPool,
    /// An address materialised from `pc` by arithmetic — `adr rd, <label>` in
    /// any of its three encodings. The address ends up in a register, and what
    /// happens to it afterwards is not visible here.
    PcRelativeAddress,
}

/// One reference to an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Xref {
    /// File offset of the reference: of the instruction for [`XrefKind::Call`],
    /// [`XrefKind::Branch`] and [`XrefKind::PcRelativeAddress`], of the 4-byte
    /// word itself for [`XrefKind::LiteralPool`].
    pub at: usize,
    /// Which of the four ways this reference names the address.
    pub kind: XrefKind,
    /// The mnemonic that produced an instruction reference (`"bl"`, `"b"`,
    /// `"adr"`, …), or `None` for a [`XrefKind::LiteralPool`] word, which is
    /// data and has no mnemonic.
    ///
    /// Carried because the distinction inside a kind is often the one that
    /// matters: `bl` and `blx` are both [`XrefKind::Call`] but only the latter
    /// changes instruction set, and a `cbz` reported as a [`XrefKind::Branch`]
    /// is a forward-only, unconditionally-narrow edge that a rewriter must
    /// treat differently from a `b.w`.
    pub via: Option<&'static str>,
}

/// Every reference to `target` in `image`, in ascending offset order.
///
/// This supersedes [`crate::find_bl_sites`], which answers a strictly smaller
/// question — direct `BL` only — and answers it unsoundly.
///
/// # The four ways an image names an address
///
/// 1. **A direct call**, `bl`/`blx <label>` → [`XrefKind::Call`].
/// 2. **A direct branch**, `b`, `b<cond>` (T1 and the wide T3), `b.w` (T4) and
///    the compare-and-branch pair `cbz`/`cbnz` → [`XrefKind::Branch`]. A tail
///    call is spelled as a branch and lands here, not in `Call`; that is the
///    truth about the encoding, and the caller's to interpret.
/// 3. **A stored pointer**, a 4-byte word equal to the target →
///    [`XrefKind::LiteralPool`]. This is how a handler reaches a table-driven
///    dispatcher, how a vector table names an interrupt handler, and how any
///    address too far or too awkward for an immediate reaches the code that
///    uses it.
/// 4. **A pc-relative address**, `adr rd, <label>` →
///    [`XrefKind::PcRelativeAddress`].
///
/// # Why the old scan was unsound, and this one is not
///
/// [`crate::find_bl_sites`] tests `BL`'s bit pattern at every even offset. Its
/// own documentation admits the consequence, and it is worse than it sounds:
/// the second halfword of a 32-bit instruction sits at an even offset too, and
/// `BL`'s first halfword is only constrained by `hw1[15:11] == 0b11110`, a test
/// one halfword in thirty-two passes by chance. A `tbb [rn, rm]` — hw2
/// `1111 0000 000H Rm` — matches it outright, and whatever halfword follows
/// decides the phantom target. The scan therefore reports call sites that are
/// not instructions at all, at offsets no processor will ever execute from, and
/// a caller that patches one corrupts an unrelated instruction.
///
/// Walking with [`isa::Decoder`] removes the whole class: the walk only ever
/// asks "what is this instruction" at an offset it has arrived at *as* an
/// instruction boundary, resynchronising by one halfword past an undefined
/// encoding rather than stopping (a firmware image is full of data, and a
/// decoder that halts at the first non-instruction is useless on one). See this
/// module's tests, which assert the divergence on exactly such a phantom.
///
/// The `LiteralPool` kind is the honest exception. A stored pointer is data:
/// there is no instruction boundary to be accurate about, so those are found by
/// testing every 4-aligned word. A word-aligned run of four bytes inside the
/// code stream can coincidentally equal the target, and will be reported. That
/// is a property of scanning data, not a phase error — corroborate with
/// [`function_start`] or [`reachable`] when it matters.
///
/// # The Thumb bit
///
/// `target` may be passed with bit 0 set or clear; it is masked off, and so is
/// every candidate. A handler pointer stored as `0x0001_2345` therefore matches
/// a query for the function at `0x0001_2344`, which is the whole point — see
/// the module documentation.
///
/// ```
/// use thumb_asm::analysis::{xrefs, XrefKind};
/// use thumb_asm::{install_branch, BranchKind};
///
/// let mut image = vec![0x00u8; 0x100];
/// // A call to 0x80 at offset 0x10 …
/// install_branch(&mut image, 0x10, BranchKind::Bl, 0x80).unwrap();
/// // … and a pointer to it, stored odd, at offset 0x40.
/// image[0x40..0x44].copy_from_slice(&0x81u32.to_le_bytes());
///
/// let refs = xrefs(&image, 0x80);
/// assert_eq!(refs.len(), 2);
/// assert_eq!((refs[0].at, refs[0].kind, refs[0].via), (0x10, XrefKind::Call, Some("bl")));
/// assert_eq!((refs[1].at, refs[1].kind, refs[1].via), (0x40, XrefKind::LiteralPool, None));
/// ```
pub fn xrefs(image: &[u8], target: u32) -> Vec<Xref> {
    let want = target & !1;
    let mut out: Vec<Xref> = Vec::new();

    // Kinds 1, 2 and 4: instruction-derived, so walked instruction-accurately
    // from offset 0 with the flat offset == address mapping the rest of the
    // crate uses.
    let mut d = Decoder::at(image, 0, 0);
    loop {
        let at = d.pos();
        if at + 2 > image.len() {
            break;
        }
        let insn = match d.next() {
            Some(i) => i,
            None => {
                // Undefined encoding — almost always data. Resynchronise by a
                // halfword rather than abandoning the rest of the image.
                // Spelled as an associated-function call because `Decoder` is
                // an `Iterator`, whose `skip` adaptor would consume it.
                Decoder::skip(&mut d, 2);
                continue;
            }
        };
        if let Some(kind) = xref_kind(&insn, want) {
            out.push(Xref {
                at,
                kind,
                via: Some(insn.mnemonic),
            });
        }
    }

    // Kind 3: stored pointers. Data, so scanned at word alignment.
    let mut p = 0usize;
    while p + 4 <= image.len() {
        if crate::read_u32(image, p) & !1 == want {
            out.push(Xref {
                at: p,
                kind: XrefKind::LiteralPool,
                via: None,
            });
        }
        p += 4;
    }

    out.sort_by_key(|x| (x.at, x.kind));
    out
}

/// Classify `insn` as a reference to `want` (already bit-0 masked), if it is
/// one.
fn xref_kind(insn: &Insn, want: u32) -> Option<XrefKind> {
    // `Insn::branch_target` documents an overload: a pc-relative *literal*
    // access also carries an `Operand::Target`, holding the address of the pool
    // word rather than a destination. The documented discriminator is the
    // presence of an `Operand::Mem`, so apply it — otherwise every
    // `ldr rt, [pc, #imm]` whose pool word happens to sit at `target` would be
    // reported as a branch there, and `ldr pc, [pc, #imm]` — a real branch —
    // would be reported as jumping to the word instead of through it.
    if insn
        .operands
        .as_slice()
        .any(|o| matches!(o, Operand::Mem(_)))
    {
        return None;
    }
    if insn.branch_target()? & !1 != want {
        return None;
    }
    if insn.is_call() {
        Some(XrefKind::Call)
    } else if insn.is_branch() {
        Some(XrefKind::Branch)
    } else {
        // `ADR`, and nothing else. Only four kinds of encoding carry an
        // `Operand::Target`: the direct branches and calls (both above), the
        // `ADR` forms, and the pc-relative literal accesses —
        // `ldr`/`ldrd`/`ldc` (literal) — which carry an `Operand::Mem` beside
        // the target and returned above. So this arm is `ADR`; there is no
        // fifth case to fall through to, and
        // `every_target_carrying_encoding_is_a_branch_a_call_or_an_adr`
        // sweeps the decoder to keep it that way.
        Some(XrefKind::PcRelativeAddress)
    }
}

/// Scan backwards from `addr` for the nearest function prologue, within
/// `max_scan` bytes.
///
/// Returns the offset of the first prologue at or below `addr`, or `None` if
/// none is found within the window. `addr` has bit 0 masked off, so a handler
/// pointer read straight out of a dispatch table or vector can be passed
/// as-is — which is the motivating use: *given a code address somewhere inside
/// a function, name the function's entry point*, so the entry can be detoured,
/// relocated, or simply reported.
///
/// # What counts as a prologue
///
/// * `push {…, lr}` T1 — `1011 0101 register_list`, i.e. `0xB5xx`
///   (ARM DDI 0403E.e A7.7.99). The `lr` bit is what makes it a prologue rather
///   than an ordinary register save.
/// * `push.w {…, lr}` T2, which is `stmdb sp!, {…, lr}` — `hw1 == 0xE92D` with
///   `hw2` bit 14 (`lr`) set. A function saving a high register, or more than
///   the narrow form's `r0`–`r7` plus `lr`, gets this one.
/// * `push.w {lr}` T3, which is `str lr, [sp, #-4]!` — `0xF84D 0xED04`. A
///   Thumb-2 compiler emits this for a function whose only callee-saved need is
///   the link register.
///
/// # This is a heuristic, and here is exactly what it cannot promise
///
/// [`crate::prologue_is_push_lr`] is the same idea in its cheapest form — does a
/// prologue appear in the next few halfwords — and shares every caveat below.
///
/// * **A leaf function need not have a prologue at all.** A function that calls
///   nothing does not have to save `lr`, and a small one saves no registers
///   either; its first instruction is ordinary work. There is no marker to find,
///   so this function will walk straight past the entry and either return the
///   *previous* function's prologue or nothing. A `None` does not mean "no
///   function here".
/// * **Backwards scanning through Thumb is ambiguous by construction.** Nothing
///   in the encoding says where an instruction begins; the only length rule runs
///   forwards (`hw1[15:11]`, A5.1). So the scan steps by halfwords, and a
///   halfword matching `0xB5xx` may be the *second* halfword of a 32-bit
///   instruction — `strd r11, r5, [rn, #imm]` encodes `hw2` as
///   `Rt:Rt2:imm8`, which is `0xB5xx` for `Rt == r11`, `Rt2 == r5` — and will be
///   reported as a prologue. The documented behaviour is: *the nearest
///   halfword-aligned match at or below `addr`*, whatever it is a halfword of.
///   The module's tests pin this rather than pretend otherwise.
/// * **The window is a guess.** `max_scan` bounds the walk; too small misses a
///   long function's entry, too large reaches into the previous function.
///
/// What it *is* reliable for: the overwhelmingly common case of a
/// compiler-emitted non-leaf function reached through a pointer, where the
/// prologue is real, near, and the first thing in the function. When the answer
/// has to be trusted, corroborate it — a real entry is usually also the target
/// of a [`XrefKind::Call`] in [`xrefs`], and [`reachable`] from it should cover
/// `addr`.
///
/// ```
/// use thumb_asm::analysis::function_start;
///
/// // push {r4, lr}; movs r0, #1; bx lr
/// let image = [0x10, 0xB5, 0x01, 0x20, 0x70, 0x47];
/// // From inside the function, with the Thumb bit set, as a pointer would be.
/// assert_eq!(function_start(&image, 0x05, 16), Some(0));
/// // Nothing within the window.
/// assert_eq!(function_start(&image, 0x04, 2), None);
/// ```
pub fn function_start(image: &[u8], addr: usize, max_scan: usize) -> Option<usize> {
    let addr = addr & !1;
    let lo = addr.saturating_sub(max_scan);
    let mut p = addr;
    loop {
        if is_prologue(image, p) {
            return Some(p);
        }
        if p < 2 || p < lo + 2 {
            return None;
        }
        p -= 2;
    }
}

/// Whether the halfword(s) at `at` are one of the three prologue forms
/// [`function_start`] documents.
fn is_prologue(image: &[u8], at: usize) -> bool {
    let hw1 = match crate::try_read_u16(image, at) {
        Some(h) => h,
        None => return false,
    };
    // `PUSH {…, lr}` T1 — `1011 0101 register_list` (A7.7.99).
    if hw1 & 0xFF00 == 0xB500 {
        return true;
    }
    // `PUSH.W {…, lr}` T2 == `STMDB sp!, {…, lr}` — bit 14 of the list is `lr`.
    if hw1 == 0xE92D {
        return matches!(crate::try_read_u16(image, at + 2), Some(hw2) if hw2 & 0x4000 != 0);
    }
    // `PUSH.W {lr}` T3 == `STR lr, [sp, #-4]!`.
    if hw1 == 0xF84D {
        return crate::try_read_u16(image, at + 2) == Some(0xED04);
    }
    false
}

/// Resolve what the `ldr rt, [pc, #imm]` at `at` actually loads.
///
/// Returns the 4-byte little-endian word at the literal-pool address the
/// instruction names, or `None` when the bytes at `at` are not a pc-relative
/// word load, or when the pool address is outside the image.
///
/// # Why this is a function and not three lines at the call site
///
/// The three lines are wrong roughly half the time. The pool address is
/// `Align(PC, 4) + imm`, where Thumb's `PC` reads as *the instruction's address
/// plus four* (A7.7.44's `base = Align(PC,4)`) — so at an address that is 2 mod
/// 4 the `Align` drops two bytes and the hand-written `(at + 4) + imm * 4` is
/// off by two, silently, in a way that reads correctly at every 4-aligned `ldr`
/// and fails at every other one. The decoder already does this arithmetic and
/// hands out the resolved address as an [`Operand::Target`]; this function just
/// reads the word there.
///
/// Going through the decoder also means both encodings work for free: the
/// narrow `LDR (literal)` T1 (`01001 Rt imm8`, unsigned `imm8 * 4`) and the wide
/// T2 (`ldr.w rt, [pc, #±imm12]`, A7.7.44), whose `U` bit can make the offset
/// *negative* — a pool behind the instruction, which no `(at + 4) + imm` ever
/// finds.
///
/// Only the word-sized `ldr` qualifies. `ldrb`/`ldrh`/`ldrsb`/`ldrsh` have
/// literal forms too, but they do not load a `u32` and there is no honest
/// widening to report; they yield `None`.
///
/// ```
/// use thumb_asm::analysis::literal_value;
///
/// // `ldr r0, [pc, #4]` at 0x00 and at 0x02 both resolve through Align(PC,4)
/// // to the same pool word at 0x08.
/// let mut image = vec![0u8; 0x10];
/// image[0x00..0x02].copy_from_slice(&0x4801u16.to_le_bytes()); // ldr r0, [pc, #4]
/// image[0x02..0x04].copy_from_slice(&0x4801u16.to_le_bytes()); // ldr r0, [pc, #4]
/// image[0x08..0x0C].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
///
/// assert_eq!(literal_value(&image, 0x00), Some(0xDEAD_BEEF));
/// assert_eq!(literal_value(&image, 0x02), Some(0xDEAD_BEEF));
/// ```
pub fn literal_value(image: &[u8], at: usize) -> Option<u32> {
    let insn = isa::decode_at_with(image, at, at as u32, false)?;
    if insn.mnemonic != "ldr" {
        return None;
    }
    // A literal load, not an ordinary one: base `pc`, no register index …
    let literal_form = insn
        .operands
        .as_slice()
        .any(|o| matches!(o, Operand::Mem(Mem { base, index: None, .. }) if base == Reg::PC));
    // … and the pool address the decoder already resolved for it.
    let pool = insn.operands.as_slice().find_map(|o| match o {
        Operand::Target(t) => Some(t),
        _ => None,
    });
    // The two are asked for together because they arrive together: the decoder
    // emits the resolved `Operand::Target` for exactly the forms whose
    // `Operand::Mem` is `[pc, #imm]` with no index (A7.7.44's
    // `base = Align(PC,4)`). Pairing them means the "not a pc-relative word
    // load" answer is one arm rather than two, and no arm claims a shape the
    // decoder cannot produce.
    match (literal_form, pool) {
        (true, Some(pool)) => crate::try_read_u32(image, pool as usize),
        // An ordinary `ldr`, or `ldr rt, [pc, rm]`, whose address is not
        // statically known.
        _ => None,
    }
}

/// Fill `image[at..at + len]` with canonical 16-bit `NOP`s (`0xBF00`).
///
/// # Why not zeros
///
/// `0x0000` is not a hole, it is `movs r0, r0` — `MOV (register)` T2, which
/// **writes N and Z** (A7.7.77; see [`crate::Asm::movs_reg`]). A run of zeroed
/// halfwords is therefore a run of real instructions that clobbers the flags,
/// and a detour that lands just after one, or a conditional branch whose `cmp`
/// it separates, reads the wrong condition. The failure is silent and the bytes
/// look inert, which is the worst combination. `NOP` T1 is architecturally a
/// hint: it changes no register and no flag.
///
/// This also makes the filled region *readable*: disassembling it yields `nop`
/// rather than a plausible-looking instruction sequence, so a later reverse
/// engineer can see at a glance that the range was deliberately blanked.
///
/// # Odd lengths, and odd offsets: refused
///
/// There is no 1-byte Thumb instruction, so there is no correct way to fill a
/// trailing odd byte — writing half a `NOP` leaves a byte that pairs with
/// whatever follows to form some other instruction entirely, which is exactly
/// the bug this function exists to prevent. Likewise an odd `at` would place
/// halfwords off the halfword grid, and Thumb instructions are halfword aligned
/// unconditionally. Both are caller bugs rather than input-dependent
/// conditions, so both panic rather than silently doing something defensible;
/// a caller that genuinely wants to blank as much as fits should round down
/// itself: `nop_fill(image, at, len & !1)`.
///
/// # Panics
///
/// Panics if `at` is odd, if `len` is odd, or if `at + len` is past the end of
/// `image` — the same "the offset came from a bounds-checked structure"
/// contract as [`crate::write()`].
///
/// ```
/// use thumb_asm::analysis::nop_fill;
/// use thumb_asm::isa::Decoder;
///
/// let mut image = vec![0u8; 8]; // eight bytes of `movs r0, r0`
/// nop_fill(&mut image, 2, 4);
/// assert_eq!(&image[2..6], &[0x00, 0xBF, 0x00, 0xBF]);
/// assert!(Decoder::at(&image, 2, 2)
///     .take(2)
///     .all(|i| i.mnemonic == "nop"));
/// ```
pub fn nop_fill(image: &mut [u8], at: usize, len: usize) {
    assert!(
        at % 2 == 0,
        "nop_fill offset {at} is odd; Thumb instructions are halfword aligned"
    );
    assert!(
        len % 2 == 0,
        "nop_fill length {len} is odd; there is no 1-byte Thumb instruction"
    );
    assert!(
        at + len <= image.len(),
        "nop_fill range {at}..{} is past the end of a {}-byte image",
        at + len,
        image.len()
    );
    for hw in image[at..at + len].chunks_exact_mut(2) {
        hw.copy_from_slice(&NOP_T1.to_le_bytes());
    }
}

/// What a control-flow walk from an entry point could see.
///
/// Produced by [`reachable`]. The three lists are deliberately separate facts:
/// what was reached, what could not be followed, and whether the walk itself
/// ran out of road.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reach {
    /// File offset of every instruction reached, ascending and deduplicated.
    pub insns: Vec<usize>,
    /// One byte past the highest byte reached — an over-approximate *end* of
    /// the function, usable as an extent when paired with the entry offset.
    ///
    /// Over-approximate because a forward branch over an interleaved literal
    /// pool, or a tail call into a neighbouring function, pulls this past the
    /// function's real end. Under no circumstances is it an under-approximation
    /// of the straight-line body.
    pub end: usize,
    /// Offsets of reached branches whose destination the walk could not
    /// follow, ascending.
    ///
    /// This is *not* an error list. It contains the ordinary function return
    /// (`bx lr`, `pop {…, pc}`) as readily as the genuinely unknown
    /// (`bx r3`, `tbb`, a ThumbEE handler branch) and the out-of-image. Telling
    /// a return from an unknown edge is the caller's judgement; this crate's
    /// [`Insn`] vocabulary reports both as "branches with no static target",
    /// which is the honest static answer.
    pub unresolved: Vec<usize>,
    /// Whether the walk ran to completion.
    ///
    /// `false` means it hit an undefined encoding or exhausted `limit`, so the
    /// other fields are a lower bound on what is really reachable. Note that
    /// `complete` is about the **walk**, not the graph: a walk that runs to
    /// completion still has `unresolved` edges — every function that returns
    /// has at least one.
    pub complete: bool,
}

/// Walk control flow forwards from `entry`, following every statically-known
/// edge, for at most `limit` instructions.
///
/// This is the "what does this function actually span" question, and it is
/// asked constantly: before relocating a prologue, before overwriting a region,
/// before believing that a pointer names a function at all. The straight-line
/// approximation everyone writes first — decode until a `bx lr` — is wrong for
/// any function whose last instruction is not the return, which is most of them
/// once the compiler has hoisted an early-exit or laid the epilogue out before
/// a cold path.
///
/// # What is and is not followed
///
/// * A direct branch with a known target (`b`, `b<cond>`, `b.w`, `cbz`,
///   `cbnz`) is followed.
/// * A **call is not followed** — `bl`/`blx <label>` names a different
///   function, and the walk resumes at the return address instead. Follow it
///   yourself by calling this again on the target.
/// * A conditional instruction — one carrying a condition of its own, or from
///   an enclosing `IT` block, plus `cbz`/`cbnz`/`chka`, which are conditional
///   without carrying one — contributes *both* its target and its fall-through.
/// * Anything with no statically-known destination ends that path and is
///   recorded in [`Reach::unresolved`]. That covers returns and genuinely
///   indirect branches alike; see there.
/// * A literal-load `Operand::Target` is never mistaken for a destination — see
///   [`Insn::branch_target`]'s documented overload — so `ldr pc, [pc, #imm]`
///   (which is how a [`veneer`] branches) is correctly `unresolved` rather than
///   "branches to the pool word".
///
/// # Over-approximation, stated plainly
///
/// A tail call is encoded as a branch and will be followed into the callee, so
/// [`Reach::end`] can run past the function. Interleaved literal pools are
/// stepped over as data would be — the walk never decodes bytes it has not
/// reached as an instruction, but a forward branch across a pool leaves the
/// pool out of `insns` while `end` still spans it. And `complete: false` means
/// the result is a lower bound, nothing more.
///
/// ```
/// use thumb_asm::analysis::reachable;
///
/// // 0: cbz r0, +6   2: movs r0, #1   4: bx lr   6: movs r0, #0   8: bx lr
/// let image = [0x08, 0xB1, 0x01, 0x20, 0x70, 0x47, 0x00, 0x20, 0x70, 0x47];
/// let r = reachable(&image, 0, 64);
/// assert!(r.complete);
/// assert_eq!(r.insns, vec![0, 2, 4, 6, 8]); // both arms, past the first `bx lr`
/// assert_eq!(r.end, 10);
/// assert_eq!(r.unresolved, vec![4, 8]); // the two returns
/// ```
pub fn reachable(image: &[u8], entry: usize, limit: usize) -> Reach {
    let mut out = Reach {
        complete: true,
        ..Reach::default()
    };
    // `visited` is a `BTreeSet` rather than a sorted `Vec`: it is only ever
    // asked "have I been here" and "how many", never iterated as output, and a
    // sorted `Vec` pays an O(k) memmove per newly-seen offset. That is fine for
    // one function body — which is what the walk is usually pointed at — but
    // `limit` is the caller's number, and a caller sweeping a whole
    // multi-megabyte image makes it O(k^2) for no benefit.
    //
    // The output lists stay `Vec`s: `out.insns` holds only offsets that decoded
    // and `out.unresolved` only those with an indirect edge, both in the order
    // the walk found them.
    let mut visited: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    // Each pending offset carries the `ITSTATE` in force when control arrives
    // there. It has to travel with the offset rather than be recomputed: an
    // instruction's conditionality can come from an `IT` two instructions
    // back, which a walk that jumps around the image cannot see by looking at
    // the instruction alone.
    //
    // `visited` is still keyed on the offset alone, so an offset reached first
    // with one state and later with another is analysed only under the first.
    // That needs the same instruction to be inside an `IT` block on one path
    // and outside it on another, which a compiler does not emit and an
    // assembler cannot write without overlapping the block.
    let mut work: Vec<(usize, ItState)> = vec![(entry & !1, ItState::INACTIVE)];

    while let Some((at, it)) = work.pop() {
        if !visited.insert(at) {
            continue;
        }
        if visited.len() > limit {
            out.complete = false;
            break;
        }
        let insn = match isa::decode_at_with(image, at, at as u32, false) {
            Some(i) => i,
            None => {
                // Data, or an encoding this crate does not know. Either way the
                // walk cannot honestly continue down this path.
                out.complete = false;
                continue;
            }
        };
        // `at` cannot already be in `insns`: `visited` above admits each offset
        // exactly once, and only offsets that decoded reach this line. The
        // search is for the insertion *position*, which is what keeps `insns`
        // ascending while the walk itself runs depth-first.
        let i = out.insns.binary_search(&at).unwrap_or_else(|i| i);
        out.insns.insert(i, at);
        out.end = out.end.max(at + insn.len());

        // The state the *next* instruction runs under: an `IT` installs a new
        // one, anything else advances the current one. `ITAdvance()` shifts
        // across the cond/mask boundary, which is what inverts an else-arm, so
        // this cannot be approximated by counting instructions.
        let next_it = if insn.mnemonic.starts_with("it") {
            // Indexed directly rather than through `get`: the offset just
            // decoded, so both bytes are in range, and a `None` arm here
            // would be a branch no input can reach.
            //
            // Mutation reports `at + 1` -> `at * 1` as a survivor here and it
            // is an *equivalent* mutant, not a gap: `it_state_from` reads the
            // condition from `hw1[7:4]` and the mask from `hw1[3:0]`, both of
            // which live in the low byte. The high byte it would stop reading
            // is `1011 1111`, the opcode, which the function never looks at.
            // No test can distinguish the two programs.
            isa::it_state_from(u16::from_le_bytes([image[at], image[at + 1]]))
        } else {
            it.advance()
        };

        let mut push = |t: usize, state: ItState, out: &mut Reach| {
            if t + 2 <= image.len() {
                work.push((t, state));
            } else {
                out.complete = false;
            }
        };

        // Conditional from its own encoding, from an enclosing `IT` block, or
        // inherently (`cbz`/`cbnz`/`chka` test a register and carry no
        // condition field). All three mean the fall-through is live.
        let conditional = insn.cond.is_some()
            || it.current().is_some()
            || matches!(insn.mnemonic, "cbz" | "cbnz" | "chka");
        if insn.is_branch() && !insn.is_call() {
            // A `Target` alongside an `Operand::Mem` is the address of a
            // literal-pool word, not a destination — `Insn::branch_target`'s
            // documented overload, and exactly the shape of `ldr pc, [pc, #imm]`.
            let has_mem = insn
                .operands
                .as_slice()
                .any(|o| matches!(o, Operand::Mem(_)));
            match insn.branch_target() {
                // A branch is only ever the *last* instruction of an `IT`
                // block (A7.7.38), so its target is reached with `ITSTATE`
                // clear however the block was spelled.
                Some(t) if !has_mem => push(t as usize & !1, ItState::INACTIVE, &mut out),
                _ => {
                    // Same insertion-position search as `insns` above, and
                    // unique for the same reason.
                    let i = out.unresolved.binary_search(&at).unwrap_or_else(|i| i);
                    out.unresolved.insert(i, at);
                }
            }
        }
        // Fall through unless control definitely leaves: an unconditional
        // branch that is not a call.
        if !insn.is_branch() || insn.is_call() || conditional {
            push(at + insn.len(), next_it, &mut out);
        }
    }

    out
}

/// Encode an 8-byte **veneer**: an absolute, unlimited-range jump to `target`,
/// to be placed at 4-aligned file offset `at`.
///
/// Returns `ldr.w pc, [pc, #0]` (`LDR (literal)` T2, A7.7.44) followed by the
/// 4-byte target word, or `None` if `at` is not 4-aligned.
///
/// # Why this exists
///
/// Every direct branch encoding Thumb has is displacement-limited: ±2046 bytes
/// for `B` T2, ±1 MB for `B<cond>` T3, ±16 MB for `BL` T1 and `B.W` T4. Past
/// that there is no encoding, and [`crate::encode_bl`] and
/// [`crate::encode_b_wide`] correctly return `None` — which is exactly when a
/// patch is most likely to need to go somewhere: injected code lives in
/// whatever erased flash the image has, and that can be at the far end of a
/// large image from the site being hooked. The standard answer, and what a
/// linker emits for the same problem, is a veneer: a short stub that loads the
/// destination from an adjacent word and writes it straight to `pc`.
///
/// The indirection costs one word of storage and one memory read, and in
/// exchange the range is the whole 32-bit address space. Point a short branch
/// at the veneer, and the veneer at the real target.
///
/// # The two things that make it wrong when hand-written
///
/// * **Alignment.** `LDR (literal)` computes `Align(PC, 4) + imm32`, not
///   `PC + imm32`. With the instruction at a 4-aligned `at`, `PC` is `at + 4`,
///   `Align(PC, 4)` is `at + 4`, and `imm12 == 0` names the word immediately
///   after — the layout emitted here. Place the same eight bytes at an offset
///   that is 2 mod 4 and `Align` rounds *down*, so the encoding names `at + 2`,
///   which is the veneer's own second halfword, and the load is unaligned
///   besides. There is no `imm12` that repairs it, which is why this returns
///   `None` rather than re-encoding: use [`crate::find_free_space`] with `align` of 4.
/// * **The Thumb bit.** `ldr pc, …` is a `LoadWritePC`, which on Armv7 is a
///   `BXWritePC`: bit 0 of the loaded word selects the instruction set, and a
///   clear bit 0 requests ARM state — a `UsageFault` on an M-profile core and a
///   crash into garbage on anything else. The word emitted here therefore
///   always has bit 0 **set**, so `target` may be passed in either form.
///
/// # What it does not preserve
///
/// A veneer written this way is a *jump*: `lr` is untouched, exactly like
/// [`crate::BranchKind::BWide`], so a called function reached through one
/// returns to whoever called the veneer's caller. To make it a *call*, branch
/// to it with a `bl` — the `bl` sets `lr` before the veneer runs, and the
/// veneer leaves it alone.
///
/// ```
/// use thumb_asm::analysis::veneer;
/// use thumb_asm::isa::disassemble;
///
/// let mut image = vec![0u8; 0x20];
/// // 0x0200_0000 is 32 MB away — out of range for every branch encoding.
/// assert_eq!(thumb_asm::encode_bl(0x10, 0x0200_0000), None);
///
/// let stub = veneer(0x10, 0x0200_0000).unwrap();
/// image[0x10..0x18].copy_from_slice(&stub);
/// assert_eq!(&image[0x14..0x18], &0x0200_0001u32.to_le_bytes()); // Thumb bit set
/// // The resolved `Operand::Target` names the word the stub reads, at 0x14.
/// assert_eq!(disassemble(&image, 0x10, 0x10, 1), ["00000010: ldr.w pc, [pc], 0x14"]);
///
/// // A misaligned placement is refused rather than mis-encoded.
/// assert_eq!(veneer(0x12, 0x0200_0000), None);
/// ```
pub fn veneer(at: usize, target: u32) -> Option<[u8; 8]> {
    if at % 4 != 0 {
        return None;
    }
    // `LDR (literal)` T2 — `1111 1000 U101 1111 Rt imm12` with U = 1 (add),
    // Rt = pc, imm12 = 0: the word at Align(PC,4) + 0 == at + 4.
    let hw1: u16 = 0xF8DF;
    let hw2: u16 = 0xF000;
    let mut out = [0u8; 8];
    out[0..2].copy_from_slice(&hw1.to_le_bytes());
    out[2..4].copy_from_slice(&hw2.to_le_bytes());
    out[4..8].copy_from_slice(&(target | 1).to_le_bytes());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode_bl, find_bl_sites, Asm};

    /// An image of `len` bytes of live (non-`0xFF`) filler.
    fn live(len: usize) -> Vec<u8> {
        vec![0x00; len]
    }

    // --- free_space ---

    /// The case that distinguishes an alignment-aware scan from rounding up
    /// after the fact: a run whose start is misaligned and which is *exactly*
    /// long enough, so rounding the start up walks past the end of the run.
    #[test]
    fn free_space_does_not_round_up_out_of_the_run() {
        let mut image = live(0x40);
        // 16 free bytes at 0x12 — 2 mod 4.
        for b in &mut image[0x12..0x22] {
            *b = 0xFF;
        }

        // The unaligned finder agrees with the crate's existing one.
        // With align 1 the run is found at its first byte.
        assert_eq!(crate::find_free_space(&image, 16, 1, 0), Some(0x12));

        // Round-up-after-the-fact would answer 0x14, whose window runs to 0x24
        // — two bytes into live image. The correct answer is that there is no
        // 4-aligned 16-byte window here at all.
        assert_eq!((0x12 + 3) & !3, 0x14, "what the naive repair computes");
        assert!(image[0x22] != 0xFF && image[0x23] != 0xFF);
        assert_eq!(crate::find_free_space(&image, 16, 4, 0), None);

        // Two bytes less does fit, at the aligned start.
        assert_eq!(crate::find_free_space(&image, 14, 4, 0), Some(0x14));
        // And the last aligned window in the run is 0x1C..0x22.
        assert_eq!(crate::find_free_space(&image, 6, 4, 0x1C), Some(0x1C));
        assert_eq!(crate::find_free_space(&image, 7, 4, 0x1C), None);
    }

    #[test]
    fn free_space_honours_every_alignment() {
        let mut image = live(0x80);
        // 0x21..0x51: 48 free bytes starting at 1 mod 16.
        for b in &mut image[0x21..0x51] {
            *b = 0xFF;
        }
        assert_eq!(crate::find_free_space(&image, 8, 1, 0), Some(0x21));
        assert_eq!(crate::find_free_space(&image, 8, 2, 0), Some(0x22));
        assert_eq!(crate::find_free_space(&image, 8, 4, 0), Some(0x24));
        assert_eq!(crate::find_free_space(&image, 8, 16, 0), Some(0x30));
        // 16-aligned windows inside the run are 0x30 and 0x40. The run's last
        // byte is 0x50, so 0x11 bytes from 0x40 is the longest that fits and
        // 0x12 is one too many — and there is no later 16-aligned run to fall
        // back to, so the answer is `None` rather than a shorter window.
        assert_eq!(crate::find_free_space(&image, 0x11, 16, 0x31), Some(0x40));
        assert_eq!(crate::find_free_space(&image, 0x12, 16, 0x31), None);
    }

    #[test]
    fn free_space_finds_a_run_at_the_very_end_of_the_image() {
        let mut image = live(0x20);
        for b in &mut image[0x18..0x20] {
            *b = 0xFF;
        }
        // The window ends exactly at the image end — the off-by-one that
        // `try_read_*` exists to prevent, in its scanning form.
        assert_eq!(crate::find_free_space(&image, 8, 4, 0), Some(0x18));
        assert_eq!(crate::find_free_space(&image, 8, 8, 0), Some(0x18));
        assert_eq!(crate::find_free_space(&image, 9, 1, 0), None);

        // An all-free image: the aligned answer is `start` itself when aligned.
        let free = vec![0xFFu8; 0x20];
        assert_eq!(crate::find_free_space(&free, 0x20, 4, 0), Some(0));
        assert_eq!(crate::find_free_space(&free, 0x20, 4, 4), None);
        assert_eq!(crate::find_free_space(&free, 0x1C, 4, 4), Some(4));
        // Zero length: the first aligned offset still inside the image, with
        // `start` clamped to the image length — the behaviour
        // `Needle::FreeRun(0)` already has, which this function must not change.
        assert_eq!(crate::find_free_space(&free, 0, 16, 0x11), Some(0x20));
        assert_eq!(crate::find_free_space(&free, 0, 1, 0x64), Some(0x20));
        assert_eq!(
            crate::find(&free, crate::Needle::FreeRun { len: 0, align: 1 }, 0x64),
            Some(0x20)
        );
        // A non-zero request past the end is still `None`, clamp or no clamp.
        assert_eq!(crate::find_free_space(&free, 1, 1, 0x64), None);
    }

    #[test]
    #[should_panic(expected = "alignment must be at least 1 byte")]
    fn free_space_rejects_a_zero_alignment() {
        crate::find_free_space(&[0xFF; 4], 1, 0, 0);
    }

    /// The whole reason the parameter exists: `Asm::finish` lays its literal
    /// pool out against `Align(PC, 4)` relative to the buffer start, so a
    /// buffer placed 2 mod 4 reads its constants from the wrong words.
    #[test]
    fn free_space_gives_asm_finish_the_alignment_it_documents() {
        let mut a = Asm::new();
        a.ldr_lit(0, 0xDEAD_BEEF);
        a.bx(0);
        let code = a.finish().unwrap();

        let mut image = live(0x100);
        for b in &mut image[0x32..0x80] {
            *b = 0xFF;
        }
        // Read both answers off the *same* image, before either write.
        let aligned = crate::find_free_space(&image, code.len(), 4, 0).unwrap();
        let unaligned = crate::find_free_space(&image, code.len(), 1, 0).unwrap();
        assert_eq!((aligned, unaligned), (0x34, 0x32));
        assert_eq!(aligned % 4, 0);

        let at = aligned;
        crate::write(&mut image, at, &code);

        // Placed at the offset this function chose, the literal resolves.
        assert_eq!(literal_value(&image, at), Some(0xDEAD_BEEF));
        // Placed at the offset the unaligned finder returns, two bytes
        // earlier, it does not: `Align(PC, 4)` rounds down past the pool word.
        let mut skewed = live(0x100);
        crate::write(&mut skewed, unaligned, &code);
        assert_ne!(literal_value(&skewed, unaligned), Some(0xDEAD_BEEF));
    }

    // --- xrefs ---

    /// All four kinds of reference to one address, in one image.
    #[test]
    fn xrefs_finds_every_kind_of_reference() {
        // Layout (target is 0x40):
        //   0x00  bl 0x40                 (Call)
        //   0x04  b.w 0x40                (Branch)
        //   0x08  adr r0, 0x40            (PcRelativeAddress)
        //   0x0C  b 0x40                  (Branch, narrow T2)
        //   0x10  beq 0x40                (Branch, narrow T1)
        //   0x20  .word 0x41              (LiteralPool, stored odd)
        //   0x40  push {r4, lr}           (the target itself)
        let mut image = live(0x80);
        crate::write(&mut image, 0x00, &encode_bl(0x00, 0x40).unwrap());
        crate::write(&mut image, 0x04, &crate::encode_b_wide(0x04, 0x40).unwrap());
        // `adr r0, 0x40` at 0x08: Align(0x0C, 4) = 0x0C, imm8 = (0x40-0x0C)/4.
        crate::write(
            &mut image,
            0x08,
            &(0xA000u16 | ((0x40 - 0x0C) / 4)).to_le_bytes(),
        );
        // `b 0x40` T2 at 0x0C: off = (0x40 - 0x10) / 2 = 0x18.
        crate::write(&mut image, 0x0C, &(0xE000u16 | 0x18).to_le_bytes());
        // `beq 0x40` T1 at 0x10: off = (0x40 - 0x14) / 2 = 0x16.
        crate::write(&mut image, 0x10, &(0xD000u16 | 0x16).to_le_bytes());
        // Filler so the walk stays in phase across the gap: `nop`s.
        nop_fill(&mut image, 0x12, 0x0E);
        crate::write(&mut image, 0x20, &0x41u32.to_le_bytes());
        crate::write(&mut image, 0x40, &0xB510u16.to_le_bytes());

        let refs = xrefs(&image, 0x40);
        let seen: Vec<(usize, XrefKind, Option<&str>)> =
            refs.iter().map(|x| (x.at, x.kind, x.via)).collect();
        assert_eq!(
            seen,
            vec![
                (0x00, XrefKind::Call, Some("bl")),
                (0x04, XrefKind::Branch, Some("b")),
                (0x08, XrefKind::PcRelativeAddress, Some("adr")),
                (0x0C, XrefKind::Branch, Some("b")),
                (0x10, XrefKind::Branch, Some("b")),
                (0x20, XrefKind::LiteralPool, None),
            ]
        );

        // The Thumb bit is masked on both sides: querying the odd form finds
        // exactly the same references, including the oddly-stored pointer.
        assert_eq!(xrefs(&image, 0x41), refs);

        // And an address nothing names has no references. All five branches
        // above resolve to 0x40, so asking about 0x44 must report none of them
        // — a scan that reported every branch it decoded would fail here.
        assert_eq!(xrefs(&image, 0x44), vec![]);
    }

    /// The claim in this module's header, tested: an undefined encoding is
    /// stepped over by one halfword and the walk carries on, so a reference
    /// *after* a patch of data is still found.
    ///
    /// A firmware image is mostly not instructions. A decoder that stopped at
    /// the first undecodable halfword would find references only in the first
    /// code region it happened to start in.
    #[test]
    fn xrefs_resynchronises_past_an_undefined_encoding() {
        let mut image = live(0x80);
        // 0x00: `0xf870 0x0000`, which the 32-bit dispatcher leaves UNDEFINED.
        crate::write(&mut image, 0x00, &[0x70, 0xf8, 0x00, 0x00]);
        // 0x04: a genuine call to 0x40, on the far side of it.
        crate::write(&mut image, 0x04, &encode_bl(0x04, 0x40).unwrap());
        assert_eq!(
            isa::decode_at_with(&image, 0x00, 0, false),
            None,
            "the test vector must be undecodable, or it proves nothing"
        );

        assert_eq!(
            xrefs(&image, 0x40),
            vec![Xref {
                at: 0x04,
                kind: XrefKind::Call,
                via: Some("bl"),
            }]
        );
    }

    /// The invariant [`xref_kind`]'s last arm rests on: an instruction that
    /// carries a resolved [`Operand::Target`] and no [`Operand::Mem`] is a
    /// branch, a call, or an `adr`.
    ///
    /// Only four kinds of encoding emit an `Operand::Target` at all — the
    /// direct branches, the calls, the `ADR` forms, and the pc-relative
    /// literal accesses, which emit an `Operand::Mem` beside it. Swept rather
    /// than argued, because the arm that classifies the leftovers as
    /// `PcRelativeAddress` is only right for as long as `ADR` *is* the
    /// leftovers.
    #[test]
    fn every_target_carrying_encoding_is_a_branch_a_call_or_an_adr() {
        /// Assert the invariant for one instruction, and report whether it was
        /// one of the encodings the invariant is about.
        fn check(insn: &Insn) -> bool {
            let has_mem = insn
                .operands
                .as_slice()
                .any(|o| matches!(o, Operand::Mem(_)));
            let target = match insn.branch_target() {
                Some(t) if !has_mem => t,
                _ => return false,
            };
            assert!(
                matches!(insn.mnemonic, "b" | "bl" | "blx" | "cbz" | "cbnz" | "adr"),
                "{insn} ({}) carries a target with no memory operand",
                insn.encoding
            );
            // Whichever it is, the reference is classified rather than dropped.
            let kind = xref_kind(insn, target & !1);
            // In the documented precedence, which is load-bearing at one
            // encoding: `adr pc, <label>` writes `pc` and so *is* a branch to
            // the label, and is reported as one rather than as an address
            // materialised into a register.
            let want = if insn.is_call() {
                XrefKind::Call
            } else if insn.is_branch() {
                XrefKind::Branch
            } else {
                XrefKind::PcRelativeAddress
            };
            assert_eq!(kind, Some(want), "{insn}");
            true
        }

        let mut seen = 0usize;
        for hw in 0x0000u16..=0xFFFF {
            if isa::insn_len(hw) != 2 {
                continue;
            }
            if let Some(insn) = isa::decode_at_with(&hw.to_le_bytes(), 0, 0x1000, false) {
                seen += usize::from(check(&insn));
            }
        }
        // The wide space cannot be swept whole, so take every `hw1` that starts
        // a 32-bit instruction against a spread of `hw2`s — enough to reach
        // every wide row that resolves an address.
        for hw1 in 0xE800u16..=0xFFFF {
            for hw2 in [
                0x0000u16, 0x0004, 0x00ff, 0x0f0f, 0x1234, 0x4000, 0x8000, 0xc000, 0xed04, 0xf000,
                0xfff0, 0xffff,
            ] {
                let [a, b] = hw1.to_le_bytes();
                let [c, d] = hw2.to_le_bytes();
                if let Some(insn) = isa::decode_at_with(&[a, b, c, d], 0, 0x1000, false) {
                    seen += usize::from(check(&insn));
                }
            }
        }
        // A floor, so a decoder regression cannot make this test vacuous.
        assert!(seen > 4_000, "only {seen} target-carrying encodings swept");
    }

    /// The test that justifies the function.
    ///
    /// `tbb [r0, r1]` is `E8D0 F001`. Its **second** halfword, `0xF001`, passes
    /// `BL`'s first-halfword test (`hw1[15:11] == 0b11110`) exactly, and the
    /// halfword after it — here the `ldr.w`'s `0xF8D0` — supplies a `J1`/`J2`
    /// pair and an `imm11`. A fixed-stride scan reads those four bytes as a
    /// `BL` to 0x11B6, which is not an instruction, not a call, and not at an
    /// offset any processor will ever execute from.
    #[test]
    fn xrefs_rejects_the_phantom_bl_that_find_bl_sites_reports() {
        let mut image = live(0x2000);
        // 0x10: tbb [r0, r1]        E8D0 F001
        // 0x14: ldr.w r0, [r0, #4]  F8D0 0004
        crate::write(&mut image, 0x10, &[0xD0, 0xE8, 0x01, 0xF0]);
        crate::write(&mut image, 0x14, &[0xD0, 0xF8, 0x04, 0x00]);
        // A genuine reference to the same address, as a stored pointer — which
        // needs no branch range and so keeps the image small.
        crate::write(&mut image, 0x100, &0x11B7u32.to_le_bytes());

        // The phantom, read at the second halfword of the `tbb`.
        let phantom = 0x12;
        assert_eq!(crate::decode_bl(&image, phantom), Some(0x11B6));

        // The old scan reports it …
        assert!(
            find_bl_sites(&image, 0x11B6).contains(&phantom),
            "find_bl_sites must report the phantom — that is the bug"
        );
        // … and the instruction-accurate walk does not.
        let refs = xrefs(&image, 0x11B6);
        assert!(
            !refs.iter().any(|x| x.at == phantom),
            "xrefs must not report a reference at {phantom:#x}: {refs:?}"
        );
        // It is not that `xrefs` found nothing: the real pointer is there.
        assert_eq!(
            refs,
            vec![Xref {
                at: 0x100,
                kind: XrefKind::LiteralPool,
                via: None,
            }]
        );

        // And the walk really did decode the two instructions it was supposed
        // to, rather than skipping the region.
        assert_eq!(
            isa::disassemble(&image, 0x10, 0x10, 2),
            ["00000010: tbb [r0, r1]", "00000014: ldr.w r0, [r0, #4]"]
        );
    }

    /// A literal load's `Operand::Target` is the address of the pool word, not
    /// a destination — `Insn::branch_target`'s documented overload. It must not
    /// surface as a branch.
    #[test]
    fn xrefs_does_not_mistake_a_pool_address_for_a_destination() {
        let mut image = live(0x40);
        // `ldr r0, [pc, #4]` at 0x00 reads the word at 0x08.
        crate::write(&mut image, 0x00, &0x4801u16.to_le_bytes());
        crate::write(&mut image, 0x08, &0x1234u32.to_le_bytes());
        // A stored pointer to the pool word itself, so the assertion below is
        // about *which* reference is reported rather than about an empty list.
        crate::write(&mut image, 0x0C, &0x08u32.to_le_bytes());

        // The `ldr` at 0x00 names 0x08 — as the word it loads, not as a
        // destination — and is not reported. The stored pointer at 0x0C is.
        assert_eq!(
            xrefs(&image, 0x08),
            vec![Xref {
                at: 0x0C,
                kind: XrefKind::LiteralPool,
                via: None,
            }]
        );
        // The value it loads is referenced by the pool word, as data.
        assert_eq!(
            xrefs(&image, 0x1234),
            vec![Xref {
                at: 0x08,
                kind: XrefKind::LiteralPool,
                via: None,
            }]
        );
    }

    // --- function_start ---

    #[test]
    fn function_start_finds_each_prologue_form() {
        // push {r4, lr}; movs r0, #1; bx lr
        let narrow = [0x10u8, 0xB5, 0x01, 0x20, 0x70, 0x47];
        assert_eq!(function_start(&narrow, 4, 16), Some(0));
        // The Thumb bit on an address read from a pointer is masked off.
        assert_eq!(function_start(&narrow, 5, 16), Some(0));
        // `addr` itself may be the prologue.
        assert_eq!(function_start(&narrow, 0, 16), Some(0));

        // push.w {r4-r8, lr} == stmdb sp!, {...}: E92D 41F0
        let wide = [0x2Du8, 0xE9, 0xF0, 0x41, 0x70, 0x47];
        assert_eq!(function_start(&wide, 4, 16), Some(0));
        // The same `stmdb` without `lr` in the list is not a prologue.
        let no_lr = [0x2Du8, 0xE9, 0xF0, 0x01, 0x70, 0x47];
        assert_eq!(function_start(&no_lr, 4, 16), None);

        // push.w {lr} == str lr, [sp, #-4]!: F84D ED04
        let t3 = [0x4Du8, 0xF8, 0x04, 0xED, 0x70, 0x47];
        assert_eq!(function_start(&t3, 4, 16), Some(0));
    }

    #[test]
    fn function_start_respects_max_scan_and_the_image_start() {
        // push {r4, lr} at 0, then 16 bytes of nops.
        let mut image = live(0x14);
        crate::write(&mut image, 0, &0xB510u16.to_le_bytes());
        nop_fill(&mut image, 2, 0x12);

        assert_eq!(function_start(&image, 0x12, 0x12), Some(0));
        // One byte short of reaching it.
        assert_eq!(function_start(&image, 0x12, 0x10), None);
        // A window of zero looks only at `addr` itself.
        assert_eq!(function_start(&image, 0x12, 0), None);
        assert_eq!(function_start(&image, 0x00, 0), Some(0));
        // A generous window cannot walk off the front of the image.
        let no_prologue = live(0x10);
        assert_eq!(function_start(&no_prologue, 0x0E, usize::MAX), None);

        // An address *past the end* of the image — a handler pointer read out
        // of a corrupt or mis-based table, which is exactly the kind of value
        // this function is handed. The out-of-image halfwords are simply not
        // prologues, so the scan walks down through them and either reaches
        // the image or runs out of window. Neither panics.
        assert_eq!(function_start(&image, 0x1000, 0x10), None);
        assert_eq!(function_start(&image, 0x20, 0x20), Some(0));
    }

    /// The documented ambiguity, asserted rather than wished away.
    ///
    /// `strd r11, r5, [r0, #0x2C]` is `E9C0 B50B`: its second halfword is
    /// `0xB50B`, which read alone is `push {r0, r1, r3, lr}`. A backwards
    /// halfword scan cannot know it is mid-instruction — nothing in Thumb marks
    /// where an instruction begins — so it reports it, and this test pins that
    /// behaviour as documented rather than claiming the scan is exact.
    #[test]
    fn function_start_is_a_heuristic_and_can_land_mid_instruction() {
        let mut image = live(0x20);
        // 0x00: push {r4, lr}   — the real entry
        // 0x02: strd r11, r5, [r0, #0x2c]
        // 0x06: bx lr
        crate::write(&mut image, 0x00, &0xB510u16.to_le_bytes());
        crate::write(&mut image, 0x02, &[0xC0, 0xE9, 0x0B, 0xB5]);
        crate::write(&mut image, 0x06, &0x4770u16.to_le_bytes());

        // A forward, instruction-accurate walk sees two instructions.
        assert_eq!(
            isa::disassemble(&image, 0x02, 0x02, 1),
            ["00000002: strd r11, r5, [r0, #44]"]
        );
        // The backwards scan from past it stops at the nearest match, which is
        // the `strd`'s second halfword — not the real entry at 0x00.
        assert_eq!(
            function_start(&image, 0x06, 0x10),
            Some(0x04),
            "documented behaviour: the nearest halfword-aligned match, whatever \
             it is a halfword of"
        );
        // Corroboration is the caller's job, and it works: a walk from the
        // phantom does not decode into the same stream the real entry does.
        assert_eq!(function_start(&image, 0x02, 0x10), Some(0x00));

        // A leaf function with no prologue has no marker at all: this is the
        // `None`-does-not-mean-no-function case.
        let leaf = [0x01u8, 0x20, 0x70, 0x47]; // movs r0, #1; bx lr
        assert_eq!(function_start(&leaf, 0x02, 0x10), None);
    }

    // --- literal_value ---

    #[test]
    fn literal_value_resolves_align_pc_4_from_either_parity() {
        let mut image = live(0x20);
        // Both loads name the pool word at 0x08 through Align(PC, 4) = 0x04.
        // At 0x00: PC = 0x04, Align = 0x04, imm = 4 → 0x08.
        // At 0x02: PC = 0x06, Align = 0x04, imm = 4 → 0x08. Same word, and the
        // naive `(at + 4) + imm` would say 0x0A for the second.
        crate::write(&mut image, 0x00, &0x4801u16.to_le_bytes());
        crate::write(&mut image, 0x02, &0x4801u16.to_le_bytes());
        crate::write(&mut image, 0x08, &0xDEAD_BEEFu32.to_le_bytes());

        assert_eq!(literal_value(&image, 0x00), Some(0xDEAD_BEEF));
        assert_eq!(literal_value(&image, 0x02), Some(0xDEAD_BEEF));
        assert_ne!(0x02 + 4 + 4, 0x08, "the arithmetic everyone gets wrong");

        // The wide form, whose `U` bit can point the pool *backwards*:
        // `ldr.w r1, [pc, #-8]` at 0x10 → Align(0x14,4) - 8 = 0x0C.
        crate::write(&mut image, 0x0C, &0x1234_5678u32.to_le_bytes());
        crate::write(&mut image, 0x10, &[0x5F, 0xF8, 0x08, 0x10]);
        assert_eq!(literal_value(&image, 0x10), Some(0x1234_5678));
    }

    #[test]
    fn literal_value_refuses_what_it_cannot_answer() {
        // A pool word past the end of the image.
        let mut short = live(0x08);
        // `ldr r0, [pc, #4]` at 0x04 names 0x0C, which is not there.
        crate::write(&mut short, 0x04, &0x4801u16.to_le_bytes());
        assert_eq!(literal_value(&short, 0x04), None);

        // Not a literal load at all.
        let mut other = live(0x10);
        crate::write(&mut other, 0x00, &0x4770u16.to_le_bytes()); // bx lr
        crate::write(&mut other, 0x02, &0x6801u16.to_le_bytes()); // ldr r1, [r0]
        crate::write(&mut other, 0x04, &0xA001u16.to_le_bytes()); // adr r0, ...
        assert_eq!(literal_value(&other, 0x00), None);
        assert_eq!(literal_value(&other, 0x02), None, "base is r0, not pc");
        assert_eq!(literal_value(&other, 0x04), None, "adr loads nothing");

        // A byte-sized literal load is not a word load.
        // `ldrb.w r0, [pc, #4]`: F89F 0004.
        let mut byte = live(0x10);
        crate::write(&mut byte, 0x00, &[0x9F, 0xF8, 0x04, 0x00]);
        assert_eq!(
            isa::decode_at(&byte, 0).map(|i| i.mnemonic),
            Some("ldrb"),
            "the fixture really is a byte load"
        );
        assert_eq!(literal_value(&byte, 0x00), None);

        // Bytes that are not an instruction at all — most of a firmware image.
        // `0xF870 0x0000` is Table A5-9's UNDEFINED row, so nothing decodes and
        // there is nothing to resolve.
        let mut data = live(0x10);
        crate::write(&mut data, 0x00, &[0x70, 0xF8, 0x00, 0x00]);
        assert_eq!(
            isa::decode_at(&data, 0),
            None,
            "the fixture must not decode"
        );
        assert_eq!(literal_value(&data, 0x00), None);
        // And an offset past the end of the image.
        assert_eq!(literal_value(&data, 0x10), None);
    }

    // --- nop_fill ---

    #[test]
    fn nop_fill_round_trips_through_the_decoder() {
        let mut image = live(0x10);
        nop_fill(&mut image, 0x04, 0x08);

        // Untouched either side, canonical NOPs between.
        assert_eq!(&image[0x00..0x04], &[0, 0, 0, 0]);
        assert_eq!(&image[0x0C..0x10], &[0, 0, 0, 0]);
        let decoded: Vec<String> = Decoder::at(&image, 0x04, 0x04)
            .take(4)
            .map(|i| i.to_string())
            .collect();
        assert_eq!(decoded, ["nop", "nop", "nop", "nop"]);

        // The zeros this function exists to avoid are a real, flag-writing
        // instruction — not a hole.
        assert_eq!(
            isa::decode_at(&image, 0).map(|i| i.to_string()),
            Some("movs r0, r0".to_string())
        );
        assert!(isa::decode_at(&image, 0).unwrap().sets_flags);
        assert!(!isa::decode_at(&image, 4).unwrap().sets_flags);

        // A zero-length fill is a no-op, not an error.
        let before = image.clone();
        nop_fill(&mut image, 0x06, 0);
        assert_eq!(image, before);
    }

    #[test]
    #[should_panic(expected = "there is no 1-byte Thumb instruction")]
    fn nop_fill_refuses_an_odd_length() {
        nop_fill(&mut live(0x10), 0x04, 0x03);
    }

    #[test]
    #[should_panic(expected = "halfword aligned")]
    fn nop_fill_refuses_an_odd_offset() {
        nop_fill(&mut live(0x10), 0x03, 0x04);
    }

    #[test]
    #[should_panic(expected = "past the end")]
    fn nop_fill_refuses_to_run_off_the_end() {
        nop_fill(&mut live(0x10), 0x0C, 0x08);
    }

    // --- reachable ---

    #[test]
    fn reachable_follows_both_arms_and_stops_at_returns() {
        // 0x00 cbz r0, 0x06
        // 0x02 movs r0, #1
        // 0x04 bx lr
        // 0x06 movs r0, #0
        // 0x08 bx lr
        let image = [0x08, 0xB1, 0x01, 0x20, 0x70, 0x47, 0x00, 0x20, 0x70, 0x47];
        let r = reachable(&image, 0, 64);
        assert!(r.complete);
        assert_eq!(r.insns, vec![0, 2, 4, 6, 8]);
        assert_eq!(r.end, 10);
        assert_eq!(r.unresolved, vec![4, 8], "the two `bx lr` returns");
    }

    #[test]
    fn reachable_does_not_follow_calls_but_does_resume_after_them() {
        let mut image = live(0x40);
        // 0x00 push {lr}
        // 0x02 bl 0x20
        // 0x06 pop {pc}
        // 0x20 bx lr   (the callee — must NOT be walked)
        crate::write(&mut image, 0x00, &0xB500u16.to_le_bytes());
        crate::write(&mut image, 0x02, &encode_bl(0x02, 0x20).unwrap());
        crate::write(&mut image, 0x06, &0xBD00u16.to_le_bytes());
        crate::write(&mut image, 0x20, &0x4770u16.to_le_bytes());

        let r = reachable(&image, 0, 64);
        assert!(r.complete);
        assert_eq!(r.insns, vec![0x00, 0x02, 0x06]);
        assert_eq!(r.end, 0x08);
        // `pop {pc}` is a branch with no static target — a return.
        assert_eq!(r.unresolved, vec![0x06]);
        // The callee is reachable on its own, by asking.
        assert_eq!(reachable(&image, 0x20, 64).insns, vec![0x20]);
    }

    #[test]
    fn reachable_reports_an_unconditional_branch_as_leaving() {
        let mut image = live(0x20);
        // 0x00 b 0x08 ; 0x02..0x08 nops that must NOT be reached ; 0x08 bx lr
        crate::write(&mut image, 0x00, &(0xE000u16 | 0x02).to_le_bytes());
        nop_fill(&mut image, 0x02, 0x06);
        crate::write(&mut image, 0x08, &0x4770u16.to_le_bytes());

        let r = reachable(&image, 0, 64);
        assert!(r.complete);
        assert_eq!(
            r.insns,
            vec![0x00, 0x08],
            "the skipped nops are not reached"
        );
        assert_eq!(r.unresolved, vec![0x08]);
    }

    #[test]
    fn reachable_is_honest_about_running_out_of_road() {
        // An instruction budget smaller than the body.
        let image = [0x00u8, 0xBF, 0x00, 0xBF, 0x00, 0xBF, 0x70, 0x47];
        assert!(reachable(&image, 0, 4).complete);
        let clipped = reachable(&image, 0, 2);
        assert!(!clipped.complete);
        assert!(clipped.insns.len() <= 3);

        // Undefined bytes: `hw1 == 0xF870` lands in Table A5-9's explicitly
        // UNDEFINED row (`op1 == 0b11`, `op2 & 0b110_0111 == 0b000_0111`), so no
        // group claims it whatever `hw2` holds.
        let bad = [0x01u8, 0x20, 0x70, 0xF8, 0x00, 0x00];
        let r = reachable(&bad, 0, 64);
        assert!(!r.complete, "an undefined encoding must not pass silently");
        assert_eq!(r.insns, vec![0]);
    }

    /// A loop is walked once. The `visited` set is what makes the walk
    /// terminate at all — every backward branch is a cycle in the graph — and
    /// what keeps a block reached from two predecessors out of `insns` twice.
    #[test]
    fn reachable_walks_a_loop_once_and_terminates() {
        // 0x00: movs r0, #1
        // 0x02: b 0x00        — imm11 = (0 - 6) / 2 = -3, i.e. 0x7FD.
        let image = [0x01u8, 0x20, 0xFD, 0xE7];
        assert_eq!(
            isa::decode_at(&image, 2).and_then(|i| i.branch_target()),
            Some(0),
            "the fixture must branch back to the top"
        );

        let r = reachable(&image, 0, 64);
        assert!(r.complete, "a loop is not a reason to give up");
        assert_eq!(r.insns, vec![0, 2], "each instruction once, not twice");
        assert_eq!(r.end, 4);
        assert_eq!(r.unresolved, vec![], "the back edge is resolved");

        // A diamond reaches its join block from two predecessors, and reports
        // it once:
        //   0x00 cbz r0, 0x08 · 0x02 movs r0, #1 · 0x04 b 0x08 · 0x06 nop
        //   0x08 bx lr
        let diamond = [0x10u8, 0xB1, 0x01, 0x20, 0x00, 0xE0, 0x00, 0xBF, 0x70, 0x47];
        assert_eq!(
            isa::decode_at(&diamond, 0).and_then(|i| i.branch_target()),
            Some(8),
            "both arms must join at 0x08"
        );
        let r = reachable(&diamond, 0, 64);
        assert!(r.complete);
        assert_eq!(r.insns, vec![0, 2, 4, 8], "0x06 is never reached");
        assert_eq!(r.unresolved, vec![8]);
    }

    /// An edge that leaves the image ends the walk as incomplete rather than
    /// as an unresolved branch: the destination is known, it is just not here.
    /// Both the fall-through off the end of a truncated image and a forward
    /// branch beyond it land in the same place.
    #[test]
    fn reachable_is_incomplete_when_an_edge_leaves_the_image() {
        // A truncated image: one instruction, and nothing to fall through to.
        let cut = [0x01u8, 0x20]; // movs r0, #1
        let r = reachable(&cut, 0, 64);
        assert!(!r.complete, "the fall-through leaves the image");
        assert_eq!(r.insns, vec![0]);
        assert_eq!(r.end, 2);
        assert_eq!(
            r.unresolved,
            vec![],
            "not an unresolved branch — an absent one"
        );

        // A branch whose target is past the end: `b 0x802` at 0x00, imm11 max.
        let far = [0xFFu8, 0xE3];
        assert_eq!(
            isa::decode_at(&far, 0).and_then(|i| i.branch_target()),
            Some(0x802)
        );
        let r = reachable(&far, 0, 64);
        assert!(!r.complete);
        assert_eq!(r.insns, vec![0]);
        assert_eq!(r.unresolved, vec![]);
    }

    /// `ldr pc, [pc, #imm]` — how a [`veneer`] branches — is a branch whose
    /// `Operand::Target` names the pool word, not the destination. It must be
    /// reported unresolved, not walked into the literal.
    #[test]
    fn reachable_does_not_walk_into_a_veneers_literal() {
        let mut image = live(0x20);
        crate::write(&mut image, 0x00, &veneer(0x00, 0x1234).unwrap());
        let r = reachable(&image, 0, 64);
        assert!(r.complete);
        assert_eq!(r.insns, vec![0x00]);
        assert_eq!(r.end, 0x04, "the literal is data, not an instruction");
        assert_eq!(r.unresolved, vec![0x00]);
    }

    // --- veneer ---

    #[test]
    fn veneer_reaches_where_no_branch_encoding_can() {
        let far = 0x0200_0000u32; // 32 MB: out of range for BL and B.W
        assert_eq!(encode_bl(0x10, far), None);
        assert_eq!(crate::encode_b_wide(0x10, far), None);

        let mut image = live(0x20);
        let stub = veneer(0x10, far).unwrap();
        crate::write(&mut image, 0x10, &stub);

        // The instruction is `ldr.w pc, [pc]`, and it names the word at 0x14.
        let insn = isa::decode_at(&image, 0x10).unwrap();
        assert_eq!(insn.mnemonic, "ldr");
        assert!(insn.is_branch() && insn.writes_pc());
        assert_eq!(insn.branch_target(), Some(0x14), "the pool word's address");
        // Which is the target, with the Thumb bit set so LoadWritePC stays in
        // Thumb state.
        assert_eq!(literal_value(&image, 0x10), Some(far | 1));
        assert_eq!(crate::read_u32(&image, 0x14) & 1, 1);

        // Either form of the target may be passed.
        assert_eq!(veneer(0x10, far | 1), Some(stub));
        // A short branch to the veneer reaches it, which is the whole idiom.
        assert!(encode_bl(0x00, 0x10).is_some());
    }

    #[test]
    fn veneer_refuses_a_placement_align_pc_4_would_break() {
        // At 2 mod 4, Align(PC, 4) rounds *down* to the veneer's own second
        // halfword; no imm12 repairs it, so the encoding is refused.
        assert_eq!(veneer(0x02, 0x1234), None);
        assert_eq!(veneer(0x06, 0x1234), None);
        assert!(veneer(0x04, 0x1234).is_some());
        assert!(veneer(0x00, 0x1234).is_some());

        // And the aligned offset comes from `free_space`, not from rounding.
        let mut image = live(0x40);
        for b in &mut image[0x22..0x40] {
            *b = 0xFF;
        }
        let at = crate::find_free_space(&image, 8, 4, 0).unwrap();
        assert_eq!(at, 0x24);
        assert!(veneer(at, 0x1234).is_some());
    }

    /// A `bx lr` that is conditional *only* because an `IT` block encloses it.
    ///
    /// `BX` has no condition field, so decoding the halfword on its own says
    /// "unconditional branch" and the walk ends the path there — reporting a
    /// function that stops at offset 4 and, worse, reporting it with
    /// `complete: true`. The instruction is really `bxeq lr`: it returns when
    /// `Z` is set and falls through when it is not, so everything after it is
    /// reachable. Deciding where a patch may safely go on the strength of the
    /// short answer would put it on top of live code.
    #[test]
    fn a_return_made_conditional_by_an_enclosing_it_block_still_falls_through() {
        // 0: it eq          (0xBF08)
        // 2: bxeq lr        (0x4770, conditional via the block)
        // 4: movs r0, #1    (0x2001)
        // 6: bx lr          (0x4770, unconditional this time)
        let image = [0x08, 0xBF, 0x70, 0x47, 0x01, 0x20, 0x70, 0x47];
        let r = reachable(&image, 0, 64);
        assert!(r.complete, "nothing here is indeterminate");
        assert_eq!(r.insns, vec![0, 2, 4, 6], "the fall-through arm is live");
        assert_eq!(r.end, 8);
        assert_eq!(r.unresolved, vec![2, 6], "both returns are indirect edges");
    }

    /// The same bytes without the `IT`: now the `bx lr` really does end it.
    #[test]
    fn an_unconditional_return_ends_the_path() {
        // 0: bx lr   2: movs r0, #1   4: bx lr
        let image = [0x70, 0x47, 0x01, 0x20, 0x70, 0x47];
        let r = reachable(&image, 0, 64);
        assert_eq!(r.insns, vec![0], "control leaves at the first instruction");
        assert_eq!(r.end, 2);
        assert_eq!(r.unresolved, vec![0]);
    }

    /// `ITSTATE` runs out after the block's stated length, so the instruction
    /// *after* an `ITT`'s two arms is unconditional again. Getting this wrong
    /// in the other direction — treating everything after an `IT` as
    /// conditional forever — would make every path look live.
    #[test]
    fn it_state_expires_and_the_next_return_is_unconditional_again() {
        // 0: itt eq        (0xBF04)
        // 2: bxeq lr       (0x4770)  conditional, falls through
        // 4: bxeq lr       (0x4770)  still conditional, falls through
        // 6: bx lr         (0x4770)  block is spent: ends the path
        // 8: movs r0, #1   (0x2001)  unreachable
        let image = [0x04, 0xBF, 0x70, 0x47, 0x70, 0x47, 0x70, 0x47, 0x01, 0x20];
        let r = reachable(&image, 0, 64);
        assert_eq!(
            r.insns,
            vec![0, 2, 4, 6],
            "offset 8 is past the last return"
        );
        assert_eq!(r.end, 8);
        assert_eq!(r.unresolved, vec![2, 4, 6]);
    }

    // --- the walks must reach the end of the image ---
    //
    // Mutation testing found both `xrefs` scans able to stop early with no
    // error. That failure is quiet and it is the worst shape this function
    // has: `xrefs` is the "find every reference to this handler" verb, so a
    // truncated walk returns a *shorter list*, not a failure. A consumer
    // repointing every call site patches the ones it was shown and leaves the
    // rest calling the original — half-patched firmware, reported as success.

    /// A branch in the image's final halfword is still a reference.
    #[test]
    fn xrefs_reaches_a_branch_in_the_final_halfword() {
        let mut image = live(0x80);
        // `b` T2 at 0x7E targeting 0x40: off = (0x40 - (0x7E + 4)) / 2 = -0x21,
        // so imm11 = 0x7DF.
        let at = image.len() - 2;
        crate::write(&mut image, at, &(0xE000u16 | 0x7DF).to_le_bytes());
        let found = xrefs(&image, 0x40);
        assert_eq!(found.len(), 1, "the last halfword is inside the image");
        assert_eq!(found[0].at, at);
        assert_eq!(found[0].kind, XrefKind::Branch);
    }

    /// A stored handler pointer in the image's final word is still a
    /// reference — the off-by-one `find_bl_sites` had before 0.2.0, one scan
    /// over.
    #[test]
    fn xrefs_finds_a_stored_pointer_in_the_last_word_of_the_image() {
        let mut image = live(0x40);
        let at = image.len() - 4;
        // Stored with the Thumb bit set, as a handler pointer really is.
        crate::write(&mut image, at, &0x41u32.to_le_bytes());
        let found = xrefs(&image, 0x40);
        assert!(
            found
                .iter()
                .any(|x| x.at == at && x.kind == XrefKind::LiteralPool),
            "a pointer in the final word must be reported: {found:?}"
        );
    }

    /// Both scans walk the *whole* image, not a fraction of it.
    ///
    /// `at + 2` becoming `at * 2` stops the instruction walk half way, and
    /// `p + 4` becoming `p * 4` stops the pointer scan at a quarter. Neither
    /// shows up unless a reference lives past the truncation point, so this
    /// puts one near the end of a large image deliberately.
    #[test]
    fn both_xref_scans_cover_the_whole_image_not_a_fraction_of_it() {
        let mut image = live(0x400);
        let branch_at = 0x300;
        // `bl` to 0x40 from 0x300.
        let bl = crate::encode_bl(branch_at, 0x40).expect("in range");
        crate::write(&mut image, branch_at, &bl);
        let pointer_at = 0x380;
        crate::write(&mut image, pointer_at, &0x41u32.to_le_bytes());

        let found = xrefs(&image, 0x40);
        assert!(
            found
                .iter()
                .any(|x| x.at == branch_at && x.kind == XrefKind::Call),
            "the call at {branch_at:#x} is past the half-way point: {found:?}"
        );
        assert!(
            found
                .iter()
                .any(|x| x.at == pointer_at && x.kind == XrefKind::LiteralPool),
            "the pointer at {pointer_at:#x} is past the quarter-way point: {found:?}"
        );
    }
}
