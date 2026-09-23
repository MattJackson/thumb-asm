//! Re-siting one decoded instruction so that it still means the same thing at
//! a new address.
//!
//! This is the primitive under [`crate::detour`], and the reason a detour can
//! be installed over *live* code instead of only over a dead prologue. Moving
//! an instruction into a stub is a byte copy for the great majority of the
//! instruction set and a wrong answer for the rest, because Thumb has three
//! separate ways for an instruction's behaviour to depend on its own address:
//!
//! * a **direct branch** carries a displacement from `PC`, so the same bytes at
//!   a new address branch somewhere else (ARM DDI 0403E.e A7.7.12);
//! * a **pc-relative literal access** — `LDR (literal)`, `ADR`, `LDRD
//!   (literal)`, `LDC` — is based on `Align(PC,4)`, which is Thumb's pc value
//!   (this instruction's address plus four) forced word-aligned (A4.2.2);
//! * a handful of instructions **read `pc` as an ordinary value** (`mov rd,
//!   pc`, `add rd, pc`), so the datum itself changes.
//!
//! This crate has already done the hard half of that work in the decoder: an
//! [`Operand::Target`] is the *resolved absolute address*, not a displacement.
//! So relocation never re-does pc arithmetic — it holds the target still and
//! asks whether the new displacement fits, which is exactly what
//! [`isa::encode`] answers. Everything here that is not that is a refusal, and
//! every refusal names the instruction and carries a stable
//! [`reason`](RelocateError::reason) string.
//!
//! # `Align(PC,4)` does not move linearly
//!
//! The subtle case, and the one worth stating out loud: for the literal forms
//! the base is `Align(PC,4)`, which steps in fours while an instruction address
//! steps in twos. Moving an instruction two bytes changes its displacement by
//! **either zero or four**, never by two. So the tempting
//! `new_offset = old_offset - (to - from)` is wrong at every second halfword,
//! and wrong in a way that still assembles. Recomputing the displacement from
//! the resolved target — as this module does — is right by construction.
//!
//! # Worked example
//!
//! A literal load moved two bytes up still reads the same pool word, and here
//! that happens to leave the bytes identical, because both addresses share one
//! `Align(PC,4)`:
//!
//! ```
//! use thumb_asm::isa;
//! use thumb_asm::relocate::relocate;
//!
//! // `ldr r0, [pc, #8]` at 0x1000 — the pool word is at 0x100c.
//! let image = [0x02, 0x48];
//! let insn = isa::decode_at_with(&image, 0, 0x1000, false).unwrap();
//! assert_eq!(insn.branch_target(), Some(0x100c));
//!
//! // Two bytes up: Align(PC,4) is unchanged, so the displacement is too.
//! let moved = relocate(&insn, 0x1002).unwrap();
//! assert_eq!(moved.branch_target(), Some(0x100c));
//! assert_eq!(isa::encode_bytes(&moved).unwrap(), vec![0x02, 0x48]);
//!
//! // Four bytes up: Align(PC,4) has stepped, so the displacement shrinks by 4.
//! let moved = relocate(&insn, 0x1004).unwrap();
//! assert_eq!(moved.branch_target(), Some(0x100c));
//! assert_eq!(isa::encode_bytes(&moved).unwrap(), vec![0x01, 0x48]);
//!
//! // Far away, the pool is out of the narrow form's 0..1020 reach.
//! let err = relocate(&insn, 0x9000).unwrap_err();
//! assert_eq!(err.reason(), "out-of-range");
//! assert_eq!(err.mnemonic(), "ldr");
//! ```

use crate::isa::{self, AddrMode, Insn, Mem, Operand, Operands, Reg, Width};
use crate::{encode_b_cond, encode_b_wide, Cond};

/// Whether [`relocate_with`] may re-encode a narrow direct branch in its wide
/// form when the narrow displacement no longer reaches.
///
/// # Why this is a choice and not a default
///
/// A narrow branch out of a relocated stub essentially never reaches: `B` T2
/// spans ±2046 bytes and `B<cond>` T1 spans −256/+254, while a stub lives in
/// whatever free space the image has, typically hundreds of kilobytes from the
/// code it was displaced from. So *some* widening is needed for the feature to
/// work at all — but widening changes the instruction's length, and a caller
/// laying out a fixed-size buffer must be told. [`relocate`] therefore never
/// widens, and the widening form is asked for by name.
///
/// The length change is visible in the returned [`Insn`] itself: [`Insn::len`]
/// and [`Insn::width`] are part of the value, so a caller who accepts a
/// widened instruction cannot fail to see that it is now four bytes.
/// [`crate::detour`] relies on exactly that, and lays its stub out in a single
/// forward pass — widening instruction *n* moves only instructions *n+1*
/// onward, which have not been placed yet, so no fixed-point iteration is
/// needed.
///
/// # What is not widened, and why
///
/// Only direct branches. A narrow `ADR` or `LDR (literal)` is refused rather
/// than widened, because the wide forms reach ±4095 bytes — the same "cannot
/// reach a literal pool from free space" class as ±1020. Widening them would
/// buy nothing and would trade a clear refusal for a slightly later one. A
/// consumer that needs a displaced literal load has to *rewrite* it (copy the
/// pool word next to the stub, or materialise the value with `movw`/`movt`),
/// which is a different operation from relocation and not this module's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Widen {
    /// Never change the instruction's length. `relocate(i, to)` guarantees
    /// `out.width == i.width`, hence `out.len() == i.len()`.
    Never,
    /// Re-encode a narrow `B` T2 or `B<cond>` T1 in its wide form (`B.W` T4 /
    /// `B<cond>.W` T3, ±16 MB and ±1 MB) when — and only when — the narrow
    /// displacement no longer reaches. The narrowest encoding that reaches is
    /// always preferred, so this is never a gratuitous four bytes.
    IfNeeded,
}

/// Why an instruction cannot be moved to a given address.
///
/// Every variant names the instruction (`mnemonic`) and the two addresses
/// involved (`from`, `to`), and every variant has a stable machine-readable
/// [`reason`](Self::reason) — a refusal a caller cannot classify is a refusal
/// it has to treat as fatal, and most of these are not.
///
/// The variants split into three kinds, which is the distinction that matters
/// when deciding what to do about one:
///
/// * **Address-independent** — [`ReadsPc`](Self::ReadsPc),
///   [`TableBranch`](Self::TableBranch),
///   [`UnresolvedPcRelative`](Self::UnresolvedPcRelative),
///   [`NotEncodable`](Self::NotEncodable). The instruction cannot be moved
///   anywhere; retrying at another address is pointless.
/// * **Address-dependent** — [`OutOfRange`](Self::OutOfRange),
///   [`ForwardOnlyBranch`](Self::ForwardOnlyBranch),
///   [`LiteralAlignment`](Self::LiteralAlignment). Another destination might
///   work, and for a branch [`Widen::IfNeeded`] often fixes it outright.
/// * **Caller error** — [`Misaligned`](Self::Misaligned).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocateError {
    /// `to` is odd. Every Thumb instruction is halfword aligned (A5.1), so
    /// there is no address to relocate to.
    Misaligned {
        /// The instruction's mnemonic.
        mnemonic: &'static str,
        /// The address it was decoded at.
        from: u32,
        /// The odd address it was asked to move to.
        to: u32,
    },
    /// The instruction reads `pc` as an ordinary value operand — `mov rd, pc`,
    /// `add rd, pc`, `cmp rn, pc`, `str pc, [rn]`, `bx pc`, `ldr rt, [rn, pc]`.
    ///
    /// The datum is the instruction's own address plus four (A4.2.2, A7.3), so
    /// it changes under relocation and nothing in the encoding can compensate.
    /// Such an instruction re-encodes perfectly at any address, which is why
    /// this has to be a refusal here rather than an [`isa::encode`] failure:
    /// the bits are fine, the meaning is not.
    ReadsPc {
        /// The instruction's mnemonic.
        mnemonic: &'static str,
        /// The address it was decoded at.
        from: u32,
        /// The address it was asked to move to.
        to: u32,
    },
    /// A `CBZ`/`CBNZ` whose target no longer reaches.
    ///
    /// The offset is `ZeroExtend(i:imm5:'0')` — **unsigned** (A7.7.21) — so the
    /// range is 0 to 126 bytes *forward* and there is no backward form at all.
    /// A stub in free space is almost never 0..126 bytes below the target, so
    /// in practice a displaced `CBZ` must be rewritten (as `cmp`/`b<cond>.w`),
    /// not relocated. Reported separately from
    /// [`OutOfRange`](Self::OutOfRange) because "out of range" invites a caller
    /// to try a nearer address, and here the reachable window is one-sided.
    ForwardOnlyBranch {
        /// The instruction's mnemonic, `"cbz"` or `"cbnz"`.
        mnemonic: &'static str,
        /// The address it was decoded at.
        from: u32,
        /// The address it was asked to move to.
        to: u32,
        /// The branch target, which does not move.
        target: u32,
    },
    /// A `TBB`/`TBH`. Not relocatable at any address.
    ///
    /// The table holds *halfword offsets from the table-branch instruction's
    /// own `PC`*: A7.7.185's operation is
    /// `BranchWritePC(PC + 2*UInt(halfwords))`. So every destination in the
    /// table is measured from the `TBB`, and moving the `TBB` silently moves
    /// all of them — while the table itself, wherever it lives, does not move.
    ///
    /// Nothing in the encoding depends on the address, so [`isa::encode`]
    /// re-encodes a moved `TBB` quite happily. This refusal is the only thing
    /// standing between a caller and a jump table that points into the middle
    /// of unrelated code.
    TableBranch {
        /// The instruction's mnemonic, `"tbb"` or `"tbh"`.
        mnemonic: &'static str,
        /// The address it was decoded at.
        from: u32,
        /// The address it was asked to move to.
        to: u32,
    },
    /// A pc-relative memory operand this module cannot re-resolve: either no
    /// [`Operand::Target`] accompanies it, or it is indexed or writes back.
    ///
    /// Recomputing a pc-relative displacement needs the resolved absolute
    /// address, and the only way to get one for `[pc, rm]` or `[pc], #imm`
    /// would be to know `pc`'s run-time value — which is the thing that
    /// changed. Both shapes are UNPREDICTABLE in the architecture anyway
    /// (A7.7.44 gives the literal form no index and no writeback), so this
    /// variant is a guard rather than a limitation.
    UnresolvedPcRelative {
        /// The instruction's mnemonic.
        mnemonic: &'static str,
        /// The address it was decoded at.
        from: u32,
        /// The address it was asked to move to.
        to: u32,
    },
    /// An `Align(PC,4)`-based narrow form whose displacement from the new
    /// address would not be a multiple of four.
    ///
    /// The narrow literal forms scale their immediate by four (`imm8:'00'` in
    /// `LDR (literal)` T1 and `ADR` T1, A7.7.44 / A7.7.7), so a displacement
    /// that is 2 mod 4 has no encoding. A *decoded* instruction can never hit
    /// this — its target is `Align(PC,4)` plus a multiple of four and therefore
    /// word-aligned, and the difference of two word-aligned addresses is always
    /// a multiple of four — so this fires only for a hand-built [`Insn`] whose
    /// [`Operand::Target`] is not word-aligned. It is kept, and named, because
    /// that invariant is exactly the one a sign or alignment slip breaks, and a
    /// bare [`OutOfRange`](Self::OutOfRange) would hide which of the two went
    /// wrong.
    LiteralAlignment {
        /// The instruction's mnemonic.
        mnemonic: &'static str,
        /// The address it was decoded at.
        from: u32,
        /// The address it was asked to move to.
        to: u32,
        /// The resolved target, which does not move.
        target: u32,
    },
    /// The instruction's displacement no longer fits its encoding.
    ///
    /// This is [`isa::encode`]'s `None`, and the only refusal that is decided
    /// by the encoder rather than by this module: the target is held still and
    /// the new displacement offered to the same encoding the instruction came
    /// from. For a narrow direct branch, [`Widen::IfNeeded`] usually turns this
    /// into a success.
    OutOfRange {
        /// The instruction's mnemonic.
        mnemonic: &'static str,
        /// The address it was decoded at.
        from: u32,
        /// The address it was asked to move to.
        to: u32,
        /// The resolved target or pool address that no longer reaches, if the
        /// instruction has one.
        ///
        /// `None` when it carries no [`Operand::Target`] — which relocation of
        /// a *decoded* instruction never produces, because every encoder whose
        /// output depends on the instruction's own address derives that
        /// dependence from a resolved target, so an instruction without one
        /// encodes identically at every address and can never come out of
        /// range by moving. The field stays an `Option` rather than reporting
        /// a fabricated address for a hand-built [`Insn`], or for a future
        /// encoding whose range turns on its address by some other route.
        target: Option<u32>,
    },
    /// This crate cannot encode the instruction at all, at any address.
    ///
    /// Checked by re-encoding it *where it already is*: if that fails too, the
    /// displacement was never the problem. A relocated instruction this module
    /// cannot hand back as bytes is one the caller cannot emit, so refusing is
    /// the honest answer — and naming [`Insn::encoding`] says which of a
    /// mnemonic's several encodings was at issue.
    NotEncodable {
        /// The instruction's mnemonic.
        mnemonic: &'static str,
        /// The architectural encoding name it was decoded as.
        encoding: &'static str,
        /// The address it was decoded at.
        from: u32,
        /// The address it was asked to move to.
        to: u32,
    },
}

impl RelocateError {
    /// A stable, machine-readable reason: `"misaligned-destination"`,
    /// `"reads-pc"`, `"forward-only-branch"`, `"pc-relative-table"`,
    /// `"unresolved-pc-relative"`, `"literal-alignment"`, `"out-of-range"`,
    /// `"not-encodable"`.
    ///
    /// These strings are part of this module's contract. A consumer that logs
    /// or tests against them — a firmware patcher deciding whether to fall
    /// back to a hand-written stub, say — should not have to parse prose or
    /// match on a non-exhaustive enum.
    pub fn reason(&self) -> &'static str {
        match self {
            RelocateError::Misaligned { .. } => "misaligned-destination",
            RelocateError::ReadsPc { .. } => "reads-pc",
            RelocateError::ForwardOnlyBranch { .. } => "forward-only-branch",
            RelocateError::TableBranch { .. } => "pc-relative-table",
            RelocateError::UnresolvedPcRelative { .. } => "unresolved-pc-relative",
            RelocateError::LiteralAlignment { .. } => "literal-alignment",
            RelocateError::OutOfRange { .. } => "out-of-range",
            RelocateError::NotEncodable { .. } => "not-encodable",
        }
    }

    /// The mnemonic of the instruction that could not be moved.
    pub fn mnemonic(&self) -> &'static str {
        match *self {
            RelocateError::Misaligned { mnemonic, .. }
            | RelocateError::ReadsPc { mnemonic, .. }
            | RelocateError::ForwardOnlyBranch { mnemonic, .. }
            | RelocateError::TableBranch { mnemonic, .. }
            | RelocateError::UnresolvedPcRelative { mnemonic, .. }
            | RelocateError::LiteralAlignment { mnemonic, .. }
            | RelocateError::OutOfRange { mnemonic, .. }
            | RelocateError::NotEncodable { mnemonic, .. } => mnemonic,
        }
    }

    /// The address the instruction was decoded at.
    pub fn from(&self) -> u32 {
        match *self {
            RelocateError::Misaligned { from, .. }
            | RelocateError::ReadsPc { from, .. }
            | RelocateError::ForwardOnlyBranch { from, .. }
            | RelocateError::TableBranch { from, .. }
            | RelocateError::UnresolvedPcRelative { from, .. }
            | RelocateError::LiteralAlignment { from, .. }
            | RelocateError::OutOfRange { from, .. }
            | RelocateError::NotEncodable { from, .. } => from,
        }
    }

    /// The address it was asked to move to.
    pub fn to(&self) -> u32 {
        match *self {
            RelocateError::Misaligned { to, .. }
            | RelocateError::ReadsPc { to, .. }
            | RelocateError::ForwardOnlyBranch { to, .. }
            | RelocateError::TableBranch { to, .. }
            | RelocateError::UnresolvedPcRelative { to, .. }
            | RelocateError::LiteralAlignment { to, .. }
            | RelocateError::OutOfRange { to, .. }
            | RelocateError::NotEncodable { to, .. } => to,
        }
    }

    /// Whether another destination address could succeed where this one did
    /// not.
    ///
    /// `false` for the refusals that are properties of the instruction itself,
    /// so a caller searching for somewhere to put a stub knows when to stop
    /// searching.
    pub fn is_address_dependent(&self) -> bool {
        matches!(
            self,
            RelocateError::Misaligned { .. }
                | RelocateError::ForwardOnlyBranch { .. }
                | RelocateError::LiteralAlignment { .. }
                | RelocateError::OutOfRange { .. }
        )
    }
}

impl core::fmt::Display for RelocateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "cannot relocate `{}` from {:#x} to {:#x}: {}",
            self.mnemonic(),
            self.from(),
            self.to(),
            self.reason()
        )?;
        match *self {
            RelocateError::Misaligned { .. } => {
                f.write_str(" (a Thumb instruction is halfword aligned)")
            }
            RelocateError::ReadsPc { .. } => {
                f.write_str(" (the pc value it observes changes with its address)")
            }
            RelocateError::ForwardOnlyBranch { target, .. } => write!(
                f,
                " (target {target:#x} is not 0..126 bytes forward; cbz/cbnz has no backward form)"
            ),
            RelocateError::TableBranch { .. } => {
                f.write_str(" (the table holds offsets from this instruction's own pc)")
            }
            RelocateError::UnresolvedPcRelative { .. } => {
                f.write_str(" (no resolved target accompanies the pc-relative operand)")
            }
            RelocateError::LiteralAlignment { target, .. } => write!(
                f,
                " (target {target:#x} is not a multiple of 4 from Align(pc,4))"
            ),
            RelocateError::OutOfRange {
                target: Some(t), ..
            } => write!(f, " (target {t:#x} no longer reaches)"),
            RelocateError::OutOfRange { target: None, .. } => {
                f.write_str(" (the displacement no longer fits)")
            }
            RelocateError::NotEncodable { encoding, .. } => {
                write!(f, " (this crate cannot encode {encoding})")
            }
        }
    }
}

impl std::error::Error for RelocateError {}

/// Produce the instruction that has the same effect at `to` as `insn` has at
/// [`Insn::addr`].
///
/// Width-preserving: the returned instruction is always the same length as
/// `insn`, so a caller can lay out a buffer knowing the sizes up front. A
/// narrow branch that no longer reaches is refused with
/// [`RelocateError::OutOfRange`] rather than silently widened; ask for
/// [`relocate_with`] with [`Widen::IfNeeded`] when widening is wanted.
///
/// Every success re-encodes: the returned instruction has been passed through
/// [`isa::encode`], so [`isa::encode_bytes`] on it cannot fail.
///
/// ```
/// use thumb_asm::isa;
/// use thumb_asm::relocate::relocate;
///
/// // `b 0x1010` (B T2) at 0x1000, and the same branch four bytes later.
/// let insn = isa::decode_at_with(&[0x06, 0xe0], 0, 0x1000, false).unwrap();
/// assert_eq!(insn.branch_target(), Some(0x1010));
/// let moved = relocate(&insn, 0x1004).unwrap();
/// assert_eq!(moved.branch_target(), Some(0x1010)); // the target did not move
/// assert_eq!(moved.len(), 2); // …and neither did the length
/// assert_eq!(isa::encode_bytes(&moved).unwrap(), vec![0x04, 0xe0]);
/// ```
pub fn relocate(insn: &Insn, to: u32) -> Result<Insn, RelocateError> {
    relocate_with(insn, to, Widen::Never)
}

/// [`relocate`], with control over whether a narrow direct branch may be
/// widened to reach.
///
/// With [`Widen::IfNeeded`] the narrowest encoding that reaches is always
/// chosen, so the result is only four bytes when two will not do. Check
/// [`Insn::len`] on the result; see [`Widen`] for why this is opt-in.
///
/// ```
/// use thumb_asm::isa;
/// use thumb_asm::relocate::{relocate_with, Widen};
///
/// // `b 0x1010` cannot reach 0x1010 from 0x9000 in eleven bits …
/// let insn = isa::decode_at_with(&[0x06, 0xe0], 0, 0x1000, false).unwrap();
/// assert_eq!(relocate_with(&insn, 0x9000, Widen::Never).unwrap_err().reason(), "out-of-range");
///
/// // … but `b.w` spans ±16 MB, and still branches to 0x1010.
/// let wide = relocate_with(&insn, 0x9000, Widen::IfNeeded).unwrap();
/// assert_eq!(wide.branch_target(), Some(0x1010));
/// assert_eq!((wide.mnemonic, wide.encoding, wide.len()), ("b", "T4", 4));
/// ```
pub fn relocate_with(insn: &Insn, to: u32, widen: Widen) -> Result<Insn, RelocateError> {
    relocate_encoded(insn, to, widen).map(|(moved, _)| moved)
}

/// [`relocate_with`], returning the relocated instruction's little-endian
/// bytes.
///
/// The form most callers want, and the one [`crate::detour`] uses: relocation
/// already had to encode the instruction to know the displacement fits, so
/// asking for the bytes costs nothing and removes an `unwrap` from every call
/// site. Two bytes for a narrow instruction, four for a wide one — in
/// word-invariant order, `hw1` first, via [`isa::encode_bytes`].
///
/// ```
/// use thumb_asm::isa;
/// use thumb_asm::relocate::{relocate_bytes, Widen};
///
/// let insn = isa::decode_at_with(&[0x06, 0xe0], 0, 0x1000, false).unwrap();
/// let bytes = relocate_bytes(&insn, 0x9000, Widen::IfNeeded).unwrap();
/// assert_eq!(bytes.len(), 4); // widened to `b.w`
/// assert_eq!(isa::decode_at_with(&bytes, 0, 0x9000, false).unwrap().branch_target(), Some(0x1010));
/// ```
pub fn relocate_bytes(insn: &Insn, to: u32, widen: Widen) -> Result<Vec<u8>, RelocateError> {
    relocate_encoded(insn, to, widen).map(|(_, bytes)| bytes)
}

/// The whole of relocation: the instruction as it should be written at `to`,
/// **and the bytes it encodes to**.
///
/// One function rather than two because deciding that a relocation is possible
/// *is* encoding it — the displacement fits exactly when the encoder says so.
/// Handing the bytes back with the instruction means [`relocate_bytes`] has
/// nothing left that can fail, so there is no second, unreachable encode
/// failure for a caller to wonder about. [`relocate_with`] drops them, which
/// costs one small allocation on a path that is not hot: relocation runs once
/// per displaced instruction, not once per decoded one.
fn relocate_encoded(insn: &Insn, to: u32, widen: Widen) -> Result<(Insn, Vec<u8>), RelocateError> {
    let moved = resite(insn, to)?;
    if let Some(bytes) = isa::encode_bytes(&moved) {
        return Ok((moved, bytes));
    }
    if widen == Widen::IfNeeded {
        if let Some(wide) = widened(insn, to) {
            return Ok(wide);
        }
    }
    Err(encode_failure(insn, to))
}

/// Thumb's `Align(PC,4)`: this instruction's address plus four, forced
/// word-aligned (ARM DDI 0403E.e A4.2.2, A7.3).
fn align_pc(addr: u32) -> u32 {
    addr.wrapping_add(4) & !3
}

/// The instruction as it would be written at `to`, with every address-derived
/// field re-derived — but without asking whether it encodes.
///
/// This is where the refusals that [`isa::encode`] *cannot* see are made:
/// `TBB`, `mov rd, pc` and friends re-encode perfectly at any address and are
/// nonetheless wrong there.
fn resite(insn: &Insn, to: u32) -> Result<Insn, RelocateError> {
    let mnemonic = insn.mnemonic;
    let from = insn.addr;

    if to & 1 != 0 {
        return Err(RelocateError::Misaligned { mnemonic, from, to });
    }
    if matches!(mnemonic, "tbb" | "tbh") {
        return Err(RelocateError::TableBranch { mnemonic, from, to });
    }
    if reads_pc(insn) {
        return Err(RelocateError::ReadsPc { mnemonic, from, to });
    }

    // A pc-relative memory operand carries the displacement *syntactically*
    // (`[pc, #imm]`) as well as resolved (`Operand::Target`), and the encoders
    // cross-check the two — so both have to be updated, or the instruction
    // stops encoding at all. See `t16_loadstore::encode`.
    let mut operands = insn.operands;
    if let Some(mem) = pc_mem(insn) {
        if mem.index.is_some() || mem.mode != AddrMode::Offset {
            return Err(RelocateError::UnresolvedPcRelative { mnemonic, from, to });
        }
        let target = match first_target(insn) {
            Some(t) => t,
            None => return Err(RelocateError::UnresolvedPcRelative { mnemonic, from, to }),
        };
        // `Mem` carries the displacement as an unsigned magnitude plus the
        // architecture's `U` bit, because `#0` and `#-0` are distinct
        // encodings (A7.7.50) — so a zero displacement must keep whichever `U`
        // the instruction already had rather than inventing `add: true` and
        // changing the bytes.
        let disp = i64::from(target) - i64::from(align_pc(to));
        let (offset, add) = if disp > 0 {
            (disp as u32, true)
        } else if disp < 0 {
            ((-disp) as u32, false)
        } else {
            (0, mem.add)
        };
        operands = replace_pc_mem(&insn.operands, Mem { offset, add, ..mem });
    }

    // The narrow `Align(PC,4)` forms scale their immediate by four, so a
    // displacement that is 2 mod 4 has no encoding. Named separately from
    // `OutOfRange` because it is the invariant a sign or alignment slip breaks.
    //
    // Written as one `Option` rather than a nested `if let`, here and for `adr`
    // below, because "this is not a scaled literal form" and "it carries no
    // resolved target" lead to the same place — leave it alone — and only the
    // first of the two happens to a decoded instruction.
    let scaled_target = if insn.width == Width::Narrow && is_align_pc_form(insn) {
        first_target(insn)
    } else {
        None
    };
    if let Some(target) = scaled_target {
        if (i64::from(target) - i64::from(align_pc(to))) % 4 != 0 {
            return Err(RelocateError::LiteralAlignment {
                mnemonic,
                from,
                to,
                target,
            });
        }
    }

    // `ADR.W` is two encodings, not one with a sign: T3 adds the immediate to
    // `Align(PC,4)` and T2 subtracts it (A7.7.7), and `Insn::encoding` is what
    // tells `t32_dp_plainimm::encode` which bits to emit. Moving an `adr` past
    // its own label flips which of the two can express it, and re-labelling it
    // here costs nothing — same mnemonic, same operands, same four bytes — so
    // the alternative would be refusing a relocation that is perfectly
    // representable.
    let mut encoding = insn.encoding;
    let adr_target = if mnemonic == "adr" && insn.width == Width::Wide {
        first_target(insn)
    } else {
        None
    };
    if let Some(target) = adr_target {
        encoding = if target >= align_pc(to) { "T3" } else { "T2" };
    }

    Ok(Insn {
        addr: to,
        encoding,
        operands,
        ..*insn
    })
}

/// Classify an [`isa::encode`] failure after [`resite`] has already passed.
fn encode_failure(insn: &Insn, to: u32) -> RelocateError {
    let mnemonic = insn.mnemonic;
    let from = insn.addr;
    // Re-encoding it where it already is separates "does not fit *there*" from
    // "this crate cannot encode this instruction".
    if isa::encode(insn).is_none() {
        return RelocateError::NotEncodable {
            mnemonic,
            encoding: insn.encoding,
            from,
            to,
        };
    }
    if matches!(mnemonic, "cbz" | "cbnz") {
        return RelocateError::ForwardOnlyBranch {
            mnemonic,
            from,
            to,
            target: first_target(insn).unwrap_or(0),
        };
    }
    RelocateError::OutOfRange {
        mnemonic,
        from,
        to,
        target: first_target(insn),
    }
}

/// The wide form of a narrow direct branch at `to`, or `None` if this is not a
/// branch that can be widened or the wide form does not reach either.
///
/// Built by encoding through the crate's own [`encode_b_wide`] /
/// [`encode_b_cond`] and *decoding the result back*, rather than by
/// hand-assembling an [`Insn`]. That way the returned instruction is by
/// construction exactly what [`isa::Decoder`](crate::isa::Decoder) would
/// report for those bytes — `encoding` of `"T4"`/`"T3"`, `explicit_width` set,
/// condition where T3 carries one — and cannot drift from it.
fn widened(insn: &Insn, to: u32) -> Option<(Insn, Vec<u8>)> {
    if insn.width != Width::Narrow || to & 1 != 0 {
        return None;
    }
    let target = first_target(insn)?;
    let bytes: Vec<u8> = match (insn.mnemonic, insn.encoding, insn.cond) {
        // `B` T2, unconditional in its own right. A `cond` here could only have
        // come from an enclosing `IT` block, and `B.W` T4 is UNPREDICTABLE
        // anywhere but last in one (A7.7.12) — so a governed `b` is left for
        // the caller to think about rather than quietly widened.
        ("b", "T2", None) => encode_b_wide(to as usize, target)?.to_vec(),
        // `B<cond>` T1 widens to T3, which carries the condition in its own
        // encoding exactly as T1 does.
        //
        // [`encode_b_cond`] picks the narrowest form that reaches, and its T1
        // window — `-256..=254`, A7.7.12 — is the same test `t16_branch`'s
        // `fit_disp` applies, which is the one that just failed. So it returns
        // four bytes here. The length is not re-checked because it does not
        // need to be: the instruction handed back is whatever `Decoder` reads
        // in these bytes, so its `width` and `len()` describe them either way.
        ("b", "T1", Some(cond)) if cond != Cond::Al => encode_b_cond(to as usize, cond, target)?,
        _ => return None,
    };
    isa::decode_at_with(&bytes, 0, to, false).map(|wide| (wide, bytes))
}

/// The first [`Operand::Target`], i.e. the resolved branch destination or pool
/// address. Same rule as [`Insn::branch_target`], spelled out here because for
/// a literal access it is a pool address and calling it a branch target would
/// read wrongly.
fn first_target(insn: &Insn) -> Option<u32> {
    insn.operands.as_slice().find_map(|op| match op {
        Operand::Target(t) => Some(t),
        _ => None,
    })
}

/// The instruction's pc-based memory operand, if it has one.
fn pc_mem(insn: &Insn) -> Option<Mem> {
    insn.operands.as_slice().find_map(|op| match op {
        Operand::Mem(m) if m.base == Reg::PC => Some(m),
        _ => None,
    })
}

/// Whether the instruction's target is measured from `Align(PC,4)` rather than
/// from `PC` — the literal accesses and `ADR`.
fn is_align_pc_form(insn: &Insn) -> bool {
    insn.mnemonic == "adr" || pc_mem(insn).is_some()
}

/// `insn.operands` with the pc-based memory operand replaced.
///
/// A whole-list rebuild because [`Operands`] is append-only — it has `push`,
/// `get` and `as_slice`, and no way to assign one slot. That is the right
/// trade for a decoder producing millions of these, and the cost lands here,
/// once.
fn replace_pc_mem(operands: &Operands, mem: Mem) -> Operands {
    operands
        .as_slice()
        .map(|op| match op {
            Operand::Mem(m) if m.base == Reg::PC => Operand::Mem(mem),
            other => other,
        })
        .collect()
}

/// Whether the instruction *reads* `pc` as an ordinary value.
///
/// The rule, stated once: `pc` named anywhere in the operands is a read, except
/// as operand 0 of an instruction whose operand 0 is a destination. That
/// exception is what keeps `mov pc, lr`, `pop {r4, pc}` and `ldr pc, [r0]`
/// relocatable — they *write* pc from a register or from memory, which does not
/// depend on where they are — while `mov r0, pc` and `add r0, pc` are refused.
///
/// [`Insn::writes_pc`] answers a neighbouring but different question and cannot
/// stand in for this: it reports `bx rm` as a pc write, which is true, but `rm`
/// is a *source* there, so `bx pc` (which branches to `Align(PC,4)`, A7.7.20)
/// would be read as relocatable. Hence the local list of mnemonics whose first
/// operand is a source — the stores, the multi-register transfers, the
/// comparisons, and the register branches.
fn reads_pc(insn: &Insn) -> bool {
    let source_first = first_operand_is_source(insn.mnemonic)
        || (destructive_first_operand(insn.mnemonic) && insn.operands.len() == 2);
    insn.operands
        .as_slice()
        .enumerate()
        .any(|(i, op)| match op {
            Operand::Reg(r) => r == Reg::PC && (source_first || i != 0),
            // Always a source: no encoding shifts its destination.
            Operand::RegShifted(r, _) => r == Reg::PC,
            // A pc *base* is the literal form, handled by re-resolving the
            // displacement. A pc *index* has no resolved target to work from.
            Operand::Mem(m) => matches!(m.index, Some((r, _)) if r == Reg::PC),
            // `pc` in a load's register list is a destination (`pop {pc}`); in
            // a store's it is the value being written out.
            Operand::RegList(bits) => source_first && bits & (1 << 15) != 0,
            _ => false,
        })
}

/// Whether operand 0 of this mnemonic is a source rather than a destination.
///
/// The stores, `push`, the multi-register transfers and `srs` name the address
/// or the data first; the comparisons consume both operands; `bx`/`blx
/// (register)`/`bxj` take the branch destination as a source register; and
/// `tbb`/`tbh` take the table base. Mirrors the list in [`Insn::writes_pc`],
/// plus the register branches, which that method deliberately treats the other
/// way round.
/// Whether a two-operand form reads its own first operand as well as writing it.
///
/// The 16-bit data-processing and high-register encodings are destructive:
/// `ADD (register)` T2 is `Rdn = Rdn + Rm` (A5.2.3, A7.7.4), so in
/// `add pc, r0` the `pc` is a *source* — the datum is `PC + R0`, which is the
/// Thumb-1 jump-table dispatch. Judging operand 0 by position alone calls that
/// a pure destination and lets [`relocate`] copy the instruction to a stub,
/// where `PC` is different and every switch case lands at the wrong address.
///
/// `mov` and `mvn` are deliberately absent: their first operand is written and
/// not read, so `mov pc, lr` means the same thing wherever it sits.
fn destructive_first_operand(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "add"
            | "adc"
            | "sub"
            | "sbc"
            | "rsb"
            | "and"
            | "orr"
            | "orn"
            | "eor"
            | "bic"
            | "mul"
            | "lsl"
            | "lsr"
            | "asr"
            | "ror"
    )
}

fn first_operand_is_source(mnemonic: &str) -> bool {
    mnemonic.starts_with("str")
        || mnemonic.starts_with("vstr")
        || mnemonic.starts_with("vstm")
        || mnemonic.starts_with("vldm")
        || mnemonic.starts_with("stm")
        || mnemonic.starts_with("srs")
        || mnemonic.starts_with("ldm")
        || mnemonic.starts_with("rfe")
        || matches!(
            mnemonic,
            "push"
                | "vpush"
                | "cmp"
                | "cmn"
                | "tst"
                | "teq"
                | "chka"
                | "bx"
                | "blx"
                | "bxj"
                | "tbb"
                | "tbh"
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::{Decoder, ShiftAmount, ShiftKind};

    /// Decode one instruction from `bytes` as if it lived at `addr`.
    fn at(bytes: &[u8], addr: u32) -> Insn {
        isa::decode_at_with(bytes, 0, addr, false).expect("test vector must decode")
    }

    /// The bytes a relocated instruction assembles to.
    fn bytes_at(insn: &Insn, to: u32) -> Vec<u8> {
        relocate_bytes(insn, to, Widen::Never).expect("must relocate")
    }

    // ----------------------------------------------------- relocatable cases

    /// The overwhelmingly common case: nothing in the encoding depends on the
    /// address, so only `addr` changes and the bytes are identical.
    #[test]
    fn an_address_independent_instruction_only_changes_its_address() {
        let insn = at(&[0x01, 0x20], 0x1000); // movs r0, #1
        assert_eq!(insn.to_string(), "movs r0, #1");
        let moved = relocate(&insn, 0x9_0000).unwrap();
        assert_eq!(moved.addr, 0x9_0000);
        assert_eq!(moved.operands, insn.operands);
        assert_eq!(bytes_at(&insn, 0x9_0000), vec![0x01, 0x20]);
    }

    /// A direct branch's target is absolute in this crate's vocabulary, so it
    /// does not move; the *displacement* is re-derived, and the instruction is
    /// refused when it no longer fits.
    #[test]
    fn a_narrow_unconditional_branch_keeps_its_target() {
        // `b 0x1010` at 0x1000: imm11 = (0x1010 - 0x1004) / 2 = 6.
        let insn = at(&[0x06, 0xe0], 0x1000);
        assert_eq!((insn.mnemonic, insn.encoding), ("b", "T2"));
        assert_eq!(insn.branch_target(), Some(0x1010));

        // Four bytes later the displacement is four smaller: imm11 = 2.
        let moved = relocate(&insn, 0x1004).unwrap();
        assert_eq!(moved.branch_target(), Some(0x1010));
        assert_eq!(bytes_at(&insn, 0x1004), vec![0x04, 0xe0]);

        // Backwards, too: from 0x1020 the displacement is -0x14, i.e. -10
        // halfwords, which is 0x7F6 in eleven bits.
        assert_eq!(bytes_at(&insn, 0x1020), vec![0xf6, 0xe7]);
        assert_eq!(at(&[0xf6, 0xe7], 0x1020).branch_target(), Some(0x1010));

        // ±2046 bytes is all there is (A7.7.12), so a stub cannot hold one.
        let err = relocate(&insn, 0x9000).unwrap_err();
        assert_eq!(err.reason(), "out-of-range");
        assert!(err.is_address_dependent());
    }

    /// `B<cond>` T1's range is −256/+254, not ±256: the offset is
    /// `SignExtend(imm8:'0')`, so the most positive `imm8` is 127 (+254) while
    /// the most negative is −128 (−256). The asymmetry is real and is pinned
    /// here from both ends.
    #[test]
    fn a_narrow_conditional_branch_has_an_asymmetric_range() {
        // `bhi` at 0x1000 with imm8 = 0x7f: target = 0x1000 + 4 + 254 = 0x1102.
        let insn = at(&[0x7f, 0xd8], 0x1000);
        assert_eq!(insn.mnemonic, "b");
        assert_eq!(insn.cond, Some(Cond::Hi));
        assert_eq!(insn.branch_target(), Some(0x1102));

        // +254 is the last reachable forward displacement …
        assert_eq!(bytes_at(&insn, 0x1000), vec![0x7f, 0xd8]);
        // … and +256, two bytes lower down, is already too far.
        assert_eq!(
            relocate(&insn, 0x0ffe).unwrap_err().reason(),
            "out-of-range"
        );

        // -256 *is* reachable, which +256 is not.
        assert_eq!(bytes_at(&insn, 0x11fe), vec![0x80, 0xd8]);
        // -258 is not.
        assert_eq!(
            relocate(&insn, 0x1200).unwrap_err().reason(),
            "out-of-range"
        );

        // Every accepted relocation still branches to the same place.
        for to in [0x1000, 0x1100, 0x11fe] {
            let moved = relocate(&insn, to).unwrap();
            let bytes = isa::encode_bytes(&moved).unwrap();
            assert_eq!(at(&bytes, to).branch_target(), Some(0x1102), "from {to:#x}");
        }
    }

    /// The test most likely to catch a sign or alignment error: a literal load
    /// moved anywhere must still read *the same pool word*.
    ///
    /// Note what the expected bytes say about `Align(PC,4)`. Moving from 0x1000
    /// to 0x1002 leaves the displacement alone, because both addresses have the
    /// same word-aligned pc; moving to 0x1004 shortens it by four, not by two.
    /// An implementation that subtracted `to - from` from the old displacement
    /// would be wrong at 0x1002 and wrong again at 0x0ffe.
    #[test]
    fn a_literal_load_still_reads_the_same_pool_word() {
        // `ldr r0, [pc, #8]` at 0x1000 — Align(pc,4) = 0x1004, pool at 0x100c.
        let insn = at(&[0x02, 0x48], 0x1000);
        assert_eq!((insn.mnemonic, insn.encoding), ("ldr", "T1"));
        assert_eq!(insn.branch_target(), Some(0x100c));
        assert_eq!(insn.to_string(), "ldr r0, [pc, #8], 0x100c");

        // (destination, expected bytes, expected syntactic displacement)
        let cases = [
            (0x0ffeu32, [0x03u8, 0x48], 12i64), // Align(pc,4) = 0x1000
            (0x1000, [0x02, 0x48], 8),          // Align(pc,4) = 0x1004
            (0x1002, [0x02, 0x48], 8),          // Align(pc,4) = 0x1004 — unchanged
            (0x1004, [0x01, 0x48], 4),          // Align(pc,4) = 0x1008 — stepped by 4
            (0x1006, [0x01, 0x48], 4),
            (0x1008, [0x00, 0x48], 0), // `ldr r0, [pc]`
            (0x100a, [0x00, 0x48], 0), // same Align(pc,4) as 0x1008
        ];
        for (to, want, want_offset) in cases {
            let moved = relocate(&insn, to).unwrap();
            // Both views of the address agree, which is what the encoders
            // cross-check: the resolved pool word …
            assert_eq!(moved.branch_target(), Some(0x100c), "from {to:#x}");
            // … and the syntactic `[pc, #imm]`.
            let mem = pc_mem(&moved).expect("pc-relative");
            assert_eq!(mem.displacement(), want_offset, "from {to:#x}");
            assert_eq!(isa::encode_bytes(&moved).unwrap(), want, "from {to:#x}");
            // And the bytes, decoded where they now live, resolve back to the
            // same word — the property the whole module exists for.
            assert_eq!(at(&want, to).branch_target(), Some(0x100c), "from {to:#x}");
        }

        // 0x100c is the first address whose Align(pc,4) is *above* the pool, so
        // it needs a negative displacement — which T1 cannot encode (imm8 is
        // unsigned, A7.7.44). That is a range refusal, not an alignment one.
        assert_eq!(
            relocate(&insn, 0x100c).unwrap_err().reason(),
            "out-of-range"
        );
    }

    /// The wide literal form is byte-granular and signed (`U` selects add or
    /// subtract, A7.7.44 encoding T2), so it relocates in both directions.
    #[test]
    fn a_wide_literal_load_relocates_in_both_directions() {
        // `ldr.w r0, [pc, #8]` at 0x1000: hw1 = 0xf8df (U = 1, Rn = pc),
        // hw2 = 0x0008 (Rt = r0).
        let insn = at(&[0xdf, 0xf8, 0x08, 0x00], 0x1000);
        assert_eq!((insn.mnemonic, insn.encoding), ("ldr", "T2"));
        assert_eq!(insn.branch_target(), Some(0x100c));

        // Above the pool, the offset goes negative and `U` clears.
        let moved = relocate(&insn, 0x2000).unwrap();
        assert_eq!(moved.branch_target(), Some(0x100c));
        assert_eq!(pc_mem(&moved).unwrap().displacement(), 0x100c - 0x2004);
        assert!(
            !pc_mem(&moved).unwrap().add,
            "U must be clear below the pool"
        );
        let bytes = isa::encode_bytes(&moved).unwrap();
        assert_eq!(bytes[0] & 0x80, 0, "U must be clear for a subtracting form");
        assert_eq!(at(&bytes, 0x2000).branch_target(), Some(0x100c));

        // ±4095 is the immediate's whole range, either way. From a
        // word-aligned target the reachable extremes are multiples of four, so
        // 4092 reaches and 4096 does not.
        assert!(relocate(&insn, 0x2004).is_ok()); // displacement -4092
        assert_eq!(
            relocate(&insn, 0x2008).unwrap_err().reason(), // -4096
            "out-of-range"
        );
        assert!(relocate(&insn, 0x000c).is_ok()); // displacement +4092
        assert_eq!(
            relocate(&insn, 0x0008).unwrap_err().reason(), // +4096
            "out-of-range"
        );
    }

    /// `ADR.W` is two encodings — T3 adds, T2 subtracts — so an `adr` moved
    /// past its own label has to change which one it claims to be, or it stops
    /// encoding for a reason that has nothing to do with range.
    #[test]
    fn a_wide_adr_flips_between_its_adding_and_subtracting_forms() {
        // `adr.w r0, 0x1004` at 0x1000 (T3, imm12 = 0).
        let insn = at(&[0x0f, 0xf2, 0x00, 0x00], 0x1000);
        assert_eq!((insn.mnemonic, insn.encoding), ("adr", "T3"));
        assert_eq!(insn.branch_target(), Some(0x1004));

        // Below the label: still T3, a positive displacement.
        let up = relocate(&insn, 0x0f00).unwrap();
        assert_eq!(up.encoding, "T3");
        assert_eq!(up.branch_target(), Some(0x1004));

        // Above it: T2, and the bytes decode back to the same label.
        let down = relocate(&insn, 0x1ffc).unwrap();
        assert_eq!(down.encoding, "T2");
        let bytes = isa::encode_bytes(&down).unwrap();
        let back = at(&bytes, 0x1ffc);
        assert_eq!((back.mnemonic, back.encoding), ("adr", "T2"));
        assert_eq!(back.branch_target(), Some(0x1004));

        // 4095 bytes is the reach of the 12-bit immediate.
        assert_eq!(
            relocate(&insn, 0x2000).unwrap_err().reason(),
            "out-of-range"
        );
    }

    /// An instruction that writes `pc` from a register or from memory is
    /// address-independent and relocates freely; only *reading* pc is a
    /// problem.
    #[test]
    fn writing_pc_is_relocatable_even_though_reading_it_is_not() {
        for (bytes, text) in [
            (vec![0x70, 0x47], "bx lr"),
            (vec![0x10, 0xbd], "pop {r4, pc}"),
            (vec![0xf7, 0x46], "mov pc, lr"),
        ] {
            let insn = at(&bytes, 0x1000);
            assert_eq!(insn.to_string(), text);
            assert!(insn.writes_pc(), "{text}");
            assert_eq!(bytes_at(&insn, 0x9_0000), bytes, "{text}");
        }
    }

    /// A whole IT block moves together, so its governed instructions are
    /// relocated with the condition `Decoder` filled in — and must still
    /// encode to the same halfwords, since the condition lives in the `IT`,
    /// not in them.
    #[test]
    fn an_it_governed_instruction_relocates_to_the_same_halfword() {
        // it eq · movs r0, #1
        let image = [0x08, 0xbf, 0x01, 0x20];
        let mut d = Decoder::at(&image, 0, 0x1000);
        let it = d.next().unwrap();
        assert_eq!(it.mnemonic, "it");
        let governed = d.next().unwrap();
        assert_eq!(governed.cond, Some(Cond::Eq));
        // `Decoder` clears `sets_flags` inside an IT block, because the narrow
        // encodings specify `setflags = !InITBlock()`.
        assert!(!governed.sets_flags);
        assert_eq!(bytes_at(&governed, 0x9_0002), vec![0x01, 0x20]);
        assert_eq!(bytes_at(&it, 0x9_0000), vec![0x08, 0xbf]);
    }

    // -------------------------------------------------------- refusal cases

    /// `cbz`/`cbnz` branch forward only, 0..126 bytes, unsigned — no backward
    /// form exists (A7.7.21), so a stub in free space can never host one.
    #[test]
    fn cbz_and_cbnz_are_refused_as_forward_only() {
        // `cbz r0, 0x100c` at 0x1000 (offset 8) and the `cbnz` beside it.
        for (bytes, mnemonic) in [([0x20, 0xb1], "cbz"), ([0x20, 0xb9], "cbnz")] {
            let insn = at(&bytes, 0x1000);
            assert_eq!(insn.mnemonic, mnemonic);
            assert_eq!(insn.branch_target(), Some(0x100c));

            let err = relocate(&insn, 0x9_0000).unwrap_err();
            assert_eq!(err.reason(), "forward-only-branch");
            assert_eq!(err.mnemonic(), mnemonic);
            assert_eq!(
                err,
                RelocateError::ForwardOnlyBranch {
                    mnemonic,
                    from: 0x1000,
                    to: 0x9_0000,
                    target: 0x100c,
                }
            );
            // Widening does not help: there is no wide `cbz`.
            assert!(relocate_with(&insn, 0x9_0000, Widen::IfNeeded).is_err());
            // Nor does moving backwards, which is the direction a stub sits in
            // only by accident.
            assert_eq!(
                relocate(&insn, 0x100e).unwrap_err().reason(),
                "forward-only-branch"
            );
        }
    }

    /// `tbb`/`tbh` re-encode perfectly at a new address and are nonetheless
    /// broken there, because the table holds offsets from the instruction's own
    /// pc (A7.7.185). This is the refusal `isa::encode` cannot make.
    #[test]
    fn a_table_branch_is_refused_although_it_re_encodes() {
        // `tbb [r0, r1]`.
        let insn = at(&[0xd0, 0xe8, 0x01, 0xf0], 0x1000);
        assert_eq!(insn.mnemonic, "tbb");

        // The encoder is perfectly happy with it at its new address …
        let naive = Insn {
            addr: 0x9_0000,
            ..insn
        };
        assert!(
            isa::encode(&naive).is_some(),
            "nothing in the bits depends on the address, which is the trap"
        );
        // … and this module refuses it anyway.
        let err = relocate(&insn, 0x9_0000).unwrap_err();
        assert_eq!(err.reason(), "pc-relative-table");
        assert!(!err.is_address_dependent());

        // `tbh [pc, r0, lsl #1]` — the pc-based form, same refusal and not the
        // `reads-pc` one, because the table-branch reason is the larger truth.
        let tbh = at(&[0xdf, 0xe8, 0x10, 0xf0], 0x1000);
        assert_eq!(tbh.mnemonic, "tbh");
        assert_eq!(
            relocate(&tbh, 0x2000).unwrap_err().reason(),
            "pc-relative-table"
        );
    }

    /// Reading `pc` as a value: the datum is the instruction's own address plus
    /// four, so no encoding can compensate.
    #[test]
    fn instructions_that_read_pc_are_refused() {
        for (bytes, text) in [
            (vec![0x78, 0x46], "mov r0, pc"),
            (vec![0x78, 0x44], "add r0, pc"),
            (vec![0x78, 0x45], "cmp r0, pc"),
            (vec![0x78, 0x47], "bx pc"),
        ] {
            let insn = at(&bytes, 0x1000);
            assert_eq!(insn.to_string(), text);
            let err = relocate(&insn, 0x2000).unwrap_err();
            assert_eq!(err.reason(), "reads-pc", "{text}");
            assert!(!err.is_address_dependent(), "{text}");
        }
    }

    /// A pc index rather than a pc base: there is no resolved target to
    /// recompute a displacement from, and the architecture does not define the
    /// form either.
    #[test]
    fn a_pc_indexed_memory_operand_is_refused() {
        // Hand-built, because no encoding produces it: `ldr r0, [r1, pc]`.
        let mut operands = Operands::new();
        operands.push(Operand::Reg(Reg(0)));
        operands.push(Operand::Mem(Mem {
            base: Reg(1),
            index: Some((
                Reg::PC,
                Some(crate::isa::Shift {
                    kind: ShiftKind::Lsl,
                    amount: ShiftAmount::Imm(0),
                }),
            )),
            offset: 0,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        }));
        let insn = Insn {
            mnemonic: "ldr",
            encoding: "T2",
            addr: 0x1000,
            width: Width::Wide,
            cond: None,
            sets_flags: false,
            explicit_width: false,
            operands,
        };
        assert_eq!(relocate(&insn, 0x2000).unwrap_err().reason(), "reads-pc");
    }

    /// An indexed or writing-back pc-relative operand is refused — and both
    /// shapes come out of *decoded* bytes, not just out of a hand-built
    /// [`Insn`].
    ///
    /// `ldrd rt, rt2, [pc], #imm` and `vst4 {…}, [pc], rm` are UNPREDICTABLE
    /// (A7.7.44 gives the literal forms no index and no writeback), which is
    /// not a promise that they are absent from an image: these are halfwords a
    /// firmware blob can contain and this crate does decode. The displacement
    /// they would need after the move cannot be computed — writeback changes
    /// the base the crate is holding still — so the answer is a named refusal
    /// rather than plausible bytes.
    #[test]
    fn an_indexed_or_writing_back_pc_operand_is_refused() {
        // `ldrd r0, r0, [pc], #-0` — post-indexed, no register index.
        let post = at(&[0x7f, 0xe8, 0x00, 0x00], 0x1000);
        assert_eq!(post.mnemonic, "ldrd");
        assert_eq!(pc_mem(&post).unwrap().mode, AddrMode::PostIndex);
        let err = relocate(&post, 0x2000).unwrap_err();
        assert_eq!(err.reason(), "unresolved-pc-relative");
        assert_eq!(err.mnemonic(), "ldrd");
        assert!(!err.is_address_dependent(), "no address can fix it");

        // `vst4.8 {d0-d3}, [pc], r0` — a register index on a pc base, which is
        // the shape with no resolvable address at all.
        let indexed = at(&[0x0f, 0xf9, 0x00, 0x00], 0x1000);
        let mem = pc_mem(&indexed).unwrap();
        assert!(mem.index.is_some());
        assert_eq!(
            relocate(&indexed, 0x2000).unwrap_err().reason(),
            "unresolved-pc-relative"
        );
    }

    /// Reading `pc` through a shifted-register operand is still reading `pc`.
    ///
    /// `Rm == pc` is UNPREDICTABLE in the shifted-register data-processing
    /// encodings, and decodes anyway — so a relocation that trusted the
    /// register list alone would copy `tst.w r0, pc, lsl #8` into a stub where
    /// the value it tests is a different address.
    #[test]
    fn a_shifted_pc_operand_is_read_as_pc() {
        // tst.w r0, pc, lsl #8 — hw1 0xEA10, hw2 0x2F0F.
        let insn = at(&[0x10, 0xea, 0x0f, 0x2f], 0x1000);
        assert_eq!(insn.to_string(), "tst.w r0, pc, lsl #8");
        assert!(reads_pc(&insn));
        let err = relocate(&insn, 0x2000).unwrap_err();
        assert_eq!(err.reason(), "reads-pc");
        assert!(!err.is_address_dependent());

        // The same instruction over an ordinary register moves byte-identically
        // — it is the `pc`, not the shift, that is the problem.
        let ordinary = at(&[0x10, 0xea, 0x01, 0x2f], 0x1000);
        assert_eq!(ordinary.to_string(), "tst.w r0, r1, lsl #8");
        assert!(!reads_pc(&ordinary));
        assert_eq!(bytes_at(&ordinary, 0x9_0000), vec![0x10, 0xea, 0x01, 0x2f]);
    }

    /// A pc-relative memory operand with no resolved target cannot be
    /// re-based, because re-basing *is* holding the resolved address still.
    #[test]
    fn a_pc_relative_operand_without_a_target_is_refused() {
        let mut operands = Operands::new();
        operands.push(Operand::Reg(Reg(0)));
        operands.push(Operand::Mem(Mem {
            base: Reg::PC,
            index: None,
            offset: 8,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        }));
        let insn = Insn {
            mnemonic: "ldr",
            encoding: "T1",
            addr: 0x1000,
            width: Width::Narrow,
            cond: None,
            sets_flags: false,
            explicit_width: false,
            operands,
        };
        let err = relocate(&insn, 0x2000).unwrap_err();
        assert_eq!(err.reason(), "unresolved-pc-relative");
        assert!(!err.is_address_dependent());
    }

    /// The alignment invariant, guarded.
    ///
    /// A decoded narrow literal access can never trip this — its target is
    /// `Align(PC,4)` plus a multiple of four, so the displacement from any
    /// other `Align(PC,4)` is a multiple of four as well. The refusal exists
    /// for a hand-built or hand-edited [`Insn`], which is precisely how a sign
    /// or shift slip in a caller's own arithmetic arrives here.
    #[test]
    fn a_narrow_literal_with_a_misaligned_target_is_refused() {
        let insn = at(&[0x02, 0x48], 0x1000); // ldr r0, [pc, #8] -> 0x100c
                                              // Two too high: not a multiple of four from any Align(pc,4).
        let bogus = Insn {
            operands: insn
                .operands
                .as_slice()
                .map(|op| match op {
                    Operand::Target(_) => Operand::Target(0x100e),
                    other => other,
                })
                .collect(),
            ..insn
        };
        let err = relocate(&bogus, 0x1000).unwrap_err();
        assert_eq!(err.reason(), "literal-alignment");
        assert_eq!(
            err,
            RelocateError::LiteralAlignment {
                mnemonic: "ldr",
                from: 0x1000,
                to: 0x1000,
                target: 0x100e,
            }
        );
    }

    /// An odd destination is not an address a Thumb instruction can have.
    #[test]
    fn an_odd_destination_is_refused() {
        let insn = at(&[0x01, 0x20], 0x1000);
        let err = relocate(&insn, 0x2001).unwrap_err();
        assert_eq!(err.reason(), "misaligned-destination");
        assert_eq!(err.to(), 0x2001);
        // Including for a branch that would otherwise widen.
        let branch = at(&[0x06, 0xe0], 0x1000);
        assert_eq!(
            relocate_with(&branch, 0x9001, Widen::IfNeeded)
                .unwrap_err()
                .reason(),
            "misaligned-destination"
        );
    }

    /// An instruction this crate cannot encode is refused with the encoding
    /// named, and is distinguished from one that merely does not reach.
    #[test]
    fn an_unencodable_instruction_is_refused_by_name() {
        let insn = Insn {
            mnemonic: "frobnicate",
            encoding: "T9",
            addr: 0x1000,
            width: Width::Narrow,
            cond: None,
            sets_flags: false,
            explicit_width: false,
            operands: Operands::new(),
        };
        let err = relocate(&insn, 0x2000).unwrap_err();
        assert_eq!(err.reason(), "not-encodable");
        assert_eq!(
            err,
            RelocateError::NotEncodable {
                mnemonic: "frobnicate",
                encoding: "T9",
                from: 0x1000,
                to: 0x2000,
            }
        );
        // Widening cannot rescue it either: there is no target to widen
        // towards, so the refusal is the same one.
        assert_eq!(
            relocate_with(&insn, 0x2000, Widen::IfNeeded).unwrap_err(),
            err
        );
    }

    /// Both shapes of the range message, including the one for an instruction
    /// with no resolved target — see [`RelocateError::OutOfRange`]'s `target`
    /// field for why this crate's own relocation cannot produce it and why the
    /// variant still carries an `Option`.
    #[test]
    fn the_range_message_says_what_no_longer_reaches() {
        let with_target = RelocateError::OutOfRange {
            mnemonic: "b",
            from: 0x1000,
            to: 0x9000,
            target: Some(0x1010),
        };
        assert_eq!(
            with_target.to_string(),
            "cannot relocate `b` from 0x1000 to 0x9000: out-of-range \
             (target 0x1010 no longer reaches)"
        );

        let without_target = RelocateError::OutOfRange {
            mnemonic: "b",
            from: 0x1000,
            to: 0x9000,
            target: None,
        };
        assert_eq!(
            without_target.to_string(),
            "cannot relocate `b` from 0x1000 to 0x9000: out-of-range \
             (the displacement no longer fits)"
        );
    }

    /// `Display` hands a sink's failure back rather than swallowing it or
    /// panicking. A firmware tool may well be formatting into a fixed buffer,
    /// and `core::fmt::Write` is allowed to fail there.
    #[test]
    fn display_propagates_a_write_failure() {
        /// A sink with no room in it.
        struct Full;

        impl core::fmt::Write for Full {
            fn write_str(&mut self, _: &str) -> core::fmt::Result {
                Err(core::fmt::Error)
            }
        }

        let err = RelocateError::Misaligned {
            mnemonic: "movs",
            from: 0x1000,
            to: 0x2001,
        };
        assert!(core::fmt::write(&mut Full, format_args!("{err}")).is_err());
    }

    // -------------------------------------------------------------- widening

    /// `B` T2 widens to `B.W` T4 only when asked, and only when it has to.
    #[test]
    fn widening_an_unconditional_branch_is_opt_in_and_minimal() {
        let insn = at(&[0x06, 0xe0], 0x1000); // b 0x1010

        // In range: the narrow form is kept even with widening allowed.
        let near = relocate_with(&insn, 0x1004, Widen::IfNeeded).unwrap();
        assert_eq!((near.width, near.len()), (Width::Narrow, 2));
        assert_eq!(near.encoding, "T2");

        // Out of range: T4, four bytes, same target, and it decodes back.
        let far = relocate_with(&insn, 0x9000, Widen::IfNeeded).unwrap();
        assert_eq!((far.mnemonic, far.encoding, far.len()), ("b", "T4", 4));
        assert!(far.explicit_width);
        assert_eq!(far.branch_target(), Some(0x1010));
        let bytes = isa::encode_bytes(&far).unwrap();
        assert_eq!(bytes.len(), 4);
        assert_eq!(at(&bytes, 0x9000).branch_target(), Some(0x1010));
        // And the same bytes read by the standalone `B.W` decoder, which
        // measures from the offset it is given.
        assert_eq!(
            crate::encode_b_wide(0x9000, 0x1010)
                .as_ref()
                .map(|b| &b[..]),
            Some(&bytes[..])
        );

        // Beyond ±16 MB even T4 cannot reach, and the original error stands.
        assert_eq!(
            relocate_with(&insn, 0x200_0000, Widen::IfNeeded)
                .unwrap_err()
                .reason(),
            "out-of-range"
        );
    }

    /// `B<cond>` T1 widens to `B<cond>.W` T3, which carries the condition in
    /// its own encoding — so the relocated branch is still conditional, and
    /// still conditional on the same thing.
    #[test]
    fn widening_a_conditional_branch_keeps_its_condition() {
        let insn = at(&[0x7f, 0xd8], 0x1000); // bhi 0x1102
        let far = relocate_with(&insn, 0x9000, Widen::IfNeeded).unwrap();
        assert_eq!((far.mnemonic, far.encoding, far.len()), ("b", "T3", 4));
        assert_eq!(far.cond, Some(Cond::Hi));
        assert_eq!(far.branch_target(), Some(0x1102));

        let bytes = isa::encode_bytes(&far).unwrap();
        let back = crate::decode_b_cond(&bytes, 0).unwrap();
        assert_eq!(back.cond, Cond::Hi);
        assert_eq!(back.len, 4);
        let decoded = at(&bytes, 0x9000);
        assert_eq!(decoded.cond, Some(Cond::Hi));
        assert_eq!(decoded.branch_target(), Some(0x1102));

        // T3 spans ±1 MB and no further: 0x10_0000 still reaches 0x1102, and
        // twice that does not.
        assert!(relocate_with(&insn, 0x10_0000, Widen::IfNeeded).is_ok());
        assert_eq!(
            relocate_with(&insn, 0x20_0000, Widen::IfNeeded)
                .unwrap_err()
                .reason(),
            "out-of-range"
        );
    }

    /// Widening is for direct branches. A `b` made conditional by an enclosing
    /// `IT` is not widened, because `B.W` T4 is UNPREDICTABLE anywhere but last
    /// in an IT block — and neither is a literal access, whose wide form reaches
    /// no further in the way that matters.
    #[test]
    fn widening_is_limited_to_direct_branches() {
        // A `b` T2 governed by an `IT`: same halfword, but `cond` is set.
        let image = [0x08, 0xbf, 0x06, 0xe0]; // it eq · b 0x1014
        let mut d = Decoder::at(&image, 0, 0x1000);
        d.next().unwrap();
        let governed = d.next().unwrap();
        assert_eq!((governed.mnemonic, governed.encoding), ("b", "T2"));
        assert_eq!(governed.cond, Some(Cond::Eq));
        assert_eq!(
            relocate_with(&governed, 0x9000, Widen::IfNeeded)
                .unwrap_err()
                .reason(),
            "out-of-range"
        );

        // A narrow literal load is refused, not widened.
        let ldr = at(&[0x02, 0x48], 0x1000);
        let err = relocate_with(&ldr, 0x9000, Widen::IfNeeded).unwrap_err();
        assert_eq!(err.reason(), "out-of-range");
        assert_eq!(err.mnemonic(), "ldr");

        // And an instruction that is *already* wide has nothing to widen to:
        // `ldr.w r0, [pc, #8]` reaches ±4095 and no further, whatever the
        // caller is willing to spend. The refusal is the same as with
        // `Widen::Never`, which is what says widening was not tried.
        let wide = at(&[0xdf, 0xf8, 0x08, 0x00], 0x1000);
        assert_eq!(wide.width, Width::Wide);
        assert_eq!(
            relocate_with(&wide, 0x9000, Widen::IfNeeded).unwrap_err(),
            relocate_with(&wide, 0x9000, Widen::Never).unwrap_err()
        );
        assert_eq!(
            relocate_with(&wide, 0x9000, Widen::IfNeeded)
                .unwrap_err()
                .reason(),
            "out-of-range"
        );
    }

    /// The contract, over the whole 16-bit encoding space: an instruction that
    /// names no pc-derived operand relocates to *byte-identical* bytes.
    ///
    /// A sweep rather than a list, because that is the invariant the rest of the
    /// module rests on — relocation is a byte copy except where it provably is
    /// not — and because it is the cheapest possible cross-check against the
    /// encoders: any group whose `encode` disagrees with its `decode` about an
    /// address-independent field shows up here as a changed halfword.
    #[test]
    fn address_independent_instructions_relocate_byte_identically() {
        let mut checked = 0usize;
        for hw in 0x0000u16..=0xFFFF {
            if isa::insn_len(hw) != 2 {
                continue;
            }
            let bytes = hw.to_le_bytes();
            let insn = match isa::decode_at_with(&bytes, 0, 0x1000, false) {
                Some(i) => i,
                None => continue,
            };
            // Only the instructions this module promises nothing about are
            // skipped: anything pc-derived, and anything the crate cannot
            // re-encode where it already is.
            if first_target(&insn).is_some()
                || reads_pc(&insn)
                || pc_mem(&insn).is_some()
                || isa::encode(&insn).is_none()
            {
                continue;
            }
            checked += 1;
            let moved = relocate(&insn, 0x2000);
            assert!(moved.is_ok(), "{insn} ({hw:#06x}) must relocate: {moved:?}");
            let moved = moved.unwrap();
            assert_eq!(moved.addr, 0x2000, "{insn} ({hw:#06x})");
            assert_eq!(
                isa::encode_bytes(&moved).as_deref(),
                Some(&bytes[..]),
                "{insn} ({hw:#06x}) changed under relocation"
            );
        }
        // A floor, so a decoder regression cannot make this test vacuous.
        assert!(checked > 20_000, "only {checked} instructions swept");
    }

    /// Every refusal's reason string, in one place, so a change to one is a
    /// change to this test.
    #[test]
    fn reason_strings_are_stable() {
        let all = [
            (
                RelocateError::Misaligned {
                    mnemonic: "movs",
                    from: 0,
                    to: 1,
                },
                "misaligned-destination",
            ),
            (
                RelocateError::ReadsPc {
                    mnemonic: "mov",
                    from: 0,
                    to: 2,
                },
                "reads-pc",
            ),
            (
                RelocateError::ForwardOnlyBranch {
                    mnemonic: "cbz",
                    from: 0,
                    to: 2,
                    target: 4,
                },
                "forward-only-branch",
            ),
            (
                RelocateError::TableBranch {
                    mnemonic: "tbb",
                    from: 0,
                    to: 2,
                },
                "pc-relative-table",
            ),
            (
                RelocateError::UnresolvedPcRelative {
                    mnemonic: "ldr",
                    from: 0,
                    to: 2,
                },
                "unresolved-pc-relative",
            ),
            (
                RelocateError::LiteralAlignment {
                    mnemonic: "ldr",
                    from: 0,
                    to: 2,
                    target: 6,
                },
                "literal-alignment",
            ),
            (
                RelocateError::OutOfRange {
                    mnemonic: "b",
                    from: 0,
                    to: 2,
                    target: Some(4),
                },
                "out-of-range",
            ),
            (
                RelocateError::NotEncodable {
                    mnemonic: "x",
                    encoding: "T1",
                    from: 0,
                    to: 2,
                },
                "not-encodable",
            ),
        ];
        for (err, reason) in all {
            assert_eq!(err.reason(), reason);
            // Every message names the instruction and both addresses.
            let text = err.to_string();
            assert!(text.contains(err.mnemonic()), "{text}");
            assert!(text.contains(reason), "{text}");
        }
    }

    /// Hand-derived vectors, deliberately *not* driven by `reads_pc`.
    ///
    /// The sweep above asks `reads_pc` which instructions to skip, so it can
    /// only ever confirm that predicate's own opinion of itself — which is how
    /// `add pc, rN` was relocated silently for as long as it was. These vectors
    /// come from the encoding diagrams instead: `ADD (register)` T2 is
    /// `Rdn = Rdn + Rm` (A7.7.4), so `add pc, rN` reads `pc` and its value
    /// changes the moment it moves. It is the Thumb-1 jump-table dispatch, and
    /// relocating it sends every switch case to the wrong address.
    #[test]
    fn a_destructive_first_operand_reads_pc_and_cannot_be_relocated() {
        // `add pc, rM` for every M: `0100 0100 1 Rm(4) 111`.
        for m in 0..16u16 {
            let hw = 0x4487 | (m << 3);
            // `decode_at_with(bytes, 0, 0x102, …)`: offset zero into a
            // two-byte slice, *addressed* at 0x102. Passing 0x102 as the offset
            // reads past the end, yields `None`, and would make every assertion
            // below unreachable — the vacuous-sweep shape this file is supposed
            // to be guarding against.
            // `assert!` then `unwrap`, not `unwrap_or_else(|| panic!(…))`:
            // the closure is a function that never runs, and this crate's
            // coverage gate is 100% of functions.
            let decoded = crate::isa::decode_at_with(&hw.to_le_bytes(), 0, 0x102, false);
            assert!(decoded.is_some(), "{hw:#06x} must decode");
            let insn = decoded.unwrap();
            assert_eq!(insn.mnemonic, "add", "{hw:#06x}");
            let err = relocate(&insn, 0x200).expect_err(&format!(
                "{hw:#06x} ({insn}) must not relocate: it reads pc"
            ));
            assert_eq!(err.reason(), "reads-pc", "{hw:#06x} ({insn})");
        }

        // `mov pc, lr` is the counter-case: its first operand is written and
        // never read, so it means the same thing at any address and must stay
        // relocatable. Refusing it would be a silent capability loss.
        let mv = crate::isa::decode_at_with(&0x46F7u16.to_le_bytes(), 0, 0x102, false).unwrap();
        assert_eq!(mv.mnemonic, "mov");
        assert!(
            relocate(&mv, 0x200).is_ok(),
            "`{mv}` is address-independent and must still relocate"
        );
    }

    // -----------------------------------------------------------------------
    // The two predicates the whole relocator rests on.
    //
    // Mutation testing found both untested in a way coverage could not show:
    // every `||` in `first_operand_is_source` could be flipped to `&&` — which
    // makes the function unconditionally `false`, since no mnemonic starts
    // with two different prefixes at once — and the `RegList` arm of
    // `reads_pc` could be deleted outright, or have its mask shifted to zero,
    // with no test noticing. Both decide whether an instruction may be moved,
    // so a wrong answer writes a broken trampoline into flash.
    // -----------------------------------------------------------------------

    #[test]
    fn first_operand_is_source_recognises_each_family_and_rejects_the_rest() {
        // One per clause, so no single clause can be removed or fused with
        // another and still pass.
        for m in [
            "str", "strb", "strh", "strd", "strex", "vstr", "vstm", "vldm", "stm", "stmdb", "srs",
            "ldm", "ldmdb", "rfe", "push", "vpush", "cmp", "cmn", "tst", "teq", "bx", "blx", "bxj",
            "tbb", "tbh",
        ] {
            assert!(first_operand_is_source(m), "{m} names a source first");
        }
        // Destination-first instructions, including the near-misses: `ldr` is
        // not `ldm`, `sub` is not `srs`, `vldr` is not `vldm`.
        for m in [
            "ldr", "ldrb", "ldrd", "ldrex", "vldr", "mov", "add", "sub", "and", "orr", "eor",
            "mul", "lsl", "asr", "adr", "pop", "b", "bl",
        ] {
            assert!(!first_operand_is_source(m), "{m} names a destination first");
        }
    }

    #[test]
    fn a_register_list_holding_pc_is_read_only_where_pc_is_a_source() {
        let list = |mnemonic: &'static str, bits: u16| Insn {
            mnemonic,
            encoding: "T2",
            addr: 0,
            width: Width::Wide,
            cond: None,
            sets_flags: false,
            explicit_width: false,
            operands: {
                let mut o = Operands::new();
                o.push(Operand::Reg(Reg::SP));
                o.push(Operand::RegList(bits));
                o
            },
        };

        // `stm`/`push` name their data first, so `pc` in the list is a value
        // being read out and the instruction cannot move.
        assert!(reads_pc(&list("stm", 1 << 15)), "stm {{pc}} reads pc");
        assert!(reads_pc(&list("push", 1 << 15)), "push {{pc}} reads pc");

        // The same list without `pc` is fine — this is what a mask shifted to
        // zero, or `&` turned into `|`, would get wrong in the other
        // direction by reporting every list as a pc read.
        assert!(!reads_pc(&list("stm", 0x00FF)), "no pc in the list");
        assert!(!reads_pc(&list("push", 1 << 14)), "lr is not pc");

        // Bit 15 exactly: bit 14 is `lr` and must not be mistaken for it.
        for b in 0..15 {
            assert!(
                !reads_pc(&list("stm", 1 << b)),
                "bit {b} is not pc and must not read as one"
            );
        }

        // A load writes its list, so `pc` there is a destination and the
        // instruction relocates: `pop {r4, pc}` is a return.
        assert!(!reads_pc(&list("pop", (1 << 15) | (1 << 4))));
    }

    // --- byte reproducibility at the zero displacement ---
    //
    // `Mem` carries the displacement as a magnitude plus the architecture's
    // `U` bit precisely because `#0` and `#-0` are distinct encodings. Two
    // guards decide which form comes out at a displacement of exactly zero,
    // and mutation found neither exercised: relocating an instruction that
    // lands on its own literal would change the bytes without changing what
    // it does, which is exactly what the encoding digest exists to notice.

    /// A wide literal load whose `U` is already clear keeps it when the
    /// displacement works out to zero.
    #[test]
    fn a_zero_displacement_keeps_the_u_bit_it_arrived_with() {
        // `ldr.w r0, [pc, #-0]` at 0x1000 — hw1 0xF85F, so `U` is clear.
        let insn = at(&[0x5F, 0xF8, 0x00, 0x00], 0x1000);
        assert!(!pc_mem(&insn).expect("a pc-based memory operand").add);
        // 0x1000 and 0x1002 share `Align(PC, 4)`, so the displacement is zero
        // at both and neither may invent an adding form.
        for to in [0x1000u32, 0x1002] {
            let moved = relocate(&insn, to).expect("address-independent");
            let m = pc_mem(&moved).expect("still a pc-based operand");
            assert_eq!(m.displacement(), 0, "from {to:#x}");
            assert!(!m.add, "U must survive relocation to {to:#x}");
            assert_eq!(
                isa::encode_bytes(&moved).expect("re-encodable"),
                vec![0x5F, 0xF8, 0x00, 0x00],
                "the same four bytes, from {to:#x}"
            );
        }
    }

    /// A wide `adr` that lands exactly on its label stays the adding form.
    ///
    /// T3 adds and T2 subtracts, and at a zero displacement either spells the
    /// same address — so the choice has to be pinned, or the same `adr`
    /// assembles to different bytes depending only on how far it moved.
    #[test]
    fn a_wide_adr_that_lands_exactly_on_its_label_stays_the_adding_form() {
        // `adr.w r0, <pc+0>` at 0x1000, T3 with imm12 == 0.
        let insn = at(&[0x0F, 0xF2, 0x00, 0x00], 0x1000);
        assert_eq!(insn.encoding, "T3");
        let label = insn.branch_target().expect("a resolved label");
        for to in [0x1000u32, 0x1002] {
            let moved = relocate(&insn, to).expect("address-independent");
            assert_eq!(moved.branch_target(), Some(label), "from {to:#x}");
            assert_eq!(moved.encoding, "T3", "the adding form, from {to:#x}");
            assert_eq!(
                isa::encode_bytes(&moved).expect("re-encodable"),
                vec![0x0F, 0xF2, 0x00, 0x00],
                "the same four bytes, from {to:#x}"
            );
        }
    }

    /// Only a *pc-based* memory operand is a literal access.
    ///
    /// `pc_mem` and `replace_pc_mem` both key on `m.base == Reg::PC`, and
    /// mutation showed neither guard exercised with an ordinary base. With
    /// them disabled every memory operand is treated as a literal and has its
    /// displacement re-resolved against the new address — so `ldr r0, [r1,
    /// #4]` would come out of a relocation pointing somewhere else entirely,
    /// while still naming `r1`.
    #[test]
    fn only_a_pc_based_memory_operand_is_a_literal_access() {
        // `ldr r0, [r1, #4]` — an ordinary base register.
        let ordinary = at(&[0x48, 0x68], 0x1000);
        assert!(
            ordinary
                .operands
                .as_slice()
                .any(|o| matches!(o, Operand::Mem(_))),
            "{ordinary} does carry a memory operand"
        );
        assert!(
            pc_mem(&ordinary).is_none(),
            "{ordinary} is not a literal access"
        );
        // So it is address-independent: the same four bytes wherever it goes.
        for to in [0x9000u32, 0x2, 0x1_0000] {
            assert_eq!(
                bytes_at(&ordinary, to),
                vec![0x48, 0x68],
                "{ordinary} moved to {to:#x}"
            );
        }

        // `ldr r0, [pc, #4]` — the same shape with `pc` as the base, and this
        // one *is* a literal access whose displacement has to move.
        let literal = at(&[0x01, 0x48], 0x1000);
        assert!(pc_mem(&literal).is_some(), "{literal} is a literal access");
    }
}
