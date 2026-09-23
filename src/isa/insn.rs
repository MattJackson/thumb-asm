//! The decoded-instruction vocabulary every encoding group speaks.
//!
//! One [`Insn`] describes any Thumb instruction, 16- or 32-bit, from any
//! profile — integer, floating-point, Advanced SIMD or coprocessor. It is
//! deliberately `Copy` and allocation-free: a decoder that walks a multi-
//! megabyte firmware image produces millions of these, and none of them should
//! touch the heap.
//!
//! The mnemonic is a `&'static str` rather than a variant of a ~250-arm
//! enum. That is a considered trade: the architecture's mnemonic set is large,
//! open (each profile adds to it), and irregular, and consumers overwhelmingly
//! want either "is this a branch" (answered by [`Insn::is_branch`] and
//! friends) or the printable form (answered by `Display`). An enum would make
//! both of those *harder* while forcing every group module through one
//! central, merge-conflicting definition.

use crate::Cond;

/// A core register, `r0`–`r15`.
///
/// `r13`/`r14`/`r15` render as `sp`/`lr`/`pc`, which is how the architecture
/// reference manual and every assembler write them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reg(pub u8);

impl Reg {
    /// The stack pointer, `r13`.
    pub const SP: Reg = Reg(13);
    /// The link register, `r14`.
    pub const LR: Reg = Reg(14);
    /// The program counter, `r15`.
    pub const PC: Reg = Reg(15);

    /// The register number, 0–15.
    pub fn num(self) -> u8 {
        self.0 & 0xF
    }

    /// Whether this is a low register (`r0`–`r7`) — the only ones most 16-bit
    /// encodings can name.
    pub fn is_low(self) -> bool {
        self.num() < 8
    }
}

impl core::fmt::Display for Reg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.num() {
            13 => f.write_str("sp"),
            14 => f.write_str("lr"),
            15 => f.write_str("pc"),
            n => write!(f, "r{n}"),
        }
    }
}

/// A floating-point or vector register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FpReg {
    /// A 32-bit single-precision register, `s0`–`s31`.
    S(u8),
    /// A 64-bit double-precision register, `d0`–`d31`.
    D(u8),
    /// A 128-bit Advanced SIMD quadword register, `q0`–`q15`.
    Q(u8),
}

impl core::fmt::Display for FpReg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FpReg::S(n) => write!(f, "s{n}"),
            FpReg::D(n) => write!(f, "d{n}"),
            FpReg::Q(n) => write!(f, "q{n}"),
        }
    }
}

/// The kind of shift or rotate applied to a register operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShiftKind {
    /// Logical shift left.
    Lsl,
    /// Logical shift right.
    Lsr,
    /// Arithmetic shift right.
    Asr,
    /// Rotate right.
    Ror,
    /// Rotate right with extend — a one-bit rotate through the carry flag,
    /// which takes no amount operand.
    Rrx,
}

impl core::fmt::Display for ShiftKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ShiftKind::Lsl => "lsl",
            ShiftKind::Lsr => "lsr",
            ShiftKind::Asr => "asr",
            ShiftKind::Ror => "ror",
            ShiftKind::Rrx => "rrx",
        })
    }
}

/// How much to shift by: an immediate, or the bottom byte of a register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShiftAmount {
    /// A shift by a constant. For `LSR` and `ASR` the architecture encodes a
    /// shift of 32 as `0`, so a decoded value of 32 here is normal and
    /// correct; `RRX` carries an amount of 1 that is never printed.
    Imm(u8),
    /// A shift by `Rs[7:0]`.
    Reg(Reg),
}

/// A shift applied to a register operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Shift {
    /// Which shift or rotate.
    pub kind: ShiftKind,
    /// By how much.
    pub amount: ShiftAmount,
}

impl core::fmt::Display for Shift {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match (self.kind, self.amount) {
            (ShiftKind::Rrx, _) => f.write_str("rrx"),
            (kind, ShiftAmount::Imm(n)) => write!(f, "{kind} #{n}"),
            (kind, ShiftAmount::Reg(r)) => write!(f, "{kind} {r}"),
        }
    }
}

/// How a memory operand computes its address and whether it writes the base
/// register back.
///
/// The four variants are the four bracketed syntax shapes UAL writes, and the
/// manual's own use of braces decides which of them may omit a zero
/// displacement: `[<Rn>{,#+/-<imm>}]` has the immediate in braces and
/// `[<Rn>,#+/-<imm>]!` and `[<Rn>],#+/-<imm>` do not (A7.7.43 and every load
/// or store page that follows it). [`Mem`]'s `Display` follows that exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddrMode {
    /// `[rn{, offset}]` — base plus offset, base unchanged. A `+0`
    /// displacement is omitted, because the manual's syntax line brackets it
    /// as optional.
    Offset,
    /// `[rn, offset]!` — base plus offset, and the sum is written back. The
    /// displacement is always printed, zero included.
    PreIndex,
    /// `[rn], offset` — the unmodified base is used, then the sum is written
    /// back. The displacement is always printed, zero included: without it the
    /// text would read back as [`AddrMode::Offset`], and the writeback is the
    /// whole point of the mode.
    PostIndex,
    /// `[rn]!` — the unmodified base is used, then incremented by an amount
    /// the encoding does not carry.
    ///
    /// This is the Advanced SIMD element and structure form of A7.7.1, where
    /// `Rm == 0b1101` means "increment `Rn` by the transfer size". Nothing is
    /// printed after the base because nothing is encoded there, and
    /// [`Mem::displacement`] is *not* the writeback amount for this mode — a
    /// consumer must get that from the instruction's element count and size.
    PostIncrement,
}

/// A memory operand: base register, optional scaled index, constant offset,
/// optional alignment qualifier.
///
/// Exactly one of `index` and a non-zero `offset` is meaningful for any given
/// encoding; both are present because the type spans every addressing form in
/// the instruction set.
///
/// # Why the offset is a magnitude and a separate `add`
///
/// The architecture's `U` bit is not a sign that can be folded into a signed
/// integer, because it is observable when the immediate is zero: A7.7.50 says
/// in as many words that "different instructions are generated for `#0` and
/// `#-0`", and A7.7.51 lists `LDRD<c> <Rt>,<Rt2>,[PC,#-0]` as an encoding in
/// its own right. In an `i32`, `-0 == 0`, so storing a sign-corrected offset
/// destroys `U` on decode and has to invent it on re-encode — which breaks the
/// byte-identity this crate exists to provide. An enumeration of the whole
/// 32-bit space finds **118,208** encodings that spell a subtracting zero
/// (24,576 dual-word, 86,016 `LDC`/`STC`, 3,543 load, 2,048 `VLDR`/`VSTR`,
/// 2,025 store); every one of them decodes and re-encodes to its own bytes
/// now, and none of them could before.
///
/// So `offset` is an unsigned magnitude and [`add`](Self::add) is the `U` bit
/// itself. `add: false, offset: 0` is `#-0` and is a different value from
/// `add: true, offset: 0`. The two alternatives both lose:
///
/// * A signed `offset` plus a `subtract_zero` flag has *two* carriers of the
///   sign, so `offset: -4, subtract_zero: false` and `offset: 4,
///   subtract_zero: true` are representable contradictions that must be
///   checked for rather than being impossible.
/// * An `Option`-shaped offset (`None` for "no displacement") says nothing
///   about `U`, so it cannot spell `#-0` at all — it only moves the hole.
///
/// Here the sign lives in exactly one field and every bit pattern of the pair
/// denotes a distinct, legal addressing form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mem {
    /// The base register. For pc-relative (literal) forms this is
    /// [`Reg::PC`], and the resolved address is also supplied separately as an
    /// [`Operand::Target`] by decoders that can compute it.
    pub base: Reg,
    /// An optional register index, itself optionally shifted.
    ///
    /// Every register index in Thumb is added, so [`add`](Self::add) has no
    /// bearing on it; the field is the `U` bit of the *immediate* forms.
    pub index: Option<(Reg, Option<Shift>)>,
    /// The magnitude of the constant byte offset, unscaled. Never negative:
    /// the direction is [`add`](Self::add), and the type docs explain why.
    pub offset: u32,
    /// The architecture's `U` bit: `true` adds [`offset`](Self::offset) to the
    /// base, `false` subtracts it. `false` with an `offset` of zero is `#-0`,
    /// which is a real and distinct encoding.
    pub add: bool,
    /// The alignment qualifier in *bits*, or `0` for "omitted" — the
    /// `[<Rn>:<align>]` of the Advanced SIMD element and structure transfers
    /// (A7.7.1, and `alignment = 4 << UInt(align)` in A8.6.307 and its
    /// siblings). Only 16, 32, 64, 128 and 256 are ever encodable, and only by
    /// that one instruction family; it is zero everywhere else.
    pub align: u16,
    /// Offset, pre-indexed, post-indexed or post-incremented.
    pub mode: AddrMode,
}

impl Mem {
    /// The displacement as a signed byte count: `offset` if
    /// [`add`](Self::add), else `-offset`.
    ///
    /// This is what a consumer computing an effective address wants, and it is
    /// deliberately *not* how the displacement is stored: `#0` and `#-0` both
    /// come back as `0` here, which is correct — they address the same
    /// byte — and is exactly the collapse that must not happen in the fields.
    /// Returns `i64` because a `u32` magnitude does not fit in an `i32` once
    /// negated.
    ///
    /// For [`AddrMode::PostIncrement`] this is `0` and says nothing about the
    /// writeback, which that mode's documentation explains.
    #[must_use]
    pub const fn displacement(&self) -> i64 {
        if self.add {
            self.offset as i64
        } else {
            -(self.offset as i64)
        }
    }
}

impl Mem {
    /// Render this operand, optionally forcing an adding zero displacement to
    /// print in [`AddrMode::Offset`].
    ///
    /// `force_offset` exists for exactly one caller — [`Insn`]'s `Display`,
    /// for the narrow `LDR (literal)` T1 — and the reason is that `[pc]` does
    /// not re-assemble to the bytes it was printed from. LLVM reads
    /// `ldr r0, [pc]` as the 32-bit T2 encoding (`F8DF 0000`), not the narrow
    /// T1 (`4800`), because no narrow literal load matches a bracketed base
    /// with no displacement; `ldr r0, [pc, #0]` assembles back to `4800`. A
    /// `.n` qualifier does not help — `ldr.n r0, [pc]` still assembles to the
    /// wide form in all three of the conformance harness's dialects — so the
    /// displacement, and only the displacement, carries the distinction.
    /// (Verified with Apple clang 21; see `docs/CONFORMANCE.md`.)
    ///
    /// It is *not* the default, because a `Mem` cannot tell a literal access
    /// from any other pc-based operand: `strex pc, r0, [pc]` and
    /// `stc p0, c0, [pc]` hold the identical value, LLVM writes and reads them
    /// bare, and printing `#0` for them would invent an operand. The caller
    /// that knows which instruction the operand belongs to is the one that
    /// decides.
    fn write(&self, f: &mut core::fmt::Formatter<'_>, force_offset: bool) -> core::fmt::Result {
        // The displacement, or the index that replaces it. `always` forces a
        // zero to print, for the two modes whose syntax lines do not brace it.
        let disp = |f: &mut core::fmt::Formatter<'_>, always: bool| -> core::fmt::Result {
            if let Some((idx, shift)) = self.index {
                write!(f, ", {idx}")?;
                if let Some(s) = shift {
                    write!(f, ", {s}")?;
                }
            } else if always || self.offset != 0 || !self.add {
                // `!self.add` keeps `#-0` visible in the offset form too: it
                // is the whole distinction the encoding makes.
                if self.add {
                    write!(f, ", #{}", self.offset)?;
                } else {
                    write!(f, ", #-{}", self.offset)?;
                }
            }
            Ok(())
        };
        // `:<align>` sits inside the brackets, immediately before the `]`.
        let close = |f: &mut core::fmt::Formatter<'_>| -> core::fmt::Result {
            if self.align != 0 {
                write!(f, ":{}", self.align)?;
            }
            f.write_str("]")
        };
        match self.mode {
            AddrMode::Offset => {
                write!(f, "[{}", self.base)?;
                disp(f, force_offset)?;
                close(f)
            }
            AddrMode::PreIndex => {
                write!(f, "[{}", self.base)?;
                disp(f, true)?;
                close(f)?;
                f.write_str("!")
            }
            AddrMode::PostIndex => {
                write!(f, "[{}", self.base)?;
                close(f)?;
                disp(f, true)
            }
            AddrMode::PostIncrement => {
                write!(f, "[{}", self.base)?;
                close(f)?;
                f.write_str("!")
            }
        }
    }
}

impl core::fmt::Display for Mem {
    /// The manual's own braces decide what prints: `[<Rn>{,#+/-<imm>}]` may
    /// omit an adding zero, `[<Rn>,#+/-<imm>]!` and `[<Rn>],#+/-<imm>` may
    /// not. `#-0` is never omitted in any mode — it is the whole of what its
    /// encoding says (A7.7.50).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.write(f, false)
    }
}

/// One operand of a decoded instruction.
///
/// Every variant is `Copy`; nothing here borrows or allocates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Operand {
    /// A core register.
    Reg(Reg),
    /// A core register with a shift applied, as in `add r0, r1, r2, lsl #3`.
    RegShifted(Reg, Shift),
    /// An immediate, already expanded (so a Thumb modified immediate appears
    /// here as the 32-bit constant it denotes, not as its 12-bit encoding) and
    /// already sign-corrected.
    Imm(i64),
    /// A register list, one bit per register, bit 0 = `r0`.
    RegList(u16),
    /// A resolved absolute branch or literal-pool target address. Decoders
    /// compute this from the instruction's own address, so consumers never
    /// have to redo the pc-relative arithmetic (and never have to remember
    /// that Thumb's pc reads as the instruction's address plus four).
    Target(u32),
    /// A memory operand.
    Mem(Mem),
    /// A floating-point or vector register.
    FpReg(FpReg),
    /// A scalar element of a vector register, as in `d3[1]`.
    FpScalar(FpReg, u8),
    /// A floating-point immediate.
    FpImm(f64),
    /// A named special-purpose register (`APSR`, `PRIMASK`, `CPSR_fc`, …).
    SpecialReg(&'static str),
    /// A barrier or memory-domain option (`sy`, `ish`, `nshst`, …).
    Option(&'static str),
    /// A coprocessor number, printed as `p14`.
    Coproc(u8),
    /// A coprocessor register, printed as `c5`.
    CoprocReg(u8),
    /// A condition, for the instructions that take one as an operand rather
    /// than as a mnemonic suffix.
    Cond(Cond),
    /// A bare textual operand for the handful of forms whose syntax is a
    /// keyword — `SETEND be`, `CPSIE if`, and similar.
    Text(&'static str),
}

impl core::fmt::Display for Operand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Operand::Reg(r) => write!(f, "{r}"),
            Operand::RegShifted(r, s) => write!(f, "{r}, {s}"),
            Operand::Imm(v) => {
                if *v < 0 {
                    write!(f, "#-{:#x}", -(*v))
                } else if *v < 10 {
                    write!(f, "#{v}")
                } else {
                    write!(f, "#{v:#x}")
                }
            }
            Operand::RegList(bits) => write_reglist(f, *bits),
            Operand::Target(addr) => write!(f, "{addr:#x}"),
            Operand::Mem(m) => write!(f, "{m}"),
            Operand::FpReg(r) => write!(f, "{r}"),
            Operand::FpScalar(r, i) => write!(f, "{r}[{i}]"),
            // A forced decimal point. `{}` on an `f64` prints `5` for `5.0`,
            // and `#5` is an *integer* literal: A7.7.229's `<imm>` is "a
            // floating-point constant" (`VMOV.F64 <Dd>, #<imm>`), and an
            // assembler holds the operand to that — LLVM rejects
            // `vmov.f32 s1, #2` outright ("invalid floating point immediate")
            // while accepting `#2.0`. Non-integral values already carry a
            // point and are printed as they are.
            Operand::FpImm(v) if v.fract() == 0.0 && v.is_finite() => write!(f, "#{v:.1}"),
            Operand::FpImm(v) => write!(f, "#{v}"),
            Operand::SpecialReg(s) => f.write_str(s),
            Operand::Option(s) => f.write_str(s),
            Operand::Coproc(n) => write!(f, "p{n}"),
            Operand::CoprocReg(n) => write!(f, "c{n}"),
            Operand::Cond(c) => write!(f, "{c}"),
            Operand::Text(s) => f.write_str(s),
        }
    }
}

/// Render a register list in UAL form, collapsing runs: `{r0-r3, r7, lr}`.
fn write_reglist(f: &mut core::fmt::Formatter<'_>, bits: u16) -> core::fmt::Result {
    f.write_str("{")?;
    let mut first = true;
    let mut i = 0u8;
    while i < 16 {
        if bits & (1 << i) == 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < 15 && bits & (1 << (i + 1)) != 0 {
            i += 1;
        }
        if !first {
            f.write_str(", ")?;
        }
        first = false;
        match i - start {
            0 => write!(f, "{}", Reg(start))?,
            1 => write!(f, "{}, {}", Reg(start), Reg(i))?,
            _ => write!(f, "{}-{}", Reg(start), Reg(i))?,
        }
        i += 1;
    }
    f.write_str("}")
}

/// The maximum number of operands any Thumb instruction has.
///
/// The widest forms in the architecture are the four-register multiply-
/// accumulates (`SMLAL rdlo, rdhi, rn, rm`) and the shifted-register data
/// processing forms carrying an explicit shift; six leaves headroom for the
/// vector instructions without making [`Insn`] unreasonably large.
pub const MAX_OPERANDS: usize = 6;

/// An inline, allocation-free operand list.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Operands {
    items: [Option<Operand>; MAX_OPERANDS],
    len: u8,
}

impl Default for Operands {
    fn default() -> Self {
        Operands {
            items: [None; MAX_OPERANDS],
            len: 0,
        }
    }
}

impl Operands {
    /// An empty operand list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an operand.
    ///
    /// # Panics
    ///
    /// Panics if more than [`MAX_OPERANDS`] operands are pushed. This is a
    /// decoder bug, not an input-dependent condition — no architectural
    /// encoding has more operands than that — so it is an assertion rather
    /// than a `Result`.
    pub fn push(&mut self, op: Operand) {
        assert!(
            (self.len as usize) < MAX_OPERANDS,
            "more than {MAX_OPERANDS} operands"
        );
        self.items[self.len as usize] = Some(op);
        self.len += 1;
    }

    /// The operands, in syntactic order.
    pub fn as_slice(&self) -> impl Iterator<Item = Operand> + '_ {
        self.items[..self.len as usize].iter().filter_map(|o| *o)
    }

    /// How many operands there are.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether there are no operands.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The operand at `i`, if any.
    pub fn get(&self, i: usize) -> Option<Operand> {
        self.items.get(i).copied().flatten()
    }
}

impl core::iter::FromIterator<Operand> for Operands {
    fn from_iter<T: IntoIterator<Item = Operand>>(iter: T) -> Self {
        let mut ops = Operands::new();
        for op in iter {
            ops.push(op);
        }
        ops
    }
}

/// Whether an instruction was encoded narrow (16-bit) or wide (32-bit).
///
/// This is not merely the byte length: it is what decides whether UAL prints a
/// `.w` suffix, which matters when re-assembling, because several operations
/// have both a narrow and a wide encoding and the assembler must be told which
/// one to pick if the choice is not to be made for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Width {
    /// A 16-bit encoding.
    Narrow,
    /// A 32-bit encoding.
    Wide,
}

impl Width {
    /// The instruction's length in bytes.
    pub fn bytes(self) -> usize {
        match self {
            Width::Narrow => 2,
            Width::Wide => 4,
        }
    }
}

/// A decoded Thumb instruction.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Insn {
    /// The base mnemonic in lower case, without condition or flag suffix —
    /// `"add"`, `"ldr"`, `"b"`, `"vmov"`. `Display` adds the suffixes back.
    pub mnemonic: &'static str,
    /// The architectural encoding name this was decoded as — `"T1"`, `"T2"`,
    /// `"T3"`, `"T4"`. Carried so that a consumer re-encoding an instruction
    /// can reproduce the exact bytes, and so that a disagreement between
    /// decoder and spec can be pinned to one named encoding.
    pub encoding: &'static str,
    /// The address the instruction was decoded from. Any [`Operand::Target`]
    /// is relative to this.
    pub addr: u32,
    /// Narrow or wide.
    pub width: Width,
    /// The condition, if the instruction is conditional. A 16-bit `B<cond>`
    /// carries its condition here; an instruction made conditional by a
    /// preceding `IT` block also carries it here once decoded through
    /// [`crate::isa::Decoder`], which tracks IT state.
    pub cond: Option<Cond>,
    /// Whether the instruction updates the condition flags — the `S` suffix.
    pub sets_flags: bool,
    /// Whether the mnemonic must be printed with an explicit width suffix to
    /// round-trip through an assembler.
    pub explicit_width: bool,
    /// The operands, in syntactic order.
    pub operands: Operands,
}

impl Insn {
    /// The instruction's length in bytes — 2 or 4.
    pub fn len(&self) -> usize {
        self.width.bytes()
    }

    /// Always false; present so `len` does not trip `clippy::len_without_is_empty`.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Whether this instruction can transfer control somewhere other than the
    /// next instruction — any branch, call, return, or a load or data
    /// operation that writes `pc`.
    ///
    /// The mnemonics named here are the ones that transfer control *without*
    /// naming `pc` as an operand, so [`writes_pc`](Self::writes_pc) cannot see
    /// them. Everything that does name `pc` as a destination — `pop {…, pc}`,
    /// `ldr pc, [r0]`, `mov pc, lr`, the `subs pc, lr, #imm` exception return
    /// — and `RFE`, which loads `pc` from memory while naming only its base,
    /// arrives through that fallback instead.
    ///
    /// `SVC`, `BKPT`, `UDF` and `SMC` are deliberately *not* branches. They
    /// raise an exception: the destination is a vector this crate cannot see,
    /// the transfer is the exception mechanism rather than a branch, and the
    /// architecture's own list of instructions that "branch to a value written
    /// to the PC" (ARM DDI 0406C B1.3.2, *Writing to the PC*) excludes them.
    /// A consumer that wants them must test the mnemonic itself.
    pub fn is_branch(&self) -> bool {
        matches!(
            self.mnemonic,
            // `hb`/`hbl`/`hbp`/`hblp` are the ThumbEE handler-branch family:
            // real branches whose destination comes from `HandlerBase`, a
            // system register, so they have no statically-known target and
            // `branch_target()` returns `None` for them.
            //
            // `chka` is the ThumbEE bounds check, and it is here for the same
            // reason `cbz` is: it is a *conditional* branch. DDI 0406C A9.5.1
            // ends `if UInt(R[n]) <= UInt(R[m]) then … BranchWritePC(TEEHBR -
            // 8)`, and B1.3.2's list of instructions that branch to a value
            // written to the PC reads "B, BL, CBNZ, CBZ, CHKA, HB, HBL, HBLP,
            // HBP, TBB, and TBH" — Arm puts it among the branches itself. The
            // arguable part is that its taken edge is the *error* path, into a
            // runtime handler that typically throws rather than returns; the
            // decision recorded here is that a control-flow consumer is better
            // served by an edge it can see and discount (`is_branch()` true,
            // `branch_target()` `None`, `is_call()` false — see there) than by
            // silently straight-lining a block that can leave.
            "b" | "bl"
                | "blx"
                | "bx"
                | "bxj"
                | "cbz"
                | "cbnz"
                | "tbb"
                | "tbh"
                | "hb"
                | "hbl"
                | "hbp"
                | "hblp"
                | "chka"
        ) || self.writes_pc()
    }

    /// Whether this is a call — it writes `lr` with the address of the
    /// following instruction, and is expected to return there.
    ///
    /// `bl` and `blx` in both their forms, and — in ThumbEE state — `hbl` and
    /// `hblp`, whose operation is `next_instr_addr = PC - 2; LR =
    /// next_instr_addr<31:1>:'1'` before the branch (ARM DDI 0406C A9.5.2 and
    /// A9.5.3). That is exactly `bl`'s contract with a handler table standing
    /// in for a label. `hb` and `hbp` are *not* calls: A9.5.2 writes `LR` only
    /// when `generate_link` (the `L` bit) is set, and A9.5.4's `HBP` has no
    /// `LR =` line at all.
    ///
    /// `chka` is the instructive exclusion, because it does write `lr`. The
    /// value it writes is not a return address: A9.5.1 gives `LR =
    /// PC<31:1>:'1'` with `PC` reading as *this instruction's address plus
    /// four*, one halfword beyond the following instruction, where `hbl`
    /// deliberately computes `PC - 2` to land on it. A consumer that took
    /// `chka` for a call and resumed the fall-through at `addr + len()` would
    /// disagree with the hardware about where control comes back — and the
    /// IndexCheck handler it enters is an error path that does not generally
    /// come back at all. So `chka` reports [`is_branch`](Self::is_branch) and
    /// not this. Anything tracking `lr` liveness rather than call structure
    /// must know that `chka`, uniquely, clobbers `lr` without being a call.
    pub fn is_call(&self) -> bool {
        matches!(self.mnemonic, "bl" | "blx" | "hbl" | "hblp")
    }

    /// Whether this instruction writes `pc`, by being a `pop {…, pc}`, a
    /// `bx lr`, a load into `pc`, or a data operation with `pc` as its
    /// destination.
    pub fn writes_pc(&self) -> bool {
        match self.mnemonic {
            "pop" | "ldm" | "ldmia" | "ldmdb" => self
                .operands
                .as_slice()
                .any(|o| matches!(o, Operand::RegList(bits) if bits & (1 << 15) != 0)),
            "bx" | "bxj" => true,
            // `BLX (register)` writes `pc` from a register exactly as `BX`
            // does — B1.3.2 names "BLX (register), BX, and BXJ" in one breath
            // — while `BLX (immediate)` branches to a displacement its own
            // encoding carries, which is the `B`/`BL` case this method answers
            // `false` for. One mnemonic covers both; the operand tells them
            // apart, `Operand::Reg` for T1 against `Operand::Target` for T2.
            // Without this arm the pair answered inconsistently: `blx r0` was
            // `false` while `blx pc` was `true`, the latter only by the
            // fallback below reading a *source* register as a destination.
            "blx" => matches!(self.operands.get(0), Some(Operand::Reg(_))),
            // `RFE` writes `pc` — and the CPSR — from memory, and names
            // neither: its one register operand is the base address the pair
            // of words is read from. B6.1.8's operation is
            // `CPSRWriteByInstr(MemA[address+4,4], …); BranchWritePC(MemA[address,4])`,
            // so both of the fallback's answers were wrong here. `rfeia r0!`
            // reported no pc write at all — and so `is_branch()` false, which
            // straight-lines an exception return — while `rfedb pc` reported
            // one for the wrong reason, off a pc *base* that B6.1.8 makes
            // UNPREDICTABLE. The mnemonic decides, unconditionally.
            "rfeia" | "rfedb" => true,
            // The fallback below reads "first operand is pc" as "writes pc",
            // which holds only for instructions whose first operand is a
            // *destination*. It is exactly wrong for the families where the
            // first operand is a source: a store transfers `Rt` to memory
            // (`str pc, [r0]` reads pc, it does not write it), a comparison
            // consumes both operands to set flags, a multi-register transfer
            // names its base address first (`vldm`, and `srs`, which stores
            // `lr` and the SPSR — the `ldm` family is answered above, off its
            // register list), and ThumbEE's `chka` takes the array size in
            // `Rn` and the index in `Rm`, reading both. Reporting any of them
            // as a pc write would corrupt any control-flow graph built on
            // this; `chka` does branch, and says so through `is_branch`.
            m if m.starts_with("str")
                || m.starts_with("vstr")
                || m.starts_with("vstm")
                || m.starts_with("vldm")
                || m.starts_with("stm")
                || m == "push"
                || m == "vpush"
                || matches!(
                    m,
                    "cmp" | "cmn" | "tst" | "teq" | "chka" | "srsia" | "srsdb"
                ) =>
            {
                false
            }
            _ => matches!(self.operands.get(0), Some(Operand::Reg(Reg::PC))),
        }
    }

    /// The absolute target of a direct branch, if this instruction has one.
    /// Indirect branches (`bx rm`, `tbb`) have no statically-known target and
    /// yield `None`, as do the ThumbEE handler branches, whose destination is
    /// `TEEHBR`-relative and so not in the instruction at all.
    ///
    /// Precisely, this is the first [`Operand::Target`] the instruction
    /// carries, and one caveat follows from that: a pc-relative *literal*
    /// access carries a `Target` too — the resolved address of the pool word,
    /// emitted alongside the [`Operand::Mem`] so consumers need not redo the
    /// `Align(PC,4)` arithmetic. For `ldr r0, [pc, #8]` that is harmless,
    /// since [`is_branch`](Self::is_branch) is false. For `ldr pc, [pc, #8]`
    /// it is not: `is_branch()` is true and this returns the address of the
    /// word *holding* the destination, not the destination. A consumer
    /// building a control-flow graph must treat a `Target` as a branch
    /// destination only when the instruction has no `Operand::Mem`. The
    /// overload is load-bearing — `t16_branch::encode` re-derives a branch
    /// displacement from it, and four modules pin literal addresses through it
    /// — so it is documented rather than removed.
    pub fn branch_target(&self) -> Option<u32> {
        self.operands.as_slice().find_map(|o| match o {
            Operand::Target(t) => Some(t),
            _ => None,
        })
    }
}

impl core::fmt::Display for Insn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.mnemonic)?;
        if self.sets_flags {
            f.write_str("s")?;
        }
        if let Some(c) = self.cond {
            f.write_str(c.suffix())?;
        }
        if self.explicit_width {
            f.write_str(match self.width {
                Width::Narrow => ".n",
                Width::Wide => ".w",
            })?;
        }
        // `LDR (literal)` T1 — the one shape in the instruction set whose
        // bracketed text is ambiguous. Three things identify it, and all three
        // are needed:
        //
        // * **narrow**, because the wide literal forms print `.w` and that is
        //   enough for an assembler to pick them (`ldr.w r0, [pc]` assembles
        //   back to `F8DF 0000`, the bytes it came from);
        // * a **pc-based memory operand**, which in the 16-bit map only
        //   `LDR (literal)` T1 has — `ADR` emits no `Mem`, and ThumbEE's pool
        //   and frame loads are based on `r10` and `r9`;
        // * a resolved [`Operand::Target`] beside it, which is this crate's
        //   marker for a *literal access* as opposed to an ordinary base
        //   register that happens to be `pc` (see [`Insn::branch_target`]).
        //
        // For that shape the displacement always prints, so `0x4800` reads
        // back as `ldr r0, [pc, #0]` and re-assembles to `0x4800` rather than
        // to the 32-bit T2 encoding. Every other pc-based operand —
        // `strex pc, r0, [pc]`, `stc p0, c0, [pc]`, `ldrd`/`strd`/`ldrexd`
        // with `Rn == pc` — is left exactly as the manual's braces write it,
        // because none of them is ambiguous and LLVM writes them bare.
        let literal = self.width == Width::Narrow
            && self
                .operands
                .as_slice()
                .any(|o| matches!(o, Operand::Target(_)));
        let mut first = true;
        for op in self.operands.as_slice() {
            f.write_str(if first { " " } else { ", " })?;
            first = false;
            match op {
                Operand::Mem(m) if literal && m.base.num() == Reg::PC.0 => m.write(f, true)?,
                _ => write!(f, "{op}")?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(mnemonic: &'static str, ops: &[Operand]) -> Insn {
        Insn {
            mnemonic,
            encoding: "T1",
            addr: 0,
            width: Width::Narrow,
            cond: None,
            sets_flags: false,
            explicit_width: false,
            operands: ops.iter().copied().collect(),
        }
    }

    /// The first operand is a destination for most instructions and a *source*
    /// for stores and comparisons. Treating it uniformly as a destination
    /// reports `str pc, [r0]` as a branch, which would corrupt any control-flow
    /// graph built on this method.
    #[test]
    fn writes_pc_distinguishes_destinations_from_sources() {
        // Destinations: pc really is written.
        assert!(insn("mov", &[Operand::Reg(Reg::PC), Operand::Reg(Reg(1))]).writes_pc());
        assert!(insn("add", &[Operand::Reg(Reg::PC), Operand::Reg(Reg::LR)]).writes_pc());
        assert!(insn("ldr", &[Operand::Reg(Reg::PC), Operand::Reg(Reg(0))]).writes_pc());

        // Sources: pc is read, not written.
        assert!(!insn("str", &[Operand::Reg(Reg::PC), Operand::Reg(Reg(0))]).writes_pc());
        assert!(!insn("strb", &[Operand::Reg(Reg::PC), Operand::Reg(Reg(0))]).writes_pc());
        assert!(!insn("stm", &[Operand::Reg(Reg::PC), Operand::RegList(0x0003)]).writes_pc());
        assert!(!insn("cmp", &[Operand::Reg(Reg::PC), Operand::Reg(Reg(0))]).writes_pc());
        assert!(!insn("tst", &[Operand::Reg(Reg::PC), Operand::Reg(Reg(0))]).writes_pc());

        // A register list is read for the pc bit regardless of operand order.
        assert!(insn("pop", &[Operand::RegList(1 << 15)]).writes_pc());
        assert!(!insn("pop", &[Operand::RegList(1 << 14)]).writes_pc());
        // …but a *store* multiple with pc in its list still does not write pc.
        assert!(!insn("push", &[Operand::RegList(1 << 15)]).writes_pc());
    }

    /// The ThumbEE handler-branch family: all four branch, and exactly the two
    /// with `L` in their name write `lr` (ARM DDI 0406C A9.5.2–A9.5.4).
    ///
    /// None of them writes `pc` in this method's sense — the destination is
    /// `TEEHBR + handler:'00000'`, a system register this crate cannot read —
    /// and none carries an `Operand::Target`, so `branch_target()` is `None`
    /// for all four. A control-flow consumer gets "control leaves here, to
    /// somewhere I cannot name", which is the truth.
    #[test]
    fn thumbee_handler_branches_are_branches_and_two_are_calls() {
        let hb = insn("hb", &[Operand::Imm(7)]);
        let hbl = insn("hbl", &[Operand::Imm(7)]);
        let hbp = insn("hbp", &[Operand::Imm(3), Operand::Imm(7)]);
        let hblp = insn("hblp", &[Operand::Imm(3), Operand::Imm(7)]);

        for i in [hb, hbl, hbp, hblp] {
            assert!(i.is_branch(), "{i}");
            assert!(!i.writes_pc(), "{i}");
            assert_eq!(i.branch_target(), None, "{i}");
        }

        // `generate_link = (L == '1')` for HB/HBL, and HBLP writes LR
        // unconditionally; HBP has no `LR =` line at all.
        assert!(!hb.is_call());
        assert!(
            hbl.is_call(),
            "A9.5.2: HBL saves a return address to the LR"
        );
        assert!(!hbp.is_call());
        assert!(
            hblp.is_call(),
            "A9.5.3: HBLP saves a return address to the LR"
        );
    }

    /// `CHKA` is a conditional branch that is not a call, and never a pc write.
    ///
    /// It is in `is_branch`'s set because A9.5.1's taken path ends
    /// `BranchWritePC(TEEHBR - 8)` and because B1.3.2 lists it among the
    /// instructions that "branch to a value written to the PC". It is *not* in
    /// `is_call`'s, because the `lr` it writes is `PC` — this instruction's
    /// address plus four — and not the address of the following instruction,
    /// so it is not a return address. And `chka pc, r0` must not report a pc
    /// write: `Rn` holds the array size and is read, not written.
    #[test]
    fn chka_is_a_branch_but_not_a_call_and_writes_no_pc() {
        let chka = insn("chka", &[Operand::Reg(Reg(0)), Operand::Reg(Reg(1))]);
        assert!(chka.is_branch());
        assert!(!chka.is_call());
        assert!(!chka.writes_pc());
        assert_eq!(chka.branch_target(), None);

        // `N:Rn` can name `pc`, which A9.5.1 makes UNPREDICTABLE and this
        // crate still decodes. The first-operand heuristic must not fire.
        let chka_pc = insn("chka", &[Operand::Reg(Reg::PC), Operand::Reg(Reg(1))]);
        assert!(!chka_pc.writes_pc(), "Rn is the array size, a source");
        assert!(chka_pc.is_branch(), "still a branch, by mnemonic");
    }

    /// `RFE` writes `pc` and the CPSR from memory (B6.1.8) while naming only
    /// the base address it reads them through, so neither half of the
    /// first-operand heuristic can see it. The mnemonic has to decide.
    #[test]
    fn rfe_is_a_branch_whatever_its_operand_looks_like() {
        // The base is emitted as `Operand::Text("r0!")` when `W == 1` and as
        // an `Operand::Reg` when it is not; both are bases, and both are
        // exception returns.
        for base in [Operand::Reg(Reg(0)), Operand::Text("r0!")] {
            for m in ["rfeia", "rfedb"] {
                let i = insn(m, &[base]);
                assert!(i.writes_pc(), "{i} loads pc from memory");
                assert!(i.is_branch(), "{i}");
                assert!(!i.is_call(), "{i} does not write lr");
                assert_eq!(i.branch_target(), None, "{i}");
            }
        }

        // `n == 15` is UNPREDICTABLE (B6.1.8) and decodes anyway; the answer
        // must come from the mnemonic, not from `pc` appearing as the base.
        assert!(insn("rfedb", &[Operand::Reg(Reg::PC)]).writes_pc());
    }

    /// `SRS` is `RFE`'s mirror image and must not be caught by it: it *stores*
    /// `lr` and the SPSR (B6.1.10), so its base operand is a source and it
    /// transfers no control.
    #[test]
    fn srs_stores_and_does_not_branch() {
        for m in ["srsia", "srsdb"] {
            let i = insn(m, &[Operand::Text("sp!"), Operand::Imm(0x11)]);
            assert!(!i.writes_pc(), "{i}");
            assert!(!i.is_branch(), "{i}");
            // The encoding fixes the base at `sp`, but the guard must hold
            // whatever a hand-built instruction claims.
            let odd = insn(m, &[Operand::Reg(Reg::PC), Operand::Imm(0x11)]);
            assert!(!odd.writes_pc(), "{odd}: the base is an address");
        }
    }

    /// `BLX` covers two encodings with one mnemonic, and only one of them
    /// writes `pc` from a register. B1.3.2 groups `BLX (register)` with `BX`
    /// and `BXJ`; `BLX (immediate)` branches to a displacement its encoding
    /// carries, which is the `B`/`BL` case this method answers `false` for.
    #[test]
    fn blx_writes_pc_only_in_its_register_form() {
        let reg = insn("blx", &[Operand::Reg(Reg(3))]);
        let imm = insn("blx", &[Operand::Target(0x1234)]);

        assert!(
            reg.writes_pc(),
            "blx r3 writes pc from r3, exactly as bx does"
        );
        assert!(!imm.writes_pc(), "blx <label> is classified with b and bl");
        // Both are branches and both are calls, whatever the operand.
        for i in [reg, imm] {
            assert!(i.is_branch(), "{i}");
            assert!(i.is_call(), "{i}");
        }
        // The register form used to answer `false` for `blx r3` and `true`
        // for `blx pc` — the latter only because the fallback read a source
        // operand as a destination.
        assert!(insn("blx", &[Operand::Reg(Reg::PC)]).writes_pc());
        assert!(insn("bx", &[Operand::Reg(Reg(3))]).writes_pc());
        assert!(insn("bxj", &[Operand::Reg(Reg(3))]).writes_pc());
        assert!(!insn("bx", &[Operand::Reg(Reg(3))]).is_call());
    }

    /// A vector load-multiple names its base address first, like `srs` and
    /// unlike every data-processing instruction. It writes floating-point
    /// registers and never the core `pc`.
    #[test]
    fn vector_load_multiple_base_is_not_a_destination() {
        for m in ["vldmia", "vldmdb"] {
            let i = insn(m, &[Operand::Reg(Reg::PC), Operand::Text("{s0-s3}")]);
            assert!(!i.writes_pc(), "{i}: the first operand is the base");
            assert!(!i.is_branch(), "{i}");
        }
    }

    /// Exception-generating instructions are not branches. They transfer
    /// control through the exception mechanism to a vector this crate cannot
    /// see, and B1.3.2's list of instructions that branch to a value written
    /// to the PC excludes every one of them.
    #[test]
    fn exception_generating_instructions_are_not_branches() {
        for m in ["svc", "bkpt", "udf", "smc"] {
            let i = insn(m, &[Operand::Imm(0)]);
            assert!(!i.is_branch(), "{i}");
            assert!(!i.is_call(), "{i}");
            assert!(!i.writes_pc(), "{i}");
        }
        // Nor are ThumbEE's state changes, which fall through to the next
        // instruction (A9.3.1).
        for m in ["enterx", "leavex"] {
            assert!(!insn(m, &[]).is_branch());
        }
    }

    /// The documented overload in `branch_target`: a pc-relative *literal*
    /// access carries an `Operand::Target` that is the address of the pool
    /// word, not a branch destination.
    ///
    /// Pinned rather than fixed. `t16_branch::encode` re-derives a branch
    /// displacement from this operand and four modules pin literal addresses
    /// through it, so the method keeps returning the first `Target` it finds;
    /// what a control-flow consumer needs to know — ignore a `Target` when the
    /// instruction also has an `Operand::Mem` — is in the doc comment.
    #[test]
    fn branch_target_of_a_literal_load_is_the_pool_word() {
        let pool = Mem {
            base: Reg::PC,
            index: None,
            offset: 8,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        };
        // Harmless: not a branch, so nothing reads the target as one.
        let plain = insn(
            "ldr",
            &[
                Operand::Reg(Reg(0)),
                Operand::Mem(pool),
                Operand::Target(0x1010),
            ],
        );
        assert!(!plain.is_branch());
        assert_eq!(plain.branch_target(), Some(0x1010));

        // Not harmless: this one *is* a branch, and 0x1010 is the address of
        // the word holding the destination, not the destination.
        let into_pc = insn(
            "ldr",
            &[
                Operand::Reg(Reg::PC),
                Operand::Mem(pool),
                Operand::Target(0x1010),
            ],
        );
        assert!(into_pc.is_branch() && into_pc.writes_pc());
        assert_eq!(into_pc.branch_target(), Some(0x1010));
        assert!(
            into_pc
                .operands
                .as_slice()
                .any(|o| matches!(o, Operand::Mem(_))),
            "the `Mem` operand is what marks the target as a pool address"
        );
    }

    /// The pc-destination fallback, spot-checked against the families that
    /// reach it: a load or data operation with `pc` first really does write
    /// `pc`, and the `ldm` family is answered off its register list instead.
    #[test]
    fn pc_destination_fallback_still_holds() {
        assert!(insn("ldrd", &[Operand::Reg(Reg::PC), Operand::Reg(Reg(1))]).writes_pc());
        assert!(insn("mrs", &[Operand::Reg(Reg::PC), Operand::SpecialReg("APSR")]).writes_pc());
        assert!(insn("sub", &[Operand::Reg(Reg::PC), Operand::Reg(Reg::LR)]).writes_pc());

        for m in ["ldm", "ldmia", "ldmdb", "pop"] {
            assert!(insn(m, &[Operand::Text("r0!"), Operand::RegList(1 << 15)]).writes_pc());
            assert!(!insn(m, &[Operand::Text("r0!"), Operand::RegList(1 << 14)]).writes_pc());
            // A pc *base* is not a pc write, in either direction.
            assert!(!insn(m, &[Operand::Reg(Reg::PC), Operand::RegList(1)]).writes_pc());
        }
        // `tbb`/`tbh` branch without writing pc as a register.
        for m in ["tbb", "tbh"] {
            let i = insn(
                m,
                &[Operand::Mem(Mem {
                    base: Reg(0),
                    index: Some((Reg(1), None)),
                    offset: 0,
                    add: true,
                    align: 0,
                    mode: AddrMode::Offset,
                })],
            );
            assert!(i.is_branch() && !i.writes_pc() && !i.is_call(), "{i}");
        }
    }

    /// `Mem`'s four addressing modes against the manual's syntax lines, and the
    /// `#0`/`#-0` distinction those lines exist to make.
    ///
    /// A7.7.50: "different instructions are generated for `#0` and `#-0`". The
    /// two must therefore be different `Mem` values, and they must print
    /// differently — otherwise a disassembly of one re-assembles as the other.
    #[test]
    fn mem_display_follows_the_manuals_syntax_lines() {
        let mem = |mode, add, offset| Mem {
            base: Reg(0),
            index: None,
            offset,
            add,
            align: 0,
            mode,
        };
        // `[<Rn>{,#+/-<imm>}]` — braced, so an adding zero is omitted. `#-0`
        // is not, because it is the whole of what that encoding says.
        assert_eq!(mem(AddrMode::Offset, true, 0).to_string(), "[r0]");
        assert_eq!(mem(AddrMode::Offset, false, 0).to_string(), "[r0, #-0]");
        assert_eq!(mem(AddrMode::Offset, true, 4).to_string(), "[r0, #4]");
        assert_eq!(mem(AddrMode::Offset, false, 4).to_string(), "[r0, #-4]");
        // `[<Rn>,#+/-<imm>]!` and `[<Rn>],#+/-<imm>` — not braced, so the
        // displacement always prints. For the post-indexed form especially:
        // `[r0]` would read back as the offset form, and the writeback is the
        // whole point of the mode.
        assert_eq!(mem(AddrMode::PreIndex, true, 0).to_string(), "[r0, #0]!");
        assert_eq!(mem(AddrMode::PreIndex, false, 0).to_string(), "[r0, #-0]!");
        assert_eq!(mem(AddrMode::PostIndex, true, 0).to_string(), "[r0], #0");
        assert_eq!(mem(AddrMode::PostIndex, false, 0).to_string(), "[r0], #-0");
        assert_eq!(mem(AddrMode::PostIndex, true, 4).to_string(), "[r0], #4");
        // `#0` and `#-0` are distinct values, and they are distinct from each
        // other in every mode, but they name the same effective address.
        for mode in [AddrMode::Offset, AddrMode::PreIndex, AddrMode::PostIndex] {
            let plus = mem(mode, true, 0);
            let minus = mem(mode, false, 0);
            assert_ne!(plus, minus);
            assert_ne!(plus.to_string(), minus.to_string());
            assert_eq!(plus.displacement(), minus.displacement());
        }
        assert_eq!(mem(AddrMode::Offset, false, 4).displacement(), -4);

        // `[<Rn>]!` with an implicit increment prints no displacement, because
        // the encoding carries none (A7.7.1).
        assert_eq!(mem(AddrMode::PostIncrement, true, 0).to_string(), "[r0]!");

        // An index replaces the displacement, and the Advanced SIMD alignment
        // qualifier goes inside the brackets.
        let indexed = Mem {
            index: Some((
                Reg(3),
                Some(Shift {
                    kind: ShiftKind::Lsl,
                    amount: ShiftAmount::Imm(1),
                }),
            )),
            ..mem(AddrMode::Offset, true, 0)
        };
        assert_eq!(indexed.to_string(), "[r0, r3, lsl #1]");
        assert_eq!(
            Mem {
                align: 64,
                ..mem(AddrMode::Offset, true, 0)
            }
            .to_string(),
            "[r0:64]"
        );
        assert_eq!(
            Mem {
                align: 128,
                ..mem(AddrMode::PostIncrement, true, 0)
            }
            .to_string(),
            "[r0:128]!"
        );
        assert_eq!(
            Mem {
                align: 64,
                index: Some((Reg(3), None)),
                ..mem(AddrMode::PostIndex, true, 0)
            }
            .to_string(),
            "[r0:64], r3"
        );
    }

    #[test]
    fn reglist_display_collapses_runs() {
        let show = |bits| insn("push", &[Operand::RegList(bits)]).to_string();
        assert_eq!(show(0b0000_0000_0000_1111), "push {r0-r3}");
        assert_eq!(show(0b0100_0000_0000_0001), "push {r0, lr}");
        assert_eq!(show(0b1000_0000_0000_0011), "push {r0, r1, pc}");
        assert_eq!(show(0b0000_0000_1000_0001), "push {r0, r7}");
    }

    /// A narrow literal load prints its zero displacement; nothing else does.
    ///
    /// `ldr r0, [pc]` is ambiguous between `LDR (literal)` T1 (`4800`) and T2
    /// (`F8DF 0000`), and an assembler resolves it the wrong way: LLVM reads
    /// the bracketed-base-with-no-displacement text as T2 only, so the eight
    /// halfwords `0x4800`, `0x4900` … `0x4F00` did not survive a byte round
    /// trip. `[pc, #0]` names the narrow encoding (verified against Apple
    /// clang 21), and A7.7.44's pc-relative syntax line
    /// `LDR<c><q> <Rt>, [PC, #+/-<imm>]` writes the immediate unbraced for
    /// exactly that reason.
    ///
    /// The gate is the instruction, not the operand: a `Mem` cannot tell a
    /// literal access from `strex pc, r0, [pc]`, which holds the identical
    /// value and which LLVM writes bare.
    #[test]
    fn a_narrow_literal_load_prints_its_zero_displacement() {
        let pool = |add, offset| Mem {
            base: Reg::PC,
            index: None,
            offset,
            add,
            align: 0,
            mode: AddrMode::Offset,
        };
        // The operand on its own follows the manual's braces, as every
        // addressing mode does.
        assert_eq!(pool(true, 0).to_string(), "[pc]");
        assert_eq!(pool(true, 8).to_string(), "[pc, #8]");
        assert_eq!(pool(false, 0).to_string(), "[pc, #-0]");

        // In a narrow literal access — a pc-based memory operand with the
        // resolved address beside it — the displacement prints.
        let literal = |width, ops: &[Operand]| Insn {
            width,
            ..insn("ldr", ops)
        };
        let t1 = literal(
            Width::Narrow,
            &[
                Operand::Reg(Reg(0)),
                Operand::Mem(pool(true, 0)),
                Operand::Target(0x1004),
            ],
        );
        assert_eq!(t1.to_string(), "ldr r0, [pc, #0], 0x1004");

        // The wide forms are already unambiguous — `.w` is what selects them,
        // and `ldr.w r0, [pc]` assembles back to the bytes it came from — so
        // they are left as the manual writes them.
        let mut t2 = literal(
            Width::Wide,
            &[
                Operand::Reg(Reg(0)),
                Operand::Mem(pool(true, 0)),
                Operand::Target(0x1004),
            ],
        );
        t2.explicit_width = true;
        assert_eq!(t2.to_string(), "ldr.w r0, [pc], 0x1004");

        // A pc *base* that is not a literal access keeps its bare form: it is
        // not ambiguous, and an invented `#0` operand would make this crate
        // disagree with LLVM's disassembly of the same bytes.
        let strex = insn(
            "strex",
            &[
                Operand::Reg(Reg::PC),
                Operand::Reg(Reg(0)),
                Operand::Mem(pool(true, 0)),
            ],
        );
        assert_eq!(strex.to_string(), "strex pc, r0, [pc]");

        // Nor does a narrow instruction with a target but an ordinary base,
        // or one whose pc-based operand already prints a displacement.
        let sp = insn(
            "ldr",
            &[
                Operand::Reg(Reg(0)),
                Operand::Mem(Mem {
                    base: Reg::SP,
                    ..pool(true, 0)
                }),
                Operand::Target(0x1004),
            ],
        );
        assert_eq!(sp.to_string(), "ldr r0, [sp], 0x1004");
        let minus = insn(
            "ldr",
            &[
                Operand::Reg(Reg(0)),
                Operand::Mem(pool(false, 0)),
                Operand::Target(0x1004),
            ],
        );
        assert_eq!(minus.to_string(), "ldr r0, [pc, #-0], 0x1004");
        // An index replaces the displacement, literal access or not.
        let indexed = insn(
            "ldr",
            &[
                Operand::Reg(Reg(0)),
                Operand::Mem(Mem {
                    index: Some((Reg(3), None)),
                    ..pool(true, 0)
                }),
                Operand::Target(0x1004),
            ],
        );
        assert_eq!(indexed.to_string(), "ldr r0, [pc, r3], 0x1004");
    }

    /// A floating-point immediate always prints with a decimal point.
    ///
    /// A7.7.229's `<imm>` is a floating-point constant, and an assembler
    /// enforces that: LLVM rejects `vmov.f32 s1, #2` ("invalid floating point
    /// immediate") and accepts `vmov.f32 s1, #2.0`. `{}` on an `f64` renders
    /// `2.0` as `2`, so every integral `VFPExpandImm`/`AdvSIMDExpandImm` value
    /// printed as an integer literal until this was forced.
    #[test]
    fn fp_immediates_always_carry_a_decimal_point() {
        let show = |v: f64| Operand::FpImm(v).to_string();
        assert_eq!(show(5.0), "#5.0");
        assert_eq!(show(2.0), "#2.0");
        assert_eq!(show(-19.0), "#-19.0");
        assert_eq!(show(0.0), "#0.0");
        assert_eq!(show(-0.0), "#-0.0");
        // A non-integral value carries its own point and is printed as it is —
        // `VFPExpandImm` produces these (`#0.3` is not one of them, but
        // `#0.125` is: sign 0, exp 0b011, frac 0).
        assert_eq!(show(0.125), "#0.125");
        assert_eq!(show(-0.375), "#-0.375");
        assert_eq!(show(31.0), "#31.0");
        // The largest and smallest VFP-expandable magnitudes, from A7.7.229's
        // table: 2^-3 x (16..31)/16 up to 2^4 x (16..31)/16.
        assert_eq!(show(0.0625), "#0.0625");
    }

    /// Every `Operand` variant's printed form, including the two that no
    /// current decoder emits, so a future one cannot silently discover that
    /// `Display` was never exercised for them.
    ///
    /// The negative-immediate arm is the interesting one: an `Imm` is already
    /// sign-corrected, so a negative value must print as a signed magnitude
    /// (`#-0x18`) and not as the 64-bit two's complement of it.
    #[test]
    fn operand_display_covers_every_variant() {
        assert_eq!(Operand::Reg(Reg(3)).to_string(), "r3");
        assert_eq!(
            Operand::RegShifted(
                Reg(3),
                Shift {
                    kind: ShiftKind::Asr,
                    amount: ShiftAmount::Imm(4),
                },
            )
            .to_string(),
            "r3, asr #4"
        );
        // Below ten in decimal, at or above it in hex — and negatives signed.
        assert_eq!(Operand::Imm(9).to_string(), "#9");
        assert_eq!(Operand::Imm(10).to_string(), "#0xa");
        assert_eq!(Operand::Imm(-0x18).to_string(), "#-0x18");
        assert_eq!(Operand::Imm(-1).to_string(), "#-0x1");
        assert_eq!(Operand::RegList(0b1001).to_string(), "{r0, r3}");
        assert_eq!(Operand::Target(0x8004).to_string(), "0x8004");
        assert_eq!(Operand::FpReg(FpReg::S(5)).to_string(), "s5");
        assert_eq!(Operand::FpReg(FpReg::D(15)).to_string(), "d15");
        assert_eq!(Operand::FpReg(FpReg::Q(3)).to_string(), "q3");
        assert_eq!(Operand::FpScalar(FpReg::D(3), 1).to_string(), "d3[1]");
        assert_eq!(Operand::SpecialReg("PRIMASK").to_string(), "PRIMASK");
        assert_eq!(Operand::Option("nshst").to_string(), "nshst");
        assert_eq!(Operand::Coproc(14).to_string(), "p14");
        assert_eq!(Operand::CoprocReg(5).to_string(), "c5");
        assert_eq!(Operand::Cond(Cond::Ge).to_string(), "ge");
        assert_eq!(Operand::Text("be").to_string(), "be");

        // The shift vocabulary, printed on its own: `RRX` takes no amount
        // (A7.4.2 gives it a fixed shift of one, through the carry flag), and a
        // register-controlled shift prints the register.
        assert_eq!(ShiftKind::Lsl.to_string(), "lsl");
        assert_eq!(ShiftKind::Lsr.to_string(), "lsr");
        assert_eq!(ShiftKind::Asr.to_string(), "asr");
        assert_eq!(ShiftKind::Ror.to_string(), "ror");
        assert_eq!(ShiftKind::Rrx.to_string(), "rrx");
        let rrx = Shift {
            kind: ShiftKind::Rrx,
            amount: ShiftAmount::Imm(1),
        };
        assert_eq!(rrx.to_string(), "rrx", "the amount is never printed");
        assert_eq!(
            Shift {
                kind: ShiftKind::Ror,
                amount: ShiftAmount::Reg(Reg(2)),
            }
            .to_string(),
            "ror r2"
        );
    }

    /// `explicit_width` renders UAL's `<q>` qualifier (A7.1.3), which is what
    /// tells an assembler which of a narrow/wide pair to emit.
    #[test]
    fn an_explicit_width_prints_as_a_qualifier() {
        let mut i = insn("mov", &[Operand::Reg(Reg(0)), Operand::Reg(Reg(1))]);
        assert_eq!(i.to_string(), "mov r0, r1", "no qualifier by default");

        i.explicit_width = true;
        assert_eq!(i.to_string(), "mov.n r0, r1");
        i.width = Width::Wide;
        assert_eq!(i.to_string(), "mov.w r0, r1");

        // The suffixes stack in UAL's order: mnemonic, `S`, condition, width.
        i.sets_flags = true;
        i.cond = Some(Cond::Eq);
        assert_eq!(i.to_string(), "movseq.w r0, r1");
    }

    /// `len` is the width in bytes and `is_empty` is always false — an
    /// instruction is never a zero-length thing, and the method exists only so
    /// that `len` does not trip `clippy::len_without_is_empty`.
    #[test]
    fn len_follows_the_width_and_is_empty_is_never_true() {
        let mut i = insn("bx", &[Operand::Reg(Reg::LR)]);
        assert_eq!(i.len(), 2);
        assert_eq!(i.len(), Width::Narrow.bytes());
        assert!(!i.is_empty());

        i.width = Width::Wide;
        assert_eq!(i.len(), 4);
        assert_eq!(i.len(), Width::Wide.bytes());
        assert!(!i.is_empty());
    }

    /// A sink that fails on its `budget`-th `write_str`, and counts calls.
    struct FailAfter {
        budget: usize,
        writes: usize,
    }

    impl core::fmt::Write for FailAfter {
        fn write_str(&mut self, _: &str) -> core::fmt::Result {
            if self.writes == self.budget {
                return Err(core::fmt::Error);
            }
            self.writes += 1;
            Ok(())
        }
    }

    /// Every `Display` impl here propagates a sink error instead of swallowing
    /// it or panicking.
    ///
    /// Not a hypothetical: a disassembly listing is written to a file, a pipe
    /// or a socket, and those fail for reasons the formatter cannot see. An
    /// impl that dropped the error would emit a silently truncated
    /// instruction — the worst possible output for a tool whose text is pasted
    /// into an assembler. The claim is exact: formatting a value that takes `n`
    /// writes fails for every budget below `n` and succeeds at `n`.
    #[test]
    fn display_propagates_writer_errors() {
        use core::fmt::Write;

        let mem = |mode, index, align| Mem {
            base: Reg(1),
            index,
            offset: 4,
            add: true,
            align,
            mode,
        };
        let lsl3 = Shift {
            kind: ShiftKind::Lsl,
            amount: ShiftAmount::Imm(3),
        };
        let shift = Some(lsl3);
        let mut rich = insn(
            "ldr",
            &[
                Operand::Reg(Reg(0)),
                Operand::Mem(mem(AddrMode::Offset, None, 0)),
                Operand::Target(0x1234),
            ],
        );
        rich.sets_flags = true;
        rich.cond = Some(Cond::Ne);
        rich.explicit_width = true;
        let literal = insn(
            "ldr",
            &[
                Operand::Reg(Reg(0)),
                Operand::Mem(Mem {
                    base: Reg::PC,
                    offset: 0,
                    ..mem(AddrMode::Offset, None, 0)
                }),
                Operand::Target(0x1004),
            ],
        );
        assert_eq!(literal.to_string(), "ldr r0, [pc, #0], 0x1004");

        let cases: &[&dyn core::fmt::Display] = &[
            &Reg::PC,
            &FpReg::D(3),
            &ShiftKind::Ror,
            &lsl3,
            // Every arm of `Mem`'s `Display`: index with a shift, a negative
            // displacement, the alignment qualifier, and all four modes.
            &mem(AddrMode::Offset, Some((Reg(2), shift)), 0),
            &mem(AddrMode::Offset, None, 64),
            &Mem {
                add: false,
                ..mem(AddrMode::Offset, None, 0)
            },
            &Mem {
                base: Reg::PC,
                offset: 0,
                ..mem(AddrMode::Offset, None, 0)
            },
            &mem(AddrMode::PreIndex, None, 0),
            &mem(AddrMode::PostIndex, None, 32),
            &mem(AddrMode::PostIncrement, None, 16),
            // A register list with a singleton, a pair and a longer run, so
            // each of `write_reglist`'s three spellings is reached.
            &Operand::RegList(0b1000_0111_0000_1101),
            &Operand::Imm(-4),
            &Operand::FpImm(2.0),
            &rich,
            // A narrow literal load, whose memory operand `Insn`'s `Display`
            // renders itself rather than delegating to `Operand`.
            &literal,
        ];

        for case in cases {
            let mut sink = FailAfter {
                budget: usize::MAX,
                writes: 0,
            };
            write!(sink, "{case}").expect("an unlimited sink never fails");
            let n = sink.writes;
            assert!(n > 0, "`{case}` wrote nothing at all");

            for budget in 0..n {
                let mut sink = FailAfter { budget, writes: 0 };
                assert!(
                    write!(sink, "{case}").is_err(),
                    "`{case}` swallowed a failure at write {budget} of {n}"
                );
                assert_eq!(sink.writes, budget, "`{case}` wrote on past the failure");
            }
            let mut sink = FailAfter {
                budget: n,
                writes: 0,
            };
            assert!(write!(sink, "{case}").is_ok(), "`{case}` at full budget");
        }
    }

    #[test]
    fn registers_print_their_architectural_names() {
        assert_eq!(Reg(0).to_string(), "r0");
        assert_eq!(Reg(12).to_string(), "r12");
        assert_eq!(Reg::SP.to_string(), "sp");
        assert_eq!(Reg::LR.to_string(), "lr");
        assert_eq!(Reg::PC.to_string(), "pc");
        assert!(Reg(7).is_low() && !Reg(8).is_low());
    }

    /// Every clause of the source-first guard in [`Insn::writes_pc`], one
    /// mnemonic at a time.
    ///
    /// The guard is a chain of `starts_with`/`==`/`matches!` disjuncts.
    /// Mutation testing flipped its `||`s to `&&` — which makes the whole
    /// chain unsatisfiable, since no mnemonic starts with two different
    /// prefixes at once — and nothing failed. With the guard disabled every
    /// one of these reports as a pc *write*, so `str pc, [r0]` becomes a
    /// branch and any control-flow graph built on it is wrong.
    #[test]
    fn no_clause_of_the_source_first_guard_can_be_dropped() {
        // `pc` as operand 0 of each source-first family: read, never written.
        for m in [
            "str", "strb", "strh", "strd", "strex", "strexb", "vstr", "vstm", "vldm", "stm",
            "stmdb", "push", "vpush", "cmp", "cmn", "tst", "teq", "chka", "srsia", "srsdb",
        ] {
            let i = insn(m, &[Operand::Reg(Reg::PC), Operand::Reg(Reg(0))]);
            assert!(
                !i.writes_pc(),
                "{m} names a source first, so `{m} pc, r0` reads pc"
            );
        }
        // And the fallback still works: a destination-first instruction with
        // `pc` as operand 0 does write it.
        for m in ["mov", "add", "sub", "and", "orr", "eor", "lsl", "adr"] {
            let i = insn(m, &[Operand::Reg(Reg::PC), Operand::Reg(Reg(0))]);
            assert!(i.writes_pc(), "`{m} pc, r0` writes pc");
        }
        // Near-misses that must not be swept up by a prefix: `ldr` is not
        // `ldm`, `vldr` is not `vldm`, `sub` is not `srsia`.
        for m in ["ldr", "vldr", "sub"] {
            let i = insn(m, &[Operand::Reg(Reg::PC), Operand::Reg(Reg(0))]);
            assert!(i.writes_pc(), "`{m} pc, r0` writes pc");
        }
    }
}
