//! Coprocessor, floating-point and Advanced-SIMD-adjacent 32-bit encodings —
//! `hw1[15:13] == 0b111` with `hw1[11:10] == 0b11`, that is `hw1` in
//! `0xEC00..=0xEFFF` and `0xFC00..=0xFFFF`
//! (ARM DDI 0403E.e A5.3.18 and Table A5-30; ARM DDI 0406B A6.3.18 and
//! Table A6-29, which allocates the same space and names the floating-point
//! rows Table A5-30 leaves implicit).
//!
//! The dispatcher reaches this module from two arms — `op1 == 0b01` and
//! `op1 == 0b11` of Table A5-9 — because `hw1[12]` is not part of the group
//! selector here. It is the bit that turns `LDC` into `LDC2`, `CDP` into
//! `CDP2`, and (once the coprocessor number says floating-point) VFPv4 into
//! the four FPv5 instructions `VSEL`, `VMAXNM`/`VMINNM`, `VRINT{A,N,P,M}` and
//! `VCVT{A,N,P,M}`. It is spelled `T` throughout this file, as it is in the
//! manual's A6 diagrams.
//!
//! # Two instruction sets share one encoding space
//!
//! Every encoding here is architecturally a coprocessor access, and the
//! coprocessor number — `hw2[11:8]` — decides how to read the rest. For
//! `coproc` values other than 10 and 11 the operand fields are *opaque*: A7.7.22
//! says of `CDP` that "only instruction bits<31:24>, bits<11:8>, and bit<4> are
//! architecturally defined. The remaining fields are recommendations". So those
//! forms decode to [`Operand::Coproc`], [`Operand::CoprocReg`] and
//! [`Operand::Imm`] and nothing is claimed about what they mean.
//!
//! `coproc == 10` (`0b1010`) and `coproc == 11` (`0b1011`) are not coprocessor
//! accesses at all in any implementation that matters: they are the
//! floating-point instruction set (A6.1), and `coproc[0]` is the precision —
//! 10 for single, 11 for double. Decoding `vadd.f32 s0, s1, s2` as
//! `cdp p10, #3, c0, c0, c1` is not wrong so much as useless, so this module
//! re-decodes the whole of chapter A6 in that space.
//!
//! # The register-numbering rule, which is the thing to get right
//!
//! An extension register number is five bits assembled from a 4-bit field and a
//! separate 1-bit field, **and the two are concatenated in opposite orders for
//! the two precisions** (Table A6-4, "Encoding of register numbers"):
//!
//! | operand | single precision | double precision |
//! |---------|------------------|------------------|
//! | `d`/destination | `Vd:D`, `bits[15:12,22]` | `D:Vd`, `bits[22,15:12]` |
//! | `n`/first source | `Vn:N`, `bits[19:16,7]` | `N:Vn`, `bits[7,19:16]` |
//! | `m`/second source | `Vm:M`, `bits[3:0,5]` | `M:Vm`, `bits[5,3:0]` |
//!
//! The bit numbers above are the manual's, over the whole 32-bit word. In this
//! crate's halfwords: `bit[22]` is `hw1[6]` (`D`), `bits[19:16]` are `hw1[3:0]`
//! (`Vn`), `bit[7]` is `hw2[7]` (`N`), `bits[15:12]` are `hw2[15:12]` (`Vd`),
//! `bit[5]` is `hw2[5]` (`M`) and `bits[3:0]` are `hw2[3:0]` (`Vm`) — which is why
//! [`sreg`] and [`dreg`] take the two halves as arguments rather than digging
//! them out of a halfword themselves. Get the order backwards
//! and `s1` decodes as `s16`: the same halfword pair names *different*
//! registers depending on the `sz` bit, and every one of the 32 register
//! numbers is reachable either way, so nothing about the bits looks wrong. The
//! only defence is a test that pins both directions, which is this module's
//! `single_and_double_read_the_same_bits_in_opposite_orders`.
//!
//! # Where this module stops and `t32_simd` starts
//!
//! Advanced SIMD (NEON) data-processing is `op1 == 0b11xxxx` in Table A6-29 —
//! `hw1[9:8] == 0b11`, that is `111x 1111 …`. Those encodings fall in this
//! module's halfword range and this module returns `None` for all of them.
//! Advanced SIMD element and structure load/store (`1111 1001 …`) never
//! reaches here: `hw1[11:10]` is `0b01` there, and the dispatcher routes it
//! straight to `t32_simd`. The one genuinely shared row is the scalar
//! `VMOV`/`VDUP` group in the `MCR` space, where the FP extension defines only
//! the 32-bit element size: this module decodes `VMOV.32 <Dd[x]>, <Rt>` and
//! `VMOV.32 <Rt>, <Dn[x]>` (`opc1[1] == 0`, `opc2 == 0b00`, A7.7.241/A7.7.242)
//! and returns `None` for the 8-bit and 16-bit element sizes and for `VDUP`,
//! which are Advanced SIMD.
//!
//! # `(0)` bits are part of the pattern
//!
//! Several encodings here have fields the manual writes `(0)`: should-be-zero
//! bits whose behaviour when set is UNPREDICTABLE. This module refuses to
//! decode an encoding with a non-zero `(0)` field. The alternative — decoding
//! it and dropping the bits — produces an [`Insn`] that cannot re-encode to the
//! halfwords it came from, which would silently weaken the round-trip proof
//! that is this crate's whole compliance argument.
//!
//! # What the shared vocabulary cannot say
//!
//! Three things in A6/A7 have no [`Operand`] variant, and all three are
//! rendered with [`Operand::Text`] from a `const` table so that the printed
//! UAL is still exactly the manual's:
//!
//! * A floating-point register *range*. `VLDM`/`VSTM`/`VPUSH`/`VPOP` encode a
//!   first register and a count, not a bitmask, so [`Operand::RegList`] — 16
//!   bits, one per core register — cannot hold one. Every list is therefore an
//!   [`Operand::Text`] drawn from [`S_RANGES`]/[`D_RANGES`], or from
//!   [`S_SINGLE`]/[`D_SINGLE`] when it holds one register.
//! * A base register with writeback, `<Rn>!`. Every [`AddrMode`] prints
//!   brackets — `[r2, #0]!` for [`AddrMode::PreIndex`], `[r2]!` for
//!   [`AddrMode::PostIncrement`] — and `VLDM` writes neither. See
//!   [`WRITEBACK`].
//! * `LDC`'s unindexed `<option>`, an integer in braces. See [`OPTIONS`].
//!
//! Two things this module used to work around are now said directly, because
//! [`Mem`] can say them. A post-indexed zero offset — `LDC`'s `[<Rn>], #0` —
//! prints as `[r0], #0`, not as the `[r0]` that reads back as the offset form:
//! [`AddrMode::PostIndex`] always prints its displacement. And `#-0`, which
//! A7.7.39 and A7.7.236 both name as a different instruction from `#0`, is
//! decoded rather than refused, because [`Mem::add`] is the `U` bit itself
//! rather than a sign folded into the offset. Both `LDC`/`STC` and
//! `VLDR`/`VSTR` therefore decode their whole `U`/`imm8` space and re-encode
//! it byte for byte.
//!
//! The unindexed form is [`AddrMode::Offset`], not [`AddrMode::PostIndex`]:
//! A7.7.39's pseudocode sets `index = FALSE` *and* `wback = FALSE` for it, so
//! the address is `R[n]` and nothing is written back. It is told apart from the
//! plain offset form by the [`Operand::Option`] that follows, which is exactly
//! what its syntax line does.
//!
//! Two more are worked around in the mnemonic. `VSEL`'s condition is part of
//! the operation, not a suffix the IT machinery supplies, and `Display` prints
//! the condition *after* the mnemonic — which for a type-suffixed mnemonic
//! would give `vsel.f32gt` — so the four conditions are spelled into the
//! mnemonic (`vselgt.f32`). And no instruction in this file sets `sets_flags`:
//! `VCMP` writes `FPSCR`, not the APSR, and a `true` there would print
//! `vcmps.f32`.

use super::{AddrMode, FpReg, Insn, Mem, Operand, Operands, Reg, Width};

// ---------------------------------------------------------------------------
// Bit plumbing
// ---------------------------------------------------------------------------

/// Bit `n` of `x`.
fn bit(x: u16, n: u32) -> u16 {
    (x >> n) & 1
}

/// Bits `hi..=lo` of `x`, shifted down to bit 0.
fn bits(x: u16, hi: u32, lo: u32) -> u16 {
    (x >> lo) & ((1u16 << (hi - lo + 1)) - 1)
}

/// `Align(PC, 4)` for the instruction at `addr` (A4.2.2): Thumb's pc is the
/// instruction's address plus four, forced word-aligned.
fn literal_base(addr: u32) -> u32 {
    addr.wrapping_add(4) & !3
}

/// A single-precision register number, `Vx:X` — the 4-bit field is the *high*
/// part (Table A6-4).
fn sreg(v: u16, x: u16) -> FpReg {
    FpReg::S((((v << 1) | x) & 0x1F) as u8)
}

/// A double-precision register number, `X:Vx` — the 1-bit field is the *high*
/// part (Table A6-4). This is the inverse concatenation of [`sreg`], and the
/// single most error-prone thing in the floating-point encoding.
fn dreg(v: u16, x: u16) -> FpReg {
    FpReg::D((((x << 4) | v) & 0x1F) as u8)
}

/// [`dreg`] when `dbl`, [`sreg`] otherwise — the `sz` bit selecting between
/// them (A6.3).
fn freg(v: u16, x: u16, dbl: bool) -> FpReg {
    if dbl {
        dreg(v, x)
    } else {
        sreg(v, x)
    }
}

/// Split a register back into its `(4-bit field, 1-bit field)` halves, by
/// precision — the inverse of [`freg`], and `None` if the register is of the
/// wrong kind (a `q` register, or a precision the encoding cannot name).
fn split(r: FpReg, dbl: bool) -> Option<(u16, u16)> {
    match (r, dbl) {
        (FpReg::S(n), false) if n < 32 => Some(((n >> 1) as u16, (n & 1) as u16)),
        (FpReg::D(n), true) if n < 32 => Some(((n & 0xF) as u16, (n >> 4) as u16)),
        _ => None,
    }
}

/// Build the shape every instruction in this group shares: wide, no condition
/// of its own, no flag update, no explicit width suffix.
fn wide(mnemonic: &'static str, encoding: &'static str, addr: u32, operands: Operands) -> Insn {
    Insn {
        mnemonic,
        encoding,
        addr,
        width: Width::Wide,
        cond: None,
        sets_flags: false,
        explicit_width: false,
        operands,
    }
}

/// Collect operands, since every decode here builds a fixed list.
fn ops(list: &[Operand]) -> Operands {
    let mut o = Operands::new();
    for item in list {
        o.push(*item);
    }
    o
}

// ---------------------------------------------------------------------------
// Printable spellings the shared `Operand` vocabulary cannot compose
// ---------------------------------------------------------------------------

/// One row of a register-range table: every `{<letter><first>-<letter><last>}`
/// spelling for one `first`.
macro_rules! fp_range_row {
    ($letter:literal, $first:literal, [$($last:literal),* $(,)?]) => {
        [$(concat!("{", $letter, $first, "-", $letter, $last, "}")),*]
    };
}

/// A `[[&str; 32]; 32]` table of register-range spellings, indexed
/// `[first][last]`.
///
/// Built by macro rather than written out because the 1,024 entries per
/// precision are mechanical, and because `Insn::mnemonic` and
/// [`Operand::Text`] are `&'static str`: a range's printed form cannot be
/// composed at run time without allocating, and this crate does not allocate.
/// Entries with `last < first`, and (for double precision) entries more than
/// sixteen registers long, are never indexed — [`fp_list`] rejects those
/// register counts as the architecture does.
macro_rules! fp_range_table {
    ($letter:literal, [$($first:literal),* $(,)?], $lasts:tt) => {
        [$(fp_range_row!($letter, $first, $lasts)),*]
    };
}

/// Single-precision register-range spellings, `S_RANGES[first][last]`.
const S_RANGES: [[&str; 32]; 32] = fp_range_table!(
    "s",
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31
    ],
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31
    ]
);

/// Double-precision register-range spellings, `D_RANGES[first][last]`.
const D_RANGES: [[&str; 32]; 32] = fp_range_table!(
    "d",
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31
    ],
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31
    ]
);

/// One-register list spellings, `{<letter><n>}`.
///
/// A6.2.3 permits dropping the braces for a single register, but no assembler
/// this crate has been checked against accepts that for `VLDM`/`VSTM`, and a
/// list that sometimes prints as a list and sometimes as a bare register is
/// harder for a consumer to handle, not easier. So every list prints braced,
/// and the one-register case needs its own table because the range macro would
/// give `{s3-s3}`.
macro_rules! fp_single_table {
    ($letter:literal, [$($n:literal),* $(,)?]) => {
        [$(concat!("{", $letter, $n, "}")),*]
    };
}

/// Single-precision one-register lists, `S_SINGLE[n]`.
const S_SINGLE: [&str; 32] = fp_single_table!(
    "s",
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31
    ]
);

/// Double-precision one-register lists, `D_SINGLE[n]`.
const D_SINGLE: [&str; 32] = fp_single_table!(
    "d",
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31
    ]
);

/// `<Rn>!` — a base register that is written back, as `VLDM`/`VSTM` spell it
/// (A7.7.235). Named with [`Reg`]'s own spellings so that `sp!` and not `r13!`
/// comes out, since `sp` is the base in almost every real use.
const WRITEBACK: [&str; 16] = [
    "r0!", "r1!", "r2!", "r3!", "r4!", "r5!", "r6!", "r7!", "r8!", "r9!", "r10!", "r11!", "r12!",
    "sp!", "lr!", "pc!",
];

/// The `{n}` spellings of `LDC`/`STC`'s unindexed `<option>`: "an integer in
/// the range 0-255, surrounded by `{` and `}`" (A7.7.158), held in `imm8`.
macro_rules! braced {
    ($($n:literal),* $(,)?) => { [$(concat!("{", $n, "}")),*] };
}

/// `LDC`/`STC` unindexed option spellings, indexed by `imm8`.
const OPTIONS: [&str; 256] = braced![
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
    74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97,
    98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
    117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135,
    136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154,
    155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173,
    174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192,
    193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211,
    212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230,
    231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249,
    250, 251, 252, 253, 254, 255
];

// ---------------------------------------------------------------------------
// Generic coprocessor mnemonics (Table A5-30)
// ---------------------------------------------------------------------------

/// `STC`/`LDC` spellings, indexed `(L << 2) | (D << 1) | T`.
///
/// `L` is `hw1[4]`: store or load. `D` — `N` in A7.7.158's own diagram — is
/// `hw1[6]`, the `L` *suffix*, which has no architectural meaning and is
/// "free for use by the coprocessor instruction set designer". `T` is
/// `hw1[12]`, the `2` suffix. UAL orders the two suffixes `2` then `L`, so
/// `stc2l`, never `stcl2`.
const LDC_STC: [&str; 8] = [
    "stc", "stc2", "stcl", "stc2l", "ldc", "ldc2", "ldcl", "ldc2l",
];

/// `CDP`/`CDP2`, `MCR`/`MCR2`, `MRC`/`MRC2`, `MCRR`/`MCRR2`, `MRRC`/`MRRC2`,
/// indexed by `T` = `hw1[12]`.
const CDP: [&str; 2] = ["cdp", "cdp2"];
/// `MCR`/`MRC` spellings, indexed `(L << 1) | T` with `L` = `hw1[4]`.
const MCR_MRC: [&str; 4] = ["mcr", "mcr2", "mrc", "mrc2"];
/// `MCRR`/`MRRC` spellings, indexed `(L << 1) | T` with `L` = `hw1[4]`.
const MCRR_MRRC: [&str; 4] = ["mcrr", "mcrr2", "mrrc", "mrrc2"];

/// `FPSCR`'s `reg` encoding — the only special register the M profile defines,
/// and the only one for which `Rt == 0b1111` means `APSR_nzcv`.
const FPSCR_REG: u16 = 0b0001;

/// Whether `VMSR` can write the special register with this `reg` encoding.
///
/// `VMRS` can read five of them, but only `FPSID`, `FPSCR` and `FPEXC` are
/// listed as `VMSR` destinations (DDI 0406B B6.1.15); `reg` of `0b01xx` — the
/// media-feature registers, which are read-only — is UNPREDICTABLE there.
fn writable_sysreg(reg: u16) -> bool {
    matches!(reg, 0b0000 | FPSCR_REG | 0b1000)
}

/// The floating-point special registers `VMRS`/`VMSR` can name, indexed by
/// `hw1[3:0]` (ARM DDI 0406B B6.1.14; ARM DDI 0403E.e pins this field to
/// `0b0001`, `FPSCR`, and leaves the rest to the A/R profile). `None` is a
/// reserved encoding.
const FP_SYSREGS: [Option<&str>; 16] = [
    Some("fpsid"), // 0000
    Some("fpscr"), // 0001
    None,          // 0010
    None,          // 0011
    None,          // 0100
    Some("mvfr2"), // 0101
    Some("mvfr1"), // 0110
    Some("mvfr0"), // 0111
    Some("fpexc"), // 1000
    None,          // 1001
    None,          // 1010
    None,          // 1011
    None,          // 1100
    None,          // 1101
    None,          // 1110
    None,          // 1111
];

// ---------------------------------------------------------------------------
// Floating-point data-processing mnemonics (Table A6-5)
// ---------------------------------------------------------------------------

/// A row of the three-register floating-point data-processing space.
///
/// Table A6-5 indexes that space by `T`, `opc1` and `opc3`. `opc1[2]` is the
/// `D` register bit and carries no opcode, so only `opc1[3]` and `opc1[1:0]`
/// select; `opc3[0]` splits every row into two operations, and `opc3[1]` is
/// `N`. Searching this table *is* the decode: a `(T, opc1, opc3[0])` triple
/// that is not a row here — `VDIV` with `opc3[0] == 1`, say — is UNDEFINED.
struct Dp3 {
    /// The `.f32` and `.f64` spellings. `sz` (`hw2[8]`) chooses.
    names: (&'static str, &'static str),
    /// `hw1[12]`, the FPv5 half of the space.
    t: u16,
    /// `opc1[3]` = `hw1[7]`.
    hi: u16,
    /// `opc1[1:0]` = `hw1[5:4]`.
    lo: u16,
    /// `opc3[0]` = `hw2[6]`.
    op: u16,
    /// The architectural encoding name.
    enc: &'static str,
}

/// The three-register floating-point data-processing operations.
///
/// The `VNMLA`/`VNMLS`/`VNMUL` rows are the awkward ones: A7.7.250 gives
/// `VNMLA` as `op == 1` and `VNMLS` as `op == 0` — the *opposite* polarity to
/// `VMLA`/`VMLS` above them — and folds `VNMUL` into the `VMUL` row as its own
/// encoding T2.
const DP3: [Dp3; 15] = [
    // A7.7.238 — opc1 = 0x00.
    Dp3 {
        names: ("vmla.f32", "vmla.f64"),
        t: 0,
        hi: 0,
        lo: 0b00,
        op: 0,
        enc: "T1",
    },
    Dp3 {
        names: ("vmls.f32", "vmls.f64"),
        t: 0,
        hi: 0,
        lo: 0b00,
        op: 1,
        enc: "T1",
    },
    // A7.7.250 — opc1 = 0x01.
    Dp3 {
        names: ("vnmls.f32", "vnmls.f64"),
        t: 0,
        hi: 0,
        lo: 0b01,
        op: 0,
        enc: "T1",
    },
    Dp3 {
        names: ("vnmla.f32", "vnmla.f64"),
        t: 0,
        hi: 0,
        lo: 0b01,
        op: 1,
        enc: "T1",
    },
    // A7.7.248 / A7.7.250 T2 — opc1 = 0x10.
    Dp3 {
        names: ("vmul.f32", "vmul.f64"),
        t: 0,
        hi: 0,
        lo: 0b10,
        op: 0,
        enc: "T1",
    },
    Dp3 {
        names: ("vnmul.f32", "vnmul.f64"),
        t: 0,
        hi: 0,
        lo: 0b10,
        op: 1,
        enc: "T2",
    },
    // A7.7.225 / A7.7.260 — opc1 = 0x11.
    Dp3 {
        names: ("vadd.f32", "vadd.f64"),
        t: 0,
        hi: 0,
        lo: 0b11,
        op: 0,
        enc: "T1",
    },
    Dp3 {
        names: ("vsub.f32", "vsub.f64"),
        t: 0,
        hi: 0,
        lo: 0b11,
        op: 1,
        enc: "T1",
    },
    // A7.7.232 — opc1 = 1x00. `op == 1` is UNDEFINED, hence no second row.
    Dp3 {
        names: ("vdiv.f32", "vdiv.f64"),
        t: 0,
        hi: 1,
        lo: 0b00,
        op: 0,
        enc: "T1",
    },
    // A7.7.234 — opc1 = 1x01. `VFNMA` is op = 1, `VFNMS` op = 0.
    Dp3 {
        names: ("vfnms.f32", "vfnms.f64"),
        t: 0,
        hi: 1,
        lo: 0b01,
        op: 0,
        enc: "T1",
    },
    Dp3 {
        names: ("vfnma.f32", "vfnma.f64"),
        t: 0,
        hi: 1,
        lo: 0b01,
        op: 1,
        enc: "T1",
    },
    // A7.7.233 — opc1 = 1x10.
    Dp3 {
        names: ("vfma.f32", "vfma.f64"),
        t: 0,
        hi: 1,
        lo: 0b10,
        op: 0,
        enc: "T1",
    },
    Dp3 {
        names: ("vfms.f32", "vfms.f64"),
        t: 0,
        hi: 1,
        lo: 0b10,
        op: 1,
        enc: "T1",
    },
    // A7.7.237 — T = 1, opc1 = 1x00: the FPv5 max/min-number pair.
    Dp3 {
        names: ("vmaxnm.f32", "vmaxnm.f64"),
        t: 1,
        hi: 1,
        lo: 0b00,
        op: 0,
        enc: "T1",
    },
    Dp3 {
        names: ("vminnm.f32", "vminnm.f64"),
        t: 1,
        hi: 1,
        lo: 0b00,
        op: 1,
        enc: "T1",
    },
];

/// `VSEL` spellings, indexed by `cc` = `hw1[5:4]` (A7.7.256).
///
/// The instruction's condition is `cc:(cc<1> XOR cc<0>):'0'`, which maps
/// `00`→`EQ`, `01`→`VS`, `10`→`GE`, `11`→`GT` — the four conditions whose
/// inverses can be had by swapping the source operands, which is why these four
/// and no others are encodable.
const VSEL: [(&str, &str); 4] = [
    ("vseleq.f32", "vseleq.f64"),
    ("vselvs.f32", "vselvs.f64"),
    ("vselge.f32", "vselge.f64"),
    ("vselgt.f32", "vselgt.f64"),
];

/// A row of the two-register floating-point data-processing space: `opc1`
/// `1x11` with `opc3[0] == 1`, dispatched on `opc2` = `hw1[3:0]` and `opc3` =
/// `hw2[7:6]` (Table A6-5).
struct Dp2 {
    /// The `.f32` and `.f64` spellings.
    names: (&'static str, &'static str),
    /// `hw1[12]`.
    t: u16,
    /// `opc2` = `hw1[3:0]`.
    opc2: u16,
    /// `opc3` = `hw2[7:6]`, both bits: these rows use `opc3[1]` as opcode
    /// rather than as `N`.
    opc3: u16,
}

/// The two-register, same-precision floating-point operations.
///
/// Everything else in the `1x11` block converts between types and so has a
/// mnemonic that names both of them; those live in the `CVT_*` tables.
const DP2: [Dp2; 11] = [
    Dp2 {
        names: ("vmov.f32", "vmov.f64"),
        t: 0,
        opc2: 0b0000,
        opc3: 0b01,
    }, // A7.7.240
    Dp2 {
        names: ("vabs.f32", "vabs.f64"),
        t: 0,
        opc2: 0b0000,
        opc3: 0b11,
    }, // A7.7.224
    Dp2 {
        names: ("vneg.f32", "vneg.f64"),
        t: 0,
        opc2: 0b0001,
        opc3: 0b01,
    }, // A7.7.249
    Dp2 {
        names: ("vsqrt.f32", "vsqrt.f64"),
        t: 0,
        opc2: 0b0001,
        opc3: 0b11,
    }, // A7.7.257
    Dp2 {
        names: ("vrintr.f32", "vrintr.f64"),
        t: 0,
        opc2: 0b0110,
        opc3: 0b01,
    }, // A7.7.255
    Dp2 {
        names: ("vrintz.f32", "vrintz.f64"),
        t: 0,
        opc2: 0b0110,
        opc3: 0b11,
    }, // A7.7.255
    Dp2 {
        names: ("vrintx.f32", "vrintx.f64"),
        t: 0,
        opc2: 0b0111,
        opc3: 0b01,
    }, // A7.7.254
    // A7.7.253 — T = 1, opc2 = 10:RM. The FPv5 directed roundings.
    Dp2 {
        names: ("vrinta.f32", "vrinta.f64"),
        t: 1,
        opc2: 0b1000,
        opc3: 0b01,
    },
    Dp2 {
        names: ("vrintn.f32", "vrintn.f64"),
        t: 1,
        opc2: 0b1001,
        opc3: 0b01,
    },
    Dp2 {
        names: ("vrintp.f32", "vrintp.f64"),
        t: 1,
        opc2: 0b1010,
        opc3: 0b01,
    },
    Dp2 {
        names: ("vrintm.f32", "vrintm.f64"),
        t: 1,
        opc2: 0b1011,
        opc3: 0b01,
    },
];

/// `VCMP`/`VCMPE` spellings, indexed by `E` = `hw2[7]` (A7.7.226).
const VCMP: [(&str, &str); 2] = [("vcmp.f32", "vcmp.f64"), ("vcmpe.f32", "vcmpe.f64")];

/// `VCVTB`/`VCVTT` spellings, indexed `[T = hw2[7]][sz][op = hw1[0]]`
/// (A7.7.231). `op == 0` converts *from* half precision, `op == 1` to it; `sz`
/// says whether the non-half side is double.
const CVT_HALF: [[[&str; 2]; 2]; 2] = [
    [
        ["vcvtb.f32.f16", "vcvtb.f16.f32"],
        ["vcvtb.f64.f16", "vcvtb.f16.f64"],
    ],
    [
        ["vcvtt.f32.f16", "vcvtt.f16.f32"],
        ["vcvtt.f64.f16", "vcvtt.f16.f64"],
    ],
];

/// `VCVT` integer-to-floating-point spellings, indexed `[sz][op = hw2[7]]`
/// (A7.7.228, `opc2 == 0b000`). `op == 0` means the *source* is unsigned.
const CVT_FROM_INT: [[&str; 2]; 2] = [
    ["vcvt.f32.u32", "vcvt.f32.s32"],
    ["vcvt.f64.u32", "vcvt.f64.s32"],
];

/// `VCVT`/`VCVTR` floating-point-to-integer spellings, indexed
/// `[op = hw2[7]][opc2[0]][sz]` (A7.7.228, `opc2 == 0b10x`).
///
/// `op == 1` is Round towards Zero, spelled by *omitting* the `R`; `op == 0`
/// uses the FPSCR rounding mode and is spelled `VCVTR`. `opc2[0]` selects
/// signed. The destination is always a single-precision register — it holds a
/// 32-bit integer — so `sz` describes only the source.
const CVT_TO_INT: [[[&str; 2]; 2]; 2] = [
    [
        ["vcvtr.u32.f32", "vcvtr.u32.f64"],
        ["vcvtr.s32.f32", "vcvtr.s32.f64"],
    ],
    [
        ["vcvt.u32.f32", "vcvt.u32.f64"],
        ["vcvt.s32.f32", "vcvt.s32.f64"],
    ],
];

/// `VCVT` between double and single precision, indexed by `sz` (A7.7.230).
/// `sz == 1` means the *operand* is double, so the mnemonic reads `.f32.f64`.
const CVT_DP_SP: [&str; 2] = ["vcvt.f64.f32", "vcvt.f32.f64"];

/// `VCVT` between floating-point and fixed-point, indexed
/// `[to_fixed = hw1[2]][sf = hw2[8]][sx = hw2[7]][U = hw1[0]]` (A7.7.229).
///
/// `sx` selects a 16- or 32-bit fixed-point container and `U` its signedness,
/// giving the four `<Td>` values `S16`, `U16`, `S32`, `U32`; `sf` is the
/// floating-point precision, which is both the source and the destination since
/// these forms convert a register in place.
const CVT_FIXED: [[[[&str; 2]; 2]; 2]; 2] = [
    [
        [
            ["vcvt.f32.s16", "vcvt.f32.u16"],
            ["vcvt.f32.s32", "vcvt.f32.u32"],
        ],
        [
            ["vcvt.f64.s16", "vcvt.f64.u16"],
            ["vcvt.f64.s32", "vcvt.f64.u32"],
        ],
    ],
    [
        [
            ["vcvt.s16.f32", "vcvt.u16.f32"],
            ["vcvt.s32.f32", "vcvt.u32.f32"],
        ],
        [
            ["vcvt.s16.f64", "vcvt.u16.f64"],
            ["vcvt.s32.f64", "vcvt.u32.f64"],
        ],
    ],
];

/// `VCVT{A,N,P,M}` spellings, indexed `[RM = hw1[1:0]][op = hw2[7]][sz]`
/// (A7.7.227). `RM` is the rounding mode — `00` away, `01` even, `10` `+inf`,
/// `11` `-inf` — and `op == 1` selects a signed result.
const CVT_RM: [[[&str; 2]; 2]; 4] = [
    [
        ["vcvta.u32.f32", "vcvta.u32.f64"],
        ["vcvta.s32.f32", "vcvta.s32.f64"],
    ],
    [
        ["vcvtn.u32.f32", "vcvtn.u32.f64"],
        ["vcvtn.s32.f32", "vcvtn.s32.f64"],
    ],
    [
        ["vcvtp.u32.f32", "vcvtp.u32.f64"],
        ["vcvtp.s32.f32", "vcvtp.s32.f64"],
    ],
    [
        ["vcvtm.u32.f32", "vcvtm.u32.f64"],
        ["vcvtm.s32.f32", "vcvtm.s32.f64"],
    ],
];

/// The extension-register transfer mnemonics of A6.5, indexed
/// `[L = hw1[4]][DB]`. `VPUSH`/`VPOP` and `VLDR`/`VSTR` are spelled out where
/// they are decoded.
const VLDM_VSTM: [[&str; 2]; 2] = [["vstmia", "vstmdb"], ["vldmia", "vldmdb"]];

// ---------------------------------------------------------------------------
// VFPExpandImm
// ---------------------------------------------------------------------------

/// `VFPExpandImm(imm8, N)` (A6.4.1), for `N` of 32 or 64 as `dbl` selects.
///
/// Transcribed from the pseudocode rather than reasoned about:
/// `sign = imm8<7>`, `exp = NOT(imm8<6>):Replicate(imm8<6>,E-3):imm8<5:4>`,
/// `frac = imm8<3:0>:Zeros(F-4)`. The result is assembled as a bit pattern and
/// read back as a float, so the only arithmetic here is the manual's.
///
/// The 256 values this can produce are exactly the floats
/// `±2^n × (16+m)/16` for `n` in `-3..=4` and `m` in `0..=15`. It cannot
/// produce zero, an infinity or a NaN: `exp` is `1:0…0:xx` or `0:1…1:xx` and so
/// is never all-zeros or all-ones.
///
/// Single precision widens to `f64` exactly — every `f32` does — so
/// [`Operand::FpImm`] holds the same real number either way, and only the
/// *encoding* differs between the precisions.
fn vfp_expand_imm(imm8: u16, dbl: bool) -> f64 {
    let imm8 = imm8 & 0xFF;
    let sign = (imm8 >> 7) & 1;
    let b6 = (imm8 >> 6) & 1;
    let low = (imm8 >> 4) & 0b11;
    let frac = imm8 & 0xF;
    if dbl {
        // E = 11, F = 52: eight replicated bits between the inverted bit and
        // `imm8<5:4>`.
        let exp =
            (u64::from(b6 ^ 1) << 10) | (if b6 == 1 { 0xFF << 2 } else { 0 }) | u64::from(low);
        f64::from_bits((u64::from(sign) << 63) | (exp << 52) | (u64::from(frac) << 48))
    } else {
        // E = 8, F = 23: five replicated bits.
        let exp = (u32::from(b6 ^ 1) << 7) | (if b6 == 1 { 0x1F << 2 } else { 0 }) | u32::from(low);
        f64::from(f32::from_bits(
            (u32::from(sign) << 31) | (exp << 23) | (u32::from(frac) << 19),
        ))
    }
}

/// The inverse of [`vfp_expand_imm`]: the `imm8` that expands to exactly
/// `value`, or `None` if no such `imm8` exists.
///
/// A search, because the mapping is onto only 256 of the 2^64 floats and there
/// is no useful nearest-representable answer: an assembler that silently
/// encoded `#0.3` as `#0.3125` would be worse than one that refused. Exact bit
/// comparison, so `-0.0` cannot slip through as `0.0` (neither is
/// representable) and a signed zero can never be produced.
fn vfp_compress_imm(value: f64, dbl: bool) -> Option<u16> {
    (0..256u16).find(|&imm8| vfp_expand_imm(imm8, dbl).to_bits() == value.to_bits())
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Decode an instruction in this group, or `None` if `hw1`/`hw2` do not belong
/// to it.
///
/// The three-way split at the top is Table A5-30's, read through
/// ARM DDI 0406B Table A6-29, which is the same table with the floating-point
/// rows spelled out: `op1 == 0b0xxxxx` (but not `0b000x0x`) is the load/store
/// row, `0b00010x` the two-core-register row, and `0b10xxxx` the
/// data-processing and single-core-register rows, split by `op` = `hw2[4]`.
/// `0b11xxxx` is Advanced SIMD and `0b00000x` is UNDEFINED.
pub(crate) fn decode(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 & 0xEC00 != 0xEC00 {
        return None;
    }
    let op1 = bits(hw1, 9, 4);
    let coproc = bits(hw2, 11, 8);
    // `coproc == 0b101x`: the floating-point instruction set, with `coproc[0]`
    // doubling as the precision bit (A6.1).
    let fp = coproc & 0b1110 == 0b1010;
    let op = bit(hw2, 4);

    if op1 & 0b11_0000 == 0b11_0000 || op1 & 0b11_1110 == 0 {
        return None;
    }
    match op1 {
        0b00_0100 | 0b00_0101 => {
            if fp {
                fp_two_core(hw1, hw2, addr)
            } else {
                mcrr(hw1, hw2, addr)
            }
        }
        o if o & 0b10_0000 == 0 => {
            if fp {
                fp_load_store(hw1, hw2, addr)
            } else {
                ldc_stc(hw1, hw2, addr)
            }
        }
        _ if op == 0 => {
            if fp {
                fp_data_processing(hw1, hw2, addr)
            } else {
                cdp(hw1, hw2, addr)
            }
        }
        _ => {
            if fp {
                fp_transfer(hw1, hw2, addr)
            } else {
                mcr(hw1, hw2, addr)
            }
        }
    }
}

/// The `T2` encodings — `CDP2`, `MCR2`, `LDC2` and the rest — are the ones with
/// `hw1[12]` set; everything else is `T1`.
fn enc_of(hw1: u16) -> &'static str {
    if bit(hw1, 12) == 1 {
        "T2"
    } else {
        "T1"
    }
}

/// `LDC`, `LDC2`, `STC`, `STC2` — A7.7.39, A7.7.40, A7.7.158.
///
/// `111T 110 P U D W L Rn | CRd coproc imm8`, with `imm8` scaled by four for
/// the three indexed forms and left raw for the unindexed one, where it is an
/// opaque `<option>` for the coprocessor rather than an offset.
fn ldc_stc(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let (p, u, d, w, l) = (
        bit(hw1, 8),
        bit(hw1, 7),
        bit(hw1, 6),
        bit(hw1, 5),
        bit(hw1, 4),
    );
    let rn = Reg(bits(hw1, 3, 0) as u8);
    let imm8 = u32::from(hw2 & 0xFF);
    let head = [
        Operand::Coproc(bits(hw2, 11, 8) as u8),
        Operand::CoprocReg(bits(hw2, 15, 12) as u8),
    ];
    let mnemonic = LDC_STC[((l << 2) | (d << 1) | bit(hw1, 12)) as usize];
    let mode = match (p, w) {
        (1, 0) => AddrMode::Offset,
        (1, 1) => AddrMode::PreIndex,
        (0, 1) => AddrMode::PostIndex,
        // Unindexed: `[<Rn>], <option>`. `index = FALSE, wback = FALSE`
        // (A7.7.39), so the address is a bare `R[n]` and the `<option>` that
        // follows is what distinguishes it from the plain offset form.
        // `P == 0 && W == 0 && U == 0` never reaches here — it is UNDEFINED or
        // `MCRR`/`MRRC`, both excluded by `decode`'s `op1` split.
        _ => {
            let mem = Mem {
                base: rn,
                index: None,
                offset: 0,
                add: true,
                align: 0,
                mode: AddrMode::Offset,
            };
            let option = Operand::Option(OPTIONS[imm8 as usize]);
            let operands = ops(&[head[0], head[1], Operand::Mem(mem), option]);
            return Some(wide(mnemonic, enc_of(hw1), addr, operands));
        }
    };
    // `#0` and `#-0` are different instructions (A7.7.39); `U` is carried as
    // `Mem::add` rather than folded into a sign, so both decode and each
    // re-encodes to its own halfwords.
    let mem = Mem {
        base: rn,
        index: None,
        offset: imm8 * 4,
        add: u == 1,
        align: 0,
        mode,
    };
    let mut operands = ops(&[head[0], head[1], Operand::Mem(mem)]);
    // `LDC (literal)`, A7.7.40: `Rn == 15` with `P == 1, W == 0` addresses a
    // literal relative to `Align(PC,4)`, so the resolved address is carried
    // too — exactly as the 16-bit literal loads do. `STC` has no literal form
    // (`n == 15` there is UNPREDICTABLE), so it gets no target.
    if l == 1 && rn.num() == 15 && mode == AddrMode::Offset {
        operands.push(Operand::Target(
            literal_base(addr).wrapping_add(mem.displacement() as u32),
        ));
    }
    Some(wide(mnemonic, enc_of(hw1), addr, operands))
}

/// `CDP`, `CDP2` — A7.7.22. `111T 1110 opc1 CRn | CRd coproc opc2 0 CRm`.
///
/// Every operand is opaque: only `bits[31:24]`, `bits[11:8]` and `bit[4]` of this
/// encoding are architecturally defined, so `opc1`, `opc2` and the three
/// coprocessor register numbers are passed through exactly as encoded.
fn cdp(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let operands = ops(&[
        Operand::Coproc(bits(hw2, 11, 8) as u8),
        Operand::Imm(i64::from(bits(hw1, 7, 4))),
        Operand::CoprocReg(bits(hw2, 15, 12) as u8),
        Operand::CoprocReg(bits(hw1, 3, 0) as u8),
        Operand::CoprocReg(bits(hw2, 3, 0) as u8),
        Operand::Imm(i64::from(bits(hw2, 7, 5))),
    ]);
    Some(wide(
        CDP[bit(hw1, 12) as usize],
        enc_of(hw1),
        addr,
        operands,
    ))
}

/// `MCR`, `MCR2`, `MRC`, `MRC2` — A7.7.72, A7.7.80.
/// `111T 1110 opc1 L CRn | Rt coproc opc2 1 CRm`.
///
/// `MRC` with `Rt == 0b1111` writes the condition flags rather than a register,
/// and UAL spells that destination `APSR_nzcv` (A7.7.80). `MCR` has no such
/// form — `t == 15` is UNPREDICTABLE there — so it keeps the register.
fn mcr(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let l = bit(hw1, 4);
    let rt = bits(hw2, 15, 12) as u8;
    let dest = if l == 1 && rt == 15 {
        Operand::SpecialReg("apsr_nzcv")
    } else {
        Operand::Reg(Reg(rt))
    };
    let operands = ops(&[
        Operand::Coproc(bits(hw2, 11, 8) as u8),
        Operand::Imm(i64::from(bits(hw1, 7, 5))),
        dest,
        Operand::CoprocReg(bits(hw1, 3, 0) as u8),
        Operand::CoprocReg(bits(hw2, 3, 0) as u8),
        Operand::Imm(i64::from(bits(hw2, 7, 5))),
    ]);
    let mnemonic = MCR_MRC[((l << 1) | bit(hw1, 12)) as usize];
    Some(wide(mnemonic, enc_of(hw1), addr, operands))
}

/// `MCRR`, `MCRR2`, `MRRC`, `MRRC2` — A7.7.73, A7.7.81.
/// `111T 1100 010 L Rt2 | Rt coproc opc1 CRm`.
fn mcrr(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let operands = ops(&[
        Operand::Coproc(bits(hw2, 11, 8) as u8),
        Operand::Imm(i64::from(bits(hw2, 7, 4))),
        Operand::Reg(Reg(bits(hw2, 15, 12) as u8)),
        Operand::Reg(Reg(bits(hw1, 3, 0) as u8)),
        Operand::CoprocReg(bits(hw2, 3, 0) as u8),
    ]);
    let mnemonic = MCRR_MRRC[((bit(hw1, 4) << 1) | bit(hw1, 12)) as usize];
    Some(wide(mnemonic, enc_of(hw1), addr, operands))
}

/// The `<list>` operand of A6.5's multiple-register transfers.
///
/// The architecture encodes a *first register and a count*, never a bitmask:
/// `<list>` "is encoded in the instruction by setting D and Vd to specify the
/// first register in the list, and `<imm8>` to the number of registers"
/// (A7.7.235). A count of zero, a list running off the end of the register
/// bank, or — for double precision — a list longer than sixteen registers, is
/// UNPREDICTABLE and decodes to `None` rather than to a list that cannot
/// re-encode.
fn fp_list(first: u16, regs: u16, dbl: bool) -> Option<Operand> {
    if regs == 0 || first + regs > 32 || (dbl && regs > 16) {
        return None;
    }
    if regs == 1 {
        let single = if dbl { D_SINGLE } else { S_SINGLE };
        return Some(Operand::Text(single[first as usize]));
    }
    let table = if dbl { &D_RANGES } else { &S_RANGES };
    Some(Operand::Text(
        table[first as usize][(first + regs - 1) as usize],
    ))
}

/// Extension register load and store — A6.5, Table A6-7: `VLDR`, `VSTR`,
/// `VLDM`, `VSTM`, `VPUSH`, `VPOP`.
///
/// `1110 110 P U D W L Rn | Vd 101 sz imm8`. `T == 1` is UNDEFINED here, which
/// is what keeps `1111 110…` — the Advanced SIMD side of the same row — out.
fn fp_load_store(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if bit(hw1, 12) == 1 {
        return None;
    }
    let (p, u, d, w, l) = (
        bit(hw1, 8),
        bit(hw1, 7),
        bit(hw1, 6),
        bit(hw1, 5),
        bit(hw1, 4),
    );
    let rn = Reg(bits(hw1, 3, 0) as u8);
    let vd = bits(hw2, 15, 12);
    let dbl = bit(hw2, 8) == 1;
    let imm8 = hw2 & 0xFF;
    // T1 is the doubleword list, T2 the singleword one, for every encoding in
    // this row (A7.7.235, A7.7.236, A7.7.251, A7.7.252, A7.7.258, A7.7.259).
    let enc = if dbl { "T1" } else { "T2" };

    if p == 1 && w == 0 {
        // `VLDR`/`VSTR`: one register, an immediate offset, no writeback.
        // `#-0` is a distinct encoding — A7.7.236's `VLDR <Dd>, [PC, #-0]`
        // special case — and `Mem::add` holds the `U` bit that says so.
        let mem = Mem {
            base: rn,
            index: None,
            offset: u32::from(imm8) * 4,
            add: u == 1,
            align: 0,
            mode: AddrMode::Offset,
        };
        let mut operands = ops(&[Operand::FpReg(freg(vd, d, dbl)), Operand::Mem(mem)]);
        if l == 1 && rn.num() == 15 {
            operands.push(Operand::Target(
                literal_base(addr).wrapping_add(mem.displacement() as u32),
            ));
        }
        let mnemonic = if l == 1 { "vldr" } else { "vstr" };
        return Some(wide(mnemonic, enc, addr, operands));
    }

    // A doubleword list encodes twice the register count, so an odd `imm8` is
    // the obsolete pre-UAL `FLDMX`/`FSTMX` (A7.7.235: "if imm8<0> == '1' then
    // SEE FLDMX"), which this crate does not decode.
    if dbl && imm8 % 2 != 0 {
        return None;
    }
    let regs = if dbl { imm8 / 2 } else { imm8 };
    let first = if dbl { (d << 4) | vd } else { (vd << 1) | d };
    let list = fp_list(first, regs, dbl)?;
    let base = |wb: bool| {
        if wb {
            Operand::Text(WRITEBACK[rn.num() as usize])
        } else {
            Operand::Reg(rn)
        }
    };
    match (p, u, w) {
        // Increment After. `P == 0, U == 1`.
        (0, 1, _) => {
            if w == 1 && l == 1 && rn.num() == 13 {
                // Table A6-7: `01x11` with `Rn == 1101` is `VPOP`, not a
                // `VLDMIA sp!` — one instruction, one spelling.
                return Some(wide("vpop", enc, addr, ops(&[list])));
            }
            let mnemonic = VLDM_VSTM[l as usize][0];
            Some(wide(mnemonic, enc, addr, ops(&[base(w == 1), list])))
        }
        // Decrement Before, which the architecture only defines with writeback.
        (1, 0, 1) => {
            if l == 0 && rn.num() == 13 {
                return Some(wide("vpush", enc, addr, ops(&[list])));
            }
            let mnemonic = VLDM_VSTM[l as usize][1];
            Some(wide(mnemonic, enc, addr, ops(&[base(true), list])))
        }
        // `P == U && W == 1` is UNDEFINED (A7.7.235); `P == 0, U == 0, W == 0`
        // was split off as `MCRR`/`MRRC` before this function was reached.
        _ => None,
    }
}

/// The register and opcode fields of a floating-point data-processing
/// encoding, named as A6.3 and A6.4 name them.
#[derive(Clone, Copy)]
struct Fp {
    /// `hw1[12]` — the FPv5 half of the space.
    t: u16,
    /// `opc1[3]` = `hw1[7]`.
    hi: u16,
    /// `D` = `hw1[6]`.
    d: u16,
    /// `opc1[1:0]` = `hw1[5:4]`, also `VSEL`'s `cc`.
    lo: u16,
    /// `hw1[3:0]` — `Vn` in the three-register rows, `opc2` in the rest.
    vn: u16,
    /// `Vd` = `hw2[15:12]`.
    vd: u16,
    /// `sz` = `hw2[8]`: double precision.
    dbl: bool,
    /// `opc3` = `hw2[7:6]`; `opc3[1]` is `N` in the three-register rows.
    opc3: u16,
    /// `N` = `hw2[7]`, which several two-register rows use as an opcode bit.
    n: u16,
    /// `M` = `hw2[5]`.
    m: u16,
    /// `Vm` = `hw2[3:0]`.
    vm: u16,
}

impl Fp {
    /// Split a halfword pair into its fields.
    fn new(hw1: u16, hw2: u16) -> Fp {
        Fp {
            t: bit(hw1, 12),
            hi: bit(hw1, 7),
            d: bit(hw1, 6),
            lo: bits(hw1, 5, 4),
            vn: bits(hw1, 3, 0),
            vd: bits(hw2, 15, 12),
            dbl: bit(hw2, 8) == 1,
            opc3: bits(hw2, 7, 6),
            n: bit(hw2, 7),
            m: bit(hw2, 5),
            vm: bits(hw2, 3, 0),
        }
    }

    /// `opc2` — the same four bits as `Vn`, which is why the two-register rows
    /// all have `Vn` unused.
    fn opc2(self) -> u16 {
        self.vn
    }

    /// `<Sd>` or `<Dd>`, per the caller's precision (not necessarily the
    /// instruction's `sz`: the conversions have operands of two precisions).
    fn rd(self, dbl: bool) -> Operand {
        Operand::FpReg(freg(self.vd, self.d, dbl))
    }

    /// `<Sn>` or `<Dn>`.
    fn rn(self, dbl: bool) -> Operand {
        Operand::FpReg(freg(self.vn, self.n, dbl))
    }

    /// `<Sm>` or `<Dm>`.
    fn rm(self, dbl: bool) -> Operand {
        Operand::FpReg(freg(self.vm, self.m, dbl))
    }
}

/// The single- or double-precision spelling of a mnemonic pair.
fn pick(names: (&'static str, &'static str), dbl: bool) -> &'static str {
    if dbl {
        names.1
    } else {
        names.0
    }
}

/// Floating-point data-processing — A6.4 and Table A6-5.
///
/// `111T 1110 opc1 opc2 | Vd 101 sz opc3 0 opc4`. These are `CDP` instructions
/// for coprocessors 10 and 11, which is why `hw2[4]` — `CDP`'s fixed zero — has
/// already been checked by [`decode`].
fn fp_data_processing(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let f = Fp::new(hw1, hw2);
    let dbl = f.dbl;

    // `VSEL` (A7.7.256): `T == 1` with `opc1[3] == 0`, the condition in
    // `opc1[1:0]`. `hw2[6]` is a fixed 0.
    if f.t == 1 && f.hi == 0 {
        if f.opc3 & 1 != 0 {
            return None;
        }
        let operands = ops(&[f.rd(dbl), f.rn(dbl), f.rm(dbl)]);
        return Some(wide(pick(VSEL[f.lo as usize], dbl), "T1", addr, operands));
    }

    // Everything but `opc1 == 1x11` is a three-register operation, and the
    // table is the decode: a combination absent from it is UNDEFINED.
    if !(f.hi == 1 && f.lo == 0b11) {
        for row in DP3.iter() {
            if row.t == f.t && row.hi == f.hi && row.lo == f.lo && row.op == f.opc3 & 1 {
                let operands = ops(&[f.rd(dbl), f.rn(dbl), f.rm(dbl)]);
                return Some(wide(pick(row.names, dbl), row.enc, addr, operands));
            }
        }
        return None;
    }

    if f.t == 1 {
        return fpv5_round_or_convert(f, addr);
    }

    // `VMOV (immediate)`, A7.7.239: `opc3 == x0`, with `hw2[7]` and `hw2[5]`
    // both `(0)`.
    if f.opc3 & 1 == 0 {
        if f.opc3 != 0 || f.m != 0 {
            return None;
        }
        let value = vfp_expand_imm((f.opc2() << 4) | f.vm, dbl);
        let operands = ops(&[f.rd(dbl), Operand::FpImm(value)]);
        return Some(wide(
            pick(("vmov.f32", "vmov.f64"), dbl),
            "T1",
            addr,
            operands,
        ));
    }

    // The two-register operations that keep their operand's type.
    for row in DP2.iter() {
        if row.t == 0 && row.opc2 == f.opc2() && row.opc3 == f.opc3 {
            let operands = ops(&[f.rd(dbl), f.rm(dbl)]);
            return Some(wide(pick(row.names, dbl), "T1", addr, operands));
        }
    }
    fp_convert(f, addr)
}

/// The FPv5 `T == 1`, `opc1 == 1x11` block: `VRINT{A,N,P,M}` (A7.7.253) at
/// `opc2 == 10:RM` and `VCVT{A,N,P,M}` (A7.7.227) at `opc2 == 11:RM`.
fn fpv5_round_or_convert(f: Fp, addr: u32) -> Option<Insn> {
    let rm = (f.opc2() & 0b11) as usize;
    match f.opc2() >> 2 {
        0b10 => {
            for row in DP2.iter() {
                if row.t == 1 && row.opc2 == f.opc2() && row.opc3 == f.opc3 {
                    let operands = ops(&[f.rd(f.dbl), f.rm(f.dbl)]);
                    return Some(wide(pick(row.names, f.dbl), "T1", addr, operands));
                }
            }
            None
        }
        0b11 if f.opc3 & 1 == 1 => {
            // The result is a 32-bit integer in a single-precision register,
            // whatever the operand's precision.
            let name = CVT_RM[rm][f.n as usize][f.dbl as usize];
            let operands = ops(&[f.rd(false), f.rm(f.dbl)]);
            Some(wide(name, "T1", addr, operands))
        }
        _ => None,
    }
}

/// The conversions in `opc1 == 1x11`, `opc3 == x1` — A7.7.228 through A7.7.231.
///
/// Each of these names two types, and several of them have operands of two
/// different precisions, which is the reason `Fp::rd`/`Fp::rm` take the
/// precision as an argument instead of reading `sz`.
fn fp_convert(f: Fp, addr: u32) -> Option<Insn> {
    let dbl = f.dbl;
    match f.opc2() {
        // `VCVTB`/`VCVTT` (A7.7.231): half precision in the bottom or top of a
        // register, `op` = `hw1[0]` choosing the direction.
        0b0010 | 0b0011 => {
            let op = f.opc2() & 1;
            let name = CVT_HALF[f.n as usize][dbl as usize][op as usize];
            // Only the non-half side can be double, and only in the direction
            // that is not converting *to* half.
            let operands = ops(&[f.rd(dbl && op == 0), f.rm(dbl && op == 1)]);
            Some(wide(name, "T1", addr, operands))
        }
        // `VCMP`/`VCMPE` (A7.7.226). `opc2[0]` selects the compare-with-zero
        // encoding T2, whose `Vm`, `M` and `hw2[4]` fields are all `(0)`.
        0b0100 | 0b0101 => {
            let name = pick(VCMP[f.n as usize], dbl);
            if f.opc2() & 1 == 1 {
                if f.vm != 0 || f.m != 0 {
                    return None;
                }
                let operands = ops(&[f.rd(dbl), Operand::Text("#0.0")]);
                Some(wide(name, "T2", addr, operands))
            } else {
                let operands = ops(&[f.rd(dbl), f.rm(dbl)]);
                Some(wide(name, "T1", addr, operands))
            }
        }
        // `VCVT` between double and single precision (A7.7.230), at
        // `opc2 == 0111` with `opc3 == 11`; `opc3 == 01` was `VRINTX`.
        0b0111 => {
            let operands = ops(&[f.rd(!dbl), f.rm(dbl)]);
            Some(wide(CVT_DP_SP[dbl as usize], "T1", addr, operands))
        }
        // `VCVT` from a 32-bit integer held in a single-precision register
        // (A7.7.228, `opc2 == 000`).
        0b1000 => {
            let name = CVT_FROM_INT[dbl as usize][f.n as usize];
            let operands = ops(&[f.rd(dbl), f.rm(false)]);
            Some(wide(name, "T1", addr, operands))
        }
        // `VCVT`/`VCVTR` to a 32-bit integer (A7.7.228, `opc2 == 10x`).
        0b1100 | 0b1101 => {
            let name = CVT_TO_INT[f.n as usize][(f.opc2() & 1) as usize][dbl as usize];
            let operands = ops(&[f.rd(false), f.rm(dbl)]);
            Some(wide(name, "T1", addr, operands))
        }
        // `VCVT` between floating-point and fixed-point (A7.7.229), `opc2` of
        // `1x1x`: `hw1[2]` is `op`, `hw1[0]` is `U`, `hw2[7]` is `sx` and the
        // fraction width is `size - UInt(imm4:i)`.
        0b1010 | 0b1011 | 0b1110 | 0b1111 => {
            let to_fixed = (f.opc2() >> 2) & 1;
            let u = f.opc2() & 1;
            let sx = f.n;
            let size = if sx == 1 { 32 } else { 16 };
            let frac = size - i64::from((f.vm << 1) | f.m);
            if frac < 0 {
                return None;
            }
            let name = CVT_FIXED[to_fixed as usize][dbl as usize][sx as usize][u as usize];
            let operands = ops(&[f.rd(dbl), f.rd(dbl), Operand::Imm(frac)]);
            Some(wide(name, "T1", addr, operands))
        }
        _ => None,
    }
}

/// 32-bit transfers between a core register and the extension registers —
/// A6.6 and Table A6-8: `VMOV` (core ↔ single), `VMOV` (core ↔ scalar),
/// `VMRS`, `VMSR`.
///
/// `1110 1110 A L Vn | Rt 101 C B 1 (0)(0)(0)(0)`. These are `MCR`/`MRC`
/// instructions for coprocessors 10 and 11, so `hw2[4]` is already known to be
/// 1. `T == 1` is UNDEFINED (A6.6).
fn fp_transfer(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if bit(hw1, 12) == 1 || bits(hw2, 3, 0) != 0 {
        return None;
    }
    let a = bits(hw1, 7, 5);
    let l = bit(hw1, 4);
    let vn = bits(hw1, 3, 0);
    let rt = Reg(bits(hw2, 15, 12) as u8);
    let c = bit(hw2, 8);
    let b = bits(hw2, 6, 5);
    let n = bit(hw2, 7);
    match (c, a) {
        // `VMOV` between a core register and a single-precision register
        // (A7.7.243). `hw2[6:5]` are `(0)`.
        (0, 0b000) if b == 0 => {
            let s = Operand::FpReg(sreg(vn, n));
            let r = Operand::Reg(rt);
            let operands = if l == 1 { ops(&[r, s]) } else { ops(&[s, r]) };
            Some(wide("vmov", "T1", addr, operands))
        }
        // `VMRS` (A7.7.246) and `VMSR` (A7.7.247). `hw2[7:5]` are `(0)`.
        (0, 0b111) if n == 0 && b == 0 => {
            let spec = Operand::SpecialReg(FP_SYSREGS[vn as usize]?);
            if l == 1 {
                // `Rt == 0b1111` names the APSR flags, which is the idiom that
                // follows every `VCMP`: the FPSCR's N, Z, C and V move to the
                // APSR's so that an integer conditional branch can test them.
                // It means nothing for the other special registers, where
                // DDI 0406B B6.1.14 makes it UNPREDICTABLE.
                if rt.num() == 15 && vn != FPSCR_REG {
                    return None;
                }
                let dest = if rt.num() == 15 {
                    Operand::SpecialReg("apsr_nzcv")
                } else {
                    Operand::Reg(rt)
                };
                Some(wide("vmrs", "T1", addr, ops(&[dest, spec])))
            } else {
                if !writable_sysreg(vn) {
                    return None;
                }
                Some(wide("vmsr", "T1", addr, ops(&[spec, Operand::Reg(rt)])))
            }
        }
        // `VMOV` between a core register and a 32-bit scalar (A7.7.241,
        // A7.7.242): `opc1[1] == 0` and `opc2 == 0b00` are what make the
        // element size 32 — the 8-bit and 16-bit element sizes, and `VDUP`
        // (`A == 0b1xx`), are Advanced SIMD and belong to `t32_simd`.
        (1, _) if a & 0b110 == 0 && b == 0 => {
            let scalar = Operand::FpScalar(dreg(vn, n), a as u8 & 1);
            let r = Operand::Reg(rt);
            let operands = if l == 1 {
                ops(&[r, scalar])
            } else {
                ops(&[scalar, r])
            };
            Some(wide("vmov.32", "T1", addr, operands))
        }
        _ => None,
    }
}

/// 64-bit transfers between two core registers and the extension registers —
/// A6.7 and Table A6-9: the two `VMOV` forms of A7.7.244 and A7.7.245.
///
/// `1110 1100 010 L Rt2 | Rt 101 C 00 M 1 Vm`. These are `MCRR`/`MRRC`
/// instructions for coprocessors 10 and 11; `T == 1` is UNDEFINED, and
/// `hw2[7:6]` and `hw2[4]` are fixed by Table A6-9's `op == 0b00x1`.
fn fp_two_core(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if bit(hw1, 12) == 1 || bits(hw2, 7, 6) != 0 || bit(hw2, 4) != 1 {
        return None;
    }
    let l = bit(hw1, 4);
    let rt2 = Operand::Reg(Reg(bits(hw1, 3, 0) as u8));
    let rt = Operand::Reg(Reg(bits(hw2, 15, 12) as u8));
    let vm = bits(hw2, 3, 0);
    let m = bit(hw2, 5);
    if bit(hw2, 8) == 1 {
        // One doubleword register (A7.7.245).
        let d = Operand::FpReg(dreg(vm, m));
        let operands = if l == 1 {
            ops(&[rt, rt2, d])
        } else {
            ops(&[d, rt, rt2])
        };
        Some(wide("vmov", "T1", addr, operands))
    } else {
        // Two consecutive single-precision registers (A7.7.244). `m == 31`
        // would name `s32`, and is UNPREDICTABLE.
        let first = (vm << 1) | m;
        if first == 31 {
            return None;
        }
        let s0 = Operand::FpReg(sreg(vm, m));
        let s1 = Operand::FpReg(FpReg::S(first as u8 + 1));
        let operands = if l == 1 {
            ops(&[rt, rt2, s0, s1])
        } else {
            ops(&[s0, s1, rt, rt2])
        };
        Some(wide("vmov", "T1", addr, operands))
    }
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

// Each accessor below matches on `Operands::get`'s `Option` rather than on a
// `?`-unwrapped operand, so that "there is no operand `i`" and "the operand at
// `i` is the wrong kind" are one refusal in one place. They are the same
// answer to the caller — this encoding cannot hold that — and splitting them
// leaves a branch that several of the callers, which check the operand count
// first, can never take.
//
// The `r.num() < 16` guard in `op_reg` below, and the three hand-written
// copies of it in `encode_mcr`, `parse_base` and `encode_vmrs_vmsr`, are
// restatements of an invariant rather than tests: `Reg::num` is
// `self.0 & 0xF` (`isa::insn`), so the predicate is total. They are written
// out because they keep the four-bit width of `Rt`/`Rn` next to the place the
// field is built, but no `Reg` can make one of them false. Weakening or
// deleting any of them — `< 16` to `<= 16`, or the whole guard to `true` —
// yields an identical program, so no test can pin them and none should be
// written.

/// The operand at `i`, if it is a core register.
fn op_reg(insn: &Insn, i: usize) -> Option<Reg> {
    match insn.operands.get(i) {
        Some(Operand::Reg(r)) if r.num() < 16 => Some(r),
        _ => None,
    }
}

/// The operand at `i`, if it is an extension register.
fn op_fp(insn: &Insn, i: usize) -> Option<FpReg> {
    match insn.operands.get(i) {
        Some(Operand::FpReg(r)) => Some(r),
        _ => None,
    }
}

/// The operand at `i`, if it is a non-negative immediate no larger than `max`.
fn op_imm(insn: &Insn, i: usize, max: i64) -> Option<u16> {
    match insn.operands.get(i) {
        Some(Operand::Imm(v)) if v >= 0 && v <= max => Some(v as u16),
        _ => None,
    }
}

/// The operand at `i`, if it is a coprocessor number.
fn op_coproc(insn: &Insn, i: usize) -> Option<u16> {
    match insn.operands.get(i) {
        Some(Operand::Coproc(n)) if n < 16 => Some(u16::from(n)),
        _ => None,
    }
}

/// The operand at `i`, if it is a coprocessor register.
fn op_creg(insn: &Insn, i: usize) -> Option<u16> {
    match insn.operands.get(i) {
        Some(Operand::CoprocReg(n)) if n < 16 => Some(u16::from(n)),
        _ => None,
    }
}

/// The operand at `i`, if it is a memory operand with no register index.
fn op_mem(insn: &Insn, i: usize) -> Option<Mem> {
    match insn.operands.get(i) {
        Some(Operand::Mem(m)) if m.index.is_none() && m.base.num() < 16 => Some(m),
        _ => None,
    }
}

/// Split an extension register into its `(4-bit, 1-bit)` halves and its
/// precision, for an encoding that has not already fixed which precision it is
/// naming.
fn split_any(r: FpReg) -> Option<(u16, u16, bool)> {
    match r {
        FpReg::S(n) if n < 32 => Some((u16::from(n >> 1), u16::from(n & 1), false)),
        FpReg::D(n) if n < 32 => Some((u16::from(n & 0xF), u16::from(n >> 4), true)),
        _ => None,
    }
}

/// Which of a table row's two spellings `mnemonic` is — `Some(true)` for the
/// double-precision one — or `None` if it is neither.
fn matches_pair(names: (&'static str, &'static str), mnemonic: &str) -> Option<bool> {
    if mnemonic == names.0 {
        Some(false)
    } else if mnemonic == names.1 {
        Some(true)
    } else {
        None
    }
}

/// `(U, imm8)` for an offset the architecture encodes as `imm8:'00'`.
///
/// `U` is [`Mem::add`] verbatim, so `#-0` — which A7.7.236 calls a different
/// instruction from `#0` — encodes back to the `U == 0` halfword it came from
/// rather than being canonicalised or refused.
fn scaled_imm8(mem: &Mem) -> Option<(u16, u16)> {
    if mem.offset % 4 != 0 || mem.offset / 4 > 0xFF {
        return None;
    }
    Some((u16::from(mem.add), (mem.offset / 4) as u16))
}

/// The pieces of a floating-point data-processing encoding —
/// `111T 1110 opc1 opc2 | Vd 101 sz opc3 0 opc4` — assembled by [`Words::pack`].
#[derive(Default)]
struct Words {
    /// `hw1[12]`.
    ///
    /// Exactly one literal below — the `VMOV (immediate)` arm of
    /// [`encode_fp_data_processing`] — writes `t: 0` *and* ends in
    /// `..Default::default()`; the rest name all ten fields. That one `t: 0`
    /// is redundant, because `Words` derives `Default` and every field is a
    /// `u16`, so the catch-all would supply the same zero. It is spelled out
    /// anyway: `T` is the bit that tells a T1 row from its T2 twin, and
    /// leaving the field that picks the encoding to a catch-all reads as an
    /// oversight. Deleting it emits byte-for-byte the same halfwords, so no
    /// test can distinguish it and none should be written.
    t: u16,
    /// `opc1[3]` = `hw1[7]`.
    hi: u16,
    /// `D` = `hw1[6]`.
    d: u16,
    /// `opc1[1:0]` = `hw1[5:4]`.
    lo: u16,
    /// `hw1[3:0]` — `Vn` or `opc2`.
    vn: u16,
    /// `Vd` = `hw2[15:12]`.
    vd: u16,
    /// `sz` = `hw2[8]`.
    sz: u16,
    /// `opc3` = `hw2[7:6]`.
    opc3: u16,
    /// `M` = `hw2[5]`.
    m: u16,
    /// `Vm` or `opc4` = `hw2[3:0]`.
    vm: u16,
}

impl Words {
    /// Assemble the halfword pair.
    fn pack(self) -> (u16, u16) {
        let hw1 =
            0xEE00 | (self.t << 12) | (self.hi << 7) | (self.d << 6) | (self.lo << 4) | self.vn;
        let hw2 = (self.vd << 12)
            | ((0b1010 | self.sz) << 8)
            | (self.opc3 << 6)
            | (self.m << 5)
            | self.vm;
        (hw1, hw2)
    }
}

/// Re-encode an instruction this module decoded, back to its two halfwords.
///
/// Strict in the same way its siblings are: the width, the recorded encoding
/// name, the operand count and the operand *kinds* must all be what [`decode`]
/// produces, and every field must still fit. `cond` is deliberately not
/// consulted — no encoding in this group has a condition field, so an
/// instruction made conditional by an enclosing `IT` block encodes identically
/// — and `sets_flags` must be false, because nothing here writes the APSR.
///
/// Returns `None` for anything that is not this module's, since
/// [`super::encode`] tries the groups in turn and a greedy `encode` would
/// answer for a sibling.
pub(crate) fn encode(insn: &Insn) -> Option<(u16, u16)> {
    if insn.width != Width::Wide || insn.sets_flags || insn.explicit_width {
        return None;
    }
    // The three generic-coprocessor groups are dispatched by searching the
    // very table [`decode`] names them from, rather than by a second list of
    // spellings kept in step by hand: the search decides "is this one of ours"
    // and supplies the `L`/`D`/`T` bits in the same step, so the two
    // directions cannot come to disagree about which mnemonics exist.
    if let Some(idx) = MCR_MRC.iter().position(|m| *m == insn.mnemonic) {
        return encode_mcr(insn, idx as u16);
    }
    if let Some(idx) = MCRR_MRRC.iter().position(|m| *m == insn.mnemonic) {
        return encode_mcrr(insn, idx as u16);
    }
    if let Some(idx) = LDC_STC.iter().position(|m| *m == insn.mnemonic) {
        return encode_ldc_stc(insn, idx as u16);
    }
    match insn.mnemonic {
        "cdp" | "cdp2" => encode_cdp(insn),
        "vldr" | "vstr" => encode_vldr_vstr(insn),
        // Table A6-7's `P`/`U`/`L` assignment, spelled out at the dispatch so
        // that the mnemonic list and the field values cannot disagree.
        "vstmia" => encode_vldm_vstm(insn, VSTMIA),
        "vldmia" => encode_vldm_vstm(insn, VLDMIA),
        "vstmdb" => encode_vldm_vstm(insn, VSTMDB),
        "vldmdb" => encode_vldm_vstm(insn, VLDMDB),
        "vpush" => encode_vldm_vstm(insn, VPUSH),
        "vpop" => encode_vldm_vstm(insn, VPOP),
        "vmrs" | "vmsr" => encode_vmrs_vmsr(insn),
        "vmov" => encode_vmov_core(insn),
        "vmov.32" => encode_vmov_scalar(insn),
        _ => encode_fp_data_processing(insn),
    }
}

/// `CDP`, `CDP2` — the inverse of [`cdp`].
fn encode_cdp(insn: &Insn) -> Option<(u16, u16)> {
    let t = u16::from(insn.mnemonic == "cdp2");
    if insn.encoding != enc_name(t) || insn.operands.len() != 6 {
        return None;
    }
    let coproc = op_coproc(insn, 0)?;
    let opc1 = op_imm(insn, 1, 15)?;
    let crd = op_creg(insn, 2)?;
    let crn = op_creg(insn, 3)?;
    let crm = op_creg(insn, 4)?;
    let opc2 = op_imm(insn, 5, 7)?;
    let hw1 = 0xEE00 | (t << 12) | (opc1 << 4) | crn;
    let hw2 = (crd << 12) | (coproc << 8) | (opc2 << 5) | crm;
    Some((hw1, hw2))
}

/// `MCR`, `MCR2`, `MRC`, `MRC2` — the inverse of [`mcr`].
///
/// `idx` is the [`MCR_MRC`] index [`encode`] found the mnemonic at, which is
/// `(L << 1) | T` by that table's own construction.
fn encode_mcr(insn: &Insn, idx: u16) -> Option<(u16, u16)> {
    let (l, t) = (idx >> 1, idx & 1);
    if insn.encoding != enc_name(t) || insn.operands.len() != 6 {
        return None;
    }
    let coproc = op_coproc(insn, 0)?;
    let opc1 = op_imm(insn, 1, 7)?;
    let rt = match insn.operands.get(2) {
        Some(Operand::Reg(r)) if r.num() < 16 => u16::from(r.num()),
        // `APSR_nzcv` is `MRC`'s spelling of `Rt == 0b1111`, and `MCR` has no
        // equivalent.
        Some(Operand::SpecialReg("apsr_nzcv")) if l == 1 => 15,
        _ => return None,
    };
    let crn = op_creg(insn, 3)?;
    let crm = op_creg(insn, 4)?;
    let opc2 = op_imm(insn, 5, 7)?;
    let hw1 = 0xEE00 | (t << 12) | (opc1 << 5) | (l << 4) | crn;
    let hw2 = (rt << 12) | (coproc << 8) | (opc2 << 5) | (1 << 4) | crm;
    Some((hw1, hw2))
}

/// `MCRR`, `MCRR2`, `MRRC`, `MRRC2` — the inverse of [`mcrr`].
///
/// `idx` is the [`MCRR_MRRC`] index, which is `(L << 1) | T`.
fn encode_mcrr(insn: &Insn, idx: u16) -> Option<(u16, u16)> {
    let (l, t) = (idx >> 1, idx & 1);
    if insn.encoding != enc_name(t) || insn.operands.len() != 5 {
        return None;
    }
    let coproc = op_coproc(insn, 0)?;
    let opc1 = op_imm(insn, 1, 15)?;
    let rt = u16::from(op_reg(insn, 2)?.num());
    let rt2 = u16::from(op_reg(insn, 3)?.num());
    let crm = op_creg(insn, 4)?;
    let hw1 = 0xEC00 | (t << 12) | (1 << 6) | (l << 4) | rt2;
    let hw2 = (rt << 12) | (coproc << 8) | (opc1 << 4) | crm;
    Some((hw1, hw2))
}

/// The encoding name for a `T` bit — the inverse of [`enc_of`].
fn enc_name(t: u16) -> &'static str {
    if t == 1 {
        "T2"
    } else {
        "T1"
    }
}

/// `LDC`, `LDC2`, `STC`, `STC2` — the inverse of [`ldc_stc`].
///
/// `idx` is the [`LDC_STC`] index, which is `(L << 2) | (D << 1) | T`.
fn encode_ldc_stc(insn: &Insn, idx: u16) -> Option<(u16, u16)> {
    let (l, d, t) = ((idx >> 2) & 1, (idx >> 1) & 1, idx & 1);
    if insn.encoding != enc_name(t) {
        return None;
    }
    let coproc = op_coproc(insn, 0)?;
    let crd = op_creg(insn, 1)?;
    let mem = op_mem(insn, 2)?;
    let rn = u16::from(mem.base.num());
    // The unindexed form and the plain offset form share `[<Rn>]`; what tells
    // them apart is the `<option>` in braces, which only the unindexed one has.
    // Binding it here rather than testing for it and re-matching keeps that one
    // fact in one place.
    let (p, u, w, imm8) = if let Some(Operand::Option(s)) = insn.operands.get(3) {
        let option = OPTIONS.iter().position(|o| *o == s)? as u16;
        if insn.operands.len() != 4 || mem.mode != AddrMode::Offset || mem.offset != 0 || !mem.add {
            return None;
        }
        (0, 1, 0, option)
    } else {
        if !matches!(insn.operands.len(), 3 | 4) {
            return None;
        }
        let (u, imm8) = scaled_imm8(&mem)?;
        let (p, w) = match mem.mode {
            AddrMode::Offset => (1, 0),
            AddrMode::PreIndex => (1, 1),
            AddrMode::PostIndex => (0, 1),
            // `[<Rn>]!` with an implicit increment is Advanced SIMD only.
            AddrMode::PostIncrement => return None,
        };
        // `LDC (literal)` carries its resolved address as a fourth operand;
        // nothing else in this group has one.
        let literal = l == 1 && rn == 15 && mem.mode == AddrMode::Offset;
        match (literal, insn.operands.get(3)) {
            (false, None) => {}
            (true, Some(Operand::Target(target)))
                if target == literal_base(insn.addr).wrapping_add(mem.displacement() as u32) => {}
            _ => return None,
        }
        (p, u, w, imm8)
    };
    let hw1 = 0xEC00 | (t << 12) | (p << 8) | (u << 7) | (d << 6) | (w << 5) | (l << 4) | rn;
    let hw2 = (crd << 12) | (coproc << 8) | imm8;
    Some((hw1, hw2))
}

/// `VLDR`, `VSTR` — the inverse of the first half of [`fp_load_store`].
fn encode_vldr_vstr(insn: &Insn) -> Option<(u16, u16)> {
    let l = u16::from(insn.mnemonic == "vldr");
    let (vd, d, dbl) = split_any(op_fp(insn, 0)?)?;
    if insn.encoding != if dbl { "T1" } else { "T2" } {
        return None;
    }
    let mem = op_mem(insn, 1)?;
    if mem.mode != AddrMode::Offset {
        return None;
    }
    let (u, imm8) = scaled_imm8(&mem)?;
    let rn = u16::from(mem.base.num());
    // Only the literal form of `VLDR` carries a resolved target, and nothing
    // in this row has a fourth operand. The count has to be bounded explicitly,
    // as every sibling encoder here bounds it: matching on `operands.get(2)`
    // alone says nothing about operand 3, so a literal `VLDR` with a trailing
    // operand used to re-encode to the halfwords of the three-operand form —
    // dropping the extra silently and claiming an exact round trip.
    let literal = l == 1 && rn == 15;
    if insn.operands.len() != if literal { 3 } else { 2 } {
        return None;
    }
    match (literal, insn.operands.get(2)) {
        (false, None) => {}
        (true, Some(Operand::Target(target)))
            if target == literal_base(insn.addr).wrapping_add(mem.displacement() as u32) => {}
        _ => return None,
    }
    let hw1 = 0xEC00 | (1 << 8) | (u << 7) | (d << 6) | (l << 4) | rn;
    let hw2 = (vd << 12) | ((0b1010 | u16::from(dbl)) << 8) | imm8;
    Some((hw1, hw2))
}

/// A base register operand, and whether it is written back — the inverse of
/// [`fp_load_store`]'s `base`.
fn parse_base(op: Option<Operand>) -> Option<(u16, u16)> {
    match op {
        Some(Operand::Reg(r)) if r.num() < 16 => Some((u16::from(r.num()), 0)),
        Some(Operand::Text(s)) => WRITEBACK
            .iter()
            .position(|w| *w == s)
            .map(|i| (i as u16, 1)),
        _ => None,
    }
}

/// A `<list>` operand as `(first register, count, double precision)` — the
/// inverse of [`fp_list`].
fn parse_list(op: Option<Operand>) -> Option<(u16, u16, bool)> {
    match op {
        Some(Operand::Text(s)) => {
            for first in 0..32usize {
                if S_SINGLE[first] == s {
                    return Some((first as u16, 1, false));
                }
                if D_SINGLE[first] == s {
                    return Some((first as u16, 1, true));
                }
                for last in first..32 {
                    let regs = (last - first + 1) as u16;
                    if S_RANGES[first][last] == s {
                        return Some((first as u16, regs, false));
                    }
                    if D_RANGES[first][last] == s {
                        return Some((first as u16, regs, true));
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// One row of Table A6-7: which `P`, `U` and `L` a multiple-register transfer
/// mnemonic names, and whether it is one of the two stack-only spellings.
///
/// Passed in from [`encode`]'s dispatch rather than looked up here, so that
/// every mnemonic that reaches this function arrives with its fields already
/// determined — there is no "some other mnemonic" case to refuse, and no way
/// to add a seventh spelling without giving it a row.
#[derive(Clone, Copy)]
struct Transfer {
    /// `P` = `hw1[8]`: Decrement Before rather than Increment After.
    p: u16,
    /// `U` = `hw1[7]`: the transfer runs upwards.
    u: u16,
    /// `L` = `hw1[4]`: a load rather than a store.
    l: u16,
    /// `VPUSH`/`VPOP`, whose base is an implicit `sp!` rather than an operand.
    stack: bool,
}

/// `VSTMIA` — Increment After, storing (A7.7.258).
const VSTMIA: Transfer = Transfer {
    p: 0,
    u: 1,
    l: 0,
    stack: false,
};
/// `VLDMIA` — Increment After, loading (A7.7.235).
const VLDMIA: Transfer = Transfer {
    p: 0,
    u: 1,
    l: 1,
    stack: false,
};
/// `VSTMDB` — Decrement Before, storing; writeback only (A7.7.258).
const VSTMDB: Transfer = Transfer {
    p: 1,
    u: 0,
    l: 0,
    stack: false,
};
/// `VLDMDB` — Decrement Before, loading; writeback only (A7.7.235).
const VLDMDB: Transfer = Transfer {
    p: 1,
    u: 0,
    l: 1,
    stack: false,
};
/// `VPUSH` — `VSTMDB sp!` under its own name (A7.7.252).
const VPUSH: Transfer = Transfer {
    p: 1,
    u: 0,
    l: 0,
    stack: true,
};
/// `VPOP` — `VLDMIA sp!` under its own name (A7.7.251).
const VPOP: Transfer = Transfer {
    p: 0,
    u: 1,
    l: 1,
    stack: true,
};

/// `VLDM`, `VSTM`, `VPUSH`, `VPOP` — the inverse of the second half of
/// [`fp_load_store`].
fn encode_vldm_vstm(insn: &Insn, form: Transfer) -> Option<(u16, u16)> {
    let Transfer { p, u, l, stack } = form;
    let (rn, w, list) = if stack {
        if insn.operands.len() != 1 {
            return None;
        }
        (13, 1, insn.operands.get(0))
    } else {
        if insn.operands.len() != 2 {
            return None;
        }
        let (rn, w) = parse_base(insn.operands.get(0))?;
        // Decrement Before exists only with writeback (Table A6-7), and
        // `sp!` in the stack direction — loading upwards or storing
        // downwards, `P != L` — is `VPOP`/`VPUSH`, which is what decode
        // produces, so it must not also round-trip through here. Storing
        // upwards or loading downwards from `sp!` is ordinary `VSTM`/`VLDM`.
        if (p == 1 && w == 0) || (rn == 13 && w == 1 && p != l) {
            return None;
        }
        (rn, w, insn.operands.get(1))
    };
    let (first, regs, dbl) = parse_list(list)?;
    if insn.encoding != if dbl { "T1" } else { "T2" } {
        return None;
    }
    if regs == 0 || first + regs > 32 || (dbl && regs > 16) {
        return None;
    }
    let imm8 = if dbl { regs * 2 } else { regs };
    let (vd, d) = if dbl {
        (first & 0xF, first >> 4)
    } else {
        (first >> 1, first & 1)
    };
    let hw1 = 0xEC00 | (p << 8) | (u << 7) | (d << 6) | (w << 5) | (l << 4) | rn;
    let hw2 = (vd << 12) | ((0b1010 | u16::from(dbl)) << 8) | imm8;
    Some((hw1, hw2))
}

/// `VMRS`, `VMSR` — the inverse of [`fp_transfer`]'s `A == 0b111` rows.
fn encode_vmrs_vmsr(insn: &Insn) -> Option<(u16, u16)> {
    if insn.encoding != "T1" || insn.operands.len() != 2 {
        return None;
    }
    let l = u16::from(insn.mnemonic == "vmrs");
    // `VMRS` reads into its first operand and `VMSR` writes from its second,
    // so the two mnemonics name the same pair of fields in opposite orders.
    let (spec, core) = if l == 1 {
        (insn.operands.get(1), insn.operands.get(0))
    } else {
        (insn.operands.get(0), insn.operands.get(1))
    };
    let reg = match spec {
        Some(Operand::SpecialReg(name)) => FP_SYSREGS
            .iter()
            .position(|r| *r == Some(name))
            .map(|i| i as u16)?,
        _ => return None,
    };
    let rt = match core {
        Some(Operand::Reg(r)) if r.num() < 16 => u16::from(r.num()),
        Some(Operand::SpecialReg("apsr_nzcv")) if l == 1 && reg == FPSCR_REG => 15,
        _ => return None,
    };
    if l == 0 && !writable_sysreg(reg) {
        return None;
    }
    let hw1 = 0xEE00 | (0b111 << 5) | (l << 4) | reg;
    let hw2 = (rt << 12) | (0b1010 << 8) | (1 << 4);
    Some((hw1, hw2))
}

/// The three `VMOV` forms that move between core and extension registers —
/// A7.7.243, A7.7.244, A7.7.245 — told apart by their operand shapes, which is
/// the only thing that distinguishes them in UAL either.
fn encode_vmov_core(insn: &Insn) -> Option<(u16, u16)> {
    if insn.encoding != "T1" {
        return None;
    }
    match insn.operands.len() {
        // `<Sn>, <Rt>` or `<Rt>, <Sn>`.
        2 => {
            let (op, s, rt) = match (insn.operands.get(0), insn.operands.get(1)) {
                (Some(Operand::FpReg(s)), Some(Operand::Reg(r))) => (0, s, r),
                (Some(Operand::Reg(r)), Some(Operand::FpReg(s))) => (1, s, r),
                _ => return None,
            };
            let (vn, n) = split(s, false)?;
            let hw1 = 0xEE00 | (op << 4) | vn;
            let hw2 = (u16::from(rt.num()) << 12) | (0b1010 << 8) | (n << 7) | (1 << 4);
            Some((hw1, hw2))
        }
        // `<Dm>, <Rt>, <Rt2>` or `<Rt>, <Rt2>, <Dm>`.
        3 => {
            let (op, dm, rt, rt2) = match (
                insn.operands.get(0),
                insn.operands.get(1),
                insn.operands.get(2),
            ) {
                (Some(Operand::FpReg(d)), Some(Operand::Reg(a)), Some(Operand::Reg(b))) => {
                    (0, d, a, b)
                }
                (Some(Operand::Reg(a)), Some(Operand::Reg(b)), Some(Operand::FpReg(d))) => {
                    (1, d, a, b)
                }
                _ => return None,
            };
            let (vm, m) = split(dm, true)?;
            let hw1 = 0xEC00 | (1 << 6) | (op << 4) | u16::from(rt2.num());
            let hw2 = (u16::from(rt.num()) << 12) | (0b1011 << 8) | (m << 5) | (1 << 4) | vm;
            Some((hw1, hw2))
        }
        // `<Sm>, <Sm1>, <Rt>, <Rt2>` or `<Rt>, <Rt2>, <Sm>, <Sm1>`.
        4 => {
            let (op, sm, sm1, rt, rt2) = match (
                insn.operands.get(0),
                insn.operands.get(1),
                insn.operands.get(2),
                insn.operands.get(3),
            ) {
                (
                    Some(Operand::FpReg(a)),
                    Some(Operand::FpReg(b)),
                    Some(Operand::Reg(t)),
                    Some(Operand::Reg(t2)),
                ) => (0, a, b, t, t2),
                (
                    Some(Operand::Reg(t)),
                    Some(Operand::Reg(t2)),
                    Some(Operand::FpReg(a)),
                    Some(Operand::FpReg(b)),
                ) => (1, a, b, t, t2),
                _ => return None,
            };
            let (vm, m) = split(sm, false)?;
            let first = (vm << 1) | m;
            // The pair is consecutive by construction, and cannot run off the
            // end of the bank.
            if first == 31 || sm1 != FpReg::S(first as u8 + 1) {
                return None;
            }
            let hw1 = 0xEC00 | (1 << 6) | (op << 4) | u16::from(rt2.num());
            let hw2 = (u16::from(rt.num()) << 12) | (0b1010 << 8) | (m << 5) | (1 << 4) | vm;
            Some((hw1, hw2))
        }
        _ => None,
    }
}

/// `VMOV.32 <Dd[x]>, <Rt>` and `VMOV.32 <Rt>, <Dn[x]>` — A7.7.241, A7.7.242.
fn encode_vmov_scalar(insn: &Insn) -> Option<(u16, u16)> {
    if insn.encoding != "T1" || insn.operands.len() != 2 {
        return None;
    }
    let (l, scalar, index, rt) = match (insn.operands.get(0), insn.operands.get(1)) {
        (Some(Operand::FpScalar(d, i)), Some(Operand::Reg(r))) => (0, d, i, r),
        (Some(Operand::Reg(r)), Some(Operand::FpScalar(d, i))) => (1, d, i, r),
        _ => return None,
    };
    if index > 1 {
        return None;
    }
    let (vd, d) = split(scalar, true)?;
    let hw1 = 0xEE00 | (u16::from(index) << 5) | (l << 4) | vd;
    let hw2 = (u16::from(rt.num()) << 12) | (0b1011 << 8) | (d << 7) | (1 << 4);
    Some((hw1, hw2))
}

/// `<Fd>, <Fn>, <Fm>` for a row of [`DP3`].
fn encode_three(insn: &Insn, dbl: bool, row: &Dp3) -> Option<(u16, u16)> {
    if insn.operands.len() != 3 || insn.encoding != row.enc {
        return None;
    }
    let (vd, d) = split(op_fp(insn, 0)?, dbl)?;
    let (vn, n) = split(op_fp(insn, 1)?, dbl)?;
    let (vm, m) = split(op_fp(insn, 2)?, dbl)?;
    Some(
        Words {
            t: row.t,
            hi: row.hi,
            d,
            lo: row.lo,
            vn,
            vd,
            sz: u16::from(dbl),
            opc3: (n << 1) | row.op,
            m,
            vm,
        }
        .pack(),
    )
}

/// `<Fd>, <Fm>` for a row of [`DP2`].
fn encode_two(insn: &Insn, dbl: bool, row: &Dp2) -> Option<(u16, u16)> {
    if insn.operands.len() != 2 || insn.encoding != "T1" {
        return None;
    }
    let (vd, d) = split(op_fp(insn, 0)?, dbl)?;
    let (vm, m) = split(op_fp(insn, 1)?, dbl)?;
    Some(
        Words {
            t: row.t,
            hi: 1,
            d,
            lo: 0b11,
            vn: row.opc2,
            vd,
            sz: u16::from(dbl),
            opc3: row.opc3,
            m,
            vm,
        }
        .pack(),
    )
}

/// `<Fd>, <Fm>` where the two registers may differ in precision, as every
/// conversion's may.
fn convert_regs(insn: &Insn, dst_dbl: bool, src_dbl: bool) -> Option<(u16, u16, u16, u16)> {
    let (vd, d) = split(op_fp(insn, 0)?, dst_dbl)?;
    let (vm, m) = split(op_fp(insn, 1)?, src_dbl)?;
    Some((vd, d, vm, m))
}

/// The floating-point data-processing operations — the inverse of
/// [`fp_data_processing`], searching the same tables by mnemonic.
fn encode_fp_data_processing(insn: &Insn) -> Option<(u16, u16)> {
    // `VMOV (immediate)` and `VMOV (register)` share a mnemonic; the second
    // operand is what tells them apart, in the encoding and in UAL alike.
    if let Some(dbl) = matches_pair(("vmov.f32", "vmov.f64"), insn.mnemonic) {
        if let Some(Operand::FpImm(value)) = insn.operands.get(1) {
            if insn.encoding != "T1" || insn.operands.len() != 2 {
                return None;
            }
            let (vd, d) = split(op_fp(insn, 0)?, dbl)?;
            let imm8 = vfp_compress_imm(value, dbl)?;
            return Some(
                Words {
                    t: 0,
                    hi: 1,
                    d,
                    lo: 0b11,
                    vn: imm8 >> 4,
                    vd,
                    sz: u16::from(dbl),
                    vm: imm8 & 0xF,
                    ..Default::default()
                }
                .pack(),
            );
        }
    }
    for row in DP3.iter() {
        if let Some(dbl) = matches_pair(row.names, insn.mnemonic) {
            return encode_three(insn, dbl, row);
        }
    }
    for (cc, names) in VSEL.iter().enumerate() {
        if let Some(dbl) = matches_pair(*names, insn.mnemonic) {
            if insn.operands.len() != 3 || insn.encoding != "T1" {
                return None;
            }
            let (vd, d) = split(op_fp(insn, 0)?, dbl)?;
            let (vn, n) = split(op_fp(insn, 1)?, dbl)?;
            let (vm, m) = split(op_fp(insn, 2)?, dbl)?;
            return Some(
                Words {
                    t: 1,
                    hi: 0,
                    d,
                    lo: cc as u16,
                    vn,
                    vd,
                    sz: u16::from(dbl),
                    opc3: n << 1,
                    m,
                    vm,
                }
                .pack(),
            );
        }
    }
    for row in DP2.iter() {
        if let Some(dbl) = matches_pair(row.names, insn.mnemonic) {
            return encode_two(insn, dbl, row);
        }
    }
    for (e, names) in VCMP.iter().enumerate() {
        if let Some(dbl) = matches_pair(*names, insn.mnemonic) {
            if insn.operands.len() != 2 {
                return None;
            }
            let (vd, d) = split(op_fp(insn, 0)?, dbl)?;
            // Encoding T2 compares against `#0.0`, which is not an operand the
            // encoding holds anywhere: `Vm` and `M` are `(0)`.
            let (opc2, vm, m) = match (insn.encoding, insn.operands.get(1)) {
                ("T1", Some(Operand::FpReg(other))) => {
                    let (vm, m) = split(other, dbl)?;
                    (0b0100, vm, m)
                }
                ("T2", Some(Operand::Text("#0.0"))) => (0b0101, 0, 0),
                _ => return None,
            };
            return Some(
                Words {
                    t: 0,
                    hi: 1,
                    d,
                    lo: 0b11,
                    vn: opc2,
                    vd,
                    sz: u16::from(dbl),
                    opc3: ((e as u16) << 1) | 1,
                    m,
                    vm,
                }
                .pack(),
            );
        }
    }
    encode_convert(insn)
}

/// The conversions — the inverse of [`fp_convert`] and of
/// [`fpv5_round_or_convert`]'s `VCVT{A,N,P,M}` half.
///
/// Split on operand count first, because the fixed-point forms share their
/// mnemonics with the integer forms and differ only in carrying a `#<fbits>`:
/// `vcvt.s32.f32 s0, s0, #4` and `vcvt.s32.f32 s0, s1` are different
/// instructions.
fn encode_convert(insn: &Insn) -> Option<(u16, u16)> {
    if insn.encoding != "T1" {
        return None;
    }
    match insn.operands.len() {
        3 => encode_convert_fixed(insn),
        2 => encode_convert_pair(insn),
        _ => None,
    }
}

/// `VCVT` between floating-point and fixed-point (A7.7.229).
fn encode_convert_fixed(insn: &Insn) -> Option<(u16, u16)> {
    for (to_fixed, by_sf) in CVT_FIXED.iter().enumerate() {
        for (sf, by_sx) in by_sf.iter().enumerate() {
            for (sx, by_u) in by_sx.iter().enumerate() {
                for (u, name) in by_u.iter().enumerate() {
                    if *name != insn.mnemonic {
                        continue;
                    }
                    let dbl = sf == 1;
                    let dest = op_fp(insn, 0)?;
                    let (vd, d) = split(dest, dbl)?;
                    // A7.7.229's operands are `<Dd>, <Dd>` / `<Sd>, <Sd>`: the
                    // destination is also the source, and the encoding holds
                    // only the one register number. Compared against the
                    // already-bound `dest` rather than re-reading operand 0,
                    // which `split` above has just proved is a register.
                    if op_fp(insn, 1) != Some(dest) {
                        return None;
                    }
                    // `<fbits>` is `size - UInt(imm4:i)`, so the field is
                    // `size - <fbits>` and must still fit in five bits.
                    let size = if sx == 1 { 32 } else { 16 };
                    let field = match insn.operands.get(2) {
                        Some(Operand::Imm(frac)) => size - frac,
                        _ => return None,
                    };
                    if !(0..32).contains(&field) {
                        return None;
                    }
                    return Some(
                        Words {
                            t: 0,
                            hi: 1,
                            d,
                            lo: 0b11,
                            vn: 0b1010 | ((to_fixed as u16) << 2) | u as u16,
                            vd,
                            sz: sf as u16,
                            opc3: ((sx as u16) << 1) | 1,
                            m: (field & 1) as u16,
                            vm: (field >> 1) as u16,
                        }
                        .pack(),
                    );
                }
            }
        }
    }
    None
}

/// The two-register conversions: half precision, integer, and the
/// double/single pair.
fn encode_convert_pair(insn: &Insn) -> Option<(u16, u16)> {
    // `VCVTB`/`VCVTT` (A7.7.231).
    for (t, by_sz) in CVT_HALF.iter().enumerate() {
        for (sz, by_op) in by_sz.iter().enumerate() {
            for (op, name) in by_op.iter().enumerate() {
                if *name != insn.mnemonic {
                    continue;
                }
                let dbl = sz == 1;
                let (vd, d, vm, m) = convert_regs(insn, dbl && op == 0, dbl && op == 1)?;
                return Some(
                    Words {
                        t: 0,
                        hi: 1,
                        d,
                        lo: 0b11,
                        vn: 0b0010 | op as u16,
                        vd,
                        sz: sz as u16,
                        opc3: ((t as u16) << 1) | 1,
                        m,
                        vm,
                    }
                    .pack(),
                );
            }
        }
    }
    // `VCVT` from a 32-bit integer (A7.7.228, `opc2 == 000`).
    for (sz, by_signed) in CVT_FROM_INT.iter().enumerate() {
        for (signed, name) in by_signed.iter().enumerate() {
            if *name != insn.mnemonic {
                continue;
            }
            let (vd, d, vm, m) = convert_regs(insn, sz == 1, false)?;
            return Some(
                Words {
                    t: 0,
                    hi: 1,
                    d,
                    lo: 0b11,
                    vn: 0b1000,
                    vd,
                    sz: sz as u16,
                    opc3: ((signed as u16) << 1) | 1,
                    m,
                    vm,
                }
                .pack(),
            );
        }
    }
    // `VCVT`/`VCVTR` to a 32-bit integer (A7.7.228, `opc2 == 10x`).
    for (round, by_signed) in CVT_TO_INT.iter().enumerate() {
        for (signed, by_sz) in by_signed.iter().enumerate() {
            for (sz, name) in by_sz.iter().enumerate() {
                if *name != insn.mnemonic {
                    continue;
                }
                let (vd, d, vm, m) = convert_regs(insn, false, sz == 1)?;
                return Some(
                    Words {
                        t: 0,
                        hi: 1,
                        d,
                        lo: 0b11,
                        vn: 0b1100 | signed as u16,
                        vd,
                        sz: sz as u16,
                        opc3: ((round as u16) << 1) | 1,
                        m,
                        vm,
                    }
                    .pack(),
                );
            }
        }
    }
    // `VCVT` between double and single precision (A7.7.230).
    for (sz, name) in CVT_DP_SP.iter().enumerate() {
        if *name == insn.mnemonic {
            let (vd, d, vm, m) = convert_regs(insn, sz == 0, sz == 1)?;
            return Some(
                Words {
                    t: 0,
                    hi: 1,
                    d,
                    lo: 0b11,
                    vn: 0b0111,
                    vd,
                    sz: sz as u16,
                    opc3: 0b11,
                    m,
                    vm,
                }
                .pack(),
            );
        }
    }
    // `VCVT{A,N,P,M}` (A7.7.227) — FPv5, `T == 1`.
    for (rm, by_signed) in CVT_RM.iter().enumerate() {
        for (signed, by_sz) in by_signed.iter().enumerate() {
            for (sz, name) in by_sz.iter().enumerate() {
                if *name != insn.mnemonic {
                    continue;
                }
                let (vd, d, vm, m) = convert_regs(insn, false, sz == 1)?;
                return Some(
                    Words {
                        t: 1,
                        hi: 1,
                        d,
                        lo: 0b11,
                        vn: 0b1100 | rm as u16,
                        vd,
                        sz: sz as u16,
                        opc3: ((signed as u16) << 1) | 1,
                        m,
                        vm,
                    }
                    .pack(),
                );
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::MAX_OPERANDS;

    /// A word-aligned address, so that `Align(PC,4)` is a no-op and the
    /// resolved literal targets in the expected strings are easy to check by
    /// hand.
    const ADDR: u32 = 0x1000;

    /// Build an instruction of this group's shape, for the encode-first
    /// direction.
    fn insn(mnemonic: &'static str, encoding: &'static str, operands: &[Operand]) -> Insn {
        wide(mnemonic, encoding, ADDR, ops(operands))
    }

    /// Decode, assert the printed UAL, and assert that it re-encodes to the
    /// halfwords it came from.
    ///
    /// Every expected string here is the manual's own syntax line with the
    /// fields filled in, lower-cased; the halfwords are the bytes a
    /// known-good assembler produces for that line.
    fn check(hw1: u16, hw2: u16, text: &str) {
        let decoded = decode(hw1, hw2, ADDR);
        // `assert!` rather than `unwrap_or_else(|| panic!(…))`: the closure in
        // the latter is a function that never runs, and this crate's coverage
        // gate is 100% of functions.
        assert!(
            decoded.is_some(),
            "{hw1:#06x} {hw2:#06x} ({text}) must decode"
        );
        let insn = decoded.unwrap();
        assert_eq!(
            insn.to_string(),
            text,
            "printed form of {hw1:#06x} {hw2:#06x}"
        );
        assert_eq!(
            encode(&insn),
            Some((hw1, hw2)),
            "round trip of {hw1:#06x} {hw2:#06x} ({text})"
        );
    }

    /// Decode and assert the invariants every instruction in this group shares,
    /// then assert the round trip. Returns `None` for an encoding that is not
    /// allocated, which the sweep counts rather than treats as a failure.
    fn round_trip(hw1: u16, hw2: u16) -> Option<Insn> {
        let insn = decode(hw1, hw2, ADDR)?;
        assert_eq!(insn.width, Width::Wide, "{hw1:#06x} {hw2:#06x}");
        assert_eq!(insn.len(), 4, "{hw1:#06x} {hw2:#06x}");
        assert_eq!(insn.addr, ADDR, "{hw1:#06x} {hw2:#06x}");
        // Nothing here has a condition field, and nothing writes the APSR
        // flags: `Display` would print `vcmps.f32` for a stray `sets_flags`.
        assert!(insn.cond.is_none(), "{hw1:#06x} {hw2:#06x}");
        assert!(!insn.sets_flags, "{hw1:#06x} {hw2:#06x}");
        assert!(!insn.explicit_width, "{hw1:#06x} {hw2:#06x}");
        assert_eq!(
            encode(&insn),
            Some((hw1, hw2)),
            "round trip of {hw1:#06x} {hw2:#06x} ({insn})"
        );
        Some(insn)
    }

    /// Decode, asserting that it does — the halfword pairs below are all
    /// instructions this module is documented to decode.
    fn dec(hw1: u16, hw2: u16) -> Insn {
        let decoded = decode(hw1, hw2, ADDR);
        assert!(decoded.is_some(), "{hw1:#06x} {hw2:#06x} must decode");
        decoded.unwrap()
    }

    /// `insn` with operand `i` replaced.
    fn replacing(insn: &Insn, i: usize, op: Operand) -> Insn {
        let mut out = *insn;
        out.operands = insn
            .operands
            .as_slice()
            .enumerate()
            .map(|(n, existing)| if n == i { op } else { existing })
            .collect();
        out
    }

    /// At least one instruction per arm of [`encode`], and per operand shape
    /// within an arm: the generic coprocessor forms, every addressing mode of
    /// `LDC`/`STC` and `VLDR`/`VSTR`, all six `VMOV`s, `VMRS`/`VMSR`, and one
    /// of each floating-point data-processing and conversion table.
    ///
    /// Every pair here also appears in one of the printed-syntax tests above,
    /// where its UAL text is pinned; this list exists so that the rejection
    /// sweeps do not have to repeat it.
    const ENCODERS: [(u16, u16); 49] = [
        (0xEE13, 0x27A4), // cdp p7, #1, c2, c3, c4, #5
        (0xFE01, 0x0E02), // cdp2 p14, #0, c0, c1, c2, #0
        (0xEE23, 0x27B4), // mcr p7, #1, r2, c3, c4, #5
        (0xEE33, 0x27B4), // mrc p7, #1, r2, c3, c4, #5
        (0xEE11, 0xFE72), // mrc p14, #0, apsr_nzcv, c1, c2, #3
        (0xEC43, 0x2714), // mcrr p7, #1, r2, r3, c4
        (0xEC53, 0x2714), // mrrc p7, #1, r2, r3, c4
        (0xED92, 0x1702), // ldc p7, c1, [r2, #8]
        (0xEDB2, 0x1702), // ldc p7, c1, [r2, #8]!
        (0xECB2, 0x1702), // ldc p7, c1, [r2], #8
        (0xEC92, 0x170C), // ldc p7, c1, [r2], {12}
        (0xED9F, 0x1704), // ldc p7, c1, [pc, #16], 0x1014
        (0xED82, 0x1702), // stc p7, c1, [r2, #8]
        (0xFDC0, 0x0E00), // stc2l p14, c0, [r0]
        (0xEDD2, 0x0A02), // vldr s1, [r2, #8]
        (0xED12, 0x3B02), // vldr d3, [r2, #-8]
        (0xEDDF, 0x0A04), // vldr s1, [pc, #16], 0x1014
        (0xED8D, 0x8AFF), // vstr s16, [sp, #1020]
        (0xECD2, 0x0A04), // vldmia r2, {s1-s4}
        (0xECB2, 0x1B06), // vldmia r2!, {d1-d3}
        (0xED72, 0x2A02), // vldmdb r2!, {s5-s6}
        (0xEC82, 0x0B04), // vstmia r2, {d0-d1}
        (0xED22, 0x4B08), // vstmdb r2!, {d4-d7}
        (0xED2D, 0x0A04), // vpush {s0-s3}
        (0xECBD, 0x2B08), // vpop {d2-d5}
        (0xEE03, 0x4A90), // vmov s7, r4
        (0xEE13, 0x4A90), // vmov r4, s7
        (0xEE23, 0x4B10), // vmov.32 d3[1], r4
        (0xEE13, 0x4B10), // vmov.32 r4, d3[0]
        (0xEC41, 0x0A32), // vmov s5, s6, r0, r1
        (0xEC51, 0x0A32), // vmov r0, r1, s5, s6
        (0xEC41, 0x0B19), // vmov d9, r0, r1
        (0xEC51, 0x0B19), // vmov r0, r1, d9
        (0xEEE1, 0x5A10), // vmsr fpscr, r5
        (0xEEF1, 0x5A10), // vmrs r5, fpscr
        (0xEEF1, 0xFA10), // vmrs apsr_nzcv, fpscr
        (0xEE71, 0x0A21), // vadd.f32 s1, s2, s3
        (0xEE32, 0x1B03), // vadd.f64 d1, d2, d3
        (0xEE12, 0x1B43), // vnmla.f64 d1, d2, d3  (a T1 row of DP3)
        (0xFE41, 0x0A21), // vseleq.f32 s1, s2, s3
        (0xFE22, 0x1B03), // vselge.f64 d1, d2, d3
        (0xEEF0, 0x0AC1), // vabs.f32 s1, s2
        (0xEEB1, 0x1B42), // vneg.f64 d1, d2
        (0xFEF8, 0x0A41), // vrinta.f32 s1, s2     (a T1 = 1 row of DP2)
        (0xEEF0, 0x0A00), // vmov.f32 s1, #2.0
        (0xEEF4, 0x0A41), // vcmp.f32 s1, s2
        (0xEEF5, 0x1B40), // vcmp.f64 d17, #0.0
        (0xEEFD, 0x0AC1), // vcvt.s32.f32 s1, s2
        (0xEEFE, 0x0A66), // vcvt.s16.f32 s1, s1, #3
    ];

    /// The conversions, whose two operands may legitimately differ in
    /// precision — kept apart from [`ENCODERS`] only because the
    /// precision-swap sweep wants both halves of each table.
    const CONVERSIONS: [(u16, u16); 6] = [
        (0xEEF8, 0x0AC1), // vcvt.f32.s32 s1, s2      CVT_FROM_INT
        (0xEEFC, 0x0B42), // vcvtr.u32.f64 s1, d2     CVT_TO_INT
        (0xEEB7, 0x1AC1), // vcvt.f64.f32 d1, s2      CVT_DP_SP
        (0xEEF7, 0x0BC2), // vcvt.f32.f64 s1, d2      CVT_DP_SP
        (0xEEF2, 0x0A41), // vcvtb.f32.f16 s1, s2     CVT_HALF
        (0xFEFC, 0x2AC3), // vcvta.s32.f32 s5, s6     CVT_RM
    ];

    /// Every halfword the dispatcher routes to this module: `op1 == 0b01` and
    /// `op1 == 0b11` of Table A5-9 with `op2` of `0b1xxxxxx`.
    fn group_halfwords() -> impl Iterator<Item = u16> {
        (0xEC00u16..=0xEFFF).chain(0xFC00u16..=0xFFFF)
    }

    #[test]
    fn systematic_sweep_round_trips_and_accounts_for_every_hole() {
        // The second halfword varies over the fields that select an encoding:
        // the coprocessor number (including both floating-point values and
        // four generic ones), `Vd`, and a spread of `sz`/`opc3`/`M`/`Vm`/
        // `bit[4]` patterns.
        let coprocs = [0x0u16, 0x7, 0xA, 0xB, 0xE, 0xF];
        let bodies = [
            0x00u16, 0x01, 0x02, 0x04, 0x08, 0x10, 0x11, 0x20, 0x41, 0x66, 0x90, 0xC1, 0xCF, 0xFF,
        ];
        let vds = [0x0u16, 0x1, 0xF];

        let (mut decoded, mut simd, mut undefined, mut unallocated) = (0usize, 0, 0, 0);
        let mut total = 0usize;
        for hw1 in group_halfwords() {
            let op1 = bits(hw1, 9, 4);
            for &coproc in coprocs.iter() {
                for &body in bodies.iter() {
                    for &vd in vds.iter() {
                        let hw2 = (vd << 12) | (coproc << 8) | body;
                        total += 1;
                        let insn = round_trip(hw1, hw2);
                        if op1 & 0b11_0000 == 0b11_0000 {
                            // Advanced SIMD data-processing — `t32_simd`'s.
                            assert!(insn.is_none(), "{hw1:#06x} {hw2:#06x} is SIMD");
                            simd += 1;
                        } else if op1 & 0b11_1110 == 0 {
                            // Table A5-30 leaves `op1 == 0b00000x` UNDEFINED.
                            assert!(insn.is_none(), "{hw1:#06x} {hw2:#06x} is UNDEFINED");
                            undefined += 1;
                        } else if insn.is_some() {
                            decoded += 1;
                        } else {
                            unallocated += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(total, 2048 * 6 * 14 * 3);
        assert_eq!(simd + undefined + decoded + unallocated, total);
        // A quarter of the space is Advanced SIMD and 1/32 is UNDEFINED, both
        // by construction of the `op1` field; of what remains, the holes are
        // the UNPREDICTABLE register lists, the non-zero `(0)` fields, and the
        // opcode combinations Table A6-5 does not allocate.
        assert_eq!(simd, total / 4);
        assert_eq!(undefined, total / 32);
        // 4_992 higher than it was before `#-0` became representable: every
        // `U == 0`, `imm8 == 0` halfword pair in the `LDC`/`STC` and
        // `VLDR`/`VSTR` rows used to be refused outright, to keep a round trip
        // from silently rewriting `U`. All 4_992 of them now decode, and
        // re-encode to themselves.
        assert_eq!(decoded, 285_238);
        assert_eq!(unallocated, 85_706);
    }

    #[test]
    fn single_and_double_read_the_same_bits_in_opposite_orders() {
        // One halfword pair, one bit apart: `sz` (`hw2[8]`) is the only
        // difference between these two, and it inverts every register-number
        // concatenation (Table A6-4).
        //
        //   D  = hw1[6]     = 0      Vd = hw2[15:12] = 15
        //   N  = hw2[7]     = 1      Vn = hw1[3:0]   = 0
        //   M  = hw2[5]     = 0      Vm = hw2[3:0]   = 1
        //
        // Double precision reads `D:Vd` = 0:1111 = 15, `N:Vn` = 1:0000 = 16,
        // `M:Vm` = 0:0001 = 1.
        check(0xEE30, 0xFB81, "vadd.f64 d15, d16, d1");
        // Single precision reads `Vd:D` = 1111:0 = 30, `Vn:N` = 0000:1 = 1,
        // `Vm:M` = 0001:0 = 2 — three different registers from the same bits.
        check(0xEE30, 0xFA81, "vadd.f32 s30, s1, s2");

        // The same inversion in the two-register shape, and in the `Vm`/`M`
        // field on its own.
        check(0xEEB0, 0xFBE1, "vabs.f64 d15, d17");
        check(0xEEB0, 0xFAE1, "vabs.f32 s30, s3");
    }

    #[test]
    fn register_halves_round_trip_for_every_high_bit_combination() {
        // 0 and 1 differ only in the low bit of the pair, 15 and 16 straddle
        // the boundary between the 4-bit and the 1-bit field, and 31 sets
        // both. Any transposition of the two halves changes at least one of
        // these five.
        const NUMBERS: [u8; 5] = [0, 1, 15, 16, 31];
        let mut checked = 0usize;
        for &a in NUMBERS.iter() {
            for &b in NUMBERS.iter() {
                for &c in NUMBERS.iter() {
                    for &dbl in [false, true].iter() {
                        let reg =
                            |n: u8| Operand::FpReg(if dbl { FpReg::D(n) } else { FpReg::S(n) });
                        let name = if dbl { "vadd.f64" } else { "vadd.f32" };
                        let original = insn(name, "T1", &[reg(a), reg(b), reg(c)]);
                        let (hw1, hw2) = encode(&original).expect("encodable");
                        assert_eq!(
                            decode(hw1, hw2, ADDR).as_ref(),
                            Some(&original),
                            "{original} through {hw1:#06x} {hw2:#06x}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 5 * 5 * 5 * 2);
    }

    #[test]
    fn vfp_expand_imm_matches_the_manuals_table() {
        // Table A6-6: the constant is `(-1)^a * 2^(UInt(NOT(b):c:d) - 3) *
        // (16 + UInt(e:f:g:h)) / 16`, for `imm8` of `abcdefgh`.
        //
        //   0x00 = 0 00 0000 -> 2^(UInt(100)-3) * 16/16 = 2^1 = 2
        //   0x80 = 1 00 0000 -> -2
        //   0x70 = 0 11 0000 -> 2^(UInt(011)-3) * 16/16 = 2^0 = 1
        //   0x40 = 0 10 0000 -> 2^(UInt(000)-3) = 2^-3 = 0.125, the smallest
        //   0x3F = 0 00 1111 -> 2^4 * 31/16 = 31, the largest
        //   0xE8 = 1 11 1000 -> -(2^-1 * 24/16) = -0.75
        for &dbl in [false, true].iter() {
            assert_eq!(vfp_expand_imm(0x00, dbl), 2.0);
            assert_eq!(vfp_expand_imm(0x80, dbl), -2.0);
            assert_eq!(vfp_expand_imm(0x70, dbl), 1.0);
            assert_eq!(vfp_expand_imm(0x40, dbl), 0.125);
            assert_eq!(vfp_expand_imm(0x3F, dbl), 31.0);
            assert_eq!(vfp_expand_imm(0xE8, dbl), -0.75);
            // Single and double precision denote the same 256 real numbers;
            // only the bit layout differs.
            for imm8 in 0..256u16 {
                assert_eq!(vfp_expand_imm(imm8, false), vfp_expand_imm(imm8, true));
                assert_eq!(vfp_compress_imm(vfp_expand_imm(imm8, dbl), dbl), Some(imm8));
            }
        }
        // Not representable: the mantissa has four bits and the exponent three,
        // so nothing outside ±[0.125, 31] and nothing between the 1/16 steps
        // can be encoded — and neither can a zero, an infinity or a NaN.
        for value in [0.0, -0.0, 0.3, 1.1, 0.0625, 32.0, f64::INFINITY, f64::NAN] {
            assert_eq!(vfp_compress_imm(value, false), None, "{value}");
            assert_eq!(vfp_compress_imm(value, true), None, "{value}");
        }
        // `#2.0` and `#-0.75` are the two the manual itself works through.
        check(0xEEF0, 0x0A00, "vmov.f32 s1, #2.0");
        check(0xEEBE, 0x1B08, "vmov.f64 d1, #-0.75");
        // An unrepresentable immediate is refused rather than approximated.
        let bad = insn(
            "vmov.f32",
            "T1",
            &[Operand::FpReg(FpReg::S(0)), Operand::FpImm(0.3)],
        );
        assert_eq!(encode(&bad), None);
    }

    #[test]
    fn generic_coprocessor_prints_the_manuals_syntax() {
        // `CDP{2}<c><q> <coproc>, #<opc1>, <CRd>, <CRn>, <CRm> {,#<opc2>}`
        // (A7.7.22). `<opc2>` is syntactically optional and always printed:
        // omitting it would make two distinct encodings print identically.
        check(0xEE13, 0x27A4, "cdp p7, #1, c2, c3, c4, #5");
        check(0xFE01, 0x0E02, "cdp2 p14, #0, c0, c1, c2, #0");
        // `MCR{2}<c><q> <coproc>, #<opc1>, <Rt>, <CRn>, <CRm>{, #<opc2>}`
        // (A7.7.72) and `MRC` (A7.7.80).
        check(0xEE23, 0x27B4, "mcr p7, #1, r2, c3, c4, #5");
        check(0xFEE1, 0x0E12, "mcr2 p14, #7, r0, c1, c2, #0");
        check(0xEE33, 0x27B4, "mrc p7, #1, r2, c3, c4, #5");
        check(0xFE11, 0x0E12, "mrc2 p14, #0, r0, c1, c2, #0");
        // `<Rt>` of `0b1111` is the APSR flags, not `pc` (A7.7.80).
        check(0xEE11, 0xFE72, "mrc p14, #0, apsr_nzcv, c1, c2, #3");
        // `MCRR{2}<c><q> <coproc>, #<opc1>, <Rt>, <Rt2>, <CRm>` (A7.7.73),
        // `MRRC` (A7.7.81).
        check(0xEC43, 0x2714, "mcrr p7, #1, r2, r3, c4");
        check(0xFC41, 0x0E02, "mcrr2 p14, #0, r0, r1, c2");
        check(0xEC53, 0x2714, "mrrc p7, #1, r2, r3, c4");
        check(0xFC51, 0x0E02, "mrrc2 p14, #0, r0, r1, c2");
    }

    #[test]
    fn coprocessor_load_store_prints_every_addressing_form() {
        // The four syntaxes of A7.7.39, plus the `L` and `2` suffixes.
        check(0xED92, 0x1702, "ldc p7, c1, [r2, #8]");
        check(0xED52, 0x1702, "ldcl p7, c1, [r2, #-8]");
        check(0xFD90, 0x0E00, "ldc2 p14, c0, [r0]");
        check(0xFDD0, 0x0E01, "ldc2l p14, c0, [r0, #4]");
        check(0xEDB2, 0x1702, "ldc p7, c1, [r2, #8]!");
        check(0xECB2, 0x1702, "ldc p7, c1, [r2], #8");
        check(0xEC32, 0x1702, "ldc p7, c1, [r2], #-8");
        // Unindexed: `imm8` is an opaque `<option>`, not an offset.
        check(0xEC92, 0x170C, "ldc p7, c1, [r2], {12}");
        check(0xEC82, 0x17FF, "stc p7, c1, [r2], {255}");
        // `LDC (literal)`, A7.7.40: the manual writes `<label>`, which this
        // crate spells as the syntactic `[pc, #imm]` plus the resolved address.
        check(0xED9F, 0x1704, "ldc p7, c1, [pc, #16], 0x1014");
        // A post-indexed zero offset is a distinct encoding, and now prints
        // as one: the writeback is the whole point of the mode, so the `#0`
        // is not omitted the way the offset form's is.
        check(0xECA0, 0x0000, "stc p0, c0, [r0], #0");
        check(0xED80, 0x0000, "stc p0, c0, [r0]");
        let post = decode(0xECA0, 0x0000, ADDR).unwrap();
        let offset = decode(0xED80, 0x0000, ADDR).unwrap();
        assert_ne!(post, offset);
        // Spelled out rather than `matches!(…, AddrMode::PostIndex)`: the
        // whole `Mem` is the claim — a post-indexed `#0` differs from the
        // offset form in the mode alone, so the other five fields have to be
        // asserted equal for the claim to mean anything.
        assert_eq!(
            post.operands.get(2),
            Some(Operand::Mem(Mem {
                base: Reg(0),
                index: None,
                offset: 0,
                add: true,
                align: 0,
                mode: AddrMode::PostIndex,
            }))
        );
        // And `#-0`, which A7.7.39 names as a different instruction from `#0`:
        // `U == 0` with `imm8 == 0`, in each of the three indexed forms.
        check(0xED10, 0x0000, "ldc p0, c0, [r0, #-0]");
        check(0xED30, 0x0000, "ldc p0, c0, [r0, #-0]!");
        check(0xEC30, 0x0000, "ldc p0, c0, [r0], #-0");
        // `STC{2}{L}<c><q> <coproc>,<CRd>,[<Rn>{,#+/-<imm>}]` (A7.7.158).
        check(0xED82, 0x1702, "stc p7, c1, [r2, #8]");
        check(0xED42, 0x1E02, "stcl p14, c1, [r2, #-8]");
        check(0xFD80, 0x0E00, "stc2 p14, c0, [r0]");
        check(0xFDC0, 0x0E00, "stc2l p14, c0, [r0]");
    }

    #[test]
    fn extension_register_load_store_prints_the_manuals_syntax() {
        // `VLDR{<c>}{<q>}{.32} <Sd>, [<Rn> {, #+/-<imm>}]` (A7.7.236) and
        // `VSTR` (A7.7.259).
        check(0xEDD2, 0x0A02, "vldr s1, [r2, #8]");
        check(0xED12, 0x3B02, "vldr d3, [r2, #-8]");
        check(0xED90, 0x0A00, "vldr s0, [r0]");
        check(0xED8D, 0x8AFF, "vstr s16, [sp, #1020]");
        check(0xEDC0, 0x1B01, "vstr d17, [r0, #4]");
        // The literal form, as for `LDC` above.
        check(0xEDDF, 0x0A04, "vldr s1, [pc, #16], 0x1014");
        // `VLDM{<mode>}{<c>}{<q>}{.<size>} <Rn>{!}, <list>` (A7.7.235) and
        // `VSTM` (A7.7.258). `IA` is the default and is spelled out here, as
        // every disassembler does, so that the two modes read alike.
        check(0xECD2, 0x0A04, "vldmia r2, {s1-s4}");
        check(0xECB2, 0x1B06, "vldmia r2!, {d1-d3}");
        check(0xED72, 0x2A02, "vldmdb r2!, {s5-s6}");
        check(0xEC82, 0x0B04, "vstmia r2, {d0-d1}");
        check(0xED22, 0x4B08, "vstmdb r2!, {d4-d7}");
        // A one-register list keeps its braces: A6.2.3 permits dropping them,
        // but assemblers in practice do not accept that spelling here.
        check(0xECA2, 0x0A01, "vstmia r2!, {s0}");
    }

    #[test]
    fn register_ranges_print_and_round_trip() {
        // `VPUSH{<c>}{<q>}{.<size>} <list>` (A7.7.252) and `VPOP` (A7.7.251),
        // with the range spelling of A6.2.3.
        check(0xED2D, 0x0A04, "vpush {s0-s3}");
        check(0xECBD, 0x2B08, "vpop {d2-d5}");
        check(0xED2D, 0x0B20, "vpush {d0-d15}");
        check(0xECFD, 0xFA01, "vpop {s31}");
        // Every legal single-precision range, both directions.
        let mut ranges = 0usize;
        for first in 0..32u16 {
            for regs in 1..=(32 - first) {
                let hw1 = 0xED2D | ((first & 1) << 6);
                let hw2 = ((first >> 1) << 12) | 0x0A00 | regs;
                let insn = round_trip(hw1, hw2).expect("a legal single-precision list");
                assert_eq!(insn.mnemonic, "vpush");
                ranges += 1;
            }
        }
        // And every legal double-precision one.
        for first in 0..32u16 {
            for regs in 1..=16.min(32 - first) {
                let hw1 = 0xECBD | ((first >> 4) << 6);
                let hw2 = ((first & 0xF) << 12) | 0x0B00 | (regs * 2);
                let insn = round_trip(hw1, hw2).expect("a legal double-precision list");
                assert_eq!(insn.mnemonic, "vpop");
                ranges += 1;
            }
        }
        assert_eq!(ranges, 528 + 392);
        // A list that runs off the end of the bank is UNPREDICTABLE, and a
        // doubleword list of more than sixteen registers likewise.
        assert!(decode(0xECFD, 0xFA02, ADDR).is_none());
        assert!(decode(0xECBD, 0x0B22, ADDR).is_none());
        // An odd `imm8` in a doubleword list is the obsolete `FLDMX`.
        assert!(decode(0xECB2, 0x1B03, ADDR).is_none());
    }

    #[test]
    fn three_register_data_processing_prints_the_manuals_syntax() {
        check(0xEE71, 0x0A21, "vadd.f32 s1, s2, s3"); // A7.7.225
        check(0xEE32, 0x1B03, "vadd.f64 d1, d2, d3");
        check(0xEE71, 0x0A61, "vsub.f32 s1, s2, s3"); // A7.7.260
        check(0xEE61, 0x0BA2, "vmul.f64 d16, d17, d18"); // A7.7.248
        check(0xEE61, 0x0A61, "vnmul.f32 s1, s2, s3"); // A7.7.250 T2
        check(0xEE82, 0x1B03, "vdiv.f64 d1, d2, d3"); // A7.7.232
        check(0xEE41, 0x0A21, "vmla.f32 s1, s2, s3"); // A7.7.238
        check(0xEE41, 0x0A61, "vmls.f32 s1, s2, s3");
        check(0xEE12, 0x1B43, "vnmla.f64 d1, d2, d3"); // A7.7.250 T1
        check(0xEE51, 0x0A21, "vnmls.f32 s1, s2, s3");
        check(0xEEE1, 0x0A21, "vfma.f32 s1, s2, s3"); // A7.7.233
        check(0xEEA2, 0x1B43, "vfms.f64 d1, d2, d3");
        check(0xEED1, 0x0A61, "vfnma.f32 s1, s2, s3"); // A7.7.234
        check(0xEE92, 0x1B03, "vfnms.f64 d1, d2, d3");
        check(0xFEC1, 0x0A21, "vmaxnm.f32 s1, s2, s3"); // A7.7.237
        check(0xFE82, 0x1B43, "vminnm.f64 d1, d2, d3");
        // `VSEL<c>.F32 <Sd>, <Sn>, <Sm>` (A7.7.256), whose condition is part
        // of the operation and so is spelled into the mnemonic.
        check(0xFE41, 0x0A21, "vseleq.f32 s1, s2, s3");
        check(0xFE51, 0x0A21, "vselvs.f32 s1, s2, s3");
        check(0xFE22, 0x1B03, "vselge.f64 d1, d2, d3");
        check(0xFE71, 0x0A21, "vselgt.f32 s1, s2, s3");
    }

    #[test]
    fn two_register_data_processing_prints_the_manuals_syntax() {
        check(0xEEF0, 0x0AC1, "vabs.f32 s1, s2"); // A7.7.224
        check(0xEEB1, 0x1B42, "vneg.f64 d1, d2"); // A7.7.249
        check(0xEEF1, 0xFACF, "vsqrt.f32 s31, s30"); // A7.7.257
        check(0xEEF0, 0x0A41, "vmov.f32 s1, s2"); // A7.7.240
        check(0xEEF0, 0x1B42, "vmov.f64 d17, d2");
        // `VCMP{E}{<c>}{<q>}.F32 <Sd>, <Sm>` and the `#0.0` form (A7.7.226).
        check(0xEEF4, 0x0A41, "vcmp.f32 s1, s2");
        check(0xEEB4, 0x1BC2, "vcmpe.f64 d1, d2");
        check(0xEEF5, 0x1B40, "vcmp.f64 d17, #0.0");
        check(0xEEF5, 0x0AC0, "vcmpe.f32 s1, #0.0");
        // `VRINT<r>{<q>}.F32 <Sd>, <Sm>` — A7.7.253, A7.7.254, A7.7.255.
        check(0xFEF8, 0x0A41, "vrinta.f32 s1, s2");
        check(0xFEB9, 0x1B42, "vrintn.f64 d1, d2");
        check(0xFEFA, 0x0A41, "vrintp.f32 s1, s2");
        check(0xFEBB, 0x1B42, "vrintm.f64 d1, d2");
        check(0xEEF7, 0x0A41, "vrintx.f32 s1, s2");
        check(0xEEB6, 0x1BC2, "vrintz.f64 d1, d2");
        check(0xEEF6, 0x0A41, "vrintr.f32 s1, s2");
    }

    #[test]
    fn conversions_print_both_of_their_types() {
        // `VCVT{R}{<c>}{<q>}.S32.F32 <Sd>, <Sm>` (A7.7.228): the destination
        // is a single-precision register holding an integer, whatever the
        // source's precision.
        check(0xEEFD, 0x0AC1, "vcvt.s32.f32 s1, s2");
        check(0xEEFC, 0x0B42, "vcvtr.u32.f64 s1, d2");
        check(0xEEF8, 0x0AC1, "vcvt.f32.s32 s1, s2");
        check(0xEEB8, 0x1B41, "vcvt.f64.u32 d1, s2");
        // `VCVT{<c>}{<q>}.F64.F32 <Dd>, <Sm>` (A7.7.230).
        check(0xEEB7, 0x1AC1, "vcvt.f64.f32 d1, s2");
        check(0xEEF7, 0x0BC2, "vcvt.f32.f64 s1, d2");
        // `VCVT{<c>}{<q>}.<Td>.F32 <Sd>, <Sd>, #<fbits>` (A7.7.229).
        check(0xEEFE, 0x0A66, "vcvt.s16.f32 s1, s1, #3");
        check(0xEEBB, 0x1B64, "vcvt.f64.u16 d1, d1, #7");
        check(0xEEBF, 0x0AC0, "vcvt.u32.f32 s0, s0, #0x20");
        // `VCVT<y>{<c>}{<q>}.F32.F16 <Sd>, <Sm>` (A7.7.231).
        check(0xEEF2, 0x0A41, "vcvtb.f32.f16 s1, s2");
        check(0xEEF3, 0x0AC1, "vcvtt.f16.f32 s1, s2");
        check(0xEEB2, 0x1B41, "vcvtb.f64.f16 d1, s2");
        check(0xEEF3, 0x0BC2, "vcvtt.f16.f64 s1, d2");
        // `VCVT<r>{<q>}.<Tm>.F64 <Sd>, <Dm>` (A7.7.227).
        check(0xFEFC, 0x2AC3, "vcvta.s32.f32 s5, s6");
        check(0xFEFD, 0x2B46, "vcvtn.u32.f64 s5, d6");
        check(0xFEFE, 0x2BC6, "vcvtp.s32.f64 s5, d6");
        check(0xFEFF, 0x2A43, "vcvtm.u32.f32 s5, s6");
    }

    #[test]
    fn core_register_transfers_print_the_manuals_syntax() {
        // `VMOV{<c>}{<q>} <Sn>, <Rt>` / `<Rt>, <Sn>` (A7.7.243).
        check(0xEE03, 0x4A90, "vmov s7, r4");
        check(0xEE13, 0x4A90, "vmov r4, s7");
        // `VMOV{<c>}{<q>}{.<size>} <Dd[x]>, <Rt>` (A7.7.241, A7.7.242).
        check(0xEE23, 0x4B10, "vmov.32 d3[1], r4");
        check(0xEE13, 0x4B10, "vmov.32 r4, d3[0]");
        // `VMOV{<c>}{<q>} <Sm>, <Sm1>, <Rt>, <Rt2>` (A7.7.244).
        check(0xEC41, 0x0A32, "vmov s5, s6, r0, r1");
        check(0xEC51, 0x0A32, "vmov r0, r1, s5, s6");
        // `VMOV{<c>}{<q>} <Dm>, <Rt>, <Rt2>` (A7.7.245).
        check(0xEC41, 0x0B19, "vmov d9, r0, r1");
        check(0xEC51, 0x0B19, "vmov r0, r1, d9");
        // `VMSR{<c>}{<q>} FPSCR, <Rt>` (A7.7.247).
        check(0xEEE1, 0x5A10, "vmsr fpscr, r5");
    }

    #[test]
    fn vmrs_apsr_nzcv_is_the_idiom_that_follows_vcmp() {
        // `VMRS{<c>}{<q>} <Rt>, FPSCR`, where `<Rt>` of `0b1111` is spelled
        // `APSR_nzcv` and moves the FPSCR's N, Z, C and V to the APSR's
        // (A7.7.246) — the instruction that turns a `VCMP` into something an
        // integer conditional branch can test, and so the commonest
        // floating-point instruction in compiled code after the arithmetic.
        check(0xEEF1, 0xFA10, "vmrs apsr_nzcv, fpscr");
        check(0xEEF1, 0x5A10, "vmrs r5, fpscr");
        // The A/R profile's other special registers (DDI 0406B B6.1.14);
        // DDI 0403E.e pins this field to FPSCR and leaves the rest reserved.
        check(0xEEF8, 0x0A10, "vmrs r0, fpexc");
        check(0xEEF0, 0x0A10, "vmrs r0, fpsid");
        assert!(decode(0xEEF2, 0x0A10, ADDR).is_none());
        // `VMSR` writes only FPSID, FPSCR and FPEXC (DDI 0406B B6.1.15), and
        // `APSR_nzcv` is a destination only for FPSCR (B6.1.14).
        check(0xEEE8, 0x0A10, "vmsr fpexc, r0");
        assert!(decode(0xEEE7, 0x0A10, ADDR).is_none());
        assert!(decode(0xEEF8, 0xFA10, ADDR).is_none());
        // The `(0)` bits are part of the pattern: this is the same `vmrs`
        // with `hw2[5]` set, which is UNPREDICTABLE and cannot round-trip.
        assert!(decode(0xEEF1, 0x5A30, ADDR).is_none());
    }

    #[test]
    fn outside_the_group_is_not_ours() {
        // One halfword below the group, and the `op2 == 0b0xxxxxx` half of
        // the same `op1` — both belong to other modules.
        assert!(decode(0xEBFF, 0x0000, ADDR).is_none());
        assert!(decode(0xE800, 0x0000, ADDR).is_none());
        assert!(decode(0xF800, 0x0000, ADDR).is_none());
        // Advanced SIMD data-processing (`op1 == 0b11xxxx`) is `t32_simd`'s,
        // for both values of `T`.
        assert!(decode(0xEF00, 0x0B10, ADDR).is_none());
        assert!(decode(0xFF00, 0x0B10, ADDR).is_none());
        // `op1 == 0b00000x` is UNDEFINED (Table A5-30).
        assert!(decode(0xEC00, 0x0700, ADDR).is_none());
        assert!(decode(0xEC10, 0x0700, ADDR).is_none());
        // The floating-point rows are all `T == 0`: `1111 110…` and
        // `1111 1110 …` with `coproc == 0b101x` are UNDEFINED (A6.5, A6.6).
        assert!(decode(0xFC92, 0x0B04, ADDR).is_none());
        assert!(decode(0xFE03, 0x4A90, ADDR).is_none());
        // `VDUP` and the 8- and 16-bit scalar `VMOV`s are Advanced SIMD; only
        // the 32-bit element size is the floating-point extension's.
        // `VDUP.32` (`A == 0b1xx`), `VMOV.8` (`opc1[1] == 1`) and `VMOV.16`
        // (`opc2 == 0b01`), in that order.
        assert!(decode(0xEE83, 0x4B10, ADDR).is_none());
        assert!(decode(0xEE43, 0x4B10, ADDR).is_none());
        assert!(decode(0xEE23, 0x4B30, ADDR).is_none());
        // `VDIV` has no second operation: `opc3[0] == 1` there is UNDEFINED.
        assert!(decode(0xEE82, 0x1B43, ADDR).is_none());
        // An encoder that is handed a sibling's instruction must decline.
        let alien = insn("add", "T3", &[Operand::Reg(Reg(0)), Operand::Reg(Reg(1))]);
        assert_eq!(encode(&alien), None);
        // …and one of ours with the wrong encoding name, or a flag set, or a
        // narrow width, must not encode either.
        let good = decode(0xEE71, 0x0A21, ADDR).unwrap();
        let mut wrong = good;
        wrong.encoding = "T2";
        assert_eq!(encode(&wrong), None);
        let mut flagged = good;
        flagged.sets_flags = true;
        assert_eq!(encode(&flagged), None);
        let mut narrow = good;
        narrow.width = Width::Narrow;
        assert_eq!(encode(&narrow), None);
    }

    #[test]
    fn encode_rejects_operands_the_encoding_cannot_hold() {
        // A `.f32` mnemonic with double-precision registers, and the reverse:
        // the mnemonic's type suffix and `sz` must agree, since it is `sz`
        // that decides how the register halves concatenate.
        let mixed = insn(
            "vadd.f32",
            "T1",
            &[
                Operand::FpReg(FpReg::D(0)),
                Operand::FpReg(FpReg::D(1)),
                Operand::FpReg(FpReg::D(2)),
            ],
        );
        assert_eq!(encode(&mixed), None);
        // Advanced SIMD quadword registers have no place in this group at all.
        let quad = insn(
            "vabs.f64",
            "T1",
            &[Operand::FpReg(FpReg::Q(0)), Operand::FpReg(FpReg::Q(1))],
        );
        assert_eq!(encode(&quad), None);
        // A register-indexed address: no coprocessor form has one.
        let indexed = insn(
            "ldc",
            "T1",
            &[
                Operand::Coproc(7),
                Operand::CoprocReg(1),
                Operand::Mem(Mem {
                    base: Reg(2),
                    index: Some((Reg(3), None)),
                    offset: 0,
                    add: true,
                    align: 0,
                    mode: AddrMode::Offset,
                }),
            ],
        );
        assert_eq!(encode(&indexed), None);
        // An offset that is not a multiple of four, and one that overflows the
        // 8-bit field.
        for offset in [6u32, 1024] {
            for add in [true, false] {
                let mem = Operand::Mem(Mem {
                    base: Reg(2),
                    index: None,
                    offset,
                    add,
                    align: 0,
                    mode: AddrMode::Offset,
                });
                let bad = insn("vldr", "T2", &[Operand::FpReg(FpReg::S(0)), mem]);
                assert_eq!(encode(&bad), None, "offset {offset} add {add}");
            }
        }
        // `<fbits>` outside the range the field can hold (A7.7.229). What
        // goes in the encoding is `imm4:i == size - <fbits>`, five bits wide,
        // and `size` is 32 here because `sx == 1` — so the legal range is
        // `#1` to `#32`, and *both* ends have to be refused. `#33` makes the
        // field -1. `#0` makes it 32, which is the one that bites: 32 is a
        // six-bit value, `imm4` takes `hw2[3:0]` and `i` takes `hw2[5]`, so
        // the carry lands on `hw2[4]` — a should-be-zero bit — and the
        // halfwords read back as `#32` fraction bits, not `#0`. Note the
        // asymmetry with the 16-bit forms, where `sx == 0` makes `size` 16 and
        // `#0` is the legal bottom of the range (pinned in the decode
        // direction below); the bound is not a property of the mnemonic
        // alone.
        for frac in [0i64, 33] {
            let fbits = insn(
                "vcvt.s32.f32",
                "T1",
                &[
                    Operand::FpReg(FpReg::S(0)),
                    Operand::FpReg(FpReg::S(0)),
                    Operand::Imm(frac),
                ],
            );
            assert_eq!(encode(&fbits), None, "fbits #{frac}");
        }
        // A doubleword list of seventeen registers: `regs > 16` is
        // UNPREDICTABLE, and the encoding has nowhere to put it.
        let long = insn("vpush", "T1", &[Operand::Text(D_RANGES[0][16])]);
        assert_eq!(encode(&long), None);
        // A list that is not a list at all.
        let bogus = insn("vpop", "T1", &[Operand::Text("{q0-q1}")]);
        assert_eq!(encode(&bogus), None);
        // `MCR` has no `APSR_nzcv` destination — only `MRC` does.
        let mcr = insn(
            "mcr",
            "T1",
            &[
                Operand::Coproc(14),
                Operand::Imm(0),
                Operand::SpecialReg("apsr_nzcv"),
                Operand::CoprocReg(1),
                Operand::CoprocReg(2),
                Operand::Imm(3),
            ],
        );
        assert_eq!(encode(&mcr), None);
    }

    #[test]
    fn writeback_and_stack_forms_do_not_overlap() {
        // Table A6-7 gives `01x11` with `Rn == 1101` to `VPOP` and `10x10`
        // with `Rn == 1101` to `VPUSH`, so `vldmia sp!` and `vstmdb sp!` are
        // not encodable: they are those instructions under another name, and
        // allowing both spellings would break the round trip.
        let list = Operand::Text(S_RANGES[0][3]);
        let pop = insn("vldmia", "T2", &[Operand::Text(WRITEBACK[13]), list]);
        assert_eq!(encode(&pop), None);
        let push = insn("vstmdb", "T2", &[Operand::Text(WRITEBACK[13]), list]);
        assert_eq!(encode(&push), None);
        // Decrement Before without writeback has no encoding at all.
        let db = insn("vldmdb", "T2", &[Operand::Reg(Reg(2)), list]);
        assert_eq!(encode(&db), None);
        // But the same list on another base register is ordinary `VLDMIA`.
        let ia = insn("vldmia", "T2", &[Operand::Text(WRITEBACK[2]), list]);
        assert_eq!(encode(&ia), Some((0xECB2, 0x0A04)));
    }

    #[test]
    fn encode_checks_every_operand_position_and_the_operand_count() {
        // `Operand::RegList` is a kind no encoding in this module decodes to,
        // so substituting it is a probe for "was this position looked at at
        // all". An encoder that validated only the operands it happens to read
        // first would accept a mangled list and emit halfwords for an
        // instruction the caller never described — into firmware.
        let alien = Operand::RegList(0b11);
        for (hw1, hw2) in ENCODERS.iter().chain(CONVERSIONS.iter()) {
            let (hw1, hw2) = (*hw1, *hw2);
            let insn = dec(hw1, hw2);
            for i in 0..insn.operands.len() {
                let mangled = replacing(&insn, i, alien);
                assert_eq!(
                    encode(&mangled),
                    None,
                    "operand {i} of {hw1:#06x} {hw2:#06x} ({insn}) is not checked"
                );
            }
            // An operand appended past the end is the same claim about the
            // position after the last one, which is the one an encoder that
            // reads a fixed set of indices forgets.
            if insn.operands.len() < MAX_OPERANDS {
                let mut longer = insn;
                longer.operands.push(alien);
                assert_eq!(
                    encode(&longer),
                    None,
                    "a trailing operand on {hw1:#06x} {hw2:#06x} ({insn}) is ignored"
                );
                if insn.operands.len() + 1 < MAX_OPERANDS {
                    longer.operands.push(alien);
                    assert_eq!(encode(&longer), None, "{hw1:#06x} {hw2:#06x}");
                }
            }
            // Dropping the last operand may name a *different* legal
            // instruction — `ldc p7, c1, [r2], {12}` without its `<option>` is
            // `ldc p7, c1, [r2]` — so the claim here is the weaker true one:
            // the operand list is load-bearing, and a shorter one must not
            // re-encode to the bytes the longer one came from.
            let mut shorter = insn;
            shorter.operands = insn
                .operands
                .as_slice()
                .take(insn.operands.len() - 1)
                .collect();
            assert_ne!(
                encode(&shorter),
                Some((hw1, hw2)),
                "{hw1:#06x} {hw2:#06x} ({insn}) re-encodes with an operand missing"
            );
        }
    }

    #[test]
    fn encode_requires_the_architectural_encoding_name_to_match() {
        // `Insn::encoding` is not a label: it is `hw1[12]` for the generic
        // coprocessor forms (the `2` suffix), the precision for the extension
        // register transfers, and the row of Table A6-5 for data processing.
        // Every encoding in this group is T1 or T2, and no instruction here is
        // both, so flipping the name always names something this instruction
        // is not.
        for (hw1, hw2) in ENCODERS.iter().chain(CONVERSIONS.iter()) {
            let (hw1, hw2) = (*hw1, *hw2);
            let insn = dec(hw1, hw2);
            let mut renamed = insn;
            renamed.encoding = if insn.encoding == "T1" { "T2" } else { "T1" };
            assert_eq!(
                encode(&renamed),
                None,
                "{hw1:#06x} {hw2:#06x} ({insn}) encodes under the wrong encoding name"
            );
        }
    }

    #[test]
    fn encode_requires_every_register_to_match_the_precision_its_field_implies() {
        // Table A6-4: an extension register number is a 4-bit field and a
        // 1-bit field concatenated in *opposite orders* for the two
        // precisions. So `sz` is not a decoration on the mnemonic — it decides
        // which register the same bits name, and `s1` and `s16` differ only in
        // which way round they are read. An operation handed a register of the
        // other precision therefore has no encoding at all; taking the number
        // anyway would silently name a different register.
        for (hw1, hw2) in ENCODERS.iter().chain(CONVERSIONS.iter()) {
            let (hw1, hw2) = (*hw1, *hw2);
            let insn = dec(hw1, hw2);
            for i in 0..insn.operands.len() {
                let swapped = match insn.operands.get(i) {
                    Some(Operand::FpReg(FpReg::S(n))) => Operand::FpReg(FpReg::D(n)),
                    Some(Operand::FpReg(FpReg::D(n))) => Operand::FpReg(FpReg::S(n)),
                    _ => continue,
                };
                let mangled = replacing(&insn, i, swapped);
                assert_eq!(
                    encode(&mangled),
                    None,
                    "operand {i} of {hw1:#06x} {hw2:#06x} ({insn}) took the wrong precision"
                );
            }
        }
    }

    #[test]
    fn encode_refuses_the_first_number_past_the_end_of_each_field() {
        // Every one of these operands is carried in a `u8` but named by a
        // field narrower than a `u8`: `s0`–`s31` and `d0`–`d31` in five bits,
        // `p0`–`p15` and `c0`–`c15` in four. The interesting value is the
        // first one past the end, because it is not a wrap-around onto a
        // neighbouring register — the surplus bit spills sideways into a
        // *control* bit of the same halfword, and the result is a valid
        // encoding of a different instruction rather than a rejection.
        //
        // `d32` is the sharpest case. A double-precision number splits as
        // `D:Vd` (Table A6-4), so 32 is `D == 0b10`, `Vd == 0b0000`, and in
        // `VLDR`/`VSTR` `D` sits at `hw1[6]` with the `U` — add/subtract —
        // bit immediately above it at `hw1[7]`. Taking `d32` would emit
        // `vldr d0, [r2, #-8]` for `vldr d32, [r2, #8]`: a load from the
        // wrong side of the base register.
        //
        // The coprocessor numbers spill the same way. `coproc` is `hw2[11:8]`,
        // so `p16` lands on `hw2[12]`, the bottom of `CRd`/`Rt`, and
        // `cdp p16, #1, c2, c3, c4, #5` would assemble as
        // `cdp p0, #1, c3, …`. `CRn` is `hw1[3:0]`, so `c16` lands on
        // `hw1[4]`, the bottom of `opc1`; `CRm` is `hw2[3:0]`, so `c16` lands
        // on `hw2[4]`, which is the single bit that tells `CDP` from `MCR`
        // (A7.7.22 against A7.7.72) — a whole different instruction, sent to
        // the coprocessor with a core register in place of `CRd`.
        for (hw1, hw2) in ENCODERS.iter().chain(CONVERSIONS.iter()) {
            let (hw1, hw2) = (*hw1, *hw2);
            let insn = dec(hw1, hw2);
            for i in 0..insn.operands.len() {
                // The substitution keeps the operand's kind and precision, so
                // that the refusal can only have come from the number: an
                // `s`-register stays an `s`-register, a scalar stays a scalar.
                let past_the_end = match insn.operands.get(i) {
                    Some(Operand::FpReg(FpReg::S(_))) => Operand::FpReg(FpReg::S(32)),
                    Some(Operand::FpReg(FpReg::D(_))) => Operand::FpReg(FpReg::D(32)),
                    Some(Operand::FpScalar(_, lane)) => Operand::FpScalar(FpReg::D(32), lane),
                    Some(Operand::Coproc(_)) => Operand::Coproc(16),
                    Some(Operand::CoprocReg(_)) => Operand::CoprocReg(16),
                    _ => continue,
                };
                let mangled = replacing(&insn, i, past_the_end);
                assert_eq!(
                    encode(&mangled),
                    None,
                    "operand {i} of {hw1:#06x} {hw2:#06x} ({insn}) overflowed its field"
                );
            }
        }
    }

    #[test]
    fn coprocessor_load_store_encode_refuses_addressing_it_cannot_hold() {
        // `LDC`/`STC` have four addressing forms (A7.7.39) and the encoding
        // holds exactly those. Each case here is a `Mem` or an `<option>` the
        // encoding has nowhere to put.
        let head = [Operand::Coproc(7), Operand::CoprocReg(1)];
        let mem = |mode, offset, add| {
            Operand::Mem(Mem {
                base: Reg(2),
                index: None,
                offset,
                add,
                align: 0,
                mode,
            })
        };
        // `[<Rn>]!` with an implicit increment is Advanced SIMD's addressing
        // mode; no coprocessor form has it.
        let post_inc = insn(
            "ldc",
            "T1",
            &[head[0], head[1], mem(AddrMode::PostIncrement, 0, true)],
        );
        assert_eq!(encode(&post_inc), None);
        // `imm8` is scaled by four: an offset that is not a multiple of four,
        // or that overflows eight bits, is not encodable.
        for offset in [6u32, 1024] {
            let bad = insn(
                "ldc",
                "T1",
                &[head[0], head[1], mem(AddrMode::Offset, offset, true)],
            );
            assert_eq!(encode(&bad), None, "offset {offset}");
        }
        // The unindexed form's `<option>` is an integer in braces (A7.7.158),
        // held in `imm8`; a barrier-style name is not one of the 256.
        let named = insn(
            "ldc",
            "T1",
            &[
                head[0],
                head[1],
                mem(AddrMode::Offset, 0, true),
                Operand::Option("sy"),
            ],
        );
        assert_eq!(encode(&named), None);
        // …and the unindexed form addresses a bare `R[n]`: `index = FALSE`
        // and `wback = FALSE`, so there is no room for an offset, a writeback
        // mode, or a `U` of 0 alongside the `<option>`.
        for bad_mem in [
            mem(AddrMode::Offset, 8, true),
            mem(AddrMode::Offset, 0, false),
            mem(AddrMode::PreIndex, 0, true),
        ] {
            let unindexed = insn(
                "ldc",
                "T1",
                &[head[0], head[1], bad_mem, Operand::Option(OPTIONS[12])],
            );
            assert_eq!(encode(&unindexed), None);
        }
        // `VLDR`/`VSTR` load one single- or one double-precision register
        // (A7.7.236); an Advanced SIMD quadword register is 128 bits and has
        // no encoding anywhere in this group.
        let quad = insn(
            "vldr",
            "T2",
            &[Operand::FpReg(FpReg::Q(0)), mem(AddrMode::Offset, 8, true)],
        );
        assert_eq!(encode(&quad), None);
        // `VLDR`/`VSTR` have one addressing form only — no writeback, no
        // post-indexing (Table A6-7 gives those to `VLDM`/`VSTM`).
        for mode in [
            AddrMode::PreIndex,
            AddrMode::PostIndex,
            AddrMode::PostIncrement,
        ] {
            let bad = insn(
                "vldr",
                "T2",
                &[Operand::FpReg(FpReg::S(0)), mem(mode, 8, true)],
            );
            assert_eq!(encode(&bad), None);
        }
        // A literal `VLDR` carries the address it resolves to; a target that
        // is not the one `Align(PC,4) + imm` gives is a different instruction,
        // so it must not re-encode to this one's halfwords.
        let literal = dec(0xEDDF, 0x0A04);
        assert_eq!(literal.operands.get(2), Some(Operand::Target(0x1014)));
        assert_eq!(
            encode(&replacing(&literal, 2, Operand::Target(0x1018))),
            None
        );
        // And the same for `LDC (literal)` (A7.7.40).
        let ldc_literal = dec(0xED9F, 0x1704);
        assert_eq!(ldc_literal.operands.get(3), Some(Operand::Target(0x1014)));
        assert_eq!(
            encode(&replacing(&ldc_literal, 3, Operand::Target(0x1018))),
            None
        );
    }

    #[test]
    fn special_register_transfers_encode_only_the_named_registers() {
        // `VMRS`/`VMSR` name their special register by a 4-bit `reg` field
        // (DDI 0406B B6.1.14). `FP_SYSREGS` names six of the sixteen values,
        // so ten are reserved and a name outside the table has no encoding.
        //
        // Five of those six are the ones B6.1.14 lists. The sixth, `MVFR2` at
        // `reg == 0b0101`, is not in the shipped A/R manual at all — it is
        // ARMv8, and the M profile reaches it as a memory-mapped register
        // (DDI 0403E.e B4-664) rather than through `VMRS`. It is kept because
        // this decoder implements the union of the profiles, and dropping it
        // would turn a real ARMv8 encoding into `None`; but it is the one row
        // of this table a reader cannot check against `spec/`.
        let unknown = insn(
            "vmrs",
            "T1",
            &[Operand::Reg(Reg(5)), Operand::SpecialReg("fpinst")],
        );
        assert_eq!(encode(&unknown), None);
        // `VMSR` writes only FPSID, FPSCR and FPEXC (DDI 0406B B6.1.15); the
        // media-feature registers are read-only, so `vmsr mvfr0, r0` is not an
        // instruction even though `vmrs r0, mvfr0` is.
        assert_eq!(dec(0xEEF7, 0x0A10).to_string(), "vmrs r0, mvfr0");
        let readonly = insn(
            "vmsr",
            "T1",
            &[Operand::SpecialReg("mvfr0"), Operand::Reg(Reg(0))],
        );
        assert_eq!(encode(&readonly), None);
        // `VMOV.32` addresses one of a *doubleword's* two 32-bit elements
        // (A7.7.241) — so the index is a single bit, and the register the
        // element belongs to is a `d` register. A single-precision register
        // is itself 32 bits and has no elements to index; the encoding has no
        // `sz` bit here to say which kind it was handed.
        let wide_index = insn(
            "vmov.32",
            "T1",
            &[Operand::FpScalar(FpReg::D(3), 2), Operand::Reg(Reg(4))],
        );
        assert_eq!(encode(&wide_index), None);
        let single = insn(
            "vmov.32",
            "T1",
            &[Operand::FpScalar(FpReg::S(3), 0), Operand::Reg(Reg(4))],
        );
        assert_eq!(encode(&single), None);
        // `VMOV <Sm>, <Sm1>, <Rt>, <Rt2>` (A7.7.244) names a *consecutive*
        // pair, because the encoding holds only the first register number.
        let gapped = insn(
            "vmov",
            "T1",
            &[
                Operand::FpReg(FpReg::S(5)),
                Operand::FpReg(FpReg::S(7)),
                Operand::Reg(Reg(0)),
                Operand::Reg(Reg(1)),
            ],
        );
        assert_eq!(encode(&gapped), None);
        // …and the pair cannot run off the end of the bank: `s31, s32` would
        // need a register that does not exist.
        let off_end = insn(
            "vmov",
            "T1",
            &[
                Operand::FpReg(FpReg::S(31)),
                Operand::FpReg(FpReg::S(0)),
                Operand::Reg(Reg(0)),
                Operand::Reg(Reg(1)),
            ],
        );
        assert_eq!(encode(&off_end), None);
    }

    #[test]
    fn multiple_register_transfer_encode_refuses_a_base_that_is_not_one() {
        // `VLDM`/`VSTM`'s base prints as `<Rn>` or `<Rn>!`, the second drawn
        // from `WRITEBACK`; a `Text` that is neither names no register.
        let bogus_base = insn(
            "vldmia",
            "T2",
            &[Operand::Text("sp!!"), Operand::Text(S_RANGES[0][3])],
        );
        assert_eq!(encode(&bogus_base), None);
        // A doubleword list under the single-precision encoding name, and the
        // reverse: T1 is the doubleword list and T2 the singleword one for
        // every encoding in this row (A7.7.235).
        let wrong_enc = insn(
            "vldmia",
            "T1",
            &[Operand::Reg(Reg(2)), Operand::Text(S_RANGES[0][3])],
        );
        assert_eq!(encode(&wrong_enc), None);
    }

    #[test]
    fn core_to_single_transfer_refuses_the_two_bits_its_neighbours_use_as_opc2() {
        // Table A6-8 gives one shape to every 32-bit core/extension transfer:
        // `1110 1110 A L Vn | Rt 101 C B 1 (0)(0)(0)(0)`, with `B` at
        // `hw2[6:5]`. `B` is not spare. In the `VMOV (scalar)` rows (`C == 1`)
        // it is `opc2`, and `opc1:opc2` is what sets the element size — the
        // 8-bit and 16-bit sizes are Advanced SIMD and belong to `t32_simd`.
        // Only in the `VMOV (core ↔ single)` row does A7.7.243 mark it
        // `(0)(0)`.
        //
        // So ignoring `B` here is not a harmless leniency: it is this module
        // claiming halfwords whose format says they are shaped differently,
        // printing `vmov s7, r4` for them, and then re-encoding to `B == 0` —
        // two bits of the image rewritten by a decode/encode round trip that
        // is supposed to be the identity.
        for b in [0x20u16, 0x40, 0x60] {
            assert!(
                decode(0xEE03, 0x4A90 | b, ADDR).is_none(),
                "vmov s7, r4 with B set by {b:#04x} must not decode"
            );
            assert!(
                decode(0xEE13, 0x4A90 | b, ADDR).is_none(),
                "vmov r4, s7 with B set by {b:#04x} must not decode"
            );
        }
        // The same halfwords with `B == 0` are the instruction the row names,
        // so the refusals above are about those two bits and nothing else.
        check(0xEE03, 0x4A90, "vmov s7, r4");
        check(0xEE13, 0x4A90, "vmov r4, s7");
    }

    #[test]
    fn generic_coprocessor_encode_bounds_every_immediate_field() {
        // `<opc1>` and `<opc2>` are bare numbers in UAL, with nothing in the
        // syntax to cap them, so this encoder is the only thing standing
        // between a caller's arithmetic slip and a halfword pair. The fields
        // are narrow and they are *not* all the same width: `CDP`'s `<opc1>`
        // has four bits (A7.7.22) but `MCR`'s has three (A7.7.72), because
        // `L` takes the fourth; `<opc2>` has three everywhere. `#16` is over
        // the top of all of them and `#-1` is under the bottom of all of them,
        // which is what makes one pair of values enough for the whole group.
        //
        // The low end matters as much as the high one, because `op_imm` ends
        // in `v as u16`: an unchecked `#-1` does not stay negative, it becomes
        // `0xFFFF` and every bit of the halfword it is shifted into comes back
        // set. For `CDP` that is `opc1`, `CRn` and the `T` bit that tells
        // `cdp` from `cdp2` — three fields wrong from one bad operand.
        //
        // Only the generic coprocessor forms are swept here: they are the
        // encodings whose immediates go through `op_imm`. `VCVT`'s
        // `#<fbits>` is bounded against its own `<size>` instead, and is
        // checked in `encode_rejects_operands_the_encoding_cannot_hold`.
        for (hw1, hw2) in [
            (0xEE13u16, 0x27A4u16), // cdp p7, #1, c2, c3, c4, #5
            (0xFE01, 0x0E02),       // cdp2 p14, #0, c0, c1, c2, #0
            (0xEE23, 0x27B4),       // mcr p7, #1, r2, c3, c4, #5
            (0xEE33, 0x27B4),       // mrc p7, #1, r2, c3, c4, #5
            (0xEC43, 0x2714),       // mcrr p7, #1, r2, r3, c4
            (0xEC53, 0x2714),       // mrrc p7, #1, r2, r3, c4
        ] {
            let insn = dec(hw1, hw2);
            for i in 0..insn.operands.len() {
                if !matches!(insn.operands.get(i), Some(Operand::Imm(_))) {
                    continue;
                }
                for value in [-1i64, 16] {
                    let mangled = replacing(&insn, i, Operand::Imm(value));
                    assert_eq!(
                        encode(&mangled),
                        None,
                        "operand {i} of {hw1:#06x} {hw2:#06x} ({insn}) accepted #{value}"
                    );
                }
            }
        }
    }

    #[test]
    fn decode_refuses_the_two_unpredictable_register_numbers_the_fields_can_hold() {
        // Both of these are reachable from firmware bytes — they are what the
        // fields say — and both are UNPREDICTABLE rather than undefined, so a
        // decoder that "could not happen" its way past them would print an
        // instruction naming a register that does not exist.

        // `VMOV <Sm>, <Sm1>, <Rt>, <Rt2>` (A7.7.244) encodes only the first of
        // the pair, in `Vm:M`. `Vm:M == 31` would make `<Sm1>` `s32`.
        // `hw1 = 1110 1100 010 0 Rt2`, `hw2 = Rt 1010 0 0 M 1 Vm` with
        // `M = 1`, `Vm = 1111`.
        assert!(decode(0xEC41, 0x2A3F, ADDR).is_none());
        // `Vm:M == 30` is the legal top of the bank, `s30, s31`.
        assert_eq!(dec(0xEC41, 0x2A1F).to_string(), "vmov s30, s31, r2, r1");

        // `VCVT` to fixed point (A7.7.229): `<fbits>` is `size - UInt(imm4:i)`
        // and `size` is 16 when `sx == 0`, so the five-bit field can name a
        // negative fraction width, which the pseudocode calls UNPREDICTABLE.
        // `opc2 = 1010`, `opc3 = 01` (so `sx = hw2[7] = 0`), `imm4:i = 11111`.
        assert!(decode(0xEEBA, 0x0A6F, ADDR).is_none());
        // `imm4:i == size` is the boundary that is still legal: `#0` fraction
        // bits, which A7.7.229 gives as the bottom of the `<fbits>` range.
        assert_eq!(dec(0xEEBA, 0x0A48).to_string(), "vcvt.f32.s16 s0, s0, #0");
    }
}
