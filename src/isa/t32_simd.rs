//! Advanced SIMD (NEON) in its Thumb encodings — ARM DDI 0406B chapter A7,
//! sections A7.4 (data processing) and A7.7 (element or structure load/store).
//!
//! This is an **ARMv7-A/R** extension: it does not exist in the M profile, so
//! nothing here is reachable from ARM DDI 0403E.e and the authority for every
//! claim below is DDI 0406B (the in-tree text dump `spec/ARMv7-AR.txt` is the
//! B edition of the same manual; the bit diagrams are identical except that
//! the B edition predates `VFMA`/`VFMS` and writes the alignment qualifier
//! `@<align>` where the C edition and every assembler write `:<align>`).
//!
//! # The two spaces, and how they are reached
//!
//! * `hw1[15:8] == 0b1111_1001` — A7.7, the element and structure load/stores
//!   (`VLD1`–`VLD4`, `VST1`–`VST4`). This is what [`super::decode_halfwords`]
//!   routes here: `op1 == 0b11` with `op2 == 0b001xxx0`.
//! * `hw1[15:8] == 0b111u_1111` (`0xEF..`/`0xFF..`) — A7.4, Advanced SIMD data
//!   processing, with the `U` bit at `hw1[12]`. Both halves of this space land
//!   in `op2[6] == 1`, which Table A5-9 gives to the coprocessor arm — so
//!   `super::decode_halfwords` offers those halfwords to `t32_coproc` first and
//!   chains here when it declines. That chain is load-bearing: without it every
//!   Advanced SIMD data-processing instruction decodes as `None` no matter how
//!   completely this module implements it, which is what happened until
//!   `super::tests::advanced_simd_is_reachable_through_the_dispatcher` was
//!   written to pin it.
//!
//! # Register numbering
//!
//! Every vector register field is five bits split across two places: the
//! doubleword number is `D:Vd` (`N:Vn`, `M:Vm`), with the single high bit in
//! `hw1`/`hw2` outside the four-bit field. A quadword register is *not* a
//! separate number space: `Qn` occupies `D(2n)` and `D(2n+1)`, so a quadword
//! operand is `D:Vd` divided by two, and `D:Vd` odd — equivalently
//! `Vd<0> == '1'`, which is how the manual's pseudocode spells it — is
//! UNDEFINED wherever `Q == 1`. [`vec`] is the one place that rule lives.
//!
//! # Data types are part of the mnemonic
//!
//! [`Insn::mnemonic`] is a `&'static str`, so `vadd.i32` cannot be assembled at
//! run time from `"vadd"` and `".i32"`. Every family therefore carries a `const`
//! table of *fully spelled* mnemonics indexed by the raw `size` field, with an
//! empty string where the manual leaves the encoding UNDEFINED. That shape is
//! deliberate: each row is four spellings wide because `size` is two bits wide,
//! so a reviewer can lay one row beside one row of Arm's table — and the rows
//! where the two-bit field is not a size at all (the bitwise forms, where it
//! selects `VAND`/`VBIC`/`VORR`/`VORN`, and the floating-point forms, where its
//! high bit is an opcode bit and its low bit is `sz`) need no special case.
//!
//! An empty cell is therefore a *hole* in Arm's table, and never a spelling.
//! Every encoder here searches its table by mnemonic, so each search skips the
//! empty cells explicitly: matching one would hand an `Insn` carrying no
//! mnemonic the encoding of an UNDEFINED instruction — bytes this module's own
//! `decode` refuses to read back.
//!
//! # What is not here
//!
//! * The VFP (floating-point) data-processing space, `A7.5`, and the
//!   core-register transfers of `A7.8`/`A7.9` — `VMOV` between core and
//!   extension registers, `VDUP (ARM core register)`, `VMRS`, `VMSR`, `VLDM`,
//!   `VSTM`, `VLDR`, `VSTR`, `VPUSH`, `VPOP`. Those are the coprocessor
//!   module's, and the boundary is drawn by register class: an operand of this
//!   module is always [`FpReg::D`] or [`FpReg::Q`], never [`FpReg::S`].
//! * `VLD1`/`VST1` and friends in their ARM (A1) encodings — this crate decodes
//!   Thumb only.

use super::{AddrMode, FpReg, Insn, Mem, Operand, Operands, Reg, Width};

/// Build the [`Insn`] shape every encoding in this file shares.
///
/// Wide, unconditional (a Thumb Advanced SIMD instruction is made conditional
/// only by an enclosing `IT` block, which [`super::Decoder`] fills in), and
/// never flag-setting: nothing in Advanced SIMD writes `APSR.{N,Z,C,V}`, and
/// `Display` would print a spurious `s` if `sets_flags` were set.
fn simd(mnemonic: &'static str, encoding: &'static str, addr: u32, operands: Operands) -> Insn {
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

/// The doubleword register number `hi:lo` — the `D:Vd`, `N:Vn` and `M:Vm`
/// splits of A7.3, where the single high bit sits outside the four-bit field.
fn dnum(hi: u16, lo: u16) -> u8 {
    (((hi & 1) << 4) | (lo & 0xF)) as u8
}

/// The register a `D:Vd` value names, as a doubleword or a quadword according
/// to the `Q` bit.
///
/// `None` is the manual's `if Q == '1' && Vd<0> == '1' then UNDEFINED`: a
/// quadword operand must name an even doubleword, because `Qn` *is* the pair
/// `D(2n):D(2n+1)`. Every `Q`-form in A7.4 carries that test, so it lives here
/// once rather than in forty places.
fn vec(q: bool, d: u8) -> Option<FpReg> {
    if q {
        if d & 1 != 0 {
            None
        } else {
            Some(FpReg::Q(d >> 1))
        }
    } else {
        Some(FpReg::D(d))
    }
}

/// The inverse of [`vec`]: the `D:Vd` value that names `reg`, and whether the
/// `Q` bit must be set to mean it.
///
/// [`FpReg::S`] is rejected outright — a single-precision register is the
/// coprocessor/VFP module's business, and accepting one here is how a greedy
/// `encode` steals a sibling's instruction.
fn vec_bits(reg: FpReg) -> Option<(bool, u8)> {
    match reg {
        FpReg::D(n) if n < 32 => Some((false, n)),
        FpReg::Q(n) if n < 16 => Some((true, n << 1)),
        _ => None,
    }
}

/// The vector register at operand `i`, or `None` if that operand is absent or
/// is not a vector register.
fn fp_at(insn: &Insn, i: usize) -> Option<FpReg> {
    match insn.operands.get(i)? {
        Operand::FpReg(r) => Some(r),
        _ => None,
    }
}

/// The immediate at operand `i`.
fn imm_at(insn: &Insn, i: usize) -> Option<i64> {
    match insn.operands.get(i)? {
        Operand::Imm(v) => Some(v),
        _ => None,
    }
}

/// The literal text at operand `i` — the register lists of A7.2, which have no
/// structured [`Operand`] variant; see the note above [`TEXT_W`].
fn text_at(insn: &Insn, i: usize) -> Option<&'static str> {
    match insn.operands.get(i)? {
        Operand::Text(s) => Some(s),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Generated spellings
//
// One thing in this space has to be printed as one operand and cannot be
// assembled at run time, because every string this crate prints is
// `&'static str`: the brace-delimited register list of A7.2 (`{d0-d3}`,
// `{d0[1], d2[1]}`, `{d0[], d1[]}`). It is finite, so it is built once, at
// compile time, into a `static` table of NUL-padded rows; `text_of` hands out a
// `&'static str` borrowed from that table. The cost is about 74 KiB of
// `.rodata` and is the price of `Operand`'s `&'static str` discipline.
//
// The bracketed addressing form of A7.7.1 with its alignment qualifier
// (`[r0:64]!`) used to need a second such table, of all 192 spellings. It does
// not any more: `insn::Mem` carries `align` and `AddrMode::PostIncrement`, so
// that family prints through the same structured operand as every other load
// and store. See `elem_mem`.
// ---------------------------------------------------------------------------

/// The width of one generated row. The longest spelling the table produces is a
/// four-register double-spaced lane list, `{d24[7], d26[7], d28[7], d30[7]}` —
/// 32 bytes.
const TEXT_W: usize = 34;

/// One generated spelling, NUL-padded to [`TEXT_W`]. An all-NUL row means "no
/// such spelling", which is how the list table represents a list that would
/// run past `d31`.
type Text = [u8; TEXT_W];

/// Write the register number `v` as decimal at `at`, returning the buffer and
/// the new position. A `const fn` because the tables are built at compile time.
///
/// One or two digits: the only numbers this prints are doubleword register
/// numbers, and A7.3 gives `D:Vd` five bits, so `v` is at most 31.
const fn put_num(mut buf: Text, mut at: usize, v: u8) -> (Text, usize) {
    if v >= 10 {
        buf[at] = b'0' + v / 10;
        at += 1;
    }
    buf[at] = b'0' + v % 10;
    (buf, at + 1)
}

/// A generated row as a `&'static str`, or `None` for an empty row.
///
/// The bytes are ASCII by construction, so `from_utf8` cannot fail; it is used
/// rather than an unchecked conversion because this crate forbids `unsafe`.
fn text_of(row: &'static Text) -> Option<&'static str> {
    let mut len = 0;
    while len < TEXT_W && row[len] != 0 {
        len += 1;
    }
    if len == 0 {
        return None;
    }
    core::str::from_utf8(&row[..len]).ok()
}

/// The `(count, spacing)` list shapes A7.7 can name: one to four doubleword
/// registers, single- or double-spaced (`{Dd, Dd+2, …}`). `VTBL`'s table list
/// is the single-spaced column of the same set.
const LIST_SHAPES: [(u8, u8); 7] = [(1, 1), (2, 1), (3, 1), (4, 1), (2, 2), (3, 2), (4, 2)];

/// How many suffix forms a list element can have: none (`d0`), all-lanes
/// (`d0[]`), or one of eight lane indices (`d0[0]`–`d0[7]`).
const LIST_SUFFIXES: usize = 10;

/// Rows in [`LIST_TEXT`]: every shape, suffix and base register.
const LIST_ROWS: usize = LIST_SHAPES.len() * LIST_SUFFIXES * 32;

/// Where `(shape, suffix, base)` sits in [`LIST_TEXT`].
const fn list_index(shape: usize, suffix: usize, base: u8) -> usize {
    (shape * LIST_SUFFIXES + suffix) * 32 + base as usize
}

/// One register-list spelling.
///
/// Runs of consecutive registers collapse to a range exactly as
/// [`super::insn`]'s core-register lists do — a run of two prints as
/// `{d0, d1}` and a run of three or more as `{d0-d3}` — which is the
/// flexibility A7.2 Table A7-5 grants ("`{D0-D3}` instead of
/// `{D0,D1,D2,D3}`"). Double-spaced and indexed lists are never collapsed,
/// again following Table A7-5, which offers no alternative spelling for
/// `{D0[3],D2[3]}`.
const fn list_row(count: u8, inc: u8, base: u8, suffix: usize) -> Text {
    let mut buf = [0u8; TEXT_W];
    let mut at = 0;
    buf[at] = b'{';
    at += 1;
    if suffix == 0 && inc == 1 && count >= 3 {
        buf[at] = b'd';
        at += 1;
        let (b, a) = put_num(buf, at, base);
        buf = b;
        at = a;
        buf[at] = b'-';
        at += 1;
        buf[at] = b'd';
        at += 1;
        let (b, a) = put_num(buf, at, base + count - 1);
        buf = b;
        at = a;
    } else {
        let mut i = 0;
        while i < count {
            if i > 0 {
                buf[at] = b',';
                at += 1;
                buf[at] = b' ';
                at += 1;
            }
            buf[at] = b'd';
            at += 1;
            let (b, a) = put_num(buf, at, base + i * inc);
            buf = b;
            at = a;
            if suffix >= 1 {
                buf[at] = b'[';
                at += 1;
                if suffix >= 2 {
                    buf[at] = b'0' + (suffix as u8 - 2);
                    at += 1;
                }
                buf[at] = b']';
                at += 1;
            }
            i += 1;
        }
    }
    buf[at] = b'}';
    buf
}

/// Every register-list spelling A7.7 and `VTBL` can print.
///
/// A row is empty when the list would run past `d31` — the manual's
/// `if d+regs > 32 then UNPREDICTABLE` — so the range check and the spelling
/// come from the same place and cannot disagree.
///
/// Written as a `static` initialiser rather than a `const fn` called from one
/// because the loop below runs at compile time and only at compile time; a
/// function here would be compiled and never executed.
static LIST_TEXT: [Text; LIST_ROWS] = {
    let mut out = [[0u8; TEXT_W]; LIST_ROWS];
    let mut shape = 0;
    while shape < LIST_SHAPES.len() {
        let (count, inc) = LIST_SHAPES[shape];
        let mut suffix = 0;
        while suffix < LIST_SUFFIXES {
            let mut base = 0u8;
            while base < 32 {
                if (base as u16) + (inc as u16) * (count as u16 - 1) < 32 {
                    out[list_index(shape, suffix, base)] = list_row(count, inc, base, suffix);
                }
                base += 1;
            }
            suffix += 1;
        }
        shape += 1;
    }
    out
};

/// The spelling of a `<list>` of `count` doubleword registers starting at
/// `base`, spaced `inc` apart, with `suffix` = 0 for a plain list, 1 for an
/// all-lanes list (`d0[]`) and `2 + x` for lane `x`.
fn list_text(count: u8, inc: u8, base: u8, suffix: u8) -> Option<&'static str> {
    let shape = LIST_SHAPES
        .iter()
        .position(|&(c, i)| c == count && i == inc)?;
    if suffix as usize >= LIST_SUFFIXES || base >= 32 {
        return None;
    }
    text_of(&LIST_TEXT[list_index(shape, suffix as usize, base)])
}

/// The inverse of [`list_text`]: `(count, inc, base, suffix)` for a spelling,
/// found by scanning the generated table, so the two directions cannot drift.
fn list_fields(text: &str) -> Option<(u8, u8, u8, u8)> {
    let want = text.as_bytes();
    // An empty spelling matched no row under the old `text_of`-based scan
    // (which returned `None` for an empty cell), and a byte compare against an
    // empty cell would wrongly match it — so refuse it explicitly.
    if want.is_empty() {
        return None;
    }
    // Still a scan of the generated table, so the two directions cannot drift
    // — but the row is compared as bytes against `LIST_TEXT` directly instead
    // of running `text_of`'s `from_utf8` on every one of the ~2,240 cells. The
    // table holds ASCII, so a byte-equal row is a str-equal row, and the
    // length prefix (`row[..want.len()]` with the next byte a terminator)
    // rejects almost every cell before the comparison.
    if want.len() > TEXT_W {
        return None;
    }
    let mut shape = 0;
    while shape < LIST_SHAPES.len() {
        let (count, inc) = LIST_SHAPES[shape];
        for suffix in 0..LIST_SUFFIXES {
            for base in 0..32u8 {
                let row = &LIST_TEXT[list_index(shape, suffix, base)];
                let terminated = want.len() == TEXT_W || row[want.len()] == 0;
                if terminated && &row[..want.len()] == want {
                    return Some((count, inc, base, suffix as u8));
                }
            }
        }
        shape += 1;
    }
    None
}

/// The address operand of an element or structure load/store —
/// `[<Rn>{:<align>}]{!}` or `[<Rn>{:<align>}], <Rm>` (A7.7.1).
///
/// The three forms are distinguished entirely by `Rm`: `0b1111` means "no
/// writeback", `0b1101` means "increment `Rn` by the transfer size" (the manual
/// notes that `[<Rn>], #<transfer_size>` is accepted on assembly but that
/// disassembly produces the `!` form), and any other value is a register
/// post-increment. `sp` and `pc` are therefore unnameable as `<Rm>`, which is
/// exactly why those two values were free to be stolen.
///
/// This is a structured [`super::Mem`] rather than a `&'static str` drawn from
/// a table of all 192 spellings, which is what an earlier revision printed:
/// `Mem` now carries the alignment qualifier ([`super::Mem::align`], in bits)
/// and the implicit-increment mode ([`AddrMode::PostIncrement`]), so a consumer
/// asking which register this instruction accesses gets a [`Reg`] instead of
/// text to parse.
fn elem_mem(rn: u16, align: u16, rm: u16) -> Mem {
    Mem {
        base: Reg(rn as u8),
        index: if rm == 13 || rm == 15 {
            None
        } else {
            Some((Reg(rm as u8), None))
        },
        offset: 0,
        add: true,
        align,
        mode: match rm {
            15 => AddrMode::Offset,
            13 => AddrMode::PostIncrement,
            _ => AddrMode::PostIndex,
        },
    }
}

/// `(Rn, align, Rm)` for an address operand — the inverse of [`elem_mem`],
/// rejecting any [`Mem`] shape that function cannot produce.
fn elem_fields(mem: &Mem) -> Option<(u16, u16, u16)> {
    if mem.offset != 0 || !mem.add {
        return None;
    }
    let rm = match (mem.mode, mem.index) {
        (AddrMode::Offset, None) => 15,
        (AddrMode::PostIncrement, None) => 13,
        // `sp` and `pc` are the two stolen values, so an `<Rm>` of 13 or 15 is
        // the `!` and the plain form, not a register post-increment.
        (AddrMode::PostIndex, Some((rm, None))) if rm.num() != 13 && rm.num() != 15 => {
            u16::from(rm.num())
        }
        _ => return None,
    };
    Some((u16::from(mem.base.num()), mem.align, rm))
}

// ---------------------------------------------------------------------------
// A7.7 — Advanced SIMD element or structure load/store
//
//   hw1 = 1111 1001 A D L 0 Rn        hw2 = Vd type size align Rm   (A == 0)
//                                     hw2 = Vd size nn index_align Rm
//                                                                   (A == 1)
//
// `A` (hw1[7]) picks multiple-element (Table A7-20/A7-21 row `A == 0`) from
// single-element (`A == 1`); `L` (hw1[5]) picks store from load. In the
// single-element half, `hw2[11:10]` is `size` unless it is `0b11`, which is
// not an element size but the escape to the "to all lanes" forms, where
// `hw2[11:8]` reads `11nn` and the element size moves to `hw2[7:6]`.
// ---------------------------------------------------------------------------

/// `VLD<n>`/`VST<n>` spelled with its element-size suffix, indexed by
/// `[L][n-1][size]`.
///
/// Only the multiple-single-element form (`VLD1`/`VST1`, `type == 0b0111` and
/// friends) has 64-bit elements; everywhere else `size == 0b11` is UNDEFINED
/// or means something other than a size, which is why those cells are empty.
const ELEM_NAMES: [[[&str; 4]; 4]; 2] = [
    [
        ["vst1.8", "vst1.16", "vst1.32", "vst1.64"],
        ["vst2.8", "vst2.16", "vst2.32", ""],
        ["vst3.8", "vst3.16", "vst3.32", ""],
        ["vst4.8", "vst4.16", "vst4.32", ""],
    ],
    [
        ["vld1.8", "vld1.16", "vld1.32", "vld1.64"],
        ["vld2.8", "vld2.16", "vld2.32", ""],
        ["vld3.8", "vld3.16", "vld3.32", ""],
        ["vld4.8", "vld4.16", "vld4.32", ""],
    ],
];

/// One row of the multiple-element half of Tables A7-20 and A7-21, indexed by
/// `type` = `hw2[11:8]`.
struct MultRow {
    /// The structure size: 1 for `VLD1`/`VST1`, …, 4 for `VLD4`/`VST4`. Zero
    /// marks the six `type` values the tables leave UNDEFINED.
    n: u8,
    /// How many doubleword registers `<list>` names.
    count: u8,
    /// Their spacing — 1 for `{Dd, Dd+1, …}`, 2 for `{Dd, Dd+2, …}`.
    inc: u8,
    /// Which `align` values are legal, as a bitmap over `align` 0–3. The three
    /// distinct constraints in the tables are "any", "not `0b11`" (128-bit
    /// alignment needs two or four registers) and "`align<1> == 0`" (a
    /// three-register or three-element transfer can only promise 64 bits).
    align_ok: u8,
    /// Whether `size == 0b11` is a legal element size in this row.
    size64: bool,
}

/// Table A7-20 / A7-21, `A == 0`: the multiple-element forms.
///
/// The `type` encoding is not ordered by structure size — Arm packed the rows
/// so that `type<1:0>` is not the structure size and `VLD1`'s four list
/// lengths are scattered across `0b0111`, `0b1010`, `0b0110` and `0b0010`.
/// The table is therefore the only sane way to read it, and this is it, row
/// for row, with the `<list>` and `<align>` constraints from each
/// instruction's own page (A8.6.307, A8.6.310, A8.6.313, A8.6.316 and their
/// store twins).
const MULT_ROWS: [MultRow; 16] = [
    MultRow {
        n: 4,
        count: 4,
        inc: 1,
        align_ok: 0b1111,
        size64: false,
    }, // 0000 VLD4/VST4 {Dd-Dd+3}
    MultRow {
        n: 4,
        count: 4,
        inc: 2,
        align_ok: 0b1111,
        size64: false,
    }, // 0001 VLD4/VST4 {Dd,+2,+4,+6}
    MultRow {
        n: 1,
        count: 4,
        inc: 1,
        align_ok: 0b1111,
        size64: true,
    }, // 0010 VLD1/VST1 {Dd-Dd+3}
    MultRow {
        n: 2,
        count: 4,
        inc: 1,
        align_ok: 0b1111,
        size64: false,
    }, // 0011 VLD2/VST2 {Dd-Dd+3}
    MultRow {
        n: 3,
        count: 3,
        inc: 1,
        align_ok: 0b0011,
        size64: false,
    }, // 0100 VLD3/VST3 {Dd-Dd+2}
    MultRow {
        n: 3,
        count: 3,
        inc: 2,
        align_ok: 0b0011,
        size64: false,
    }, // 0101 VLD3/VST3 {Dd,+2,+4}
    MultRow {
        n: 1,
        count: 3,
        inc: 1,
        align_ok: 0b0011,
        size64: true,
    }, // 0110 VLD1/VST1 {Dd-Dd+2}
    MultRow {
        n: 1,
        count: 1,
        inc: 1,
        align_ok: 0b0011,
        size64: true,
    }, // 0111 VLD1/VST1 {Dd}
    MultRow {
        n: 2,
        count: 2,
        inc: 1,
        align_ok: 0b0111,
        size64: false,
    }, // 1000 VLD2/VST2 {Dd,Dd+1}
    MultRow {
        n: 2,
        count: 2,
        inc: 2,
        align_ok: 0b0111,
        size64: false,
    }, // 1001 VLD2/VST2 {Dd,Dd+2}
    MultRow {
        n: 1,
        count: 2,
        inc: 1,
        align_ok: 0b0111,
        size64: true,
    }, // 1010 VLD1/VST1 {Dd,Dd+1}
    MultRow {
        n: 0,
        count: 0,
        inc: 0,
        align_ok: 0,
        size64: false,
    }, // 1011 UNDEFINED
    MultRow {
        n: 0,
        count: 0,
        inc: 0,
        align_ok: 0,
        size64: false,
    }, // 1100 UNDEFINED
    MultRow {
        n: 0,
        count: 0,
        inc: 0,
        align_ok: 0,
        size64: false,
    }, // 1101 UNDEFINED
    MultRow {
        n: 0,
        count: 0,
        inc: 0,
        align_ok: 0,
        size64: false,
    }, // 1110 UNDEFINED
    MultRow {
        n: 0,
        count: 0,
        inc: 0,
        align_ok: 0,
        size64: false,
    }, // 1111 UNDEFINED
];

/// The alignment an `align` field of 1–3 denotes, in bits: `4 << UInt(align)`
/// bytes, i.e. 64, 128 or 256 bits (`alignment = if align == '00' then 1 else
/// 4 << UInt(align)`, A8.6.307). `align == 0b00` is "omitted", 0 here.
fn mult_align(align: u16) -> u16 {
    match align {
        1 => 64,
        2 => 128,
        3 => 256,
        _ => 0,
    }
}

/// `index`, register spacing and alignment (in bits) for a single-lane form.
///
/// Transcribed from the `case size of` blocks of A8.6.308, A8.6.311, A8.6.314
/// and A8.6.317 (and their `VST` twins, which are identical), cross-checked
/// against Tables A8-5 to A8-11. This one is pseudocode rather than a table in
/// the manual because no two of the twelve cells constrain `index_align` the
/// same way — `VLD1.32` demands `index_align<1:0>` be `00` or `11`, `VLD4.32`
/// forbids only `11`, `VLD3` forbids every alignment bit — so a literal
/// transcription is what a reviewer can check line for line.
fn lane_fields(n: u8, size: u16, ia: u16) -> Option<(u8, u8, u16)> {
    let (index, inc, align) = match (n, size) {
        (1, 0) => {
            if ia & 1 != 0 {
                return None;
            }
            (ia >> 1, 1, 0)
        }
        (1, 1) => {
            if ia & 2 != 0 {
                return None;
            }
            (ia >> 2, 1, if ia & 1 == 0 { 0 } else { 16 })
        }
        (1, 2) => {
            if ia & 4 != 0 || (ia & 3 != 0 && ia & 3 != 3) {
                return None;
            }
            (ia >> 3, 1, if ia & 3 == 0 { 0 } else { 32 })
        }
        (2, 0) => (ia >> 1, 1, if ia & 1 == 0 { 0 } else { 16 }),
        (2, 1) => (
            ia >> 2,
            if ia & 2 == 0 { 1 } else { 2 },
            if ia & 1 == 0 { 0 } else { 32 },
        ),
        (2, 2) => {
            if ia & 2 != 0 {
                return None;
            }
            (
                ia >> 3,
                if ia & 4 == 0 { 1 } else { 2 },
                if ia & 1 == 0 { 0 } else { 64 },
            )
        }
        (3, 0) => {
            if ia & 1 != 0 {
                return None;
            }
            (ia >> 1, 1, 0)
        }
        (3, 1) => {
            if ia & 1 != 0 {
                return None;
            }
            (ia >> 2, if ia & 2 == 0 { 1 } else { 2 }, 0)
        }
        (3, 2) => {
            if ia & 3 != 0 {
                return None;
            }
            (ia >> 3, if ia & 4 == 0 { 1 } else { 2 }, 0)
        }
        (4, 0) => (ia >> 1, 1, if ia & 1 == 0 { 0 } else { 32 }),
        (4, 1) => (
            ia >> 2,
            if ia & 2 == 0 { 1 } else { 2 },
            if ia & 1 == 0 { 0 } else { 64 },
        ),
        // `(4, 2)`, the twelfth and last cell: `n` is `(b & 3) + 1` and
        // `size` is `b >> 2` taken where `b < 0b1100`, so 1-4 by 0-2 is the
        // whole domain and nothing else can arrive here.
        _ => {
            if ia & 3 == 3 {
                return None;
            }
            (
                ia >> 3,
                if ia & 4 == 0 { 1 } else { 2 },
                match ia & 3 {
                    1 => 64,
                    2 => 128,
                    _ => 0,
                },
            )
        }
    };
    Some((index as u8, inc, align))
}

/// Element size (as a `size`-field value) and alignment for a "to all lanes"
/// form, from the `T` and `a` bits.
///
/// A8.6.309, A8.6.312, A8.6.315 and A8.6.318. `VLD4`'s `size == 0b11` is the
/// one place in the architecture where that value means 32-bit elements: it
/// exists only to spell the 128-bit alignment, and requires `a == 1`.
fn all_lanes_fields(n: u8, size: u16, a: bool) -> Option<(u16, u16)> {
    // `n` is `(b & 3) + 1`, so the four arms below are its whole range.
    match n {
        1 => {
            if size == 3 || (size == 0 && a) {
                return None;
            }
            Some((size, if a { 8 << size } else { 0 }))
        }
        2 => {
            if size == 3 {
                return None;
            }
            Some((size, if a { 16 << size } else { 0 }))
        }
        3 => {
            if size == 3 || a {
                return None;
            }
            Some((size, 0))
        }
        _ => {
            if size == 3 {
                // A8.6.320: `if size == '11' && a == '0' then UNDEFINED`, and
                // `<align>` lists 128 as "available only if <size> is 32,
                // encoded as a = 1, size = 0b11". So `size == 0b11` is the
                // 32-bit element size *spelled to ask for 16-byte alignment*,
                // and the `a` bit that asks for it is required, not forbidden.
                // Reading the condition the other way round refuses the only
                // legal `:128` form and decodes the UNDEFINED one as if it
                // were that form.
                if !a {
                    return None;
                }
                Some((2, 128))
            } else if size == 2 {
                Some((2, if a { 64 } else { 0 }))
            } else {
                Some((size, if a { 32 << size } else { 0 }))
            }
        }
    }
}

/// Assemble the operands of an element or structure transfer: the register
/// list and the address, which [`elem_mem`] builds from `Rn`, the alignment
/// qualifier and `Rm`.
///
/// Two operands, always — the post-increment register is the [`Mem`]'s index,
/// so `[r0:64], r3` is one operand and prints as one.
fn elem_operands(list: &'static str, rn: u16, align: u16, rm: u16) -> Operands {
    let mut ops = Operands::new();
    ops.push(Operand::Text(list));
    ops.push(Operand::Mem(elem_mem(rn, align, rm)));
    ops
}

/// Decode an element or structure load/store — A7.7, `hw1[15:8] == 0xF9`.
fn decode_elem(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 & 0x0010 != 0 {
        return None; // hw1[4] is not part of any encoding in this space
    }
    let a = (hw1 >> 7) & 1;
    let l = ((hw1 >> 5) & 1) as usize;
    let rn = hw1 & 0xF;
    let d = dnum((hw1 >> 6) & 1, hw2 >> 12);
    let rm = hw2 & 0xF;

    if a == 0 {
        // Multiple-element: `type size align`.
        let row = &MULT_ROWS[((hw2 >> 8) & 0xF) as usize];
        if row.n == 0 {
            return None;
        }
        let size = (hw2 >> 6) & 3;
        if size == 3 && !row.size64 {
            return None;
        }
        let align = (hw2 >> 4) & 3;
        if row.align_ok & (1 << align) == 0 {
            return None;
        }
        // `size == 3` has just been confined to the rows that spell a `.64`
        // form, and no other cell of `ELEM_NAMES` is empty, so the spelling
        // below always exists — see `every_reachable_element_spelling_exists`.
        let name = ELEM_NAMES[l][row.n as usize - 1][size as usize];
        let list = list_text(row.count, row.inc, d, 0)?;
        let ops = elem_operands(list, rn, mult_align(align), rm);
        return Some(simd(name, "T1", addr, ops));
    }

    let b = (hw2 >> 8) & 0xF;
    let n = ((b & 3) + 1) as u8;
    if b & 0b1100 == 0b1100 {
        // "To all lanes" — loads only: Table A7-20 has no `1_11xx` row.
        if l == 0 {
            return None;
        }
        let (size, align) = all_lanes_fields(n, (hw2 >> 6) & 3, hw2 & 0x10 != 0)?;
        // `T` means two different things: for `VLD1` it doubles the *number*
        // of registers written (`regs = if T == '0' then 1 else 2`, A8.6.309),
        // and for `VLD2`–`VLD4` it doubles the *spacing* between them
        // (`inc = if T == '0' then 1 else 2`). Both spellings are two, three
        // or four registers wide; only `VLD1`'s grows.
        let t = (hw2 & 0x20 != 0) as u8;
        let (count, inc) = if n == 1 { (1 + t, 1) } else { (n, 1 + t) };
        // `all_lanes_fields` never yields `size == 3`, so the spelling exists.
        let name = ELEM_NAMES[l][n as usize - 1][size as usize];
        let list = list_text(count, inc, d, 1)?;
        let ops = elem_operands(list, rn, align, rm);
        return Some(simd(name, "T1", addr, ops));
    }

    // Single element to/from one lane: `size nn index_align`.
    let size = b >> 2;
    let (index, inc, align) = lane_fields(n, size, (hw2 >> 4) & 0xF)?;
    // `b < 0b1100` here, so `size` is at most 2 and the spelling exists.
    let name = ELEM_NAMES[l][n as usize - 1][size as usize];
    let list = list_text(n, inc, d, 2 + index)?;
    let ops = elem_operands(list, rn, align, rm);
    Some(simd(name, "T1", addr, ops))
}

/// Re-encode an element or structure load/store.
///
/// The `type` and `index_align` fields are inverted by scanning their (4-bit)
/// value space and re-running the forward decode helpers, so the two
/// directions are the same tables read in two orders and cannot disagree.
/// Both fields are injective in what they encode, so the scan has exactly one
/// hit and there is no canonicalisation choice to make.
fn encode_elem(insn: &Insn) -> Option<(u16, u16)> {
    // An empty cell is a hole in Arm's table, not a mnemonic: matching one
    // would hand an instruction with no mnemonic an UNDEFINED encoding.
    let (l, n, size) = ELEM_NAMES.iter().enumerate().find_map(|(l, per_n)| {
        per_n.iter().enumerate().find_map(|(i, per_size)| {
            per_size
                .iter()
                .position(|&s| !s.is_empty() && s == insn.mnemonic)
                .map(|size| (l, i as u8 + 1, size as u16))
        })
    })?;

    let (count, inc, base, suffix) = list_fields(text_at(insn, 0)?)?;
    // The operand is read before the arity is checked, so that an absent one
    // and one of the wrong kind are the same refusal rather than two, one of
    // which could never be reached.
    let mem = match insn.operands.get(1) {
        Some(Operand::Mem(m)) => m,
        _ => return None,
    };
    if insn.operands.len() != 2 {
        return None;
    }
    let (rn, align, rm) = elem_fields(&mem)?;

    let hw1 = 0xF900 | (((base as u16) >> 4) << 6) | ((l as u16) << 5) | rn;
    let hw2_base = (((base as u16) & 0xF) << 12) | rm;

    if suffix == 0 {
        // Multiple-element.
        let want = (0..4u16).find(|&w| mult_align(w) == align)?;
        // `size == 3` reaches this only as `vld1.64`/`vst1.64`, and every row
        // with `n == 1` takes 64-bit elements, so `size64` needs no re-test.
        let ty = MULT_ROWS.iter().position(|r| {
            r.n == n && r.count == count && r.inc == inc && r.align_ok & (1 << want) != 0
        })?;
        return Some((
            hw1,
            hw2_base | ((ty as u16) << 8) | (size << 6) | (want << 4),
        ));
    }

    if suffix == 1 {
        // To all lanes. See the note in `decode_elem` on what `T` means.
        if l == 0 {
            return None;
        }
        let t_set = if n == 1 {
            if inc != 1 || count > 2 {
                return None;
            }
            count == 2
        } else {
            if count != n {
                return None;
            }
            inc == 2
        };
        for raw_size in 0..4u16 {
            for a in [false, true] {
                if all_lanes_fields(n, raw_size, a) == Some((size, align)) {
                    let t = if t_set { 0x20 } else { 0 };
                    let hw2 = hw2_base
                        | ((0b1100 | (n as u16 - 1)) << 8)
                        | (raw_size << 6)
                        | t
                        | if a { 0x10 } else { 0 };
                    return Some((hw1 | 0x0080, hw2));
                }
            }
        }
        return None;
    }

    // Single element to/from one lane.
    if count != n || size == 3 {
        return None;
    }
    let index = suffix - 2;
    for ia in 0..16u16 {
        if lane_fields(n, size, ia) == Some((index, inc, align)) {
            let hw2 = hw2_base | (((size << 2) | (n as u16 - 1)) << 8) | (ia << 4);
            return Some((hw1 | 0x0080, hw2));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// A7.4 — Advanced SIMD data processing
//
//   hw1 = 111 U 1111 A(23) D size/… Vn      hw2 = Vd opc N Q M op Vm
//
// Table A7-8's three selector fields, translated to Thumb halfword bits:
//   A (bits 23:19) = hw1[7] and hw1[5:3]
//   B (bits 11:8)  = hw2[11:8]
//   C (bits 7:4)   = hw2[7:4]
// and the U bit, which the manual puts at bit 24 in ARM and at hw1[12] in
// Thumb — the one field whose position differs between the two instruction
// sets (A7.4).
// ---------------------------------------------------------------------------

/// Dispatch Table A7-8.
///
/// Read top to bottom this is: bit 23 clear is the three-registers-of-the-
/// same-length space; bit 23 set splits on `C<0>` (hw2[4]) into the immediate
/// forms and the register forms; within the immediate forms `L:imm6<5:3>`
/// (hw2[7] and hw1[5:3]) all zero is the modified-immediate escape; within the
/// register forms `size == 0b11` leaves the long/wide and by-scalar rows and
/// opens the miscellaneous block.
///
/// `hw1[11:8]` is `0b1111` in everything that reaches here: [`decode`] routes
/// on `hw1[15:8]`, and the only two values it gives this function are `0xEF`
/// and `0xFF`.
fn decode_dp(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 & 0x0080 == 0 {
        return decode_same3(hw1, hw2, addr);
    }
    if hw2 & 0x0010 != 0 {
        // `L:imm3` — hw2[7] and hw1[5:3], Arm's `imm6<5:3>` — all zero is the
        // one-register-and-modified-immediate block (A7.4.4's opening note).
        if is_modimm_escape((hw2 >> 7) & 1, hw1 & 0x3F) {
            return decode_modimm(hw1, hw2, addr);
        }
        return decode_shift(hw1, hw2, addr);
    }
    if hw1 & 0x0030 != 0x0030 {
        return if hw2 & 0x0040 == 0 {
            decode_diff(hw1, hw2, addr)
        } else {
            decode_scalar(hw1, hw2, addr)
        };
    }
    if hw1 & 0x1000 == 0 {
        return decode_vext(hw1, hw2, addr);
    }
    match (hw2 >> 8) & 0xF {
        0b0000..=0b0111 => decode_misc(hw1, hw2, addr),
        0b1000..=0b1011 => decode_vtbl(hw1, hw2, addr),
        // Table A7-8 spells this row `1100 0xx0`: the fixed bit is C<3>
        // (hw2[7]), not C<2>, which is `VDUP`'s own `Q`.
        0b1100 if hw2 & 0x0080 == 0 => decode_vdup(hw1, hw2, addr),
        _ => None,
    }
}

/// Re-encode a data-processing instruction, trying each sub-table in turn.
///
/// The order matters only where one mnemonic spans two sub-tables — `vqshl.s8`
/// is both a register shift (Table A7-9) and an immediate shift (Table A7-12),
/// `vmul.i16` is both a vector multiply and a by-scalar multiply — and in
/// every such case the families are told apart by operand *shape*, not by
/// name, so each encoder validates its own shape and declines otherwise.
fn encode_dp(insn: &Insn) -> Option<(u16, u16)> {
    encode_same3(insn)
        .or_else(|| encode_shift(insn))
        .or_else(|| encode_modimm(insn))
        .or_else(|| encode_misc(insn))
        .or_else(|| encode_diff(insn))
        .or_else(|| encode_scalar(insn))
        .or_else(|| encode_vext(insn))
        .or_else(|| encode_vtbl(insn))
        .or_else(|| encode_vdup(insn))
}

/// `<mnemonic>.<t>8`, `.<t>16`, `.<t>32` and an UNDEFINED `size == 0b11`.
macro_rules! t3 {
    ($m:literal, $t:literal) => {
        [
            concat!($m, ".", $t, "8"),
            concat!($m, ".", $t, "16"),
            concat!($m, ".", $t, "32"),
            "",
        ]
    };
}

/// `<mnemonic>.<t>8` … `.<t>64` — the rows whose element size runs to 64.
macro_rules! t4 {
    ($m:literal, $t:literal) => {
        [
            concat!($m, ".", $t, "8"),
            concat!($m, ".", $t, "16"),
            concat!($m, ".", $t, "32"),
            concat!($m, ".", $t, "64"),
        ]
    };
}

/// A floating-point row whose `size<1>` is an opcode bit choosing between two
/// mnemonics and whose `size<0>` is `sz`, which must be 0 (`sz == 1` is the
/// double-precision encoding, UNDEFINED in Advanced SIMD).
macro_rules! f2 {
    ($a:literal, $b:literal) => {
        [concat!($a, ".f32"), "", concat!($b, ".f32"), ""]
    };
}

/// A floating-point row with a single mnemonic: `size` must be `0b00`.
macro_rules! f1 {
    ($a:literal) => {
        [concat!($a, ".f32"), "", "", ""]
    };
}

/// A row available only for 16- and 32-bit signed elements — the saturating
/// doubling multiplies.
macro_rules! s1632 {
    ($m:literal) => {
        ["", concat!($m, ".s16"), concat!($m, ".s32"), ""]
    };
}

/// A row Table A7-9 (or A7-10, A7-11, A7-12) leaves UNDEFINED.
const UNDEF4: [&str; 4] = ["", "", "", ""];

/// Table A7-9 — three registers of the same length — indexed by
/// `U:opc:B`, that is `hw1[12]`, `hw2[11:8]` and `hw2[4]`, with each row's
/// four cells selected by the raw two-bit `size` field `hw1[5:4]`.
///
/// The `size` field is not always a size, and that is the point of giving
/// every row four cells: in the bitwise row (`opc == 0b0001`, `B == 1`) it
/// selects the *operation*, and in the floating-point rows its high bit is an
/// opcode bit and its low bit is `sz`. An empty cell is UNDEFINED.
///
/// The only doubleword-only rows in the whole table are the three pairwise
/// forms — `VPADD`, `VPMAX`, `VPMIN`, for which `Q == 1` is UNDEFINED
/// (A8.6.349, A8.6.352, A8.6.353) — and they are exactly the rows whose
/// mnemonic begins `vp`, so no separate shape column is needed.
const SAME3: [[&str; 4]; 64] = [
    t3!("vhadd", "s"),                // U=0 opc=0000 B=0  VHADD    A8.6.306
    t4!("vqadd", "s"),                // U=0 opc=0000 B=1  VQADD    A8.6.357
    t3!("vrhadd", "s"),               // U=0 opc=0001 B=0  VRHADD   A8.6.374
    ["vand", "vbic", "vorr", "vorn"], // U=0 opc=0001 B=1  A8.6.276/278/347/345
    t3!("vhsub", "s"),                // U=0 opc=0010 B=0  VHSUB    A8.6.306
    t4!("vqsub", "s"),                // U=0 opc=0010 B=1  VQSUB    A8.6.369
    t3!("vcgt", "s"),                 // U=0 opc=0011 B=0  VCGT     A8.6.284
    t3!("vcge", "s"),                 // U=0 opc=0011 B=1  VCGE     A8.6.282
    t4!("vshl", "s"),                 // U=0 opc=0100 B=0  VSHL     A8.6.383
    t4!("vqshl", "s"),                // U=0 opc=0100 B=1  VQSHL    A8.6.366
    t4!("vrshl", "s"),                // U=0 opc=0101 B=0  VRSHL    A8.6.375
    t4!("vqrshl", "s"),               // U=0 opc=0101 B=1  VQRSHL   A8.6.364
    t3!("vmax", "s"),                 // U=0 opc=0110 B=0  VMAX     A8.6.321
    t3!("vmin", "s"),                 // U=0 opc=0110 B=1  VMIN     A8.6.321
    t3!("vabd", "s"),                 // U=0 opc=0111 B=0  VABD     A8.6.267
    t3!("vaba", "s"),                 // U=0 opc=0111 B=1  VABA     A8.6.266
    t4!("vadd", "i"),                 // U=0 opc=1000 B=0  VADD     A8.6.271
    t3!("vtst", ""),                  // U=0 opc=1000 B=1  VTST     A8.6.408
    t3!("vmla", "i"),                 // U=0 opc=1001 B=0  VMLA     A8.6.323
    t3!("vmul", "i"),                 // U=0 opc=1001 B=1  VMUL     A8.6.337
    t3!("vpmax", "s"),                // U=0 opc=1010 B=0  VPMAX    A8.6.352
    t3!("vpmin", "s"),                // U=0 opc=1010 B=1  VPMIN    A8.6.352
    s1632!("vqdmulh"),                // U=0 opc=1011 B=0  VQDMULH  A8.6.359
    t3!("vpadd", "i"),                // U=0 opc=1011 B=1  VPADD    A8.6.349
    UNDEF4,                           // U=0 opc=1100 B=0
    f2!("vfma", "vfms"),              // U=0 opc=1100 B=1  VFMA/VFMS (DDI 0406C)
    f2!("vadd", "vsub"),              // U=0 opc=1101 B=0  A8.6.272 / A8.6.402
    f2!("vmla", "vmls"),              // U=0 opc=1101 B=1  VMLA/VMLS A8.6.324
    f1!("vceq"),                      // U=0 opc=1110 B=0  VCEQ     A8.6.280
    UNDEF4,                           // U=0 opc=1110 B=1
    f2!("vmax", "vmin"),              // U=0 opc=1111 B=0  VMAX/VMIN A8.6.322
    f2!("vrecps", "vrsqrts"),         // U=0 opc=1111 B=1  A8.6.372 / A8.6.379
    t3!("vhadd", "u"),                // U=1 opc=0000 B=0
    t4!("vqadd", "u"),                // U=1 opc=0000 B=1
    t3!("vrhadd", "u"),               // U=1 opc=0001 B=0
    ["veor", "vbsl", "vbit", "vbif"], // U=1 opc=0001 B=1  A8.6.304 / A8.6.279
    t3!("vhsub", "u"),                // U=1 opc=0010 B=0
    t4!("vqsub", "u"),                // U=1 opc=0010 B=1
    t3!("vcgt", "u"),                 // U=1 opc=0011 B=0
    t3!("vcge", "u"),                 // U=1 opc=0011 B=1
    t4!("vshl", "u"),                 // U=1 opc=0100 B=0
    t4!("vqshl", "u"),                // U=1 opc=0100 B=1
    t4!("vrshl", "u"),                // U=1 opc=0101 B=0
    t4!("vqrshl", "u"),               // U=1 opc=0101 B=1
    t3!("vmax", "u"),                 // U=1 opc=0110 B=0
    t3!("vmin", "u"),                 // U=1 opc=0110 B=1
    t3!("vabd", "u"),                 // U=1 opc=0111 B=0
    t3!("vaba", "u"),                 // U=1 opc=0111 B=1
    t4!("vsub", "i"),                 // U=1 opc=1000 B=0  VSUB     A8.6.401
    t3!("vceq", "i"),                 // U=1 opc=1000 B=1  VCEQ     A8.6.280
    t3!("vmls", "i"),                 // U=1 opc=1001 B=0  VMLS     A8.6.323
    ["vmul.p8", "", "", ""],          // U=1 opc=1001 B=1  VMUL (polynomial)
    t3!("vpmax", "u"),                // U=1 opc=1010 B=0
    t3!("vpmin", "u"),                // U=1 opc=1010 B=1
    s1632!("vqrdmulh"),               // U=1 opc=1011 B=0  VQRDMULH A8.6.363
    UNDEF4,                           // U=1 opc=1011 B=1
    UNDEF4,                           // U=1 opc=1100 B=0
    UNDEF4,                           // U=1 opc=1100 B=1
    f2!("vpadd", "vabd"),             // U=1 opc=1101 B=0  A8.6.350 / A8.6.268
    f1!("vmul"),                      // U=1 opc=1101 B=1  VMUL     A8.6.338
    f2!("vcge", "vcgt"),              // U=1 opc=1110 B=0  A8.6.282 / A8.6.284
    f2!("vacge", "vacgt"),            // U=1 opc=1110 B=1  VACGE    A8.6.270
    f2!("vpmax", "vpmin"),            // U=1 opc=1111 B=0  VPMAX    A8.6.353
    UNDEF4,                           // U=1 opc=1111 B=1
];

/// Whether a row of Table A7-9 is one of the four shift-by-register forms,
/// which name their operands the other way round.
///
/// `VSHL`, `VQSHL`, `VRSHL` and `VQRSHL` (register) are written
/// `{<Qd>,} <Qm>, <Qn>` — the vector *to be shifted* second and the vector of
/// shift amounts third (A8.6.383, A8.6.366, A8.6.375, A8.6.364). Every other
/// row of the table is `{<Qd>,} <Qn>, <Qm>`. The difference is not cosmetic:
/// print them in the usual order and `vshl.s8 d0, d1, d2` claims to shift the
/// wrong register by the wrong amount.
fn shifts_by_register(opc: u16) -> bool {
    matches!(opc, 0b0100 | 0b0101)
}

/// Decode Table A7-9 — three registers of the same length.
fn decode_same3(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let u = (hw1 >> 12) & 1;
    let size = ((hw1 >> 4) & 3) as usize;
    let opc = (hw2 >> 8) & 0xF;
    let b = (hw2 >> 4) & 1;
    let name = SAME3[((u << 5) | (opc << 1) | b) as usize][size];
    if name.is_empty() {
        return None;
    }
    let q = hw2 & 0x0040 != 0;
    if q && name.starts_with("vp") {
        return None;
    }
    let dd = dnum(hw1 >> 6, hw2 >> 12);
    let dn = dnum(hw2 >> 7, hw1);
    let dm = dnum(hw2 >> 5, hw2);
    let mut ops = Operands::new();
    ops.push(Operand::FpReg(vec(q, dd)?));
    // `VMOV (register)` is `VORR` with both source registers the same: the
    // page's own first line is `if !Consistent(M) || !Consistent(Vm) then SEE
    // VORR (register)` (A8.6.327), so the alias is `N:Vn == M:Vm` exactly.
    if name == "vorr" && dn == dm {
        ops.push(Operand::FpReg(vec(q, dm)?));
        return Some(simd("vmov", "T1", addr, ops));
    }
    let (first, second) = if shifts_by_register(opc) {
        (dm, dn)
    } else {
        (dn, dm)
    };
    ops.push(Operand::FpReg(vec(q, first)?));
    ops.push(Operand::FpReg(vec(q, second)?));
    Some(simd(name, "T1", addr, ops))
}

/// Re-encode Table A7-9.
fn encode_same3(insn: &Insn) -> Option<(u16, u16)> {
    let alias = insn.mnemonic == "vmov" && insn.operands.len() == 2;
    let name = if alias { "vorr" } else { insn.mnemonic };
    let (row, size) = SAME3.iter().enumerate().find_map(|(r, cells)| {
        cells
            .iter()
            .position(|&c| !c.is_empty() && c == name)
            .map(|s| (r as u16, s as u16))
    })?;
    let u = row >> 5;
    let opc = (row >> 1) & 0xF;
    let b = row & 1;
    let (qd, dd) = vec_bits(fp_at(insn, 0)?)?;
    let (q1, r1) = vec_bits(fp_at(insn, 1)?)?;
    let (q2, r2) = if alias {
        (q1, r1)
    } else {
        vec_bits(fp_at(insn, 2)?)?
    };
    // The shift-by-register rows print `<Vm>, <Vn>`; see `shifts_by_register`.
    let ((qn, dn), (qm, dm)) = if shifts_by_register(opc) {
        ((q2, r2), (q1, r1))
    } else {
        ((q1, r1), (q2, r2))
    };
    if !alias && insn.operands.len() != 3 {
        return None;
    }
    if qd != qn || qd != qm {
        return None;
    }
    if qd && name.starts_with("vp") {
        return None;
    }
    let hw1 = 0xEF00 | (u << 12) | ((dd as u16 & 0x10) << 2) | (size << 4) | (dn as u16 & 0xF);
    let hw2 = ((dd as u16 & 0xF) << 12)
        | (opc << 8)
        | ((dn as u16 & 0x10) << 3)
        | if qd { 0x0040 } else { 0 }
        | ((dm as u16 & 0x10) << 1)
        | (b << 4)
        | (dm as u16 & 0xF);
    Some((hw1, hw2))
}

/// Which of the five shift-amount decodings a row of Table A7-12 uses.
///
/// The `imm6` field never holds a shift directly: it holds `esize + shift` for
/// a left shift and `2 * esize - shift` for a right shift, so that the element
/// size and the amount share six bits. Which of the five readings applies is a
/// property of the row, not of the field.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ShiftClass {
    /// `<Vd>, <Vm>, #<imm>`, right shift, `L:imm6` sized, amount `1..=esize`.
    Right,
    /// `<Vd>, <Vm>, #<imm>`, left shift, amount `0..=esize-1`.
    Left,
    /// `<Dd>, <Qm>, #<imm>` — the narrowing right shifts. `L` must be 0 and
    /// `hw2[6]` is an opcode bit rather than `Q`.
    Narrow,
    /// `<Qd>, <Dm>, #<imm>` — `VSHLL`, which becomes `VMOVL` at a zero shift.
    Long,
    /// `<Vd>, <Vm>, #<fbits>` — the fixed-point converts, which read `imm6`
    /// as `64 - fbits`.
    Cvt,
}

/// One row of Table A7-12 — two registers and a shift amount.
struct ShiftRow {
    /// Mnemonics indexed by element-size code (0–3 for 8/16/32/64); for the
    /// narrowing rows the index is the *result* size code and the spelling
    /// names the operand size, which is twice it.
    names: [&'static str; 4],
    /// How to read `imm6`.
    class: ShiftClass,
}

/// A right-shift row.
macro_rules! rsh {
    ($names:expr) => {
        ShiftRow {
            names: $names,
            class: ShiftClass::Right,
        }
    };
}
/// A left-shift row.
macro_rules! lsh {
    ($names:expr) => {
        ShiftRow {
            names: $names,
            class: ShiftClass::Left,
        }
    };
}
/// A narrowing row.
macro_rules! nsh {
    ($names:expr) => {
        ShiftRow {
            names: $names,
            class: ShiftClass::Narrow,
        }
    };
}
/// A lengthening row.
macro_rules! lng {
    ($names:expr) => {
        ShiftRow {
            names: $names,
            class: ShiftClass::Long,
        }
    };
}
/// A fixed-point convert row.
macro_rules! cvt {
    ($names:expr) => {
        ShiftRow {
            names: $names,
            class: ShiftClass::Cvt,
        }
    };
}
/// An UNDEFINED row.
macro_rules! ush {
    () => {
        ShiftRow {
            names: UNDEF4,
            class: ShiftClass::Right,
        }
    };
}

/// The narrowing rows' mnemonics, indexed by the *result* element size code —
/// so `.i16` in cell 0 means "eight-bit results, sixteen-bit operands".
macro_rules! n3 {
    ($m:literal, $t:literal) => {
        [
            concat!($m, ".", $t, "16"),
            concat!($m, ".", $t, "32"),
            concat!($m, ".", $t, "64"),
            "",
        ]
    };
}

/// Table A7-12 — two registers and a shift amount — indexed by `U:A:B`, that
/// is `hw1[12]`, `hw2[11:8]` and `hw2[6]`.
///
/// `B` is the `Q` bit in every row except the three narrowing/lengthening ones
/// (`A == 0b1000`, `0b1001`, `0b1010`), where Table A7-12 spends it as an
/// opcode bit. Rows therefore come in identical pairs *except* where the table
/// says otherwise, and a pair that differs is exactly a row where `Q` is not
/// available.
const SHIFT_ROWS: [ShiftRow; 64] = [
    rsh!(t4!("vshr", "s")),             // U=0 A=0000 B=0  VSHR      A8.6.385
    rsh!(t4!("vshr", "s")),             // U=0 A=0000 B=1
    rsh!(t4!("vsra", "s")),             // U=0 A=0001 B=0  VSRA      A8.6.389
    rsh!(t4!("vsra", "s")),             // U=0 A=0001 B=1
    rsh!(t4!("vrshr", "s")),            // U=0 A=0010 B=0  VRSHR     A8.6.376
    rsh!(t4!("vrshr", "s")),            // U=0 A=0010 B=1
    rsh!(t4!("vrsra", "s")),            // U=0 A=0011 B=0  VRSRA     A8.6.380
    rsh!(t4!("vrsra", "s")),            // U=0 A=0011 B=1
    ush!(),                             // U=0 A=0100 B=0  (VSRI is U=1 only)
    ush!(),                             // U=0 A=0100 B=1
    lsh!(t4!("vshl", "i")),             // U=0 A=0101 B=0  VSHL (imm) A8.6.382
    lsh!(t4!("vshl", "i")),             // U=0 A=0101 B=1
    ush!(),                             // U=0 A=0110 B=0  U==0 && op==0 UNDEFINED
    ush!(),                             // U=0 A=0110 B=1
    lsh!(t4!("vqshl", "s")),            // U=0 A=0111 B=0  VQSHL (imm) A8.6.367
    lsh!(t4!("vqshl", "s")),            // U=0 A=0111 B=1
    nsh!(n3!("vshrn", "i")),            // U=0 A=1000 B=0  VSHRN     A8.6.386
    nsh!(n3!("vrshrn", "i")),           // U=0 A=1000 B=1  VRSHRN    A8.6.377
    nsh!(n3!("vqshrn", "s")),           // U=0 A=1001 B=0  VQSHRN    A8.6.368
    nsh!(n3!("vqrshrn", "s")),          // U=0 A=1001 B=1  VQRSHRN   A8.6.365
    lng!(t3!("vshll", "s")),            // U=0 A=1010 B=0  VSHLL/VMOVL A8.6.384/333
    ush!(),                             // U=0 A=1010 B=1
    ush!(),                             // U=0 A=1011 B=0
    ush!(),                             // U=0 A=1011 B=1
    ush!(),                             // U=0 A=1100 B=0
    ush!(),                             // U=0 A=1100 B=1
    ush!(),                             // U=0 A=1101 B=0
    ush!(),                             // U=0 A=1101 B=1
    cvt!(["vcvt.f32.s32", "", "", ""]), // U=0 A=1110 B=0  VCVT A8.6.296
    cvt!(["vcvt.f32.s32", "", "", ""]), // U=0 A=1110 B=1
    cvt!(["vcvt.s32.f32", "", "", ""]), // U=0 A=1111 B=0
    cvt!(["vcvt.s32.f32", "", "", ""]), // U=0 A=1111 B=1
    rsh!(t4!("vshr", "u")),             // U=1 A=0000 B=0
    rsh!(t4!("vshr", "u")),             // U=1 A=0000 B=1
    rsh!(t4!("vsra", "u")),             // U=1 A=0001 B=0
    rsh!(t4!("vsra", "u")),             // U=1 A=0001 B=1
    rsh!(t4!("vrshr", "u")),            // U=1 A=0010 B=0
    rsh!(t4!("vrshr", "u")),            // U=1 A=0010 B=1
    rsh!(t4!("vrsra", "u")),            // U=1 A=0011 B=0
    rsh!(t4!("vrsra", "u")),            // U=1 A=0011 B=1
    rsh!(t4!("vsri", "")),              // U=1 A=0100 B=0  VSRI      A8.6.390
    rsh!(t4!("vsri", "")),              // U=1 A=0100 B=1
    lsh!(t4!("vsli", "")),              // U=1 A=0101 B=0  VSLI      A8.6.387
    lsh!(t4!("vsli", "")),              // U=1 A=0101 B=1
    lsh!(t4!("vqshlu", "s")),           // U=1 A=0110 B=0  VQSHLU    A8.6.367
    lsh!(t4!("vqshlu", "s")),           // U=1 A=0110 B=1
    lsh!(t4!("vqshl", "u")),            // U=1 A=0111 B=0
    lsh!(t4!("vqshl", "u")),            // U=1 A=0111 B=1
    nsh!(n3!("vqshrun", "s")),          // U=1 A=1000 B=0  VQSHRUN   A8.6.368
    nsh!(n3!("vqrshrun", "s")),         // U=1 A=1000 B=1  VQRSHRUN  A8.6.365
    nsh!(n3!("vqshrn", "u")),           // U=1 A=1001 B=0
    nsh!(n3!("vqrshrn", "u")),          // U=1 A=1001 B=1
    lng!(t3!("vshll", "u")),            // U=1 A=1010 B=0
    ush!(),                             // U=1 A=1010 B=1
    ush!(),                             // U=1 A=1011 B=0
    ush!(),                             // U=1 A=1011 B=1
    ush!(),                             // U=1 A=1100 B=0
    ush!(),                             // U=1 A=1100 B=1
    ush!(),                             // U=1 A=1101 B=0
    ush!(),                             // U=1 A=1101 B=1
    cvt!(["vcvt.f32.u32", "", "", ""]), // U=1 A=1110 B=0
    cvt!(["vcvt.f32.u32", "", "", ""]), // U=1 A=1110 B=1
    cvt!(["vcvt.u32.f32", "", "", ""]), // U=1 A=1111 B=0
    cvt!(["vcvt.u32.f32", "", "", ""]), // U=1 A=1111 B=1
];

/// `VSHLL` with a zero shift is `VMOVL` (A8.6.384: "if shift_amount == 0 then
/// SEE VMOVL"), which prints a different mnemonic and drops the `#0` operand.
const VMOVL_NAMES: [[&str; 4]; 2] = [t3!("vmovl", "s"), t3!("vmovl", "u")];

/// Whether `L:imm6<5:3>` is all zero — Table A7-8's escape from the shift
/// block to the one-register-and-modified-immediate block (A7.4.4's opening
/// note), and the one `L:imm6` value that encodes no element size.
fn is_modimm_escape(l: u16, imm6: u16) -> bool {
    l == 0 && imm6 & 0x38 == 0
}

/// The element-size code (0–3 for 8/16/32/64) `L:imm6` encodes: the position
/// of the highest set bit of `L:imm6<5:3>`.
///
/// Total, because the one value that names no size is the escape above, and
/// neither caller asks about it — [`decode_dp`] has already routed that
/// pattern to [`decode_modimm`], and [`encode_shift`]'s scan over `imm6` tests
/// [`is_modimm_escape`] itself.
fn shift_code(l: u16, imm6: u16) -> usize {
    if l != 0 {
        3
    } else if imm6 & 0x20 != 0 {
        2
    } else if imm6 & 0x10 != 0 {
        1
    } else {
        0
    }
}

/// The shift amount `imm6` encodes for `class`, given the element-size code.
///
/// Right shifts count down from twice the element size (`shift = 16 - imm6`
/// for 8-bit elements, and 64 rather than 128 for the 64-bit row, which is the
/// one place the pattern breaks); left shifts count up from it.
///
/// Total, and deliberately so: the amount is always in the range its
/// instruction page permits, because the code and `imm6` are not independent.
/// [`shift_code`] *is* the position of the highest set bit of `L:imm6<5:3>`,
/// so a `code` below 3 pins `imm6` to `[8 << code, 16 << code)` and a `code` of
/// 3 means `L == 1`, where `imm6` is the whole six bits. Read those ranges back
/// through each arm and every one lands inside `1..=esize` (right), `0..esize`
/// (left and long) or `1..=32` (convert, where `imm6<5>` is 1 by A8.6.296).
/// A range test here would be a test that cannot fail; see
/// `shift_amounts_stay_inside_their_instruction_page`.
fn shift_amount(class: ShiftClass, code: usize, imm6: u16) -> u32 {
    let esize = 8u32 << code;
    match class {
        ShiftClass::Right | ShiftClass::Narrow => {
            let base: u32 = if code == 3 { 64 } else { 16 << code };
            base - imm6 as u32
        }
        ShiftClass::Left => imm6 as u32 - if code == 3 { 0 } else { esize },
        ShiftClass::Long => imm6 as u32 - esize,
        ShiftClass::Cvt => 64 - imm6 as u32,
    }
}

/// Decode Table A7-12 — two registers and a shift amount.
fn decode_shift(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let u = (hw1 >> 12) & 1;
    let imm6 = hw1 & 0x3F;
    let row = &SHIFT_ROWS[(((u << 5) | ((hw2 >> 8) & 0xF) << 1) | ((hw2 >> 6) & 1)) as usize];
    let l = (hw2 >> 7) & 1;
    let q = hw2 & 0x0040 != 0;
    let dd = dnum(hw1 >> 6, hw2 >> 12);
    let dm = dnum(hw2 >> 5, hw2);
    // The narrowing, lengthening and fixed-point-convert rows all fix `L` at
    // 0: their element size comes from `imm6` alone.
    if row.class != ShiftClass::Right && row.class != ShiftClass::Left && l != 0 {
        return None;
    }
    let code = if row.class == ShiftClass::Cvt {
        if imm6 & 0x20 == 0 {
            return None; // `imm6 == '0xxxxx'` is UNDEFINED (A8.6.296)
        }
        0
    } else {
        shift_code(l, imm6)
    };
    let name = row.names[code];
    if name.is_empty() {
        return None;
    }
    let amount = shift_amount(row.class, code, imm6);
    let mut ops = Operands::new();
    match row.class {
        ShiftClass::Right | ShiftClass::Left | ShiftClass::Cvt => {
            ops.push(Operand::FpReg(vec(q, dd)?));
            ops.push(Operand::FpReg(vec(q, dm)?));
        }
        ShiftClass::Narrow => {
            ops.push(Operand::FpReg(FpReg::D(dd)));
            ops.push(Operand::FpReg(vec(true, dm)?));
        }
        ShiftClass::Long => {
            ops.push(Operand::FpReg(vec(true, dd)?));
            ops.push(Operand::FpReg(FpReg::D(dm)));
            if amount == 0 {
                // `L` is 0 in a lengthening row, so `code` is at most 2 and
                // `VMOVL_NAMES`' one empty cell — the 64-bit one — is out of
                // reach.
                return Some(simd(VMOVL_NAMES[u as usize][code], "T1", addr, ops));
            }
        }
    }
    ops.push(Operand::Imm(amount as i64));
    Some(simd(name, "T1", addr, ops))
}

/// Re-encode Table A7-12.
fn encode_shift(insn: &Insn) -> Option<(u16, u16)> {
    let movl = VMOVL_NAMES.iter().enumerate().find_map(|(u, n)| {
        n.iter()
            .position(|&c| !c.is_empty() && c == insn.mnemonic)
            .map(|c| (u, c))
    });
    let (row_index, code) = match movl {
        // `VMOVL` re-encodes as the `VSHLL` row it is the zero-shift case of.
        Some((u, code)) => (((u as u16) << 5) | (0b1010 << 1), code),
        None => SHIFT_ROWS.iter().enumerate().find_map(|(r, row)| {
            row.names
                .iter()
                .position(|&c| !c.is_empty() && c == insn.mnemonic)
                .map(|c| (r as u16, c))
        })?,
    };
    let row = &SHIFT_ROWS[row_index as usize];
    let want = if movl.is_some() {
        0
    } else {
        let v = imm_at(insn, 2)?;
        if v < 0 || v > u32::MAX as i64 {
            return None;
        }
        v as u32
    };
    let (qd, dd) = vec_bits(fp_at(insn, 0)?)?;
    let (qm, dm) = vec_bits(fp_at(insn, 1)?)?;
    let q = match row.class {
        ShiftClass::Right | ShiftClass::Left | ShiftClass::Cvt => {
            if qd != qm || insn.operands.len() != 3 {
                return None;
            }
            qd
        }
        ShiftClass::Narrow => {
            if qd || !qm || insn.operands.len() != 3 {
                return None;
            }
            false
        }
        ShiftClass::Long => {
            if !qd || qm || insn.operands.len() != if movl.is_some() { 2 } else { 3 } {
                return None;
            }
            false
        }
    };
    // Invert `imm6` by scanning it: the field is injective in
    // (element size, amount), so the scan has exactly one hit.
    let l = if row.class == ShiftClass::Right || row.class == ShiftClass::Left {
        (code == 3) as u16
    } else {
        0
    };
    let imm6 = (0..64u16).find(|&i| {
        let c = if row.class == ShiftClass::Cvt {
            if i & 0x20 == 0 {
                return false;
            }
            0
        } else {
            if is_modimm_escape(l, i) {
                return false;
            }
            shift_code(l, i)
        };
        c == code && shift_amount(row.class, code, i) == want
    })?;
    let u = row_index >> 5;
    let opc = (row_index >> 1) & 0xF;
    let b = row_index & 1;
    let hw1 = 0xEF80 | (u << 12) | ((dd as u16 & 0x10) << 2) | imm6;
    let hw2 = ((dd as u16 & 0xF) << 12)
        | (opc << 8)
        | (l << 7)
        | if q { 0x0040 } else { (b) << 6 }
        | ((dm as u16 & 0x10) << 1)
        | 0x0010
        | (dm as u16 & 0xF);
    Some((hw1, hw2))
}

/// Table A7-14 — one register and a modified immediate value — indexed by
/// `[op][cmode]`, `op` being `hw2[5]` and `cmode` `hw2[11:8]`.
///
/// The data type in each spelling is the one Table A7-15's `<dt>` column gives
/// for that row, which is what makes the disassembly reassemble to the same
/// encoding: `VMOV.I32 d0,#0xFF` and `VMOV.I8 d0,#0xFF` are different
/// instructions.
const MODIMM_NAMES: [[&str; 16]; 2] = [
    [
        "vmov.i32", // op=0 cmode=0000  imm8
        "vorr.i32", // op=0 cmode=0001
        "vmov.i32", // op=0 cmode=0010  imm8 << 8
        "vorr.i32", // op=0 cmode=0011
        "vmov.i32", // op=0 cmode=0100  imm8 << 16
        "vorr.i32", // op=0 cmode=0101
        "vmov.i32", // op=0 cmode=0110  imm8 << 24
        "vorr.i32", // op=0 cmode=0111
        "vmov.i16", // op=0 cmode=1000  imm8
        "vorr.i16", // op=0 cmode=1001
        "vmov.i16", // op=0 cmode=1010  imm8 << 8
        "vorr.i16", // op=0 cmode=1011
        "vmov.i32", // op=0 cmode=1100  (imm8 << 8)  | 0xFF
        "vmov.i32", // op=0 cmode=1101  (imm8 << 16) | 0xFFFF
        "vmov.i8",  // op=0 cmode=1110
        "vmov.f32", // op=0 cmode=1111
    ],
    [
        "vmvn.i32", // op=1 cmode=0000
        "vbic.i32", // op=1 cmode=0001
        "vmvn.i32", // op=1 cmode=0010
        "vbic.i32", // op=1 cmode=0011
        "vmvn.i32", // op=1 cmode=0100
        "vbic.i32", // op=1 cmode=0101
        "vmvn.i32", // op=1 cmode=0110
        "vbic.i32", // op=1 cmode=0111
        "vmvn.i16", // op=1 cmode=1000
        "vbic.i16", // op=1 cmode=1001
        "vmvn.i16", // op=1 cmode=1010
        "vbic.i16", // op=1 cmode=1011
        "vmvn.i32", // op=1 cmode=1100
        "vmvn.i32", // op=1 cmode=1101
        "vmov.i64", // op=1 cmode=1110  one byte of result per bit of imm8
        "",         // op=1 cmode=1111  UNDEFINED
    ],
];

/// Table A7-15's note d: in every row whose constant is a *shifted* byte, an
/// `imm8` of zero is UNPREDICTABLE — and would also be a second spelling of a
/// constant the unshifted rows already encode, so the encoding space is only
/// injective once these are excluded. [`decode_modimm`] rejects them rather
/// than decode an instruction that cannot re-encode to the bytes it came from.
fn modimm_needs_nonzero(cmode: u16) -> bool {
    matches!(cmode >> 1, 0b001 | 0b010 | 0b011 | 0b101 | 0b110)
}

/// `AdvSIMDExpandImm(op, cmode, imm8)` — Table A7-15, exactly.
///
/// The result is the 64-bit pattern the instruction places in (or ORs into,
/// or BICs out of, or inverts into) each doubleword of its destination. Note
/// that for `VMVN` and `VBIC` this is the value *before* the inversion the
/// operation applies, which is also the value the assembler syntax names:
/// `VMVN.I32 d0,#0xFF` writes `0xFFFFFF00` and encodes `imm8 == 0xFF`.
fn expand_imm(op: u16, cmode: u16, imm8: u8) -> Option<u64> {
    let b = imm8 as u64;
    /// Replicate a 32-bit half into both halves of the doubleword.
    fn rep32(v: u64) -> u64 {
        v | (v << 32)
    }
    /// Replicate a 16-bit quarter into all four.
    fn rep16(v: u64) -> u64 {
        let v = v | (v << 16);
        v | (v << 32)
    }
    Some(match cmode >> 1 {
        0b000 => rep32(b),
        0b001 => rep32(b << 8),
        0b010 => rep32(b << 16),
        0b011 => rep32(b << 24),
        0b100 => rep16(b),
        0b101 => rep16(b << 8),
        0b110 => {
            if cmode & 1 == 0 {
                rep32((b << 8) | 0xFF)
            } else {
                rep32((b << 16) | 0xFFFF)
            }
        }
        _ => {
            if cmode & 1 == 0 && op == 0 {
                // cmode = 0b1110, op = 0: the byte, eight times.
                let v = b | (b << 8);
                let v = v | (v << 16);
                v | (v << 32)
            } else if cmode & 1 == 0 {
                // cmode = 0b1110, op = 1: one byte of result per bit of imm8 —
                // `aaaaaaaa bbbbbbbb …`, the only 64-bit constant in the table.
                let mut v = 0u64;
                for i in 0..8 {
                    if b & (1 << i) != 0 {
                        v |= 0xFFu64 << (i * 8);
                    }
                }
                v
            } else if op == 0 {
                // cmode = 0b1111, op = 0: `aBbbbbbc defgh000 …`, where B is
                // NOT(b) — a single-precision number with a three-bit
                // exponent bias adjustment and a four-bit mantissa.
                let a = (b >> 7) & 1;
                let bb = (b >> 6) & 1;
                let c = (b >> 5) & 1;
                let defgh = b & 0x1F;
                rep32(
                    (a << 31)
                        | ((1 - bb) << 30)
                        | (if bb == 1 { 0x1F << 25 } else { 0 })
                        | (c << 24)
                        | (defgh << 19),
                )
            } else {
                return None; // cmode = 0b1111, op = 1: UNDEFINED
            }
        }
    })
}

/// The immediate operand a modified-immediate mnemonic prints: the element of
/// the expanded pattern, at the width its data type names.
fn modimm_operand(name: &str, imm64: u64) -> Operand {
    if name.ends_with(".i8") {
        Operand::Imm((imm64 & 0xFF) as i64)
    } else if name.ends_with(".i16") {
        Operand::Imm((imm64 & 0xFFFF) as i64)
    } else if name.ends_with(".i32") {
        Operand::Imm((imm64 & 0xFFFF_FFFF) as i64)
    } else if name.ends_with(".f32") {
        Operand::FpImm(f32::from_bits(imm64 as u32) as f64)
    } else {
        // `.i64`: the one width that does not fit `Operand::Imm`'s `i64`
        // unsigned; a pattern with bit 63 set therefore prints as a negative
        // hex constant. The bits round-trip exactly.
        Operand::Imm(imm64 as i64)
    }
}

/// Decode Table A7-14 — one register and a modified immediate value.
fn decode_modimm(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let op = (hw2 >> 5) & 1;
    let cmode = (hw2 >> 8) & 0xF;
    let imm8 = ((((hw1 >> 12) & 1) << 7) | ((hw1 & 7) << 4) | (hw2 & 0xF)) as u8;
    if imm8 == 0 && modimm_needs_nonzero(cmode) {
        return None;
    }
    // Table A7-15's one UNDEFINED cell is `op == 1` with `cmode == 0b1111`,
    // which is the one cell `MODIMM_NAMES` leaves empty; rejecting it here
    // rejects the spelling with it.
    let imm64 = expand_imm(op, cmode, imm8)?;
    let name = MODIMM_NAMES[op as usize][cmode as usize];
    let q = hw2 & 0x0040 != 0;
    let mut ops = Operands::new();
    ops.push(Operand::FpReg(vec(q, dnum(hw1 >> 6, hw2 >> 12))?));
    ops.push(modimm_operand(name, imm64));
    Some(simd(name, "T1", addr, ops))
}

/// Re-encode Table A7-14.
///
/// The inverse of `AdvSIMDExpandImm` is a search rather than a formula, which
/// is how Table A7-15's note b defines it: "if it is available in more than
/// one way, the first entry in this table that can produce it is used". The
/// search is over `cmode` ascending and then `imm8` ascending, and it is
/// confined to the rows whose `<dt>` matches the mnemonic — so `vmov.i8 #0`
/// cannot be captured by the `I32` row that would otherwise take it.
fn encode_modimm(insn: &Insn) -> Option<(u16, u16)> {
    // The operand is read before the arity is checked, so that an absent one
    // and one of the wrong kind are the same refusal rather than two, one of
    // which could never be reached.
    let want = match insn.operands.get(1) {
        Some(v @ Operand::Imm(_)) => v,
        Some(v @ Operand::FpImm(_)) => v,
        _ => return None,
    };
    if insn.operands.len() != 2 {
        return None;
    }
    let (qd, dd) = vec_bits(fp_at(insn, 0)?)?;
    for op in 0..2u16 {
        for cmode in 0..16u16 {
            let name = MODIMM_NAMES[op as usize][cmode as usize];
            // Hoisted out of the `imm8` loop below, where it used to sit
            // *after* `expand_imm`. `name` is a pure function of `(op,
            // cmode)`, so a block whose name does not match the mnemonic can
            // never produce an answer — and testing it inside meant running
            // `expand_imm` up to 256 times per block, 8,192 times per call,
            // to reject every one of them on a condition that was already
            // decided. Skipping the block is behaviour-identical: it cannot
            // change which `(op, cmode, imm8)` triple is returned first.
            if name != insn.mnemonic {
                continue;
            }
            for imm8 in 0..=255u8 {
                if imm8 == 0 && modimm_needs_nonzero(cmode) {
                    continue;
                }
                let got = match expand_imm(op, cmode, imm8) {
                    Some(v) => v,
                    // Table A7-15's UNDEFINED cell, which spells nothing
                    // either, so the name test below would reject it too.
                    None => continue,
                };
                if modimm_operand(name, got) != want {
                    continue;
                }
                let hw1 = 0xEF80
                    | ((imm8 as u16 >> 7) << 12)
                    | ((dd as u16 & 0x10) << 2)
                    | ((imm8 as u16 >> 4) & 7);
                let hw2 = ((dd as u16 & 0xF) << 12)
                    | (cmode << 8)
                    | if qd { 0x0040 } else { 0 }
                    | (op << 5)
                    | 0x0010
                    | (imm8 as u16 & 0xF);
                return Some((hw1, hw2));
            }
        }
    }
    None
}

/// The operand shape of a row of Table A7-13 — two registers, miscellaneous.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MiscShape {
    /// `<Vd>, <Vm>`, both doubleword or both quadword by the `Q` bit.
    Same,
    /// `<Vd>, <Vm>, #0` — the compare-against-zero rows.
    Zero,
    /// `<Dd>, <Qm>` — the narrowing moves and `VCVT.F16.F32`.
    Narrow,
    /// `<Qd>, <Dm>` — `VCVT.F32.F16`.
    Long,
    /// `<Qd>, <Dm>, #<size>` — `VSHLL` at its maximum (element-size) shift,
    /// which is the only shift that does not fit the A7.4.4 encoding.
    LongMax,
}

/// One row of Table A7-13.
struct MiscRow {
    /// Mnemonics indexed by `size` = `hw1[3:2]` (Arm's bits 19:18).
    names: [&'static str; 4],
    /// The operand shape.
    shape: MiscShape,
}

/// A plain `<Vd>, <Vm>` row.
macro_rules! m {
    ($names:expr) => {
        MiscRow {
            names: $names,
            shape: MiscShape::Same,
        }
    };
}
/// A compare-against-zero row.
macro_rules! mz {
    ($names:expr) => {
        MiscRow {
            names: $names,
            shape: MiscShape::Zero,
        }
    };
}
/// A narrowing row.
macro_rules! mn {
    ($names:expr) => {
        MiscRow {
            names: $names,
            shape: MiscShape::Narrow,
        }
    };
}
/// A lengthening row.
macro_rules! ml {
    ($names:expr) => {
        MiscRow {
            names: $names,
            shape: MiscShape::Long,
        }
    };
}
/// The maximum-shift `VSHLL` row.
macro_rules! mx {
    ($names:expr) => {
        MiscRow {
            names: $names,
            shape: MiscShape::LongMax,
        }
    };
}
/// An UNDEFINED row.
macro_rules! mu {
    () => {
        MiscRow {
            names: UNDEF4,
            shape: MiscShape::Same,
        }
    };
}

/// Table A7-13 — two registers, miscellaneous — indexed by `A:B`, where `A` is
/// `hw1[1:0]` (Arm's bits 17:16) and `B` is `hw2[10:6]`.
///
/// `B` is five bits wide in Arm's table because its low bit is `Q` — and in
/// the `A == 0b10` block that low bit stops being `Q` and becomes an opcode
/// bit (`VMOVN` against `VQMOVUN`, signed `VQMOVN` against unsigned), so the
/// index here is Arm's `B` exactly rather than a four-bit opcode with `Q`
/// factored out. Rows that ignore `Q` appear twice, identically.
const MISC_ROWS: [MiscRow; 128] = [
    m!(t3!("vrev64", "")),                    // A=00 B=00000  VREV64  A8.6.373
    m!(t3!("vrev64", "")),                    // A=00 B=00001  VREV64  A8.6.373
    m!(["vrev32.8", "vrev32.16", "", ""]),    // A=00 B=00010  VREV32
    m!(["vrev32.8", "vrev32.16", "", ""]),    // A=00 B=00011  VREV32
    m!(["vrev16.8", "", "", ""]),             // A=00 B=00100  VREV16
    m!(["vrev16.8", "", "", ""]),             // A=00 B=00101  VREV16
    mu!(),                                    // A=00 B=00110
    mu!(),                                    // A=00 B=00111
    m!(t3!("vpaddl", "s")),                   // A=00 B=01000  VPADDL  A8.6.351
    m!(t3!("vpaddl", "s")),                   // A=00 B=01001  VPADDL  A8.6.351
    m!(t3!("vpaddl", "u")),                   // A=00 B=01010  VPADDL
    m!(t3!("vpaddl", "u")),                   // A=00 B=01011  VPADDL
    mu!(),                                    // A=00 B=01100
    mu!(),                                    // A=00 B=01101
    mu!(),                                    // A=00 B=01110
    mu!(),                                    // A=00 B=01111
    m!(t3!("vcls", "s")),                     // A=00 B=10000  VCLS    A8.6.288
    m!(t3!("vcls", "s")),                     // A=00 B=10001  VCLS    A8.6.288
    m!(t3!("vclz", "i")),                     // A=00 B=10010  VCLZ    A8.6.291
    m!(t3!("vclz", "i")),                     // A=00 B=10011  VCLZ    A8.6.291
    m!(["vcnt.8", "", "", ""]),               // A=00 B=10100  VCNT    A8.6.293
    m!(["vcnt.8", "", "", ""]),               // A=00 B=10101  VCNT    A8.6.293
    m!(["vmvn", "", "", ""]),                 // A=00 B=10110  VMVN    A8.6.341
    m!(["vmvn", "", "", ""]),                 // A=00 B=10111  VMVN    A8.6.341
    m!(t3!("vpadal", "s")),                   // A=00 B=11000  VPADAL  A8.6.348
    m!(t3!("vpadal", "s")),                   // A=00 B=11001  VPADAL  A8.6.348
    m!(t3!("vpadal", "u")),                   // A=00 B=11010  VPADAL
    m!(t3!("vpadal", "u")),                   // A=00 B=11011  VPADAL
    m!(t3!("vqabs", "s")),                    // A=00 B=11100  VQABS   A8.6.356
    m!(t3!("vqabs", "s")),                    // A=00 B=11101  VQABS   A8.6.356
    m!(t3!("vqneg", "s")),                    // A=00 B=11110  VQNEG   A8.6.362
    m!(t3!("vqneg", "s")),                    // A=00 B=11111  VQNEG   A8.6.362
    mz!(t3!("vcgt", "s")),                    // A=01 B=00000  VCGT #0 A8.6.285
    mz!(t3!("vcgt", "s")),                    // A=01 B=00001  VCGT #0 A8.6.285
    mz!(t3!("vcge", "s")),                    // A=01 B=00010  VCGE #0 A8.6.283
    mz!(t3!("vcge", "s")),                    // A=01 B=00011  VCGE #0 A8.6.283
    mz!(t3!("vceq", "i")),                    // A=01 B=00100  VCEQ #0 A8.6.281
    mz!(t3!("vceq", "i")),                    // A=01 B=00101  VCEQ #0 A8.6.281
    mz!(t3!("vcle", "s")),                    // A=01 B=00110  VCLE #0 A8.6.287
    mz!(t3!("vcle", "s")),                    // A=01 B=00111  VCLE #0 A8.6.287
    mz!(t3!("vclt", "s")),                    // A=01 B=01000  VCLT #0 A8.6.290
    mz!(t3!("vclt", "s")),                    // A=01 B=01001  VCLT #0 A8.6.290
    mu!(),                                    // A=01 B=01010
    mu!(),                                    // A=01 B=01011
    m!(t3!("vabs", "s")),                     // A=01 B=01100  VABS    A8.6.269
    m!(t3!("vabs", "s")),                     // A=01 B=01101  VABS    A8.6.269
    m!(t3!("vneg", "s")),                     // A=01 B=01110  VNEG    A8.6.342
    m!(t3!("vneg", "s")),                     // A=01 B=01111  VNEG    A8.6.342
    mz!(["", "", "vcgt.f32", ""]),            // A=01 B=10000  VCGT #0 (F32)
    mz!(["", "", "vcgt.f32", ""]),            // A=01 B=10001  VCGT #0 (F32)
    mz!(["", "", "vcge.f32", ""]),            // A=01 B=10010  VCGE #0 (F32)
    mz!(["", "", "vcge.f32", ""]),            // A=01 B=10011  VCGE #0 (F32)
    mz!(["", "", "vceq.f32", ""]),            // A=01 B=10100  VCEQ #0 (F32)
    mz!(["", "", "vceq.f32", ""]),            // A=01 B=10101  VCEQ #0 (F32)
    mz!(["", "", "vcle.f32", ""]),            // A=01 B=10110  VCLE #0 (F32)
    mz!(["", "", "vcle.f32", ""]),            // A=01 B=10111  VCLE #0 (F32)
    mz!(["", "", "vclt.f32", ""]),            // A=01 B=11000  VCLT #0 (F32)
    mz!(["", "", "vclt.f32", ""]),            // A=01 B=11001  VCLT #0 (F32)
    mu!(),                                    // A=01 B=11010
    mu!(),                                    // A=01 B=11011
    m!(["", "", "vabs.f32", ""]),             // A=01 B=11100  VABS (F32)
    m!(["", "", "vabs.f32", ""]),             // A=01 B=11101  VABS (F32)
    m!(["", "", "vneg.f32", ""]),             // A=01 B=11110  VNEG (F32)
    m!(["", "", "vneg.f32", ""]),             // A=01 B=11111  VNEG (F32)
    m!(["vswp", "", "", ""]),                 // A=10 B=00000  VSWP    A8.6.405
    m!(["vswp", "", "", ""]),                 // A=10 B=00001  VSWP    A8.6.405
    m!(t3!("vtrn", "")),                      // A=10 B=00010  VTRN    A8.6.407
    m!(t3!("vtrn", "")),                      // A=10 B=00011  VTRN    A8.6.407
    m!(["vuzp.8", "vuzp.16", "", ""]),        // A=10 B=00100  VUZP    A8.6.409
    m!(["vuzp.8", "vuzp.16", "vuzp.32", ""]), // A=10 B=00101  VUZP    A8.6.409
    m!(["vzip.8", "vzip.16", "", ""]),        // A=10 B=00110  VZIP    A8.6.410
    m!(["vzip.8", "vzip.16", "vzip.32", ""]), // A=10 B=00111  VZIP    A8.6.410
    mn!(["vmovn.i16", "vmovn.i32", "vmovn.i64", ""]), // A=10 B=01000  VMOVN/VQMOVUN A8.6.334/361
    mn!(["vqmovun.s16", "vqmovun.s32", "vqmovun.s64", ""]), // A=10 B=01001  VMOVN/VQMOVUN A8.6.334/361
    mn!(["vqmovn.s16", "vqmovn.s32", "vqmovn.s64", ""]),    // A=10 B=01010  VQMOVN  A8.6.361
    mn!(["vqmovn.u16", "vqmovn.u32", "vqmovn.u64", ""]),    // A=10 B=01011  VQMOVN  A8.6.361
    mx!(["vshll.i8", "vshll.i16", "vshll.i32", ""]),        // A=10 B=01100  VSHLL max A8.6.384 (T2)
    mu!(),                                                  // A=10 B=01101  VSHLL max A8.6.384 (T2)
    mu!(),                                                  // A=10 B=01110
    mu!(),                                                  // A=10 B=01111
    mu!(),                                                  // A=10 B=10000
    mu!(),                                                  // A=10 B=10001
    mu!(),                                                  // A=10 B=10010
    mu!(),                                                  // A=10 B=10011
    mu!(),                                                  // A=10 B=10100
    mu!(),                                                  // A=10 B=10101
    mu!(),                                                  // A=10 B=10110
    mu!(),                                                  // A=10 B=10111
    mn!(["", "vcvt.f16.f32", "", ""]),                      // A=10 B=11000  VCVT .f16.f32 A8.6.299
    mu!(),                                                  // A=10 B=11001  VCVT .f16.f32 A8.6.299
    mu!(),                                                  // A=10 B=11010
    mu!(),                                                  // A=10 B=11011
    ml!(["", "vcvt.f32.f16", "", ""]),                      // A=10 B=11100  VCVT .f32.f16
    mu!(),                                                  // A=10 B=11101  VCVT .f32.f16
    mu!(),                                                  // A=10 B=11110
    mu!(),                                                  // A=10 B=11111
    mu!(),                                                  // A=11 B=00000
    mu!(),                                                  // A=11 B=00001
    mu!(),                                                  // A=11 B=00010
    mu!(),                                                  // A=11 B=00011
    mu!(),                                                  // A=11 B=00100
    mu!(),                                                  // A=11 B=00101
    mu!(),                                                  // A=11 B=00110
    mu!(),                                                  // A=11 B=00111
    mu!(),                                                  // A=11 B=01000
    mu!(),                                                  // A=11 B=01001
    mu!(),                                                  // A=11 B=01010
    mu!(),                                                  // A=11 B=01011
    mu!(),                                                  // A=11 B=01100
    mu!(),                                                  // A=11 B=01101
    mu!(),                                                  // A=11 B=01110
    mu!(),                                                  // A=11 B=01111
    m!(["", "", "vrecpe.u32", ""]),                         // A=11 B=10000  VRECPE  A8.6.371
    m!(["", "", "vrecpe.u32", ""]),                         // A=11 B=10001  VRECPE  A8.6.371
    m!(["", "", "vrsqrte.u32", ""]),                        // A=11 B=10010  VRSQRTE A8.6.378
    m!(["", "", "vrsqrte.u32", ""]),                        // A=11 B=10011  VRSQRTE A8.6.378
    m!(["", "", "vrecpe.f32", ""]),                         // A=11 B=10100  VRECPE (F32)
    m!(["", "", "vrecpe.f32", ""]),                         // A=11 B=10101  VRECPE (F32)
    m!(["", "", "vrsqrte.f32", ""]),                        // A=11 B=10110  VRSQRTE (F32)
    m!(["", "", "vrsqrte.f32", ""]),                        // A=11 B=10111  VRSQRTE (F32)
    m!(["", "", "vcvt.f32.s32", ""]),                       // A=11 B=11000  VCVT    A8.6.294
    m!(["", "", "vcvt.f32.s32", ""]),                       // A=11 B=11001  VCVT    A8.6.294
    m!(["", "", "vcvt.f32.u32", ""]),                       // A=11 B=11010  VCVT
    m!(["", "", "vcvt.f32.u32", ""]),                       // A=11 B=11011  VCVT
    m!(["", "", "vcvt.s32.f32", ""]),                       // A=11 B=11100  VCVT
    m!(["", "", "vcvt.s32.f32", ""]),                       // A=11 B=11101  VCVT
    m!(["", "", "vcvt.u32.f32", ""]),                       // A=11 B=11110  VCVT
    m!(["", "", "vcvt.u32.f32", ""]),                       // A=11 B=11111  VCVT
];

/// Decode Table A7-13 — two registers, miscellaneous.
fn decode_misc(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let size = ((hw1 >> 2) & 3) as usize;
    let row = &MISC_ROWS[(((hw1 & 3) << 5) | ((hw2 >> 6) & 0x1F)) as usize];
    let name = row.names[size];
    if name.is_empty() {
        return None;
    }
    let q = hw2 & 0x0040 != 0;
    let dd = dnum(hw1 >> 6, hw2 >> 12);
    let dm = dnum(hw2 >> 5, hw2);
    let mut ops = Operands::new();
    match row.shape {
        MiscShape::Same | MiscShape::Zero => {
            ops.push(Operand::FpReg(vec(q, dd)?));
            ops.push(Operand::FpReg(vec(q, dm)?));
            if row.shape == MiscShape::Zero {
                ops.push(Operand::Imm(0));
            }
        }
        MiscShape::Narrow => {
            ops.push(Operand::FpReg(FpReg::D(dd)));
            ops.push(Operand::FpReg(vec(true, dm)?));
        }
        MiscShape::Long | MiscShape::LongMax => {
            ops.push(Operand::FpReg(vec(true, dd)?));
            ops.push(Operand::FpReg(FpReg::D(dm)));
            if row.shape == MiscShape::LongMax {
                ops.push(Operand::Imm(8 << size));
            }
        }
    }
    // `VSHLL` at the maximum shift is the T2 encoding of a page whose T1 lives
    // in Table A7-12; every other row here is its page's T1.
    let enc = if name.starts_with("vshll") {
        "T2"
    } else {
        "T1"
    };
    Some(simd(name, enc, addr, ops))
}

/// Re-encode Table A7-13.
fn encode_misc(insn: &Insn) -> Option<(u16, u16)> {
    let (found, size) = MISC_ROWS.iter().enumerate().find_map(|(r, row)| {
        row.names
            .iter()
            .position(|&c| !c.is_empty() && c == insn.mnemonic)
            .map(|s| (r as u16, s as u16))
    })?;
    let (qd, dd) = vec_bits(fp_at(insn, 0)?)?;
    let (qm, dm) = vec_bits(fp_at(insn, 1)?)?;
    let shape = MISC_ROWS[found as usize].shape;
    let (index, want_ops) = match shape {
        MiscShape::Same | MiscShape::Zero => {
            if qd != qm {
                return None;
            }
            // `Q` comes from the operands, not from the row the name search
            // happened to land on — the two `Q` halves of a row hold the same
            // mnemonic. Re-checking the name at the recomputed index is what
            // rejects `vuzp.32 d0, d1`, which exists only in the `Q == 1` half.
            let index = (found & !1) | qd as u16;
            if MISC_ROWS[index as usize].names[size as usize] != insn.mnemonic {
                return None;
            }
            (index, if shape == MiscShape::Zero { 3 } else { 2 })
        }
        MiscShape::Narrow => {
            if qd || !qm {
                return None;
            }
            (found, 2)
        }
        MiscShape::Long => {
            if !qd || qm {
                return None;
            }
            (found, 2)
        }
        MiscShape::LongMax => {
            if !qd || qm || imm_at(insn, 2)? != 8 << size {
                return None;
            }
            (found, 3)
        }
    };
    if insn.operands.len() != want_ops {
        return None;
    }
    if shape == MiscShape::Zero && imm_at(insn, 2)? != 0 {
        return None;
    }
    let hw1 = 0xFFB0 | ((dd as u16 & 0x10) << 2) | (size << 2) | (index >> 5);
    let hw2 = ((dd as u16 & 0xF) << 12)
        | ((index & 0x1F) << 6)
        | ((dm as u16 & 0x10) << 1)
        | (dm as u16 & 0xF);
    Some((hw1, hw2))
}

/// The operand shape of a row of Table A7-10 — three registers of different
/// lengths.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DiffShape {
    /// `<Qd>, <Dn>, <Dm>` — the "long" forms.
    Long,
    /// `<Qd>, <Qn>, <Dm>` — the "wide" forms, `VADDW` and `VSUBW`.
    Wide,
    /// `<Dd>, <Qn>, <Qm>` — the "narrow, returning high half" forms.
    Narrow,
}

/// One row of Table A7-10.
struct DiffRow {
    /// Mnemonics indexed by `size` = `hw1[5:4]`. For the narrowing rows the
    /// spelling names the *operand* size, which is twice the element size the
    /// field encodes.
    names: [&'static str; 4],
    /// The operand shape.
    shape: DiffShape,
    /// The architectural encoding name. Five of these rows are the T2 of a
    /// page whose T1 is the equal-length form in Table A7-9 (`VMULL` under
    /// `VMUL`, `VABAL` under `VABA`, and so on); the rest are their own page's
    /// T1.
    enc: &'static str,
}

/// A long row that is its page's T1.
macro_rules! dl {
    ($names:expr) => {
        DiffRow {
            names: $names,
            shape: DiffShape::Long,
            enc: "T1",
        }
    };
}
/// A long row that is the T2 of an equal-length page.
macro_rules! dl2 {
    ($names:expr) => {
        DiffRow {
            names: $names,
            shape: DiffShape::Long,
            enc: "T2",
        }
    };
}
/// A wide row.
macro_rules! dw {
    ($names:expr) => {
        DiffRow {
            names: $names,
            shape: DiffShape::Wide,
            enc: "T1",
        }
    };
}
/// A narrowing row.
macro_rules! dn {
    ($names:expr) => {
        DiffRow {
            names: $names,
            shape: DiffShape::Narrow,
            enc: "T1",
        }
    };
}
/// An UNDEFINED row.
macro_rules! du {
    () => {
        DiffRow {
            names: UNDEF4,
            shape: DiffShape::Long,
            enc: "T1",
        }
    };
}

/// Table A7-10 — three registers of different lengths — indexed by `U:A`,
/// that is `hw1[12]` and `hw2[11:8]`.
const DIFF_ROWS: [DiffRow; 32] = [
    dl!(t3!("vaddl", "s")),         // U=0 A=0000  VADDL    A8.6.274
    dw!(t3!("vaddw", "s")),         // U=0 A=0001  VADDW    A8.6.274
    dl!(t3!("vsubl", "s")),         // U=0 A=0010  VSUBL    A8.6.404
    dw!(t3!("vsubw", "s")),         // U=0 A=0011  VSUBW    A8.6.404
    dn!(n3!("vaddhn", "i")),        // U=0 A=0100  VADDHN   A8.6.273
    dl2!(t3!("vabal", "s")),        // U=0 A=0101  VABAL    A8.6.266
    dn!(n3!("vsubhn", "i")),        // U=0 A=0110  VSUBHN   A8.6.403
    dl2!(t3!("vabdl", "s")),        // U=0 A=0111  VABDL    A8.6.267
    dl2!(t3!("vmlal", "s")),        // U=0 A=1000  VMLAL    A8.6.323
    dl!(s1632!("vqdmlal")),         // U=0 A=1001  VQDMLAL  A8.6.358
    dl2!(t3!("vmlsl", "s")),        // U=0 A=1010  VMLSL    A8.6.323
    dl!(s1632!("vqdmlsl")),         // U=0 A=1011  VQDMLSL  A8.6.358
    dl2!(t3!("vmull", "s")),        // U=0 A=1100  VMULL    A8.6.337
    dl!(s1632!("vqdmull")),         // U=0 A=1101  VQDMULL  A8.6.360
    dl2!(["vmull.p8", "", "", ""]), // U=0 A=1110  VMULL (polynomial)
    du!(),                          // U=0 A=1111
    dl!(t3!("vaddl", "u")),         // U=1 A=0000
    dw!(t3!("vaddw", "u")),         // U=1 A=0001
    dl!(t3!("vsubl", "u")),         // U=1 A=0010
    dw!(t3!("vsubw", "u")),         // U=1 A=0011
    dn!(n3!("vraddhn", "i")),       // U=1 A=0100  VRADDHN  A8.6.370
    dl2!(t3!("vabal", "u")),        // U=1 A=0101
    dn!(n3!("vrsubhn", "i")),       // U=1 A=0110  VRSUBHN  A8.6.381
    dl2!(t3!("vabdl", "u")),        // U=1 A=0111
    dl2!(t3!("vmlal", "u")),        // U=1 A=1000
    du!(),                          // U=1 A=1001  (VQDMLAL is U=0 only)
    dl2!(t3!("vmlsl", "u")),        // U=1 A=1010
    du!(),                          // U=1 A=1011
    dl2!(t3!("vmull", "u")),        // U=1 A=1100
    du!(),                          // U=1 A=1101
    du!(),                          // U=1 A=1110
    du!(),                          // U=1 A=1111
];

/// Decode Table A7-10 — three registers of different lengths.
fn decode_diff(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let size = ((hw1 >> 4) & 3) as usize;
    let row = &DIFF_ROWS[((((hw1 >> 12) & 1) << 4) | ((hw2 >> 8) & 0xF)) as usize];
    let name = row.names[size];
    if name.is_empty() {
        return None;
    }
    let dd = dnum(hw1 >> 6, hw2 >> 12);
    let dn = dnum(hw2 >> 7, hw1);
    let dm = dnum(hw2 >> 5, hw2);
    let mut ops = Operands::new();
    match row.shape {
        DiffShape::Long => {
            ops.push(Operand::FpReg(vec(true, dd)?));
            ops.push(Operand::FpReg(FpReg::D(dn)));
            ops.push(Operand::FpReg(FpReg::D(dm)));
        }
        DiffShape::Wide => {
            ops.push(Operand::FpReg(vec(true, dd)?));
            ops.push(Operand::FpReg(vec(true, dn)?));
            ops.push(Operand::FpReg(FpReg::D(dm)));
        }
        DiffShape::Narrow => {
            ops.push(Operand::FpReg(FpReg::D(dd)));
            ops.push(Operand::FpReg(vec(true, dn)?));
            ops.push(Operand::FpReg(vec(true, dm)?));
        }
    }
    Some(simd(name, row.enc, addr, ops))
}

/// Re-encode Table A7-10.
fn encode_diff(insn: &Insn) -> Option<(u16, u16)> {
    if insn.operands.len() != 3 {
        return None;
    }
    let (index, size) = DIFF_ROWS.iter().enumerate().find_map(|(r, row)| {
        row.names
            .iter()
            .position(|&c| !c.is_empty() && c == insn.mnemonic)
            .map(|s| (r as u16, s as u16))
    })?;
    let (qd, dd) = vec_bits(fp_at(insn, 0)?)?;
    let (qn, dn) = vec_bits(fp_at(insn, 1)?)?;
    let (qm, dm) = vec_bits(fp_at(insn, 2)?)?;
    let ok = match DIFF_ROWS[index as usize].shape {
        DiffShape::Long => qd && !qn && !qm,
        DiffShape::Wide => qd && qn && !qm,
        DiffShape::Narrow => !qd && qn && qm,
    };
    if !ok {
        return None;
    }
    let hw1 =
        0xEF80 | ((index >> 4) << 12) | ((dd as u16 & 0x10) << 2) | (size << 4) | (dn as u16 & 0xF);
    let hw2 = ((dd as u16 & 0xF) << 12)
        | ((index & 0xF) << 8)
        | ((dn as u16 & 0x10) << 3)
        | ((dm as u16 & 0x10) << 1)
        | (dm as u16 & 0xF);
    Some((hw1, hw2))
}

/// One row of Table A7-11 — two registers and a scalar.
struct ScalarRow {
    /// Mnemonics indexed by `size` = `hw1[5:4]`; only 16- and 32-bit elements
    /// exist here, so cells 0 and 3 are always empty.
    names: [&'static str; 4],
    /// Whether the destination is twice the operand length (`VMULL` and
    /// friends), in which case `U` is the signedness rather than `Q`.
    long: bool,
    /// The architectural encoding name.
    enc: &'static str,
}

/// An equal-length by-scalar row (its page's T1).
macro_rules! sc {
    ($names:expr) => {
        ScalarRow {
            names: $names,
            long: false,
            enc: "T1",
        }
    };
}
/// An equal-length by-scalar row that is the T2 of a page whose T1 is the
/// vector-by-vector form — the two saturating doubling multiplies.
macro_rules! sc2 {
    ($names:expr) => {
        ScalarRow {
            names: $names,
            long: false,
            enc: "T2",
        }
    };
}
/// A long by-scalar row; every one of these is a T2.
macro_rules! scl {
    ($names:expr) => {
        ScalarRow {
            names: $names,
            long: true,
            enc: "T2",
        }
    };
}
/// An UNDEFINED row.
macro_rules! scu {
    () => {
        ScalarRow {
            names: UNDEF4,
            long: false,
            enc: "T1",
        }
    };
}

/// `<mnemonic>.<t>16` and `.<t>32` — every by-scalar row's shape.
macro_rules! x1632 {
    ($m:literal, $t:literal) => {
        [
            "",
            concat!($m, ".", $t, "16"),
            concat!($m, ".", $t, "32"),
            "",
        ]
    };
}

/// Table A7-11 — two registers and a scalar — indexed by `U:A`, that is
/// `hw1[12]` and `hw2[11:8]`.
///
/// In the equal-length rows `U` *is* `Q` (the manual draws the encoding as
/// `1111001Q1D…`), so those rows appear identically in both halves of the
/// table; in the long rows `U` is the signedness, and the saturating doubling
/// long forms exist only for `U == 0`.
const SCALAR_ROWS: [ScalarRow; 32] = [
    sc!(x1632!("vmla", "i")),      // U/Q=0 A=0000  VMLA (by scalar)  A8.6.325
    sc!(["", "", "vmla.f32", ""]), // U/Q=0 A=0001  VMLA (F32)
    scl!(x1632!("vmlal", "s")),    // U=0   A=0010  VMLAL             A8.6.325
    scl!(x1632!("vqdmlal", "s")),  // U=0   A=0011  VQDMLAL           A8.6.358
    sc!(x1632!("vmls", "i")),      // U/Q=0 A=0100  VMLS (by scalar)
    sc!(["", "", "vmls.f32", ""]), // U/Q=0 A=0101  VMLS (F32)
    scl!(x1632!("vmlsl", "s")),    // U=0   A=0110  VMLSL
    scl!(x1632!("vqdmlsl", "s")),  // U=0   A=0111  VQDMLSL
    sc!(x1632!("vmul", "i")),      // U/Q=0 A=1000  VMUL (by scalar)  A8.6.339
    sc!(["", "", "vmul.f32", ""]), // U/Q=0 A=1001  VMUL (F32)
    scl!(x1632!("vmull", "s")),    // U=0   A=1010  VMULL             A8.6.339
    scl!(x1632!("vqdmull", "s")),  // U=0   A=1011  VQDMULL           A8.6.360
    sc2!(x1632!("vqdmulh", "s")),  // U/Q=0 A=1100  VQDMULH           A8.6.359
    sc2!(x1632!("vqrdmulh", "s")), // U/Q=0 A=1101  VQRDMULH          A8.6.363
    scu!(),                        // U     A=1110
    scu!(),                        // U     A=1111
    sc!(x1632!("vmla", "i")),      // U/Q=1 A=0000
    sc!(["", "", "vmla.f32", ""]), // U/Q=1 A=0001
    scl!(x1632!("vmlal", "u")),    // U=1   A=0010
    scu!(),                        // U=1   A=0011  (VQDMLAL is U=0 only)
    sc!(x1632!("vmls", "i")),      // U/Q=1 A=0100
    sc!(["", "", "vmls.f32", ""]), // U/Q=1 A=0101
    scl!(x1632!("vmlsl", "u")),    // U=1   A=0110
    scu!(),                        // U=1   A=0111
    sc!(x1632!("vmul", "i")),      // U/Q=1 A=1000
    sc!(["", "", "vmul.f32", ""]), // U/Q=1 A=1001
    scl!(x1632!("vmull", "u")),    // U=1   A=1010
    scu!(),                        // U=1   A=1011
    sc2!(x1632!("vqdmulh", "s")),  // U/Q=1 A=1100
    sc2!(x1632!("vqrdmulh", "s")), // U/Q=1 A=1101
    scu!(),                        // U     A=1110
    scu!(),                        // U     A=1111
];

/// The scalar `<Dm[x]>` a by-scalar encoding names — Table A7-7.
///
/// The scalar register field is *not* `M:Vm`: for 16-bit elements it is
/// `Vm<2:0>`, only eight registers, with `M:Vm<3>` supplying a two-bit index;
/// for 32-bit elements it is `Vm<3:0>`, sixteen registers, with `M` the
/// one-bit index. That is why a by-scalar multiply cannot reach `d16`–`d31`.
///
/// `size` is 1 or 2 here and nothing else: every cell of [`SCALAR_ROWS`] at
/// `size == 0` and `size == 3` is empty, so [`decode_scalar`]'s spelling test
/// has already turned those back.
fn scalar_operand(size: u16, m: u16, vm: u16) -> Operand {
    if size == 1 {
        Operand::FpScalar(FpReg::D((vm & 7) as u8), ((m << 1) | ((vm >> 3) & 1)) as u8)
    } else {
        Operand::FpScalar(FpReg::D((vm & 0xF) as u8), m as u8)
    }
}

/// The inverse of [`scalar_operand`]: the `M:Vm` bits that name `d<n>[x]`.
fn scalar_bits(size: u16, reg: FpReg, index: u8) -> Option<(u16, u16)> {
    match (size, reg) {
        (1, FpReg::D(n)) if n < 8 && index < 4 => Some((
            (index >> 1) as u16,
            (n as u16) | (((index & 1) as u16) << 3),
        )),
        (2, FpReg::D(n)) if n < 16 && index < 2 => Some((index as u16, n as u16)),
        _ => None,
    }
}

/// Decode Table A7-11 — two registers and a scalar.
fn decode_scalar(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let u = (hw1 >> 12) & 1;
    let size = (hw1 >> 4) & 3;
    let row = &SCALAR_ROWS[((u << 4) | ((hw2 >> 8) & 0xF)) as usize];
    let name = row.names[size as usize];
    if name.is_empty() {
        return None;
    }
    let dd = dnum(hw1 >> 6, hw2 >> 12);
    let dn = dnum(hw2 >> 7, hw1);
    let scalar = scalar_operand(size, (hw2 >> 5) & 1, hw2 & 0xF);
    let mut ops = Operands::new();
    if row.long {
        ops.push(Operand::FpReg(vec(true, dd)?));
        ops.push(Operand::FpReg(FpReg::D(dn)));
    } else {
        let q = u == 1;
        ops.push(Operand::FpReg(vec(q, dd)?));
        ops.push(Operand::FpReg(vec(q, dn)?));
    }
    ops.push(scalar);
    Some(simd(name, row.enc, addr, ops))
}

/// Re-encode Table A7-11.
fn encode_scalar(insn: &Insn) -> Option<(u16, u16)> {
    // The operand is read before the arity is checked, so that an absent one
    // and one of the wrong kind are the same refusal rather than two, one of
    // which could never be reached.
    let (index, scalar_index) = match insn.operands.get(2) {
        Some(Operand::FpScalar(r, i)) => (r, i),
        _ => return None,
    };
    if insn.operands.len() != 3 {
        return None;
    }
    let (found, size) = SCALAR_ROWS.iter().enumerate().find_map(|(r, row)| {
        row.names
            .iter()
            .position(|&c| !c.is_empty() && c == insn.mnemonic)
            .map(|s| (r as u16, s as u16))
    })?;
    let (qd, dd) = vec_bits(fp_at(insn, 0)?)?;
    let (qn, dn) = vec_bits(fp_at(insn, 1)?)?;
    let row = &SCALAR_ROWS[found as usize];
    let u = if row.long {
        if !qd || qn {
            return None;
        }
        found >> 4
    } else {
        if qd != qn {
            return None;
        }
        // `U` is `Q` in these rows, so it comes from the operands; the two
        // halves of the table hold the same mnemonic.
        qd as u16
    };
    // No re-check of the spelling at the recomputed index: where `U` is `Q`
    // the two halves of Table A7-11 hold the same mnemonics, and where it is
    // the signedness `u` is the half the name was found in, so `(u << 4) | a`
    // is always the row `found` already names.
    let a = found & 0xF;
    let (m, vm) = scalar_bits(size, index, scalar_index)?;
    let hw1 = 0xEF80 | (u << 12) | ((dd as u16 & 0x10) << 2) | (size << 4) | (dn as u16 & 0xF);
    let hw2 =
        ((dd as u16 & 0xF) << 12) | (a << 8) | ((dn as u16 & 0x10) << 3) | 0x0040 | (m << 5) | vm;
    Some((hw1, hw2))
}

/// Decode `VEXT` — A8.6.305, the `U == 0` half of Table A7-8's `A == 1x11x`
/// row.
///
/// The element size is always 8: `VEXT.16`, `.32` and `.64` are
/// pseudo-instructions an assembler turns into `VEXT.8` with the byte count
/// multiplied out, so there is nothing for a disassembler to print but `.8`.
fn decode_vext(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let q = hw2 & 0x0040 != 0;
    let imm4 = (hw2 >> 8) & 0xF;
    if !q && imm4 & 0x8 != 0 {
        return None; // a doubleword extract cannot start past byte 7
    }
    let mut ops = Operands::new();
    ops.push(Operand::FpReg(vec(q, dnum(hw1 >> 6, hw2 >> 12))?));
    ops.push(Operand::FpReg(vec(q, dnum(hw2 >> 7, hw1))?));
    ops.push(Operand::FpReg(vec(q, dnum(hw2 >> 5, hw2))?));
    ops.push(Operand::Imm(imm4 as i64));
    Some(simd("vext.8", "T1", addr, ops))
}

/// Re-encode `VEXT`.
fn encode_vext(insn: &Insn) -> Option<(u16, u16)> {
    if insn.mnemonic != "vext.8" || insn.operands.len() != 4 {
        return None;
    }
    let (qd, dd) = vec_bits(fp_at(insn, 0)?)?;
    let (qn, dn) = vec_bits(fp_at(insn, 1)?)?;
    let (qm, dm) = vec_bits(fp_at(insn, 2)?)?;
    if qd != qn || qd != qm {
        return None;
    }
    let imm4 = imm_at(insn, 3)?;
    if imm4 < 0 || imm4 > if qd { 15 } else { 7 } {
        return None;
    }
    let hw1 = 0xEFB0 | ((dd as u16 & 0x10) << 2) | (dn as u16 & 0xF);
    let hw2 = ((dd as u16 & 0xF) << 12)
        | ((imm4 as u16) << 8)
        | ((dn as u16 & 0x10) << 3)
        | if qd { 0x0040 } else { 0 }
        | ((dm as u16 & 0x10) << 1)
        | (dm as u16 & 0xF);
    Some((hw1, hw2))
}

/// Decode `VTBL`/`VTBX` — A8.6.406.
fn decode_vtbl(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let name = if hw2 & 0x0040 == 0 {
        "vtbl.8"
    } else {
        "vtbx.8"
    };
    let len = ((hw2 >> 8) & 3) as u8 + 1;
    let list = list_text(len, 1, dnum(hw2 >> 7, hw1), 0)?;
    let mut ops = Operands::new();
    ops.push(Operand::FpReg(FpReg::D(dnum(hw1 >> 6, hw2 >> 12))));
    ops.push(Operand::Text(list));
    ops.push(Operand::FpReg(FpReg::D(dnum(hw2 >> 5, hw2))));
    Some(simd(name, "T1", addr, ops))
}

/// Re-encode `VTBL`/`VTBX`.
fn encode_vtbl(insn: &Insn) -> Option<(u16, u16)> {
    let op = match insn.mnemonic {
        "vtbl.8" => 0u16,
        "vtbx.8" => 1,
        _ => return None,
    };
    if insn.operands.len() != 3 {
        return None;
    }
    let (qd, dd) = vec_bits(fp_at(insn, 0)?)?;
    let (qm, dm) = vec_bits(fp_at(insn, 2)?)?;
    if qd || qm {
        return None;
    }
    let (count, inc, dn, suffix) = list_fields(text_at(insn, 1)?)?;
    if inc != 1 || suffix != 0 || count > 4 {
        return None;
    }
    let hw1 = 0xFFB0 | ((dd as u16 & 0x10) << 2) | (dn as u16 & 0xF);
    let hw2 = ((dd as u16 & 0xF) << 12)
        | (0b10 << 10)
        | (((count as u16) - 1) << 8)
        | ((dn as u16 & 0x10) << 3)
        | (op << 6)
        | ((dm as u16 & 0x10) << 1)
        | (dm as u16 & 0xF);
    Some((hw1, hw2))
}

/// `VDUP (scalar)`'s element size and lane index, from `imm4` — A8.6.302.
///
/// The index is packed above a one-hot marker of the element size, the same
/// trick `index_align` plays in A7.7: `xxx1` is a byte with a three-bit index,
/// `xx10` a halfword with two, `x100` a word with one, and `x000` UNDEFINED.
fn vdup_fields(imm4: u16) -> Option<(usize, u8)> {
    if imm4 & 1 != 0 {
        Some((0, (imm4 >> 1) as u8))
    } else if imm4 & 2 != 0 {
        Some((1, (imm4 >> 2) as u8))
    } else if imm4 & 4 != 0 {
        Some((2, (imm4 >> 3) as u8))
    } else {
        None
    }
}

/// `VDUP (scalar)` spelled with its element size.
const VDUP_NAMES: [&str; 3] = ["vdup.8", "vdup.16", "vdup.32"];

/// Decode `VDUP (scalar)` — A8.6.302.
fn decode_vdup(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let (size, index) = vdup_fields(hw1 & 0xF)?;
    let q = hw2 & 0x0040 != 0;
    let mut ops = Operands::new();
    ops.push(Operand::FpReg(vec(q, dnum(hw1 >> 6, hw2 >> 12))?));
    ops.push(Operand::FpScalar(FpReg::D(dnum(hw2 >> 5, hw2)), index));
    Some(simd(VDUP_NAMES[size], "T1", addr, ops))
}

/// Re-encode `VDUP (scalar)`.
fn encode_vdup(insn: &Insn) -> Option<(u16, u16)> {
    let size = VDUP_NAMES.iter().position(|&n| n == insn.mnemonic)? as u16;
    // The operand is read before the arity is checked, so that an absent one
    // and one of the wrong kind are the same refusal rather than two, one of
    // which could never be reached.
    let (dm, index) = match insn.operands.get(1) {
        Some(Operand::FpScalar(FpReg::D(n), i)) => (n, i),
        _ => return None,
    };
    if insn.operands.len() != 2 {
        return None;
    }
    let (qd, dd) = vec_bits(fp_at(insn, 0)?)?;
    let imm4 = (0..16u16).find(|&i| vdup_fields(i) == Some((size as usize, index)))?;
    let hw1 = 0xFFB0 | ((dd as u16 & 0x10) << 2) | imm4;
    let hw2 = ((dd as u16 & 0xF) << 12)
        | (0b1100 << 8)
        | if qd { 0x0040 } else { 0 }
        | ((dm as u16 & 0x10) << 1)
        | (dm as u16 & 0xF);
    Some((hw1, hw2))
}

/// Decode an Advanced SIMD instruction, or `None` if `hw1`/`hw2` are not one.
///
/// Two disjoint halfword patterns are accepted, matching the two sections of
/// chapter A7 this module implements. Both are reachable from
/// [`super::decode_halfwords`]: the element/structure space directly, and the
/// data-processing space through the coprocessor arm, which declines it.
pub(crate) fn decode(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    match hw1 >> 8 {
        0xF9 => decode_elem(hw1, hw2, addr),
        0xEF | 0xFF => decode_dp(hw1, hw2, addr),
        _ => None,
    }
}

/// Re-encode an instruction this module decoded, back to its two halfwords.
///
/// Returns `None` for anything that is not this module's: `mod.rs` tries the
/// group encoders in turn, so a greedy one here would silently swallow its
/// siblings' instructions. The two tests that matter are the register class —
/// every vector operand of an Advanced SIMD instruction is a `D` or a `Q`
/// register, never an `S`, which is what separates this module from the VFP
/// half of the coprocessor space — and the fully spelled mnemonic, which
/// carries the data type (`vadd.i32`, not `vadd`) for every form that has one.
pub(crate) fn encode(insn: &Insn) -> Option<(u16, u16)> {
    if insn.width != Width::Wide || insn.sets_flags || insn.explicit_width {
        return None;
    }
    encode_elem(insn).or_else(|| encode_dp(insn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::Target;

    /// `list_fields` inverts the spelling table by scan, and two spellings can
    /// never appear there: the empty string and one longer than a cell.
    ///
    /// Both are refused before the scan. The empty case matters because a
    /// byte-compare against an empty cell would otherwise match it, where the
    /// old `text_of`-based scan returned `None`; the over-long case cannot fit
    /// any `TEXT_W`-wide row and short-circuits.
    #[test]
    fn list_fields_refuses_spellings_no_row_can_hold() {
        assert_eq!(list_fields(""), None, "an empty spelling is in no row");
        let too_long = "d".repeat(TEXT_W + 1);
        assert_eq!(list_fields(&too_long), None, "longer than any cell");
        // A real spelling still round-trips through the scan.
        assert_eq!(
            list_fields("{d0}"),
            Some((1, 1, 0, 0)),
            "the inverse of list_text for a one-register list"
        );
    }

    /// Decode a halfword pair and, if it decodes, insist that it re-encodes to
    /// exactly the bytes it came from. Returns whether it decoded, so that the
    /// sweeps below can report how much of each sub-table they covered.
    fn round_trip(hw1: u16, hw2: u16) -> bool {
        match decode(hw1, hw2, 0x1000) {
            None => false,
            Some(insn) => {
                let back = encode(&insn);
                assert_eq!(
                    back,
                    Some((hw1, hw2)),
                    "{insn} decoded from {hw1:#06x} {hw2:#06x} re-encoded as {back:x?}"
                );
                true
            }
        }
    }

    /// The doubleword numbers a sweep uses: both ends of the four-bit field,
    /// the values either side of the `D` bit, and the top of the file.
    const DREGS: [u16; 5] = [0, 1, 15, 16, 31];

    /// Quadword numbers, as their `D:Vd` values — `q0`, `q1`, `q7`, `q15`,
    /// `q14`, `q13` — and last the odd value 1, which names no quadword.
    ///
    /// Every `Q` form in A7.4 carries `if Q == '1' && Vd<0> == '1' then
    /// UNDEFINED` (A8.6.271 and forty pages like it), so a sweep that only
    /// ever offers even numbers never tests the rule; firmware is not so
    /// considerate. The odd number is last on purpose: the sweeps below take
    /// three consecutive entries as `(Vd, Vn, Vm)`, so the first four windows
    /// are legal triples and the last three put the odd number in each of the
    /// three operand positions in turn.
    const QREGS: [u16; 7] = [0, 2, 14, 30, 28, 26, 1];

    /// Pack a `D:Vd`-style value into its two halves.
    fn split(d: u16) -> (u16, u16) {
        ((d >> 4) & 1, d & 0xF)
    }

    // -- A7.7: element and structure load/store ----------------------------

    #[test]
    fn sweep_multiple_element() {
        let mut n = 0;
        for l in 0..2u16 {
            for ty in 0..16u16 {
                for size in 0..4u16 {
                    for align in 0..4u16 {
                        for &d in &DREGS {
                            for rm in [0u16, 3, 13, 15] {
                                let (dh, dl) = split(d);
                                let hw1 = 0xF900 | (dh << 6) | (l << 5) | 7;
                                let hw2 = (dl << 12) | (ty << 8) | (size << 6) | (align << 4) | rm;
                                n += round_trip(hw1, hw2) as usize;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(n, 3584, "multiple-element forms decoded");
    }

    #[test]
    fn sweep_single_lane() {
        let mut n = 0;
        for l in 0..2u16 {
            for size in 0..4u16 {
                for nn in 0..4u16 {
                    for ia in 0..16u16 {
                        for &d in &DREGS {
                            for rm in [0u16, 3, 13, 15] {
                                let (dh, dl) = split(d);
                                let hw1 = 0xF980 | (dh << 6) | (l << 5) | 7;
                                let hw2 = (dl << 12) | (size << 10) | (nn << 8) | (ia << 4) | rm;
                                n += round_trip(hw1, hw2) as usize;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(n, 4820, "single-lane and all-lanes forms decoded");
    }

    /// One cell of [`LANE_INDEX_ALIGN`]: the `(index, inc, align)` a single
    /// `index_align` value names — the lane the transfer touches, the spacing
    /// between the registers of the list, and the alignment in bits (0 for
    /// "omitted") — or `None` where the instruction page makes that value
    /// UNDEFINED. It is [`lane_fields`]' return type, named so that the three
    /// nesting levels of the table below are readable.
    type LaneFields = Option<(u8, u8, u16)>;

    /// What `index_align` names in each of the twelve single-lane cells,
    /// indexed by `[n - 1][size]` and then by the field's own value.
    ///
    /// A second reading of the `case size of` blocks of A8.6.308, A8.6.311,
    /// A8.6.314 and A8.6.317 — the `(index, inc, align)` each of the sixteen
    /// values names, or `None` where that page makes it UNDEFINED.
    ///
    /// It is written out rather than computed because the sweeps above cannot
    /// see this at all. [`lane_fields`] is *both* directions of the
    /// single-lane forms: `decode_elem` reads it forward and `encode_elem`
    /// inverts it by scanning `index_align` for a match, so a cell that hands
    /// the right `(index, inc, align)` to the wrong bit pattern still
    /// round-trips, and `sweep_single_lane` still counts 4820 decodes. Only
    /// the bytes change — and they are the whole product here. `vld1.8
    /// {d0[3]}, [r0]` is `index_align == 0b0110` and nothing else; an
    /// assembler that wrote `0b0111` would set the bit A8.6.308 makes
    /// UNDEFINED, and one that wrote `0b0010` would load lane 1.
    #[rustfmt::skip]
    const LANE_INDEX_ALIGN: [[[LaneFields; 16]; 3]; 4] = [
        [ // VLD1/VST1
            // `index_align<0>` must be 0 (A8.6.308), and an 8-bit element
            // needs no alignment: three bits of index and a bit that must be
            // clear.
            [ // size = 0b00
                Some((0, 1, 0)), None, Some((1, 1, 0)), None,
                Some((2, 1, 0)), None, Some((3, 1, 0)), None,
                Some((4, 1, 0)), None, Some((5, 1, 0)), None,
                Some((6, 1, 0)), None, Some((7, 1, 0)), None,
            ],
            [ // size = 0b01 — `index_align<1>` must be 0; `<0>` is `:16`.
                Some((0, 1, 0)), Some((0, 1, 16)), None, None,
                Some((1, 1, 0)), Some((1, 1, 16)), None, None,
                Some((2, 1, 0)), Some((2, 1, 16)), None, None,
                Some((3, 1, 0)), Some((3, 1, 16)), None, None,
            ],
            // `<2>` must be 0 and `<1:0>` must be `00` or `11`, so three
            // quarters of this column is UNDEFINED; `11` is `:32`.
            [ // size = 0b10
                Some((0, 1, 0)), None, None, Some((0, 1, 32)),
                None, None, None, None,
                Some((1, 1, 0)), None, None, Some((1, 1, 32)),
                None, None, None, None,
            ],
        ],
        [ // VLD2/VST2
            [ // size = 0b00 — A8.6.311: nothing here is UNDEFINED. `<0>` is `:16`.
                Some((0, 1, 0)), Some((0, 1, 16)), Some((1, 1, 0)), Some((1, 1, 16)),
                Some((2, 1, 0)), Some((2, 1, 16)), Some((3, 1, 0)), Some((3, 1, 16)),
                Some((4, 1, 0)), Some((4, 1, 16)), Some((5, 1, 0)), Some((5, 1, 16)),
                Some((6, 1, 0)), Some((6, 1, 16)), Some((7, 1, 0)), Some((7, 1, 16)),
            ],
            [ // size = 0b01 — `<1>` doubles the spacing, `<0>` is `:32`.
                Some((0, 1, 0)), Some((0, 1, 32)), Some((0, 2, 0)), Some((0, 2, 32)),
                Some((1, 1, 0)), Some((1, 1, 32)), Some((1, 2, 0)), Some((1, 2, 32)),
                Some((2, 1, 0)), Some((2, 1, 32)), Some((2, 2, 0)), Some((2, 2, 32)),
                Some((3, 1, 0)), Some((3, 1, 32)), Some((3, 2, 0)), Some((3, 2, 32)),
            ],
            [ // size = 0b10 — `<1>` must be 0; `<2>` doubles the spacing and `<0>` is `:64`.
                Some((0, 1, 0)), Some((0, 1, 64)), None, None,
                Some((0, 2, 0)), Some((0, 2, 64)), None, None,
                Some((1, 1, 0)), Some((1, 1, 64)), None, None,
                Some((1, 2, 0)), Some((1, 2, 64)), None, None,
            ],
        ],
        [ // VLD3/VST3
            // A8.6.314: a three-register structure is never aligned, so
            // every alignment bit must be clear.
            [ // size = 0b00
                Some((0, 1, 0)), None, Some((1, 1, 0)), None,
                Some((2, 1, 0)), None, Some((3, 1, 0)), None,
                Some((4, 1, 0)), None, Some((5, 1, 0)), None,
                Some((6, 1, 0)), None, Some((7, 1, 0)), None,
            ],
            [ // size = 0b01 — `<0>` must be 0; `<1>` doubles the spacing.
                Some((0, 1, 0)), None, Some((0, 2, 0)), None,
                Some((1, 1, 0)), None, Some((1, 2, 0)), None,
                Some((2, 1, 0)), None, Some((2, 2, 0)), None,
                Some((3, 1, 0)), None, Some((3, 2, 0)), None,
            ],
            [ // size = 0b10 — `<1:0>` must be 0; `<2>` doubles the spacing.
                Some((0, 1, 0)), None, None, None,
                Some((0, 2, 0)), None, None, None,
                Some((1, 1, 0)), None, None, None,
                Some((1, 2, 0)), None, None, None,
            ],
        ],
        [ // VLD4/VST4
            [ // size = 0b00 — A8.6.317: `<0>` is `:32` and nothing is UNDEFINED.
                Some((0, 1, 0)), Some((0, 1, 32)), Some((1, 1, 0)), Some((1, 1, 32)),
                Some((2, 1, 0)), Some((2, 1, 32)), Some((3, 1, 0)), Some((3, 1, 32)),
                Some((4, 1, 0)), Some((4, 1, 32)), Some((5, 1, 0)), Some((5, 1, 32)),
                Some((6, 1, 0)), Some((6, 1, 32)), Some((7, 1, 0)), Some((7, 1, 32)),
            ],
            [ // size = 0b01 — `<1>` doubles the spacing, `<0>` is `:64`.
                Some((0, 1, 0)), Some((0, 1, 64)), Some((0, 2, 0)), Some((0, 2, 64)),
                Some((1, 1, 0)), Some((1, 1, 64)), Some((1, 2, 0)), Some((1, 2, 64)),
                Some((2, 1, 0)), Some((2, 1, 64)), Some((2, 2, 0)), Some((2, 2, 64)),
                Some((3, 1, 0)), Some((3, 1, 64)), Some((3, 2, 0)), Some((3, 2, 64)),
            ],
            // `<1:0>` is the alignment — `01` is `:64`, `10` is `:128` and
            // `11` alone is UNDEFINED; `<2>` doubles the spacing.
            [ // size = 0b10
                Some((0, 1, 0)), Some((0, 1, 64)), Some((0, 1, 128)), None,
                Some((0, 2, 0)), Some((0, 2, 64)), Some((0, 2, 128)), None,
                Some((1, 1, 0)), Some((1, 1, 64)), Some((1, 1, 128)), None,
                Some((1, 2, 0)), Some((1, 2, 64)), Some((1, 2, 128)), None,
            ],
        ],
    ];

    /// Every `index_align` value of every single-lane cell means what Tables
    /// A8-5 to A8-11 say it means.
    #[test]
    fn index_align_names_the_lane_the_manual_gives_it() {
        for (i, per_size) in LANE_INDEX_ALIGN.iter().enumerate() {
            let n = i as u8 + 1;
            for (size, want) in per_size.iter().enumerate() {
                for (ia, &expect) in want.iter().enumerate() {
                    assert_eq!(
                        lane_fields(n, size as u16, ia as u16),
                        expect,
                        "VLD{n} size {size:#04b} index_align {ia:#06b}"
                    );
                }
            }
        }
    }

    /// One cell of [`ALL_LANES`]: the `(size code, alignment in bits)` a
    /// `(size, a)` pair names in the "to all lanes" forms, or `None` where
    /// the instruction page makes that pair UNDEFINED. Alignment is 0 for
    /// "omitted", as everywhere else here.
    type AllLanesFields = Option<(u16, u16)>;

    /// What every `(size, a)` pair names, indexed by `[n - 1][size][a]`.
    ///
    /// A second reading of A8.6.309, A8.6.312, A8.6.315 and A8.6.318, and it
    /// is needed for the same reason [`LANE_INDEX_ALIGN`] is:
    /// [`all_lanes_fields`] is inverted by scanning `(size, a)` for the pair
    /// `encode_elem` wants, so an alignment that is wrong here is wrong in
    /// both directions at once and every round trip still closes.
    ///
    /// What changes is the qualifier this module prints and believes. `a` is
    /// an assertion about the pointer, not a preference: A8.6.312 says a
    /// `vld2.32 {d0[], d1[]}, [r0:64]` whose `r0` is not 8-byte aligned takes
    /// an alignment fault, so printing `:64` where the architecture said
    /// `:32` invents a promise the original code never made.
    #[rustfmt::skip]
    const ALL_LANES: [[[AllLanesFields; 2]; 4]; 4] = [
        // A8.6.309: an 8-bit element has nothing to align to, so `VLD1`'s
        // `size == 0b00` with `a` set is the one UNDEFINED pair here.
        [ // VLD1                    a = 0                 a = 1
            /* size = 0b00 */ [Some((0, 0)),         None              ],
            /* size = 0b01 */ [Some((1, 0)),         Some((1, 16))     ],
            /* size = 0b10 */ [Some((2, 0)),         Some((2, 32))     ],
            /* size = 0b11 */ [None,                 None              ],
        ],
        // A8.6.312: a two-element structure aligns to two elements.
        [ // VLD2
            /* size = 0b00 */ [Some((0, 0)),         Some((0, 16))     ],
            /* size = 0b01 */ [Some((1, 0)),         Some((1, 32))     ],
            /* size = 0b10 */ [Some((2, 0)),         Some((2, 64))     ],
            /* size = 0b11 */ [None,                 None              ],
        ],
        // A8.6.315: three elements are never a power of two, so `VLD3` has
        // no alignment at all and `a` set is UNDEFINED in every size.
        [ // VLD3
            /* size = 0b00 */ [Some((0, 0)),         None              ],
            /* size = 0b01 */ [Some((1, 0)),         None              ],
            /* size = 0b10 */ [Some((2, 0)),         None              ],
            /* size = 0b11 */ [None,                 None              ],
        ],
        // A8.6.318: four elements would align to 128 bits at `.32`, which
        // does not fit the `a` bit — so `size == 0b11` is not a size here at
        // all but a second 32-bit row carrying the wider qualifier, and it
        // exists only with `a` set. That irregularity is why the `.32` row
        // above it stops at `:64` instead of doubling like the rest.
        [ // VLD4
            /* size = 0b00 */ [Some((0, 0)),         Some((0, 32))     ],
            /* size = 0b01 */ [Some((1, 0)),         Some((1, 64))     ],
            /* size = 0b10 */ [Some((2, 0)),         Some((2, 64))     ],
            /* size = 0b11 */ [None,                 Some((2, 128))    ],
        ],
    ];

    /// Every `(size, a)` pair of every "to all lanes" form means what its
    /// instruction page says it means.
    #[test]
    fn the_all_lanes_forms_align_where_their_pages_say_they_do() {
        for (i, per_size) in ALL_LANES.iter().enumerate() {
            let n = i as u8 + 1;
            for (size, want) in per_size.iter().enumerate() {
                for (a, &expect) in want.iter().enumerate() {
                    assert_eq!(
                        all_lanes_fields(n, size as u16, a == 1),
                        expect,
                        "VLD{n} size {size:#04b} a = {a}"
                    );
                }
            }
        }
    }

    // -- A7.4.1: three registers of the same length ------------------------

    #[test]
    fn sweep_three_same() {
        let mut n = 0;
        for u in 0..2u16 {
            for opc in 0..16u16 {
                for b in 0..2u16 {
                    for size in 0..4u16 {
                        for q in 0..2u16 {
                            let regs: &[u16] = if q == 1 { &QREGS } else { &DREGS };
                            for (i, &d) in regs.iter().enumerate() {
                                let (dh, dl) = split(d);
                                let (nh, nl) = split(regs[(i + 1) % regs.len()]);
                                let (mh, ml) = split(regs[(i + 2) % regs.len()]);
                                let hw1 = 0xEF00 | (u << 12) | (dh << 6) | (size << 4) | nl;
                                let hw2 = (dl << 12)
                                    | (opc << 8)
                                    | (nh << 7)
                                    | (q << 6)
                                    | (mh << 5)
                                    | (b << 4)
                                    | ml;
                                n += round_trip(hw1, hw2) as usize;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(n, 1485, "three-registers-same forms decoded");
    }

    // -- A7.4.4: two registers and a shift amount --------------------------

    #[test]
    fn sweep_two_shift() {
        let mut n = 0;
        for u in 0..2u16 {
            for opc in 0..16u16 {
                for l in 0..2u16 {
                    for q in 0..2u16 {
                        for imm6 in 0..64u16 {
                            if l == 0 && imm6 < 8 {
                                continue; // `L:imm6 == '0000xxx'` is Table A7-14
                            }
                            let regs: &[u16] = if q == 1 { &QREGS } else { &DREGS };
                            for (i, &d) in regs.iter().enumerate() {
                                let (dh, dl) = split(d);
                                let (mh, ml) = split(regs[(i + 1) % regs.len()]);
                                let hw1 = 0xEF80 | (u << 12) | (dh << 6) | imm6;
                                let hw2 = (dl << 12)
                                    | (opc << 8)
                                    | (l << 7)
                                    | (q << 6)
                                    | (mh << 5)
                                    | 0x0010
                                    | ml;
                                n += round_trip(hw1, hw2) as usize;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(n, 20096, "two-registers-and-shift forms decoded");
    }

    // -- A7.4.6: one register and a modified immediate ---------------------

    #[test]
    fn sweep_modimm() {
        let mut n = 0;
        for i in 0..2u16 {
            for op in 0..2u16 {
                for cmode in 0..16u16 {
                    for q in 0..2u16 {
                        for imm in [0u16, 1, 0xAB, 0xFF] {
                            let regs: &[u16] = if q == 1 { &QREGS } else { &DREGS };
                            for &d in regs {
                                let (dh, dl) = split(d);
                                let hw1 = 0xEF80 | (i << 12) | (dh << 6) | ((imm >> 4) & 7);
                                let hw2 = (dl << 12)
                                    | (cmode << 8)
                                    | (q << 6)
                                    | (op << 5)
                                    | 0x0010
                                    | (imm & 0xF);
                                n += round_trip(hw1, hw2) as usize;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(n, 2508, "modified-immediate forms decoded");
    }

    // -- A7.4.5: two registers, miscellaneous ------------------------------

    #[test]
    fn sweep_two_misc() {
        let mut n = 0;
        for a in 0..4u16 {
            for b in 0..32u16 {
                for size in 0..4u16 {
                    let q = b & 1;
                    let regs: &[u16] = if q == 1 { &QREGS } else { &DREGS };
                    for (i, &d) in regs.iter().enumerate() {
                        let (dh, dl) = split(d);
                        let (mh, ml) = split(regs[(i + 1) % regs.len()]);
                        let hw1 = 0xFFB0 | (dh << 6) | (size << 2) | a;
                        let hw2 = (dl << 12) | (b << 6) | (mh << 5) | ml;
                        n += round_trip(hw1, hw2) as usize;
                    }
                }
            }
        }
        assert_eq!(n, 828, "two-registers-miscellaneous forms decoded");
    }

    // -- A7.4.2 / A7.4.3 / VEXT / VTBL / VDUP ------------------------------

    #[test]
    fn sweep_three_diff() {
        let mut n = 0;
        for u in 0..2u16 {
            for a in 0..16u16 {
                for size in 0..3u16 {
                    // All three register fields move together, so the wide and
                    // narrowing rows (whose sources are quadwords) meet both
                    // even numbers, which they accept, and odd ones, which
                    // name half a quadword and must be refused.
                    for (i, &d) in QREGS.iter().enumerate() {
                        let (dh, dl) = split(d);
                        let (nh, nl) = split(QREGS[(i + 1) % QREGS.len()]);
                        let (mh, ml) = split(QREGS[(i + 2) % QREGS.len()]);
                        let hw1 = 0xEF80 | (u << 12) | (dh << 6) | (size << 4) | nl;
                        let hw2 = (dl << 12) | (a << 8) | (nh << 7) | (mh << 5) | ml;
                        n += round_trip(hw1, hw2) as usize;
                    }
                }
            }
        }
        assert_eq!(n, 414, "three-registers-different-lengths forms decoded");
    }

    /// `VMOV (register)` is `VORR` with its two sources equal — the page's own
    /// first line is `if !Consistent(M) || !Consistent(Vm) then SEE VORR
    /// (register)` (A8.6.327) — and it is the one row of Table A7-9 that
    /// prints two operands instead of three.
    ///
    /// `sweep_three_same` never sets `N:Vn == M:Vm`, so without this the alias
    /// is decoded in one test and never re-encoded at all.
    #[test]
    fn sweep_vmov_register_alias() {
        let mut n = 0;
        for q in 0..2u16 {
            let regs: &[u16] = if q == 1 { &QREGS } else { &DREGS };
            for (i, &d) in regs.iter().enumerate() {
                let src = regs[(i + 1) % regs.len()];
                let (dh, dl) = split(d);
                let (sh, sl) = split(src);
                // U=0, opc=0b0001, B=1, size=0b10: `VORR (register)`, with
                // `N:Vn` and `M:Vm` both naming `src`.
                let hw1 = 0xEF20 | (dh << 6) | sl;
                let hw2 =
                    (dl << 12) | (0b0001 << 8) | (sh << 7) | (q << 6) | (sh << 5) | 0x0010 | sl;
                n += round_trip(hw1, hw2) as usize;
            }
        }
        assert_eq!(n, 10, "VMOV (register) forms decoded");
    }

    #[test]
    fn sweep_two_scalar() {
        let mut n = 0;
        for u in 0..2u16 {
            for a in 0..16u16 {
                // `size == 0b11` is not this sub-table at all: it is the
                // escape to `VEXT`, `VTBL` and the miscellaneous block.
                for size in 0..3u16 {
                    for &d in &DREGS {
                        // `N:Vn` = 16, so the `Q`-form rows are reachable.
                        let (dh, dl) = split(d);
                        let hw1 = 0xEF80 | (u << 12) | (dh << 6) | (size << 4);
                        let hw2 = (dl << 12) | (a << 8) | 0x0080 | 0x0040 | 3;
                        n += round_trip(hw1, hw2) as usize;
                    }
                }
            }
        }
        assert_eq!(n, 127, "two-registers-and-a-scalar forms decoded");
    }

    #[test]
    fn sweep_vext_vtbl_vdup() {
        let mut ext = 0;
        for imm4 in 0..16u16 {
            for q in 0..2u16 {
                let regs: &[u16] = if q == 1 { &QREGS } else { &DREGS };
                for (i, &d) in regs.iter().enumerate() {
                    let (dh, dl) = split(d);
                    let (nh, nl) = split(regs[(i + 1) % regs.len()]);
                    let (mh, ml) = split(regs[(i + 2) % regs.len()]);
                    let hw1 = 0xEFB0 | (dh << 6) | nl;
                    let hw2 = (dl << 12) | (imm4 << 8) | (nh << 7) | (q << 6) | (mh << 5) | ml;
                    ext += round_trip(hw1, hw2) as usize;
                }
            }
        }
        assert_eq!(ext, 104, "VEXT forms decoded");

        let mut tbl = 0;
        for len in 0..4u16 {
            for op in 0..2u16 {
                for &d in &DREGS {
                    let (dh, dl) = split(d);
                    let (nh, nl) = split(d);
                    let hw1 = 0xFFB0 | (dh << 6) | nl;
                    let hw2 = (dl << 12) | (0b10 << 10) | (len << 8) | (nh << 7) | (op << 6) | 1;
                    tbl += round_trip(hw1, hw2) as usize;
                }
            }
        }
        assert_eq!(tbl, 34, "VTBL/VTBX forms decoded");

        let mut dup = 0;
        for imm4 in 0..16u16 {
            for q in 0..2u16 {
                let regs: &[u16] = if q == 1 { &QREGS } else { &DREGS };
                for &d in regs {
                    let (dh, dl) = split(d);
                    let hw1 = 0xFFB0 | (dh << 6) | imm4;
                    let hw2 = (dl << 12) | (0b1100 << 8) | (q << 6) | 5;
                    dup += round_trip(hw1, hw2) as usize;
                }
            }
        }
        assert_eq!(dup, 154, "VDUP (scalar) forms decoded");
    }

    /// What each `imm4` of `VDUP (scalar)` names: the element size as an
    /// index into [`VDUP_NAMES`] and the lane, or `None` where A8.6.302
    /// leaves the field UNDEFINED.
    ///
    /// `imm4` is the one-hot trick `index_align` plays in A7.7 read the other
    /// way up — the marker is at the bottom and the index above it — and
    /// [`vdup_fields`] is again both directions, `encode_vdup` inverting it by
    /// scanning all sixteen values. So a slip in the shift that lifts the
    /// index off the marker survives every round trip in `sweep_vext_vtbl_vdup`
    /// and changes only which lane of the source register is broadcast:
    /// `vdup.8 d0, d5[7]` and `vdup.8 d0, d5[0]` are the same four bytes to a
    /// sweep and different data to the device.
    #[rustfmt::skip]
    const VDUP_IMM4: [Option<(usize, u8)>; 16] = [
        // `x000` marks nothing and is UNDEFINED; `xxx1` is a byte and keeps
        // three bits of index, `xx10` a halfword with two, `x100` a word with
        // one.
        None,           Some((0, 0)),   Some((1, 0)),   Some((0, 1)),
        Some((2, 0)),   Some((0, 2)),   Some((1, 1)),   Some((0, 3)),
        None,           Some((0, 4)),   Some((1, 2)),   Some((0, 5)),
        Some((2, 1)),   Some((0, 6)),   Some((1, 3)),   Some((0, 7)),
    ];

    /// Every `imm4` of `VDUP (scalar)` names the lane A8.6.302 gives it.
    #[test]
    fn vdup_reads_its_element_size_off_the_bottom_of_imm4() {
        for (imm4, &expect) in VDUP_IMM4.iter().enumerate() {
            assert_eq!(vdup_fields(imm4 as u16), expect, "imm4 {imm4:#06b}");
        }
    }

    // -- The quadword numbering rule ---------------------------------------

    #[test]
    fn quadword_is_the_even_doubleword_pair() {
        // `vadd.i32 q0, q0, q0`: U=0, opc=0b1000, B=0, size=0b10, Q=1, every
        // register field zero. hw1 = 0xEF00 | size<<4 = 0xEF20.
        let insn = decode(0xEF20, 0x0840, 0).expect("q-form with even D:Vd");
        assert_eq!(insn.to_string(), "vadd.i32 q0, q0, q0");

        // The same encoding with Vd = 1 — `D:Vd` odd — names half a quadword
        // and is UNDEFINED (A8.6.271: `if Q == '1' && Vd<0> == '1'`).
        assert_eq!(decode(0xEF20, 0x1840, 0), None);
        // Likewise for `Vn` (hw1[3:0]) and `Vm` (hw2[3:0]).
        assert_eq!(decode(0xEF21, 0x0840, 0), None);
        assert_eq!(decode(0xEF20, 0x0841, 0), None);

        // `q3` is `D:Vd == 6`: D = 0, Vd = 0b0110.
        let q3 = decode(0xEF20, 0x6840, 0).expect("q3");
        assert_eq!(q3.to_string(), "vadd.i32 q3, q0, q0");
        assert_eq!(encode(&q3), Some((0xEF20, 0x6840)));

        // …and `q15` is `D:Vd == 30`: D = 1, Vd = 0b1110, so the high bit is
        // the one outside the four-bit field.
        let q15 = decode(0xEF60, 0xE840, 0).expect("q15");
        assert_eq!(q15.to_string(), "vadd.i32 q15, q0, q0");
        assert_eq!(encode(&q15), Some((0xEF60, 0xE840)));

        // The doubleword form has no such rule: `d1` is a whole register.
        let d1 = decode(0xEF20, 0x1800, 0).expect("d1");
        assert_eq!(d1.to_string(), "vadd.i32 d1, d0, d0");
    }

    // -- AdvSIMDExpandImm --------------------------------------------------

    #[test]
    fn advsimd_expand_imm_matches_table_a7_15() {
        // One vector per expansion rule, hand-expanded from Table A7-15 with
        // abcdefgh = 0b1010_1011.
        assert_eq!(expand_imm(0, 0b0000, 0xAB), Some(0x0000_00AB_0000_00AB));
        assert_eq!(expand_imm(0, 0b0010, 0xAB), Some(0x0000_AB00_0000_AB00));
        assert_eq!(expand_imm(0, 0b0100, 0xAB), Some(0x00AB_0000_00AB_0000));
        assert_eq!(expand_imm(0, 0b0110, 0xAB), Some(0xAB00_0000_AB00_0000));
        assert_eq!(expand_imm(0, 0b1000, 0xAB), Some(0x00AB_00AB_00AB_00AB));
        assert_eq!(expand_imm(0, 0b1010, 0xAB), Some(0xAB00_AB00_AB00_AB00));
        assert_eq!(expand_imm(0, 0b1100, 0xAB), Some(0x0000_ABFF_0000_ABFF));
        assert_eq!(expand_imm(0, 0b1101, 0xAB), Some(0x00AB_FFFF_00AB_FFFF));
        assert_eq!(expand_imm(0, 0b1110, 0xAB), Some(0xABAB_ABAB_ABAB_ABAB));
        // op == 1, cmode == 0b1110: one byte of result per bit of imm8.
        assert_eq!(expand_imm(1, 0b1110, 0xAB), Some(0xFF00_FF00_FF00_FFFF));
        // op == 0, cmode == 0b1111: `aBbbbbbc defgh000`. imm8 == 0 gives
        // exp = UInt(NOT(0):0:0) - 3 = 1 and mantissa = 1, i.e. 2.0.
        assert_eq!(expand_imm(0, 0b1111, 0x00), Some(0x4000_0000_4000_0000));
        // imm8 == 0b0111_0000: a=0, b=1 so B=0 and bbbbb=11111, c=1,
        // defgh=10000 → 0b0_01111111_00000000… = 0x3F800000, which is 1.0
        // (exp = UInt(0:1:1) - 3 = 0, mantissa = 16/16).
        assert_eq!(expand_imm(0, 0b1111, 0x70), Some(0x3F80_0000_3F80_0000));
        // op == 1, cmode == 0b1111 is the one UNDEFINED cell.
        assert_eq!(expand_imm(1, 0b1111, 0xAB), None);
    }

    #[test]
    fn advsimd_expand_imm_inverse_rejects_what_it_cannot_build() {
        let mut ops = Operands::new();
        ops.push(Operand::FpReg(FpReg::D(0)));
        ops.push(Operand::Imm(0x1234_5678));
        let insn = simd("vmov.i32", "T1", 0, ops);
        assert_eq!(
            encode(&insn),
            None,
            "0x12345678 is not a modified immediate"
        );

        // …while a constant that *is* available comes back as the first
        // `cmode` that can produce it (Table A7-15 note b).
        let mut ops = Operands::new();
        ops.push(Operand::FpReg(FpReg::D(0)));
        ops.push(Operand::Imm(0x0000_AB00));
        let insn = simd("vmov.i32", "T1", 0, ops);
        let (hw1, hw2) = encode(&insn).expect("imm8 << 8 is cmode 0b0010");
        assert_eq!((hw2 >> 8) & 0xF, 0b0010);
        assert_eq!(
            decode(hw1, hw2, 0).unwrap().to_string(),
            "vmov.i32 d0, #0xab00"
        );
    }

    // -- Printed UAL --------------------------------------------------------

    /// Decode and print, for the syntax assertions below.
    fn show(hw1: u16, hw2: u16) -> String {
        decode(hw1, hw2, 0x100)
            .expect("halfwords decode")
            .to_string()
    }

    #[test]
    fn the_dispatcher_routes_the_load_store_space_here() {
        // `op1 == 0b11` with `op2 == 0b001xxx0` is Table A5-9's row for the
        // Advanced SIMD element and structure load/stores, and it is the only
        // part of this module the shared dispatcher reaches; the A7.4 data
        // processing space is given to the coprocessor group instead, for the
        // reason set out at the top of this file.
        let insn =
            crate::isa::decode_halfwords(0xF920, 0x070F, 0, Target::Union).expect("routed here");
        assert_eq!(insn.to_string(), "vld1.8 {d0}, [r0]");
        assert_eq!(crate::isa::encode(&insn), Some((0xF920, 0x070F)));
        assert_eq!(
            crate::isa::encode_bytes(&insn),
            Some(vec![0x20, 0xF9, 0x0F, 0x07])
        );
    }

    #[test]
    fn declines_what_belongs_to_the_coprocessor_module() {
        // Every operand of an Advanced SIMD instruction is a `D` or a `Q`
        // register. The VFP forms that share a mnemonic — `VADD.F32` on
        // single-precision registers, `VMOV` between core and extension
        // registers — must fall through to the module that owns them, or
        // `mod.rs`'s ordered `encode` chain breaks.
        let mut ops = Operands::new();
        ops.push(Operand::FpReg(FpReg::S(0)));
        ops.push(Operand::FpReg(FpReg::S(1)));
        ops.push(Operand::FpReg(FpReg::S(2)));
        assert_eq!(encode(&simd("vadd.f32", "T2", 0, ops)), None);

        let mut ops = Operands::new();
        ops.push(Operand::Reg(Reg(0)));
        ops.push(Operand::Reg(Reg(1)));
        ops.push(Operand::FpReg(FpReg::D(2)));
        assert_eq!(encode(&simd("vmov", "T1", 0, ops)), None);

        let mut ops = Operands::new();
        ops.push(Operand::FpReg(FpReg::D(0)));
        ops.push(Operand::FpReg(FpReg::D(1)));
        assert_eq!(encode(&simd("vmov.f64", "T2", 0, ops)), None);

        // …and a narrow instruction is nobody's business here.
        let mut narrow = simd("vmov", "T1", 0, Operands::new());
        narrow.width = Width::Narrow;
        assert_eq!(encode(&narrow), None);
    }

    #[test]
    fn prints_ual_element_and_structure_loads() {
        // VLD1 (multiple single elements), A8.6.307: type = 0b0111 is `{Dd}`,
        // size = 0b00 is `.8`, align = 0b00 is omitted, Rm = 0b1111 is no
        // writeback.
        assert_eq!(show(0xF920, 0x070F), "vld1.8 {d0}, [r0]");
        // VST4 (multiple 4-element structures), A8.6.397: type = 0b0000,
        // size = 0b10, align = 0b10 is `:128`, Rm = 0b1101 is `!`.
        assert_eq!(show(0xF901, 0x00AD), "vst4.32 {d0-d3}, [r1:128]!");
        // The third addressing form: `<Rm>` is a register post-increment.
        assert_eq!(show(0xF920, 0x0703), "vld1.8 {d0}, [r0], r3");
        // Two-register list, 64-bit alignment, and the `D` bit set.
        assert_eq!(show(0xF960, 0x0A1F), "vld1.8 {d16, d17}, [r0:64]");
        // VLD2 double-spaced (type = 0b1001) and VLD3 single-spaced.
        assert_eq!(show(0xF921, 0x090F), "vld2.8 {d0, d2}, [r1]");
        assert_eq!(show(0xF922, 0x144F), "vld3.16 {d1-d3}, [r2]");
        // Single element to one lane, A8.6.308: `.16`, index 3, `:16`.
        assert_eq!(show(0xF9A0, 0x04DF), "vld1.16 {d0[3]}, [r0:16]");
        // Single element to all lanes, A8.6.309, double-spaced.
        assert_eq!(show(0xF9A0, 0x0CAF), "vld1.32 {d0[], d1[]}, [r0]");
        // A 4-element structure from one lane, double-spaced, A8.6.398.
        assert_eq!(
            show(0xF983, 0x3BCF),
            "vst4.32 {d3[1], d5[1], d7[1], d9[1]}, [r3]"
        );
    }

    #[test]
    fn prints_ual_data_processing() {
        // Three registers of the same length.
        assert_eq!(show(0xEF20, 0x0840), "vadd.i32 q0, q0, q0");
        assert_eq!(show(0xEF01, 0x2002), "vhadd.s8 d2, d1, d2");
        assert_eq!(show(0xFF41, 0x2812), "vceq.i8 d18, d1, d2");
        assert_eq!(show(0xEF02, 0x1114), "vand d1, d2, d4");
        assert_eq!(show(0xFF12, 0x1114), "vbsl d1, d2, d4");
        assert_eq!(show(0xEF02, 0x1D04), "vadd.f32 d1, d2, d4");
        assert_eq!(show(0xEF22, 0x1D04), "vsub.f32 d1, d2, d4");
        assert_eq!(show(0xEF24, 0x1114), "vmov d1, d4");
        assert_eq!(show(0xEF02, 0x1B10), "vpadd.i8 d1, d2, d0");
        // The shift-by-register rows name the shifted vector second and the
        // shift amounts third (A8.6.383): this is `d31` shifted by `d17`.
        assert_eq!(show(0xEF01, 0x14AF), "vshl.s8 d1, d31, d17");
        // Two registers and a shift amount.
        assert_eq!(show(0xEF9B, 0x3014), "vshr.s16 d3, d4, #5");
        assert_eq!(show(0xFF88, 0x0514), "vsli.8 d0, d4, #0");
        assert_eq!(show(0xEF8D, 0x0810), "vshrn.i16 d0, q0, #3");
        assert_eq!(show(0xEF88, 0x0A10), "vmovl.s8 q0, d0");
        assert_eq!(show(0xEF89, 0x0A10), "vshll.s8 q0, d0, #1");
        assert_eq!(show(0xEFBF, 0x0E10), "vcvt.f32.s32 d0, d0, #1");
        // One register and a modified immediate value.
        assert_eq!(show(0xFF87, 0x001F), "vmov.i32 d0, #0xff");
        assert_eq!(show(0xFF87, 0x083F), "vmvn.i16 d0, #0xff");
        assert_eq!(show(0xFF87, 0x011F), "vorr.i32 d0, #0xff");
        assert_eq!(show(0xFF87, 0x093F), "vbic.i16 d0, #0xff");
        // Two registers, miscellaneous.
        assert_eq!(show(0xFFB0, 0x0000), "vrev64.8 d0, d0");
        assert_eq!(show(0xFFB0, 0x0540), "vcnt.8 q0, q0");
        assert_eq!(show(0xFFB2, 0x0040), "vswp q0, q0");
        assert_eq!(show(0xFFBA, 0x0140), "vuzp.32 q0, q0");
        assert_eq!(show(0xFFB6, 0x0200), "vmovn.i32 d0, q0");
        assert_eq!(show(0xFFBA, 0x02C0), "vqmovn.u64 d0, q0");
        assert_eq!(show(0xFFB5, 0x0000), "vcgt.s16 d0, d0, #0");
        assert_eq!(show(0xFFB9, 0x07C0), "vneg.f32 q0, q0");
        assert_eq!(show(0xFFBB, 0x0500), "vrecpe.f32 d0, d0");
        assert_eq!(show(0xFFBB, 0x0700), "vcvt.s32.f32 d0, d0");
        assert_eq!(show(0xFFB2, 0x0300), "vshll.i8 q0, d0, #8");
        // The half-precision converts are the two rows of Table A7-13 whose
        // operands are not the same width.
        assert_eq!(show(0xFFB6, 0x0600), "vcvt.f16.f32 d0, q0");
        assert_eq!(show(0xFFB6, 0x0700), "vcvt.f32.f16 q0, d0");
        // Three registers of different lengths, and by-scalar.
        assert_eq!(show(0xEF91, 0x0002), "vaddl.s16 q0, d1, d2");
        assert_eq!(show(0xEF92, 0x0404), "vaddhn.i32 d0, q1, q2");
        assert_eq!(show(0xEF81, 0x0E02), "vmull.p8 q0, d1, d2");
        assert_eq!(show(0xEF91, 0x0043), "vmla.i16 d0, d1, d3[0]");
        assert_eq!(show(0xEFA1, 0x0A43), "vmull.s32 q0, d1, d3[0]");
        // VEXT, VTBL, VDUP.
        assert_eq!(show(0xEFB1, 0x0302), "vext.8 d0, d1, d2, #3");
        assert_eq!(show(0xFFB1, 0x0902), "vtbl.8 d0, {d1, d2}, d2");
        assert_eq!(show(0xFFBA, 0x0C05), "vdup.16 d0, d5[2]");
    }

    // -- The generated register-list spellings ------------------------------

    /// One generated row as text. [`text_of`] wants a `&'static Text`, which a
    /// freshly built row is not, so the NUL trimming is repeated here.
    fn row(count: u8, inc: u8, base: u8, suffix: usize) -> String {
        let r = list_row(count, inc, base, suffix);
        let len = r.iter().position(|&b| b == 0).unwrap_or(TEXT_W);
        String::from_utf8(r[..len].to_vec()).expect("ASCII by construction")
    }

    /// The spellings of A7.2 Table A7-5, built by the same `const fn` that
    /// fills [`LIST_TEXT`] at compile time.
    #[test]
    fn generated_list_spellings_follow_table_a7_5() {
        // Table A7-5 offers `{D0-D3}` as an alternative to `{D0,D1,D2,D3}`;
        // this file takes it for a run of three or more and leaves a run of
        // two as a comma list, which the table also spells.
        assert_eq!(row(1, 1, 0, 0), "{d0}");
        assert_eq!(row(2, 1, 0, 0), "{d0, d1}");
        assert_eq!(row(3, 1, 0, 0), "{d0-d2}");
        assert_eq!(row(4, 1, 28, 0), "{d28-d31}");
        // Double-spaced lists have no range spelling in Table A7-5 at all.
        assert_eq!(row(2, 2, 0, 0), "{d0, d2}");
        assert_eq!(row(4, 2, 1, 0), "{d1, d3, d5, d7}");
        // Suffix 1 is the all-lanes form and 2 + x is lane x, neither of which
        // the table collapses either.
        assert_eq!(row(1, 1, 0, 1), "{d0[]}");
        assert_eq!(row(2, 1, 30, 1), "{d30[], d31[]}");
        assert_eq!(row(1, 1, 9, 2), "{d9[0]}");
        assert_eq!(row(3, 1, 1, 9), "{d1[7], d2[7], d3[7]}");
        // `d10` is where [`put_num`] starts printing two digits, and the one
        // number the sweeps never reach: `DREGS` steps 0, 1, 15, 16, 31 and
        // skips the whole decade. A tens digit dropped here would not fail
        // any round trip — `list_fields` scans the same table back — it would
        // quietly put `{d10}`'s spelling and `{d0}`'s in two rows reading
        // `{d0}`, and the scan would answer `d0` for both.
        assert_eq!(row(1, 1, 9, 0), "{d9}");
        assert_eq!(row(1, 1, 10, 0), "{d10}");
        assert_eq!(row(2, 1, 10, 0), "{d10, d11}");
        // The longest spelling the table can produce — the claim [`TEXT_W`] is
        // sized against.
        let longest = row(4, 2, 24, 9);
        assert_eq!(longest, "{d24[7], d26[7], d28[7], d30[7]}");
        assert_eq!(longest.len(), 32);
        assert!(longest.len() <= TEXT_W);
    }

    /// [`list_text`] is defined exactly where A7.7 spells a list.
    ///
    /// No encoding reaches the domain tests it makes: [`LIST_SHAPES`] has no
    /// one-register double-spaced row because the manual names none, [`dnum`]
    /// is five bits wide so `base` is always below 32, and [`lane_fields`]
    /// yields an index of at most 7 so `suffix` is at most 9. They stay
    /// because the lookup is one flat index — out of its domain it would not
    /// fail but quietly name another shape's row, and print a register list
    /// the instruction does not hold.
    #[test]
    fn list_text_is_defined_exactly_where_a7_7_spells_a_list() {
        assert_eq!(list_text(1, 2, 0, 0), None, "no double-spaced single reg");
        assert_eq!(list_text(5, 1, 0, 0), None, "no five-register list");
        assert_eq!(list_text(1, 1, 32, 0), None, "there is no d32");
        let past_end = LIST_SUFFIXES as u8;
        assert_eq!(list_text(1, 1, 0, past_end), None, "there is no lane 8");
        // A list that would run past `d31` has no spelling either — the
        // `if d+regs > 32 then UNPREDICTABLE` of A8.6.307.
        assert_eq!(list_text(4, 1, 30, 0), None);
        assert_eq!(list_text(4, 1, 28, 0), Some("{d28-d31}"));
    }

    // -- What the tables promise, in place of checks no longer made ---------

    /// Every `(L, n, size)` an A7.7 encoding can reach names a real mnemonic.
    ///
    /// [`decode_elem`] used to test each spelling for emptiness. Deleting a
    /// test is only safe if the case it caught cannot arise, so this asserts
    /// that over the tables instead of once per decode.
    #[test]
    fn every_reachable_element_spelling_exists() {
        for (ty, mult) in MULT_ROWS.iter().enumerate() {
            if mult.n == 0 {
                continue;
            }
            // 64-bit elements belong to the `VLD1`/`VST1` rows and to no
            // others, and those are exactly the rows `ELEM_NAMES` spells a
            // `.64` form for. That is what makes `decode_elem`'s `size == 3`
            // test sufficient and `encode_elem`'s re-test of it unnecessary.
            assert_eq!(mult.size64, mult.n == 1, "MULT_ROWS type {ty:#06b}");
            for names in ELEM_NAMES.iter() {
                for (size, spelling) in names[mult.n as usize - 1].iter().enumerate() {
                    if size == 3 && !mult.size64 {
                        continue;
                    }
                    assert!(!spelling.is_empty(), "VLD{}.{size}", mult.n);
                }
            }
        }
        for n in 1..=4u8 {
            // `all_lanes_fields` never yields the 64-bit size code…
            for raw in 0..4u16 {
                for a in [false, true] {
                    if let Some((size, _)) = all_lanes_fields(n, raw, a) {
                        assert!(size < 3, "all-lanes size {size} for VLD{n}");
                        assert!(!ELEM_NAMES[1][n as usize - 1][size as usize].is_empty());
                    }
                }
            }
            // …and a single-lane `size` is `hw2[11:8] >> 2` read where that
            // field is below `0b1100`, so it is at most 2.
            for names in ELEM_NAMES.iter() {
                for spelling in names[n as usize - 1].iter().take(3) {
                    assert!(!spelling.is_empty(), "VLD{n}");
                }
            }
        }
    }

    /// The other three deletions, each against the table that justifies it.
    #[test]
    fn the_tables_support_the_checks_that_are_not_made() {
        // `decode_shift` prints `VMOVL` without testing the cell, because a
        // lengthening row fixes `L` at 0 and so `code` is at most 2.
        for names in VMOVL_NAMES.iter() {
            for spelling in names.iter().take(3) {
                assert!(!spelling.is_empty());
            }
        }
        // `scalar_operand` has no 8-bit and no 64-bit case, Table A7-11
        // spelling neither.
        for row in SCALAR_ROWS.iter() {
            assert!(row.names[0].is_empty() && row.names[3].is_empty());
        }
        // `encode_scalar` does not re-check the spelling at the row index it
        // recomputes from the operands. In the long rows it cannot differ —
        // `U` is the signedness there, and is taken from the half the name was
        // found in. In the rest `U` *is* `Q`, so the recomputation may cross
        // to the other half, which must therefore spell the same instruction.
        for a in 0..16usize {
            for (found, other) in [(a, a + 16), (a + 16, a)] {
                if SCALAR_ROWS[found].long {
                    continue;
                }
                for size in 0..4 {
                    let name = SCALAR_ROWS[found].names[size];
                    if !name.is_empty() {
                        assert_eq!(SCALAR_ROWS[other].names[size], name);
                    }
                }
            }
        }
        // `decode_modimm` leans on Table A7-15's one UNDEFINED cell and
        // `MODIMM_NAMES`' one empty cell being the same cell.
        for op in 0..2u16 {
            for cmode in 0..16u16 {
                let spelled = !MODIMM_NAMES[op as usize][cmode as usize].is_empty();
                assert_eq!(
                    spelled,
                    expand_imm(op, cmode, 0xAB).is_some(),
                    "op {op} cmode {cmode:#06b}"
                );
            }
        }
    }

    /// The shift amounts A7.4.4 can encode all lie inside the range their
    /// instruction page permits, which is why [`shift_amount`] is total.
    ///
    /// The ranges are the `shift` of A8.6.385 (right: `1..=esize`), A8.6.382
    /// (left: `0..esize`), A8.6.384 (`VSHLL`: `1..esize`, `0` being `VMOVL`)
    /// and the `fbits` of A8.6.296 (`1..=32`).
    #[test]
    fn shift_amounts_stay_inside_their_instruction_page() {
        for l in 0..2u16 {
            for imm6 in 0..64u16 {
                if is_modimm_escape(l, imm6) {
                    continue; // Table A7-14's block, not this one
                }
                let code = shift_code(l, imm6);
                let esize = 8u32 << code;
                let right = shift_amount(ShiftClass::Right, code, imm6);
                assert!((1..=esize).contains(&right), "right {imm6} {code}");
                assert_eq!(shift_amount(ShiftClass::Narrow, code, imm6), right);
                let left = shift_amount(ShiftClass::Left, code, imm6);
                assert!(left < esize, "left {imm6} {code}");
                if l == 0 && code < 3 {
                    let long = shift_amount(ShiftClass::Long, code, imm6);
                    assert!(long < esize, "long {imm6} {code}");
                }
                if imm6 & 0x20 != 0 {
                    // A8.6.296: `imm6<5>` is 1 in every encodable convert.
                    let fbits = shift_amount(ShiftClass::Cvt, 0, imm6);
                    assert!((1..=32).contains(&fbits), "cvt {imm6}");
                }
            }
        }
    }

    // -- What `encode` refuses ---------------------------------------------

    /// A doubleword register operand.
    fn dr(n: u8) -> Operand {
        Operand::FpReg(FpReg::D(n))
    }

    /// A quadword register operand.
    fn qr(n: u8) -> Operand {
        Operand::FpReg(FpReg::Q(n))
    }

    /// A scalar operand, `d<n>[x]`.
    fn sr(n: u8, x: u8) -> Operand {
        Operand::FpScalar(FpReg::D(n), x)
    }

    /// The address operand `[r0]`, with an alignment qualifier in bits.
    fn at_r0(align: u16) -> Operand {
        Operand::Mem(Mem {
            base: Reg(0),
            index: None,
            offset: 0,
            add: true,
            align,
            mode: AddrMode::Offset,
        })
    }

    /// An instruction of the shape this module decodes.
    fn built(mnemonic: &'static str, ops: &[Operand]) -> Insn {
        simd(mnemonic, "T1", 0x1000, ops.iter().copied().collect())
    }

    /// Whether `encode` declines to assemble this spelling.
    fn refused(mnemonic: &'static str, ops: &[Operand]) -> bool {
        encode(&built(mnemonic, ops)).is_none()
    }

    /// Operand shapes the manual does not spell, each named by the page that
    /// refuses it. An encoder that took any of these would emit bytes meaning
    /// something other than what it was handed — or nothing at all.
    #[test]
    fn refuses_shapes_the_architecture_does_not_spell() {
        // Three registers of the same length (Table A7-9). The pairwise rows
        // are doubleword-only: `Q == 1` is UNDEFINED (A8.6.349, A8.6.352,
        // A8.6.353).
        assert!(refused("vpadd.i8", &[qr(0), qr(0), qr(0)]));
        // The three registers must agree in width…
        assert!(refused("vadd.i32", &[qr(0), dr(1), qr(0)]));
        // …and an operand this module did not put there is not ignored.
        assert!(refused("vadd.i32", &[dr(0), dr(1), dr(2), Operand::Imm(0)]));

        // Two registers and a shift amount (Table A7-12).
        assert!(refused("vshr.s16", &[qr(0), dr(1), Operand::Imm(5)]));
        assert!(refused("vshrn.i16", &[qr(0), qr(1), Operand::Imm(3)]));
        assert!(refused("vshll.s8", &[dr(0), dr(1), Operand::Imm(1)]));
        assert!(refused("vmovl.s8", &[qr(0), dr(0), Operand::Imm(1)]));
        assert!(refused("vshr.s16", &[dr(0), dr(1), Operand::Imm(-1)]));
        // A8.6.384: the T1 `VSHLL` shifts by 1 to esize-1. A shift *of* the
        // element size is a different encoding — the T2 in Table A7-13, whose
        // data type is the unsigned-agnostic `i8` — and must not be encoded
        // as a T1 with an out-of-range `imm6`.
        assert!(refused("vshll.s8", &[qr(0), dr(0), Operand::Imm(8)]));
        assert_eq!(
            encode(&built("vshll.i8", &[qr(0), dr(0), Operand::Imm(8)])),
            Some((0xFFB2, 0x0300))
        );
        // The other end of that page is an alias rather than a refusal: "if
        // shift_amount == 0 then SEE VMOVL", so the long spelling with a zero
        // shift assembles to `VMOVL` and disassembles back as `VMOVL`.
        assert_eq!(
            encode(&built("vshll.s8", &[qr(0), dr(0), Operand::Imm(0)])),
            Some((0xEF88, 0x0A10))
        );
        assert_eq!(show(0xEF88, 0x0A10), "vmovl.s8 q0, d0");

        // Two registers, miscellaneous (Table A7-13). A8.6.409: `VUZP.32` on
        // doublewords would be a no-op and the table leaves the cell empty,
        // which the `Q` half of the same row does not.
        assert!(refused("vuzp.32", &[dr(0), dr(1)]));
        assert!(refused("vmovn.i32", &[qr(0), qr(0)]));
        assert!(refused("vcvt.f32.f16", &[dr(0), dr(0)]));
        assert!(refused("vshll.i8", &[qr(0), dr(0), Operand::Imm(7)]));
        assert!(refused("vrev64.8", &[dr(0), qr(0)]));
        // The compare-with-zero rows take `#0` and nothing else (A8.6.285).
        assert!(refused("vcgt.s16", &[dr(0), dr(0), Operand::Imm(1)]));
        assert!(refused("vrev64.8", &[dr(0), dr(0), dr(0)]));

        // Three registers of different lengths (Table A7-10): `VADDL`'s
        // destination is twice the width of its sources (A8.6.274).
        assert!(refused("vaddl.s16", &[dr(0), dr(1), dr(2)]));

        // Two registers and a scalar (Table A7-11).
        assert!(refused("vmull.s16", &[dr(0), dr(1), sr(2, 0)]));
        assert!(refused("vmla.i16", &[qr(0), dr(1), sr(2, 0)]));
        // Table A7-7: a 16-bit scalar names `d0`–`d7` with a two-bit lane, a
        // 32-bit one `d0`–`d15` with a one-bit lane.
        assert!(refused("vmla.i16", &[dr(0), dr(1), sr(9, 0)]));
        assert!(refused("vmla.i32", &[dr(0), dr(1), sr(0, 2)]));

        // `VEXT` (A8.6.305): one width throughout, and a doubleword extract
        // cannot start past byte 7 — `imm4<3>` is 0 when `Q` is 0.
        assert!(refused("vext.8", &[dr(0), qr(1), dr(2), Operand::Imm(3)]));
        assert!(refused("vext.8", &[dr(0), dr(1), dr(2), Operand::Imm(8)]));

        // `VTBL` (A8.6.406): doubleword operands and a single-spaced list of
        // at most four registers.
        assert!(refused(
            "vtbl.8",
            &[qr(0), Operand::Text("{d1, d2}"), dr(2)]
        ));
        assert!(refused(
            "vtbl.8",
            &[dr(0), Operand::Text("{d1, d3}"), dr(2)]
        ));
        assert!(refused("vtbl.8", &[dr(0), Operand::Text("{d1, d2}")]));

        // `VDUP (scalar)` (A8.6.302): `imm4` spells lanes 0–7 of a byte, 0–3
        // of a halfword and 0–1 of a word, and nothing else.
        assert!(refused("vdup.16", &[dr(0)]));
        assert!(refused("vdup.16", &[dr(0), dr(1)]));
        assert!(refused("vdup.8", &[dr(0), sr(0, 9)]));
    }

    /// The element and structure transfers refuse the same way (A7.7).
    #[test]
    fn refuses_element_transfer_shapes_a7_7_does_not_spell() {
        // Table A7-21 has no `1_11xx` row: there is no `VST1` to all lanes.
        assert!(refused(
            "vst1.8",
            &[Operand::Text("{d0[], d1[]}"), at_r0(0)]
        ));
        // A8.6.309: `VLD1` to all lanes writes one or two *consecutive*
        // registers, so neither a double-spaced pair nor a third register.
        assert!(refused(
            "vld1.8",
            &[Operand::Text("{d0[], d2[]}"), at_r0(0)]
        ));
        assert!(refused(
            "vld1.8",
            &[Operand::Text("{d0[], d1[], d2[]}"), at_r0(0)]
        ));
        // A8.6.312: `VLD2` to all lanes names exactly two registers.
        assert!(refused("vld2.8", &[Operand::Text("{d0[]}"), at_r0(0)]));
        // A8.6.315: `VLD3` to all lanes has no alignment qualifier — its `a`
        // bit must be 0 — so `:64` is unencodable.
        assert!(refused(
            "vld3.8",
            &[Operand::Text("{d0[], d1[], d2[]}"), at_r0(64)]
        ));
        // A8.6.308: there is no 64-bit single-lane transfer, the list names
        // exactly `n` registers, and `VLD1.32`'s only alignment is `:32`.
        assert!(refused("vld1.64", &[Operand::Text("{d0[0]}"), at_r0(0)]));
        assert!(refused("vld2.8", &[Operand::Text("{d0[1]}"), at_r0(0)]));
        assert!(refused("vld1.32", &[Operand::Text("{d0[0]}"), at_r0(64)]));
        // A8.6.307: `align` spells 64, 128 or 256 bits, never 8.
        assert!(refused("vld1.8", &[Operand::Text("{d0}"), at_r0(8)]));
        // The list must be one the row can hold: no `VLD1` row is
        // double-spaced (Table A7-20).
        assert!(refused("vld1.8", &[Operand::Text("{d0, d2}"), at_r0(0)]));
        // A7.7.1 spells `[<Rn>{:<align>}]`, `…]!` and `…], <Rm>`, and nothing
        // else: no displacement, no subtraction, no pre-index, and no `<Rm>`
        // of `sp` or `pc`, whose encodings name the other two forms.
        let shapes = [
            (4u32, true, None, AddrMode::Offset),
            (0, false, None, AddrMode::Offset),
            (0, true, None, AddrMode::PreIndex),
            (0, true, Some((Reg(13), None)), AddrMode::PostIndex),
            (0, true, Some((Reg(3), None)), AddrMode::Offset),
        ];
        for (offset, add, index, mode) in shapes {
            let mem = Operand::Mem(Mem {
                base: Reg(0),
                index,
                offset,
                add,
                align: 0,
                mode,
            });
            assert!(
                refused("vld1.8", &[Operand::Text("{d0}"), mem]),
                "{mem:?} is not an A7.7.1 address"
            );
        }
        // `hw1[4]` is a fixed zero in this whole space (A7.7).
        assert_eq!(decode(0xF930, 0x070F, 0), None);
    }

    /// An instruction with no mnemonic assembles to nothing.
    ///
    /// Every spelling table here has empty cells where Arm's table has holes,
    /// and each is searched by mnemonic. A search that matched an empty cell
    /// would hand an `Insn` carrying no mnemonic the encoding of an UNDEFINED
    /// instruction — bytes that decode back to nothing at all.
    #[test]
    fn the_holes_in_the_tables_are_not_spellings() {
        assert!(refused("", &[dr(0), dr(1), dr(2)]));
        assert!(refused("", &[dr(0), dr(1), Operand::Imm(1)]));
        assert!(refused("", &[dr(0), dr(1)]));
        assert!(refused("", &[dr(0), Operand::Imm(1)]));
        assert!(refused("", &[dr(0), dr(1), sr(0, 0)]));
        assert!(refused("", &[Operand::Text("{d0}"), at_r0(0)]));
    }

    /// One encoding of every operand shape this module decodes.
    const SAMPLES: [(u16, u16); 29] = [
        (0xF920, 0x070F), // vld1.8 {d0}, [r0]
        (0xF901, 0x00AD), // vst4.32 {d0-d3}, [r1:128]!
        (0xF920, 0x0703), // vld1.8 {d0}, [r0], r3
        (0xF9A0, 0x0CAF), // vld1.32 {d0[], d1[]}, [r0]
        (0xF9A0, 0x04DF), // vld1.16 {d0[3]}, [r0:16]
        (0xEF20, 0x0840), // vadd.i32 q0, q0, q0
        (0xEF01, 0x2002), // vhadd.s8 d2, d1, d2
        (0xEF24, 0x1114), // vmov d1, d4 — the VORR alias, two operands
        (0xEF01, 0x14AF), // vshl.s8 d1, d31, d17 — sources the other way up
        (0xEF02, 0x1B10), // vpadd.i8 d1, d2, d0 — doubleword-only
        (0xEF9B, 0x3014), // vshr.s16 d3, d4, #5
        (0xEF8D, 0x0810), // vshrn.i16 d0, q0, #3
        (0xEF88, 0x0A10), // vmovl.s8 q0, d0
        (0xEF89, 0x0A10), // vshll.s8 q0, d0, #1
        (0xEFBF, 0x0E10), // vcvt.f32.s32 d0, d0, #1
        (0xFF87, 0x001F), // vmov.i32 d0, #0xff
        (0xFFB0, 0x0000), // vrev64.8 d0, d0
        (0xFFB5, 0x0000), // vcgt.s16 d0, d0, #0
        (0xFFB6, 0x0200), // vmovn.i32 d0, q0
        (0xFFB6, 0x0700), // vcvt.f32.f16 q0, d0
        (0xFFB2, 0x0300), // vshll.i8 q0, d0, #8
        (0xEF91, 0x0002), // vaddl.s16 q0, d1, d2
        (0xEF90, 0x0102), // vaddw.s16 q0, q0, d2
        (0xEF92, 0x0404), // vaddhn.i32 d0, q1, q2
        (0xEF91, 0x0043), // vmla.i16 d0, d1, d3[0]
        (0xEFA1, 0x0A43), // vmull.s32 q0, d1, d3[0]
        (0xEFB1, 0x0302), // vext.8 d0, d1, d2, #3
        (0xFFB1, 0x0902), // vtbl.8 d0, {d1, d2}, d2
        (0xFFBA, 0x0C05), // vdup.16 d0, d5[2]
    ];

    /// Operands that are wrong somewhere: a core register or a list where a
    /// vector belongs, a single-precision register (the VFP module's class),
    /// an odd doubleword where a quadword must start, an immediate out of
    /// every range this module encodes, a lane no element size has, a list of
    /// the wrong length or spacing, and addresses A7.7.1 cannot spell.
    /// Operands to substitute into every slot of every sample.
    ///
    /// The boundary entries at the end were added after mutation testing
    /// showed the shape guards were thoroughly exercised and the *range*
    /// guards were not at all. `FpReg::D`/`Q` and `FpScalar` carry bare
    /// `u8`s with no range invariant, so a caller can name a register or a
    /// lane that does not exist — and each one fails in a different and
    /// quiet way rather than by being out of range:
    ///
    /// * `D(32)` / `Q(16)`: `D:Vd` is five bits, so the number is truncated
    ///   and `d32` assembles to the bytes of `d16`.
    /// * `FpScalar(D(0), 4)`: a 16-bit scalar's lane is two bits and the
    ///   third is already ORed in as a fixed 1, so `d0[4]` assembles to the
    ///   bytes of `d0[0]` — a silently relabelled lane with every other
    ///   field intact.
    /// * `FpScalar(D(8), 0)`: a 16-bit scalar's register is three bits and
    ///   the fourth is the low lane bit, so `d8[0]` becomes `d0[1]`.
    /// * `FpScalar(D(16), 0)`: a 32-bit scalar's register is four bits and
    ///   the fifth is Table A7-8's `C<0>`, which moves the halfwords out of
    ///   the by-scalar block entirely.
    /// * `Imm(1 << 32)`: the shift scan works in `u32`, and `as u32` turns
    ///   this into a shift of zero — which is a real encoding (`VSHLL` by
    ///   zero is `VMOVL`).
    /// * the `align: 128` memory operand: `MULT_ROWS` carries an `align_ok`
    ///   column because a three-register transfer cannot promise 128-bit
    ///   alignment, and an over-aligned list encodes an `align` field the
    ///   architecture leaves UNDEFINED.
    ///
    /// Putting them here rather than in one assertion each is deliberate:
    /// the sweep substitutes every entry into every slot of all 29 samples,
    /// so one row covers every encoder in the module instead of one call
    /// site.
    const WRONG: [Operand; 28] = [
        Operand::Reg(Reg(0)),
        Operand::RegList(0b11),
        Operand::FpReg(FpReg::S(0)),
        Operand::FpReg(FpReg::D(1)),
        Operand::FpReg(FpReg::D(31)),
        Operand::FpReg(FpReg::Q(1)),
        Operand::Imm(0),
        Operand::Imm(-1),
        Operand::Imm(99),
        Operand::FpImm(1.5),
        Operand::FpScalar(FpReg::D(0), 0),
        Operand::FpScalar(FpReg::D(9), 3),
        Operand::FpScalar(FpReg::D(0), 9),
        Operand::FpScalar(FpReg::Q(0), 0),
        Operand::Text("{d0}"),
        Operand::Text("{d0, d2}"),
        Operand::Text("{d0[]}"),
        Operand::Text("{d0[0]}"),
        Operand::Text("not a register list"),
        Operand::FpReg(FpReg::D(32)),
        Operand::FpReg(FpReg::Q(16)),
        Operand::FpScalar(FpReg::D(8), 0),
        Operand::FpScalar(FpReg::D(0), 4),
        Operand::FpScalar(FpReg::D(16), 0),
        Operand::Imm(1 << 32),
        Operand::Mem(Mem {
            base: Reg(0),
            index: None,
            offset: 0,
            add: true,
            align: 128,
            mode: AddrMode::Offset,
        }),
        Operand::Mem(Mem {
            base: Reg(0),
            index: None,
            offset: 0,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        }),
        Operand::Mem(Mem {
            base: Reg(0),
            index: Some((Reg(3), None)),
            offset: 0,
            add: true,
            align: 7,
            mode: AddrMode::PostIndex,
        }),
    ];

    /// `insn` with operand `k` replaced by `with`, or dropped if it is `None`.
    fn mutated(insn: &Insn, k: usize, with: Option<Operand>) -> Insn {
        let mut out = *insn;
        out.operands = insn
            .operands
            .as_slice()
            .enumerate()
            .filter_map(|(i, op)| if i == k { with } else { Some(op) })
            .collect();
        out
    }

    /// `insn` with one operand too many.
    fn appended(insn: &Insn, extra: Operand) -> Insn {
        let mut out = *insn;
        out.operands.push(extra);
        out
    }

    /// `encode` either refuses an instruction or produces bytes that mean it.
    ///
    /// This is the property that matters for a patcher: the operand list an
    /// `Insn` carries is not a hint. Every family is taken apart one operand
    /// at a time — each dropped, each replaced by something of the wrong kind,
    /// class, width or range, and one too many added — and whatever survives
    /// must decode back to exactly the instruction it was built from. A few
    /// mutations *are* other legal instructions (`vadd.i32 q0, q0, q1`), which
    /// is why the assertion is round-trip identity rather than refusal — and
    /// why it allows for the one alias a mutation can reach, `VSHLL` with a
    /// zero shift, which A8.6.384 defines to be `VMOVL`.
    #[test]
    fn encode_reproduces_or_refuses_every_mutation() {
        for &(hw1, hw2) in SAMPLES.iter() {
            let insn = decode(hw1, hw2, 0x1000).expect("sample decodes");
            assert_eq!(encode(&insn), Some((hw1, hw2)), "{insn} does not survive");
            let mut mutants = vec![{
                let mut bare = insn;
                bare.operands = Operands::new();
                bare
            }];
            for k in 0..insn.operands.len() {
                mutants.push(mutated(&insn, k, None));
                for &w in WRONG.iter() {
                    mutants.push(mutated(&insn, k, Some(w)));
                }
            }
            for &w in WRONG.iter() {
                mutants.push(appended(&insn, w));
            }
            for m in mutants {
                if let Some((h1, h2)) = encode(&m) {
                    let back = decode(h1, h2, m.addr).expect("encoded bytes decode");
                    let vshll_zero = imm_at(&m, 2) == Some(0)
                        && VMOVL_NAMES.iter().any(|row| row.contains(&back.mnemonic))
                        && SHIFT_ROWS
                            .iter()
                            .any(|r| r.class == ShiftClass::Long && r.names.contains(&m.mnemonic));
                    if !vshll_zero {
                        assert_eq!(
                            (back.mnemonic, back.operands),
                            (m.mnemonic, m.operands),
                            "{m} encoded to {h1:#06x} {h2:#06x}, which means {back}"
                        );
                    }
                }
            }
        }
    }

    /// The `Insn` header this module produces is part of its contract.
    ///
    /// Nothing in Advanced SIMD is narrow, sets flags, or carries an explicit
    /// width qualifier — `simd` builds every instruction in the group the same
    /// way, so no sweep here ever varies the header and the guard at the top
    /// of `encode` had no coverage at all. A caller can still hand-build an
    /// `Insn` that claims otherwise, and accepting one would return two
    /// halfwords for something asking to be narrow, or silently drop an `s`
    /// that has no bit to live in.
    #[test]
    fn encode_declines_headers_this_group_never_produces() {
        let ok = built("vadd.i32", &[dr(0), dr(1), dr(2)]);
        assert!(encode(&ok).is_some(), "the unmodified header must encode");

        let narrow = Insn {
            width: Width::Narrow,
            ..ok
        };
        assert_eq!(
            encode(&narrow),
            None,
            "no Advanced SIMD instruction is narrow"
        );

        let flagged = Insn {
            sets_flags: true,
            ..ok
        };
        assert_eq!(encode(&flagged), None, "Advanced SIMD writes no APSR flags");

        let suffixed = Insn {
            explicit_width: true,
            ..ok
        };
        assert_eq!(
            encode(&suffixed),
            None,
            "nothing here has a narrow sibling, so `.w` names no instruction"
        );
    }
}
