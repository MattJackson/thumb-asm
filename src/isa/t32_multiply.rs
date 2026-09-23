//! 32-bit multiply, multiply-accumulate, absolute difference, long multiply
//! and divide — `hw1[15:11] == 0b11111` with `hw1[10:4]` of `0110xxx`
//! (ARM DDI 0403E.e A5.3.16, Table A5-28) or `0111xxx` (A5.3.17,
//! Table A5-29). Identically ARM DDI 0406C A6.3.16/A6.3.17, Tables A6-27 and
//! A6-28.
//!
//! Both sub-tables share the top byte `0xFB`; `hw1[7]` is the only bit that
//! tells them apart, which is why one module owns both and [`decode`] splits
//! on that bit rather than on anything in `hw2`.
//!
//! ```text
//! A5.3.16   hw1 = 1111 1011 0 op1(3) Rn(4)    hw2 = Ra(4) Rd(4) 0 0 op2(2) Rm(4)
//! A5.3.17   hw1 = 1111 1011 1 op1(3) Rn(4)    hw2 = RdLo(4) RdHi(4) op2(4) Rm(4)
//! ```
//!
//! # `Ra == 0b1111` is an alias, not a register
//!
//! Almost every row of Table A5-28 is a multiply-accumulate, and almost every
//! one of them spends the `Ra` encoding `0b1111` on naming the *non*-
//! accumulating operation instead of on `r15`: `MLA` becomes `MUL`, `SMLABB`
//! becomes `SMULBB`, `USADA8` becomes `USAD8`, and so on. The accumulating
//! form takes four register operands and the plain form three. Each A7.7 page
//! states it as a decode-time redirection — `if Ra == '1111' then SEE MUL;`
//! (A7.7.74), `... SEE SMULBB, SMULBT, SMULTB, SMULTT;` (A7.7.136),
//! `... SEE USAD8;` (A7.7.212) — so it is not an assembler convenience that
//! could be left to a printer: the two forms are different instructions.
//!
//! Two rows deliberately have no alias, and there `Ra == 0b1111` really does
//! mean `r15` (UNPREDICTABLE, but decodable): `MLS` (`op1 = 000`, `op2 = 01`)
//! and `SMMLS`/`SMMLSR` (`op1 = 110`), both of which Table A5-28 writes with
//! `-` in the `Ra` column. [`Cell::plain`] is `None` for exactly those two.
//!
//! **Table erratum.** The `Ra` column of the `op1 = 111` row is garbled in the
//! text renderings of *both* manuals in `spec/` — ARM DDI 0403E.e Table A5-28
//! extracts as `1111 → USADA8`, ARM DDI 0406C Table A6-27 as
//! `not 1111 → USAD8`, and the two cannot both be right. The encoding
//! diagrams settle it: `USAD8` T1 is `11111011 0111 Rn 1111 Rd 0000 Rm`, with
//! a literal `1111` where `Ra` sits (A7.7.211), and `USADA8` T1 carries a real
//! `Ra` field plus `if Ra == '1111' then SEE USAD8;` (A7.7.212). So this row
//! obeys the same rule as every other: `Ra == 0b1111` is `USAD8`.
//!
//! # Suffixes come from the encoding, not from an operand
//!
//! Three families vary their *mnemonic* with bits of `op2`, which is why this
//! module is a table of `&'static str` rather than anything that builds a
//! name at run time — [`Insn::mnemonic`] is a `&'static str` by design, and
//! the crate does not allocate.
//!
//! * `<x><y>` on the `SMLAxy`/`SMULxy`/`SMLALxy` families: `op2` supplies
//!   `N:M`, `N` selecting which halfword of `Rn` and `M` which halfword of
//!   `Rm`, `0` = bottom and `1` = top (A7.7.136, A7.7.146, A7.7.139). So
//!   `op2 = 0b01` is `BT` — bottom of `Rn`, top of `Rm` — and `0b10` is `TB`.
//!   Transposing those two is silent: both mnemonics exist and both assemble.
//! * `X` on `SMLAD`/`SMUAD`/`SMLSD`/`SMUSD`/`SMLALD`/`SMLSLD`: `op2` bit 0 is
//!   `M`, "swap the halfwords of the second operand before multiplying", so
//!   the products become top × bottom and bottom × top (A7.7.137).
//! * `R` on `SMMLA`/`SMMUL`/`SMMLS`: `op2` bit 0 is `R`, "round rather than
//!   truncate" — the constant `0x80000000` is added before the high word is
//!   extracted (A7.7.144).
//!
//! # Architecture variants
//!
//! A consumer staring at an unknown firmware image can read the core's
//! feature set off this group, so each table row records the variant Arm
//! gives it:
//!
//! * **All** (ARMv6T2 and above, every Thumb-2 profile): `MUL`, `MLA`, `MLS`,
//!   `SMULL`, `UMULL`, `SMLAL`, `UMLAL`.
//! * **v7E-M** (the M-profile DSP extension; on A/R these are baseline
//!   ARMv6T2): everything else in Table A5-28, plus `SMLALBB`…`SMLALTT`,
//!   `SMLALD`, `SMLSLD` and `UMAAL`. An `SMLALD` in the stream means a
//!   Cortex-M4/M7-class core, not an M3.
//! * `SDIV`/`UDIV`: mandatory from ARMv7-M (so present on Cortex-M3 and
//!   above) and present on ARMv7-R, but **UNDEFINED on ARMv7-A** — Table
//!   A6-28 marks them `v7-R` with the footnote "UNDEFINED in ARMv7-A".
//!   Finding one therefore rules an A-profile core out.
//!
//! # What this group does *not* do
//!
//! Nothing here writes the condition flags. Every A7.7 page in the group ends
//! its operation with a plain register write, and the two that mention flags
//! at all (`SMLAxy`, `SMLAD`) set only `APSR.Q` on saturation, which UAL does
//! not spell with an `S`. [`Insn::sets_flags`] therefore stays `false`
//! throughout: `Display` appends `"s"` when it is set, and a stray `true`
//! here would print `muls` — a real instruction, but the 16-bit `MUL` T1 from
//! a different table (A5.2.2).
//!
//! `MUL` is the one operation in this group that also has a 16-bit encoding
//! (T1, `MULS <Rdm>,<Rn>,<Rdm>`), so its wide form is encoding **T2** and is
//! the only member that needs `explicit_width` — without the `.w` an
//! assembler re-reading the printed form is free to pick the narrow encoding
//! and the round-trip is lost. Nothing else in Tables A5-28 or A5-29 has a
//! narrow counterpart, so nothing else carries a width suffix.

use super::{Insn, Operand, Operands, Reg, Width};

/// One cell of Table A5-28 (ARM DDI 0403E.e A5.3.16), selected by
/// `op1` and `op2`.
#[derive(Clone, Copy)]
struct Cell {
    /// The mnemonic when `Ra` is a genuine accumulator operand, i.e. for
    /// every `Ra` except the alias value.
    acc: &'static str,
    /// The mnemonic `Ra == 0b1111` aliases to, or `None` for the two rows
    /// (`MLS`, `SMMLS`) whose `Ra` column Table A5-28 writes as `-` because
    /// they have no non-accumulating counterpart.
    plain: Option<&'static str>,
}

// The four table constructors below are `macro_rules!` and not `const fn`s,
// which is what they were. A `const fn` called only from a `const` initialiser
// is evaluated by the compiler and never runs: it is a real function in the
// binary that no execution ever enters, so the coverage gate reads it —
// correctly — as an uncalled function, and there is no test that can call it
// which would not be a test of the compiler. A macro expands at each call
// site, leaving only the constant it built, which is all these ever were. They
// exist so the tables below stay one row to a line and column-aligned against
// the manual's own tables; see [`TABLE_A5_28`] and [`TABLE_A5_29`].

/// A cell of Table A5-28 whose `Ra == 0b1111` encoding names a different
/// instruction: `both!(accumulating, plain)`.
macro_rules! both {
    ($acc:expr, $plain:expr) => {
        Some(Cell {
            acc: $acc,
            plain: Some($plain),
        })
    };
}

/// A cell of Table A5-28 that reads `Ra` as an ordinary register for all
/// sixteen values: `only!(accumulating)`.
macro_rules! only {
    ($acc:expr) => {
        Some(Cell {
            acc: $acc,
            plain: None,
        })
    };
}

/// Table A5-28, indexed `[op1][op2]`. `None` is UNDEFINED.
///
/// Read across a row and the `op2` columns are exactly the suffix matrix:
/// for `op1 = 001` they are `N:M` (`BB`, `BT`, `TB`, `TT`), and everywhere
/// else only `op2[0]` is live — as `M` for the `X` forms, as `R` for the
/// rounded forms — which is why those rows stop after two columns.
const TABLE_A5_28: [[Option<Cell>; 4]; 8] = [
    // op1     op2 = 00                    op2 = 01                      op2 = 10                      op2 = 11
    /* 000 */
    [both!("mla", "mul"), only!("mls"), None, None], // All
    /* 001 */
    [
        both!("smlabb", "smulbb"),
        both!("smlabt", "smulbt"),
        both!("smlatb", "smultb"),
        both!("smlatt", "smultt"),
    ], // v7E-M
    /* 010 */
    [
        both!("smlad", "smuad"),
        both!("smladx", "smuadx"),
        None,
        None,
    ], // v7E-M
    /* 011 */
    [
        both!("smlawb", "smulwb"),
        both!("smlawt", "smulwt"),
        None,
        None,
    ], // v7E-M
    /* 100 */
    [
        both!("smlsd", "smusd"),
        both!("smlsdx", "smusdx"),
        None,
        None,
    ], // v7E-M
    /* 101 */
    [
        both!("smmla", "smmul"),
        both!("smmlar", "smmulr"),
        None,
        None,
    ], // v7E-M
    /* 110 */
    [only!("smmls"), only!("smmlsr"), None, None], // v7E-M
    /* 111 */
    [both!("usada8", "usad8"), None, None, None], // v7E-M
];

/// Which operand shape a Table A5-29 row uses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shape {
    /// `<RdLo>, <RdHi>, <Rn>, <Rm>` — a 64-bit result in a register pair.
    /// The manual makes `RdLo == RdHi` UNPREDICTABLE for every one of these
    /// (`if dHi == dLo then UNPREDICTABLE;`, e.g. A7.7.138), which this
    /// module decodes and re-encodes faithfully rather than rejecting: an
    /// UNPREDICTABLE encoding is still a defined bit pattern that a real
    /// image can contain, unlike an UNDEFINED one, and a disassembler that
    /// dropped it would leave a hole in the listing.
    Long,
    /// `<Rd>, <Rn>, <Rm>` — `SDIV`/`UDIV`, which put their destination in the
    /// `RdHi` field and leave the `RdLo` field as SBO.
    Div,
}

/// One row of Table A5-29 (ARM DDI 0403E.e A5.3.17).
#[derive(Clone, Copy)]
struct Row29 {
    /// `hw1[6:4]`.
    op1: u16,
    /// `hw2[7:4]`, as a concrete value — the manual's `10xx` and `110x`
    /// patterns are expanded below so that every decodable `(op1, op2)` pair
    /// appears literally.
    op2: u16,
    /// The mnemonic, suffixes and all.
    mnemonic: &'static str,
    /// Operand shape.
    shape: Shape,
}

/// A 64-bit-result row of Table A5-29: `long!(op1, op2, mnemonic)`.
macro_rules! long {
    ($op1:expr, $op2:expr, $mnemonic:expr) => {
        Row29 {
            op1: $op1,
            op2: $op2,
            mnemonic: $mnemonic,
            shape: Shape::Long,
        }
    };
}

/// A divide row of Table A5-29: `div!(op1, op2, mnemonic)`.
macro_rules! div {
    ($op1:expr, $op2:expr, $mnemonic:expr) => {
        Row29 {
            op1: $op1,
            op2: $op2,
            mnemonic: $mnemonic,
            shape: Shape::Div,
        }
    };
}

/// Table A5-29, with the manual's wildcard `op2` patterns expanded.
///
/// Arm writes `100 / 10xx` for the halfword long multiply-accumulates and
/// `100 / 110x`, `101 / 110x` for the dual ones; spelling out the sixteen
/// concrete `op2` values a row covers is what lets [`decode`] be a lookup and
/// lets a reviewer check the `N`/`M` bit order by eye. Fifteen rows out of the
/// 8 × 16 = 128 `(op1, op2)` pairs are allocated; the other 113 are UNDEFINED,
/// including the whole of `op1 = 111`.
const TABLE_A5_29: [Row29; 15] = [
    //    op1     op2     mnemonic            variant
    long!(0b000, 0b0000, "smull"),   // All
    div!(0b001, 0b1111, "sdiv"),     // All of v7-M / v7-R; UNDEFINED on v7-A
    long!(0b010, 0b0000, "umull"),   // All
    div!(0b011, 0b1111, "udiv"),     // All of v7-M / v7-R; UNDEFINED on v7-A
    long!(0b100, 0b0000, "smlal"),   // All
    long!(0b100, 0b1000, "smlalbb"), // v7E-M   op2 = 10 N M
    long!(0b100, 0b1001, "smlalbt"), // v7E-M
    long!(0b100, 0b1010, "smlaltb"), // v7E-M
    long!(0b100, 0b1011, "smlaltt"), // v7E-M
    long!(0b100, 0b1100, "smlald"),  // v7E-M   op2 = 110 M
    long!(0b100, 0b1101, "smlaldx"), // v7E-M
    long!(0b101, 0b1100, "smlsld"),  // v7E-M   op2 = 110 M
    long!(0b101, 0b1101, "smlsldx"), // v7E-M
    long!(0b110, 0b0000, "umlal"),   // All
    long!(0b110, 0b0110, "umaal"),   // v7E-M
];

/// The `Ra` value that turns an accumulating form into a plain multiply, and
/// the value the `RdLo` field of `SDIV`/`UDIV` is specified to hold.
const ALIAS: u8 = 0b1111;

/// Decode an instruction in this group, or `None` if `hw1`/`hw2` do not
/// belong to it — including the UNDEFINED holes in Tables A5-28 and A5-29,
/// which are numerous and must not be guessed at.
pub(crate) fn decode(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    // `hw1[15:8] == 0b1111_1011` is exactly "`hw1[15:11] == 0b11111` and
    // `hw1[10:7]` is `0110` or `0111`", the two `op2` patterns `isa::mod`
    // routes here; `hw1[7]` then picks the sub-table.
    if hw1 >> 8 != 0xFB {
        return None;
    }
    if hw1 & 0x80 == 0 {
        decode_a5_3_16(hw1, hw2, addr)
    } else {
        decode_a5_3_17(hw1, hw2, addr)
    }
}

/// A5.3.16: multiply, multiply accumulate, and absolute difference.
fn decode_a5_3_16(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    // "If, in the second halfword of the instruction, bits[7:6] != 0b00, the
    // instruction is UNDEFINED" (A5.3.16). Every encoding diagram in the
    // group shows those two bits as literal zeros, so this is not a
    // should-be-zero field that may be ignored.
    if hw2 & 0b1100_0000 != 0 {
        return None;
    }
    let op1 = ((hw1 >> 4) & 0b111) as usize;
    let op2 = ((hw2 >> 4) & 0b11) as usize;
    let cell = TABLE_A5_28[op1][op2]?;

    let rn = Reg((hw1 & 0xF) as u8);
    let ra = Reg(((hw2 >> 12) & 0xF) as u8);
    let rd = Reg(((hw2 >> 8) & 0xF) as u8);
    let rm = Reg((hw2 & 0xF) as u8);

    // Every row's syntax line is `<Rd>,<Rn>,<Rm>` with `,<Ra>` appended for
    // the accumulating form, so the first three operands are shared and only
    // the tail and the mnemonic depend on `Ra`.
    let mut operands = Operands::new();
    operands.push(Operand::Reg(rd));
    operands.push(Operand::Reg(rn));
    operands.push(Operand::Reg(rm));
    let mnemonic = match cell.plain {
        Some(plain) if ra.num() == ALIAS => plain,
        _ => {
            operands.push(Operand::Reg(ra));
            cell.acc
        }
    };

    Some(Insn {
        mnemonic,
        // The wide `MUL` is encoding T2 because `MUL` T1 is the 16-bit form
        // (A7.7.84); everything else in the group has a T1 and only a T1.
        encoding: if mnemonic == "mul" { "T2" } else { "T1" },
        addr,
        width: Width::Wide,
        cond: None,
        sets_flags: false,
        // No `.W`. A7.7.84 gives T2 the syntax line `MUL<c> <Rd>,<Rn>,<Rm>`,
        // offering no width qualifier, and LLVM rejects `mul.w` on input for
        // the same reason. The two encodings are told apart by their operands
        // instead: T1 is `<Rdm>,<Rn>,<Rdm>` and sets flags outside an IT block.
        explicit_width: false,
        operands,
    })
}

/// A5.3.17: long multiply, long multiply accumulate, and divide.
fn decode_a5_3_17(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let op1 = (hw1 >> 4) & 0b111;
    let op2 = (hw2 >> 4) & 0xF;
    let row = TABLE_A5_29.iter().find(|r| r.op1 == op1 && r.op2 == op2)?;

    let rn = Reg((hw1 & 0xF) as u8);
    let rdlo = Reg(((hw2 >> 12) & 0xF) as u8);
    let rdhi = Reg(((hw2 >> 8) & 0xF) as u8);
    let rm = Reg((hw2 & 0xF) as u8);

    let mut operands = Operands::new();
    match row.shape {
        // `SMLAL<c> <RdLo>,<RdHi>,<Rn>,<Rm>` (A7.7.138) — four operands, and
        // the destination pair comes first, low half before high half. That
        // is the manual's order and not the bit order: `RdLo` is the *upper*
        // nibble of `hw2`.
        Shape::Long => {
            operands.push(Operand::Reg(rdlo));
            operands.push(Operand::Reg(rdhi));
            operands.push(Operand::Reg(rn));
            operands.push(Operand::Reg(rm));
        }
        // `SDIV<c> <Rd>,<Rn>,<Rm>` (A7.7.127) — the destination sits in the
        // `RdHi` field and the `RdLo` field is `(1)(1)(1)(1)`, SBO. Requiring
        // the architectural `1111` rather than ignoring the field is a
        // deliberate trade: it is the only way [`decode`] and [`encode`] can
        // be exact inverses, since an encode has nothing but `1111` to emit
        // there. A non-conforming image yields `None` instead of an `sdiv`
        // whose bytes this crate could not reproduce.
        Shape::Div => {
            if rdlo.num() != ALIAS {
                return None;
            }
            operands.push(Operand::Reg(rdhi));
            operands.push(Operand::Reg(rn));
            operands.push(Operand::Reg(rm));
        }
    }

    Some(Insn {
        mnemonic: row.mnemonic,
        encoding: "T1",
        addr,
        width: Width::Wide,
        cond: None,
        sets_flags: false,
        // Nothing in Table A5-29 has a 16-bit counterpart, so none of these
        // needs a `.w` to re-assemble unambiguously.
        explicit_width: false,
        operands,
    })
}

/// Re-encode an instruction this module decoded, back to its two halfwords.
///
/// Deliberately strict, because `isa::encode` tries the wide groups in turn
/// and the first `Some` wins: a group that claimed anything beyond its own
/// table would silently steal encodings from its siblings. The gate is the
/// full shape — wide, no flags, the encoding name this module stamps, the
/// exact operand count, all-register operands — and not the mnemonic alone.
/// In particular the narrow `MUL` (T1, A5.2.2) never reaches here: it is
/// `Width::Narrow`, and `isa::encode` routes narrow instructions to the
/// 16-bit groups anyway.
pub(crate) fn encode(insn: &Insn) -> Option<(u16, u16)> {
    // No encoding in either table has an `S` bit, and none is width-suffixed
    // except the wide `MUL`.
    if insn.width != Width::Wide || insn.sets_flags {
        return None;
    }
    encode_a5_3_16(insn).or_else(|| encode_a5_3_17(insn))
}

/// The register number of operand `i`, or `None` if that operand is absent or
/// is not a plain core register.
fn reg_at(insn: &Insn, i: usize) -> Option<u16> {
    match insn.operands.get(i) {
        Some(Operand::Reg(r)) => Some(r.num() as u16),
        _ => None,
    }
}

/// Encode a Table A5-28 instruction, or `None` if the mnemonic is not in it.
fn encode_a5_3_16(insn: &Insn) -> Option<(u16, u16)> {
    // `plain` records which of the cell's two mnemonics matched, which is
    // also which operand shape to expect and what to put in the `Ra` field.
    let (op1, op2, cell, plain) = find_a5_28(insn.mnemonic)?;

    let wide_mul = insn.mnemonic == "mul";
    if insn.encoding != if wide_mul { "T2" } else { "T1" } || insn.explicit_width {
        return None;
    }

    let rd = reg_at(insn, 0)?;
    let rn = reg_at(insn, 1)?;
    let rm = reg_at(insn, 2)?;
    let ra = if plain {
        if insn.operands.len() != 3 {
            return None;
        }
        u16::from(ALIAS)
    } else {
        if insn.operands.len() != 4 {
            return None;
        }
        let ra = reg_at(insn, 3)?;
        // An accumulating form whose row has an alias cannot hold `r15` in
        // `Ra`: those bits mean the plain mnemonic, so emitting them would
        // re-decode as a different instruction.
        if cell.plain.is_some() && ra == u16::from(ALIAS) {
            return None;
        }
        ra
    };

    Some((0xFB00 | op1 << 4 | rn, ra << 12 | rd << 8 | op2 << 4 | rm))
}

/// Encode a Table A5-29 instruction, or `None` if the mnemonic is not in it.
fn encode_a5_3_17(insn: &Insn) -> Option<(u16, u16)> {
    let row = TABLE_A5_29.iter().find(|r| r.mnemonic == insn.mnemonic)?;
    if insn.encoding != "T1" || insn.explicit_width {
        return None;
    }

    // `Rn`'s operand index differs between the shapes — it is third in
    // `<RdLo>, <RdHi>, <Rn>, <Rm>` but second in `<Rd>, <Rn>, <Rm>` — so it is
    // read inside the match rather than shared, which is what made the first
    // cut of this function re-encode `sdiv r0, r0, r1` with `Rn = r1`.
    let (rn, hw2) = match row.shape {
        Shape::Long => {
            if insn.operands.len() != 4 {
                return None;
            }
            let (rdlo, rdhi) = (reg_at(insn, 0)?, reg_at(insn, 1)?);
            let (rn, rm) = (reg_at(insn, 2)?, reg_at(insn, 3)?);
            (rn, rdlo << 12 | rdhi << 8 | row.op2 << 4 | rm)
        }
        Shape::Div => {
            if insn.operands.len() != 3 {
                return None;
            }
            let rd = reg_at(insn, 0)?;
            let (rn, rm) = (reg_at(insn, 1)?, reg_at(insn, 2)?);
            (rn, 0xF000 | rd << 8 | row.op2 << 4 | rm)
        }
    };
    Some((0xFB80 | row.op1 << 4 | rn, hw2))
}

/// Find `mnemonic` in Table A5-28, yielding `(op1, op2, cell, plain)` where
/// `plain` says the match was the `Ra == 0b1111` alias rather than the
/// accumulating form. Every string in the table is distinct, so the first
/// match is the only one.
fn find_a5_28(mnemonic: &str) -> Option<(u16, u16, Cell, bool)> {
    for (op1, row) in TABLE_A5_28.iter().enumerate() {
        for (op2, cell) in row.iter().enumerate() {
            if let Some(cell) = cell {
                if cell.acc == mnemonic {
                    return Some((op1 as u16, op2 as u16, *cell, false));
                }
                if cell.plain == Some(mnemonic) {
                    return Some((op1 as u16, op2 as u16, *cell, true));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::decode_halfwords;

    /// `hw1` for a Table A5-28 encoding.
    fn hw1_28(op1: u16, rn: u16) -> u16 {
        0xFB00 | op1 << 4 | rn
    }

    /// `hw1` for a Table A5-29 encoding.
    fn hw1_29(op1: u16, rn: u16) -> u16 {
        0xFB80 | op1 << 4 | rn
    }

    /// `hw2` for a Table A5-28 encoding: `Ra(4) Rd(4) 00 op2(2) Rm(4)`.
    fn hw2_28(ra: u16, rd: u16, op2: u16, rm: u16) -> u16 {
        ra << 12 | rd << 8 | op2 << 4 | rm
    }

    /// `hw2` for a Table A5-29 encoding: `RdLo(4) RdHi(4) op2(4) Rm(4)`.
    fn hw2_29(rdlo: u16, rdhi: u16, op2: u16, rm: u16) -> u16 {
        rdlo << 12 | rdhi << 8 | op2 << 4 | rm
    }

    /// The printed UAL of an A5.3.16 encoding with `Rd = r0`, `Rn = r1`,
    /// `Rm = r2` and the given `Ra`, so every field is distinguishable.
    fn ual28(op1: u16, op2: u16, ra: u16) -> String {
        decode(hw1_28(op1, 1), hw2_28(ra, 0, op2, 2), 0)
            .expect("allocated in Table A5-28")
            .to_string()
    }

    /// The printed UAL of an A5.3.17 encoding with `RdLo`, `RdHi = r1`,
    /// `Rn = r2`, `Rm = r3`.
    fn ual29(op1: u16, op2: u16, rdlo: u16) -> String {
        decode(hw1_29(op1, 2), hw2_29(rdlo, 1, op2, 3), 0)
            .expect("allocated in Table A5-29")
            .to_string()
    }

    /// Every combination the sweep visits, so a count can be checked against
    /// the tables rather than against itself.
    const RA: [u16; 2] = [0, 15];
    const REGS: [u16; 3] = [0, 1, 15];

    #[test]
    fn a5_3_16_round_trips_exhaustively() {
        let mut decoded = 0usize;
        let mut undefined = 0usize;
        for op1 in 0..8u16 {
            for op2 in 0..4u16 {
                for ra in RA {
                    for rn in REGS {
                        for rd in REGS {
                            for rm in REGS {
                                let hw1 = hw1_28(op1, rn);
                                let hw2 = hw2_28(ra, rd, op2, rm);
                                match decode(hw1, hw2, 0) {
                                    Some(insn) => {
                                        decoded += 1;
                                        assert_eq!(
                                            insn.width,
                                            Width::Wide,
                                            "{hw1:#06x} {hw2:#06x}"
                                        );
                                        assert_eq!(insn.len(), 4, "{hw1:#06x} {hw2:#06x}");
                                        assert!(
                                            !insn.sets_flags,
                                            "nothing in A5.3.16 sets flags: {hw1:#06x} {hw2:#06x}"
                                        );
                                        assert!(insn.cond.is_none(), "{hw1:#06x} {hw2:#06x}");
                                        assert_eq!(
                                            encode(&insn),
                                            Some((hw1, hw2)),
                                            "round-trip of {hw1:#06x} {hw2:#06x} ({insn})"
                                        );
                                    }
                                    None => {
                                        undefined += 1;
                                        assert!(
                                            TABLE_A5_28[op1 as usize][op2 as usize].is_none(),
                                            "{hw1:#06x} {hw2:#06x} is allocated but did not decode"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // 8 op1 x 4 op2 x 2 Ra x 3 Rn x 3 Rd x 3 Rm.
        assert_eq!(decoded + undefined, 1728);
        // Seventeen of the 32 `(op1, op2)` pairs are allocated — 000/00,
        // 000/01, all four of 001, 010/0x, 011/0x, 100/0x, 101/0x, 110/0x and
        // 111/00 — and each covers all 2 x 27 register combinations.
        assert_eq!(decoded, 17 * 54, "allocated cells");
        assert_eq!(decoded, 918);
        // The other fifteen are the UNDEFINED holes: `op2 = 1x` on every row
        // but 001 (six rows x 2 = 12) and `op2 != 00` on 111 (3).
        assert_eq!(undefined, 15 * 54, "UNDEFINED cells");
        assert_eq!(undefined, 810);
    }

    #[test]
    fn a5_3_17_round_trips_exhaustively() {
        let mut decoded = 0usize;
        let mut undefined = 0usize;
        for op1 in 0..8u16 {
            for op2 in 0..16u16 {
                for rdlo in RA {
                    for rn in REGS {
                        for rdhi in REGS {
                            for rm in REGS {
                                let hw1 = hw1_29(op1, rn);
                                let hw2 = hw2_29(rdlo, rdhi, op2, rm);
                                match decode(hw1, hw2, 0) {
                                    Some(insn) => {
                                        decoded += 1;
                                        assert_eq!(
                                            insn.width,
                                            Width::Wide,
                                            "{hw1:#06x} {hw2:#06x}"
                                        );
                                        assert_eq!(insn.encoding, "T1", "{hw1:#06x} {hw2:#06x}");
                                        assert!(
                                            !insn.sets_flags,
                                            "nothing in A5.3.17 sets flags: {hw1:#06x} {hw2:#06x}"
                                        );
                                        assert!(!insn.explicit_width, "{hw1:#06x} {hw2:#06x}");
                                        assert_eq!(
                                            encode(&insn),
                                            Some((hw1, hw2)),
                                            "round-trip of {hw1:#06x} {hw2:#06x} ({insn})"
                                        );
                                    }
                                    None => {
                                        undefined += 1;
                                        // Two reasons, and only two: the pair
                                        // is not in Table A5-29 at all, or it
                                        // is a divide whose SBO `RdLo` field
                                        // is not the architectural `1111`.
                                        let row = TABLE_A5_29
                                            .iter()
                                            .find(|r| r.op1 == op1 && r.op2 == op2);
                                        match row {
                                            None => {}
                                            Some(r) => assert!(
                                                r.shape == Shape::Div && rdlo != 15,
                                                "{hw1:#06x} {hw2:#06x} is allocated but did not decode"
                                            ),
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // 8 op1 x 16 op2 x 2 RdLo x 3 Rn x 3 RdHi x 3 Rm.
        assert_eq!(decoded + undefined, 6912);
        // Fifteen of the 128 `(op1, op2)` pairs are allocated. Thirteen are
        // `Shape::Long` and decode for both `RdLo` values (13 x 54 = 702);
        // the two divides need `RdLo == 1111`, so only half their register
        // combinations decode (2 x 27 = 54).
        assert_eq!(decoded, 13 * 54 + 2 * 27, "allocated rows");
        assert_eq!(decoded, 756);
        // 113 unallocated pairs x 54, plus the divides' 2 x 27 rejected SBO
        // halves.
        assert_eq!(undefined, 113 * 54 + 2 * 27, "UNDEFINED plus SBO rejects");
        assert_eq!(undefined, 6156);
    }

    #[test]
    fn second_halfword_bits_7_6_must_be_zero() {
        // "If, in the second halfword of the instruction, bits[7:6] != 0b00,
        // the instruction is UNDEFINED" (A5.3.16). Only A5.3.16 says this —
        // in A5.3.17 those bits are part of `op2`.
        for op1 in 0..8u16 {
            for op2 in 0..4u16 {
                for high in 1..4u16 {
                    let hw2 = hw2_28(3, 0, op2, 2) | high << 6;
                    assert!(
                        decode(hw1_28(op1, 1), hw2, 0).is_none(),
                        "op1={op1:03b} op2={op2:02b} hw2[7:6]={high:02b}"
                    );
                }
            }
        }
    }

    #[test]
    fn outside_the_group_is_not_ours() {
        // One below (`0101xxx`, data processing (register)) and one above
        // (`1000xxx`, the coprocessor space) in `hw1[10:4]`.
        assert!(decode(0xFAF1, 0xF082, 0).is_none());
        assert!(decode(0xFC01, 0xF002, 0).is_none());
        // A 16-bit halfword can never be ours.
        assert!(decode(0x4351, 0, 0).is_none());
    }

    #[test]
    fn table_a5_28_prints_ual() {
        // Syntax lines from A7.7.73, .74, .75, .136, .146, .137, .147, .141,
        // .148, .142, .149, .143, .145, .144, .212, .211 — `Rd = r0`,
        // `Rn = r1`, `Rm = r2`, `Ra = r3`.
        assert_eq!(ual28(0b000, 0b00, 3), "mla r0, r1, r2, r3");
        assert_eq!(ual28(0b000, 0b00, 15), "mul r0, r1, r2");
        assert_eq!(ual28(0b000, 0b01, 3), "mls r0, r1, r2, r3");

        assert_eq!(ual28(0b001, 0b00, 3), "smlabb r0, r1, r2, r3");
        assert_eq!(ual28(0b001, 0b01, 3), "smlabt r0, r1, r2, r3");
        assert_eq!(ual28(0b001, 0b10, 3), "smlatb r0, r1, r2, r3");
        assert_eq!(ual28(0b001, 0b11, 3), "smlatt r0, r1, r2, r3");
        assert_eq!(ual28(0b001, 0b00, 15), "smulbb r0, r1, r2");
        assert_eq!(ual28(0b001, 0b01, 15), "smulbt r0, r1, r2");
        assert_eq!(ual28(0b001, 0b10, 15), "smultb r0, r1, r2");
        assert_eq!(ual28(0b001, 0b11, 15), "smultt r0, r1, r2");

        assert_eq!(ual28(0b010, 0b00, 3), "smlad r0, r1, r2, r3");
        assert_eq!(ual28(0b010, 0b01, 3), "smladx r0, r1, r2, r3");
        assert_eq!(ual28(0b010, 0b00, 15), "smuad r0, r1, r2");
        assert_eq!(ual28(0b010, 0b01, 15), "smuadx r0, r1, r2");

        assert_eq!(ual28(0b011, 0b00, 3), "smlawb r0, r1, r2, r3");
        assert_eq!(ual28(0b011, 0b01, 3), "smlawt r0, r1, r2, r3");
        assert_eq!(ual28(0b011, 0b00, 15), "smulwb r0, r1, r2");
        assert_eq!(ual28(0b011, 0b01, 15), "smulwt r0, r1, r2");

        assert_eq!(ual28(0b100, 0b00, 3), "smlsd r0, r1, r2, r3");
        assert_eq!(ual28(0b100, 0b01, 3), "smlsdx r0, r1, r2, r3");
        assert_eq!(ual28(0b100, 0b00, 15), "smusd r0, r1, r2");
        assert_eq!(ual28(0b100, 0b01, 15), "smusdx r0, r1, r2");

        assert_eq!(ual28(0b101, 0b00, 3), "smmla r0, r1, r2, r3");
        assert_eq!(ual28(0b101, 0b01, 3), "smmlar r0, r1, r2, r3");
        assert_eq!(ual28(0b101, 0b00, 15), "smmul r0, r1, r2");
        assert_eq!(ual28(0b101, 0b01, 15), "smmulr r0, r1, r2");

        assert_eq!(ual28(0b110, 0b00, 3), "smmls r0, r1, r2, r3");
        assert_eq!(ual28(0b110, 0b01, 3), "smmlsr r0, r1, r2, r3");

        assert_eq!(ual28(0b111, 0b00, 3), "usada8 r0, r1, r2, r3");
        assert_eq!(ual28(0b111, 0b00, 15), "usad8 r0, r1, r2");
    }

    #[test]
    fn table_a5_29_prints_ual() {
        // Syntax lines from A7.7.149, .127, .152, .193, .138, .139, .140,
        // .142, .203, .202 — `RdLo = r0`, `RdHi = r1`, `Rn = r2`, `Rm = r3`,
        // and for the divides `Rd = r1`, `Rn = r2`, `Rm = r3`.
        assert_eq!(ual29(0b000, 0b0000, 0), "smull r0, r1, r2, r3");
        assert_eq!(ual29(0b001, 0b1111, 15), "sdiv r1, r2, r3");
        assert_eq!(ual29(0b010, 0b0000, 0), "umull r0, r1, r2, r3");
        assert_eq!(ual29(0b011, 0b1111, 15), "udiv r1, r2, r3");

        assert_eq!(ual29(0b100, 0b0000, 0), "smlal r0, r1, r2, r3");
        assert_eq!(ual29(0b100, 0b1000, 0), "smlalbb r0, r1, r2, r3");
        assert_eq!(ual29(0b100, 0b1001, 0), "smlalbt r0, r1, r2, r3");
        assert_eq!(ual29(0b100, 0b1010, 0), "smlaltb r0, r1, r2, r3");
        assert_eq!(ual29(0b100, 0b1011, 0), "smlaltt r0, r1, r2, r3");
        assert_eq!(ual29(0b100, 0b1100, 0), "smlald r0, r1, r2, r3");
        assert_eq!(ual29(0b100, 0b1101, 0), "smlaldx r0, r1, r2, r3");

        assert_eq!(ual29(0b101, 0b1100, 0), "smlsld r0, r1, r2, r3");
        assert_eq!(ual29(0b101, 0b1101, 0), "smlsldx r0, r1, r2, r3");

        assert_eq!(ual29(0b110, 0b0000, 0), "umlal r0, r1, r2, r3");
        assert_eq!(ual29(0b110, 0b0110, 0), "umaal r0, r1, r2, r3");
    }

    #[test]
    fn ra_1111_is_the_plain_multiply_not_r15() {
        // Every row of Table A5-28 that has an alias: four operands with a
        // real `Ra`, three with `Ra == 0b1111`, and two different mnemonics.
        let rows: [(u16, u16, &str, &str); 12] = [
            (0b000, 0b00, "mla", "mul"),
            (0b001, 0b00, "smlabb", "smulbb"),
            (0b001, 0b11, "smlatt", "smultt"),
            (0b010, 0b00, "smlad", "smuad"),
            (0b010, 0b01, "smladx", "smuadx"),
            (0b011, 0b00, "smlawb", "smulwb"),
            (0b011, 0b01, "smlawt", "smulwt"),
            (0b100, 0b00, "smlsd", "smusd"),
            (0b100, 0b01, "smlsdx", "smusdx"),
            (0b101, 0b00, "smmla", "smmul"),
            (0b101, 0b01, "smmlar", "smmulr"),
            (0b111, 0b00, "usada8", "usad8"),
        ];
        for (op1, op2, acc, plain) in rows {
            let with_ra = decode(hw1_28(op1, 1), hw2_28(3, 0, op2, 2), 0).unwrap();
            assert_eq!(with_ra.mnemonic, acc, "op1={op1:03b} op2={op2:02b}");
            assert_eq!(with_ra.operands.len(), 4, "{acc} accumulates");
            assert_eq!(with_ra.operands.get(3), Some(Operand::Reg(Reg(3))));

            let aliased = decode(hw1_28(op1, 1), hw2_28(15, 0, op2, 2), 0).unwrap();
            assert_eq!(aliased.mnemonic, plain, "op1={op1:03b} op2={op2:02b}");
            assert_eq!(aliased.operands.len(), 3, "{plain} has nothing to add");
            assert_ne!(with_ra.mnemonic, aliased.mnemonic);
            // The spurious `pc` operand this aliasing exists to prevent.
            assert!(!aliased.to_string().contains("pc"));
        }
    }

    #[test]
    fn the_two_rows_without_an_alias_read_ra_as_r15() {
        // Table A5-28 writes `-` in the `Ra` column for `MLS` (op1 = 000,
        // op2 = 01) and `SMMLS`/`SMMLSR` (op1 = 110), and neither A7.7.75 nor
        // A7.7.145 has an `if Ra == '1111' then SEE ...` line. So `r15` there
        // is just `r15` — UNPREDICTABLE, but a four-operand `mls`.
        for (op1, op2, mnemonic) in [
            (0b000u16, 0b01u16, "mls"),
            (0b110, 0b00, "smmls"),
            (0b110, 0b01, "smmlsr"),
        ] {
            let insn = decode(hw1_28(op1, 1), hw2_28(15, 0, op2, 2), 0).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            assert_eq!(insn.operands.len(), 4);
            assert_eq!(insn.operands.get(3), Some(Operand::Reg(Reg::PC)));
            assert!(insn.to_string().ends_with(", pc"));
            assert_eq!(
                encode(&insn),
                Some((hw1_28(op1, 1), hw2_28(15, 0, op2, 2))),
                "{mnemonic} with r15 still round-trips"
            );
        }
    }

    #[test]
    fn halfword_suffix_matrix_is_n_then_m() {
        // `op2 = N:M`, `N` selecting the half of `Rn` and `M` the half of
        // `Rm`, `0` = bottom, `1` = top (A7.7.136). `BT` is therefore
        // `op2 = 0b01` and `TB` is `0b10`; swapping them is silent, because
        // both mnemonics exist.
        let expected = ["bb", "bt", "tb", "tt"];
        for (op2, half) in expected.iter().enumerate() {
            let op2 = op2 as u16;
            assert_eq!(
                decode(hw1_28(0b001, 1), hw2_28(3, 0, op2, 2), 0)
                    .unwrap()
                    .mnemonic,
                format!("smla{half}"),
                "op2 = {op2:02b}"
            );
            assert_eq!(
                decode(hw1_28(0b001, 1), hw2_28(15, 0, op2, 2), 0)
                    .unwrap()
                    .mnemonic,
                format!("smul{half}"),
                "op2 = {op2:02b}"
            );
            // The long form puts the same `N:M` in `op2[1:0]` under a `10`
            // prefix (Table A5-29, `100 / 10xx`).
            assert_eq!(
                decode(hw1_29(0b100, 2), hw2_29(0, 1, 0b1000 | op2, 3), 0)
                    .unwrap()
                    .mnemonic,
                format!("smlal{half}"),
                "op2 = 10{op2:02b}"
            );
        }
        // And the word-by-halfword row, whose `<y>` is `M` alone.
        assert_eq!(ual28(0b011, 0b00, 3), "smlawb r0, r1, r2, r3");
        assert_eq!(ual28(0b011, 0b01, 3), "smlawt r0, r1, r2, r3");
    }

    #[test]
    fn x_suffix_is_op2_bit_0() {
        // `M == '1'` swaps the halfwords of the second operand (A7.7.137).
        for (op1, base, x) in [(0b010u16, "smlad", "smladx"), (0b100, "smlsd", "smlsdx")] {
            assert_eq!(
                decode(hw1_28(op1, 1), hw2_28(3, 0, 0, 2), 0)
                    .unwrap()
                    .mnemonic,
                base
            );
            assert_eq!(
                decode(hw1_28(op1, 1), hw2_28(3, 0, 1, 2), 0)
                    .unwrap()
                    .mnemonic,
                x
            );
        }
        for (op1, base, x) in [(0b010u16, "smuad", "smuadx"), (0b100, "smusd", "smusdx")] {
            assert_eq!(
                decode(hw1_28(op1, 1), hw2_28(15, 0, 0, 2), 0)
                    .unwrap()
                    .mnemonic,
                base
            );
            assert_eq!(
                decode(hw1_28(op1, 1), hw2_28(15, 0, 1, 2), 0)
                    .unwrap()
                    .mnemonic,
                x
            );
        }
        // The long dual forms: `op2 = 110M`.
        for (op1, base, x) in [
            (0b100u16, "smlald", "smlaldx"),
            (0b101, "smlsld", "smlsldx"),
        ] {
            assert_eq!(
                decode(hw1_29(op1, 2), hw2_29(0, 1, 0b1100, 3), 0)
                    .unwrap()
                    .mnemonic,
                base
            );
            assert_eq!(
                decode(hw1_29(op1, 2), hw2_29(0, 1, 0b1101, 3), 0)
                    .unwrap()
                    .mnemonic,
                x
            );
        }
    }

    #[test]
    fn r_suffix_is_op2_bit_0() {
        // `R == '1'` rounds instead of truncating (A7.7.144).
        for (op1, ra, base, rounded) in [
            (0b101u16, 3u16, "smmla", "smmlar"),
            (0b101, 15, "smmul", "smmulr"),
            (0b110, 3, "smmls", "smmlsr"),
        ] {
            assert_eq!(
                decode(hw1_28(op1, 1), hw2_28(ra, 0, 0, 2), 0)
                    .unwrap()
                    .mnemonic,
                base
            );
            assert_eq!(
                decode(hw1_28(op1, 1), hw2_28(ra, 0, 1, 2), 0)
                    .unwrap()
                    .mnemonic,
                rounded
            );
        }
    }

    #[test]
    fn smlal_names_both_destinations_in_the_manuals_order() {
        // `SMLAL<c><q> <RdLo>, <RdHi>, <Rn>, <Rm>` (A7.7.138): four operands,
        // low half first, and `RdLo` is the *upper* nibble of `hw2`.
        let insn = decode(hw1_29(0b100, 2), hw2_29(4, 5, 0b0000, 3), 0).unwrap();
        assert_eq!(insn.mnemonic, "smlal");
        assert_eq!(insn.operands.len(), 4);
        assert!(insn.operands.len() <= crate::isa::MAX_OPERANDS);
        assert_eq!(insn.operands.get(0), Some(Operand::Reg(Reg(4)))); // RdLo
        assert_eq!(insn.operands.get(1), Some(Operand::Reg(Reg(5)))); // RdHi
        assert_eq!(insn.operands.get(2), Some(Operand::Reg(Reg(2)))); // Rn
        assert_eq!(insn.operands.get(3), Some(Operand::Reg(Reg(3)))); // Rm
        assert_eq!(insn.to_string(), "smlal r4, r5, r2, r3");

        // `if dHi == dLo then UNPREDICTABLE;` — UNPREDICTABLE, not
        // UNDEFINED, so it decodes and round-trips like any other encoding.
        let same = decode(hw1_29(0b100, 2), hw2_29(4, 4, 0b0000, 3), 0).unwrap();
        assert_eq!(same.to_string(), "smlal r4, r4, r2, r3");
        assert_eq!(
            encode(&same),
            Some((hw1_29(0b100, 2), hw2_29(4, 4, 0b0000, 3)))
        );
    }

    #[test]
    fn divides_are_three_operands_with_an_sbo_field() {
        // `SDIV<c> <Rd>,<Rn>,<Rm>` with `(1)(1)(1)(1)` where `RdLo` sits
        // (A7.7.127). Known-good bytes: `sdiv r0, r1, r2` = fb91 f0f2 and
        // `udiv r0, r1, r2` = fbb1 f0f2.
        let sdiv = decode(0xFB91, 0xF0F2, 0).unwrap();
        assert_eq!(sdiv.to_string(), "sdiv r0, r1, r2");
        assert_eq!(sdiv.operands.len(), 3);
        assert_eq!(encode(&sdiv), Some((0xFB91, 0xF0F2)));

        let udiv = decode(0xFBB1, 0xF0F2, 0).unwrap();
        assert_eq!(udiv.to_string(), "udiv r0, r1, r2");
        assert_eq!(encode(&udiv), Some((0xFBB1, 0xF0F2)));

        // A non-conforming SBO field is not decoded, because there would be
        // no way to re-encode it. `op2` still has to be `1111`.
        assert!(decode(0xFB91, 0x00F2, 0).is_none());
        assert!(decode(0xFB91, 0xF002, 0).is_none());
    }

    #[test]
    fn known_good_encodings() {
        // Byte sequences checked against Arm's syntax lines and the field
        // layouts of A5.3.16/A5.3.17.
        for (hw1, hw2, text) in [
            (0xFB01u16, 0xF002u16, "mul r0, r1, r2"),
            (0xFB01, 0x3002, "mla r0, r1, r2, r3"),
            (0xFB01, 0x3012, "mls r0, r1, r2, r3"),
            (0xFB11, 0x3002, "smlabb r0, r1, r2, r3"),
            (0xFB71, 0xF002, "usad8 r0, r1, r2"),
            (0xFB71, 0x3002, "usada8 r0, r1, r2, r3"),
            (0xFB82, 0x0103, "smull r0, r1, r2, r3"),
            (0xFBA2, 0x0103, "umull r0, r1, r2, r3"),
            (0xFBC2, 0x0103, "smlal r0, r1, r2, r3"),
            (0xFBE2, 0x0103, "umlal r0, r1, r2, r3"),
            (0xFBE2, 0x0163, "umaal r0, r1, r2, r3"),
        ] {
            let insn = decode(hw1, hw2, 0).expect(text);
            assert_eq!(insn.to_string(), text);
            assert_eq!(encode(&insn), Some((hw1, hw2)), "{text}");
        }
    }

    #[test]
    fn wide_mul_does_not_collide_with_the_narrow_one() {
        // A7.7.84 gives T2 the syntax line `MUL<c> <Rd>,<Rn>,<Rm>` and offers
        // no width qualifier, so this must print bare `mul` — LLVM rejects
        // `mul.w` outright. What keeps the two encodings apart in text is the
        // operand shape: T1 is `<Rdm>,<Rn>,<Rdm>`, so any instruction whose
        // destination differs from its second source has no narrow form, and
        // outside an IT block T1 sets flags and prints `muls` instead.
        let wide = decode(0xFB01, 0xF002, 0).unwrap();
        assert_eq!(wide.mnemonic, "mul");
        assert_eq!(wide.encoding, "T2");
        assert_eq!(wide.width, Width::Wide);
        assert!(!wide.explicit_width);
        assert!(!wide.sets_flags, "`muls` is the 16-bit T1, not this");
        assert_eq!(wide.to_string(), "mul r0, r1, r2");
        assert_eq!(encode(&wide), Some((0xFB01, 0xF002)));

        // The whole-crate dispatcher agrees, in both directions.
        assert_eq!(decode_halfwords(0xFB01, 0xF002, 0, false), Some(wide));
        assert_eq!(crate::isa::encode(&wide), Some((0xFB01, 0xF002)));

        // And the 16-bit `MULS r1, r2, r1` is emphatically not ours: this
        // module must not claim it, or `isa::encode` would hand back wide
        // halfwords for a narrow instruction.
        let narrow = decode_halfwords(0x4351, 0, 0, false).unwrap();
        assert_eq!(narrow.mnemonic, "mul");
        assert_eq!(narrow.width, Width::Narrow);
        assert_eq!(encode(&narrow), None);
        assert_eq!(crate::isa::encode(&narrow), Some((0x4351, 0)));
    }

    #[test]
    fn the_dispatcher_routes_both_sub_tables_here() {
        // `isa::mod` sends `hw1[10:4]` of `0110xxx` and `0111xxx` to this
        // module; confirm with one encoding from each that the whole-crate
        // entry point produces what `decode` does.
        for (hw1, hw2) in [(0xFB11u16, 0x3002u16), (0xFBC2, 0x0103)] {
            assert_eq!(decode_halfwords(hw1, hw2, 0, false), decode(hw1, hw2, 0));
            assert!(decode(hw1, hw2, 0).is_some());
        }
    }

    #[test]
    fn addr_is_carried_through() {
        // Nothing in this group is pc-relative, but `Insn::addr` still has to
        // be what it was decoded at.
        let insn = decode(0xFB01, 0xF002, 0x8010).unwrap();
        assert_eq!(insn.addr, 0x8010);
        assert!(insn.branch_target().is_none());
    }

    #[test]
    fn encode_rejects_what_this_group_cannot_hold() {
        let mla = decode(0xFB01, 0x3002, 0).unwrap();
        let smlal = decode(0xFBC2, 0x0103, 0).unwrap();

        // A mnemonic from another group.
        let mut foreign = mla;
        foreign.mnemonic = "add";
        assert_eq!(encode(&foreign), None);

        // Narrow width, or the wrong encoding name.
        let mut narrow = mla;
        narrow.width = Width::Narrow;
        assert_eq!(encode(&narrow), None);
        let mut t2 = mla;
        t2.encoding = "T2";
        assert_eq!(encode(&t2), None);
        let mut suffixed = mla;
        suffixed.explicit_width = true;
        assert_eq!(encode(&suffixed), None);

        // `mul` here is the T2 form and nothing else, and it carries no
        // width suffix — a `.w` on it is not an encoding this group produces.
        let mut mul = decode(0xFB01, 0xF002, 0).unwrap();
        mul.encoding = "T1";
        assert_eq!(encode(&mul), None);
        let mut suffixed_mul = decode(0xFB01, 0xF002, 0).unwrap();
        suffixed_mul.explicit_width = true;
        assert_eq!(encode(&suffixed_mul), None);

        // Nothing in the group sets flags.
        let mut flagged = mla;
        flagged.sets_flags = true;
        assert_eq!(encode(&flagged), None);

        // `Ra == r15` on an aliasing row is the plain mnemonic's encoding, so
        // an `mla` holding it cannot be represented.
        let mut mla_pc = mla;
        mla_pc.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Reg(Reg(2)),
            Operand::Reg(Reg::PC),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&mla_pc), None);

        // Wrong operand counts, in both directions and both shapes.
        let mut short_mla = mla;
        short_mla.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Reg(Reg(2)),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&short_mla), None);

        let mut long_mul = decode(0xFB01, 0xF002, 0).unwrap();
        long_mul.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Reg(Reg(2)),
            Operand::Reg(Reg(3)),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&long_mul), None);

        let mut short_smlal = smlal;
        short_smlal.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Reg(Reg(2)),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&short_smlal), None);

        let mut long_sdiv = decode(0xFB91, 0xF0F2, 0).unwrap();
        long_sdiv.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Reg(Reg(2)),
            Operand::Reg(Reg(3)),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&long_sdiv), None);

        // The A5-29 half gates width and encoding name in its own function,
        // so `mla`'s rejection above says nothing about it. A long multiply
        // or divide is T1, and nothing in Table A5-29 has a narrow
        // counterpart to need a `.w`.
        let mut smlal_t2 = smlal;
        smlal_t2.encoding = "T2";
        assert_eq!(encode(&smlal_t2), None, "no T2 in Table A5-29");
        let mut smlal_wide = smlal;
        smlal_wide.explicit_width = true;
        assert_eq!(encode(&smlal_wide), None, "`smlal.w` is not a spelling");

        // Non-register operands, in every slot of every operand shape.
        //
        // Each field is read from a fixed index, and the two halves of this
        // group disagree about what that index means — `Rn` is operand 2 in
        // `<RdLo>,<RdHi>,<Rn>,<Rm>` and operand 1 in `<Rd>,<Rn>,<Rm>`, which
        // is the transposition the `encode_a5_3_17` comment records as a real
        // bug once fixed. A slot that is checked nowhere is a slot whose
        // contents could be read from the wrong place without a test noticing,
        // so every one of them is asked directly.
        let shapes: [(Insn, usize); 4] = [
            (mla, 4),                                // A5-28, accumulating
            (decode(0xFB01, 0xF002, 0).unwrap(), 3), // A5-28, plain (`mul`)
            (smlal, 4),                              // A5-29, `Shape::Long`
            (decode(0xFB91, 0xF0F2, 0).unwrap(), 3), // A5-29, `Shape::Div`
        ];
        for (template, arity) in shapes {
            assert_eq!(
                template.operands.len(),
                arity,
                "`{}` should take {arity} operands",
                template.mnemonic
            );
            for slot in 0..arity {
                let mut mangled = template;
                mangled.operands = (0..arity)
                    .map(|i| {
                        if i == slot {
                            Operand::Imm(0)
                        } else {
                            Operand::Reg(Reg(i as u8))
                        }
                    })
                    .collect();
                assert_eq!(
                    encode(&mangled),
                    None,
                    "`{}` with a non-register in operand {slot}",
                    template.mnemonic
                );
            }
        }
    }
}
