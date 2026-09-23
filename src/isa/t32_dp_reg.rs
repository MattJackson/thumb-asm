//! Data processing (register), the two parallel add/subtract tables, and the
//! miscellaneous operations — `hw1[15:8] == 0b1111_1010` (ARM DDI 0403E.e
//! A5.3.12–A5.3.15, Tables A5-24 to A5-27; identically ARM DDI 0406C
//! A6.3.12–A6.3.15, Tables A6-23 to A6-26).
//!
//! Four numbered sub-tables share one dispatch arm because they share one
//! encoding shape:
//!
//! ```text
//! hw1 = 1 1 1 1 1 0 1 0 | op1(4) | Rn(4)
//! hw2 = 1 1 1 1         | Rd(4)  | op2(4) | Rm(4)
//! ```
//!
//! Table A5-24 is the top level. `op1[3] == 0` keeps the instruction here —
//! the shift-by-register forms and the six extend pairs. `op1[3] == 1` hands
//! the rest of `op1` and all of `op2` to one of the three continuation tables,
//! selected by `op2[3:2]`: `00` and `01` are the signed and unsigned parallel
//! grids (A5-25, A5-26), `10` is the miscellaneous table (A5-27), and `11` is
//! unallocated.
//!
//! # The first check is not a table lookup
//!
//! Stated under the A5.3.12 bit diagram and repeated under each of A5.3.13,
//! A5.3.14 and A5.3.15: *if, in the second halfword, bits[15:12] != 0b1111,
//! the instruction is UNDEFINED*. That is a quarter of the group's encoding
//! space rejected before any `op1`/`op2` decoding happens, and it is the one
//! rule a table-driven decoder is most likely to skip, because it lives in the
//! prose rather than in a table row.
//!
//! # What "the same bits, different `Rn`" means here
//!
//! Six of Table A5-24's rows are pairs: `op1 == 0b0000` with `op2 == 0b1xxx`
//! is `SXTAH` (sign-extend a halfword of `Rm` and add `Rn`) unless `Rn` is
//! `0b1111`, in which case there is nothing to add to and the instruction is
//! the plain `SXTH`. The instruction pages say so from the other direction —
//! A7.7.181's decode pseudocode opens `if Rn == '1111' then SEE SXTH;` — so
//! the aliasing is architectural, not a disassembler convention. Reading it
//! backwards yields an instruction that is plausible, assembles, and is wrong.
//!
//! # `(0)` and `Consistent(Rm)`: two ways a bit pattern can be in a table and
//! still not be an instruction
//!
//! The extends encode `hw2 = 1111 Rd 1 (0) rotate Rm`. Bit 6 is a
//! *should-be-zero* bit, and an encoding diagram's `(0)` means exactly one
//! thing (DDI 0406C A6.1.1, and Appendix I.1 for the diagram convention
//! itself): a Thumb instruction is UNPREDICTABLE if a bit marked `(0)` is not
//! `0`. This decoder declines those encodings rather than decoding them and
//! silently dropping a bit it could never put back — an instruction that
//! decodes here must re-encode to the halfwords it came from, and that
//! invariant is worth more than claiming four `op2` values whose behaviour the
//! architecture refuses to define.
//!
//! `REV`, `REV16`, `RBIT`, `REVSH` and `CLZ` encode their single source
//! register *twice*, in `hw1`'s `Rn` field and in `hw2`'s `Rm` field, and
//! every one of those pages opens with `if !Consistent(Rm) then
//! UNPREDICTABLE;`. Same reasoning, same treatment: the two fields must agree.
//!
//! # Flags
//!
//! Only the four shift-by-register forms have an `S` bit — it is `op1[0]`, so
//! `LSL (register)` occupies `op1` of `0b0000` *and* `0b0001`. Nothing else in
//! these four tables sets the `N`/`Z`/`C`/`V` flags. The parallel instructions
//! write `APSR.GE` and the saturating ones write `APSR.Q`, but neither is the
//! `S` suffix, and [`Insn`]'s `Display` prints an `s` for every `sets_flags`,
//! so a stray `true` here would emit `qadd16s` — a mnemonic no assembler
//! accepts.
//!
//! # Extensions
//!
//! Most of this group is DSP-extension territory. The whole of A5-25 and A5-26
//! is v7E-M, as are the extend-and-add forms, `SXTB16`/`UXTB16`, `SEL`, and
//! the four saturating `Q` operations. Only the shifts, the plain byte and
//! halfword extends, `REV`/`REV16`/`RBIT`/`REVSH` and `CLZ` are baseline. The
//! variant column of each table is reproduced in the comments beside it,
//! because a consumer analysing what it believed to be a Cortex-M3 image and
//! finding a `QADD16` has learned something important about the image.

use super::{Insn, Operand, Operands, Reg, Shift, ShiftAmount, ShiftKind, Width};

/// The fixed `hw1[15:8]` of every encoding in these four tables.
const GROUP: u16 = 0b1111_1010;

/// The `Rn` value that means "no register": the extend rows of Table A5-24
/// read it as "this is the plain extend, not the extend-and-add".
const RN_NONE: u8 = 0b1111;

/// Table A5-24 rows `000x`–`011x` — the shift-by-register forms, indexed by
/// `op1[3:1]`. All variants.
///
/// `op1[0]` is the `S` bit (A7.7.69 encoding T2 is
/// `1111 1010 000S Rn 1111 Rd 0000 Rm`), which is why each of these occupies
/// two `op1` values, and why Table A5-24 writes the row as `000x`. `op2` must
/// be `0b0000` exactly.
const SHIFTS: [&str; 4] = [
    "lsl", // 000x  LSL (register) A7.7.69 T2
    "lsr", // 001x  LSR (register) A7.7.71 T2
    "asr", // 010x  ASR (register) A7.7.11 T2
    "ror", // 011x  ROR (register) A7.7.117 T2
];

/// Table A5-24 rows `0000`–`0101` — the extends, indexed by `op1`.
///
/// Each row is `(extend-and-add, plain extend)`: the first is selected when
/// `Rn != 0b1111`, the second when it is. Every one of these rows requires
/// `op2 == 0b1xxx`, where `op2[1:0]` is the `rotate` field and `op2[2]` is a
/// should-be-zero bit.
///
/// Variants, from the table's own column: the `and-add` forms are all v7E-M;
/// of the plain extends, `SXTB16` and `UXTB16` are v7E-M and the other four
/// are in every version of the architecture that has 32-bit Thumb.
const EXTENDS: [(&str, &str); 6] = [
    ("sxtah", "sxth"),     // 0000  A7.7.181 / A7.7.184 T2
    ("uxtah", "uxth"),     // 0001  A7.7.220 / A7.7.223 T2
    ("sxtab16", "sxtb16"), // 0010  A7.7.180 / A7.7.183
    ("uxtab16", "uxtb16"), // 0011  A7.7.219 / A7.7.222
    ("sxtab", "sxtb"),     // 0100  A7.7.179 / A7.7.182 T2
    ("uxtab", "uxtb"),     // 0101  A7.7.218 / A7.7.221 T2
];

/// Tables A5-25 and A5-26 — the signed and unsigned parallel add/subtract
/// grids, every entry v7E-M.
///
/// Indexed `[op2[2]][op2[1:0]][op1[2:0]]`: the first index picks the signed
/// (`0`) or unsigned (`1`) table, the second the variant — `00` plain, `01`
/// saturating, `10` halving — and the third the operation. Arm prints the rows
/// in the order 001, 010, 110, 101, 000, 100; they are in numeric order here,
/// which is why the columns read add8, add16, asx, —, sub8, sub16, sax, —.
/// `op1[2:0]` of `0b011` and `0b111`, and `op2[1:0]` of `0b11`, are holes.
const PARALLEL: [[[&str; 8]; 3]; 2] = [
    [
        // Signed, op2[1:0] == 00: A7.7.122, .121, .123, .157, .156, .154.
        ["sadd8", "sadd16", "sasx", "", "ssub8", "ssub16", "ssax", ""],
        // Signed saturating, op2[1:0] == 01: A7.7.104, .103, .105, .111, .110, .108.
        ["qadd8", "qadd16", "qasx", "", "qsub8", "qsub16", "qsax", ""],
        // Signed halving, op2[1:0] == 10: A7.7.131, .130, .132, .135, .134, .133.
        [
            "shadd8", "shadd16", "shasx", "", "shsub8", "shsub16", "shsax", "",
        ],
    ],
    [
        // Unsigned, op2[1:0] == 00: A7.7.191, .190, .192, .217, .216, .215.
        ["uadd8", "uadd16", "uasx", "", "usub8", "usub16", "usax", ""],
        // Unsigned saturating, op2[1:0] == 01: A7.7.206, .205, .207, .210, .209, .208.
        [
            "uqadd8", "uqadd16", "uqasx", "", "uqsub8", "uqsub16", "uqsax", "",
        ],
        // Unsigned halving, op2[1:0] == 10: A7.7.197, .196, .198, .201, .200, .199.
        [
            "uhadd8", "uhadd16", "uhasx", "", "uhsub8", "uhsub16", "uhsax", "",
        ],
    ],
];

/// Table A5-27 — the miscellaneous operations, indexed `[op1[1:0]][op2[1:0]]`.
///
/// Reached only when `op1 == 0b10xx` and `op2 == 0b10xx`. The last two rows
/// allocate one column each; the rest of those rows is UNDEFINED. Variants:
/// the saturating row is v7E-M and so is `SEL`; the reverse row and `CLZ` are
/// in every version.
///
/// The row index also selects the operand order, which is *not* uniform —
/// see [`decode`].
const MISC: [[&str; 4]; 4] = [
    ["qadd", "qdadd", "qsub", "qdsub"], // 00  A7.7.102, .106, .109, .107
    ["rev", "rev16", "rbit", "revsh"],  // 01  A7.7.113, .114, .112, .115
    ["sel", "", "", ""],                // 10  A7.7.128
    ["clz", "", "", ""],                // 11  A7.7.24
];

/// Whether this mnemonic also names a 16-bit encoding, so that UAL needs an
/// explicit `.w` to select the wide one.
///
/// The answer doubles as the encoding name: a wide encoding in this group is
/// `T2` exactly when a narrow `T1` got there first, and `T1` otherwise. That
/// is not a coincidence — the encodings are numbered in the order the
/// architecture defined them — so both facts come from one list and cannot
/// drift apart. Each entry is the manual's own syntax line: A7.7.69 spells
/// encoding T2 `LSL{S}<c>.W <Rd>,<Rn>,<Rm>` and A7.7.184 spells it
/// `SXTH<c>.W <Rd>,<Rm>{,<rotation>}`, `.W` and all.
///
/// Everything else here — the extend-and-adds, `SXTB16`/`UXTB16`, all 36
/// parallel operations, the four saturating `Q` forms, `SEL`, `RBIT` and
/// `CLZ` — exists only as a 32-bit encoding, so a width suffix would be noise.
fn has_narrow_counterpart(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "lsl"
            | "lsr"
            | "asr"
            | "ror"
            | "sxtb"
            | "sxth"
            | "uxtb"
            | "uxth"
            | "rev"
            | "rev16"
            | "revsh"
    )
}

/// The architectural encoding name this group decodes `mnemonic` as.
fn encoding_name(mnemonic: &str) -> &'static str {
    if has_narrow_counterpart(mnemonic) {
        "T2"
    } else {
        "T1"
    }
}

/// The `Rm` operand of an extend, carrying its optional rotation.
///
/// `rotation = UInt(rotate:'000')`, so the four encodable amounts are 0, 8, 16
/// and 24 (A7.7.184). UAL omits a zero rotation entirely — the manual is
/// explicit that `ROR #0`, while an assembler may accept it, "is not standard
/// UAL and must not be used for disassembly" — so a zero rotation produces a
/// bare [`Operand::Reg`] and only a non-zero one produces an
/// [`Operand::RegShifted`].
fn extended_operand(rm: Reg, rotate: u8) -> Operand {
    if rotate == 0 {
        Operand::Reg(rm)
    } else {
        Operand::RegShifted(
            rm,
            Shift {
                kind: ShiftKind::Ror,
                amount: ShiftAmount::Imm(rotate * 8),
            },
        )
    }
}

/// Decode an instruction in this group, or `None` if `hw1`/`hw2` do not
/// belong to it.
pub(crate) fn decode(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 >> 8 != GROUP {
        return None;
    }
    // A5.3.12, immediately under the bit diagram: "If, in the second halfword
    // of the instruction, bits[15:12] != 0b1111, the instruction is
    // UNDEFINED." Before any table is consulted.
    if hw2 >> 12 != 0b1111 {
        return None;
    }

    let op1 = ((hw1 >> 4) & 0xF) as u8;
    let rn = Reg((hw1 & 0xF) as u8);
    let rd = Reg(((hw2 >> 8) & 0xF) as u8);
    let op2 = ((hw2 >> 4) & 0xF) as u8;
    let rm = Reg((hw2 & 0xF) as u8);

    let mut operands = Operands::new();
    operands.push(Operand::Reg(rd));
    let mut sets_flags = false;

    let mnemonic = if op1 & 0b1000 == 0 {
        // The top half of Table A5-24 stays in this table.
        if op2 == 0b0000 {
            // `000x`/`001x`/`010x`/`011x` with `op2 == 0000`:
            // `LSL{S}.W <Rd>,<Rn>,<Rm>` and friends.
            sets_flags = op1 & 1 == 1;
            operands.push(Operand::Reg(rn));
            operands.push(Operand::Reg(rm));
            SHIFTS[(op1 >> 1) as usize]
        } else if op2 & 0b1000 != 0 {
            // `0000`..`0101` with `op2 == 1xxx`: the extend pairs. Rows
            // `011x` have no extend, so `EXTENDS` runs out and this is
            // UNDEFINED.
            let (and_add, plain) = *EXTENDS.get(op1 as usize)?;
            // `hw2[6]` is `(0)` in every one of these encodings.
            if op2 & 0b0100 != 0 {
                return None;
            }
            let rotated = extended_operand(rm, op2 & 0b11);
            if rn.num() == RN_NONE {
                operands.push(rotated);
                plain
            } else {
                operands.push(Operand::Reg(rn));
                operands.push(rotated);
                and_add
            }
        } else {
            // `op2` of `0001`..`0111`: no row in Table A5-24.
            return None;
        }
    } else if op2 & 0b1000 == 0 {
        // `1xxx` with `op2 == 00xx` or `01xx`: Tables A5-25 and A5-26. Every
        // one is `<Rd>,<Rn>,<Rm>`.
        let variant = op2 & 0b11;
        if variant == 0b11 {
            return None;
        }
        let mnemonic =
            PARALLEL[((op2 >> 2) & 1) as usize][variant as usize][(op1 & 0b111) as usize];
        if mnemonic.is_empty() {
            return None;
        }
        operands.push(Operand::Reg(rn));
        operands.push(Operand::Reg(rm));
        mnemonic
    } else if op1 & 0b0100 == 0 && op2 & 0b0100 == 0 {
        // `10xx` with `op2 == 10xx`: Table A5-27.
        let row = (op1 & 0b11) as usize;
        let mnemonic = MISC[row][(op2 & 0b11) as usize];
        if mnemonic.is_empty() {
            return None;
        }
        match row {
            // The saturating row reads its operands *backwards*: A7.7.102
            // spells it `QADD<c> <Rd>,<Rm>,<Rn>`, and the pseudocode agrees —
            // `R[d] = SignedSatQ(SInt(R[m]) - SInt(R[n]))` for `QSUB`, so
            // printing `Rn` first would invert every subtraction.
            0 => {
                operands.push(Operand::Reg(rm));
                operands.push(Operand::Reg(rn));
            }
            // `SEL<c> <Rd>,<Rn>,<Rm>` (A7.7.128).
            2 => {
                operands.push(Operand::Reg(rn));
                operands.push(Operand::Reg(rm));
            }
            // The reverse row and `CLZ` take one source register, encoded
            // twice: `if !Consistent(Rm) then UNPREDICTABLE`.
            _ => {
                if rn != rm {
                    return None;
                }
                operands.push(Operand::Reg(rm));
            }
        }
        mnemonic
    } else {
        // `11xx` with `op2 == 10xx` (no miscellaneous row), or any `op1` with
        // `op2 == 11xx` (unallocated in Table A5-24).
        return None;
    };

    Some(Insn {
        mnemonic,
        encoding: encoding_name(mnemonic),
        addr,
        width: Width::Wide,
        cond: None,
        sets_flags,
        explicit_width: has_narrow_counterpart(mnemonic),
        operands,
    })
}

/// The `i`th operand as a plain core register.
fn reg(insn: &Insn, i: usize) -> Option<Reg> {
    match insn.operands.get(i)? {
        Operand::Reg(r) if r.0 < 16 => Some(r),
        _ => None,
    }
}

/// The `i`th operand as an extend's source register, returning the `rotate`
/// field it encodes — the inverse of [`extended_operand`].
///
/// A bare register is `rotate == 0`; a `ROR` by 8, 16 or 24 is 1, 2 or 3.
/// `ROR #0` is deliberately *not* accepted: [`decode`] never emits it, so
/// accepting it here would make two distinct operand lists encode to the same
/// halfwords and break the round-trip in the other direction.
fn rotated_operand(insn: &Insn, i: usize) -> Option<(Reg, u16)> {
    match insn.operands.get(i)? {
        Operand::Reg(r) if r.0 < 16 => Some((r, 0)),
        Operand::RegShifted(
            r,
            Shift {
                kind: ShiftKind::Ror,
                amount: ShiftAmount::Imm(n),
            },
        ) if r.0 < 16 && matches!(n, 8 | 16 | 24) => Some((r, (n / 8) as u16)),
        _ => None,
    }
}

/// Assemble the two halfwords, after checking that the instruction claims the
/// encoding name and width suffix [`decode`] attaches to its mnemonic.
///
/// That check is what keeps this `encode` from answering for a sibling group:
/// `lsl` also names `LSL (immediate)` T2 in the shifted-register table, and a
/// `lsl` that arrives here without `.w`, or claiming `T3`, is not this one.
fn assemble(insn: &Insn, op1: u16, rn: Reg, rd: Reg, op2: u16, rm: Reg) -> Option<(u16, u16)> {
    if insn.encoding != encoding_name(insn.mnemonic)
        || insn.explicit_width != has_narrow_counterpart(insn.mnemonic)
    {
        return None;
    }
    Some((
        GROUP << 8 | op1 << 4 | u16::from(rn.num()),
        0xF000 | u16::from(rd.num()) << 8 | op2 << 4 | u16::from(rm.num()),
    ))
}

/// Re-encode an instruction this module decoded, back to its two halfwords.
///
/// Returns `None` for anything outside Tables A5-24 to A5-27, including an
/// instruction that shares a mnemonic with one of them but not its operand
/// shape — `super::encode` tries each group in turn, so a greedy answer here
/// would take an encoding away from the group that owns it.
pub(crate) fn encode(insn: &Insn) -> Option<(u16, u16)> {
    if insn.width != Width::Wide || insn.mnemonic.is_empty() {
        return None;
    }

    // Every arm below checks the operand count as an *upper* bound only. Too
    // few operands is caught by the reads themselves — [`reg`] and
    // [`rotated_operand`] are `None` when the operand is not there — and
    // checking the exact count first instead would make every one of those
    // `?`s unreachable, which is to say it would state a dozen cases that
    // cannot arise.

    // Table A5-24 rows `000x`–`011x`: the only forms in these four tables
    // with an `S` bit, which lands in `op1[0]`.
    if let Some(i) = SHIFTS.iter().position(|m| *m == insn.mnemonic) {
        if insn.operands.len() > 3 {
            return None;
        }
        let (rd, rn, rm) = (reg(insn, 0)?, reg(insn, 1)?, reg(insn, 2)?);
        let op1 = (i as u16) << 1 | u16::from(insn.sets_flags);
        return assemble(insn, op1, rn, rd, 0b0000, rm);
    }

    // Nothing else in Tables A5-24 to A5-27 has an `S` bit; `APSR.GE` and
    // `APSR.Q` are written without one.
    if insn.sets_flags {
        return None;
    }

    // Table A5-24 rows `0000`–`0101`: the extends, `Rn == 1111` or not.
    for (op1, (and_add, plain)) in EXTENDS.iter().enumerate() {
        if insn.mnemonic == *and_add {
            if insn.operands.len() > 3 {
                return None;
            }
            let rd = reg(insn, 0)?;
            let rn = reg(insn, 1)?;
            // `Rn == 1111` is the plain extend. An extend-and-add cannot name
            // it, or it would decode back as the other instruction.
            if rn.num() == RN_NONE {
                return None;
            }
            let (rm, rotate) = rotated_operand(insn, 2)?;
            return assemble(insn, op1 as u16, rn, rd, 0b1000 | rotate, rm);
        }
        if insn.mnemonic == *plain {
            if insn.operands.len() > 2 {
                return None;
            }
            let rd = reg(insn, 0)?;
            let (rm, rotate) = rotated_operand(insn, 1)?;
            return assemble(insn, op1 as u16, Reg(RN_NONE), rd, 0b1000 | rotate, rm);
        }
    }

    // Tables A5-25 and A5-26: the 2 x 3 x 6 parallel grid.
    for (signedness, table) in PARALLEL.iter().enumerate() {
        for (variant, row) in table.iter().enumerate() {
            let found = row.iter().position(|m| *m == insn.mnemonic);
            if let Some(op) = found {
                if insn.operands.len() > 3 {
                    return None;
                }
                let (rd, rn, rm) = (reg(insn, 0)?, reg(insn, 1)?, reg(insn, 2)?);
                let op2 = (signedness as u16) << 2 | variant as u16;
                return assemble(insn, 0b1000 | op as u16, rn, rd, op2, rm);
            }
        }
    }

    // Table A5-27, whose rows disagree about operand order.
    for (row, names) in MISC.iter().enumerate() {
        let found = names.iter().position(|m| *m == insn.mnemonic);
        if let Some(col) = found {
            let rd = reg(insn, 0)?;
            let (rn, rm) = match row {
                // `QADD <Rd>,<Rm>,<Rn>` — second operand first.
                0 => {
                    if insn.operands.len() > 3 {
                        return None;
                    }
                    (reg(insn, 2)?, reg(insn, 1)?)
                }
                // `SEL <Rd>,<Rn>,<Rm>`.
                2 => {
                    if insn.operands.len() > 3 {
                        return None;
                    }
                    (reg(insn, 1)?, reg(insn, 2)?)
                }
                // One source register, written into both fields.
                _ => {
                    if insn.operands.len() > 2 {
                        return None;
                    }
                    let r = reg(insn, 1)?;
                    (r, r)
                }
            };
            return assemble(insn, 0b1000 | row as u16, rn, rd, 0b1000 | col as u16, rm);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every register field, at every value, in both directions.
    ///
    /// The census test above samples `Rd` at two values, which is right for
    /// attributing the encoding space but was blind to the bug this test
    /// exists for: `assemble` placed `Rd` at `hw2[15:12]` while `decode` read
    /// it from `hw2[11:8]`, so `0xF000` swallowed it and only `Rd == r0`
    /// survived a round trip — fifteen sixteenths of the group silently
    /// mis-encoded. It went unseen because the census's own `hw()` helper
    /// repeated the encoder's formula, so the two agreed with each other and
    /// disagreed with the decoder. A helper that re-derives what it is
    /// checking cannot check it; this test sweeps the fields directly against
    /// the real decoder instead.
    #[test]
    fn every_register_field_survives_a_round_trip() {
        // `clz` (Table A5-27): one op1/op2 cell, three independent register
        // fields, and `Rn`/`Rm` must agree for it to decode at all.
        let mut checked = 0usize;
        for rd in 0..16u16 {
            for r in 0..16u16 {
                let (hw1, hw2) = hw(0b1011, r, rd, 0b1000, r);
                // Every `(Rd, Rn == Rm)` pair is a defined `clz`, so this is
                // an assertion and not an `if let`: a pair that stopped
                // decoding would otherwise be counted as "not applicable"
                // rather than as the regression it is.
                let decoded = decode(hw1, hw2, 0);
                assert!(
                    decoded.is_some(),
                    "{hw1:#06x} {hw2:#06x} is `clz r{rd}, r{r}` and must decode"
                );
                let insn = decoded.unwrap();
                assert_eq!(
                    encode(&insn),
                    Some((hw1, hw2)),
                    "round-trip of {hw1:#06x} {hw2:#06x} ({insn})"
                );
                assert_eq!(
                    insn.operands.get(0),
                    Some(Operand::Reg(Reg(rd as u8))),
                    "Rd must decode from hw2[11:8], not hw2[15:12]"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 256, "every (Rd, Rn==Rm) pair should decode");
    }

    /// The halfwords for one point in the group's encoding space.
    fn hw(op1: u16, rn: u16, rd: u16, op2: u16, rm: u16) -> (u16, u16) {
        (GROUP << 8 | op1 << 4 | rn, 0xF000 | rd << 8 | op2 << 4 | rm)
    }

    /// The printed UAL form of one point in the space, decoded at address 0.
    fn ual(op1: u16, rn: u16, rd: u16, op2: u16, rm: u16) -> String {
        let (hw1, hw2) = hw(op1, rn, rd, op2, rm);
        let decoded = decode(hw1, hw2, 0);
        // `assert!` rather than a panicking match arm: the arm would be a
        // branch nothing ever takes, and this crate's coverage gate is 100%
        // of regions.
        assert!(
            decoded.is_some(),
            "{hw1:#06x} {hw2:#06x} should be a defined encoding"
        );
        decoded.unwrap().to_string()
    }

    /// Which sub-table a raw `(op1, op2, Rn, Rm)` belongs to, or the reason it
    /// is not an instruction.
    ///
    /// Written straight from Tables A5-24 to A5-27 and the prose around them,
    /// deliberately *not* by calling [`decode`]: the sweep asserts the two
    /// agree on all 3072 sampled points, so this function is the independent
    /// statement of what the manual allocates and [`decode`] is the
    /// implementation of it. Every `Err` is one named reason, so no
    /// non-decoding combination goes unaccounted for.
    fn classify(op1: u16, op2: u16, rn: u16, rm: u16) -> Result<&'static str, &'static str> {
        match (op1, op2) {
            // Table A5-24 rows `000x`-`011x`, `op2 == 0000`.
            (0..=7, 0) => Ok("shift"),
            (0..=7, 1..=7) => Err("A5-24: op1 0xxx allocates op2 0000 and 1xxx only"),
            // Table A5-24 rows `0000`-`0101`, `op2 == 1xxx`.
            (0..=5, 8..=11) => Ok("extend"),
            (0..=5, 12..=15) => Err("hw2[6] is (0) in the extends: UNPREDICTABLE, not encodable"),
            (6..=7, 8..=15) => Err("A5-24: rows 011x have no extend"),
            // Tables A5-25 and A5-26.
            (8..=15, 0..=7) => {
                if op2 & 0b11 == 0b11 {
                    Err("A5-25/26: no op2 11 variant")
                } else if op1 & 0b111 == 0b011 || op1 & 0b111 == 0b111 {
                    Err("A5-25/26: no op1 011 or 111 row")
                } else {
                    Ok("parallel")
                }
            }
            // Table A5-27.
            (8..=11, 8..=11) => {
                if MISC[(op1 & 0b11) as usize][(op2 & 0b11) as usize].is_empty() {
                    Err("A5-27: unallocated op1/op2")
                } else if matches!(op1 & 0b11, 0b01 | 0b11) && rn != rm {
                    Err("Consistent(Rm): the source register is encoded twice")
                } else {
                    Ok("misc")
                }
            }
            (12..=15, 8..=11) => Err("A5-24: the miscellaneous table needs op1 10xx"),
            // `op2 == 11xx` with `op1 == 1xxx`, spelt `_` because the arms
            // above already cover every other `(op1, op2)` a four-bit pair
            // can take. Writing the pattern out would need a second arm for
            // the values a `u16` admits and the fields do not, and that arm
            // could never run.
            _ => Err("A5-24: op2 11xx is unallocated"),
        }
    }

    /// Every operand slot of every operand shape in the four tables, mangled
    /// one at a time, plus every operand count either side of the right one.
    ///
    /// This is the module the `Rd` bug was found in — `assemble` wrote `Rd`
    /// to `hw2[15:12]` while `decode` read it from `hw2[11:8]`, so `0xF000`
    /// swallowed it and only `Rd == r0` round-tripped — and the shape of that
    /// bug is a field read from the wrong place. The slots here are the other
    /// half of the same risk: Table A5-27 alone puts its two source registers
    /// in three different orders (`QADD <Rd>,<Rm>,<Rn>`, `SEL
    /// <Rd>,<Rn>,<Rm>`, `REV <Rd>,<Rm>` with `Rm` written into both fields),
    /// so a slot that no test reads is a slot whose contents could be taken
    /// from the wrong index without anything noticing.
    ///
    /// [`Insn`] is a public struct with public fields, so `encode` is
    /// reachable with any operand list at all. The failure that matters is
    /// not a panic but a `Some`.
    #[test]
    fn encode_rejects_every_mangled_operand_slot() {
        // `Rd` is deliberately neither `r0` nor equal to `Rn` or `Rm`: a
        // sweep that only ever names `r0` as the destination cannot tell a
        // destination field read from the wrong place from one read from the
        // right place, because both yield zero.
        for (op1, rn, rd, op2, rm) in [
            (0b0000u16, 1u16, 3u16, 0b0000u16, 2u16), // lsl.w   r3, r1, r2
            (0b0111, 1, 7, 0b0000, 2),                // ror.w   r7, r1, r2
            (0b0000, 1, 3, 0b1000, 2),                // sxtah   r3, r1, r2
            (0b0000, 1, 9, 0b1011, 2),                // sxtah   r9, r1, r2, ror #24
            (0b0000, 15, 3, 0b1000, 2),               // sxth.w  r3, r2
            (0b0101, 15, 12, 0b1010, 2),              // uxtb.w  r12, r2, ror #16
            (0b1000, 1, 3, 0b0000, 2),                // sadd8   r3, r1, r2
            (0b1000, 1, 3, 0b1000, 2),                // qadd    r3, r2, r1
            (0b1001, 1, 3, 0b1000, 1),                // rev.w   r3, r1
            (0b1010, 1, 3, 0b1000, 2),                // sel     r3, r1, r2
            (0b1011, 1, 3, 0b1000, 1),                // clz     r3, r1
        ] {
            let (hw1, hw2) = hw(op1, rn, rd, op2, rm);
            let insn = decode(hw1, hw2, 0).unwrap();
            // Operand 0 is `<Rd>` in every row of all four tables. Checked
            // against the `rd` that went *into* `hw` rather than against
            // anything `encode` produced: a round trip alone proves only that
            // the encoder and this helper agree, and they share a field
            // layout. That is exactly how the `Rd` bug survived — `0xF000`
            // swallowed `rd << 12` identically on both sides, so the trip
            // closed and the register was wrong.
            assert_eq!(
                insn.operands.get(0),
                Some(Operand::Reg(Reg(rd as u8))),
                "{hw1:#06x} {hw2:#06x}: Rd comes from hw2[11:8]"
            );
            assert_eq!(
                encode(&insn),
                Some((hw1, hw2)),
                "`{insn}` should round-trip before anything is mangled"
            );
            let arity = insn.operands.len();

            // One slot at a time, replaced by an immediate — an operand kind
            // nothing in these four tables takes in any position.
            for slot in 0..arity {
                let mut mangled = insn;
                mangled.operands = (0..arity)
                    .map(|i| {
                        if i == slot {
                            Operand::Imm(0)
                        } else {
                            insn.operands.get(i).unwrap()
                        }
                    })
                    .collect();
                assert_eq!(encode(&mangled), None, "`{insn}`, operand {slot} mangled");
            }

            // One operand too few, one too many, and none at all.
            let (fewer, more) = (arity - 1, arity + 1);
            let mut short = insn;
            short.operands = (0..fewer).map(|i| insn.operands.get(i).unwrap()).collect();
            assert_eq!(encode(&short), None, "`{insn}` with {fewer} operands");
            let mut long = insn;
            long.operands = (0..more)
                .map(|i| insn.operands.get(i).unwrap_or(Operand::Reg(Reg(3))))
                .collect();
            assert_eq!(encode(&long), None, "`{insn}` with {more} operands");
            let mut empty = insn;
            empty.operands = Operands::new();
            assert_eq!(encode(&empty), None, "`{insn}` with no operands");
        }
    }

    #[test]
    fn exhaustive_round_trip_and_allocation_census() {
        // `Rn` takes 0, 1 and 15 so that the `Rn == 1111` aliasing and the
        // `Consistent(Rm)` rule are both exercised against an `Rm` that does
        // and does not match; `Rd` and `Rm` take both extremes.
        let rns = [0u16, 1, 15];
        let rds = [0u16, 15];
        let rms = [0u16, 15];

        let mut total = 0usize;
        let mut decoded = 0usize;
        let mut shift = 0usize;
        let mut extend = 0usize;
        let mut extend_plain = 0usize;
        let mut parallel = 0usize;
        let mut misc = 0usize;
        let mut reasons: Vec<(&str, usize)> = Vec::new();

        for op1 in 0..16u16 {
            for op2 in 0..16u16 {
                for rn in rns {
                    for rd in rds {
                        for rm in rms {
                            total += 1;
                            let (hw1, hw2) = hw(op1, rn, rd, op2, rm);
                            let got = decode(hw1, hw2, 0);
                            // The two independent readings are compared as
                            // assertions rather than as extra match arms:
                            // "decoded but the manual says no" and "the
                            // manual says yes but did not decode" are the
                            // failures this sweep exists to catch, and an
                            // arm that only ever panics is a branch no
                            // passing run enters.
                            match classify(op1, op2, rn, rm) {
                                Ok(table) => {
                                    assert!(
                                        got.is_some(),
                                        "{hw1:#06x} {hw2:#06x} is a {table}, yet did not decode"
                                    );
                                    let insn = got.unwrap();
                                    decoded += 1;
                                    match table {
                                        "shift" => shift += 1,
                                        "extend" => {
                                            extend += 1;
                                            if insn.operands.len() == 2 {
                                                extend_plain += 1;
                                            }
                                        }
                                        "parallel" => parallel += 1,
                                        _ => misc += 1,
                                    }
                                    assert_eq!(insn.width, Width::Wide, "{hw1:#06x} {hw2:#06x}");
                                    assert_eq!(insn.len(), 4, "{hw1:#06x} {hw2:#06x}");
                                    assert_eq!(insn.addr, 0, "{hw1:#06x} {hw2:#06x}");
                                    assert!(insn.cond.is_none(), "{hw1:#06x} {hw2:#06x}");
                                    // Only the four shift-by-register forms
                                    // print an `S`.
                                    assert_eq!(
                                        insn.sets_flags,
                                        table == "shift" && op1 & 1 == 1,
                                        "{hw1:#06x} {hw2:#06x} flag suffix"
                                    );
                                    assert_eq!(
                                        encode(&insn),
                                        Some((hw1, hw2)),
                                        "round-trip of {hw1:#06x} {hw2:#06x} ({insn})"
                                    );
                                }
                                Err(why) => {
                                    assert!(
                                        got.is_none(),
                                        "{hw1:#06x} {hw2:#06x} decoded, but the manual says: {why}"
                                    );
                                    match reasons.iter_mut().find(|r| r.0 == why) {
                                        Some(r) => r.1 += 1,
                                        None => reasons.push((why, 1)),
                                    }
                                }
                            }

                            // A5.3.12-A5.3.15, stated under every one of the
                            // four bit diagrams: hw2[15:12] != 0b1111 is
                            // UNDEFINED, whatever the rest of the halfwords
                            // say.
                            for top in 0..16u16 {
                                if top == 0b1111 {
                                    continue;
                                }
                                let spoiled = (hw2 & 0x0FFF) | (top << 12);
                                assert!(
                                    decode(hw1, spoiled, 0).is_none(),
                                    "{hw1:#06x} {spoiled:#06x} must be UNDEFINED"
                                );
                            }
                        }
                    }
                }
            }
        }

        // 16 op1 x 16 op2 x 3 Rn x 2 Rd x 2 Rm.
        assert_eq!(total, 3072);

        // Table A5-24, rows `000x`-`011x`: 8 op1 values, one op2 value, and
        // every register combination decodes. 8 * 1 * 12.
        assert_eq!(shift, 96);
        // Table A5-24, rows `0000`-`0101`: 6 op1 values and the 4 of 8 `1xxx`
        // op2 values whose should-be-zero bit is zero. 6 * 4 * 12.
        assert_eq!(extend, 288);
        // A third of the sampled `Rn` values are `0b1111`, and those are the
        // plain extends — two operands rather than three.
        assert_eq!(extend_plain, 96);
        assert_eq!(extend - extend_plain, 192);
        // Tables A5-25 and A5-26: 6 of 8 op1 values (011 and 111 are holes) x
        // 6 of 8 op2 values (the 11 variant is a hole in both tables) * 12.
        assert_eq!(parallel, 432);
        // Table A5-27: the saturating row is 4 op2 x 12 = 48; the reverse row
        // is 4 op2 but only the 2 of 6 (Rn, Rm) pairs that agree, x 2 Rd = 16;
        // `SEL` is one op2 x 12 = 12; `CLZ` is one op2 x 2 agreeing pairs x 2
        // Rd = 4.
        assert_eq!(misc, 80);
        assert_eq!(decoded, shift + extend + parallel + misc);
        assert_eq!(decoded, 896);

        // Every one of the remaining 2176 combinations, attributed. The sum is
        // the compliance claim: nothing in the group's encoding space is
        // unexplained.
        reasons.sort_unstable();
        assert_eq!(
            reasons,
            vec![
                // 8 op1 (0b0xxx) x 7 op2 (0b0001-0b0111) x 12.
                ("A5-24: op1 0xxx allocates op2 0000 and 1xxx only", 672),
                // 8 op1 (0b1xxx) x 4 op2 (0b11xx) x 12.
                ("A5-24: op2 11xx is unallocated", 384),
                // 2 op1 (0b0110, 0b0111) x 8 op2 (0b1xxx) x 12.
                ("A5-24: rows 011x have no extend", 192),
                // 4 op1 (0b11xx) x 4 op2 (0b10xx) x 12.
                ("A5-24: the miscellaneous table needs op1 10xx", 192),
                // 2 op1 (0b1011, 0b1111) x 6 allocated op2 x 12.
                ("A5-25/26: no op1 011 or 111 row", 144),
                // 8 op1 (0b1xxx) x 2 op2 (0b0011, 0b0111) x 12.
                ("A5-25/26: no op2 11 variant", 192),
                // The 6 empty cells of Table A5-27 (op1 10 and 11, op2 01, 10
                // and 11) x 12.
                ("A5-27: unallocated op1/op2", 72),
                // 5 allocated (op1, op2) pairs that encode Rm twice x the 4 of
                // 6 sampled (Rn, Rm) pairs that disagree x 2 Rd.
                ("Consistent(Rm): the source register is encoded twice", 40),
                // 6 op1 (0b0000-0b0101) x 4 op2 (0b11xx) x 12.
                (
                    "hw2[6] is (0) in the extends: UNPREDICTABLE, not encodable",
                    288
                ),
            ]
        );
        assert_eq!(
            reasons.iter().map(|r| r.1).sum::<usize>(),
            total - decoded,
            "every non-decoding combination is attributed exactly once"
        );
        assert_eq!(total - decoded, 2176);
    }

    #[test]
    fn second_halfword_must_name_all_ones() {
        // The rule has its own test as well as its sweep, because it is the
        // one thing in A5.3.12 that is not a table row.
        let (hw1, hw2) = hw(0b0000, 1, 0, 0b0000, 2); // lsl.w r0, r1, r2
        assert!(decode(hw1, hw2, 0).is_some());
        for top in 0..16u16 {
            let spoiled = (hw2 & 0x0FFF) | (top << 12);
            assert_eq!(
                decode(hw1, spoiled, 0).is_some(),
                top == 0b1111,
                "hw2 top nibble {top:#x}"
            );
        }
        // And a first halfword one bit outside the group is not ours.
        assert!(decode(0xF901, hw2, 0).is_none());
        assert!(decode(0xFB01, hw2, 0).is_none());
    }

    #[test]
    fn table_a5_24_shifts_print_ual() {
        // A7.7.69, .71, .11, .117, encoding T2: `LSL{S}<c>.W <Rd>,<Rn>,<Rm>`.
        assert_eq!(ual(0b0000, 1, 0, 0b0000, 2), "lsl.w r0, r1, r2");
        assert_eq!(ual(0b0001, 1, 0, 0b0000, 2), "lsls.w r0, r1, r2");
        assert_eq!(ual(0b0010, 1, 0, 0b0000, 2), "lsr.w r0, r1, r2");
        assert_eq!(ual(0b0011, 1, 0, 0b0000, 2), "lsrs.w r0, r1, r2");
        assert_eq!(ual(0b0100, 1, 0, 0b0000, 2), "asr.w r0, r1, r2");
        assert_eq!(ual(0b0101, 1, 0, 0b0000, 2), "asrs.w r0, r1, r2");
        assert_eq!(ual(0b0110, 1, 0, 0b0000, 2), "ror.w r0, r1, r2");
        assert_eq!(ual(0b0111, 1, 0, 0b0000, 2), "rors.w r0, r1, r2");
    }

    #[test]
    fn table_a5_24_extends_print_ual() {
        // A7.7.181/.184, .220/.223, .180/.183, .219/.222, .179/.182,
        // .218/.221. The `and-add` syntax line is
        // `SXTAH<c> <Rd>,<Rn>,<Rm>{,<rotation>}`; the plain one is
        // `SXTH<c>.W <Rd>,<Rm>{,<rotation>}`.
        assert_eq!(ual(0b0000, 1, 0, 0b1000, 2), "sxtah r0, r1, r2");
        assert_eq!(ual(0b0000, 15, 0, 0b1000, 2), "sxth.w r0, r2");
        assert_eq!(ual(0b0001, 1, 0, 0b1000, 2), "uxtah r0, r1, r2");
        assert_eq!(ual(0b0001, 15, 0, 0b1000, 2), "uxth.w r0, r2");
        assert_eq!(ual(0b0010, 1, 0, 0b1000, 2), "sxtab16 r0, r1, r2");
        assert_eq!(ual(0b0010, 15, 0, 0b1000, 2), "sxtb16 r0, r2");
        assert_eq!(ual(0b0011, 1, 0, 0b1000, 2), "uxtab16 r0, r1, r2");
        assert_eq!(ual(0b0011, 15, 0, 0b1000, 2), "uxtb16 r0, r2");
        assert_eq!(ual(0b0100, 1, 0, 0b1000, 2), "sxtab r0, r1, r2");
        assert_eq!(ual(0b0100, 15, 0, 0b1000, 2), "sxtb.w r0, r2");
        assert_eq!(ual(0b0101, 1, 0, 0b1000, 2), "uxtab r0, r1, r2");
        assert_eq!(ual(0b0101, 15, 0, 0b1000, 2), "uxtb.w r0, r2");
    }

    #[test]
    fn table_a5_25_signed_parallel_prints_ual() {
        // `SADD16{<c>}{<q>} {<Rd>,} <Rn>, <Rm>` and the rest of A5-25.
        assert_eq!(ual(0b1000, 1, 0, 0b0000, 2), "sadd8 r0, r1, r2");
        assert_eq!(ual(0b1001, 1, 0, 0b0000, 2), "sadd16 r0, r1, r2");
        assert_eq!(ual(0b1010, 1, 0, 0b0000, 2), "sasx r0, r1, r2");
        assert_eq!(ual(0b1100, 1, 0, 0b0000, 2), "ssub8 r0, r1, r2");
        assert_eq!(ual(0b1101, 1, 0, 0b0000, 2), "ssub16 r0, r1, r2");
        assert_eq!(ual(0b1110, 1, 0, 0b0000, 2), "ssax r0, r1, r2");
        assert_eq!(ual(0b1000, 1, 0, 0b0001, 2), "qadd8 r0, r1, r2");
        assert_eq!(ual(0b1001, 1, 0, 0b0001, 2), "qadd16 r0, r1, r2");
        assert_eq!(ual(0b1010, 1, 0, 0b0001, 2), "qasx r0, r1, r2");
        assert_eq!(ual(0b1100, 1, 0, 0b0001, 2), "qsub8 r0, r1, r2");
        assert_eq!(ual(0b1101, 1, 0, 0b0001, 2), "qsub16 r0, r1, r2");
        assert_eq!(ual(0b1110, 1, 0, 0b0001, 2), "qsax r0, r1, r2");
        assert_eq!(ual(0b1000, 1, 0, 0b0010, 2), "shadd8 r0, r1, r2");
        assert_eq!(ual(0b1001, 1, 0, 0b0010, 2), "shadd16 r0, r1, r2");
        assert_eq!(ual(0b1010, 1, 0, 0b0010, 2), "shasx r0, r1, r2");
        assert_eq!(ual(0b1100, 1, 0, 0b0010, 2), "shsub8 r0, r1, r2");
        assert_eq!(ual(0b1101, 1, 0, 0b0010, 2), "shsub16 r0, r1, r2");
        assert_eq!(ual(0b1110, 1, 0, 0b0010, 2), "shsax r0, r1, r2");
    }

    #[test]
    fn table_a5_26_unsigned_parallel_prints_ual() {
        assert_eq!(ual(0b1000, 1, 0, 0b0100, 2), "uadd8 r0, r1, r2");
        assert_eq!(ual(0b1001, 1, 0, 0b0100, 2), "uadd16 r0, r1, r2");
        assert_eq!(ual(0b1010, 1, 0, 0b0100, 2), "uasx r0, r1, r2");
        assert_eq!(ual(0b1100, 1, 0, 0b0100, 2), "usub8 r0, r1, r2");
        assert_eq!(ual(0b1101, 1, 0, 0b0100, 2), "usub16 r0, r1, r2");
        assert_eq!(ual(0b1110, 1, 0, 0b0100, 2), "usax r0, r1, r2");
        assert_eq!(ual(0b1000, 1, 0, 0b0101, 2), "uqadd8 r0, r1, r2");
        assert_eq!(ual(0b1001, 1, 0, 0b0101, 2), "uqadd16 r0, r1, r2");
        assert_eq!(ual(0b1010, 1, 0, 0b0101, 2), "uqasx r0, r1, r2");
        assert_eq!(ual(0b1100, 1, 0, 0b0101, 2), "uqsub8 r0, r1, r2");
        assert_eq!(ual(0b1101, 1, 0, 0b0101, 2), "uqsub16 r0, r1, r2");
        assert_eq!(ual(0b1110, 1, 0, 0b0101, 2), "uqsax r0, r1, r2");
        assert_eq!(ual(0b1000, 1, 0, 0b0110, 2), "uhadd8 r0, r1, r2");
        assert_eq!(ual(0b1001, 1, 0, 0b0110, 2), "uhadd16 r0, r1, r2");
        assert_eq!(ual(0b1010, 1, 0, 0b0110, 2), "uhasx r0, r1, r2");
        assert_eq!(ual(0b1100, 1, 0, 0b0110, 2), "uhsub8 r0, r1, r2");
        assert_eq!(ual(0b1101, 1, 0, 0b0110, 2), "uhsub16 r0, r1, r2");
        assert_eq!(ual(0b1110, 1, 0, 0b0110, 2), "uhsax r0, r1, r2");
    }

    #[test]
    fn table_a5_27_misc_prints_ual() {
        // A7.7.102/.106/.109/.107: `QADD<c> <Rd>,<Rm>,<Rn>` — the `Rm` field
        // of the second halfword is the *first* printed source.
        assert_eq!(ual(0b1000, 1, 0, 0b1000, 2), "qadd r0, r2, r1");
        assert_eq!(ual(0b1000, 1, 0, 0b1001, 2), "qdadd r0, r2, r1");
        assert_eq!(ual(0b1000, 1, 0, 0b1010, 2), "qsub r0, r2, r1");
        assert_eq!(ual(0b1000, 1, 0, 0b1011, 2), "qdsub r0, r2, r1");
        // A7.7.113/.114/.112/.115, with the source register in both fields.
        assert_eq!(ual(0b1001, 2, 0, 0b1000, 2), "rev.w r0, r2");
        assert_eq!(ual(0b1001, 2, 0, 0b1001, 2), "rev16.w r0, r2");
        assert_eq!(ual(0b1001, 2, 0, 0b1010, 2), "rbit r0, r2");
        assert_eq!(ual(0b1001, 2, 0, 0b1011, 2), "revsh.w r0, r2");
        // A7.7.128: `SEL<c> <Rd>,<Rn>,<Rm>`.
        assert_eq!(ual(0b1010, 1, 0, 0b1000, 2), "sel r0, r1, r2");
        // A7.7.24: `CLZ<c> <Rd>,<Rm>`.
        assert_eq!(ual(0b1011, 2, 0, 0b1000, 2), "clz r0, r2");
    }

    #[test]
    fn rn_1111_switches_each_extend_to_its_plain_form() {
        // Six pairs, one `op1` each, distinguished by nothing but `Rn`
        // (A7.7.181: `if Rn == '1111' then SEE SXTH;`).
        let pairs = [
            (0b0000u16, "sxtah", "sxth"),
            (0b0001, "uxtah", "uxth"),
            (0b0010, "sxtab16", "sxtb16"),
            (0b0011, "uxtab16", "uxtb16"),
            (0b0100, "sxtab", "sxtb"),
            (0b0101, "uxtab", "uxtb"),
        ];
        for (op1, and_add, plain) in pairs {
            // `Rn == 14` is a register, so the add form; `Rn == 15` is not.
            let (hw1, hw2) = hw(op1, 14, 0, 0b1000, 2);
            let with_add = decode(hw1, hw2, 0).unwrap();
            let (hw1_p, hw2_p) = hw(op1, 15, 0, 0b1000, 2);
            let without = decode(hw1_p, hw2_p, 0).unwrap();

            assert_eq!(with_add.mnemonic, and_add, "op1 {op1:04b}");
            assert_eq!(without.mnemonic, plain, "op1 {op1:04b}");
            assert_ne!(with_add.mnemonic, without.mnemonic);
            // The add form names three registers, the plain form two.
            assert_eq!(with_add.operands.len(), 3, "{and_add}");
            assert_eq!(with_add.operands.get(1), Some(Operand::Reg(Reg::LR)));
            assert_eq!(without.operands.len(), 2, "{plain}");
            assert_eq!(encode(&with_add), Some((hw1, hw2)));
            assert_eq!(encode(&without), Some((hw1_p, hw2_p)));

            // An `and-add` form cannot be re-encoded naming `pc` as its
            // addend: those halfwords are the plain extend.
            let mut impostor = with_add;
            impostor.operands = [
                Operand::Reg(Reg(0)),
                Operand::Reg(Reg::PC),
                Operand::Reg(Reg(2)),
            ]
            .into_iter()
            .collect();
            assert_eq!(encode(&impostor), None, "{and_add} with Rn = pc");
        }
    }

    #[test]
    fn extend_rotation_is_omitted_when_zero() {
        // `rotation = UInt(rotate:'000')`, so `rotate` of 0, 1, 2, 3 is a
        // rotation of 0, 8, 16, 24 (A7.7.184). UAL writes nothing for zero.
        assert_eq!(ual(0b0000, 15, 0, 0b1000, 2), "sxth.w r0, r2");
        assert_eq!(ual(0b0000, 15, 0, 0b1001, 2), "sxth.w r0, r2, ror #8");
        assert_eq!(ual(0b0000, 15, 0, 0b1010, 2), "sxth.w r0, r2, ror #16");
        assert_eq!(ual(0b0000, 15, 0, 0b1011, 2), "sxth.w r0, r2, ror #24");
        // The same asymmetry on an `and-add` form, where the rotation belongs
        // to the third operand.
        assert_eq!(ual(0b0100, 1, 0, 0b1000, 2), "sxtab r0, r1, r2");
        assert_eq!(ual(0b0100, 1, 0, 0b1011, 2), "sxtab r0, r1, r2, ror #24");

        for op2 in [0b1000u16, 0b1001, 0b1010, 0b1011] {
            let (hw1, hw2) = hw(0b0000, 15, 0, op2, 2);
            let insn = decode(hw1, hw2, 0).unwrap();
            // Zero rotation is a bare register; anything else is a shifted
            // one, always `ROR`, always by a multiple of eight. Compared as a
            // whole operand rather than matched and picked apart: an
            // extracting match needs a third arm for the operand kinds that
            // cannot appear, and that arm can never run.
            let expected = if op2 == 0b1000 {
                Operand::Reg(Reg(2))
            } else {
                Operand::RegShifted(
                    Reg(2),
                    Shift {
                        kind: ShiftKind::Ror,
                        amount: ShiftAmount::Imm(((op2 & 0b11) * 8) as u8),
                    },
                )
            };
            assert_eq!(insn.operands.get(1), Some(expected), "op2 {op2:04b}");
            assert_eq!(encode(&insn), Some((hw1, hw2)), "round-trip of rotate");
        }

        // `ROR #0` is not standard UAL for these ("must not be used for
        // disassembly"), so it is not an input this module will encode either —
        // otherwise two operand lists would produce one pair of halfwords.
        let mut zero_ror = decode(GROUP << 8 | 0x0F, 0xF082, 0).unwrap();
        zero_ror.operands = [
            Operand::Reg(Reg(0)),
            Operand::RegShifted(
                Reg(2),
                Shift {
                    kind: ShiftKind::Ror,
                    amount: ShiftAmount::Imm(0),
                },
            ),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&zero_ror), None);
    }

    #[test]
    fn the_parallel_grid_is_three_variants_by_six_operations() {
        // Arm's Table A5-25 and A5-26 row order is 001, 010, 110, 101, 000,
        // 100 — add16, asx, sax, sub16, add8, sub8 — so a decoder that assumed
        // the obvious numeric order would swap `SADD8` with `SADD16` and
        // `SSAX` with `SSUB16`. Asserting the whole grid at once is what
        // catches that; a spot check on one cell would not.
        let op1s = [0b1000u16, 0b1001, 0b1010, 0b1100, 0b1101, 0b1110];
        let signed: [[&str; 6]; 3] = [
            ["sadd8", "sadd16", "sasx", "ssub8", "ssub16", "ssax"],
            ["qadd8", "qadd16", "qasx", "qsub8", "qsub16", "qsax"],
            ["shadd8", "shadd16", "shasx", "shsub8", "shsub16", "shsax"],
        ];
        let unsigned: [[&str; 6]; 3] = [
            ["uadd8", "uadd16", "uasx", "usub8", "usub16", "usax"],
            ["uqadd8", "uqadd16", "uqasx", "uqsub8", "uqsub16", "uqsax"],
            ["uhadd8", "uhadd16", "uhasx", "uhsub8", "uhsub16", "uhsax"],
        ];

        let mut seen = 0usize;
        for (table, base) in [(signed, 0b0000u16), (unsigned, 0b0100)] {
            for (variant, row) in table.iter().enumerate() {
                for (i, expected) in row.iter().enumerate() {
                    let op2 = base | variant as u16;
                    let op1 = op1s[i];
                    let (hw1, hw2) = hw(op1, 1, 0, op2, 2);
                    let insn = decode(hw1, hw2, 0).expect("allocated cell");
                    // `op1` is bound rather than interpolated positionally: a
                    // positional `assert_eq!` argument is an expression
                    // evaluated only when the assertion fails, which is a
                    // region no passing test can reach.
                    assert_eq!(insn.mnemonic, *expected, "op1 {op1:04b} op2 {op2:04b}");
                    // Every cell is `<Rd>,<Rn>,<Rm>`, and none prints an `S`.
                    assert_eq!(insn.operands.len(), 3);
                    assert_eq!(insn.operands.get(0), Some(Operand::Reg(Reg(0))));
                    assert_eq!(insn.operands.get(1), Some(Operand::Reg(Reg(1))));
                    assert_eq!(insn.operands.get(2), Some(Operand::Reg(Reg(2))));
                    assert!(!insn.sets_flags, "{expected} writes GE or Q, not NZCV");
                    assert_eq!(insn.encoding, "T1");
                    assert!(!insn.explicit_width, "{expected} has no narrow form");
                    assert_eq!(encode(&insn), Some((hw1, hw2)));
                    seen += 1;
                }
            }
            // The fourth `op2` variant, and the two `op1` holes, are UNDEFINED.
            for i in [0b1011u16, 0b1111] {
                assert!(decode(hw(i, 1, 0, base, 2).0, hw(i, 1, 0, base, 2).1, 0).is_none());
            }
            assert!(decode(
                hw(0b1001, 1, 0, base | 0b11, 2).0,
                hw(0b1001, 1, 0, base | 0b11, 2).1,
                0
            )
            .is_none());
        }
        assert_eq!(seen, 36, "two tables x three variants x six operations");
    }

    #[test]
    fn reverse_and_clz_need_their_source_register_twice() {
        // A7.7.113/.114/.112/.115/.24 all open `if !Consistent(Rm) then
        // UNPREDICTABLE`, so halfwords whose two `Rm` fields disagree are not
        // an instruction this decoder will claim.
        for op2 in [0b1000u16, 0b1001, 0b1010, 0b1011] {
            assert!(decode(hw(0b1001, 2, 0, op2, 2).0, hw(0b1001, 2, 0, op2, 2).1, 0).is_some());
            let (hw1, hw2) = hw(0b1001, 3, 0, op2, 2);
            assert!(decode(hw1, hw2, 0).is_none(), "{hw1:#06x} {hw2:#06x}");
        }
        let (hw1, hw2) = hw(0b1011, 3, 0, 0b1000, 2); // clz with Rn != Rm
        assert!(decode(hw1, hw2, 0).is_none());
        // `SEL` and the saturating row genuinely take two sources, so a
        // mismatch there is an ordinary instruction.
        assert!(decode(
            hw(0b1010, 3, 0, 0b1000, 2).0,
            hw(0b1010, 3, 0, 0b1000, 2).1,
            0
        )
        .is_some());
        assert!(decode(
            hw(0b1000, 3, 0, 0b1000, 2).0,
            hw(0b1000, 3, 0, 0b1000, 2).1,
            0
        )
        .is_some());
    }

    #[test]
    fn only_the_shifts_carry_a_flag_bit() {
        // `op1[0]` is `S` for the four shift-by-register forms, and part of the
        // operation selector everywhere else in the group.
        for op1 in [0b0000u16, 0b0010, 0b0100, 0b0110] {
            assert!(
                !decode(hw(op1, 1, 0, 0, 2).0, hw(op1, 1, 0, 0, 2).1, 0)
                    .unwrap()
                    .sets_flags
            );
            assert!(
                decode(hw(op1 | 1, 1, 0, 0, 2).0, hw(op1 | 1, 1, 0, 0, 2).1, 0)
                    .unwrap()
                    .sets_flags
            );
        }
        // A parallel or saturating instruction with `sets_flags` set would
        // print as `qadd16s`; the encoder refuses it rather than inventing an
        // `S` bit for an encoding that has none.
        let (hw1, hw2) = hw(0b1001, 1, 0, 0b0001, 2); // qadd16 r0, r1, r2
        let insn = decode(hw1, hw2, 0).unwrap();
        assert_eq!(insn.to_string(), "qadd16 r0, r1, r2");
        let mut flagged = insn;
        flagged.sets_flags = true;
        assert_eq!(flagged.to_string(), "qadd16s r0, r1, r2");
        assert_eq!(encode(&flagged), None);
    }

    #[test]
    fn encode_rejects_what_this_group_does_not_own() {
        let base = decode(hw(0b0000, 1, 0, 0, 2).0, hw(0b0000, 1, 0, 0, 2).1, 0).unwrap();

        // A mnemonic from another group.
        let mut foreign = base;
        foreign.mnemonic = "add";
        assert_eq!(encode(&foreign), None);
        let mut blank = base;
        blank.mnemonic = "";
        assert_eq!(encode(&blank), None);

        // The narrow encoding of the same operation.
        let mut narrow = base;
        narrow.width = Width::Narrow;
        assert_eq!(encode(&narrow), None);

        // `lsl` without `.w` and three registers is not this encoding: the
        // shifted-register table's `LSL (immediate)` T2 and the narrow T1 both
        // want that spelling.
        let mut unsuffixed = base;
        unsuffixed.explicit_width = false;
        assert_eq!(encode(&unsuffixed), None);
        let mut wrong_encoding = base;
        wrong_encoding.encoding = "T3";
        assert_eq!(encode(&wrong_encoding), None);

        // `LSL (immediate)`, which shares the mnemonic but not the operands.
        let mut immediate = base;
        immediate.operands = [Operand::Reg(Reg(0)), Operand::Reg(Reg(1)), Operand::Imm(3)]
            .into_iter()
            .collect();
        assert_eq!(encode(&immediate), None);

        // Wrong operand counts, in each shape.
        let mut short_shift = base;
        short_shift.operands = [Operand::Reg(Reg(0)), Operand::Reg(Reg(1))]
            .into_iter()
            .collect();
        assert_eq!(encode(&short_shift), None);

        let (h1, h2) = hw(0b1011, 2, 0, 0b1000, 2); // clz r0, r2
        let mut clz = decode(h1, h2, 0).unwrap();
        clz.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Reg(Reg(2)),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&clz), None);

        let (h1, h2) = hw(0b1010, 1, 0, 0b1000, 2); // sel r0, r1, r2
        let mut sel = decode(h1, h2, 0).unwrap();
        sel.operands = [Operand::Reg(Reg(0)), Operand::Reg(Reg(1))]
            .into_iter()
            .collect();
        assert_eq!(encode(&sel), None);

        let (h1, h2) = hw(0b0000, 15, 0, 0b1000, 2); // sxth.w r0, r2
        let mut sxth = decode(h1, h2, 0).unwrap();
        sxth.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Reg(Reg(2)),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&sxth), None);
        // A rotation that is not 0, 8, 16 or 24 has no `rotate` field.
        let mut bad_rot = decode(h1, h2, 0).unwrap();
        bad_rot.operands = [
            Operand::Reg(Reg(0)),
            Operand::RegShifted(
                Reg(2),
                Shift {
                    kind: ShiftKind::Ror,
                    amount: ShiftAmount::Imm(4),
                },
            ),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&bad_rot), None);
        // Nor does any other kind of shift.
        let mut lsl_rot = decode(h1, h2, 0).unwrap();
        lsl_rot.operands = [
            Operand::Reg(Reg(0)),
            Operand::RegShifted(
                Reg(2),
                Shift {
                    kind: ShiftKind::Lsl,
                    amount: ShiftAmount::Imm(8),
                },
            ),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&lsl_rot), None);
        // A shift by a register is not a rotation field either.
        let mut reg_rot = decode(h1, h2, 0).unwrap();
        reg_rot.operands = [
            Operand::Reg(Reg(0)),
            Operand::RegShifted(
                Reg(2),
                Shift {
                    kind: ShiftKind::Ror,
                    amount: ShiftAmount::Reg(Reg(3)),
                },
            ),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&reg_rot), None);

        // A register number that does not fit four bits is not silently
        // truncated into a different instruction.
        let mut huge = base;
        huge.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Reg(Reg(0x1F)),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&huge), None);
    }

    #[test]
    fn a_condition_does_not_change_the_halfwords() {
        // These encodings have no condition field; one carried in `Insn::cond`
        // came from an enclosing IT block and re-encodes identically.
        let (hw1, hw2) = hw(0b1001, 1, 0, 0b0110, 2); // uhadd16 r0, r1, r2
        let mut insn = decode(hw1, hw2, 0).unwrap();
        insn.cond = Some(crate::Cond::Ne);
        assert_eq!(insn.to_string(), "uhadd16ne r0, r1, r2");
        assert_eq!(encode(&insn), Some((hw1, hw2)));
    }
}
