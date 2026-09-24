//! 16-bit data processing — `hw1[15:10] == 0b010000` (ARM DDI 0403E.e A5.2.2,
//! Table A5-3; identically ARM DDI 0406B A6.2.2, Table A6-3).
//!
//! The whole group is one shape: `0100 00 opcode(4) Rm(3) Rdn(3)`, so the
//! halfword is `0x4000 | opcode << 6 | Rm << 3 | Rdn` and the space
//! `0x4000..=0x43FF` is fully allocated — all sixteen `opcode` values name an
//! instruction, every operand is a low register, and nothing here is
//! UNDEFINED or UNPREDICTABLE. That is why [`decode`] has no fallible arm
//! beyond the group check itself.
//!
//! Three things in Table A5-3 do *not* follow from the shared layout, and each
//! is handled by a [`Form`] of its own rather than by a special case sprinkled
//! through the decoder:
//!
//! * `TST`/`CMP`/`CMN` exist *to* write the flags, so UAL gives them no `S`
//!   suffix (A7.7.189, A7.7.28, A7.7.26 all spell encoding T1 as
//!   `TST<c> <Rn>,<Rm>`, with no `{S}` in the syntax line). Since
//!   [`Insn`]'s `Display` appends `"s"` whenever `sets_flags` is set, these
//!   three must carry `sets_flags: false` — the flag means "prints an `S`",
//!   and the architectural fact that they update `APSR` unconditionally is
//!   not expressible in it.
//! * `RSB (immediate)` T1 (A7.7.119) — the `NEG` of pre-UAL assembly — has no
//!   immediate field at all: `imm32 = Zeros(32)`, and the syntax line is
//!   `RSBS <Rd>,<Rn>,#0`. The `#0` is part of the mnemonic's UAL form, so it
//!   is emitted as a real third operand.
//! * `MUL` T1 (A7.7.84) names its destination twice: the encoding is
//!   `Rn` in the `Rm` field and `Rdm` in the `Rdn` field, and the syntax line
//!   is `MULS <Rdm>,<Rn>,<Rdm>`.
//!
//! The four shift-by-register forms (`LSL`/`LSR`/`ASR`/`ROR` register) are two
//! plain [`Operand::Reg`]s, not an [`Operand::RegShifted`]. Their UAL form is
//! `LSLS <Rdn>,<Rm>` (A7.7.69): the shift *is* the operation, not a modifier
//! attached to some other operation's operand. `RegShifted` models the latter
//! — the 32-bit `AND{S}.W <Rd>,<Rn>,<Rm>{,<shift>}` family — and using it here
//! would print `lsls r1, r2, lsl r2` and lose the distinction between
//! "shift `Rdn` by `Rm`" and "AND with a shifted `Rm`".

use super::{Insn, Operand, Operands, Reg, Width};

/// Which of the group's four operand shapes an `opcode` uses.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Form {
    /// `<Rdn>, <Rm>` and sets flags — the destructive two-register majority.
    Dest,
    /// `<Rn>, <Rm>` and prints no `S` — `TST`, `CMP`, `CMN`.
    Test,
    /// `<Rd>, <Rn>, #0` — `RSB (immediate)` T1, whose immediate is implicit.
    Rsb,
    /// `<Rdm>, <Rn>, <Rdm>` — `MUL` T1, whose destination appears twice.
    Mul,
}

/// Table A5-3, indexed by `hw1[9:6]`.
///
/// The mnemonic is the base form; the `S` suffix comes from `sets_flags`, which
/// [`Form::sets_flags`] derives, so the table cannot disagree with itself about
/// whether `tst` prints as `tsts`.
const TABLE: [(&str, Form); 16] = [
    ("and", Form::Dest), // 0000 AND (register) T1
    ("eor", Form::Dest), // 0001 EOR (register) T1
    ("lsl", Form::Dest), // 0010 LSL (register) T1
    ("lsr", Form::Dest), // 0011 LSR (register) T1
    ("asr", Form::Dest), // 0100 ASR (register) T1
    ("adc", Form::Dest), // 0101 ADC (register) T1
    ("sbc", Form::Dest), // 0110 SBC (register) T1
    ("ror", Form::Dest), // 0111 ROR (register) T1
    ("tst", Form::Test), // 1000 TST (register) T1
    ("rsb", Form::Rsb),  // 1001 RSB (immediate) T1
    ("cmp", Form::Test), // 1010 CMP (register) T1
    ("cmn", Form::Test), // 1011 CMN (register) T1
    ("orr", Form::Dest), // 1100 ORR (register) T1
    ("mul", Form::Mul),  // 1101 MUL T1
    ("bic", Form::Dest), // 1110 BIC (register) T1
    ("mvn", Form::Dest), // 1111 MVN (register) T1
];

impl Form {
    /// Whether UAL writes an `S` suffix for this form.
    ///
    /// Every instruction in Table A5-3 updates the flags when executed outside
    /// an IT block, but `TST`/`CMP`/`CMN` have no other effect, so their
    /// syntax lines carry no `{S}` and an emitted `tsts` would not assemble.
    fn sets_flags(self) -> bool {
        self != Form::Test
    }
}

/// Decode an instruction in this group, or `None` if `hw1`/`hw2` do not
/// belong to it.
pub(crate) fn decode(hw1: u16, _hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 >> 10 != 0b010000 {
        return None;
    }
    let (mnemonic, form) = TABLE[((hw1 >> 6) & 0xF) as usize];
    // The two register fields, by position. Which architectural name each one
    // carries depends on the form: bits [5:3] are `Rm` for most of the table,
    // but `Rn` for `RSB` and `MUL`, and bits [2:0] are correspondingly `Rdn`,
    // `Rd` or `Rdm`.
    let hi = Reg(((hw1 >> 3) & 0b111) as u8);
    let lo = Reg((hw1 & 0b111) as u8);

    let mut operands = Operands::new();
    operands.push(Operand::Reg(lo));
    operands.push(Operand::Reg(hi));
    match form {
        Form::Dest | Form::Test => {}
        Form::Rsb => operands.push(Operand::Imm(0)),
        Form::Mul => operands.push(Operand::Reg(lo)),
    }

    Some(Insn {
        mnemonic,
        encoding: "T1",
        addr,
        width: Width::Narrow,
        cond: None,
        sets_flags: form.sets_flags(),
        explicit_width: false,
        operands,
    })
}

/// Re-encode an instruction this module decoded, back to its halfword.
///
/// Deliberately strict: the mnemonics here are shared with encodings outside
/// the group (`cmp` is also CMP (immediate) T1 and CMP (register) T2, `mul` is
/// also MUL T2, `lsl` is also LSL (immediate) T1), so a match requires the
/// `"T1"` encoding name, a narrow width, the exact operand shape of the form,
/// and low registers throughout. `cond` is not consulted — the halfword has no
/// condition field, and an instruction inside an IT block encodes identically.
pub(crate) fn encode(insn: &Insn) -> Option<u16> {
    if insn.width != Width::Narrow || insn.encoding != "T1" || insn.explicit_width {
        return None;
    }
    let (opcode, form) = TABLE
        .iter()
        .position(|(m, _)| *m == insn.mnemonic)
        .map(|i| (i as u16, TABLE[i].1))?;
    if insn.sets_flags != form.sets_flags() {
        return None;
    }

    let reg = |i: usize| match insn.operands.get(i) {
        Some(Operand::Reg(r)) if r.is_low() => Some(r.num() as u16),
        _ => None,
    };
    let (hi, lo) = match form {
        Form::Dest | Form::Test => {
            if insn.operands.len() != 2 {
                return None;
            }
            (reg(1)?, reg(0)?)
        }
        Form::Rsb => {
            if insn.operands.len() != 3 || insn.operands.get(2) != Some(Operand::Imm(0)) {
                return None;
            }
            (reg(1)?, reg(0)?)
        }
        Form::Mul => {
            // `MULS <Rdm>,<Rn>,<Rdm>`: the first and third operands are the
            // same register, and only one field encodes it. `Rdm` is read once
            // and compared, rather than read again below, so that each field
            // has exactly one place to be refused.
            let rdm = reg(0)?;
            if insn.operands.len() != 3 || reg(2)? != rdm {
                return None;
            }
            (reg(1)?, rdm)
        }
    };
    Some(0x4000 | opcode << 6 | hi << 3 | lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The printed UAL form of `hw1`, decoded at address 0.
    fn ual(hw1: u16) -> String {
        decode(hw1, 0, 0)
            .expect("fully allocated group")
            .to_string()
    }

    /// `opcode` with `Rm`/`Rn` = `r2` and `Rdn`/`Rd`/`Rdm` = `r1`, so every
    /// assertion below distinguishes the two register fields.
    fn hw(opcode: u16) -> u16 {
        0x4000 | opcode << 6 | 2 << 3 | 1
    }

    #[test]
    fn group_is_fully_allocated_and_round_trips() {
        // All sixteen opcodes name an instruction and every field is three
        // bits, so the space has no hole — stated as a property of the whole
        // range rather than as a per-halfword branch that can never be taken.
        let holes: Vec<u16> = (0x4000..=0x43FFu16)
            .filter(|hw1| decode(*hw1, 0, 0).is_none())
            .collect();
        assert_eq!(
            holes,
            Vec::new(),
            "A5.2.2 leaves no hole in 0x4000..=0x43ff"
        );

        for hw1 in 0x4000..=0x43FFu16 {
            let insn = decode(hw1, 0, 0).expect("the group is fully allocated");
            assert_eq!(insn.width, Width::Narrow, "{hw1:#06x} is a 16-bit encoding");
            assert_eq!(insn.encoding, "T1", "{hw1:#06x}");
            assert_eq!(insn.len(), 2, "{hw1:#06x}");
            assert!(insn.cond.is_none(), "{hw1:#06x} carries no condition");
            assert!(
                insn.operands.as_slice().all(|o| match o {
                    Operand::Reg(r) => r.is_low(),
                    _ => true,
                }),
                "{hw1:#06x} names only r0-r7"
            );
            assert_eq!(encode(&insn), Some(hw1), "round-trip of {hw1:#06x}");
        }
        assert_eq!(
            (0x4000..=0x43FFu16).count(),
            1024,
            "the whole 0x4000..=0x43ff space"
        );
    }

    #[test]
    fn outside_the_group_is_not_ours() {
        // One below (the shift/add/sub/mov/cmp group) and one above (special
        // data / branch-and-exchange).
        assert!(decode(0x3FFF, 0, 0).is_none());
        assert!(decode(0x4400, 0, 0).is_none());
    }

    #[test]
    fn table_a5_3_prints_ual() {
        // Syntax lines from the T1 encodings of A7.7.9, .36, .69, .71, .11,
        // .2, .126, .117, .92, .16, .86.
        assert_eq!(ual(hw(0b0000)), "ands r1, r2");
        assert_eq!(ual(hw(0b0001)), "eors r1, r2");
        assert_eq!(ual(hw(0b0010)), "lsls r1, r2");
        assert_eq!(ual(hw(0b0011)), "lsrs r1, r2");
        assert_eq!(ual(hw(0b0100)), "asrs r1, r2");
        assert_eq!(ual(hw(0b0101)), "adcs r1, r2");
        assert_eq!(ual(hw(0b0110)), "sbcs r1, r2");
        assert_eq!(ual(hw(0b0111)), "rors r1, r2");
        assert_eq!(ual(hw(0b1000)), "tst r1, r2");
        assert_eq!(ual(hw(0b1001)), "rsbs r1, r2, #0");
        assert_eq!(ual(hw(0b1010)), "cmp r1, r2");
        assert_eq!(ual(hw(0b1011)), "cmn r1, r2");
        assert_eq!(ual(hw(0b1100)), "orrs r1, r2");
        assert_eq!(ual(hw(0b1101)), "muls r1, r2, r1");
        assert_eq!(ual(hw(0b1110)), "bics r1, r2");
        assert_eq!(ual(hw(0b1111)), "mvns r1, r2");
    }

    #[test]
    fn register_fields_are_read_in_the_right_order() {
        // `ands r7, r0` is Rm = 0, Rdn = 7.
        assert_eq!(ual(0x4007), "ands r7, r0");
        // The base of each opcode, all fields zero.
        assert_eq!(ual(0x4000), "ands r0, r0");
        assert_eq!(ual(0x43C0), "mvns r0, r0");
    }

    #[test]
    fn flag_setters_print_no_s_suffix() {
        // A7.7.189/.28/.26: encoding T1 is `TST<c> <Rn>,<Rm>` — no `{S}` in
        // the syntax line, so `tsts`/`cmps`/`cmns` would not assemble.
        for hw1 in [hw(0b1000), hw(0b1010), hw(0b1011)] {
            let insn = decode(hw1, 0, 0).unwrap();
            assert!(!insn.sets_flags, "{hw1:#06x}");
            assert!(!insn.to_string().starts_with("tsts"));
            assert!(!insn.to_string().starts_with("cmps"));
            assert!(!insn.to_string().starts_with("cmns"));
        }
        // Everything else in the table does print the suffix.
        for opcode in [0u16, 1, 2, 3, 4, 5, 6, 7, 9, 12, 13, 14, 15] {
            assert!(decode(hw(opcode), 0, 0).unwrap().sets_flags, "{opcode:04b}");
        }
    }

    #[test]
    fn rsb_t1_emits_its_implicit_zero() {
        // A7.7.119 encoding T1: `RSBS <Rd>,<Rn>,#0`, and the encoding has no
        // immediate field — `imm32 = Zeros(32)`.
        let insn = decode(0x4252, 0, 0).unwrap(); // rsbs r2, r2, #0
        assert_eq!(insn.mnemonic, "rsb");
        assert_eq!(insn.operands.len(), 3);
        assert_eq!(insn.operands.get(2), Some(Operand::Imm(0)));
        assert_eq!(insn.to_string(), "rsbs r2, r2, #0");
        // The `NEG r3, r1` of pre-UAL assembly: Rn = r1, Rd = r3.
        assert_eq!(ual(0x424B), "rsbs r3, r1, #0");
    }

    #[test]
    fn mul_t1_names_its_destination_twice() {
        // A7.7.84 encoding T1: `0100001101 Rn Rdm`, `MULS <Rdm>,<Rn>,<Rdm>`.
        let insn = decode(0x4351, 0, 0).unwrap(); // Rn = r2, Rdm = r1
        assert_eq!(insn.mnemonic, "mul");
        assert_eq!(insn.operands.get(0), Some(Operand::Reg(Reg(1))));
        assert_eq!(insn.operands.get(1), Some(Operand::Reg(Reg(2))));
        assert_eq!(insn.operands.get(2), Some(Operand::Reg(Reg(1))));
        assert_eq!(insn.to_string(), "muls r1, r2, r1");
    }

    #[test]
    fn shift_by_register_is_two_plain_registers() {
        // `LSLS <Rdn>,<Rm>` (A7.7.69 T1) — the shift is the operation, so no
        // operand carries an `Operand::RegShifted`.
        for opcode in [0b0010u16, 0b0011, 0b0100, 0b0111] {
            let insn = decode(hw(opcode), 0, 0).unwrap();
            assert_eq!(insn.operands.len(), 2, "{opcode:04b}");
            assert!(
                insn.operands
                    .as_slice()
                    .all(|o| matches!(o, Operand::Reg(_))),
                "{opcode:04b}"
            );
        }
    }

    #[test]
    fn encode_rejects_what_this_group_cannot_hold() {
        let base = decode(0x4000, 0, 0).unwrap(); // ands r0, r0

        // A mnemonic from another group.
        let mut foreign = base;
        foreign.mnemonic = "add";
        assert_eq!(encode(&foreign), None);

        // The wide or width-suffixed forms of the same operation.
        let mut wide = base;
        wide.width = Width::Wide;
        assert_eq!(encode(&wide), None);
        let mut t2 = base;
        t2.encoding = "T2";
        assert_eq!(encode(&t2), None);
        let mut suffixed = base;
        suffixed.explicit_width = true;
        assert_eq!(encode(&suffixed), None);

        // `and` without `S` is the 32-bit encoding, and `tst` with one is not
        // a form at all.
        let mut flagless = base;
        flagless.sets_flags = false;
        assert_eq!(encode(&flagless), None);
        let mut flagged_tst = decode(0x4200, 0, 0).unwrap();
        flagged_tst.sets_flags = true;
        assert_eq!(encode(&flagged_tst), None);

        // High registers need the T2 encodings.
        let mut high = base;
        high.operands = [Operand::Reg(Reg::SP), Operand::Reg(Reg(0))]
            .into_iter()
            .collect();
        assert_eq!(encode(&high), None);
        let mut high_hi = base;
        high_hi.operands = [Operand::Reg(Reg(0)), Operand::Reg(Reg::LR)]
            .into_iter()
            .collect();
        assert_eq!(encode(&high_hi), None);

        // Wrong operand shapes: too many, too few, or the wrong kind.
        let mut three = base;
        three.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Reg(Reg(2)),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&three), None);
        let mut immediate = base;
        immediate.operands = [Operand::Reg(Reg(0)), Operand::Imm(1)]
            .into_iter()
            .collect();
        assert_eq!(encode(&immediate), None);

        // `rsb` only encodes here with a literal `#0` third operand.
        let mut rsb = decode(0x4240, 0, 0).unwrap();
        rsb.operands = [Operand::Reg(Reg(0)), Operand::Reg(Reg(0)), Operand::Imm(1)]
            .into_iter()
            .collect();
        assert_eq!(encode(&rsb), None);
        let mut rsb_short = decode(0x4240, 0, 0).unwrap();
        rsb_short.operands = [Operand::Reg(Reg(0)), Operand::Reg(Reg(0))]
            .into_iter()
            .collect();
        assert_eq!(encode(&rsb_short), None);
        let mut rsb_high = decode(0x4240, 0, 0).unwrap();
        rsb_high.operands = [Operand::Reg(Reg(0)), Operand::Reg(Reg::PC), Operand::Imm(0)]
            .into_iter()
            .collect();
        assert_eq!(encode(&rsb_high), None);

        // `mul` needs its destination in both the first and third operand.
        let mut mul = decode(0x4340, 0, 0).unwrap();
        mul.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Reg(Reg(2)),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&mul), None);
        let mut mul_short = decode(0x4340, 0, 0).unwrap();
        mul_short.operands = [Operand::Reg(Reg(0)), Operand::Reg(Reg(1))]
            .into_iter()
            .collect();
        assert_eq!(encode(&mul_short), None);
        let mut mul_high = decode(0x4340, 0, 0).unwrap();
        mul_high.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Reg(Reg::PC),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&mul_high), None);

        // Each of the three fields of the three-operand forms, refused in its
        // own right. `MUL` T2 and `RSB (immediate)` T2 are where a high
        // register belongs (A7.7.84, A7.7.119), and those are other modules'
        // encodings — so answering `Some` here would take an instruction away
        // from the group that can actually express it.
        let high = Operand::Reg(Reg(8));
        let r0 = Operand::Reg(Reg(0));
        let r1 = Operand::Reg(Reg(1));
        for (base, ops, field) in [
            (0x4240u16, [high, r0, Operand::Imm(0)], "rsb Rd"),
            (0x4240, [r0, high, Operand::Imm(0)], "rsb Rn"),
            (0x4240, [r0, r1, r1], "rsb #0 is literal"),
            (0x4340, [high, r1, high], "mul Rdm"),
            (0x4340, [r0, high, r0], "mul Rn"),
            (0x4340, [r0, r1, high], "mul Rdm repeated"),
            (0x4340, [r0, r1, Operand::Imm(0)], "mul third is a register"),
            (0x4340, [Operand::Imm(0), r1, r0], "mul first is a register"),
        ] {
            let bad = Insn {
                operands: ops.into_iter().collect(),
                ..decode(base, 0, 0).unwrap()
            };
            assert_eq!(encode(&bad), None, "`{bad}` encoded anyway: {field}");
        }
    }
}
