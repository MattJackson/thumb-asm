//! Shift (immediate), add, subtract, move, and compare — the 16-bit encodings
//! with `hw1[15:14] == 0b00` (ARM DDI 0403E.e A5.2.1, Table A5-2; the A/R
//! profile view is DDI 0406B A6.2.1 and is bit-for-bit the same).
//!
//! The space is *fully* allocated: every one of the 16384 halfwords in
//! `0x0000..=0x3FFF` is a defined instruction, so [`decode`] never returns
//! `None` for an `hw1` the dispatcher actually routes here. That is worth
//! stating because it makes the exhaustive round-trip test at the bottom of
//! this file a total check of the group rather than a sample of it.
//!
//! Two traps live in this table, both of them the kind that produce a decoder
//! which looks right and disassembles wrongly:
//!
//! * **Footnote a of Table A5-2.** `LSL (immediate)` T1 with `imm5 == 0` is not
//!   a shift by zero — it is `MOV (register)` T2. The instruction description
//!   (A7.7.68) says so as pseudocode: `if imm5 == '00000' then SEE MOV
//!   (register)`. The two differ in observable behaviour, not just in spelling:
//!   `LSLS` writes `APSR.C` from the shifted-out bit and `MOVS` leaves `C`
//!   alone.
//! * **`DecodeImmShift` (A7.4.2).** For `LSR` and `ASR` a zero `imm5` field
//!   means a shift of **32**, not 0 — the assembler syntax gives those forms a
//!   range of 1-32 while `LSL` gets 0-31. A decoder that prints `#0` there is
//!   off by a factor of 2^32.
//!
//! Every instruction here writes the condition flags when executed outside an
//! IT block (`setflags = !InITBlock()`), so [`Insn::sets_flags`] is `true`
//! throughout — with one exception. `CMP` has no `S` bit and no `S` suffix in
//! UAL: writing the flags is the whole instruction, and `Display` would render
//! a `sets_flags` of `true` as the non-existent mnemonic `cmps`.

use super::insn::{Operand, Operands, Reg, Width};
use super::Insn;

/// Assemble one narrow, unconditional instruction from this group.
///
/// `cond` is always `None`: nothing in this table encodes a condition of its
/// own. [`super::Decoder`] fills one in afterwards when an `IT` block is in
/// effect.
fn narrow(
    mnemonic: &'static str,
    encoding: &'static str,
    addr: u32,
    sets_flags: bool,
    operands: Operands,
) -> Insn {
    Insn {
        mnemonic,
        encoding,
        addr,
        width: Width::Narrow,
        cond: None,
        sets_flags,
        explicit_width: false,
        operands,
    }
}

/// Decode an instruction in this group, or `None` if `hw1`/`hw2` do not
/// belong to it.
pub(crate) fn decode(hw1: u16, _hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 >> 14 != 0 {
        return None;
    }

    // The register and immediate fields, named by bit position rather than by
    // role, because the role changes from row to row of Table A5-2 while the
    // position does not: `rd` is bits[2:0] (Rd), `rlow` is bits[5:3] (Rm for
    // the shifts, Rn for the register and 3-bit-immediate forms), `rhigh` is
    // bits[8:6] (Rm for ADD/SUB register).
    let rd = Reg((hw1 & 7) as u8);
    let rlow = Reg(((hw1 >> 3) & 7) as u8);
    let rhigh = Reg(((hw1 >> 6) & 7) as u8);
    let imm3 = i64::from((hw1 >> 6) & 7);
    let imm5 = (hw1 >> 6) & 0x1F;
    // The 8-bit-immediate rows move the register field to bits[10:8].
    let rdn = Reg(((hw1 >> 8) & 7) as u8);
    let imm8 = i64::from(hw1 & 0xFF);

    // `LSL{S} <Rd>, <Rm>, #<imm5>` — Rd, Rm and a bare immediate. The shift is
    // the operation, not a modifier on an operand, so this is three plain
    // operands and not an `Operand::RegShifted`; `lsrs r0, r0, lsr #3` is not
    // syntax any assembler accepts.
    let shift = |mnemonic: &'static str, amount: u16| {
        narrow(
            mnemonic,
            "T1",
            addr,
            true,
            [
                Operand::Reg(rd),
                Operand::Reg(rlow),
                Operand::Imm(i64::from(amount)),
            ]
            .into_iter()
            .collect(),
        )
    };
    // `ADDS <Rd>, <Rn>, <Rm>` / `ADDS <Rd>, <Rn>, #<imm3>`. All three registers
    // print even when Rd == Rn: the two-operand spelling is a *different*
    // encoding (T2, A5.2.3) that does not set the flags.
    let three = |mnemonic: &'static str, third: Operand| {
        narrow(
            mnemonic,
            "T1",
            addr,
            true,
            [Operand::Reg(rd), Operand::Reg(rlow), third]
                .into_iter()
                .collect(),
        )
    };
    // `MOVS <Rd>, #<imm8>`, `CMP <Rn>, #<imm8>`, `ADDS <Rdn>, #<imm8>`.
    let imm8_form = |mnemonic: &'static str, encoding: &'static str, sets_flags: bool| {
        narrow(
            mnemonic,
            encoding,
            addr,
            sets_flags,
            [Operand::Reg(rdn), Operand::Imm(imm8)]
                .into_iter()
                .collect(),
        )
    };

    Some(match (hw1 >> 9) & 0x1F {
        // 000xx — Logical Shift Left, except for footnote a's hole at the
        // bottom of it.
        0b00000..=0b00011 => {
            if imm5 == 0 {
                narrow(
                    "mov",
                    "T2",
                    addr,
                    true,
                    [Operand::Reg(rd), Operand::Reg(rlow)].into_iter().collect(),
                )
            } else {
                shift("lsl", imm5)
            }
        }
        // 001xx / 010xx — Logical and Arithmetic Shift Right, whose zero field
        // denotes 32 (A7.4.2 `DecodeImmShift`).
        0b00100..=0b00111 => shift("lsr", if imm5 == 0 { 32 } else { imm5 }),
        0b01000..=0b01011 => shift("asr", if imm5 == 0 { 32 } else { imm5 }),
        // 0110x / 0111x — the three-operand register and 3-bit-immediate forms.
        0b01100 => three("add", Operand::Reg(rhigh)),
        0b01101 => three("sub", Operand::Reg(rhigh)),
        0b01110 => three("add", Operand::Imm(imm3)),
        0b01111 => three("sub", Operand::Imm(imm3)),
        // 1xxxx — the 8-bit-immediate rows. `CMP` is the one form here that
        // takes no `S` suffix.
        0b10000..=0b10011 => imm8_form("mov", "T1", true),
        0b10100..=0b10111 => imm8_form("cmp", "T1", false),
        0b11000..=0b11011 => imm8_form("add", "T2", true),
        // 111xx, the only remaining opcode now that `hw1 >> 14 == 0`.
        _ => imm8_form("sub", "T2", true),
    })
}

/// A low register's number, or `None` for anything else.
///
/// Every register field in this group is three bits wide, so an operand naming
/// `r8`–`pc` cannot have come from here and must not be re-encoded as if it
/// had — that is how `add rd, sp, #imm` (A7.7.5) would otherwise be silently
/// mangled into `ADD (immediate)` T1.
///
/// An absent operand answers `None` through the same arm as a wrong one, and
/// deliberately: "there is no operand here" and "the operand here is not a low
/// register" are the same answer to the same question, and splitting them would
/// add a branch that the arity guards in [`encode`] already make unreachable.
fn low(op: Option<Operand>) -> Option<u16> {
    match op {
        Some(Operand::Reg(r)) if r.is_low() => Some(u16::from(r.num())),
        _ => None,
    }
}

/// An unsigned immediate no larger than `max`, or `None` — including for an
/// operand that is absent or is not an immediate at all.
fn imm(op: Option<Operand>, max: i64) -> Option<u16> {
    match op {
        Some(Operand::Imm(v)) if (0..=max).contains(&v) => Some(v as u16),
        _ => None,
    }
}

/// Check that [`Insn::sets_flags`] agrees with what this encoding can express.
///
/// `expected` is what the encoding does outside an IT block. Inside one,
/// `setflags` is architecturally `FALSE` for every form in this table, so a
/// conditional instruction is allowed to carry `sets_flags == false` without
/// changing a single bit of the halfword.
fn flags_ok(insn: &Insn, expected: bool) -> bool {
    insn.sets_flags == expected || (insn.cond.is_some() && !insn.sets_flags)
}

/// Re-encode an instruction this module decoded, back to its halfword.
///
/// Returns `None` for anything this group cannot express, which includes the
/// same-mnemonic instructions belonging to other groups: `mov`/`T1`,
/// `add`/`T2` and `cmp`/`T1` all also name encodings in A5.2.3, and are told
/// apart here by operand shape (`cmp r0, r1` is two registers; `cmp r0, #1` is
/// a register and an immediate).
// `allow`: nothing in `super` dispatches re-encoding yet, so from the lib
// target's point of view this and its helpers are unreachable. The tests below
pub(crate) fn encode(insn: &Insn) -> Option<u16> {
    if insn.width != Width::Narrow {
        return None;
    }
    let ops = &insn.operands;
    let (a, b, c) = (ops.get(0), ops.get(1), ops.get(2));

    match (insn.mnemonic, insn.encoding, ops.len()) {
        // `MOV (register)` T2 — `0000 0000 00 Rm Rd`, Table A5-2 footnote a.
        ("mov", "T2", 2) if flags_ok(insn, true) => Some((low(b)? << 3) | low(a)?),
        // The shift rows — `000 type imm5 Rm Rd`. `LSL #0` is deliberately
        // unencodable: that halfword is `MOV (register)` T2 and must round-trip
        // as the `mov` above.
        ("lsl", "T1", 3) | ("lsr", "T1", 3) | ("asr", "T1", 3) if flags_ok(insn, true) => {
            let (base, max) = match insn.mnemonic {
                "lsl" => (0x0000, 31),
                "lsr" => (0x0800, 32),
                _ => (0x1000, 32),
            };
            let n = imm(c, max)?;
            if n == 0 {
                return None;
            }
            // A shift of 32 encodes as a zero field (A7.4.2).
            Some(base | ((n & 0x1F) << 6) | (low(b)? << 3) | low(a)?)
        }
        // `ADD`/`SUB (register)` T1 — `0001 10x Rm Rn Rd`.
        ("add", "T1", 3) | ("sub", "T1", 3) if flags_ok(insn, true) => {
            // The register and immediate rows share a mnemonic and are told
            // apart by the third operand's shape. A missing third operand
            // cannot reach here — the arity is part of the match key above —
            // and would fall through to the immediate row, where `imm` refuses
            // it; that is why neither `match` needs an arm of its own for it.
            let base = match (insn.mnemonic, c) {
                ("add", Some(Operand::Reg(_))) => 0x1800,
                ("sub", Some(Operand::Reg(_))) => 0x1A00,
                ("add", _) => 0x1C00,
                _ => 0x1E00,
            };
            // `ADD`/`SUB (immediate)` T1 — `0001 11x imm3 Rn Rd`.
            let third = match c {
                Some(Operand::Reg(_)) => low(c)?,
                _ => imm(c, 7)?,
            };
            Some(base | (third << 6) | (low(b)? << 3) | low(a)?)
        }
        // The 8-bit-immediate rows — `001 op Rdn imm8`.
        ("mov", "T1", 2) if flags_ok(insn, true) => Some(0x2000 | (low(a)? << 8) | imm(b, 255)?),
        ("cmp", "T1", 2) if flags_ok(insn, false) => Some(0x2800 | (low(a)? << 8) | imm(b, 255)?),
        ("add", "T2", 2) if flags_ok(insn, true) => Some(0x3000 | (low(a)? << 8) | imm(b, 255)?),
        ("sub", "T2", 2) if flags_ok(insn, true) => Some(0x3800 | (low(a)? << 8) | imm(b, 255)?),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};
    use crate::isa::Target;
    use crate::isa::{decode_halfwords, Operand, Width};

    /// Every halfword in `0x0000..=0x3FFF` that decodes must re-encode to
    /// itself. Table A5-2 allocates the whole space, so the count must be all
    /// 16384 of them.
    #[test]
    fn exhaustive_round_trip() {
        // The allocation claim first, as a claim about the whole range rather
        // than as a per-halfword branch: Table A5-2 leaves no hole, so there is
        // no "did not decode" case for the loop below to skip past.
        let holes: Vec<u16> = (0x0000u16..=0x3FFF)
            .filter(|hw| decode(*hw, 0, 0).is_none())
            .collect();
        assert_eq!(
            holes,
            Vec::new(),
            "A5.2.1 allocates every encoding in 00xxxx"
        );

        for hw in 0x0000u16..=0x3FFF {
            let insn = decode(hw, 0, 0).expect("the group is fully allocated");
            assert_eq!(insn.width, Width::Narrow, "{hw:#06x} is a 16-bit encoding");
            assert_eq!(
                encode(&insn),
                Some(hw),
                "{hw:#06x} decoded as `{insn}` but did not re-encode"
            );
        }
    }

    /// The dispatcher must route the whole group here and nothing else: what
    /// `decode_halfwords` produces for this range has to be what `decode`
    /// produces, and the group must stop dead at `0x4000` (A5.2.2's space).
    #[test]
    fn dispatch_boundary() {
        for hw in 0x0000u16..=0x3FFF {
            assert_eq!(
                decode_halfwords(hw, 0, 0, Target::Union),
                decode(hw, 0, 0),
                "{hw:#06x} is not reaching t16_shift"
            );
        }
        assert!(decode(0x4000, 0, 0).is_none());
        assert!(decode(0xFFFF, 0, 0).is_none());
    }

    /// Print one instruction per row of Table A5-2. Expected strings are the
    /// UAL of the `Assembler syntax` section of each instruction description,
    /// with immediates rendered by `Operand`'s rule (decimal below 10, hex at
    /// or above it).
    #[test]
    fn ual_per_table_row() {
        let cases: &[(u16, &str)] = &[
            // 000xx `LSL (immediate)` T1 — A7.7.68, `LSLS <Rd>,<Rm>,#<imm5>`.
            (0x0088, "lsls r0, r1, #2"),
            // 001xx `LSR (immediate)` T1 — A7.7.70.
            (0x08CB, "lsrs r3, r1, #3"),
            // 010xx `ASR (immediate)` T1 — A7.7.10.
            (0x1151, "asrs r1, r2, #5"),
            // 01100 `ADD (register)` T1 — A7.7.4, `ADDS <Rd>,<Rn>,<Rm>`.
            (0x1888, "adds r0, r1, r2"),
            // 01101 `SUB (register)` T1 — A7.7.175.
            (0x1AE5, "subs r5, r4, r3"),
            // 01110 `ADD (immediate)` T1 — A7.7.3, `ADDS <Rd>,<Rn>,#<imm3>`.
            (0x1C08, "adds r0, r1, #0"),
            // 01111 `SUB (immediate)` T1 — A7.7.174.
            (0x1FD1, "subs r1, r2, #7"),
            // 100xx `MOV (immediate)` T1 — A7.7.76, `MOVS <Rd>,#<imm8>`.
            (0x232A, "movs r3, #0x2a"),
            // 101xx `CMP (immediate)` T1 — A7.7.27, `CMP <Rn>,#<imm8>`.
            (0x2F00, "cmp r7, #0"),
            (0x2864, "cmp r0, #0x64"),
            // 110xx `ADD (immediate)` T2 — A7.7.3, `ADDS <Rdn>,#<imm8>`.
            (0x3101, "adds r1, #1"),
            // 111xx `SUB (immediate)` T2 — A7.7.174.
            (0x3CFF, "subs r4, #0xff"),
        ];
        for &(hw, text) in cases {
            let bytes = hw.to_le_bytes();
            let insn = crate::isa::decode_at(&bytes, 0).expect("defined encoding");
            assert_eq!(insn.to_string(), text, "for {hw:#06x}");
        }
    }

    /// Table A5-2 footnote a: opcode `0b00000` with `hw1[8:6] == 0b000` is
    /// `MOV (register)` T2 (A7.7.77), not `LSL (immediate)` with a zero shift.
    /// T2 has `setflags = TRUE`, so it prints as `movs`.
    #[test]
    fn lsl_zero_is_mov_register_t2() {
        let insn = decode(0x0000, 0, 0).unwrap();
        assert_eq!(insn.mnemonic, "mov");
        assert_eq!(insn.encoding, "T2");
        assert!(insn.sets_flags);
        assert_eq!(insn.operands.len(), 2);
        assert_eq!(insn.to_string(), "movs r0, r0");

        // `0000 0000 00 010 001` — Rm = r2, Rd = r1.
        let insn = decode(0x0011, 0, 0).unwrap();
        assert_eq!(insn.to_string(), "movs r1, r2");
        assert_eq!(encode(&insn), Some(0x0011));

        // The hole is exactly eight halfwords wide: every other opcode-0b00000
        // encoding, i.e. every non-zero `hw1[8:6]`, is still an `LSL`.
        for hw in 0x0000u16..=0x07FF {
            let insn = decode(hw, 0, 0).unwrap();
            let expected = if (hw >> 6) & 0x1F == 0 { "mov" } else { "lsl" };
            assert_eq!(insn.mnemonic, expected, "for {hw:#06x}");
        }
    }

    /// `DecodeImmShift` (A7.4.2): a zero `imm5` field means a shift of 32 for
    /// `LSR` and `ASR`, which is why their documented syntax range is 1-32
    /// while `LSL`'s is 0-31.
    #[test]
    fn right_shift_by_zero_field_is_thirty_two() {
        // `0000 1 00000 000 000` — LSR, imm5 = 0, Rm = Rd = r0.
        let insn = decode(0x0800, 0, 0).unwrap();
        assert_eq!(insn.mnemonic, "lsr");
        assert_eq!(insn.operands.get(2), Some(Operand::Imm(32)));
        assert_eq!(insn.to_string(), "lsrs r0, r0, #0x20");
        assert_eq!(encode(&insn), Some(0x0800));

        // `0001 0 00000 000 000` — ASR, same story.
        let insn = decode(0x1000, 0, 0).unwrap();
        assert_eq!(insn.mnemonic, "asr");
        assert_eq!(insn.operands.get(2), Some(Operand::Imm(32)));
        assert_eq!(encode(&insn), Some(0x1000));

        // A neighbouring non-zero field is itself, not 32: `0x0840` has
        // imm5 = 1.
        let insn = decode(0x0840, 0, 0).unwrap();
        assert_eq!(insn.operands.get(2), Some(Operand::Imm(1)));
        assert_eq!(insn.to_string(), "lsrs r0, r0, #1");

        // ... and `LSL` really does shift by the field, once past the hole.
        let insn = decode(0x0040, 0, 0).unwrap();
        assert_eq!(insn.to_string(), "lsls r0, r0, #1");
    }

    /// `CMP` writes the flags but takes no `S` suffix in UAL (A7.7.27 spells
    /// the syntax `CMP<c><q> <Rn>, #<const>`), and `Display` appends an `s`
    /// for any instruction with `sets_flags` set — so the whole `101xx` row
    /// must carry `sets_flags == false` or it prints as the non-existent
    /// `cmps`.
    #[test]
    fn cmp_never_prints_an_s_suffix() {
        for hw in 0x2800u16..=0x2FFF {
            let insn = decode(hw, 0, 0).unwrap();
            assert_eq!(insn.mnemonic, "cmp");
            assert!(!insn.sets_flags, "{hw:#06x} would print as `cmps`");
            let text = insn.to_string();
            assert!(text.starts_with("cmp "), "{hw:#06x} printed `{text}`");
        }
    }

    /// `ADD (register)` T1 with `Rd == Rn` keeps all three operands. Collapsing
    /// it to `adds r0, r1` would name a *different* encoding — A5.2.3's
    /// `ADD (register)` T2, which does not set the flags.
    #[test]
    fn add_register_keeps_three_operands() {
        // `0001 100 010 000 000` — Rm = r2, Rn = r0, Rd = r0.
        let insn = decode(0x1880, 0, 0).unwrap();
        assert_eq!(insn.operands.len(), 3);
        assert_eq!(insn.to_string(), "adds r0, r0, r2");
    }

    /// `encode` must reject the same-mnemonic encodings that belong to other
    /// groups, since a consumer re-encoding a whole instruction stream hands
    /// every `Insn` to every group's `encode`.
    #[test]
    fn encode_rejects_foreign_forms() {
        use crate::isa::{Insn, Operands, Reg};

        let mut ops = Operands::new();
        ops.push(Operand::Reg(Reg(0)));
        ops.push(Operand::Reg(Reg::SP));
        ops.push(Operand::Imm(4));
        let sp_form = Insn {
            mnemonic: "add",
            encoding: "T1",
            addr: 0,
            width: Width::Narrow,
            cond: None,
            sets_flags: true,
            explicit_width: false,
            operands: ops,
        };
        // `ADD (SP plus immediate)` T1 (A7.7.5) shares mnemonic and encoding
        // name with `ADD (immediate)` T1 but names the SP, which no field here
        // can hold.
        assert_eq!(encode(&sp_form), None);

        // A wide encoding is never ours.
        let mut wide = decode(0x3101, 0, 0).unwrap();
        wide.width = Width::Wide;
        assert_eq!(encode(&wide), None);

        // An out-of-range immediate is not encodable in eight bits.
        let mut big = decode(0x3101, 0, 0).unwrap();
        big.operands = [Operand::Reg(Reg(1)), Operand::Imm(256)]
            .into_iter()
            .collect();
        assert_eq!(encode(&big), None);
    }

    /// Every field of every row, offered something that does not fit it.
    ///
    /// `encode` is reachable from [`crate::isa::encode`], which hands each
    /// group every narrow instruction in turn until one answers — so a group
    /// that accepted an operand its fields cannot hold would emit a halfword
    /// for an instruction that belongs to a *different* group, and the
    /// neighbour's own tests would never see it. Refusing is what makes the
    /// chain safe, and refusing is therefore what is asserted here: one case
    /// per register and immediate field in Table A5-2.
    #[test]
    fn encode_refuses_operands_no_field_can_hold() {
        use crate::isa::{Insn, Operands, Reg};

        let build = |mnemonic, encoding, ops: &[Operand], sets_flags| Insn {
            mnemonic,
            encoding,
            addr: 0,
            width: Width::Narrow,
            cond: None,
            sets_flags,
            explicit_width: false,
            operands: ops.iter().copied().collect::<Operands>(),
        };
        let r0 = Operand::Reg(Reg(0));
        let r1 = Operand::Reg(Reg(1));
        // `r8` is the point: every register field in this table is three bits
        // wide, so a high register is not merely unusual, it is unencodable —
        // and `mov r0, r8` is `MOV (register)` T1 in A5.2.3, another group's
        // instruction entirely.
        let r8 = Operand::Reg(Reg(8));

        let cases: &[(&'static str, &'static str, &[Operand], bool, &str)] = &[
            // `MOV (register)` T2 — both fields, both directions.
            ("mov", "T2", &[r0, r8], true, "Rm is high"),
            ("mov", "T2", &[r8, r0], true, "Rd is high"),
            // The shift rows. `LSL #0` is deliberately unencodable: that
            // halfword is `MOV (register)` T2 (Table A5-2 footnote a) and
            // must round-trip as the `mov`, so `lsl r0, r1, #0` — which an
            // assembler would itself rewrite to `movs` — gets no encoding.
            (
                "lsl",
                "T1",
                &[r0, r1, Operand::Imm(0)],
                true,
                "LSL #0 is a MOV",
            ),
            (
                "lsr",
                "T1",
                &[r0, r1, Operand::Imm(0)],
                true,
                "LSR #0 is #32",
            ),
            (
                "asr",
                "T1",
                &[r0, r1, Operand::Imm(0)],
                true,
                "ASR #0 is #32",
            ),
            // …and the ends of each range: LSL is 0-31 (with 0 excluded
            // above), LSR and ASR are 1-32 (A7.4.2 `DecodeImmShift`).
            (
                "lsl",
                "T1",
                &[r0, r1, Operand::Imm(32)],
                true,
                "LSL max is 31",
            ),
            (
                "lsr",
                "T1",
                &[r0, r1, Operand::Imm(33)],
                true,
                "LSR max is 32",
            ),
            (
                "lsl",
                "T1",
                &[r0, r1, r1],
                true,
                "a shift amount is no register",
            ),
            ("lsl", "T1", &[r0, r8, Operand::Imm(2)], true, "Rm is high"),
            ("lsl", "T1", &[r8, r0, Operand::Imm(2)], true, "Rd is high"),
            // `ADD`/`SUB (register)` T1 and `(immediate)` T1 — imm3 is three
            // bits, and `adds r0, r1, r8` is the wide encoding's business.
            ("add", "T1", &[r0, r1, r8], true, "Rm is high"),
            ("add", "T1", &[r0, r8, r1], true, "Rn is high"),
            ("add", "T1", &[r8, r0, r1], true, "Rd is high"),
            (
                "add",
                "T1",
                &[r0, r1, Operand::Imm(8)],
                true,
                "imm3 max is 7",
            ),
            (
                "sub",
                "T1",
                &[r0, r1, Operand::Imm(-1)],
                true,
                "imm3 is unsigned",
            ),
            // The 8-bit-immediate rows, register field and immediate field.
            ("mov", "T1", &[r8, Operand::Imm(1)], true, "Rd is high"),
            (
                "mov",
                "T1",
                &[r0, Operand::Imm(256)],
                true,
                "imm8 max is 255",
            ),
            (
                "cmp",
                "T1",
                &[r0, Operand::Imm(256)],
                false,
                "imm8 max is 255",
            ),
            ("cmp", "T1", &[r8, Operand::Imm(1)], false, "Rn is high"),
            (
                "add",
                "T2",
                &[r0, Operand::Imm(256)],
                true,
                "imm8 max is 255",
            ),
            ("add", "T2", &[r8, Operand::Imm(1)], true, "Rdn is high"),
            (
                "sub",
                "T2",
                &[r0, Operand::Imm(256)],
                true,
                "imm8 max is 255",
            ),
            ("sub", "T2", &[r8, Operand::Imm(1)], true, "Rdn is high"),
            // The flag column is part of the encoding, not decoration: every
            // row here sets the flags outside an IT block except `CMP`, which
            // has no `S` bit at all.
            (
                "mov",
                "T1",
                &[r0, Operand::Imm(1)],
                false,
                "MOV T1 sets flags",
            ),
            (
                "cmp",
                "T1",
                &[r0, Operand::Imm(1)],
                true,
                "CMP has no S bit",
            ),
            // …and the same for every other row of the table, because each
            // carries its own `flags_ok` guard and a missing one is invisible
            // from the round trip: the decoder only ever *produces*
            // `sets_flags == true` here, so nothing but a hand-built `Insn`
            // asks the question. Getting it wrong would hand back a halfword
            // that sets the flags to a caller who asked for one that does not
            // — and in a firmware patch the next instruction is quite
            // possibly a conditional branch reading them.
            ("mov", "T2", &[r0, r1], false, "MOV T2 sets flags"),
            (
                "lsl",
                "T1",
                &[r0, r1, Operand::Imm(2)],
                false,
                "LSL T1 sets flags",
            ),
            ("add", "T1", &[r0, r1, r1], false, "ADD reg T1 sets flags"),
            (
                "add",
                "T2",
                &[r0, Operand::Imm(1)],
                false,
                "ADD imm T2 sets flags",
            ),
            (
                "sub",
                "T2",
                &[r0, Operand::Imm(1)],
                false,
                "SUB imm T2 sets flags",
            ),
        ];
        for &(mnemonic, encoding, ops, sets_flags, why) in cases {
            let insn = build(mnemonic, encoding, ops, sets_flags);
            assert_eq!(encode(&insn), None, "`{insn}` encoded anyway: {why}");
        }

        // Each rejection above is a rejection of the *operand*, not of the
        // row: the same row with operands that fit encodes.
        assert_eq!(encode(&build("mov", "T2", &[r0, r1], true)), Some(0x0008));
        assert_eq!(
            encode(&build("lsl", "T1", &[r0, r1, Operand::Imm(31)], true)),
            Some(0x07C8)
        );
        assert_eq!(
            encode(&build("lsr", "T1", &[r0, r1, Operand::Imm(32)], true)),
            Some(0x0808),
            "a shift of 32 encodes as a zero field (A7.4.2)"
        );
        assert_eq!(
            encode(&build("add", "T1", &[r0, r1, Operand::Imm(7)], true)),
            Some(0x1DC8)
        );
        assert_eq!(
            encode(&build("sub", "T2", &[r0, Operand::Imm(255)], true)),
            Some(0x38FF)
        );
    }
}
