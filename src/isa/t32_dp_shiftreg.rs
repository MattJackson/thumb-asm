//! 32-bit data processing (shifted register) — `hw1[15:9] == 0b1110101`
//! (ARM DDI 0403E.e A5.3.11, Tables A5-22 and A5-23; the A/R profile view is
//! ARM DDI 0406C A6.3.11, Table A6-22, which differs only in naming the
//! `0110` row `PKH` rather than `PKHBT, PKHTB`).
//!
//! The layout is one shape in two halfwords:
//!
//! ```text
//! hw1 = 1110 101 op(4) S Rn(4)
//! hw2 = (0)  imm3(3)   Rd(4) imm2(2) type(2) Rm(4)
//! ```
//!
//! so every instruction here is "`Rn` combined with `Rm` shifted by `type` by
//! `imm3:imm2`, into `Rd`, optionally setting the flags". The five bits of
//! `imm3:imm2` and the two of `type` are a single [`Shift`], and this group is
//! what [`Operand::RegShifted`] exists for.
//!
//! # The three things that are not the shared shape
//!
//! **`Rd == 1111` is a test instruction, not a destination.** For `op` of
//! `0000`, `0100`, `1000` and `1101`, writing `pc` would be meaningless for an
//! operation whose only purpose can then be the flags, so Arm reclaims the
//! encoding: `AND`→`TST`, `EOR`→`TEQ`, `ADD`→`CMN`, `SUB`→`CMP`. The reclaim
//! only happens with `S == 1`; `Rd == 1111` with `S == 0` is UNPREDICTABLE in
//! Table A5-22 and names no instruction at all, so [`decode`] returns `None`
//! for those 8192 encodings rather than inventing an `and pc, …` that no
//! assembler would accept back.
//!
//! **`Rn == 1111` is "no first operand".** `ORR` with nothing to OR against is
//! a move (`op == 0010`), and `ORN` with nothing is a bitwise NOT
//! (`op == 0011` → `MVN`). This mirrors the modified-immediate group exactly
//! (A5.3.1), which is the point: the same two aliasing rules are applied to
//! both halves of the data-processing space.
//!
//! **Table A5-23, the sub-table, is the interesting part.** When
//! `op == 0010 && Rn == 1111` the instruction is not `ORR`, and it is not
//! simply `MOV` either: `type` and `imm3:imm2` between them select one of six
//! instructions, because *the shift is the operation* once there is no first
//! operand left to combine with.
//!
//! | `type` | `imm3:imm2` | instruction | encoding |
//! |---|---|---|---|
//! | `00` | `00000` | `MOV (register)` | T3 |
//! | `00` | not `00000` | `LSL (immediate)` | T2 |
//! | `01` | — | `LSR (immediate)` | T2 |
//! | `10` | — | `ASR (immediate)` | T2 |
//! | `11` | `00000` | `RRX` | T1 |
//! | `11` | not `00000` | `ROR (immediate)` | T2 |
//!
//! The two boundaries in that table are the whole of A5.3.11's difficulty. A
//! left shift by zero is a no-op, so `type == 00` with a zero amount is spent
//! on `MOV` (A7.7.68: *`if (imm3:imm2) == '00000' then SEE MOV (register)`*).
//! A rotate by zero is equally a no-op, so `type == 11` with a zero amount is
//! spent on `RRX` (A7.7.116: *`if (imm3:imm2) == '00000' then SEE RRX`*).
//! `LSR` and `ASR` have no such hole, because for them a zero field already
//! means something: 32.
//!
//! # `DecodeImmShift` — a zero field is not always a zero shift
//!
//! [`imm_shift`] is A7.4.2's `DecodeImmShift()` verbatim. For `LSR` and `ASR`
//! an `imm3:imm2` of `00000` denotes a shift of **32**, not 0 — their syntax
//! lines give `<imm5>` a range of 1-32 while `LSL` gets 0-31 and `ROR` gets
//! 1-31. A decoder that prints `#0` there is wrong by a factor of 2^32, and it
//! is wrong silently, because `#0` is a perfectly plausible-looking operand.
//!
//! # The zero shift is omitted, in both directions
//!
//! UAL writes `and.w r0, r1, r2`, never `and.w r0, r1, r2, lsl #0`: every
//! syntax line in this group spells the shift `{,<shift>}`, and
//! *"if `<shift>` is omitted, no shift is applied"*. So [`shifted`] yields a
//! plain [`Operand::Reg`] for `type == 00 && imm3:imm2 == 00000` and an
//! [`Operand::RegShifted`] for everything else, and [`unshift`] inverts that:
//! a bare register re-encodes to `type = 00, imm5 = 0`, while a `Shift` of
//! `lsl #0` is *rejected*, since it is not the form this decoder ever
//! produces and encoding it would yield halfwords that decode back to a
//! different [`Insn`].
//!
//! # `PKHBT`/`PKHTB` — the shift chooses the mnemonic
//!
//! The `0110` row (A7.7.93, Armv7E-M) reads the `type` field as `tb:T` rather
//! than as a shift type: `T == 1` and `S == 1` are both UNDEFINED, and `tb`
//! picks between `PKHBT` (`LSL`, `type == 00`) and `PKHTB` (`ASR`,
//! `type == 10`). Because the encoding-specific pseudocode is
//! `DecodeImmShift(tb:'0', imm3:imm2)`, the *amount* still decodes by the
//! ordinary rule — which is why `PKHTB` with a zero field prints
//! `, asr #32` and never omits its shift, while `PKHBT` with a zero field
//! omits it. That asymmetry is in the manual, not in this file: *"For
//! `PKHTB` … A shift by 32 bits is encoded as `0b00000`"*, and Arm explicitly
//! forbids the `PKHTB …, asr #0` spelling for disassembly.
//!
//! # `.W`, per instruction
//!
//! [`Insn::explicit_width`] is set from each instruction's own syntax line,
//! not from a blanket rule, because Arm does not apply one. An instruction
//! whose operation also has a 16-bit encoding of the *same operand shape*
//! needs the qualifier to reassemble to these bytes and gets it: `AND` T2,
//! `TST` T2, `BIC` T2, `ORR` T2, `MVN` T2, `EOR` T2, `ADD` T3, `CMN` T2,
//! `ADC` T2, `SBC` T2, `SUB` T2, `CMP` T3, `MOV` T3, `LSL` T2, `LSR` T2 and
//! `ASR` T2 are all written `<op>{S}<c>.W …`. Six are not:
//!
//! * `ORN` T1, `TEQ` T1, `RSB (register)` T1 and `PKHBT`/`PKHTB` T1 have no
//!   16-bit encoding at all, so there is nothing to disambiguate.
//! * `ROR (immediate)` T1 and `RRX` T1 likewise: the only narrow `ROR` is
//!   `ROR (register)` T1, whose operand shape (`rors rdn, rm`) cannot be
//!   confused with `ror rd, rm, #imm5`, and `RRX` has no narrow form.
//!
//! Note that `RSB` here is T1 while the narrow reverse-subtract is
//! `RSB (immediate)` T1 — same mnemonic, same encoding name, different
//! *width*, which is why [`encode`] keys on width first.
//!
//! # `sp` and `pc`
//!
//! `Rn`, `Rd` and `Rm` are full four-bit fields, and nearly every instruction
//! page here declares the extremes UNPREDICTABLE — typically
//! `if d IN {13,15} || n IN {13,15} || m IN {13,15}`, relaxed to
//! `d == 13 || (d == 15 && S == '0')` for the four that have a `Rd == 1111`
//! alias, and to `n == 13` for `ORR`/`ORN` (whose `Rn == 1111` is the alias
//! rather than an error). Those encodings are decoded anyway, exactly as
//! `t16_special` decodes its deprecated `sp`/`pc` combinations: an
//! UNPREDICTABLE instruction still has bits, and a disassembler reading a
//! firmware image is more useful reporting `and.w r0, sp, r2` than refusing
//! to. They round-trip, so nothing is lost.
//!
//! Two things *are* refused, both because they are not representable in an
//! [`Insn`] and so could not round-trip:
//!
//! * `hw2[15]`, drawn `(0)` in every encoding diagram in this group. A `(0)`
//!   bit that is not zero makes the instruction UNPREDICTABLE (D6.1), and
//!   carrying the stray bit is impossible, so a `1` there decodes to `None`.
//! * The `Rd == 1111, S == 0` rows of Table A5-22, discussed above.

use super::insn::{Operand, Operands, Reg, Shift, ShiftAmount, ShiftKind, Width};
use super::Insn;

/// `hw1[15:9]` for the whole group: `1110101`.
const GROUP: u16 = 0b111_0101 << 9;

/// The operand shape of one row of Table A5-22 or A5-23.
///
/// The shape is what decides where `Rn` and `Rd` come from — several rows put
/// a literal `1111` in one of those fields rather than an operand — so it is
/// carried in the table rather than rediscovered by each direction.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Form {
    /// `{<Rd>,} <Rn>, <Rm> {,<shift>}` — the ten ordinary binary operations.
    Three,
    /// `<Rn>, <Rm> {,<shift>}` — `TST`/`TEQ`/`CMN`/`CMP`. The `Rd` field is a
    /// literal `1111` and `S` is a literal `1`; UAL gives them no `S` suffix,
    /// so [`Insn::sets_flags`] is `false` even though they always write the
    /// flags (that is their entire effect).
    Test,
    /// `<Rd>, <Rm> {,<shift>}` — `MVN`, reached by `Rn == 1111` on `op 0011`.
    Mvn,
    /// `{<Rd>,} <Rn>, <Rm> {, LSL|ASR #<imm>}` — `PKHBT` (`tb == 0`) and
    /// `PKHTB` (`tb == 1`). `type` is `tb:T` and `S` must be `0`.
    Pack {
        /// `hw2[5]`: 0 for `PKHBT`, 1 for `PKHTB`.
        tb: u16,
    },
    /// `<Rd>, <Rm>` — `MOV` T3 (`type == 00`) and `RRX` T1 (`type == 11`),
    /// both with a zero `imm3:imm2`. Table A5-23.
    Move {
        /// The `type` field this row occupies.
        ty: u16,
    },
    /// `<Rd>, <Rm>, #<imm5>` — `LSL`/`LSR`/`ASR`/`ROR (immediate)`. The shift
    /// is the operation, so the amount is a plain [`Operand::Imm`] and not an
    /// [`Operand::RegShifted`]: `lsr.w r0, r1, lsr #3` is not syntax.
    /// Table A5-23.
    ShiftImm {
        /// The `type` field this row occupies.
        ty: u16,
    },
}

impl Form {
    /// Whether this row is reached by `Rn == 1111` — i.e. whether it steals
    /// that encoding from the `Three`-shaped instruction sharing its `op`.
    fn takes_rn_1111(self) -> bool {
        matches!(self, Form::Mvn | Form::Move { .. } | Form::ShiftImm { .. })
    }
}

/// One row of Table A5-22, or of Table A5-23 where `op == 0010, Rn == 1111`.
struct Row {
    /// `hw1[8:5]`.
    op: u16,
    /// The base mnemonic, lower case, without `S` or width suffix.
    mnemonic: &'static str,
    /// The architectural encoding name, from the instruction's own page.
    encoding: &'static str,
    /// Where the operands come from.
    form: Form,
    /// Whether the instruction's syntax line carries `.W` — see the module
    /// docs, which justify this per row.
    wide_suffix: bool,
}

/// Tables A5-22 and A5-23, flattened.
///
/// `(op, mnemonic)` identifies a row for [`decode`] and `(mnemonic, encoding)`
/// identifies one for [`encode`]; both are unique across the table, which is
/// what lets the two directions share it and so makes them unable to disagree
/// about a mnemonic, an encoding name or a `.W`.
const TABLE: [Row; 23] = [
    // Table A5-22. `-` in the `Rn`/`Rd`/`S` columns means "any".
    Row {
        op: 0b0000,
        mnemonic: "and",
        encoding: "T2",
        form: Form::Three,
        wide_suffix: true,
    }, // A7.7.9
    Row {
        op: 0b0000,
        mnemonic: "tst",
        encoding: "T2",
        form: Form::Test,
        wide_suffix: true,
    }, // A7.7.189
    Row {
        op: 0b0001,
        mnemonic: "bic",
        encoding: "T2",
        form: Form::Three,
        wide_suffix: true,
    }, // A7.7.16
    Row {
        op: 0b0010,
        mnemonic: "orr",
        encoding: "T2",
        form: Form::Three,
        wide_suffix: true,
    }, // A7.7.92
    Row {
        op: 0b0011,
        mnemonic: "orn",
        encoding: "T1",
        form: Form::Three,
        wide_suffix: false,
    }, // A7.7.90
    Row {
        op: 0b0011,
        mnemonic: "mvn",
        encoding: "T2",
        form: Form::Mvn,
        wide_suffix: true,
    }, // A7.7.86
    Row {
        op: 0b0100,
        mnemonic: "eor",
        encoding: "T2",
        form: Form::Three,
        wide_suffix: true,
    }, // A7.7.36
    Row {
        op: 0b0100,
        mnemonic: "teq",
        encoding: "T1",
        form: Form::Test,
        wide_suffix: false,
    }, // A7.7.187
    Row {
        op: 0b0110,
        mnemonic: "pkhbt",
        encoding: "T1",
        form: Form::Pack { tb: 0 },
        wide_suffix: false,
    }, // A7.7.93
    Row {
        op: 0b0110,
        mnemonic: "pkhtb",
        encoding: "T1",
        form: Form::Pack { tb: 1 },
        wide_suffix: false,
    }, // A7.7.93
    Row {
        op: 0b1000,
        mnemonic: "add",
        encoding: "T3",
        form: Form::Three,
        wide_suffix: true,
    }, // A7.7.4
    Row {
        op: 0b1000,
        mnemonic: "cmn",
        encoding: "T2",
        form: Form::Test,
        wide_suffix: true,
    }, // A7.7.26
    Row {
        op: 0b1010,
        mnemonic: "adc",
        encoding: "T2",
        form: Form::Three,
        wide_suffix: true,
    }, // A7.7.2
    Row {
        op: 0b1011,
        mnemonic: "sbc",
        encoding: "T2",
        form: Form::Three,
        wide_suffix: true,
    }, // A7.7.125
    Row {
        op: 0b1101,
        mnemonic: "sub",
        encoding: "T2",
        form: Form::Three,
        wide_suffix: true,
    }, // A7.7.175
    Row {
        op: 0b1101,
        mnemonic: "cmp",
        encoding: "T3",
        form: Form::Test,
        wide_suffix: true,
    }, // A7.7.28
    Row {
        op: 0b1110,
        mnemonic: "rsb",
        encoding: "T1",
        form: Form::Three,
        wide_suffix: false,
    }, // A7.7.120
    // Table A5-23 — `op == 0010` with `Rn == 1111`.
    Row {
        op: 0b0010,
        mnemonic: "mov",
        encoding: "T3",
        form: Form::Move { ty: 0b00 },
        wide_suffix: true,
    }, // A7.7.77
    Row {
        op: 0b0010,
        mnemonic: "lsl",
        encoding: "T2",
        form: Form::ShiftImm { ty: 0b00 },
        wide_suffix: true,
    }, // A7.7.68
    Row {
        op: 0b0010,
        mnemonic: "lsr",
        encoding: "T2",
        form: Form::ShiftImm { ty: 0b01 },
        wide_suffix: true,
    }, // A7.7.70
    Row {
        op: 0b0010,
        mnemonic: "asr",
        encoding: "T2",
        form: Form::ShiftImm { ty: 0b10 },
        wide_suffix: true,
    }, // A7.7.10
    Row {
        op: 0b0010,
        mnemonic: "rrx",
        encoding: "T1",
        form: Form::Move { ty: 0b11 },
        wide_suffix: false,
    }, // A7.7.118
    Row {
        op: 0b0010,
        mnemonic: "ror",
        // T1, not T2. `LSL`/`LSR`/`ASR` (immediate) each spend a T1 on their
        // 16-bit form, so their 32-bit form is T2 — but there is no 16-bit
        // `ROR` immediate, so A7.7.116 lists exactly one encoding and this is
        // it. `RRX` above is T1 for the same reason.
        encoding: "T1",
        form: Form::ShiftImm { ty: 0b11 },
        wide_suffix: false,
    }, // A7.7.116
];

impl Form {
    /// How many operands this form's UAL syntax line has.
    ///
    /// [`encode`] checks this as an upper bound only. The lower bound falls
    /// out of reading the operands — every read below is a `?` on
    /// `Operands::get`, which is `None` when the operand is not there — and
    /// checking the exact count up front instead would make every one of
    /// those `?`s unreachable, which is to say it would spell out a dozen
    /// cases that cannot happen.
    fn arity(self) -> usize {
        match self {
            Form::Three | Form::Pack { .. } | Form::ShiftImm { .. } => 3,
            Form::Test | Form::Mvn | Form::Move { .. } => 2,
        }
    }
}

/// Whether `op` gives up its `Rd == 1111` encodings to a test instruction —
/// true for `0000`, `0100`, `1000` and `1101`.
fn has_test_alias(op: u16) -> bool {
    TABLE.iter().any(|r| r.op == op && r.form == Form::Test)
}

/// Whether `op` gives up its `Rn == 1111` encodings to a move-like
/// instruction — true for `0010` (Table A5-23) and `0011` (`MVN`).
fn has_rn_alias(op: u16) -> bool {
    TABLE.iter().any(|r| r.op == op && r.form.takes_rn_1111())
}

/// `DecodeImmShift()` — ARM DDI 0403E.e A7.4.2, transcribed.
///
/// The one subtlety is that the five-bit field is not the shift amount for
/// three of the four `type` values: `LSR` and `ASR` read `00000` as 32, and
/// `ROR` reads it as "this is `RRX`, whose amount is fixed at 1".
fn imm_shift(ty: u16, imm5: u16) -> (ShiftKind, u16) {
    match ty {
        0b00 => (ShiftKind::Lsl, imm5),
        0b01 => (ShiftKind::Lsr, if imm5 == 0 { 32 } else { imm5 }),
        0b10 => (ShiftKind::Asr, if imm5 == 0 { 32 } else { imm5 }),
        _ if imm5 == 0 => (ShiftKind::Rrx, 1),
        _ => (ShiftKind::Ror, imm5),
    }
}

/// The `Rm` operand: shifted, or plain when there is no shift to print.
///
/// `LSL #0` is the one encodable no-op shift, and UAL omits it — see the
/// module docs. Every other `(type, imm3:imm2)` denotes a real shift, `RRX`
/// included.
fn shifted(rm: Reg, ty: u16, imm5: u16) -> Operand {
    match imm_shift(ty, imm5) {
        (ShiftKind::Lsl, 0) => Operand::Reg(rm),
        (kind, amount) => Operand::RegShifted(
            rm,
            Shift {
                kind,
                amount: ShiftAmount::Imm(amount as u8),
            },
        ),
    }
}

/// The five-bit field that encodes a shift of `amount` for this `type`, or
/// `None` if the amount is out of range for it.
///
/// The inverse of [`imm_shift`], and the reason the ranges differ per type:
/// `LSL` and `ROR` take 1-31, `LSR` and `ASR` take 1-32 with 32 encoded as
/// zero. Zero is refused for all four — a zero `LSL` is a plain register
/// operand or `MOV`, and a zero `ROR` is `RRX`.
fn shift_amount_bits(ty: u16, amount: i64) -> Option<u16> {
    match ty {
        0b01 | 0b10 if (1..=32).contains(&amount) => Some(amount as u16 & 0x1F),
        0b00 | 0b11 if (1..=31).contains(&amount) => Some(amount as u16),
        _ => None,
    }
}

/// The `(Rm, type, imm3:imm2)` a second-operand [`Operand`] encodes.
///
/// The inverse of [`shifted`], and deliberately no more permissive: a bare
/// register is `type = 00, imm5 = 0`, and anything that [`shifted`] cannot
/// produce — a register-controlled shift, an `lsl #0`, a `ror #0`, an
/// `rrx` with an amount other than 1 — is refused, because encoding it would
/// hand back halfwords that decode to a different instruction.
fn unshift(op: Operand) -> Option<(u16, u16, u16)> {
    let (rm, kind, amount) = match op {
        Operand::Reg(r) => return Some((u16::from(r.num()), 0b00, 0)),
        Operand::RegShifted(
            r,
            Shift {
                kind,
                amount: ShiftAmount::Imm(n),
            },
        ) => (r, kind, i64::from(n)),
        _ => return None,
    };
    let (ty, imm5) = match kind {
        ShiftKind::Lsl => (0b00, shift_amount_bits(0b00, amount)?),
        ShiftKind::Lsr => (0b01, shift_amount_bits(0b01, amount)?),
        ShiftKind::Asr => (0b10, shift_amount_bits(0b10, amount)?),
        ShiftKind::Ror => (0b11, shift_amount_bits(0b11, amount)?),
        ShiftKind::Rrx if amount == 1 => (0b11, 0),
        ShiftKind::Rrx => return None,
    };
    Some((u16::from(rm.num()), ty, imm5))
}

/// Decode an instruction in this group, or `None` if `hw1`/`hw2` do not
/// belong to it, name an UNDEFINED `op`, or are one of the UNPREDICTABLE
/// patterns the module docs list.
pub(crate) fn decode(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 & 0xFE00 != GROUP {
        return None;
    }
    // `hw2[15]` is drawn `(0)` throughout A5.3.11.
    if hw2 & 0x8000 != 0 {
        return None;
    }

    let op = (hw1 >> 5) & 0xF;
    let s = hw1 & 0x10 != 0;
    let rn = Reg((hw1 & 0xF) as u8);
    let rd = Reg(((hw2 >> 8) & 0xF) as u8);
    let rm = Reg((hw2 & 0xF) as u8);
    let ty = (hw2 >> 4) & 0b11;
    let imm5 = ((hw2 >> 12) & 0b111) << 2 | (hw2 >> 6) & 0b11;

    // Which *shape* of row these halfwords name. [`Form`] is the right key
    // because it already carries the fields being matched on — `type` for the
    // Table A5-23 rows, `tb` for the pack — so the alias arms below pick a
    // row by the bits that select it rather than by a mnemonic spelt out as a
    // string literal. Spelling the name would mean a table lookup that cannot
    // fail (`"mvn"` is in [`TABLE`] a few lines up), and a `?` that cannot
    // fail states a case that cannot arise.
    let want = match op {
        // `op == 0010, Rn == 1111` — Table A5-23, where `type` and the shift
        // amount together name the instruction. `MOV` (`type == 00`) and
        // `RRX` (`type == 11`) are the two with no amount to print, and they
        // are exactly the rows with a zero `imm3:imm2`; the other four are
        // `LSL`, `LSR`, `ASR` and `ROR` by `type`.
        0b0010 if rn.num() == 15 => {
            if imm5 == 0 && (ty == 0b00 || ty == 0b11) {
                Form::Move { ty }
            } else {
                Form::ShiftImm { ty }
            }
        }
        // `op == 0011, Rn == 1111` — `ORN` with no first operand is `MVN`.
        0b0011 if rn.num() == 15 => Form::Mvn,
        // `op == 0110` — `PKHBT`/`PKHTB`, where `type` is `tb:T` and
        // `if S == '1' || T == '1' then UNDEFINED` (A7.7.93).
        0b0110 => {
            if s || ty & 1 == 1 {
                return None;
            }
            Form::Pack { tb: ty >> 1 }
        }
        // The test alias, where `Rd == 1111` and this `op` has one. Table
        // A5-22: `Rd == 1111` with `S == 0` is UNPREDICTABLE and names no
        // instruction.
        _ if rd.num() == 15 && has_test_alias(op) => {
            if !s {
                return None;
            }
            Form::Test
        }
        // Everything else is the ordinary three-operand row — if this `op`
        // has one. Most do not: 113 of the 128 `(op, form)` pairs are holes,
        // which is why this lookup is fallible and the ones above are not.
        _ => Form::Three,
    };
    let row = TABLE.iter().find(|r| r.op == op && r.form == want)?;

    let mut operands = Operands::new();
    match row.form {
        Form::Three | Form::Pack { .. } => {
            operands.push(Operand::Reg(rd));
            operands.push(Operand::Reg(rn));
            operands.push(shifted(rm, ty, imm5));
        }
        Form::Test => {
            operands.push(Operand::Reg(rn));
            operands.push(shifted(rm, ty, imm5));
        }
        Form::Mvn => {
            operands.push(Operand::Reg(rd));
            operands.push(shifted(rm, ty, imm5));
        }
        Form::Move { .. } => {
            operands.push(Operand::Reg(rd));
            operands.push(Operand::Reg(rm));
        }
        Form::ShiftImm { ty } => {
            operands.push(Operand::Reg(rd));
            operands.push(Operand::Reg(rm));
            operands.push(Operand::Imm(i64::from(imm_shift(ty, imm5).1)));
        }
    }

    Some(Insn {
        mnemonic: row.mnemonic,
        encoding: row.encoding,
        addr,
        width: Width::Wide,
        // Nothing in this group encodes a condition. `super::Decoder` fills one
        // in from an enclosing `IT` block, which does not change these bits —
        // and unlike the 16-bit forms, `S` here is explicit and unaffected by
        // being inside the block.
        cond: None,
        sets_flags: match row.form {
            Form::Test | Form::Pack { .. } => false,
            _ => s,
        },
        explicit_width: row.wide_suffix,
        operands,
    })
}

/// Re-encode an instruction this module decoded, back to its two halfwords.
///
/// Strict by design: `super::encode` tries the 32-bit groups in turn, so a
/// module that accepts an instruction belonging to a sibling silently steals
/// it. Several mnemonics here name encodings elsewhere in the wide space —
/// `add`/`T3` is also `ADD (immediate)` T3, `mov`/`T3` is also `MOVW`,
/// `lsl`/`T2` is also `LSL (register)` T2 — and they are told apart by
/// operand shape, which is why every arm below checks the operand count and
/// every operand's kind before committing.
///
/// [`Insn::cond`] is ignored rather than rejected: the halfwords have no
/// condition field.
pub(crate) fn encode(insn: &Insn) -> Option<(u16, u16)> {
    if insn.width != Width::Wide {
        return None;
    }
    let row = TABLE
        .iter()
        .find(|r| r.mnemonic == insn.mnemonic && r.encoding == insn.encoding)?;
    // The `.W` is part of the instruction's identity: `and r0, r1, r2` without
    // one is the narrow T1 encoding, not these four bytes.
    if insn.explicit_width != row.wide_suffix {
        return None;
    }

    let reg = |i: usize| match insn.operands.get(i) {
        Some(Operand::Reg(r)) => Some(u16::from(r.num())),
        _ => None,
    };
    let s = match row.form {
        // `TST`/`TEQ`/`CMN`/`CMP` are the `S == 1` half of their `op`, and
        // print no `S` suffix; a `sets_flags` here would render `tsts`.
        Form::Test => {
            if insn.sets_flags {
                return None;
            }
            1
        }
        // `PKHBT`/`PKHTB`: `if S == '1' … then UNDEFINED`.
        Form::Pack { .. } => {
            if insn.sets_flags {
                return None;
            }
            0
        }
        _ => u16::from(insn.sets_flags),
    };

    // Too many operands, checked once for every form; too few is caught by
    // the `?`s below, which is the only place it can be caught without
    // stating a case that cannot happen. See [`Form::arity`].
    if insn.operands.len() > row.form.arity() {
        return None;
    }

    let (rn, rd, rm, ty, imm5) = match row.form {
        Form::Three => {
            let rd = reg(0)?;
            let rn = reg(1)?;
            // These two encodings are not this instruction's to give: they are
            // the test and move aliases, and `decode` would not return them
            // here.
            if (has_test_alias(row.op) && rd == 15) || (has_rn_alias(row.op) && rn == 15) {
                return None;
            }
            let (rm, ty, imm5) = unshift(insn.operands.get(2)?)?;
            (rn, rd, rm, ty, imm5)
        }
        Form::Test => {
            let (rm, ty, imm5) = unshift(insn.operands.get(1)?)?;
            (reg(0)?, 15, rm, ty, imm5)
        }
        Form::Mvn => {
            let (rm, ty, imm5) = unshift(insn.operands.get(1)?)?;
            (15, reg(0)?, rm, ty, imm5)
        }
        Form::Pack { tb } => {
            let rd = reg(0)?;
            let rn = reg(1)?;
            let (rm, ty, imm5) = unshift(insn.operands.get(2)?)?;
            // `type` is `tb:T` with `T` always zero, so the shift kind is not
            // free: `PKHBT` takes `LSL` (or none) and `PKHTB` takes `ASR`.
            // A shiftless `PKHTB` is the pseudo-instruction Arm assembles as
            // `PKHBT <Rd>,<Rm>,<Rn>`, and is not this encoding.
            if ty != tb << 1 {
                return None;
            }
            (rn, rd, rm, ty, imm5)
        }
        Form::Move { ty } => (15, reg(0)?, reg(1)?, ty, 0),
        Form::ShiftImm { ty } => {
            let amount = match insn.operands.get(2)? {
                Operand::Imm(v) => v,
                _ => return None,
            };
            (15, reg(0)?, reg(1)?, ty, shift_amount_bits(ty, amount)?)
        }
    };

    Some((
        GROUP | row.op << 5 | s << 4 | rn,
        (imm5 >> 2) << 12 | rd << 8 | (imm5 & 0b11) << 6 | ty << 4 | rm,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::decode_halfwords;

    /// The two halfwords with these fields, `imm3:imm2` given whole.
    fn hw(op: u16, s: u16, rn: u16, rd: u16, ty: u16, imm5: u16, rm: u16) -> (u16, u16) {
        (
            GROUP | op << 5 | s << 4 | rn,
            (imm5 >> 2) << 12 | rd << 8 | (imm5 & 0b11) << 6 | ty << 4 | rm,
        )
    }

    /// The instruction those fields decode to, at address 0.
    fn dec(op: u16, s: u16, rn: u16, rd: u16, ty: u16, imm5: u16, rm: u16) -> Insn {
        let (a, b) = hw(op, s, rn, rd, ty, imm5, rm);
        let decoded = decode(a, b, 0);
        // `assert!` rather than `unwrap_or_else(|| panic!(…))`: the closure in
        // the latter is a function that never runs, and this crate's coverage
        // gate is 100% of functions.
        assert!(decoded.is_some(), "{a:#06x} {b:#06x} should decode");
        decoded.unwrap()
    }

    /// The printed UAL form of those fields, decoded at address 0.
    fn ual(op: u16, s: u16, rn: u16, rd: u16, ty: u16, imm5: u16, rm: u16) -> String {
        dec(op, s, rn, rd, ty, imm5, rm).to_string()
    }

    /// The whole group swept systematically: every `op`, `S`, `Rn` (including
    /// `1111`), `Rd` (including `1111`), `type` and all 32 values of
    /// `imm3:imm2`, with `Rm` fixed (it is a plain field with no aliasing).
    /// Anything that decodes must re-encode to the halfwords it came from, and
    /// the per-`op` totals must account for every combination that does not.
    /// Every operand slot of every [`Form`] in the group, mangled one at a
    /// time, plus every operand count either side of the right one.
    ///
    /// [`Insn`] is a public struct with public fields, so `encode` is
    /// reachable with any operand list a consumer cares to build, and this
    /// group is where reading the wrong slot does the most damage: the six
    /// forms put `Rd`, `Rn` and `Rm` at three different operand indices over
    /// the same three halfword fields, and `mvn r0, r2` and `orn r0, r1, r2`
    /// differ only in whether `Rn` is an operand at all. The failure that
    /// matters is not a panic but a `Some`.
    #[test]
    fn encode_rejects_every_mangled_operand_slot() {
        for (hw1, hw2) in [
            hw(0b0000, 0, 1, 0, 0b00, 0, 2),  // and.w  r0, r1, r2   Three
            hw(0b0000, 1, 1, 15, 0b00, 0, 2), // tst.w  r1, r2       Test
            hw(0b0011, 0, 15, 0, 0b00, 0, 2), // mvn.w  r0, r2       Mvn
            hw(0b0110, 0, 1, 0, 0b00, 0, 2),  // pkhbt  r0, r1, r2   Pack
            hw(0b0110, 0, 1, 0, 0b10, 4, 2),  // pkhtb  r0, r1, r2, asr #4
            hw(0b0010, 0, 15, 0, 0b00, 0, 2), // mov.w  r0, r2       Move
            hw(0b0010, 0, 15, 0, 0b11, 0, 2), // rrx    r0, r2
            hw(0b0010, 0, 15, 0, 0b00, 3, 2), // lsl.w  r0, r2, #3   ShiftImm
            hw(0b0010, 0, 15, 0, 0b01, 3, 2), // lsr.w  r0, r2, #3
            hw(0b0010, 0, 15, 0, 0b10, 3, 2), // asr.w  r0, r2, #3
            hw(0b0010, 0, 15, 0, 0b11, 3, 2), // ror.w  r0, r2, #3
        ] {
            let insn = decode(hw1, hw2, 0).unwrap();
            assert_eq!(
                encode(&insn),
                Some((hw1, hw2)),
                "`{insn}` should round-trip before anything is mangled"
            );
            let arity = insn.operands.len();

            // One slot at a time, replaced by an operand of a kind that slot
            // cannot hold: an immediate where a register or a shifted
            // register belongs, a register where a shift amount belongs.
            for slot in 0..arity {
                let mut mangled = insn;
                mangled.operands = (0..arity)
                    .map(|i| {
                        let op = insn.operands.get(i).unwrap();
                        if i != slot {
                            op
                        } else {
                            match op {
                                Operand::Imm(_) => Operand::Reg(Reg(0)),
                                _ => Operand::Imm(0),
                            }
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
                .map(|i| insn.operands.get(i).unwrap_or(Operand::Imm(0)))
                .collect();
            assert_eq!(encode(&long), None, "`{insn}` with {more} operands");
            let mut empty = insn;
            empty.operands = Operands::new();
            assert_eq!(encode(&empty), None, "`{insn}` with no operands");
        }
    }

    /// The shift on a second operand is checked against what [`shifted`] can
    /// produce, kind by kind, because an amount outside the field's range or
    /// a shift `decode` would have omitted re-encodes to halfwords that mean
    /// a different instruction.
    ///
    /// The ranges are Arm's, not this crate's: `LSR` and `ASR` encode a shift
    /// of 32 as `imm5 == 0` and so take 1–32, while `LSL` and `ROR` take 1–31
    /// and spend `imm5 == 0` on `MOV` and `RRX` respectively (A5.3.11,
    /// `DecodeImmShift`).
    #[test]
    fn encode_rejects_shifts_no_encoding_can_hold() {
        let and = dec(0b0000, 0, 1, 0, 0b00, 0, 2);
        let shifted_and = |kind, n| {
            let mut insn = and;
            insn.operands = [
                Operand::Reg(Reg(0)),
                Operand::Reg(Reg(1)),
                Operand::RegShifted(
                    Reg(2),
                    Shift {
                        kind,
                        amount: ShiftAmount::Imm(n),
                    },
                ),
            ]
            .iter()
            .copied()
            .collect();
            encode(&insn)
        };

        // `LSR #0` and `ASR #0` are not spellings of anything: `imm5 == 0` in
        // those two `type`s means 32, so a zero amount has no encoding and a
        // 33 runs off the end of the field.
        for kind in [ShiftKind::Lsr, ShiftKind::Asr] {
            assert_eq!(shifted_and(kind, 0), None, "{kind} #0");
            assert_eq!(shifted_and(kind, 33), None, "{kind} #33");
            // 32 is the one they take and `LSL`/`ROR` do not.
            assert!(shifted_and(kind, 32).is_some(), "{kind} #32");
        }
        // `LSL #0` is a bare register and `ROR #0` is `RRX`; 32 is past the
        // end of both.
        for kind in [ShiftKind::Lsl, ShiftKind::Ror] {
            assert_eq!(shifted_and(kind, 0), None, "{kind} #0");
            assert_eq!(shifted_and(kind, 32), None, "{kind} #32");
            assert!(shifted_and(kind, 31).is_some(), "{kind} #31");
        }
        // `RRX` carries an amount of 1 that is never printed; any other value
        // is an `Insn` `decode` could not have built.
        assert!(shifted_and(ShiftKind::Rrx, 1).is_some(), "rrx");
        for n in [0u8, 2, 32] {
            assert_eq!(shifted_and(ShiftKind::Rrx, n), None, "rrx with amount {n}");
        }
        // A register-controlled shift is A5.3.11's neighbour, not this group:
        // `and.w r0, r1, r2, lsl r3` has no encoding here at all.
        let mut by_register = and;
        by_register.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::RegShifted(
                Reg(2),
                Shift {
                    kind: ShiftKind::Lsl,
                    amount: ShiftAmount::Reg(Reg(3)),
                },
            ),
        ]
        .iter()
        .copied()
        .collect();
        assert_eq!(encode(&by_register), None);
    }

    #[test]
    fn systematic_round_trip() {
        let mut per_op = [0u32; 16];
        let mut total = 0u32;
        for op in 0..16u16 {
            for s in 0..2u16 {
                for rn in 0..16u16 {
                    for rd in 0..16u16 {
                        for ty in 0..4u16 {
                            for imm5 in 0..32u16 {
                                total += 1;
                                let (a, b) = hw(op, s, rn, rd, ty, imm5, 2);
                                let insn = match decode(a, b, 0) {
                                    Some(i) => i,
                                    None => continue,
                                };
                                per_op[op as usize] += 1;
                                assert_eq!(insn.width, Width::Wide, "{a:#06x} {b:#06x}");
                                assert_eq!(insn.len(), 4, "{a:#06x} {b:#06x}");
                                assert!(insn.cond.is_none(), "{a:#06x} {b:#06x}");
                                assert_eq!(
                                    encode(&insn),
                                    Some((a, b)),
                                    "{a:#06x} {b:#06x} decoded as `{insn}` but did not re-encode"
                                );
                            }
                        }
                    }
                }
            }
        }

        // 16 ops x 2 S x 16 Rn x 16 Rd x 4 type x 32 imm3:imm2.
        assert_eq!(total, 1_048_576);
        // Per `op`, out of 65536 combinations each:
        //   * 0000/0100/1000/1101 lose 2048 to `Rd == 1111, S == 0`, which
        //     Table A5-22 calls UNPREDICTABLE.
        //   * 0110 (`PKHBT`/`PKHTB`) keeps only `S == 0` and `T == 0`: a
        //     quarter of the space, 16384.
        //   * 0101/0111/1001/1100/1111 are UNDEFINED: nothing at all.
        //   * the other six are fully allocated, aliases included.
        assert_eq!(
            per_op,
            [
                63488, 65536, 65536, 65536, 63488, 0, 16384, 0, 63488, 0, 65536, 65536, 0, 63488,
                65536, 0
            ]
        );
        let decoded: u32 = per_op.iter().sum();
        assert_eq!(decoded, 663_552);
        // And the remainder, accounted for exactly: five UNDEFINED opcodes,
        // four UNPREDICTABLE `Rd == 1111, S == 0` blocks, and the three
        // quarters of `op == 0110` that `S`/`T` make UNDEFINED.
        assert_eq!(total - decoded, 5 * 65536 + 4 * 2048 + 3 * 16384);
        assert_eq!(total - decoded, 385_024);
    }

    /// The dispatcher must route this group here, and `decode` must stop at
    /// the group's edges.
    #[test]
    fn dispatch_boundary() {
        for op in 0..16u16 {
            for s in 0..2u16 {
                let (a, b) = hw(op, s, 1, 0, 0b01, 3, 2);
                assert_eq!(
                    decode_halfwords(a, b, 0, false),
                    decode(a, b, 0),
                    "{a:#06x} {b:#06x} is not reaching t32_dp_shiftreg"
                );
            }
        }
        // `hw1[15:9] == 1110100` is A5.3.5/A5.3.6 (load/store multiple, dual,
        // exclusive) and `1110110` is the coprocessor space.
        assert!(decode(0xE800, 0, 0).is_none());
        assert!(decode(0xEC00, 0, 0).is_none());
        assert!(decode(0xF000, 0, 0).is_none());
    }

    /// The same round-trip through the crate's public pair, which tries the
    /// wide groups in order. Several of this module's `(mnemonic, encoding)`
    /// pairs are shared with siblings — `add`/`T3` with `ADD (immediate)`,
    /// `mov`/`T3` with `MOVW`, `lsl`/`T2` with `LSL (register)` — so passing
    /// here and not in [`systematic_round_trip`] would mean a neighbour is
    /// claiming these bytes.
    #[test]
    fn round_trips_through_the_group_dispatcher() {
        let mut checked = 0u32;
        for op in 0..16u16 {
            for s in 0..2u16 {
                for rn in [0u16, 1, 13, 15] {
                    for rd in [0u16, 3, 13, 15] {
                        for ty in 0..4u16 {
                            for imm5 in [0u16, 1, 2, 30, 31] {
                                let (a, b) = hw(op, s, rn, rd, ty, imm5, 2);
                                let insn = match decode_halfwords(a, b, 0, false) {
                                    Some(i) => i,
                                    None => continue,
                                };
                                checked += 1;
                                assert_eq!(
                                    crate::isa::encode(&insn),
                                    Some((a, b)),
                                    "{a:#06x} {b:#06x} decoded as `{insn}` but the dispatcher \
                                     re-encoded it elsewhere"
                                );
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 6240);
    }

    /// Table A5-23, all 128 of it: four `type` values by 32 shift amounts, at
    /// `op == 0010, Rn == 1111`. This is the test that pins the `MOV`/`LSL`
    /// and `RRX`/`ROR` boundaries — the only two places in the architecture
    /// where the same five bits mean "no shift, so this is a move" in one row
    /// and "a shift amount" in the next.
    #[test]
    fn table_a5_23_exhaustively() {
        let mut cases = 0u32;
        for ty in 0..4u16 {
            for imm5 in 0..32u16 {
                let expected = match (ty, imm5) {
                    (0b00, 0) => "mov",
                    (0b00, _) => "lsl",
                    (0b01, _) => "lsr",
                    (0b10, _) => "asr",
                    (0b11, 0) => "rrx",
                    _ => "ror",
                };
                let (a, b) = hw(0b0010, 0, 15, 0, ty, imm5, 2);
                let insn = decode(a, b, 0).expect("Table A5-23 leaves no hole");
                assert_eq!(
                    insn.mnemonic, expected,
                    "type {ty:02b}, imm3:imm2 {imm5:05b}"
                );
                // The two move-shaped rows take no amount operand; the four
                // shift rows take exactly one.
                assert_eq!(
                    insn.operands.len(),
                    if matches!(expected, "mov" | "rrx") {
                        2
                    } else {
                        3
                    },
                    "type {ty:02b}, imm3:imm2 {imm5:05b}"
                );
                assert_eq!(encode(&insn), Some((a, b)), "round-trip of `{insn}`");
                cases += 1;
            }
        }
        assert_eq!(cases, 128);

        // The encoding names the rows carry, from each instruction's page.
        let name = |ty, imm5| dec(0b0010, 0, 15, 0, ty, imm5, 2).encoding;
        assert_eq!(name(0b00, 0), "T3"); // MOV (register) T3
        assert_eq!(name(0b00, 1), "T2"); // LSL (immediate) T2
        assert_eq!(name(0b01, 1), "T2"); // LSR (immediate) T2
        assert_eq!(name(0b10, 1), "T2"); // ASR (immediate) T2
        assert_eq!(name(0b11, 0), "T1"); // RRX T1
                                         // T1, not T2: the three shifts above are T2 here because each spends
                                         // a T1 on its 16-bit form, and `ROR` has no 16-bit immediate form to
                                         // spend one on. A7.7.116 lists this as its only encoding.
        assert_eq!(name(0b11, 1), "T1"); // ROR (immediate) T1
    }

    /// `DecodeImmShift` (A7.4.2): a zero amount field means 32 for `LSR` and
    /// `ASR`, and the `LSL` zero slot is spent on `MOV` instead.
    #[test]
    fn decode_imm_shift_reads_zero_as_thirty_two() {
        // `LSR{S}<c>.W <Rd>,<Rm>,#<imm5>`, A7.7.70: "<imm5> … in the range
        // 1-32".
        assert_eq!(ual(0b0010, 0, 15, 0, 0b01, 0, 2), "lsr.w r0, r2, #0x20");
        assert_eq!(ual(0b0010, 0, 15, 0, 0b10, 0, 2), "asr.w r0, r2, #0x20");
        let lsr = dec(0b0010, 0, 15, 0, 0b01, 0, 2);
        assert_eq!(lsr.operands.get(2), Some(Operand::Imm(32)));
        // `LSL` is the one type whose zero is legitimately zero — and that
        // encoding is `MOV (register)` T3, not `lsl #0`.
        assert_eq!(ual(0b0010, 0, 15, 0, 0b00, 0, 2), "mov.w r0, r2");
        assert_eq!(ual(0b0010, 0, 15, 0, 0b00, 1, 2), "lsl.w r0, r2, #1");
        // And the same rule inside a shifted-register operand.
        assert_eq!(
            ual(0b0000, 0, 1, 0, 0b01, 0, 2),
            "and.w r0, r1, r2, lsr #32"
        );
        assert_eq!(
            ual(0b0000, 0, 1, 0, 0b10, 0, 2),
            "and.w r0, r1, r2, asr #32"
        );
        // `type == 11` with a zero amount is `RRX`, which prints no amount.
        assert_eq!(ual(0b0000, 0, 1, 0, 0b11, 0, 2), "and.w r0, r1, r2, rrx");
        assert_eq!(ual(0b0010, 0, 15, 0, 0b11, 0, 2), "rrx r0, r2");
    }

    /// A zero shift is omitted from the printed form, and only from the
    /// printed form: the bits still say `type = 00, imm5 = 0`.
    #[test]
    fn a_zero_shift_is_omitted_and_round_trips() {
        let (a, b) = hw(0b0000, 0, 1, 0, 0b00, 0, 2);
        let insn = decode(a, b, 0).unwrap();
        assert_eq!(insn.to_string(), "and.w r0, r1, r2");
        assert_eq!(
            insn.operands.get(2),
            Some(Operand::Reg(Reg(2))),
            "a zero shift is a plain register operand, not a `lsl #0`"
        );
        assert_eq!(encode(&insn), Some((a, b)));

        let (a, b) = hw(0b0000, 0, 1, 0, 0b00, 3, 2);
        let insn = decode(a, b, 0).unwrap();
        assert_eq!(insn.to_string(), "and.w r0, r1, r2, lsl #3");
        assert_eq!(
            insn.operands.get(2),
            Some(Operand::RegShifted(
                Reg(2),
                Shift {
                    kind: ShiftKind::Lsl,
                    amount: ShiftAmount::Imm(3),
                }
            ))
        );
        assert_eq!(encode(&insn), Some((a, b)));

        // The inverse of the omission: an explicit `lsl #0` is not a form this
        // decoder produces, so re-encoding one would not round-trip and is
        // refused instead.
        let mut explicit_zero = insn;
        explicit_zero.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::RegShifted(
                Reg(2),
                Shift {
                    kind: ShiftKind::Lsl,
                    amount: ShiftAmount::Imm(0),
                },
            ),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&explicit_zero), None);
        // As is a `ror #0`, which is `RRX`'s encoding.
        let mut ror_zero = insn;
        ror_zero.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
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
        assert_eq!(encode(&ror_zero), None);
    }

    /// One printed form per row of Table A5-22, spelled as the `Assembler
    /// syntax` section of each instruction's page spells it. `Rn` is `r1`,
    /// `Rd` is `r0`, `Rm` is `r2`.
    #[test]
    fn table_a5_22_prints_ual() {
        // 0000 `AND{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}` — A7.7.9.
        assert_eq!(ual(0b0000, 0, 1, 0, 0, 0, 2), "and.w r0, r1, r2");
        assert_eq!(ual(0b0000, 1, 1, 0, 0, 0, 2), "ands.w r0, r1, r2");
        // 0000, Rd == 1111, S == 1: `TST<c>.W <Rn>,<Rm>{,<shift>}` — A7.7.189.
        assert_eq!(ual(0b0000, 1, 1, 15, 0, 0, 2), "tst.w r1, r2");
        // 0001 `BIC{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}` — A7.7.16.
        assert_eq!(ual(0b0001, 1, 1, 0, 0, 0, 2), "bics.w r0, r1, r2");
        // 0010, Rn != 1111: `ORR{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}` — A7.7.92.
        assert_eq!(ual(0b0010, 0, 1, 0, 0, 0, 2), "orr.w r0, r1, r2");
        // 0010, Rn == 1111: Table A5-23, exercised in full above.
        assert_eq!(ual(0b0010, 0, 15, 0, 0, 0, 2), "mov.w r0, r2");
        // 0011, Rn != 1111: `ORN{S}<c> <Rd>,<Rn>,<Rm>{,<shift>}` — A7.7.90,
        // whose syntax line has no `.W` because it has no narrow encoding.
        assert_eq!(ual(0b0011, 0, 1, 0, 0, 0, 2), "orn r0, r1, r2");
        // 0011, Rn == 1111: `MVN{S}<c>.W <Rd>,<Rm>{,<shift>}` — A7.7.86.
        assert_eq!(ual(0b0011, 0, 15, 0, 0, 0, 2), "mvn.w r0, r2");
        // 0100 `EOR{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}` — A7.7.36.
        assert_eq!(ual(0b0100, 0, 1, 0, 0, 0, 2), "eor.w r0, r1, r2");
        // 0100, Rd == 1111, S == 1: `TEQ<c> <Rn>,<Rm>{,<shift>}` — A7.7.187.
        assert_eq!(ual(0b0100, 1, 1, 15, 0, 0, 2), "teq r1, r2");
        // 0110 `PKHBT<c> <Rd>,<Rn>,<Rm>{,LSL #<imm>}` — A7.7.93.
        assert_eq!(ual(0b0110, 0, 1, 0, 0b00, 0, 2), "pkhbt r0, r1, r2");
        assert_eq!(ual(0b0110, 0, 1, 0, 0b00, 4, 2), "pkhbt r0, r1, r2, lsl #4");
        // 0110 `PKHTB<c> <Rd>,<Rn>,<Rm>{,ASR #<imm>}`.
        assert_eq!(ual(0b0110, 0, 1, 0, 0b10, 3, 2), "pkhtb r0, r1, r2, asr #3");
        // 1000 `ADD{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}` — A7.7.4.
        assert_eq!(ual(0b1000, 0, 1, 0, 0, 0, 2), "add.w r0, r1, r2");
        // 1000, Rd == 1111, S == 1: `CMN<c>.W <Rn>,<Rm>{,<shift>}` — A7.7.26.
        assert_eq!(ual(0b1000, 1, 1, 15, 0, 0, 2), "cmn.w r1, r2");
        // 1010 `ADC{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}` — A7.7.2.
        assert_eq!(ual(0b1010, 0, 1, 0, 0, 0, 2), "adc.w r0, r1, r2");
        // 1011 `SBC{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}` — A7.7.125.
        assert_eq!(ual(0b1011, 0, 1, 0, 0, 0, 2), "sbc.w r0, r1, r2");
        // 1101 `SUB{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}` — A7.7.175.
        assert_eq!(ual(0b1101, 0, 1, 0, 0, 0, 2), "sub.w r0, r1, r2");
        // 1101, Rd == 1111, S == 1: `CMP<c>.W <Rn>,<Rm>{,<shift>}` — A7.7.28.
        assert_eq!(ual(0b1101, 1, 1, 15, 0, 0, 2), "cmp.w r1, r2");
        // 1110 `RSB{S}<c> <Rd>,<Rn>,<Rm>{,<shift>}` — A7.7.120, again with no
        // `.W`: the narrow `rsbs rd, rn, #0` is a different operand shape.
        assert_eq!(ual(0b1110, 0, 1, 0, 0, 0, 2), "rsb r0, r1, r2");
        assert_eq!(ual(0b1110, 1, 1, 0, 0, 0, 2), "rsbs r0, r1, r2");
        // And Table A5-23's four shift rows, `LSL{S}<c>.W <Rd>,<Rm>,#<imm5>`
        // and friends — `ROR (immediate)` T1 carries no `.W` (A7.7.116).
        assert_eq!(ual(0b0010, 1, 15, 0, 0b00, 5, 2), "lsls.w r0, r2, #5");
        assert_eq!(ual(0b0010, 0, 15, 0, 0b01, 5, 2), "lsr.w r0, r2, #5");
        assert_eq!(ual(0b0010, 0, 15, 0, 0b10, 5, 2), "asr.w r0, r2, #5");
        assert_eq!(ual(0b0010, 0, 15, 0, 0b11, 5, 2), "ror r0, r2, #5");
        assert_eq!(ual(0b0010, 1, 15, 0, 0b11, 0, 2), "rrxs r0, r2");
    }

    /// The flag-setting tests take no `S` suffix, and `PKHBT`/`PKHTB` take
    /// none either.
    #[test]
    fn test_forms_print_no_s_suffix() {
        for (op, mnemonic) in [
            (0b0000u16, "tst"),
            (0b0100, "teq"),
            (0b1000, "cmn"),
            (0b1101, "cmp"),
        ] {
            let (a, b) = hw(op, 1, 1, 15, 0, 0, 2);
            let insn = decode(a, b, 0).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            assert!(
                !insn.sets_flags,
                "{mnemonic} writes flags but prints no `s`"
            );
            let printed = insn.to_string();
            assert!(
                printed.starts_with(mnemonic) && !printed.starts_with(&format!("{mnemonic}s")),
                "`{printed}` should not carry an `s` suffix"
            );
            assert_eq!(encode(&insn), Some((a, b)));
        }
        for ty in [0b00u16, 0b10] {
            assert!(!dec(0b0110, 0, 1, 0, ty, 3, 2).sets_flags);
        }
    }

    /// `Rd == 1111` with `S == 0` is UNPREDICTABLE in Table A5-22 and names no
    /// instruction, so it decodes to nothing — and `encode` will not produce
    /// it from the corresponding three-operand instruction either.
    #[test]
    fn rd_1111_without_s_is_unpredictable() {
        for op in [0b0000u16, 0b0100, 0b1000, 0b1101] {
            for ty in 0..4u16 {
                for imm5 in 0..32u16 {
                    let (a, b) = hw(op, 0, 1, 15, ty, imm5, 2);
                    assert!(
                        decode(a, b, 0).is_none(),
                        "{a:#06x} {b:#06x} is UNPREDICTABLE, not an instruction"
                    );
                }
            }
        }
        // `and.w pc, r1, r2` is that same encoding written out, and is refused
        // rather than encoded into an UNPREDICTABLE pattern.
        let mut and_pc = dec(0b0000, 0, 1, 0, 0, 0, 2);
        and_pc.operands = [
            Operand::Reg(Reg::PC),
            Operand::Reg(Reg(1)),
            Operand::Reg(Reg(2)),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&and_pc), None);
        // The ops with no test alias keep their `Rd == 1111` encodings.
        for op in [0b0001u16, 0b0011, 0b1010, 0b1011, 0b1110] {
            let (a, b) = hw(op, 0, 1, 15, 0, 0, 2);
            let insn = decode(a, b, 0).expect("no test alias here");
            assert_eq!(encode(&insn), Some((a, b)));
        }
    }

    /// The `(0)` bit at `hw2[15]`: non-zero is UNPREDICTABLE (D6.1) and not
    /// representable, so it is refused rather than silently dropped.
    #[test]
    fn the_should_be_zero_bit_is_enforced() {
        let (a, b) = hw(0b0000, 0, 1, 0, 0, 0, 2);
        assert!(decode(a, b, 0).is_some());
        assert!(decode(a, b | 0x8000, 0).is_none());
    }

    /// `PKHBT`/`PKHTB`: `S == 1` or `T == 1` is UNDEFINED, `tb` chooses the
    /// mnemonic, and `PKHTB`'s zero amount field is 32 rather than "omitted".
    #[test]
    fn pkh_reads_type_as_tb_and_t() {
        // `if S == '1' || T == '1' then UNDEFINED` — A7.7.93.
        for s in 0..2u16 {
            for ty in 0..4u16 {
                let (a, b) = hw(0b0110, s, 1, 0, ty, 3, 2);
                let defined = s == 0 && ty & 1 == 0;
                assert_eq!(decode(a, b, 0).is_some(), defined, "S={s} type={ty:02b}");
            }
        }
        // `tb == 0` is `PKHBT` with `LSL`; `tb == 1` is `PKHTB` with `ASR`.
        assert_eq!(ual(0b0110, 0, 1, 0, 0b00, 1, 2), "pkhbt r0, r1, r2, lsl #1");
        assert_eq!(ual(0b0110, 0, 1, 0, 0b10, 1, 2), "pkhtb r0, r1, r2, asr #1");
        // A zero field omits the shift for `PKHBT` (no shift) and means 32 for
        // `PKHTB`, which Arm spells out and forbids writing as `asr #0`.
        assert_eq!(ual(0b0110, 0, 1, 0, 0b00, 0, 2), "pkhbt r0, r1, r2");
        assert_eq!(
            ual(0b0110, 0, 1, 0, 0b10, 0, 2),
            "pkhtb r0, r1, r2, asr #32"
        );
        // A shiftless `PKHTB` is the pseudo-instruction, not this encoding.
        let mut bare_tb = dec(0b0110, 0, 1, 0, 0b10, 1, 2);
        bare_tb.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Reg(Reg(2)),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&bare_tb), None);
    }

    /// The `Rn == 1111` aliases belong to the sub-table and to `MVN`, so
    /// `ORR`/`ORN` may not re-encode into them.
    #[test]
    fn rn_1111_belongs_to_the_aliases() {
        for (op, mnemonic) in [(0b0010u16, "orr"), (0b0011, "orn")] {
            let (a, b) = hw(op, 0, 1, 0, 0, 0, 2);
            let mut insn = decode(a, b, 0).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            insn.operands = [
                Operand::Reg(Reg(0)),
                Operand::Reg(Reg::PC),
                Operand::Reg(Reg(2)),
            ]
            .into_iter()
            .collect();
            assert_eq!(encode(&insn), None, "{mnemonic} rn == pc is an alias");
        }
    }

    /// `encode` must refuse everything that is not this group's, because
    /// `super::encode` tries the groups in turn and a greedy one steals its
    /// siblings' instructions.
    #[test]
    fn encode_rejects_what_this_group_cannot_hold() {
        let base = dec(0b0000, 0, 1, 0, 0, 0, 2); // and.w r0, r1, r2

        // A mnemonic that is not in the table at all.
        let mut foreign = base;
        foreign.mnemonic = "ldr";
        assert_eq!(encode(&foreign), None);

        // The narrow encoding of the same operation.
        let mut narrow = base;
        narrow.width = Width::Narrow;
        assert_eq!(encode(&narrow), None);

        // The wrong encoding name, and the missing `.W`.
        let mut t1 = base;
        t1.encoding = "T1";
        assert_eq!(encode(&t1), None);
        let mut unsuffixed = base;
        unsuffixed.explicit_width = false;
        assert_eq!(encode(&unsuffixed), None);
        // …and conversely, the rows that carry no `.W` must not gain one.
        let mut rsb = dec(0b1110, 0, 1, 0, 0, 0, 2);
        rsb.explicit_width = true;
        assert_eq!(encode(&rsb), None);

        // Wrong operand counts and kinds. `add.w r0, r1, #4` is
        // `ADD (immediate)` T3, another group's encoding with this group's
        // mnemonic and encoding name.
        let mut too_few = base;
        too_few.operands = [Operand::Reg(Reg(0)), Operand::Reg(Reg(1))]
            .into_iter()
            .collect();
        assert_eq!(encode(&too_few), None);
        let mut immediate = dec(0b1000, 0, 1, 0, 0, 0, 2);
        assert_eq!(immediate.mnemonic, "add");
        assert_eq!(immediate.encoding, "T3");
        immediate.operands = [Operand::Reg(Reg(0)), Operand::Reg(Reg(1)), Operand::Imm(4)]
            .into_iter()
            .collect();
        assert_eq!(encode(&immediate), None);
        // `mov.w r0, #4` is `MOVW` (A5.3.3), not `MOV (register)` T3.
        let mut movw = dec(0b0010, 0, 15, 0, 0, 0, 2);
        movw.operands = [Operand::Reg(Reg(0)), Operand::Imm(4)]
            .into_iter()
            .collect();
        assert_eq!(encode(&movw), None);
        // `lsl.w r0, r1, r2` is `LSL (register)` T2 (A5.3.12), which shares
        // this module's mnemonic *and* encoding name and is told apart only by
        // its third operand being a register.
        let mut lsl_reg = dec(0b0010, 0, 15, 0, 0b00, 3, 2);
        assert_eq!((lsl_reg.mnemonic, lsl_reg.encoding), ("lsl", "T2"));
        lsl_reg.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Reg(Reg(2)),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&lsl_reg), None);

        // Shift amounts out of range for their type: `LSL`/`ROR` take 1-31,
        // `LSR`/`ASR` take 1-32.
        let mut lsl32 = dec(0b0010, 0, 15, 0, 0b00, 3, 2);
        lsl32.operands = [Operand::Reg(Reg(0)), Operand::Reg(Reg(2)), Operand::Imm(32)]
            .into_iter()
            .collect();
        assert_eq!(encode(&lsl32), None);
        let mut lsr33 = dec(0b0010, 0, 15, 0, 0b01, 3, 2);
        lsr33.operands = [Operand::Reg(Reg(0)), Operand::Reg(Reg(2)), Operand::Imm(33)]
            .into_iter()
            .collect();
        assert_eq!(encode(&lsr33), None);

        // A register-controlled shift has no encoding in this group.
        let mut by_register = base;
        by_register.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::RegShifted(
                Reg(2),
                Shift {
                    kind: ShiftKind::Lsl,
                    amount: ShiftAmount::Reg(Reg(3)),
                },
            ),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&by_register), None);

        // `tst`/`cmn`/`teq`/`cmp` with `sets_flags` would print `tsts`, and
        // `pkhbt` has no `S` bit to set.
        let mut flagged_tst = dec(0b0000, 1, 1, 15, 0, 0, 2);
        flagged_tst.sets_flags = true;
        assert_eq!(encode(&flagged_tst), None);
        let mut flagged_pkh = dec(0b0110, 0, 1, 0, 0b00, 3, 2);
        flagged_pkh.sets_flags = true;
        assert_eq!(encode(&flagged_pkh), None);
    }
}
