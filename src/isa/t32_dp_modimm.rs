//! 32-bit data processing (modified immediate) — `hw1[15:11] == 0b11110`,
//! `hw1[9] == 0`, `hw2[15] == 0` (ARM DDI 0403E.e A5.3.1, Table A5-10;
//! identically ARM DDI 0406B A6.3.1, Table A6-10).
//!
//! # The field layout, and the `op`-versus-`S` question
//!
//! The two manuals draw the same bits two different ways, and the difference
//! matters because it changes what "`op`" means:
//!
//! * Armv7-M Table A5-10 lists a five-bit `op` whose values are written
//!   `0000x`, `0001x`, … The trailing `x` is not a don't-care in the encoding —
//!   it *is* the `S` bit, folded into `op` because the table has no `S` column.
//! * Armv7-A/R Table A6-10 draws `11110 i 0 op(4) S Rn` and gives `S` its own
//!   column, so its `op` is four bits and its rows are written `0000`, `0001`, …
//!
//! The individual instruction pages settle it: `AND (immediate)` T1 (A7.7.8) is
//! `1 1 1 1 0 i 0 0 0 0 0 S Rn / 0 imm3 Rd imm8`, so the halfwords are
//!
//! ```text
//!   hw1 = 1 1 1 1 0 | i | 0 | op(4) | S | Rn(4)
//!   hw2 =         0 | imm3(3) | Rd(4) | imm8(8)
//! ```
//!
//! — i.e. `op(4)` is `hw1[8:5]`, `S` is `hw1[4]`, and Table A5-10's five-bit
//! `op` is exactly `hw1[8:4]` = `op(4):S`. This module decodes on the four-bit
//! `op` plus a separate `S`, the A/R spelling, because every predicate in the
//! instruction pages (`if Rd == '1111' && S == '1' then SEE TST`) is written in
//! terms of a standalone `S`, and because folding `S` into the opcode would
//! duplicate all sixteen rows. The A5-10 row names are kept in the comments so
//! the table can still be read beside the code.
//!
//! # Aliasing is the character of this group
//!
//! Six of the ten allocated operations have a second identity, selected not by
//! an opcode bit but by a register field holding `1111`:
//!
//! * `Rd == 1111 && S == 1` — the result is discarded and only the flags
//!   matter, so `AND`/`EOR`/`ADD`/`SUB` become `TST`/`TEQ`/`CMN`/`CMP`.
//! * `Rn == 1111` — there is no first operand, so `ORR`/`ORN` (whose identity
//!   element is zero) become `MOV`/`MVN`.
//!
//! Additionally `Rn == 1101` redirects `ADD`/`SUB` to `ADD (SP plus immediate)`
//! T3 (A7.7.5) and `SUB (SP minus immediate)` T2 (A7.7.176) — the same bits,
//! and UAL text identical to the general form (`add{s}.w <Rd>, sp, #<const>`),
//! so the only visible effect here is [`Insn::encoding`], which follows the
//! manual's `SEE` directive and reports `"T2"` for a `SUB` with `Rn == 1101`.
//!
//! What this group does *not* contain: `ADR` and the `ADDW`/`SUBW`/`MOVW` plain
//! binary immediates. Those have `hw1[9] == 1` (A5.3.3, Table A5-12) and belong
//! to `t32_dp_plainimm`. `ADD (immediate)` T3 with `Rn == 1111` is *not* `ADR`;
//! it is UNPREDICTABLE, and is decoded here as an `ADD` from `pc`.
//!
//! # UNDEFINED versus UNPREDICTABLE
//!
//! Six of the sixteen `op(4)` values (`0101`, `0110`, `0111`, `1001`, `1100`,
//! `1111`) are unallocated: "Other encodings in this space are UNDEFINED", so
//! [`decode`] returns `None` for them. UNPREDICTABLE is a different
//! architectural category — the encoding *is* allocated, its behaviour merely is
//! not guaranteed — and `None` here means "no such instruction", so conflating
//! the two would make this decoder claim that, say, `and pc, r0, #1` is not an
//! encoding at all. It is one; it is an `AND (immediate)` T1 that the
//! architecture declines to define the effect of. So:
//!
//! * **UNPREDICTABLE register choices are decoded normally.** That covers
//!   `Rd == 1111 && S == 0` (A6-10 marks the whole row UNPREDICTABLE, and
//!   A7.7.8's `if d == 13 || (d == 15 && S == '0') || n IN {13,15} then
//!   UNPREDICTABLE` says why: the `1111` alias only exists for the flag-setting
//!   form, so with `S == 0` the field really does name `pc`), and equally
//!   `Rd == 1101`, `Rn == 1101` and `Rn == 1111` where the instruction page
//!   forbids them. A disassembler looking at a firmware image must report what
//!   the bits say; suppressing them would hide exactly the malformed code a
//!   reverse-engineer is hunting for.
//! * **An UNPREDICTABLE *immediate* is not decoded.** The three encodings
//!   `i:imm3:a == 0001x`/`0010x`/`0011x` with `imm8 == 0` are UNPREDICTABLE in
//!   `ThumbExpandImm_C` itself (A5.3.2), which means the *value of an operand*
//!   is architecturally unspecified. There is no honest [`Operand::Imm`] to
//!   emit — reporting `0` would invent a number the architecture does not
//!   define — so [`decode`] returns `None` for those three `imm12` values, and
//!   only those three.
//!
//! That second rule has a pleasant side effect on re-encoding, described below.
//!
//! # `ThumbExpandImm`, and why its inverse is well-defined
//!
//! The twelve bits `i:imm3:imm8` are not a binary number (A5.3.2, Table A5-11):
//! the top five, `i:imm3:a` where `a` is `imm8[7]`, select a *pattern*, and
//! [`thumb_expand_imm`] implements the manual's `ThumbExpandImm_C` pseudocode
//! line for line. The carry-out that pseudocode also returns is dropped: it
//! depends on `APSR.C` at execution time for the `00xxx` cases and on bit 31 of
//! the result otherwise, and [`Insn`] models no flag state.
//!
//! The expansion is famously non-injective in general — but on the encodings
//! this module decodes it is a *bijection*, and [`encode_modified_imm`] is its
//! exact inverse rather than a heuristic search. The four disjoint images are:
//!
//! | `i:imm3:a` | constant | count |
//! |---|---|---|
//! | `0000x` | `0x000000XY` | 256 |
//! | `0001x` | `0x00XY00XY`, `XY != 0` | 255 |
//! | `0010x` | `0xXY00XY00`, `XY != 0` | 255 |
//! | `0011x` | `0xXYXYXYXY`, `XY != 0` | 255 |
//! | `>= 01000` | `(0x80 \| imm8[6:0]) << (32 - i:imm3:a)` | 3072 |
//!
//! The rotate case cannot collide with the others: for a rotate amount of 8 or
//! more the `ROR` of an 8-bit value never wraps, so the constant is
//! `u << s` with `u` in `128..=255` and `s = 32 - r` in `1..=24` — a value whose
//! set bits all lie in one 8-bit window at least one bit above the bottom.
//! `0000x` constants are below `0x100`; the three replicating patterns spread
//! set bits across bytes 16 or 24 bits apart. Within the rotate case, the
//! position of the constant's highest set bit is `7 + s`, which recovers `s`,
//! and then `u`, uniquely. The replicating patterns differ in which bytes are
//! non-zero (`{0,2}`, `{1,3}`, all four), so they cannot collide either.
//!
//! So there is exactly one canonicalisation question, and the UNPREDICTABLE-
//! immediate rule above answers it: the *only* many-to-one case in the whole
//! 12-bit space is that `0x100`, `0x200` and `0x300` would all expand to `0`,
//! which `0x000` already encodes — and those three are precisely the encodings
//! [`decode`] rejects. The canonical choice is therefore forced, not preferred:
//! smallest `imm12`, which is pattern order, which is the unique survivor.
//! `encode_modified_imm` tries the patterns in that order anyway, so the rule is
//! visible in the code, and `round_trip_sweep` proves that no decoded
//! instruction needs a different-but-equivalent encoding — zero cases.
//!
//! Table A6-11's footnotes ("Not available in ARM instructions", "Not available
//! in ARM instructions if `h == 1`") are about the *ARM* immediate encoding,
//! which has eight bits and a four-bit rotate-by-two, so it can express neither
//! the replicating patterns nor an odd rotate. They do not constrain Thumb, but
//! they explain the shape of this encoding: the replicating rows and the
//! single-bit-granularity rotate are exactly what Thumb-2 added.
//!
//! # `.w`, per instruction, from the manual's own syntax lines
//!
//! [`Insn::explicit_width`] is set for exactly the five encodings whose
//! assembler-syntax line in chapter A7 carries a literal `.W`: `MOV` T2, `ADD`
//! T3, `SUB` T3, `CMP` T2 and `RSB` T2. That is not a coincidence of
//! typography — it is the rule "a narrow encoding of this mnemonic *with an
//! immediate operand* exists, so the assembler must be told which to pick":
//! `MOV`/`ADD`/`SUB`/`CMP` T1/T2 (A5.2.1) and `RSB` T1 (`rsbs rd, rn, #0`,
//! A5.2.2). The rest of this group has no narrow immediate counterpart —
//! `AND`/`BIC`/`ORR`/`EOR`/`ADC`/`SBC`/`MVN`/`TST`/`CMN` are register-only at
//! 16 bits, `ORN`/`TEQ` do not exist there at all — so `mvn r0, #1` is already
//! unambiguous and printing `mvn.w` would add a suffix the manual does not.

use super::{Insn, Operand, Operands, Reg, Width};

/// Which of the group's three operand shapes a row uses.
///
/// The shape is not derivable from the opcode alone: it is what the `1111`
/// aliases *do*, namely delete one of the two register operands from the
/// syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// `{<Rd>,} <Rn>, #<const>` — the general three-operand form. `Rd` is
    /// always printed, matching the encoding-specific syntax line
    /// (`AND{S}<c> <Rd>,<Rn>,#<const>`) rather than the optional-`<Rd>` form.
    Binary,
    /// `<Rn>, #<const>` — `TST`/`TEQ`/`CMN`/`CMP`, where `Rd == 1111` means the
    /// result is discarded.
    Test,
    /// `<Rd>, #<const>` — `MOV`/`MVN`, where `Rn == 1111` means there is no
    /// first operand.
    Move,
}

impl Form {
    /// How many operands this shape has.
    fn arity(self) -> usize {
        match self {
            Form::Binary => 3,
            Form::Test | Form::Move => 2,
        }
    }
}

/// One resolved row of Table A5-10: everything about the instruction that the
/// `op`/`S`/`Rn`/`Rd` fields decide, other than the operand values themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row {
    /// The base mnemonic, lower case, with no `S` or width suffix.
    mnemonic: &'static str,
    /// The architectural encoding name from the instruction's page in A7.7.
    encoding: &'static str,
    /// The operand shape.
    form: Form,
    /// Whether UAL prints an `S` suffix — false for the test forms even though
    /// they always write the flags.
    sets_flags: bool,
    /// Whether UAL must print `.w` for this encoding to reassemble.
    explicit_width: bool,
}

/// Resolve Table A5-10 for one instruction's fields, or `None` if `op` is
/// unallocated (UNDEFINED).
///
/// `op` is the four-bit `hw1[8:5]`; `s` is `hw1[4]`. The `Rd == 1111` tests are
/// applied before the `Rn` ones, following the order of the `SEE` directives on
/// the instruction pages: `ADD (immediate)` T3 reads
/// `if Rd == '1111' && S == '1' then SEE CMN` *then*
/// `if Rn == '1101' then SEE ADD (SP plus immediate)`, so `Rd == 1111`,
/// `S == 1`, `Rn == 1101` is `cmn sp, #<const>` and not an `ADD`.
fn resolve(op: u16, s: bool, rn: u16, rd: u16) -> Option<Row> {
    /// A row whose UAL prints `S` iff the `S` bit is set and never prints `.w`.
    fn plain(mnemonic: &'static str, s: bool) -> Row {
        Row {
            mnemonic,
            encoding: "T1",
            form: Form::Binary,
            sets_flags: s,
            explicit_width: false,
        }
    }
    /// A `TST`/`TEQ`/`CMN`/`CMP` row: no `S` suffix, two operands.
    fn test(mnemonic: &'static str, encoding: &'static str, explicit_width: bool) -> Row {
        Row {
            mnemonic,
            encoding,
            form: Form::Test,
            sets_flags: false,
            explicit_width,
        }
    }

    let alias_rd = rd == 0b1111 && s;
    Some(match op {
        // 0000x AND (immediate) T1 / TST (immediate) T1.
        0b0000 if alias_rd => test("tst", "T1", false),
        0b0000 => plain("and", s),
        // 0001x BIC (immediate) T1 — no alias in either field.
        0b0001 => plain("bic", s),
        // 0010x ORR (immediate) T1 / MOV (immediate) T2.
        0b0010 if rn == 0b1111 => Row {
            mnemonic: "mov",
            encoding: "T2",
            form: Form::Move,
            sets_flags: s,
            explicit_width: true,
        },
        0b0010 => plain("orr", s),
        // 0011x ORN (immediate) T1 / MVN (immediate) T1.
        0b0011 if rn == 0b1111 => Row {
            mnemonic: "mvn",
            encoding: "T1",
            form: Form::Move,
            sets_flags: s,
            explicit_width: false,
        },
        0b0011 => plain("orn", s),
        // 0100x EOR (immediate) T1 / TEQ (immediate) T1.
        0b0100 if alias_rd => test("teq", "T1", false),
        0b0100 => plain("eor", s),
        // 1000x ADD (immediate) T3 / CMN (immediate) T1, and with Rn == 1101
        // ADD (SP plus immediate) T3 — also named T3, so nothing to switch on.
        0b1000 if alias_rd => test("cmn", "T1", false),
        0b1000 => Row {
            mnemonic: "add",
            encoding: "T3",
            form: Form::Binary,
            sets_flags: s,
            explicit_width: true,
        },
        // 1010x ADC (immediate) T1.
        0b1010 => plain("adc", s),
        // 1011x SBC (immediate) T1.
        0b1011 => plain("sbc", s),
        // 1101x SUB (immediate) T3 / CMP (immediate) T2. With Rn == 1101 the
        // manual's SEE sends this to SUB (SP minus immediate), whose encoding
        // the A7.7.176 page names T2 rather than T3.
        0b1101 if alias_rd => test("cmp", "T2", true),
        0b1101 => Row {
            mnemonic: "sub",
            encoding: if rn == 0b1101 { "T2" } else { "T3" },
            form: Form::Binary,
            sets_flags: s,
            explicit_width: true,
        },
        // 1110x RSB (immediate) T2.
        0b1110 => Row {
            mnemonic: "rsb",
            encoding: "T2",
            form: Form::Binary,
            sets_flags: s,
            explicit_width: true,
        },
        // 0101x 0110x 0111x 1001x 1100x 1111x — UNDEFINED.
        _ => return None,
    })
}

/// `ThumbExpandImm(imm12)` — ARM DDI 0403E.e A5.3.2, Table A5-11.
///
/// Returns `None` for the three encodings the pseudocode calls UNPREDICTABLE
/// (a replicating pattern with `imm8 == 0`); see the module documentation for
/// why that is a decode failure rather than a zero.
///
/// The `imm12` argument is `i:imm3:imm8`, assembled from `hw1[10]` and
/// `hw2[14:12]`/`hw2[7:0]`. Bits above 12 are ignored.
fn thumb_expand_imm(imm12: u16) -> Option<u32> {
    let imm12 = imm12 & 0x0FFF;
    let imm8 = u32::from(imm12 & 0x00FF);
    if (imm12 & 0b1100_0000_0000) != 0 {
        // `unrotated_value = ZeroExtend('1':imm12<6:0>)`, rotated right by
        // `UInt(imm12<11:7>)`. The rotate amount is 8..=31 here, so the value's
        // own bits never wrap round into the bottom of the word.
        let unrotated = 0x80 | u32::from(imm12 & 0x7F);
        return Some(unrotated.rotate_right(u32::from(imm12 >> 7)));
    }
    match (imm12 >> 8) & 0b11 {
        0b00 => Some(imm8),
        0b01 => {
            if imm8 == 0 {
                None
            } else {
                Some((imm8 << 16) | imm8)
            }
        }
        0b10 => {
            if imm8 == 0 {
                None
            } else {
                Some((imm8 << 24) | (imm8 << 8))
            }
        }
        _ => {
            if imm8 == 0 {
                None
            } else {
                Some((imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8)
            }
        }
    }
}

/// The inverse of [`thumb_expand_imm`]: the `imm12` field that expands to
/// `value`, or `None` if no modified immediate denotes it.
///
/// Most 32-bit constants have no encoding at all (only 4093 do), which is why
/// this is fallible and why an assembler that wants an arbitrary constant must
/// fall back to `MOVW`/`MOVT` or a literal pool. Where an encoding exists it is
/// unique — see the module documentation — so the patterns are tried in
/// ascending `imm12` order purely so the canonical choice is legible, not
/// because a later pattern could also match.
fn encode_modified_imm(value: u32) -> Option<u16> {
    // 0000x: an 8-bit value, zero-extended.
    if value <= 0xFF {
        return Some(value as u16);
    }
    let byte0 = value & 0xFF;
    let byte1 = (value >> 8) & 0xFF;
    // 0001x: 0x00XY00XY. 0010x: 0xXY00XY00. 0011x: 0xXYXYXYXY. A zero byte is
    // unreachable here (`value > 0xFF` and the byte is replicated), but the
    // guards keep the correspondence with the pseudocode's UNPREDICTABLE case
    // explicit.
    if byte0 != 0 && value == (byte0 << 16) | byte0 {
        return Some(0x100 | byte0 as u16);
    }
    if byte1 != 0 && value == (byte1 << 24) | (byte1 << 8) {
        return Some(0x200 | byte1 as u16);
    }
    if byte0 != 0 && value == (byte0 << 24) | (byte0 << 16) | (byte0 << 8) | byte0 {
        return Some(0x300 | byte0 as u16);
    }
    // >= 01000: `value == (0x80 | imm8[6:0]) << s`. The constant's highest set
    // bit is at `7 + s`, so `s` is forced; the shift is then exact only if the
    // low `s` bits are clear, and the recovered 8-bit value necessarily has its
    // own bit 7 set.
    let s = 31 - value.leading_zeros() - 7;
    if value & ((1 << s) - 1) != 0 {
        return None;
    }
    let unrotated = value >> s;
    Some((((32 - s) as u16) << 7) | ((unrotated & 0x7F) as u16))
}

/// Decode an instruction in this group, or `None` if `hw1`/`hw2` do not
/// belong to it.
///
/// `None` also means UNDEFINED (an unallocated `op`) or an UNPREDICTABLE
/// immediate; UNPREDICTABLE register choices decode normally. The group guard
/// is re-tested here rather than trusted from the dispatcher so that the
/// function is correct when called directly.
pub(crate) fn decode(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 >> 11 != 0b11110 || (hw1 & (1 << 9)) != 0 || (hw2 & (1 << 15)) != 0 {
        return None;
    }
    let op = (hw1 >> 5) & 0xF;
    let s = (hw1 & (1 << 4)) != 0;
    let rn = hw1 & 0xF;
    let rd = (hw2 >> 8) & 0xF;
    let imm12 = ((hw1 >> 10) & 1) << 11 | ((hw2 >> 12) & 0b111) << 8 | (hw2 & 0xFF);

    let row = resolve(op, s, rn, rd)?;
    let imm32 = thumb_expand_imm(imm12)?;

    let mut operands = Operands::new();
    match row.form {
        Form::Binary => {
            operands.push(Operand::Reg(Reg(rd as u8)));
            operands.push(Operand::Reg(Reg(rn as u8)));
        }
        Form::Test => operands.push(Operand::Reg(Reg(rn as u8))),
        Form::Move => operands.push(Operand::Reg(Reg(rd as u8))),
    }
    // The expanded constant is a 32-bit *bit pattern*, so it is widened
    // unsigned: `mvn r0, #0xffffffff` is what the encoding says, and printing
    // it as `#-0x1` would name a constant this encoding cannot express.
    operands.push(Operand::Imm(i64::from(imm32)));

    Some(Insn {
        mnemonic: row.mnemonic,
        encoding: row.encoding,
        addr,
        width: Width::Wide,
        cond: None,
        sets_flags: row.sets_flags,
        explicit_width: row.explicit_width,
        operands,
    })
}

/// Re-encode an instruction this module decoded, back to its two halfwords.
///
/// This runs first in the crate's 32-bit `encode` chain, so it must be strict:
/// several mnemonics here also name a wide *register* form with the same
/// encoding letter (`sub.w r0, r1, r2` is `SUB (register)` T2; `cmp.w r0, r1`
/// is `CMP (register)` T2), and `add`/`sub`/`mov` additionally name the plain
/// binary immediates of A5.3.3. Rejection is by construction rather than by a
/// list of exclusions: the candidate halfwords are assembled and then decoded
/// again, and anything that does not come back identical — different operand
/// kinds, a constant with no modified-immediate encoding, an encoding name from
/// another group, an `and pc, …` that would really read as `tst` — yields
/// `None`. `addr` and `cond` are excluded from that comparison: neither is in
/// the bits (a condition here comes from an enclosing `IT` block).
pub(crate) fn encode(insn: &Insn) -> Option<(u16, u16)> {
    if insn.width != Width::Wide {
        return None;
    }
    let (op, form) = match insn.mnemonic {
        "and" => (0b0000, Form::Binary),
        "tst" => (0b0000, Form::Test),
        "bic" => (0b0001, Form::Binary),
        "orr" => (0b0010, Form::Binary),
        "mov" => (0b0010, Form::Move),
        "orn" => (0b0011, Form::Binary),
        "mvn" => (0b0011, Form::Move),
        "eor" => (0b0100, Form::Binary),
        "teq" => (0b0100, Form::Test),
        "add" => (0b1000, Form::Binary),
        "cmn" => (0b1000, Form::Test),
        "adc" => (0b1010, Form::Binary),
        "sbc" => (0b1011, Form::Binary),
        "sub" => (0b1101, Form::Binary),
        "cmp" => (0b1101, Form::Test),
        "rsb" => (0b1110, Form::Binary),
        _ => return None,
    };
    if insn.operands.len() != form.arity() {
        return None;
    }
    // `Rd == 1111` / `Rn == 1111` are supplied by the form for the aliases:
    // that is the whole content of "`TST` has no destination".
    // `get(i)` rather than `get(i)?`: the arity check above already fixes how
    // many slots there are, so "absent" is unreachable and splitting it from
    // "wrong shape" would be a branch nothing can take. One wildcard answers
    // both.
    let (rd, rn, imm) = match (form, insn.operands.get(0), insn.operands.get(1)) {
        (Form::Binary, Some(Operand::Reg(d)), Some(Operand::Reg(n))) => {
            match insn.operands.get(2) {
                Some(Operand::Imm(v)) => (u16::from(d.num()), u16::from(n.num()), v),
                _ => return None,
            }
        }
        (Form::Test, Some(Operand::Reg(n)), Some(Operand::Imm(v))) => {
            (0b1111, u16::from(n.num()), v)
        }
        (Form::Move, Some(Operand::Reg(d)), Some(Operand::Imm(v))) => {
            (u16::from(d.num()), 0b1111, v)
        }
        _ => return None,
    };
    // The test forms set the flags as their purpose, so their `S` bit is 1
    // whatever `sets_flags` (which only says whether UAL prints an `S`) holds.
    let s = form == Form::Test || insn.sets_flags;
    let bits = if (0..=0xFFFF_FFFF).contains(&imm) {
        imm as u32
    } else {
        return None;
    };
    let imm12 = encode_modified_imm(bits)?;

    let hw1 = (0b11110 << 11) | ((imm12 >> 11) << 10) | (op << 5) | (u16::from(s) << 4) | rn;
    let hw2 = ((imm12 >> 8) & 0b111) << 12 | (rd << 8) | (imm12 & 0xFF);

    // `map_or` with a plain `false` rather than a `match` or `?`: "did not
    // decode at all" and "decoded to something else" are the same answer —
    // refuse — and only the second is reachable, because these halfwords are
    // assembled from the very table this module decodes by. Writing it as one
    // expression keeps the unreachable case from existing as a branch here at
    // all; the eager `false` argument is not a closure, so the choice happens
    // inside `Option::map_or` rather than in a line of this function that no
    // test could ever run.
    let faithful = decode(hw1, hw2, insn.addr).map_or(false, |back| {
        back.mnemonic == insn.mnemonic
            && back.encoding == insn.encoding
            && back.width == insn.width
            && back.sets_flags == insn.sets_flags
            && back.explicit_width == insn.explicit_width
            && back.operands == insn.operands
    });
    if faithful {
        Some((hw1, hw2))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble the halfwords for `op(4)`, `S`, `Rn`, `Rd` and a 12-bit
    /// `i:imm3:imm8`, so the tests can speak in Table A5-10's own fields.
    fn bits(op: u16, s: bool, rn: u16, rd: u16, imm12: u16) -> (u16, u16) {
        let hw1 = (0b11110 << 11) | ((imm12 >> 11) << 10) | (op << 5) | (u16::from(s) << 4) | rn;
        let hw2 = ((imm12 >> 8) & 0b111) << 12 | (rd << 8) | (imm12 & 0xFF);
        (hw1, hw2)
    }

    /// Decode from fields, or panic — for the tests that expect a hit.
    fn dec(op: u16, s: bool, rn: u16, rd: u16, imm12: u16) -> Insn {
        let (hw1, hw2) = bits(op, s, rn, rd, imm12);
        decode(hw1, hw2, 0x1000).expect("should decode")
    }

    // ---------------------------------------------------------------- A5.3.2

    /// Table A5-11, one assertion per row of the table, with the constants
    /// hand-expanded from the `abcdefgh` bit patterns printed there.
    #[test]
    fn thumb_expand_imm_table_a5_11() {
        // 0000x: 00000000 00000000 00000000 abcdefgh.
        assert_eq!(thumb_expand_imm(0x000), Some(0x0000_0000));
        assert_eq!(thumb_expand_imm(0x05A), Some(0x0000_005A));
        assert_eq!(thumb_expand_imm(0x0FF), Some(0x0000_00FF));
        // 0001x: 00000000 abcdefgh 00000000 abcdefgh.
        assert_eq!(thumb_expand_imm(0x1AB), Some(0x00AB_00AB));
        assert_eq!(thumb_expand_imm(0x101), Some(0x0001_0001));
        // 0010x: abcdefgh 00000000 abcdefgh 00000000.
        assert_eq!(thumb_expand_imm(0x2AB), Some(0xAB00_AB00));
        assert_eq!(thumb_expand_imm(0x280), Some(0x8000_8000));
        // 0011x: abcdefgh abcdefgh abcdefgh abcdefgh.
        assert_eq!(thumb_expand_imm(0x3AB), Some(0xABAB_ABAB));
        assert_eq!(thumb_expand_imm(0x3FF), Some(0xFFFF_FFFF));
        // The three UNPREDICTABLE encodings: a replicating pattern of zero.
        assert_eq!(thumb_expand_imm(0x100), None);
        assert_eq!(thumb_expand_imm(0x200), None);
        assert_eq!(thumb_expand_imm(0x300), None);

        // Rotates. `imm12 = i:imm3:a:bcdefgh`, so the five-bit rotate field is
        // `imm12 >> 7` and the low seven bits are `bcdefgh`.
        // 01000: 1bcdefgh 00000000 00000000 00000000.
        assert_eq!(thumb_expand_imm(8 << 7), Some(0x8000_0000));
        assert_eq!(thumb_expand_imm((8 << 7) | 0x7F), Some(0xFF00_0000));
        // 01001: 01bcdefg h0000000 00000000 00000000.
        assert_eq!(thumb_expand_imm(9 << 7), Some(0x4000_0000));
        // The `h == 1` case Table A6-11 notes is inexpressible in ARM: the
        // eighth bit lands in the next byte down.
        assert_eq!(thumb_expand_imm((9 << 7) | 0x01), Some(0x4080_0000));
        // 01010: 001bcdef gh000000 00000000 00000000.
        assert_eq!(thumb_expand_imm(10 << 7), Some(0x2000_0000));
        // 01011: 0001bcde fgh00000 00000000 00000000.
        assert_eq!(thumb_expand_imm(11 << 7), Some(0x1000_0000));
        // 11101: 00000000 00000000 000001bc defgh000.
        assert_eq!(thumb_expand_imm(29 << 7), Some(0x0000_0400));
        // 11110: 00000000 00000000 0000001b cdefgh00.
        assert_eq!(thumb_expand_imm(30 << 7), Some(0x0000_0200));
        // 11111: 00000000 00000000 00000001 bcdefgh0.
        assert_eq!(thumb_expand_imm(31 << 7), Some(0x0000_0100));
        assert_eq!(thumb_expand_imm((31 << 7) | 0x7F), Some(0x0000_01FE));
    }

    /// The rotate case is `ROR` of an 8-bit value by 8..=31, which for these
    /// amounts is a plain left shift — spot-check the identity the inverse
    /// relies on at both boundaries and in the middle.
    #[test]
    fn thumb_expand_imm_rotate_is_a_left_shift() {
        for r in 8u16..=31 {
            for v in [0u16, 1, 0x3F, 0x7F] {
                let expected = (0x80 | u32::from(v)) << (32 - u32::from(r));
                assert_eq!(
                    thumb_expand_imm((r << 7) | v),
                    Some(expected),
                    "r={r} v={v}"
                );
            }
        }
    }

    /// The expansion is injective on everything [`decode`] accepts: over the
    /// whole 12-bit space the only collision is the three UNPREDICTABLE
    /// encodings that would all mean zero, and those decode to `None`. This is
    /// what makes [`encode_modified_imm`] an inverse rather than a choice.
    #[test]
    fn expansion_is_a_bijection_on_the_decodable_space() {
        let mut seen: Vec<(u32, u16)> = Vec::with_capacity(4096);
        for imm12 in 0u16..4096 {
            match thumb_expand_imm(imm12) {
                Some(v) => {
                    assert_eq!(
                        encode_modified_imm(v),
                        Some(imm12),
                        "inverse disagrees for imm12={imm12:#05x} -> {v:#010x}"
                    );
                    seen.push((v, imm12));
                }
                // `contains`, not `matches!`: the latter's implicit `_ => false`
                // arm only runs when the assertion is about to fail, which is a
                // branch no passing run can take.
                None => assert!(
                    [0x100, 0x200, 0x300].contains(&imm12),
                    "unexpected UNPREDICTABLE immediate {imm12:#05x}"
                ),
            }
        }
        assert_eq!(seen.len(), 4093);
        seen.sort_unstable();
        let mut deduped = seen.clone();
        deduped.dedup_by_key(|(v, _)| *v);
        assert_eq!(deduped.len(), seen.len(), "two encodings share a constant");
    }

    /// Most constants are not expressible, and the inverse must say so rather
    /// than round something off.
    #[test]
    fn unrepresentable_constants_are_rejected() {
        for v in [
            0x1234_5678, // nothing like a pattern
            0x0000_0100 + 1,
            0x0001_0002, // almost 0001x, but the halves differ
            0x00AB_00AC,
            0xAB00_AB01,
            0x0000_01FF, // nine significant bits, so no 8-bit window fits
            0x8000_0001,
            0xFFFF_FFFE,
        ] {
            assert_eq!(encode_modified_imm(v), None, "{v:#010x} is not encodable");
        }
        // …and the ones that are.
        assert_eq!(encode_modified_imm(0x0000_00FF), Some(0x0FF));
        assert_eq!(encode_modified_imm(0x00AB_00AB), Some(0x1AB));
        assert_eq!(encode_modified_imm(0xAB00_AB00), Some(0x2AB));
        assert_eq!(encode_modified_imm(0xABAB_ABAB), Some(0x3AB));
        assert_eq!(encode_modified_imm(0x8000_0000), Some(8 << 7));
        assert_eq!(encode_modified_imm(0x0000_01FE), Some((31 << 7) | 0x7F));
    }

    // ---------------------------------------------------------------- A5.3.1

    /// Every row of Table A5-10, printed. The expected strings are the syntax
    /// lines from chapter A7 — `AND{S}<c> <Rd>,<Rn>,#<const>`,
    /// `MOV{S}<c>.W <Rd>,#<const>`, `TST<c> <Rn>,#<const>` — with `<const>`
    /// set to 1 (`imm12 = 0x001`) and the `S` bit varied where the row has one.
    #[test]
    fn printed_ual_for_every_row_of_table_a5_10() {
        let one = 0x001;
        // op, S, Rn, Rd, expected.
        let cases: [(u16, bool, u16, u16, &str); 22] = [
            (0b0000, false, 1, 0, "and r0, r1, #1"),
            (0b0000, true, 1, 0, "ands r0, r1, #1"),
            (0b0000, true, 1, 0b1111, "tst r1, #1"),
            (0b0001, false, 1, 0, "bic r0, r1, #1"),
            (0b0001, true, 1, 0, "bics r0, r1, #1"),
            (0b0010, false, 1, 0, "orr r0, r1, #1"),
            (0b0010, true, 1, 0, "orrs r0, r1, #1"),
            (0b0010, false, 0b1111, 0, "mov.w r0, #1"),
            (0b0010, true, 0b1111, 0, "movs.w r0, #1"),
            (0b0011, false, 1, 0, "orn r0, r1, #1"),
            (0b0011, false, 0b1111, 0, "mvn r0, #1"),
            (0b0011, true, 0b1111, 0, "mvns r0, #1"),
            (0b0100, false, 1, 0, "eor r0, r1, #1"),
            (0b0100, true, 1, 0b1111, "teq r1, #1"),
            (0b1000, false, 1, 0, "add.w r0, r1, #1"),
            (0b1000, true, 1, 0, "adds.w r0, r1, #1"),
            (0b1000, true, 1, 0b1111, "cmn r1, #1"),
            (0b1010, false, 1, 0, "adc r0, r1, #1"),
            (0b1011, false, 1, 0, "sbc r0, r1, #1"),
            (0b1101, false, 1, 0, "sub.w r0, r1, #1"),
            (0b1101, true, 1, 0b1111, "cmp.w r1, #1"),
            (0b1110, false, 1, 0, "rsb.w r0, r1, #1"),
        ];
        for (op, s, rn, rd, expected) in cases {
            assert_eq!(dec(op, s, rn, rd, one).to_string(), expected);
        }
    }

    /// The test forms must not print an `S`, and must still be encodable.
    #[test]
    fn test_forms_print_no_s_suffix() {
        for (op, mnemonic) in [
            (0b0000, "tst"),
            (0b0100, "teq"),
            (0b1000, "cmn"),
            (0b1101, "cmp"),
        ] {
            let insn = dec(op, true, 2, 0b1111, 0x0FF);
            assert_eq!(insn.mnemonic, mnemonic);
            assert!(!insn.sets_flags, "{mnemonic} would print as {mnemonic}s");
            assert_eq!(insn.operands.len(), 2);
            assert_eq!(encode(&insn), Some(bits(op, true, 2, 0b1111, 0x0FF)));
        }
    }

    /// The `.w` suffix appears for exactly the five encodings whose A7 syntax
    /// line shows it — the ones with a narrow immediate counterpart.
    #[test]
    fn explicit_width_matches_the_manuals_syntax_lines() {
        let wide = [
            (0b0010, false, 0b1111, 0, "mov"),
            (0b1000, false, 1, 0, "add"),
            (0b1101, false, 1, 0, "sub"),
            (0b1101, true, 1, 0b1111, "cmp"),
            (0b1110, false, 1, 0, "rsb"),
        ];
        for (op, s, rn, rd, mnemonic) in wide {
            let insn = dec(op, s, rn, rd, 0x001);
            assert_eq!(insn.mnemonic, mnemonic);
            assert!(insn.explicit_width, "{mnemonic} needs .w to reassemble");
        }
        for (op, s, rn, rd) in [
            (0b0000, false, 1, 0),
            (0b0000, true, 1, 0b1111),
            (0b0001, false, 1, 0),
            (0b0010, false, 1, 0),
            (0b0011, false, 1, 0),
            (0b0011, false, 0b1111, 0),
            (0b0100, false, 1, 0),
            (0b0100, true, 1, 0b1111),
            (0b1000, true, 1, 0b1111),
            (0b1010, false, 1, 0),
            (0b1011, false, 1, 0),
        ] {
            let insn = dec(op, s, rn, rd, 0x001);
            assert!(
                !insn.explicit_width,
                "{} has no narrow immediate form, so no .w",
                insn.mnemonic
            );
        }
    }

    // -------------------------------------------------------------- aliasing

    /// `Rn == 1111` is `MOV`/`MVN`, not `ORR`/`ORN` — and the `Rn` operand
    /// disappears from the syntax rather than printing as `pc`.
    #[test]
    fn rn_1111_aliases_orr_to_mov_and_orn_to_mvn() {
        let mov = dec(0b0010, true, 0b1111, 3, 0x0FF);
        assert_eq!(mov.mnemonic, "mov");
        assert_eq!(mov.encoding, "T2");
        assert_eq!(mov.operands.len(), 2);
        assert_eq!(mov.to_string(), "movs.w r3, #0xff");

        let orr = dec(0b0010, true, 0b1110, 3, 0x0FF);
        assert_eq!(orr.mnemonic, "orr");
        assert_eq!(orr.to_string(), "orrs r3, lr, #0xff");

        let mvn = dec(0b0011, false, 0b1111, 3, 0x0FF);
        assert_eq!(mvn.mnemonic, "mvn");
        assert_eq!(mvn.operands.len(), 2);
        let orn = dec(0b0011, false, 0b1110, 3, 0x0FF);
        assert_eq!(orn.mnemonic, "orn");
    }

    /// `Rd == 1111` with `S == 1` is the test form, not the data operation.
    #[test]
    fn rd_1111_with_s_aliases_to_the_test_forms() {
        assert_eq!(dec(0b0000, true, 1, 0b1111, 0x001).mnemonic, "tst");
        assert_eq!(dec(0b0100, true, 1, 0b1111, 0x001).mnemonic, "teq");
        assert_eq!(dec(0b1000, true, 1, 0b1111, 0x001).mnemonic, "cmn");
        assert_eq!(dec(0b1101, true, 1, 0b1111, 0x001).mnemonic, "cmp");
        // …but only for the four rows that have one. `BIC`/`ADC`/`SBC`/`RSB`
        // and `ORR`/`ORN` have no `Rd` alias, so `Rd == 1111` is just `pc`.
        for op in [0b0001, 0b0010, 0b0011, 0b1010, 0b1011, 0b1110] {
            let insn = dec(op, true, 1, 0b1111, 0x001);
            assert_eq!(insn.operands.get(0), Some(Operand::Reg(Reg::PC)));
        }
    }

    /// `Rd == 1111 && S == 0` is UNPREDICTABLE, not UNDEFINED: the `1111` alias
    /// only exists for the flag-setting form, so with `S == 0` the field names
    /// `pc` and the instruction decodes as the base operation. Documented
    /// policy — a decoder that returned `None` here would be reporting "these
    /// bytes are not an instruction", which is a different claim.
    #[test]
    fn rd_1111_without_s_is_unpredictable_but_still_decoded() {
        let and = dec(0b0000, false, 1, 0b1111, 0x001);
        assert_eq!(and.mnemonic, "and");
        assert!(!and.sets_flags);
        assert_eq!(and.to_string(), "and pc, r1, #1");
        assert_eq!(encode(&and), Some(bits(0b0000, false, 1, 0b1111, 0x001)));

        for (op, mnemonic) in [(0b0100, "eor"), (0b1000, "add"), (0b1101, "sub")] {
            let insn = dec(op, false, 1, 0b1111, 0x001);
            assert_eq!(insn.mnemonic, mnemonic);
            assert_eq!(insn.operands.get(0), Some(Operand::Reg(Reg::PC)));
        }

        // The flag-setting counterpart of the same bits is the test form, so
        // `ands pc, r1, #1` is not encodable at all: the bits would read back
        // as `tst`.
        let mut ands = and;
        ands.sets_flags = true;
        assert_eq!(encode(&ands), None);
    }

    /// `Rn == 1101` sends `ADD`/`SUB` to the SP forms. The UAL text is the same
    /// as the general form, so the only difference is the encoding name, which
    /// follows the `SEE` directives: `ADD (SP plus immediate)` is also T3, but
    /// `SUB (SP minus immediate)` is T2.
    #[test]
    fn rn_1101_is_the_sp_form() {
        let add = dec(0b1000, false, 0b1101, 0, 0x008);
        assert_eq!((add.mnemonic, add.encoding), ("add", "T3"));
        assert_eq!(add.to_string(), "add.w r0, sp, #8");
        assert_eq!(encode(&add), Some(bits(0b1000, false, 0b1101, 0, 0x008)));

        let sub = dec(0b1101, false, 0b1101, 0, 0x008);
        assert_eq!((sub.mnemonic, sub.encoding), ("sub", "T2"));
        assert_eq!(sub.to_string(), "sub.w r0, sp, #8");
        assert_eq!(encode(&sub), Some(bits(0b1101, false, 0b1101, 0, 0x008)));

        // `Rd == 1111 && S == 1` wins over `Rn == 1101`, per the order of the
        // `SEE` lines on the ADD/SUB pages.
        assert_eq!(dec(0b1000, true, 0b1101, 0b1111, 0x008).mnemonic, "cmn");
        assert_eq!(dec(0b1101, true, 0b1101, 0b1111, 0x008).mnemonic, "cmp");
    }

    // ------------------------------------------------------------- undefined

    /// The six unallocated `op` values are UNDEFINED for every register and
    /// immediate combination.
    #[test]
    fn unallocated_ops_are_undefined() {
        for op in [0b0101, 0b0110, 0b0111, 0b1001, 0b1100, 0b1111] {
            for s in [false, true] {
                for rn in [0u16, 1, 0b1101, 0b1111] {
                    for rd in [0u16, 1, 0b1101, 0b1111] {
                        let (hw1, hw2) = bits(op, s, rn, rd, 0x001);
                        assert_eq!(decode(hw1, hw2, 0), None, "op={op:04b}");
                    }
                }
            }
        }
    }

    /// The group guard: anything outside `11110 x 0 …` / `0 …` is somebody
    /// else's, including the plain-binary-immediate space (`hw1[9] == 1`) that
    /// holds `ADR` and `ADDW`, and the branch space (`hw2[15] == 1`).
    #[test]
    fn group_guard_rejects_neighbours() {
        let (hw1, hw2) = bits(0b1000, false, 1, 0, 0x001);
        assert!(decode(hw1, hw2, 0).is_some());
        assert_eq!(decode(hw1 | 1 << 9, hw2, 0), None, "that is A5.3.3");
        assert_eq!(decode(hw1, hw2 | 1 << 15, 0), None, "that is A5.3.4");
        assert_eq!(decode(hw1 & !(0b11 << 11), hw2, 0), None, "16-bit space");
        // ADR T3 — `11110 i 1 0000 0 1111` — must not be stolen from A5.3.3.
        assert_eq!(decode(0xF20F, 0x0000, 0), None);
    }

    // ------------------------------------------------------------ round trip

    /// Systematic round trip: every `op`, both `S` values, the interesting
    /// register numbers (including `1111` and `1101`), and all 4096 values of
    /// `i:imm3:imm8`. Everything that decodes must re-encode to the exact bytes
    /// it came from — no case needs an equivalent-but-different encoding,
    /// because the expansion is a bijection on the decodable space (see
    /// `expansion_is_a_bijection_on_the_decodable_space`).
    #[test]
    fn round_trip_sweep() {
        let mut decoded = 0usize;
        for op in 0u16..16 {
            for s in [false, true] {
                for rn in [0u16, 1, 0b1101, 0b1111] {
                    for rd in [0u16, 3, 0b1101, 0b1111] {
                        for imm12 in 0u16..4096 {
                            let (hw1, hw2) = bits(op, s, rn, rd, imm12);
                            let insn = match decode(hw1, hw2, 0x2000) {
                                Some(i) => i,
                                None => continue,
                            };
                            decoded += 1;
                            assert_eq!(
                                encode(&insn),
                                Some((hw1, hw2)),
                                "{hw1:#06x} {hw2:#06x} decoded as `{insn}`"
                            );
                        }
                    }
                }
            }
        }
        // 10 allocated ops * 2 S * 16 register pairs * 4093 immediates, less
        // nothing: every allocated combination decodes.
        assert_eq!(decoded, 10 * 2 * 16 * 4093);
    }

    /// A condition from an enclosing `IT` block is not in the bits, so it must
    /// not stop the instruction re-encoding.
    #[test]
    fn encode_ignores_an_it_block_condition() {
        let mut insn = dec(0b0000, true, 1, 0, 0x0FF);
        insn.cond = Some(crate::Cond::Ne);
        assert_eq!(insn.to_string(), "andsne r0, r1, #0xff");
        assert_eq!(encode(&insn), Some(bits(0b0000, true, 1, 0, 0x0FF)));
    }

    /// `encode` runs first in the crate's wide chain, so it has to decline
    /// everything that merely shares a mnemonic.
    #[test]
    fn encode_declines_what_is_not_ours() {
        let insn = dec(0b1000, false, 1, 0, 0x001);

        // A narrow instruction, whatever its mnemonic.
        let mut narrow = insn;
        narrow.width = Width::Narrow;
        assert_eq!(encode(&narrow), None);

        // A register form: `add.w r0, r1, r2` is A5.3.11's, not ours.
        let mut reg = insn;
        reg.operands = Operands::new();
        reg.operands.push(Operand::Reg(Reg(0)));
        reg.operands.push(Operand::Reg(Reg(1)));
        reg.operands.push(Operand::Reg(Reg(2)));
        assert_eq!(encode(&reg), None);

        // `addw r0, r1, #0x123` — an encoding name from A5.3.3, and a constant
        // with no modified-immediate form either.
        let mut addw = insn;
        addw.encoding = "T4";
        assert_eq!(encode(&addw), None);
        let mut unrepresentable = insn;
        unrepresentable.operands = Operands::new();
        unrepresentable.operands.push(Operand::Reg(Reg(0)));
        unrepresentable.operands.push(Operand::Reg(Reg(1)));
        unrepresentable.operands.push(Operand::Imm(0x123));
        assert_eq!(encode(&unrepresentable), None);

        // A mnemonic this group does not contain, and a wrong operand count.
        let mut alien = insn;
        alien.mnemonic = "ldr";
        assert_eq!(encode(&alien), None);
        let mut short = insn;
        short.operands = Operands::new();
        short.operands.push(Operand::Reg(Reg(0)));
        short.operands.push(Operand::Imm(1));
        assert_eq!(encode(&short), None);

        // An immediate outside the 32-bit range, and a negative one: `decode`
        // always emits the unsigned bit pattern, so nothing else round-trips.
        for v in [-1i64, 1 << 32, i64::MIN] {
            let mut bad = insn;
            bad.operands = Operands::new();
            bad.operands.push(Operand::Reg(Reg(0)));
            bad.operands.push(Operand::Reg(Reg(1)));
            bad.operands.push(Operand::Imm(v));
            assert_eq!(encode(&bad), None, "{v}");
        }
    }

    /// Real encodings, checked against whole halfwords rather than against
    /// this module's own field assembly. `f04f 00ff` is `mov.w r0, #0xff`;
    /// `f04f 30ff` is the same instruction with `i:imm3:a == 0011x`, i.e. the
    /// byte replicated four times, which is how `#-1` is written.
    #[test]
    fn known_halfwords() {
        let mov = decode(0xF04F, 0x00FF, 0).expect("mov.w");
        assert_eq!(mov.to_string(), "mov.w r0, #0xff");
        let mov_all = decode(0xF04F, 0x30FF, 0).expect("mov.w");
        assert_eq!(mov_all.to_string(), "mov.w r0, #0xffffffff");
        let sub = decode(0xF1A2, 0x0201, 0).expect("sub.w");
        assert_eq!(sub.to_string(), "sub.w r2, r2, #1");
        // `f5b0 5f00` — cmp.w r0, #0x2000: `i:imm3:imm8 == 0xd00`, so the
        // rotate field is `11010` (26) and the constant is `0x80 << (32 - 26)`.
        let cmp = decode(0xF5B0, 0x5F00, 0).expect("cmp.w");
        assert_eq!(cmp.to_string(), "cmp.w r0, #0x2000");
        assert_eq!(encode(&cmp), Some((0xF5B0, 0x5F00)));
    }
}
