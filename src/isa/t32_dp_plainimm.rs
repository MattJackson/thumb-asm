//! Data processing (plain binary immediate) — the 32-bit encodings reached
//! when `hw1[15:11] == 0b11110`, `hw1[9] == 1` and `hw2[15] == 0`
//! (ARM DDI 0403E.e A5.3.3, Table A5-12; the A/R view is DDI 0406B A6.3.3,
//! Table A6-12, which allocates exactly the same eleven `op` values).
//!
//! The layout is `hw1 = 11110 i 1 op(5) Rn(4)`, `hw2 = 0 imm3 Rd imm8`, the
//! same bit positions as the sibling *modified* immediate group (A5.3.1) —
//! and that shared shape is the whole reason this table exists as a separate
//! one. Here the immediate is a **plain binary number**: `ThumbExpandImm` is
//! not applied, so `ADDW r0, r1, #0xFF` really does add 255 where the
//! modified-immediate `ADD.W r0, r1, #0xFF` would add `0x000000FF` only by
//! coincidence of the expansion rule, and `ADD.W r0, r1, #0x101` cannot be
//! encoded at all while `ADDW r0, r1, #0x101` can. The `hw1[9]` bit is the
//! only thing that tells the two tables apart.
//!
//! # What lives here
//!
//! | `op` | `Rn` | instruction | page |
//! |---|---|---|---|
//! | `00000` | not `1111` | `ADD (immediate)` T4 — `ADDW`, 12-bit | A7.7.3 |
//! | `00000` | `1111` | `ADR` T3, add form | A7.7.7 |
//! | `00100` | — | `MOV (immediate)` T3 — `MOVW`, 16-bit | A7.7.76 |
//! | `01010` | not `1111` | `SUB (immediate)` T4 — `SUBW`, 12-bit | A7.7.174 |
//! | `01010` | `1111` | `ADR` T2, subtract form | A7.7.7 |
//! | `01100` | — | `MOVT`, 16-bit into the top half | A7.7.79 |
//! | `10000`, `10010` | — | `SSAT` | A7.7.152 |
//! | `10010` with `hw2[14:12,7:6] == 0` | — | `SSAT16` (v7E-M) | A7.7.153 |
//! | `10100` | — | `SBFX` | A7.7.126 |
//! | `10110` | not `1111` | `BFI` | A7.7.14 |
//! | `10110` | `1111` | `BFC` | A7.7.13 |
//! | `11000`, `11010` | — | `USAT` | A7.7.213 |
//! | `11010` with `hw2[14:12,7:6] == 0` | — | `USAT16` (v7E-M) | A7.7.214 |
//! | `11100` | — | `UBFX` | A7.7.193 |
//!
//! Every other `op` — in particular every *odd* one, since bit 0 of `op` is
//! zero in all eleven allocated rows — is UNDEFINED and decodes to `None`.
//!
//! # Nothing here sets the flags
//!
//! Not one row has an `S` bit. `ADDW`/`SUBW` exist precisely *because* they
//! are the non-flag-setting wide add and subtract, complementing the
//! modified-immediate `ADDS.W`/`SUBS.W`; `SSAT`/`USAT` write `APSR.Q`, which
//! is not the `S`-suffix condition flags; the bitfield instructions write no
//! status at all. So [`Insn::sets_flags`] is `false` throughout, and
//! [`encode`] refuses any instruction that claims otherwise — `Display`
//! appends an `s` for a set `sets_flags`, and `addws` is not a mnemonic.
//!
//! # The three deliberate off-by-ones
//!
//! Three fields are printed by UAL one away from what the encoding holds, and
//! each is spelled out in the instruction's own pseudocode:
//!
//! * `SSAT` (A7.7.152): `saturate_to = UInt(sat_imm) + 1`, syntax range 1-32.
//!   `SSAT16` (A7.7.153) likewise, range 1-16 over a 4-bit field.
//! * `USAT` (A7.7.213): `saturate_to = UInt(sat_imm)`, syntax range **0-31** —
//!   no `+1`. The signed and unsigned saturates differ here, which is the
//!   single easiest thing in this table to get wrong, because the encodings
//!   are otherwise the same instruction with one opcode bit flipped.
//! * `SBFX`/`UBFX` (A7.7.126, A7.7.193): the field is `widthm1` and
//!   `<width> = widthm1 + 1`, syntax range 1-32.
//! * `BFI`/`BFC` (A7.7.14, A7.7.13): the encoding holds `lsb` and `msb`, but
//!   UAL writes `lsb` and `width`, with `msbit = <lsb> + <width> - 1`.
//!
//! # Should-be-zero bits
//!
//! The saturate and bitfield rows show `hw1[10]` (the `i` bit) and `hw2[5]`
//! as `(0)`, and `SSAT16`/`USAT16` additionally show `hw2[4]` as `(0)`.
//! [`decode`] ignores them — an image with one set is UNPREDICTABLE, not
//! undefined, and the instruction it denotes is still unambiguous — while
//! [`encode`] always emits zero. So `encode(decode(x))` is `x` for every
//! canonical encoding and is `x` with those bits cleared otherwise.
//!
//! # When `decode` refuses
//!
//! Exactly when the encoding has no representable UAL form: an unallocated
//! `op`, or a `BFI`/`BFC` with `msb < lsb`, whose `<width>` operand would be
//! zero or negative (the operation pseudocode calls that case UNPREDICTABLE).
//! Everything else decodes, *including* the UNPREDICTABLE register choices —
//! `Rd` or `Rn` of `1101`/`1111` is UNPREDICTABLE for most rows here, but it
//! still prints, and a disassembler that hides those bytes is less useful
//! than one that shows them.

use super::insn::{Operand, Operands, Reg, Shift, ShiftAmount, ShiftKind, Width};
use super::Insn;

/// The `Align(PC,4)` value of a Thumb instruction at `addr`.
///
/// Two rules compose here (A4.2.2): the PC value of a Thumb instruction is
/// its address **plus 4**, and `Align(PC,4)` is that ANDed with
/// `0xFFFFFFFC`. The alignment step only bites at odd halfword alignments, so
/// an `ADR` at `0x1000` and the identical `ADR` at `0x1002` resolve to the
/// *same* address — which is counter-intuitive and is why `ADR` gets its own
/// test below.
fn align_pc(addr: u32) -> u32 {
    addr.wrapping_add(4) & !3
}

/// Assemble one wide instruction from this group.
///
/// `cond` is always `None` and `sets_flags` always `false`: no encoding in
/// Table A5-12 carries a condition or an `S` bit. [`super::Decoder`] fills a
/// condition in afterwards when an `IT` block is in effect.
fn wide(
    mnemonic: &'static str,
    encoding: &'static str,
    addr: u32,
    explicit_width: bool,
    operands: Operands,
) -> Insn {
    Insn {
        mnemonic,
        encoding,
        addr,
        width: Width::Wide,
        cond: None,
        sets_flags: false,
        explicit_width,
        operands,
    }
}

/// Build the `ADR` T2/T3 form, resolving the pc-relative address.
///
/// The syntactic operand of `ADR` in UAL is a *label* (A7.7.7:
/// `ADR<c>.W <Rd>,<label>`), so the resolved address is the operand, carried
/// as [`Operand::Target`] — a consumer never has to redo, or even know about,
/// the `Align(PC,4)` arithmetic. `add` selects T3 (`op == 00000`) from T2
/// (`op == 01010`), and is kept in [`Insn::encoding`] rather than inferred
/// from the sign of the offset, because a zero offset is encodable both ways
/// and only the encoding name tells them apart.
///
/// One manual footnote does not survive this representation: A7.7.7 notes
/// that "the only possible syntax for encoding T2 with all immediate bits
/// zero is `SUB <Rd>,PC,#0`", since `ADR.W <Rd>,<label>` at a zero offset
/// assembles as T3. That is a fact about re-assembling the *text*; this
/// crate's [`encode`] reads [`Insn::encoding`] and reproduces the original
/// bits either way.
fn adr(addr: u32, rd: Reg, add: bool, imm32: u32) -> Insn {
    let base = align_pc(addr);
    let target = if add {
        base.wrapping_add(imm32)
    } else {
        base.wrapping_sub(imm32)
    };
    wide(
        "adr",
        if add { "T3" } else { "T2" },
        addr,
        // A7.7.7 spells the wide forms `ADR<c>.W`; the 16-bit T1 `ADR` exists
        // too, so the suffix is load-bearing for re-assembly.
        true,
        [Operand::Reg(rd), Operand::Target(target)]
            .into_iter()
            .collect(),
    )
}

/// Decode an instruction in this group, or `None` if `hw1`/`hw2` do not
/// belong to it.
pub(crate) fn decode(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 >> 11 != 0b11110 || (hw1 >> 9) & 1 != 1 || hw2 & 0x8000 != 0 {
        return None;
    }

    let i = (hw1 >> 10) & 1;
    let op = (hw1 >> 4) & 0x1F;
    let rn = Reg((hw1 & 0xF) as u8);
    let imm3 = (hw2 >> 12) & 7;
    let rd = Reg(((hw2 >> 8) & 0xF) as u8);
    let imm2 = (hw2 >> 6) & 3;
    let imm8 = hw2 & 0xFF;
    // `hw2[4:0]` is `sat_imm` for the saturates, `widthm1` for the bitfield
    // extracts and `msb` for the bitfield insert and clear — one position,
    // three meanings, never more than five bits.
    let tail = hw2 & 0x1F;
    // The 12-bit plain immediate, `i:imm3:imm8` (0-4095), and the 16-bit one,
    // `imm4:i:imm3:imm8`, whose top nibble is the *`Rn` field position*.
    let imm12 = i64::from((i << 11) | (imm3 << 8) | imm8);
    let imm16 = imm12 | (i64::from(hw1 & 0xF) << 12);
    // `imm3:imm2` — the shift amount for `SSAT`/`USAT`, the `lsb` for the
    // four bitfield instructions.
    let five = (imm3 << 2) | imm2;

    let three = |a: Reg, b: Reg, v: i64| -> Operands {
        [Operand::Reg(a), Operand::Reg(b), Operand::Imm(v)]
            .into_iter()
            .collect()
    };

    Some(match op {
        // `00000` with `Rn == 1111`: A7.7.3's T4 pseudocode opens with
        // `if Rn == '1111' then SEE ADR`.
        0b00000 if rn == Reg::PC => adr(addr, rd, true, imm12 as u32),
        // `ADDW <Rd>, <Rn>, #<imm12>` (A7.7.3 T4). UAL's own note: T3 is
        // preferred where both fit, "if encoding T4 is required, use the ADDW
        // syntax" — so the mnemonic is spelled `addw` rather than `add` with
        // an `explicit_width` of `.w`, which would name T3 and re-assemble to
        // different bits (or fail outright for an immediate no modified
        // immediate can express).
        //
        // `Rn == 1101` is not a separate mnemonic: A7.7.3 says `SEE ADD (SP
        // plus immediate)`, and that page's T4 (A7.7.5) is the same bits with
        // the same syntax, `ADDW <Rd>,SP,#<imm12>`. It is a distinct page
        // only because it relaxes the UNPREDICTABLE rule — `ADDW sp, sp, #n`
        // is legal where `ADDW r13, r1, #n` is not.
        0b00000 => wide("addw", "T4", addr, false, three(rd, rn, imm12)),
        // `MOVW <Rd>, #<imm16>` (A7.7.76 T3) — the only 16-bit plain
        // immediate in Thumb, assembled `imm4:i:imm3:imm8`.
        0b00100 => wide(
            "movw",
            "T3",
            addr,
            false,
            [Operand::Reg(rd), Operand::Imm(imm16)]
                .into_iter()
                .collect(),
        ),
        // `01010` with `Rn == 1111` is the subtracting `ADR` (A7.7.174 T4:
        // `if Rn == '1111' then SEE ADR`).
        0b01010 if rn == Reg::PC => adr(addr, rd, false, imm12 as u32),
        // `SUBW <Rd>, <Rn>, #<imm12>`. The encoding name is T4 on A7.7.174
        // but **T3** on A7.7.176, `SUB (SP minus immediate)`, which has one
        // fewer 32-bit encoding: there is no 16-bit `SUB <Rd>,SP,#<imm8>` to
        // occupy T1, so every wide encoding shifts down by one. (A7.7.176's
        // prose line still says "Only encoding T4 permitted", contradicting
        // its own encoding diagram; the diagram is what the bits say.)
        0b01010 => wide(
            "subw",
            if rn == Reg::SP { "T3" } else { "T4" },
            addr,
            false,
            three(rd, rn, imm12),
        ),
        // `MOVT <Rd>, #<imm16>` (A7.7.79). `R[d]<31:16> = imm16` and
        // `R[d]<15:0>` is *unchanged* — that is the whole instruction, and it
        // is what makes `MOVW` then `MOVT` the pool-free way to materialise
        // an arbitrary 32-bit constant in two instructions. A consumer that
        // models `MOVT` as a full-register write gets the low half wrong.
        0b01100 => wide(
            "movt",
            "T1",
            addr,
            false,
            [Operand::Reg(rd), Operand::Imm(imm16)]
                .into_iter()
                .collect(),
        ),
        // The four saturate rows. `op` bit 3 selects unsigned, `op` bit 1 is
        // the `sh` bit of the shift type (`sh:'0'` fed to `DecodeImmShift`,
        // A7.4.2 — so `0` is `LSL` and `1` is `ASR`, and `LSR`/`ROR`/`RRX`
        // are unreachable here).
        0b10000 | 0b10010 | 0b11000 | 0b11010 => {
            let signed = op & 0b01000 == 0;
            let asr = op & 0b00010 != 0;
            if asr && five == 0 {
                // `sh == 1 && imm3:imm2 == 00000` is the v7E-M pair form
                // (A7.7.152: `if sh == '1' && (imm3:imm2) == '00000' then …
                // SEE SSAT16`). Its `sat_imm` is only four bits wide.
                let sat = i64::from(hw2 & 0xF) + i64::from(signed);
                wide(
                    if signed { "ssat16" } else { "usat16" },
                    "T1",
                    addr,
                    false,
                    [Operand::Reg(rd), Operand::Imm(sat), Operand::Reg(rn)]
                        .into_iter()
                        .collect(),
                )
            } else {
                // `SSAT` saturates to `UInt(sat_imm) + 1` bits, `USAT` to
                // `UInt(sat_imm)`. Same field, different meaning.
                let sat = i64::from(tail) + i64::from(signed);
                // UAL omits an `LSL #0`, so that case is a bare register;
                // `ASR #0` never arises, having been claimed by `SSAT16`.
                let source = if asr || five != 0 {
                    Operand::RegShifted(
                        rn,
                        Shift {
                            kind: if asr { ShiftKind::Asr } else { ShiftKind::Lsl },
                            amount: ShiftAmount::Imm(five as u8),
                        },
                    )
                } else {
                    Operand::Reg(rn)
                };
                wide(
                    if signed { "ssat" } else { "usat" },
                    "T1",
                    addr,
                    false,
                    [Operand::Reg(rd), Operand::Imm(sat), source]
                        .into_iter()
                        .collect(),
                )
            }
        }
        // `SBFX`/`UBFX <Rd>, <Rn>, #<lsb>, #<width>`. `widthm1` is one less
        // than the printed width. A `lsb + width > 32` encoding is
        // UNPREDICTABLE (`msbit <= 31` in the pseudocode) but still decodes:
        // both printed operands are exactly the encoded fields, so the text
        // is faithful and the round-trip is exact.
        0b10100 | 0b11100 => wide(
            if op == 0b10100 { "sbfx" } else { "ubfx" },
            "T1",
            addr,
            false,
            [
                Operand::Reg(rd),
                Operand::Reg(rn),
                Operand::Imm(i64::from(five)),
                Operand::Imm(i64::from(tail) + 1),
            ]
            .into_iter()
            .collect(),
        ),
        // `BFI`/`BFC`. The encoding holds `lsb` and `msb`; UAL prints `lsb`
        // and `width = msb - lsb + 1`. An `msb < lsb` encoding is
        // UNPREDICTABLE (both operation pseudocodes branch to it explicitly)
        // and has no UAL spelling at all — `<width>` is documented as being
        // in the range 1 to 32-<lsb> — so it is refused rather than printed
        // with a zero or negative width no assembler would accept.
        0b10110 => {
            if tail < five {
                return None;
            }
            let width = i64::from(tail) - i64::from(five) + 1;
            if rn == Reg::PC {
                // A7.7.14: `if Rn == '1111' then SEE BFC`.
                wide(
                    "bfc",
                    "T1",
                    addr,
                    false,
                    [
                        Operand::Reg(rd),
                        Operand::Imm(i64::from(five)),
                        Operand::Imm(width),
                    ]
                    .into_iter()
                    .collect(),
                )
            } else {
                wide(
                    "bfi",
                    "T1",
                    addr,
                    false,
                    [
                        Operand::Reg(rd),
                        Operand::Reg(rn),
                        Operand::Imm(i64::from(five)),
                        Operand::Imm(width),
                    ]
                    .into_iter()
                    .collect(),
                )
            }
        }
        // Every remaining `op`, which is every odd one plus `00010`, `00110`,
        // `01000`, `01110`, `10001`-style holes and `11110`: UNDEFINED.
        _ => return None,
    })
}

/// The register number in a [`Operand::Reg`], or `None` for any other operand.
fn reg(op: Option<Operand>) -> Option<u16> {
    // Matched on the `Option` rather than opened with `op?`: every caller
    // reads a slot the arity in [`encode`]'s match key has already fixed, so
    // a separate `None` branch here could never run. One wildcard covers
    // "absent" and "not a register" alike, and it does run.
    match op {
        Some(Operand::Reg(r)) => Some(u16::from(r.num())),
        _ => None,
    }
}

/// The value of an [`Operand::Imm`], or `None` for any other operand.
fn imm_val(op: Option<Operand>) -> Option<i64> {
    // One wildcard for "absent" and "not an immediate"; see [`reg`].
    match op {
        Some(Operand::Imm(v)) => Some(v),
        _ => None,
    }
}

/// An unsigned immediate operand, range-checked against `max`.
fn uimm(op: Option<Operand>, max: i64) -> Option<u16> {
    let v = imm_val(op)?;
    if (0..=max).contains(&v) {
        Some(v as u16)
    } else {
        None
    }
}

/// Encode a `SSAT`/`USAT`/`SSAT16`/`USAT16` saturation position back to its
/// `sat_imm` field: `signed` forms print one greater than they encode
/// (A7.7.152, A7.7.153), unsigned forms print exactly what they encode
/// (A7.7.213, A7.7.214).
fn sat_field(op: Option<Operand>, signed: bool, max: i64) -> Option<u16> {
    let v = imm_val(op)?;
    let min = i64::from(signed);
    if !(min..=max).contains(&v) {
        return None;
    }
    Some((v - min) as u16)
}

/// Split the saturated source operand of `SSAT`/`USAT` into its register, its
/// `sh` bit and its shift amount.
///
/// A bare register is `LSL #0`; a shift of zero written explicitly is
/// rejected, so that the canonical spelling is the only one that encodes —
/// and an `ASR #0` would in any case collide with `SSAT16`.
fn sat_source(op: Option<Operand>) -> Option<(u16, u16, u16)> {
    // One wildcard for "absent" and "not a source register"; see [`reg`].
    match op {
        Some(Operand::Reg(r)) => Some((u16::from(r.num()), 0, 0)),
        Some(Operand::RegShifted(r, s)) => {
            let amount = match s.amount {
                ShiftAmount::Imm(n) => u16::from(n),
                ShiftAmount::Reg(_) => return None,
            };
            let sh = match s.kind {
                ShiftKind::Lsl => 0,
                ShiftKind::Asr => 1,
                _ => return None,
            };
            if amount == 0 || amount > 31 {
                return None;
            }
            Some((u16::from(r.num()), sh, amount))
        }
        _ => None,
    }
}

/// Lay out one of the plain-12-bit rows: `hw1 = 11110 i 1 op Rn`,
/// `hw2 = 0 imm3 Rd imm8`, with `imm12 = i:imm3:imm8`.
///
/// `MOVW`/`MOVT` reuse this by passing their `imm4` as `rn` — that reuse of
/// the `Rn` slot as the top nibble of a 16-bit immediate is the encoding's
/// one genuine surprise, and putting it here keeps it stated once.
fn plain12(op: u16, rn: u16, rd: u16, imm12: u16) -> (u16, u16) {
    (
        0xF200 | ((imm12 >> 11) << 10) | (op << 4) | rn,
        (((imm12 >> 8) & 7) << 12) | (rd << 8) | (imm12 & 0xFF),
    )
}

/// Lay out one of the saturate or bitfield rows: `hw1 = 11110 (0) 1 op Rn`,
/// `hw2 = 0 imm3 Rd imm2 (0) tail`, where `five` is the `imm3:imm2` pair
/// (a shift amount or an `lsb`) and `tail` is `sat_imm`/`widthm1`/`msb`.
///
/// Both `(0)` bits are emitted as zero, which is what the architecture asks
/// of an assembler.
fn field_form(op: u16, rn: u16, rd: u16, five: u16, tail: u16) -> (u16, u16) {
    (
        0xF200 | (op << 4) | rn,
        ((five >> 2) << 12) | (rd << 8) | ((five & 3) << 6) | tail,
    )
}

/// Re-encode an instruction this module decoded, back to its two halfwords.
///
/// Returns `None` for anything this group cannot express. That includes the
/// forms whose mnemonic it shares with no one — `addw`, `movt`, `sbfx` and
/// friends are unique to Table A5-12 — and, importantly, the *neighbouring*
/// readings of its own rows: an `addw` naming `pc` is really an `ADR`, a
/// `bfi` naming `pc` is really a `BFC`, and both are refused so that each
/// encoding has exactly one `Insn` that produces it.
///
/// `insn.addr` is read for the `ADR` forms, whose operand is an absolute
/// target that only means something relative to `Align(PC,4)`.
// `allow`: nothing in `super` dispatches re-encoding yet, so from the lib
// target's point of view this and its helpers are unreachable. The tests
pub(crate) fn encode(insn: &Insn) -> Option<(u16, u16)> {
    // No row here has an `S` bit, and all of them are 32-bit.
    if insn.width != Width::Wide || insn.sets_flags {
        return None;
    }
    let ops = &insn.operands;
    let (a, b, c, d) = (ops.get(0), ops.get(1), ops.get(2), ops.get(3));

    match (insn.mnemonic, insn.encoding, ops.len()) {
        // `ADDW <Rd>, <Rn>, #<imm12>` — `Rn == 1111` belongs to `ADR` T3.
        ("addw", "T4", 3) => {
            let rn = reg(b)?;
            if rn == 15 {
                return None;
            }
            Some(plain12(0b00000, rn, reg(a)?, uimm(c, 4095)?))
        }
        // `SUBW <Rd>, <Rn>, #<imm12>` — T3 is the `SP` page's name for these
        // bits and T4 every other register's, so the two must agree or the
        // `Insn` did not come from here.
        ("subw", "T4", 3) | ("subw", "T3", 3) => {
            let rn = reg(b)?;
            if rn == 15 || (rn == 13) != (insn.encoding == "T3") {
                return None;
            }
            Some(plain12(0b01010, rn, reg(a)?, uimm(c, 4095)?))
        }
        // `ADR<c>.W <Rd>, <label>`. The offset is recovered from the target
        // and the instruction's own `Align(PC,4)`; T3 adds it, T2 subtracts.
        ("adr", "T3", 2) | ("adr", "T2", 2) => {
            let add = insn.encoding == "T3";
            // `b` is matched as an `Option`: the arity in the match key
            // above already guarantees it is present, so a `?` here would be
            // a branch nothing can take.
            let target = match b {
                Some(Operand::Target(t)) => t,
                _ => return None,
            };
            let base = align_pc(insn.addr);
            let off = if add {
                target.wrapping_sub(base)
            } else {
                base.wrapping_sub(target)
            };
            if off > 4095 {
                return None;
            }
            Some(plain12(
                if add { 0b00000 } else { 0b01010 },
                15,
                reg(a)?,
                off as u16,
            ))
        }
        // `MOVW`/`MOVT <Rd>, #<imm16>` — the top nibble goes in the `Rn`
        // field, the rest through the ordinary 12-bit path.
        ("movw", "T3", 2) | ("movt", "T1", 2) => {
            let imm = uimm(b, 0xFFFF)?;
            let op = if insn.mnemonic == "movw" {
                0b00100
            } else {
                0b01100
            };
            Some(plain12(op, imm >> 12, reg(a)?, imm & 0xFFF))
        }
        // `SSAT`/`USAT <Rd>, #<imm>, <Rn> {,<shift>}`.
        ("ssat", "T1", 3) | ("usat", "T1", 3) => {
            let signed = insn.mnemonic == "ssat";
            let sat = sat_field(b, signed, if signed { 32 } else { 31 })?;
            let (rn, sh, amount) = sat_source(c)?;
            let op = 0b10000 | (if signed { 0 } else { 0b01000 }) | (sh << 1);
            Some(field_form(op, rn, reg(a)?, amount, sat))
        }
        // `SSAT16`/`USAT16 <Rd>, #<imm>, <Rn>` — `sh == 1`, no shift, and a
        // `sat_imm` only four bits wide.
        ("ssat16", "T1", 3) | ("usat16", "T1", 3) => {
            let signed = insn.mnemonic == "ssat16";
            let sat = sat_field(b, signed, if signed { 16 } else { 15 })?;
            let op = 0b10010 | (if signed { 0 } else { 0b01000 });
            Some(field_form(op, reg(c)?, reg(a)?, 0, sat))
        }
        // `SBFX`/`UBFX <Rd>, <Rn>, #<lsb>, #<width>` — `widthm1 = width - 1`.
        ("sbfx", "T1", 4) | ("ubfx", "T1", 4) => {
            let lsb = uimm(c, 31)?;
            let width = imm_val(d)?;
            if !(1..=32).contains(&width) {
                return None;
            }
            let op = if insn.mnemonic == "sbfx" {
                0b10100
            } else {
                0b11100
            };
            Some(field_form(op, reg(b)?, reg(a)?, lsb, (width - 1) as u16))
        }
        // `BFI <Rd>, <Rn>, #<lsb>, #<width>` — `msb = lsb + width - 1`, and
        // `Rn == 1111` would be a `BFC`.
        ("bfi", "T1", 4) => {
            let rn = reg(b)?;
            let lsb = uimm(c, 31)?;
            let msb = i64::from(lsb) + imm_val(d)? - 1;
            if rn == 15 || !(i64::from(lsb)..=31).contains(&msb) {
                return None;
            }
            Some(field_form(0b10110, rn, reg(a)?, lsb, msb as u16))
        }
        // `BFC <Rd>, #<lsb>, #<width>`.
        ("bfc", "T1", 3) => {
            let lsb = uimm(b, 31)?;
            let msb = i64::from(lsb) + imm_val(c)? - 1;
            if !(i64::from(lsb)..=31).contains(&msb) {
                return None;
            }
            Some(field_form(0b10110, 15, reg(a)?, lsb, msb as u16))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{align_pc, decode, encode};
    use crate::isa::{decode_halfwords, Insn, Operand, Operands, Reg, Width};

    /// The eleven `op` values Table A5-12 allocates. Every other value in the
    /// five-bit field is UNDEFINED.
    const ALLOCATED: [u16; 11] = [
        0b00000, 0b00100, 0b01010, 0b01100, 0b10000, 0b10010, 0b10100, 0b10110, 0b11000, 0b11010,
        0b11100,
    ];

    /// The canonical spelling of `(hw1, hw2)`: the same encoding with every
    /// SHOULD-BE-ZERO `(0)` bit of its row cleared.
    ///
    /// The saturate and bitfield rows show `hw1[10]` (the `i` bit, which they
    /// have no immediate to put there) and `hw2[5]` as `(0)`; `SSAT16` and
    /// `USAT16` show `hw2[4]` as `(0)` as well, their `sat_imm` being four
    /// bits rather than five. `decode` ignores all of them and `encode`
    /// writes zero, so this is exactly what a round-trip must produce.
    fn canonical(hw1: u16, hw2: u16) -> (u16, u16) {
        let op = (hw1 >> 4) & 0x1F;
        let mut h1 = hw1;
        let mut h2 = hw2;
        if op >= 0b10000 {
            h1 &= !0x0400;
            h2 &= !0x0020;
        }
        // `hw2[14:12] == 0 && hw2[7:6] == 0` with `sh == 1` is the pair form.
        if (op == 0b10010 || op == 0b11010) && hw2 & 0x70C0 == 0 {
            h2 &= !0x0010;
        }
        (h1, h2)
    }

    /// A systematic sweep of the whole group: both values of `i`, all 32
    /// values of `op`, all 16 values of `Rn` (so `1111` and `1101` are
    /// covered for every row), against a spread of `hw2` that hits 0, 1,
    /// maximum and maximum-1 for `imm3`, `Rd`, `imm2` and the five-bit tail,
    /// and the byte boundaries of `imm8`.
    ///
    /// Anything that decodes must re-encode to its canonical bits.
    #[test]
    fn systematic_round_trip() {
        const IMM3: [u16; 4] = [0, 1, 6, 7];
        const RD: [u16; 6] = [0, 1, 7, 8, 14, 15];
        // Chosen so that, read as `imm8`, these are 0/1/max-1/max; read as
        // `imm2:(0):tail`, they cover every `imm2` against a tail of
        // 0/1/30/31; and the `(0)` bit at position 5 is set in half of them.
        const LOW8: [u16; 16] = [
            0x00, 0x01, 0x1E, 0x1F, 0x20, 0x3F, 0x40, 0x41, 0x5E, 0x7F, 0x80, 0x9F, 0xC0, 0xDE,
            0xFE, 0xFF,
        ];

        let mut seen = [0u32; 32];
        for i in 0..2u16 {
            for op in 0..32u16 {
                for rn in 0..16u16 {
                    let hw1 = 0xF200 | (i << 10) | (op << 4) | rn;
                    for imm3 in IMM3 {
                        for rd in RD {
                            for low in LOW8 {
                                let hw2 = (imm3 << 12) | (rd << 8) | low;
                                let insn = match decode(hw1, hw2, 0x1000) {
                                    Some(x) => x,
                                    None => continue,
                                };
                                seen[op as usize] += 1;
                                assert_eq!(insn.width, Width::Wide, "{hw1:#06x} {hw2:#06x}");
                                assert!(
                                    !insn.sets_flags,
                                    "{hw1:#06x} {hw2:#06x} would print as `{}s`",
                                    insn.mnemonic
                                );
                                assert_eq!(insn.addr, 0x1000);
                                assert_eq!(
                                    encode(&insn),
                                    Some(canonical(hw1, hw2)),
                                    "{hw1:#06x} {hw2:#06x} decoded as `{insn}` but did not \
                                     re-encode"
                                );
                            }
                        }
                    }
                }
            }
        }

        for (op, &count) in seen.iter().enumerate() {
            let allocated = ALLOCATED.contains(&(op as u16));
            // Bound rather than recomputed inside the message: a format
            // argument is evaluated only when the assertion fails, which is a
            // region no passing run reaches.
            let negation = if allocated { "" } else { "not " };
            assert_eq!(
                count > 0,
                allocated,
                "op {op:#07b} is {negation}allocated in Table A5-12"
            );
        }
    }

    /// The dispatcher must route this whole group here — `hw1[15:11]` of
    /// `11110`, `hw1[9]` set and `hw2[15]` clear — and `decode` must refuse
    /// everything else.
    #[test]
    fn dispatch_boundary() {
        for op in ALLOCATED {
            let hw1 = 0xF200 | (op << 4) | 1;
            let hw2 = 0x0102;
            assert_eq!(
                decode_halfwords(hw1, hw2, 0x1000, false),
                decode(hw1, hw2, 0x1000),
                "{hw1:#06x} is not reaching t32_dp_plainimm"
            );
            // `hw1[9] == 0` is the modified-immediate table, A5.3.1.
            assert!(decode(hw1 & !0x0200, hw2, 0).is_none());
            // `hw2[15] == 1` is the branch and miscellaneous table, A5.3.4.
            assert!(decode(hw1, hw2 | 0x8000, 0).is_none());
        }
        // A 16-bit halfword, and the other two 32-bit prefixes.
        assert!(decode(0x4770, 0, 0).is_none());
        assert!(decode(0xE800, 0x0102, 0).is_none());
        assert!(decode(0xFA00, 0x0102, 0).is_none());
    }

    /// `MOVW` and `MOVT` assemble their 16-bit immediate as
    /// `imm4:i:imm3:imm8`, where `imm4` sits in the **`Rn` field**
    /// (`hw1[3:0]`) — the one place this table reuses a register slot as
    /// immediate bits.
    ///
    /// The constants are chosen so that all four fields differ: `0xBEEF` is
    /// `imm4 = 0xB`, `i = 1`, `imm3 = 0b110`, `imm8 = 0xEF`, and `0x1234` is
    /// `imm4 = 0x1`, `i = 0`, `imm3 = 0b010`, `imm8 = 0x34`. Any transposition
    /// of the four fields changes the value.
    #[test]
    fn movw_movt_immediate_field_order() {
        // 1111 0 1 1 00100 1011 | 0 110 0011 1110 1111
        let insn = decode(0xF64B, 0x63EF, 0).unwrap();
        assert_eq!(insn.mnemonic, "movw");
        assert_eq!(insn.encoding, "T3");
        assert_eq!(insn.operands.get(1), Some(Operand::Imm(0xBEEF)));
        assert_eq!(insn.to_string(), "movw r3, #0xbeef");
        assert_eq!(encode(&insn), Some((0xF64B, 0x63EF)));

        // 1111 0 0 1 01100 0001 | 0 010 0011 0011 0100
        let insn = decode(0xF2C1, 0x2334, 0).unwrap();
        assert_eq!(insn.mnemonic, "movt");
        assert_eq!(insn.encoding, "T1");
        assert_eq!(insn.operands.get(1), Some(Operand::Imm(0x1234)));
        assert_eq!(insn.to_string(), "movt r3, #0x1234");
        assert_eq!(encode(&insn), Some((0xF2C1, 0x2334)));

        // Each field's weight, checked by flipping it alone. The `i` bit is
        // worth 0x800 and the `imm4` nibble sitting in the `Rn` slot is worth
        // 0x1000 a step — which is exactly what `imm4:i:imm3:imm8` claims and
        // what any other concatenation would get wrong.
        let movw = decode(0xF64B, 0x63EF, 0).unwrap();
        assert_eq!(movw.operands.get(1), Some(Operand::Imm(0xBEEF)));
        let no_i = decode(0xF64B & !0x0400, 0x63EF, 0).unwrap();
        assert_eq!(no_i.operands.get(1), Some(Operand::Imm(0xBEEF - 0x800)));
        let no_imm4 = decode(0xF640, 0x63EF, 0).unwrap();
        assert_eq!(no_imm4.operands.get(1), Some(Operand::Imm(0xBEEF - 0xB000)));
        let no_imm3 = decode(0xF64B, 0x03EF, 0).unwrap();
        assert_eq!(no_imm3.operands.get(1), Some(Operand::Imm(0xBEEF - 0x600)));

        // Walk a single set bit through all sixteen positions: each must land
        // in the field the spec names and come back out at the same weight.
        for bit in 0..16u32 {
            let v = 1u32 << bit;
            let (imm4, i, imm3, imm8) = (v >> 12, (v >> 11) & 1, (v >> 8) & 7, v & 0xFF);
            let hw1 = 0xF240 | ((i as u16) << 10) | (imm4 as u16);
            let hw2 = ((imm3 as u16) << 12) | (imm8 as u16);
            let insn = decode(hw1, hw2, 0).unwrap();
            assert_eq!(insn.mnemonic, "movw");
            assert_eq!(
                insn.operands.get(1),
                Some(Operand::Imm(i64::from(v))),
                "bit {bit} of a MOVW immediate"
            );
            assert_eq!(encode(&insn), Some((hw1, hw2)));
        }
    }

    /// `ADR` resolves against `Align(PC,4)`, not `PC` (A7.7.7:
    /// `result = if add then (Align(PC,4) + imm32) else (Align(PC,4) -
    /// imm32)`), and a Thumb `PC` is the instruction's address plus 4
    /// (A4.2.2). So the *same bits* at `0x1000` and at `0x1002` resolve to
    /// the same address: `0x1004` and `0x1006` both align down to `0x1004`.
    #[test]
    fn adr_resolves_against_aligned_pc() {
        assert_eq!(align_pc(0x1000), 0x1004);
        assert_eq!(align_pc(0x1002), 0x1004);
        assert_eq!(align_pc(0x1004), 0x1008);
        assert_eq!(align_pc(0x1006), 0x1008);

        // T3, the add form: 1111 0 0 1 00000 1111 | 0 000 0000 0001 0000
        for &addr in &[0x1000u32, 0x1002] {
            let insn = decode(0xF20F, 0x0010, addr).unwrap();
            assert_eq!(insn.mnemonic, "adr");
            assert_eq!(insn.encoding, "T3");
            assert!(insn.explicit_width);
            assert_eq!(insn.branch_target(), Some(0x1014), "at {addr:#x}");
            assert_eq!(insn.to_string(), "adr.w r0, 0x1014");
            assert_eq!(encode(&insn), Some((0xF20F, 0x0010)), "at {addr:#x}");
        }

        // T2, the subtract form: 1111 0 0 1 01010 1111 | 0 000 0001 0010 0000
        for &addr in &[0x1000u32, 0x1002] {
            let insn = decode(0xF2AF, 0x0120, addr).unwrap();
            assert_eq!(insn.mnemonic, "adr");
            assert_eq!(insn.encoding, "T2");
            assert_eq!(insn.branch_target(), Some(0x0FE4), "at {addr:#x}");
            assert_eq!(insn.to_string(), "adr.w r1, 0xfe4");
            assert_eq!(encode(&insn), Some((0xF2AF, 0x0120)), "at {addr:#x}");
        }

        // The next word up really is a different answer — the alignment is
        // collapsing pairs of halfwords, not ignoring the address.
        assert_eq!(
            decode(0xF20F, 0x0010, 0x1004).unwrap().branch_target(),
            Some(0x1018)
        );

        // A zero offset is encodable both ways, and only `Insn::encoding`
        // tells the two apart. Both resolve to `Align(PC,4)` itself.
        let add0 = decode(0xF20F, 0x0000, 0x1000).unwrap();
        let sub0 = decode(0xF2AF, 0x0000, 0x1000).unwrap();
        assert_eq!(add0.branch_target(), sub0.branch_target());
        assert_eq!(add0.branch_target(), Some(0x1004));
        assert_eq!(encode(&add0), Some((0xF20F, 0x0000)));
        assert_eq!(encode(&sub0), Some((0xF2AF, 0x0000)));

        // Both directions reach their full 0-4095 range.
        let far = decode(0xF60F, 0x70FF, 0x1000).unwrap();
        assert_eq!(far.branch_target(), Some(0x1004 + 4095));
        let back = decode(0xF6AF, 0x70FF, 0x1000).unwrap();
        assert_eq!(back.branch_target(), Some(0x1004 - 4095));
    }

    /// The five fields UAL prints differently from how they are encoded, one
    /// hand-computed vector each, derived from the syntax and pseudocode of
    /// the instruction's own page.
    #[test]
    fn fields_ual_prints_differently_from_the_encoding() {
        // `SSAT` (A7.7.152): `saturate_to = UInt(sat_imm) + 1`, range 1-32.
        // sat_imm = 0 is `#1`, not `#0`.
        let insn = decode(0xF301, 0x0000, 0).unwrap();
        assert_eq!(insn.to_string(), "ssat r0, #1, r1");
        assert_eq!(insn.operands.get(1), Some(Operand::Imm(1)));
        assert_eq!(encode(&insn), Some((0xF301, 0x0000)));
        // ... and sat_imm = 31 is `#32`, the top of the documented range.
        let insn = decode(0xF301, 0x001F, 0).unwrap();
        assert_eq!(insn.to_string(), "ssat r0, #0x20, r1");

        // `USAT` (A7.7.213): `saturate_to = UInt(sat_imm)`, range 0-31 — the
        // *same field* with no `+1`. This is the asymmetry.
        let insn = decode(0xF381, 0x0000, 0).unwrap();
        assert_eq!(insn.to_string(), "usat r0, #0, r1");
        assert_eq!(insn.operands.get(1), Some(Operand::Imm(0)));
        let insn = decode(0xF381, 0x001F, 0).unwrap();
        assert_eq!(insn.to_string(), "usat r0, #0x1f, r1");

        // `SSAT16` keeps the `+1` over a four-bit field (range 1-16);
        // `USAT16` keeps the absence of it (range 0-15).
        assert_eq!(
            decode(0xF321, 0x0000, 0).unwrap().to_string(),
            "ssat16 r0, #1, r1"
        );
        assert_eq!(
            decode(0xF3A1, 0x0000, 0).unwrap().to_string(),
            "usat16 r0, #0, r1"
        );

        // `SBFX` (A7.7.126): `widthm1` is one less than `<width>`. Here
        // lsb = imm3:imm2 = 0b001:0b01 = 5 and widthm1 = 7, so `#5, #8`.
        let insn = decode(0xF341, 0x1047, 0).unwrap();
        assert_eq!(insn.to_string(), "sbfx r0, r1, #5, #8");
        assert_eq!(insn.operands.get(2), Some(Operand::Imm(5)));
        assert_eq!(insn.operands.get(3), Some(Operand::Imm(8)));
        assert_eq!(encode(&insn), Some((0xF341, 0x1047)));

        // `UBFX` (A7.7.193): widthm1 = 31 is the whole register.
        let insn = decode(0xF3C1, 0x001F, 0).unwrap();
        assert_eq!(insn.to_string(), "ubfx r0, r1, #0, #0x20");
        assert_eq!(insn.operands.get(3), Some(Operand::Imm(32)));

        // `BFI` (A7.7.14): the encoding holds `msb`, UAL prints `width`.
        // lsb = 0b001:0b00 = 4, msb = 15, so `<width> = 15 - 4 + 1 = 12`.
        let insn = decode(0xF361, 0x100F, 0).unwrap();
        assert_eq!(insn.to_string(), "bfi r0, r1, #4, #0xc");
        assert_eq!(insn.operands.get(2), Some(Operand::Imm(4)));
        assert_eq!(insn.operands.get(3), Some(Operand::Imm(12)));
        assert_eq!(encode(&insn), Some((0xF361, 0x100F)));
    }

    /// One printed line per row of Table A5-12, in table order, each spelled
    /// as the `Assembler syntax` section of its instruction page spells it.
    #[test]
    fn ual_per_table_row() {
        let cases: &[(u16, u16, &str)] = &[
            // 00000 / Rn != 1111 — `ADDW<c> <Rd>,<Rn>,#<imm12>` (A7.7.3 T4).
            // imm12 = 0x123 = i 0, imm3 0b001, imm8 0x23.
            (0xF201, 0x1023, "addw r0, r1, #0x123"),
            // ... and its `SP` spelling, A7.7.5 T4.
            (0xF20D, 0x1D00, "addw sp, sp, #0x100"),
            // 00000 / Rn == 1111 — `ADR<c>.W <Rd>,<label>` (A7.7.7 T3).
            (0xF20F, 0x0010, "adr.w r0, 0x1014"),
            // 00100 — `MOVW<c> <Rd>,#<imm16>` (A7.7.76 T3).
            (0xF64B, 0x63EF, "movw r3, #0xbeef"),
            // 01010 / Rn != 1111 — `SUBW<c> <Rd>,<Rn>,#<imm12>` (A7.7.174).
            (0xF6A3, 0x72FF, "subw r2, r3, #0xfff"),
            // ... and the `SP` spelling, A7.7.176, whose diagram calls these
            // bits T3.
            (0xF6AD, 0x7DFF, "subw sp, sp, #0xfff"),
            // 01010 / Rn == 1111 — `ADR<c>.W <Rd>,<label>` (A7.7.7 T2).
            (0xF2AF, 0x0120, "adr.w r1, 0xfe4"),
            // 01100 — `MOVT<c> <Rd>,#<imm16>` (A7.7.79 T1).
            (0xF2C1, 0x2334, "movt r3, #0x1234"),
            // 10000 — `SSAT<c> <Rd>,#<imm5>,<Rn>{,<shift>}` (A7.7.152).
            (0xF301, 0x10D7, "ssat r0, #0x18, r1, lsl #7"),
            (0xF301, 0x0000, "ssat r0, #1, r1"),
            // 10010 with a non-zero imm3:imm2 — the `ASR` half of `SSAT`.
            (0xF321, 0x101F, "ssat r0, #0x20, r1, asr #4"),
            // 10010 with imm3:imm2 == 0 — `SSAT16<c> <Rd>,#<imm>,<Rn>`.
            (0xF321, 0x000F, "ssat16 r0, #0x10, r1"),
            // 10100 — `SBFX<c> <Rd>,<Rn>,#<lsb>,#<width>` (A7.7.126).
            (0xF341, 0x1047, "sbfx r0, r1, #5, #8"),
            // 10110 / Rn != 1111 — `BFI<c> <Rd>,<Rn>,#<lsb>,#<width>`.
            (0xF361, 0x100F, "bfi r0, r1, #4, #0xc"),
            // 10110 / Rn == 1111 — `BFC<c> <Rd>,#<lsb>,#<width>`.
            (0xF36F, 0x200B, "bfc r0, #8, #4"),
            // 11000 — `USAT<c> <Rd>,#<imm5>,<Rn>{,<shift>}` (A7.7.213).
            (0xF381, 0x001F, "usat r0, #0x1f, r1"),
            // 11010 with a non-zero imm3:imm2 — the `ASR` half of `USAT`.
            (0xF3A1, 0x10D7, "usat r0, #0x17, r1, asr #7"),
            // 11010 with imm3:imm2 == 0 — `USAT16<c> <Rd>,#<imm4>,<Rn>`.
            (0xF3A1, 0x000F, "usat16 r0, #0xf, r1"),
            // 11100 — `UBFX<c> <Rd>,<Rn>,#<lsb>,#<width>` (A7.7.193).
            (0xF3C1, 0x001F, "ubfx r0, r1, #0, #0x20"),
        ];
        for &(hw1, hw2, text) in cases {
            // Through the dispatcher, so each row is also a check that
            // `decode_halfwords` routes this encoding here. `0x1000` rather
            // than `0` because the `ADR` rows resolve against their address.
            let insn = decode_halfwords(hw1, hw2, 0x1000, false).expect("defined encoding");
            assert_eq!(insn.to_string(), text, "for {hw1:#06x} {hw2:#06x}");
            assert_eq!(encode(&insn), Some((hw1, hw2)), "for `{text}`");
        }
    }

    /// `BFI`/`BFC` with `msb < lsb` is UNPREDICTABLE — the operation
    /// pseudocode of both A7.7.13 and A7.7.14 ends `else UNPREDICTABLE` — and
    /// its `<width>` would be zero or negative, which no UAL syntax admits
    /// (`<width>` is documented as 1 to 32-<lsb>). `decode` refuses it, and
    /// `encode` refuses the corresponding `Insn` if one is synthesised.
    #[test]
    fn bitfield_with_msb_below_lsb_is_refused() {
        // lsb = imm3:imm2 = 0b010:0b00 = 8, msb = 3.
        assert!(decode(0xF361, 0x2003, 0).is_none());
        assert!(decode(0xF36F, 0x2003, 0).is_none());
        // msb == lsb is the narrowest legal field: one bit wide.
        let insn = decode(0xF361, 0x2008, 0).unwrap();
        assert_eq!(insn.to_string(), "bfi r0, r1, #8, #1");
        assert_eq!(encode(&insn), Some((0xF361, 0x2008)));
        // One below it is gone.
        assert!(decode(0xF361, 0x2007, 0).is_none());

        // The whole triangle: every `msb < lsb` pair, for both mnemonics.
        for lsb in 0..32u16 {
            for msb in 0..32u16 {
                let hw2 = ((lsb >> 2) << 12) | ((lsb & 3) << 6) | msb;
                assert_eq!(
                    decode(0xF361, hw2, 0).is_some(),
                    msb >= lsb,
                    "bfi lsb {lsb} msb {msb}"
                );
                assert_eq!(
                    decode(0xF36F, hw2, 0).is_some(),
                    msb >= lsb,
                    "bfc lsb {lsb} msb {msb}"
                );
            }
        }

        // A hand-built `bfi` with a zero width does not encode either.
        let mut zero_width = decode(0xF361, 0x2008, 0).unwrap();
        zero_width.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Imm(8),
            Operand::Imm(0),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&zero_width), None);
        // ... nor does one that runs off the top of the register.
        zero_width.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Imm(24),
            Operand::Imm(9),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&zero_width), None);
    }

    /// The `(0)` bits of the saturate and bitfield rows are ignored on the
    /// way in and written as zero on the way out, so a non-canonical encoding
    /// decodes to the same instruction and re-encodes to the canonical bits.
    #[test]
    fn should_be_zero_bits_are_ignored() {
        // `hw1[10]`, the unused `i` bit of `SBFX`.
        let canon = decode(0xF341, 0x1047, 0).unwrap();
        let stray = decode(0xF741, 0x1047, 0).unwrap();
        assert_eq!(canon, stray);
        assert_eq!(encode(&stray), Some((0xF341, 0x1047)));

        // `hw2[5]`, between `imm2` and the five-bit tail.
        let stray = decode(0xF341, 0x1067, 0).unwrap();
        assert_eq!(canon, stray);
        assert_eq!(encode(&stray), Some((0xF341, 0x1047)));

        // `hw2[4]` as well, for the four-bit `sat_imm` of `SSAT16`.
        let canon = decode(0xF321, 0x000F, 0).unwrap();
        let stray = decode(0xF321, 0x001F, 0).unwrap();
        assert_eq!(canon, stray);
        assert_eq!(encode(&stray), Some((0xF321, 0x000F)));
        // That bit is *not* spare for plain `SSAT`, where `sat_imm` is five
        // bits wide — `0xF301, 0x001F` is `#32`, not `#16`.
        assert_eq!(
            decode(0xF301, 0x001F, 0).unwrap().operands.get(1),
            Some(Operand::Imm(32))
        );
    }

    /// `ADDW`/`SUBW` are the non-flag-setting wide add and subtract — that is
    /// their entire reason for existing alongside the modified-immediate
    /// `ADD`/`SUB` of A5.3.1 — so none of them may print an `s`.
    #[test]
    fn wide_add_and_subtract_never_set_flags() {
        for op in [0b00000u16, 0b01010] {
            for rn in 0..15u16 {
                let insn = decode(0xF200 | (op << 4) | rn, 0x1023, 0).unwrap();
                assert!(!insn.sets_flags);
                let text = insn.to_string();
                assert!(
                    text.starts_with("addw ") || text.starts_with("subw "),
                    "printed `{text}`"
                );
            }
        }
    }

    /// The `SP` rows keep the mnemonic but change the encoding name, because
    /// `SUB (SP minus immediate)` (A7.7.176) has one fewer 32-bit encoding to
    /// number than `SUB (immediate)` (A7.7.174).
    #[test]
    fn sp_forms_carry_their_own_encoding_names() {
        assert_eq!(decode(0xF20D, 0x1D00, 0).unwrap().encoding, "T4");
        assert_eq!(decode(0xF6AD, 0x7DFF, 0).unwrap().encoding, "T3");
        assert_eq!(decode(0xF6A3, 0x72FF, 0).unwrap().encoding, "T4");
        // A mismatched pair is not something this module produced.
        let mut wrong = decode(0xF6AD, 0x7DFF, 0).unwrap();
        wrong.encoding = "T4";
        assert_eq!(encode(&wrong), None);
    }

    /// `encode` must reject what belongs to other groups, since a consumer
    /// re-encoding a stream hands every `Insn` to every group's `encode`.
    #[test]
    fn encode_rejects_foreign_forms() {
        let base = decode(0xF201, 0x1023, 0).unwrap();

        // A narrow instruction is never ours.
        let mut narrow = base;
        narrow.width = Width::Narrow;
        assert_eq!(encode(&narrow), None);

        // Nothing in Table A5-12 sets the flags.
        let mut flags = base;
        flags.sets_flags = true;
        assert_eq!(encode(&flags), None);

        // `add`/T3 is the modified-immediate sibling in A5.3.1.
        let mut modimm = base;
        modimm.mnemonic = "add";
        modimm.encoding = "T3";
        assert_eq!(encode(&modimm), None);

        // An `ADDW` naming `pc` is really an `ADR`, and must not be encodable
        // twice over.
        let mut pc_form = base;
        pc_form.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg::PC),
            Operand::Imm(0x123),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&pc_form), None);

        // Likewise a `bfi` naming `pc`, which is a `BFC`.
        let mut bfi_pc = decode(0xF361, 0x100F, 0).unwrap();
        bfi_pc.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg::PC),
            Operand::Imm(4),
            Operand::Imm(12),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&bfi_pc), None);

        // Out-of-range immediates.
        let mut big = base;
        big.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Imm(4096),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&big), None);

        // `SSAT`'s range is 1-32 and `USAT`'s is 0-31 (A7.7.152, A7.7.213) —
        // each rejects what the other accepts at its own end.
        let ssat = decode(0xF301, 0x0000, 0).unwrap();
        let usat = decode(0xF381, 0x0000, 0).unwrap();
        let sat_with = |insn: &Insn, v: i64| {
            let mut i = *insn;
            let mut ops = Operands::new();
            ops.push(Operand::Reg(Reg(0)));
            ops.push(Operand::Imm(v));
            ops.push(Operand::Reg(Reg(1)));
            i.operands = ops;
            encode(&i)
        };
        assert_eq!(sat_with(&ssat, 0), None);
        assert!(sat_with(&ssat, 32).is_some());
        assert!(sat_with(&usat, 0).is_some());
        assert_eq!(sat_with(&usat, 32), None);

        // An `ADR` whose target is out of the 0-4095 range in the direction
        // its encoding can express. `0x1004 + 4095 == 0x2003` is the last one
        // that fits, so `0x2003` encodes and `0x2004` does not.
        let mut far = decode(0xF20F, 0x0010, 0x1000).unwrap();
        far.operands = [Operand::Reg(Reg(0)), Operand::Target(0x2003)]
            .into_iter()
            .collect();
        assert!(encode(&far).is_some());
        far.operands = [Operand::Reg(Reg(0)), Operand::Target(0x2004)]
            .into_iter()
            .collect();
        assert_eq!(encode(&far), None);
        // The T3 (add) form cannot reach backwards at all.
        far.operands = [Operand::Reg(Reg(0)), Operand::Target(0x0FF0)]
            .into_iter()
            .collect();
        assert_eq!(encode(&far), None);
    }

    /// `SSAT`/`USAT` carry a shift, and UAL omits an `LSL #0` (A7.7.152:
    /// "If `<shift>` is omitted, `LSL #0` is used"). `ASR #0` is not a legal
    /// spelling at all: those bits are `SSAT16`.
    #[test]
    fn saturate_shift_operand() {
        use crate::isa::{Shift, ShiftAmount, ShiftKind};

        let plain = decode(0xF301, 0x0000, 0).unwrap();
        assert_eq!(plain.operands.get(2), Some(Operand::Reg(Reg(1))));

        // imm3:imm2 = 0b001:0b11 = 7.
        let shifted = decode(0xF301, 0x10D7, 0).unwrap();
        assert_eq!(
            shifted.operands.get(2),
            Some(Operand::RegShifted(
                Reg(1),
                Shift {
                    kind: ShiftKind::Lsl,
                    amount: ShiftAmount::Imm(7),
                }
            ))
        );

        // `sh == 1` is `ASR`, and its amount is never zero here.
        let asr = decode(0xF321, 0x101F, 0).unwrap();
        assert_eq!(
            asr.operands.get(2),
            Some(Operand::RegShifted(
                Reg(1),
                Shift {
                    kind: ShiftKind::Asr,
                    amount: ShiftAmount::Imm(4),
                }
            ))
        );

        // An explicit `LSL #0` is not the canonical spelling and does not
        // encode; the bare register does.
        let mut explicit_zero = plain;
        explicit_zero.operands = [
            Operand::Reg(Reg(0)),
            Operand::Imm(1),
            Operand::RegShifted(
                Reg(1),
                Shift {
                    kind: ShiftKind::Lsl,
                    amount: ShiftAmount::Imm(0),
                },
            ),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&explicit_zero), None);

        // Neither does a shift this encoding has no bit for.
        explicit_zero.operands = [
            Operand::Reg(Reg(0)),
            Operand::Imm(1),
            Operand::RegShifted(
                Reg(1),
                Shift {
                    kind: ShiftKind::Ror,
                    amount: ShiftAmount::Imm(4),
                },
            ),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&explicit_zero), None);
    }

    /// Every operand slot of every row of Table A5-12, mangled one at a time.
    ///
    /// [`Insn`] is a public struct with public fields, so `encode` is
    /// reachable with any operand list at all, and this table is unusually
    /// easy to read wrongly: the same slot index means different things from
    /// row to row — operand 1 is the source register in `ADDW <Rd>,<Rn>,#imm`
    /// and the saturation *immediate* in `SSAT <Rd>,#imm,<Rn>` — and `MOVW`
    /// spends the `Rn` field on the top nibble of a 16-bit constant. A slot
    /// read from the wrong place still produces halfwords; they are simply
    /// the wrong ones, and they get written into a firmware image.
    #[test]
    fn encode_rejects_every_mangled_operand_slot() {
        for (hw1, hw2) in [
            (0xF201u16, 0x1023u16), // addw   r0, r1, #0x123
            (0xF6A3, 0x72FF),       // subw   r2, r3, #0xfff
            (0xF6AD, 0x7DFF),       // subw   sp, sp, #0xfff   (T3)
            (0xF20F, 0x0010),       // adr.w  r0, <label>      (T3, adding)
            (0xF2AF, 0x0120),       // adr.w  r1, <label>      (T2, subtracting)
            (0xF64B, 0x63EF),       // movw   r3, #0xbeef
            (0xF2C1, 0x2334),       // movt   r3, #0x1234
            (0xF301, 0x10D7),       // ssat   r0, #0x18, r1, lsl #7
            (0xF301, 0x0000),       // ssat   r0, #1, r1
            (0xF321, 0x000F),       // ssat16 r0, #0x10, r1
            (0xF381, 0x001F),       // usat   r0, #0x1f, r1
            (0xF3A1, 0x000F),       // usat16 r0, #0xf, r1
            (0xF341, 0x1047),       // sbfx   r0, r1, #5, #8
            (0xF3C1, 0x001F),       // ubfx   r0, r1, #0, #0x20
            (0xF361, 0x100F),       // bfi    r0, r1, #4, #0xc
            (0xF36F, 0x200B),       // bfc    r0, #8, #4
        ] {
            let insn = decode(hw1, hw2, 0x1000).unwrap();
            assert_eq!(
                encode(&insn),
                Some((hw1, hw2)),
                "`{insn}` should round-trip before anything is mangled"
            );
            let arity = insn.operands.len();

            // One slot at a time, swapped for an operand of a kind that slot
            // cannot hold. A register goes where an immediate or a resolved
            // target belongs, and an immediate everywhere else — including
            // where a *shifted* register belongs, because a bare register is
            // a legal shifted-source operand (`LSL #0`) and swapping one for
            // the other would produce a different instruction rather than no
            // instruction.
            for slot in 0..arity {
                let mut mangled = insn;
                mangled.operands = (0..arity)
                    .map(|i| {
                        let op = insn.operands.get(i).unwrap();
                        if i != slot {
                            op
                        } else {
                            match op {
                                Operand::Imm(_) | Operand::Target(_) => Operand::Reg(Reg(0)),
                                _ => Operand::Imm(0),
                            }
                        }
                    })
                    .collect();
                assert_eq!(encode(&mangled), None, "`{insn}`, operand {slot} mangled");
            }
        }
    }

    /// The two bitfield width rules, one per mnemonic pair.
    ///
    /// `SBFX`/`UBFX` encode `widthm1 = width - 1` in a five-bit field, so a
    /// width of zero has no encoding and 33 runs off the end (A7.7.13,
    /// A7.7.187). `BFC` encodes `msb = lsb + width - 1` and needs the result
    /// to stay inside the register, so the width is bounded by where the
    /// field starts (A7.7.12).
    #[test]
    fn bitfield_widths_outside_the_field_are_refused() {
        let extract = |mnemonic: &'static str, hw1, hw2, lsb: i64, width: i64| {
            let mut insn: Insn = decode(hw1, hw2, 0).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            insn.operands = [
                Operand::Reg(Reg(0)),
                Operand::Reg(Reg(1)),
                Operand::Imm(lsb),
                Operand::Imm(width),
            ]
            .into_iter()
            .collect();
            encode(&insn)
        };
        for (mnemonic, hw1, hw2) in [("sbfx", 0xF341u16, 0x1047u16), ("ubfx", 0xF3C1, 0x001F)] {
            assert_eq!(
                extract(mnemonic, hw1, hw2, 0, 0),
                None,
                "{mnemonic} #0 wide"
            );
            assert_eq!(extract(mnemonic, hw1, hw2, 0, 33), None, "{mnemonic} #33");
            assert_eq!(extract(mnemonic, hw1, hw2, 0, -1), None, "{mnemonic} #-1");
            // The two ends that do encode.
            assert!(extract(mnemonic, hw1, hw2, 0, 1).is_some(), "{mnemonic} #1");
            assert!(
                extract(mnemonic, hw1, hw2, 0, 32).is_some(),
                "{mnemonic} #32"
            );
        }

        // `BFC <Rd>, #<lsb>, #<width>`: three operands, and the width is
        // bounded by `32 - lsb` rather than by a field of its own.
        let clear = |lsb: i64, width: i64| {
            let mut insn: Insn = decode(0xF36F, 0x200B, 0).unwrap();
            assert_eq!(insn.mnemonic, "bfc");
            insn.operands = [Operand::Reg(Reg(0)), Operand::Imm(lsb), Operand::Imm(width)]
                .into_iter()
                .collect();
            encode(&insn)
        };
        assert!(
            clear(8, 24).is_some(),
            "bits 8..=31 is the whole of the top"
        );
        assert_eq!(clear(8, 25), None, "that would need bit 32");
        assert_eq!(clear(8, 0), None, "a field of no bits clears nothing");
        assert!(clear(0, 32).is_some(), "the whole register");
        assert_eq!(clear(0, 33), None);
    }

    /// `SSAT`'s shifted source takes an immediate shift and nothing else: the
    /// encoding has a five-bit `imm3:imm2` and no register field to put a
    /// shift amount in (A7.7.153).
    #[test]
    fn a_saturating_shift_cannot_be_by_a_register() {
        use crate::isa::{Shift, ShiftAmount, ShiftKind};

        let mut insn = decode(0xF301, 0x10D7, 0).unwrap();
        assert_eq!(insn.mnemonic, "ssat");
        insn.operands = [
            Operand::Reg(Reg(0)),
            Operand::Imm(1),
            Operand::RegShifted(
                Reg(1),
                Shift {
                    kind: ShiftKind::Lsl,
                    amount: ShiftAmount::Reg(Reg(2)),
                },
            ),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&insn), None);
    }

    /// `MOVW` then `MOVT` materialises an arbitrary 32-bit constant without a
    /// literal pool, which is the practical reason this table matters. The
    /// pair only works because `MOVT` leaves `R[d]<15:0>` alone (A7.7.79).
    #[test]
    fn movw_movt_pair_builds_a_word() {
        let lo = decode(0xF64B, 0x63EF, 0).unwrap();
        let hi = decode(0xF6CD, 0x63AD, 4).unwrap();
        // The two decoded immediates are the halves of the word the pair
        // materialises, asserted against it rather than extracted and
        // recombined: an extracting match needs an arm for the operand kinds
        // that cannot appear, and that arm can never run.
        const WORD: u32 = 0xDEAD_BEEF;
        assert_eq!(
            lo.operands.get(1),
            Some(Operand::Imm(i64::from(WORD & 0xFFFF)))
        );
        assert_eq!(
            hi.operands.get(1),
            Some(Operand::Imm(i64::from(WORD >> 16)))
        );
        assert_eq!(lo.to_string(), "movw r3, #0xbeef");
        assert_eq!(hi.to_string(), "movt r3, #0xdead");
    }
}
