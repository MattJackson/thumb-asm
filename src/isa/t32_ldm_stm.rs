//! Load Multiple and Store Multiple — `hw1[15:11] == 0b11101`, `hw1[10:4]`
//! matching `00xx0xx` (ARM DDI 0403E.e A5.3.5, Table A5-16; ARM DDI 0406B
//! A6.3.5, Table A6-16).
//!
//! ```text
//!  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
//!   1  1  1  0  1  0  0 <op>  0  W  L <---- Rn ---->   hw1
//!  <-------------- register_list ---------------->     hw2
//! ```
//!
//! Six operations out of two bits, because `W:Rn` is consulted as well as
//! `op:L`:
//!
//! | `op` | `L` | `W:Rn` | instruction | encoding |
//! |---|---|---|---|---|
//! | `01` | 0 | — | `STM` / `STMIA` / `STMEA` | T2 |
//! | `01` | 1 | not `11101` | `LDM` / `LDMIA` / `LDMFD` | T2 |
//! | `01` | 1 | `11101` | `POP` | T2 |
//! | `10` | 0 | not `11101` | `STMDB` / `STMFD` | T1 |
//! | `10` | 0 | `11101` | `PUSH` | T2 |
//! | `10` | 1 | — | `LDMDB` / `LDMEA` | T1 |
//! | `00` | 0 | — | `SRS` (A/R profile only) | T1 |
//! | `00` | 1 | — | `RFE` (A/R profile only) | T1 |
//! | `11` | 0 | — | `SRS` (A/R profile only) | T2 |
//! | `11` | 1 | — | `RFE` (A/R profile only) | T2 |
//!
//! The last four rows are Table A6-16's and not Table A5-16's: `SRS` (Store
//! Return State, ARM DDI 0406B B6.1.10) and `RFE` (Return From Exception,
//! B6.1.8) need banked registers and an SPSR, neither of which an M-profile
//! core has, so `op == 00` and `op == 11` are simply UNDEFINED on Armv7-M.
//! This module decodes the union of the two profiles, as the crate does
//! throughout; the `op` bits themselves select the addressing mode, `00` being
//! decrement-before and `11` increment-after.
//!
//! # `W:Rn == 11101` is what makes a `push`
//!
//! Writeback to `sp` is not *like* a push, it **is** one: A7.7.159's
//! `STMDB` carries *`if W == '1' && Rn == '1101' then SEE PUSH`* and A7.7.41's
//! `LDM` carries *`if W == '1' && Rn == '1101' then SEE POP (Thumb)`*, and the
//! `PUSH`/`POP` pages give `STMDB<c><q> SP!, <registers>` and
//! `LDMIA<c><q> SP!, <registers>` as the *equivalent* syntax for their own.
//! One halfword pair, two spellings, and UAL's is the short one: `e92d 4010`
//! is `push.w {r4, lr}`, not `stmdb sp!, {r4, lr}`. Decoding it the long way
//! would leave every 32-bit function prologue in a firmware image legible but
//! un-reassemblable, so `push`/`pop` are decoded with a bare register list and
//! no base operand at all — exactly the operands the UAL form has.
//!
//! Note which four rows this does *not* touch. `LDMDB sp!` is not a `pop`
//! (wrong direction), `STM sp!` is not a `push` (likewise), and neither
//! `LDM sp` nor `STMDB sp` without the `!` is anything but itself. Only
//! `W == 1` aliases.
//!
//! # The register list is sixteen bits wide
//!
//! Unlike the 16-bit encodings, whose eight-bit list reaches `r0`–`r7` and
//! bolts `lr`/`pc` on as a separate `M`/`P` bit, `hw2` here *is* the list, one
//! bit per register, and `pc` (bit 15) and `lr` (bit 14) are ordinary members
//! of it. [`Insn::writes_pc`] reads bit 15 of an `ldm`/`ldmdb`/`pop` list, so
//! the [`Operand::RegList`] this module produces is the real 16-bit mask and
//! not a re-packed eight-bit one.
//!
//! Two bits of the list are constrained by the encoding diagrams rather than
//! by prose:
//!
//! * **Bit 13 is `(0)` in all six encodings** — `sp` cannot be in any list.
//! * **Bit 15 is `(0)` in the three stores** (`STM`, `STMDB`, `PUSH`: their
//!   diagrams read `(0) M (0) register_list`, and the loads' read
//!   `P M (0) register_list`) — `pc` cannot be stored by a Store Multiple.
//!
//! A bit drawn as `(0)` that is not zero makes the instruction UNPREDICTABLE
//! (ARM DDI 0403E.e D6.1) and, unlike an UNPREDICTABLE *operand*, cannot be
//! carried in an [`Insn`]: decoding it would discard the offending bit and
//! re-encode to a different halfword. Both are therefore refused outright.
//!
//! # A wide Load/Store Multiple needs two registers in its list
//!
//! One rule, six encodings: **`BitCount(registers) < 2` is refused
//! everywhere in this group.** Arm states it identically on all six pages —
//! *`if BitCount(registers) < 2 then UNPREDICTABLE`* in A7.7.41 `LDM` T2,
//! A7.7.42 `LDMDB` T1, A7.7.159 `STM` T2, A7.7.160 `STMDB` T1, A7.7.99 `POP`
//! T2 and A7.7.101 `PUSH` T2 — and unlike the UNPREDICTABLE rules tabulated
//! below it is not a statement about a *value*. It is a statement about which
//! encoding a piece of syntax belongs to, and every page that has somewhere
//! else to send a one-register list says so in prose:
//!
//! * `LDM` and `STM`: *"Encoding T2 does not support a list containing only
//!   one register. If an `LDMIA` instruction with just one register `<Rt>` in
//!   the list is assembled to Thumb and encoding T1 is not available, it is
//!   assembled to the equivalent `LDR<c><q> <Rt>,[<Rn>]{,#4}` instruction"* —
//!   and the same sentence, with `STR`, on A7.7.159.
//! * `PUSH` and `POP`: *"If the list contains more than one register, the
//!   instruction is assembled to encoding T1 or T2. If the list contains
//!   exactly one register, the instruction is assembled to encoding T1 or
//!   T3."* Their T2 syntax lines are qualified *`<registers>` contains more
//!   than one register*, and each has a separate T3 line for the
//!   single-register case.
//!
//! So `push.w {r0}` is not this encoding's text: an assembler reads it back as
//! `PUSH` T3, `f84d 0d04`, where the halfwords in hand were `e92d 0001`. Nor
//! is `ldm.w r0, {r4}`, which comes back as an `LDR` or as the narrow T1. And
//! an empty list is worse than ambiguous — `{}` is not syntax any assembler
//! will parse at all, so `stm.w r0, {}` is text that cannot be read back by
//! anything. Printing a string that does not name the bytes it came from is
//! the one thing this crate must not do, so both cases are refused outright,
//! exactly as `sp` in a list and `pc` in a store's list are, and for the same
//! reason: the halfwords cannot survive the trip out through text and back.
//!
//! The threshold really is `2` here and `1` in the 16-bit encodings, whose
//! `PUSH`/`POP`/`STM`/`LDM` T1 carry *`if BitCount(registers) < 1 then
//! UNPREDICTABLE`* instead (A7.7.101, A7.7.99, A7.7.159, A7.7.41; decoded in
//! `t16_misc` and `t16_loadstore`). That is Arm's asymmetry and not a typo
//! here: a *narrow* single-register `push` has no shorter spelling to be
//! re-assembled into, so `push {r0}` is the encoding its own text names, while
//! a wide one is outranked by two shorter encodings of the same operation.
//!
//! # The UNPREDICTABLE rules that are decoded anyway
//!
//! The remaining UNPREDICTABLE rules constrain values that *are* representable
//! and *do* round-trip, so — as elsewhere in this crate — they are decoded,
//! on the grounds that a disassembler reading a firmware image is more use
//! reporting the halfword that is there than refusing to:
//!
//! | rule | source | decoded as |
//! |---|---|---|
//! | `n == 15` | `STM`/`LDM`/`STMDB`/`LDMDB` | `stm.w pc, {r0, r1}` |
//! | `P == '1' && M == '1'` (`pc` **and** `lr` in a load list) | `LDM`/`LDMDB`/`POP` | `pop.w {lr, pc}` |
//! | `wback && registers<n> == '1'` | all four base-register forms | `stm.w r0!, {r0, r1}` |
//! | `n == 15` | `RFE` | `rfedb pc!` |
//!
//! One rule cannot be checked here at all: *`if registers<15> == '1' &&
//! InITBlock() && !LastInITBlock()`*. Whether an instruction is the last in an
//! IT block is a property of the stream, not of the halfwords, and belongs to
//! [`crate::isa::Decoder`], which tracks `ITSTATE`.
//!
//! # Writeback, and how it is printed
//!
//! [`Insn`] has no writeback flag, and the `!` in `stmdb sp!, {…}` is a
//! suffix on one operand rather than an operand of its own — so a trailing
//! `Operand::Text("!")` would print `stmdb sp, !, {…}`, since `Display` joins
//! operands with `", "`. The base register is therefore emitted as a *single*
//! operand that already carries the marker: [`Operand::Reg`] when `W == 0`,
//! and [`Operand::Text`] of `"r0!"`…`"pc!"` (the [`WRITEBACK`] table) when
//! `W == 1`. That prints correct UAL, round-trips exactly, and keeps `W` out
//! of the mnemonic, where it would be worse. A consumer matching on
//! `Operand::Reg` to find the base must handle the `Text` case too; the
//! alternative — inventing a second operand — prints text no assembler
//! accepts, which is the one thing this crate must not do.
//!
//! # `.w`
//!
//! `STM`, `LDM`, `PUSH` and `POP` all have 16-bit encodings, so their wide
//! forms need the suffix to round-trip, and Arm's syntax lines duly read
//! `STM<c>.W`, `LDM<c>.W`, `PUSH<c>.W`, `POP<c>.W`. `STMDB`, `LDMDB`, `SRS`
//! and `RFE` have no narrow counterpart, their syntax lines carry no `.W`, and
//! neither do we.
//!
//! # What this group does not set, and what it does not say
//!
//! Nothing here sets flags. One limit of the shared vocabulary used to bite
//! here and no longer does: `RFE` loads the pc, but [`Insn::writes_pc`]
//! recognises pc-writing loads by mnemonic (`ldm`, `ldmdb`, `pop`) or by a pc
//! destination operand, and `RFE` is neither — its one register operand is the
//! base address it reads the pc and the CPSR through (B6.1.8) — so `rfeia r0!`
//! reported `is_branch() == false`, straight-lining an exception return.
//! `writes_pc` now names `rfeia` and `rfedb` outright. `SRS` is untouched by
//! that: it *stores* `lr` and the SPSR, and is not a branch.

use super::{Insn, Operand, Reg, Width};

/// Decode one instruction of this group, or `None` if `hw1`/`hw2` are not in
/// it, or set one of the `(0)` bits the encoding diagrams fix at zero.
pub(crate) fn decode(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    // `1110 100 op(2) 0 W L Rn(4)`.
    if hw1 >> 11 != 0b11101 || (hw1 >> 9) & 0b11 != 0 || (hw1 >> 6) & 1 != 0 {
        return None;
    }
    let op = (hw1 >> 7) & 0b11;
    let wback = (hw1 >> 5) & 1 == 1;
    let load = (hw1 >> 4) & 1 == 1;
    let rn = Reg((hw1 & 0xF) as u8);

    // `op == 00`/`11` are the A/R-only exception-handling pair, which have no
    // register list: their second halfword is entirely fixed bits.
    if op == 0b00 || op == 0b11 {
        // `00` is decrement-before, `11` increment-after; each is its own
        // numbered encoding of the same instruction.
        let increment = op == 0b11;
        let encoding = if increment { "T2" } else { "T1" };
        if load {
            // RFE: `(1)(1)` then fourteen `(0)`s.
            if hw2 != 0xC000 {
                return None;
            }
            let mnemonic = if increment { "rfeia" } else { "rfedb" };
            return Some(wide(mnemonic, encoding, addr, false, &[base(rn, wback)]));
        }
        // SRS: the base is the banked `sp` of the *target* mode, so `Rn` is
        // fixed at `1101` and the mode number lives in `hw2[4:0]`.
        if rn.num() != 13 || hw2 & 0xFFE0 != 0xC000 {
            return None;
        }
        let mnemonic = if increment { "srsia" } else { "srsdb" };
        return Some(wide(
            mnemonic,
            encoding,
            addr,
            false,
            &[base(Reg::SP, wback), Operand::Imm(i64::from(hw2 & 0x1F))],
        ));
    }

    // `sp` is `(0)` in every list; `pc` is `(0)` in a store's.
    if hw2 & 0x2000 != 0 || (!load && hw2 & 0x8000 != 0) {
        return None;
    }
    // `BitCount(registers) < 2` in any wide form: the syntax belongs to a
    // shorter encoding, so the text would not read back as these halfwords.
    // See the module docs.
    if !has_two_registers(hw2) {
        return None;
    }
    let list = Operand::RegList(hw2);
    let decrement = op == 0b10;

    // Writeback to `sp` is `push`/`pop`, in the one direction each.
    if wback && rn.num() == 13 {
        if load && !decrement {
            return Some(wide("pop", "T2", addr, true, &[list]));
        }
        if !load && decrement {
            return Some(wide("push", "T2", addr, true, &[list]));
        }
    }

    let (mnemonic, encoding, explicit_width) = match (decrement, load) {
        (false, false) => ("stm", "T2", true),
        (false, true) => ("ldm", "T2", true),
        (true, false) => ("stmdb", "T1", false),
        (true, true) => ("ldmdb", "T1", false),
    };
    Some(wide(
        mnemonic,
        encoding,
        addr,
        explicit_width,
        &[base(rn, wback), list],
    ))
}

/// Re-encode an instruction this module decoded, back to its two halfwords.
///
/// Refuses the forms that belong to the *other* spelling of the same bits: an
/// `stmdb sp!, {…}` or `ldm sp!, {…}` built by hand is `push`/`pop`'s
/// halfword pair, and letting both mnemonics produce it would mean two
/// [`Insn`]s claiming one encoding. It also refuses a list with `sp` in it,
/// `pc` in a store's, or fewer than two registers in any of them, for the
/// reasons given in the module docs — [`decode`] cannot produce those shapes
/// and this must not invent them.
///
/// [`Insn::cond`] is ignored rather than rejected: nothing in this group has a
/// condition field, so a condition can only have come from an enclosing `IT`
/// block, which does not change the instruction's own bits.
pub(crate) fn encode(insn: &Insn) -> Option<(u16, u16)> {
    if insn.width != Width::Wide || insn.sets_flags {
        return None;
    }
    match insn.mnemonic {
        "push" | "pop" => {
            if insn.encoding != "T2" {
                return None;
            }
            let bits = match insn.operands.get(0) {
                Some(Operand::RegList(b)) => b,
                _ => return None,
            };
            // The `get` above has ruled out too *few* operands; this rules out
            // too many, and is the only thing left for a count to decide.
            if insn.operands.len() > 1 {
                return None;
            }
            if bits & 0x2000 != 0 || !has_two_registers(bits) {
                return None;
            }
            if insn.mnemonic == "pop" {
                Some((0xE8BD, bits))
            } else if bits & 0x8000 != 0 {
                None
            } else {
                Some((0xE92D, bits))
            }
        }
        "stm" | "ldm" | "stmdb" | "ldmdb" => {
            let (rn, wback) = base_of(insn.operands.get(0)?)?;
            let bits = match insn.operands.get(1) {
                Some(Operand::RegList(b)) => b,
                _ => return None,
            };
            // The two `get`s above have ruled out too *few* operands; this
            // rules out too many, and is the only thing left for a count to
            // decide. Checking `len() != 2` up front instead would leave the
            // `?` above unreachable, which is worse than a check that reads
            // out of order: an unreachable guard implies a case that cannot
            // happen.
            if insn.operands.len() > 2 {
                return None;
            }
            let (op, load, encoding) = match insn.mnemonic {
                "stm" => (0b01u16, false, "T2"),
                "ldm" => (0b01, true, "T2"),
                "stmdb" => (0b10, false, "T1"),
                _ => (0b10, true, "T1"),
            };
            if insn.encoding != encoding
                || bits & 0x2000 != 0
                || (!load && bits & 0x8000 != 0)
                || !has_two_registers(bits)
                // `stm`/`ldmdb` to `sp!` are not aliased; `ldm`/`stmdb` are.
                || (wback && rn.num() == 13 && (load == (op == 0b01)))
            {
                return None;
            }
            Some((assemble_hw1(op, wback, load, rn), bits))
        }
        "srsdb" | "srsia" => {
            let increment = insn.mnemonic == "srsia";
            if insn.encoding != encoding_name(increment) {
                return None;
            }
            let (rn, wback) = base_of(insn.operands.get(0)?)?;
            let mode = match insn.operands.get(1) {
                Some(Operand::Imm(m)) if (0..32).contains(&m) => m as u16,
                _ => return None,
            };
            if rn.num() != 13 || insn.operands.len() > 2 {
                return None;
            }
            let op = if increment { 0b11 } else { 0b00 };
            Some((assemble_hw1(op, wback, false, rn), 0xC000 | mode))
        }
        "rfedb" | "rfeia" => {
            let increment = insn.mnemonic == "rfeia";
            if insn.encoding != encoding_name(increment) {
                return None;
            }
            let (rn, wback) = base_of(insn.operands.get(0)?)?;
            if insn.operands.len() > 1 {
                return None;
            }
            let op = if increment { 0b11 } else { 0b00 };
            Some((assemble_hw1(op, wback, true, rn), 0xC000))
        }
        _ => None,
    }
}

/// Whether a register list holds the two registers every wide form of this
/// group requires — `BitCount(registers) >= 2`, the single rule the module
/// docs derive from all six instruction pages.
fn has_two_registers(list: u16) -> bool {
    list.count_ones() >= 2
}

/// `"r0!"`…`"pc!"`, indexed by register number: the base register printed with
/// its writeback marker, as one operand. See the module docs for why the `!`
/// cannot be an operand of its own.
const WRITEBACK: [&str; 16] = [
    "r0!", "r1!", "r2!", "r3!", "r4!", "r5!", "r6!", "r7!", "r8!", "r9!", "r10!", "r11!", "r12!",
    "sp!", "lr!", "pc!",
];

/// The base-register operand for a form whose writeback is `wback`.
fn base(rn: Reg, wback: bool) -> Operand {
    if wback {
        Operand::Text(WRITEBACK[rn.num() as usize])
    } else {
        Operand::Reg(rn)
    }
}

/// The inverse of [`base`]: the register and whether it is written back.
fn base_of(op: Operand) -> Option<(Reg, bool)> {
    match op {
        Operand::Reg(r) => Some((r, false)),
        Operand::Text(s) => WRITEBACK
            .iter()
            .position(|&w| w == s)
            .map(|i| (Reg(i as u8), true)),
        _ => None,
    }
}

/// `1110 100 op 0 W L Rn`.
fn assemble_hw1(op: u16, wback: bool, load: bool, rn: Reg) -> u16 {
    0xE800 | (op << 7) | (u16::from(wback) << 5) | (u16::from(load) << 4) | u16::from(rn.num())
}

/// `SRS` and `RFE` number their decrement-before form T1 and their
/// increment-after form T2.
fn encoding_name(increment: bool) -> &'static str {
    if increment {
        "T2"
    } else {
        "T1"
    }
}

/// Build a 32-bit, unconditional, flag-preserving instruction of this group.
fn wide(
    mnemonic: &'static str,
    encoding: &'static str,
    addr: u32,
    explicit_width: bool,
    ops: &[Operand],
) -> Insn {
    Insn {
        mnemonic,
        encoding,
        addr,
        width: Width::Wide,
        cond: None,
        sets_flags: false,
        explicit_width,
        operands: ops.iter().copied().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::Target;

    /// Decode a halfword pair of this group, panicking with the pattern if it
    /// does not decode — a failing assertion should name the encoding it
    /// tripped on rather than an anonymous `unwrap`.
    fn dec(hw1: u16, hw2: u16) -> Insn {
        let decoded = decode(hw1, hw2, 0x1000);
        // `assert!` rather than `unwrap_or_else(|| panic!(…))`: the closure in
        // the latter is a function that never runs, and this crate's coverage
        // gate is 100% of functions.
        assert!(decoded.is_some(), "{hw1:#06x} {hw2:#06x} failed to decode");
        decoded.unwrap()
    }

    /// Assert that `hw1`/`hw2` decode to `text` and re-encode to themselves.
    fn check(hw1: u16, hw2: u16, text: &str) -> Insn {
        let insn = dec(hw1, hw2);
        assert_eq!(insn.to_string(), text, "{hw1:#06x} {hw2:#06x}");
        assert_eq!(
            encode(&insn),
            Some((hw1, hw2)),
            "`{insn}` did not re-encode to {hw1:#06x} {hw2:#06x}"
        );
        assert!(!insn.sets_flags, "nothing in this group sets flags");
        insn
    }

    /// Whether `hw1`/`hw2` is a defined encoding, restated from the manual's
    /// rules rather than from [`decode`]'s control flow, so that the sweep
    /// below checks two independent statements of the same thing.
    fn is_defined(hw1: u16, hw2: u16) -> bool {
        let op = (hw1 >> 7) & 0b11;
        let load = (hw1 >> 4) & 1 == 1;
        let rn = hw1 & 0xF;
        match op {
            // A list form: `sp` is never in the list, `pc` never in a store's,
            // and `BitCount(registers) < 2` is a shorter encoding's syntax.
            // `count_ones` rather than [`has_two_registers`] on purpose: this
            // function restates the manual and must not share code with the
            // thing it is checking.
            0b01 | 0b10 => {
                hw2 & 0x2000 == 0 && (load || hw2 & 0x8000 == 0) && hw2.count_ones() >= 2
            }
            // RFE's second halfword is wholly fixed; SRS's holds only a mode,
            // and its base register field is fixed at `sp`.
            _ if load => hw2 == 0xC000,
            _ => rn == 13 && hw2 & 0xFFE0 == 0xC000,
        }
    }

    #[test]
    fn systematic_round_trip() {
        // Empty, single-register, contiguous, `{r0-r15}`, and every
        // combination of the three special registers, plus the fixed second
        // halfwords the SRS/RFE rows require.
        let lists = [
            0x0000u16, 0x0001, 0x0003, 0x0007, 0x00FF, 0x0010, 0x1FFF, 0x2000, 0x4000, 0x8000,
            0xC000, 0xA000, 0x6000, 0xE000, 0xFFFF, 0x5FFF, 0x9FFF, 0xC010, 0xC01F, 0xC020, 0x400D,
            0x000D,
        ];
        let mut decoded = 0;
        let mut undefined = 0;
        for op in 0u16..4 {
            for w in 0u16..2 {
                for l in 0u16..2 {
                    for rn in 0u16..16 {
                        let hw1 = 0xE800 | (op << 7) | (w << 5) | (l << 4) | rn;
                        for &hw2 in &lists {
                            // No `let … else`: MSRV is 1.58 (that is 1.65).
                            if let Some(insn) = decode(hw1, hw2, 0x2000) {
                                assert!(is_defined(hw1, hw2), "{hw1:#06x} {hw2:#06x} is UNDEFINED");
                                decoded += 1;
                                assert_eq!(
                                    encode(&insn),
                                    Some((hw1, hw2)),
                                    "{hw1:#06x} {hw2:#06x} re-encoded wrongly as `{insn}`"
                                );
                            } else {
                                assert!(!is_defined(hw1, hw2), "{hw1:#06x} {hw2:#06x} is defined");
                                undefined += 1;
                            }
                        }
                    }
                }
            }
        }
        // 4 op x 2 W x 2 L x 16 Rn = 256 first halfwords, 22 lists each, and
        // every one of the 5632 pairs accounted for:
        //
        //   * of the 22 lists, 5 have `sp` in them and are refused everywhere,
        //     and 6 of the remaining 17 have `pc`, which only a load may take.
        //     That leaves 17 a load could take and 11 a store could — but a
        //     wide form also needs two registers in the list, which knocks out
        //     5 of the load's 17 (`{}`, `{r0}`, `{r4}`, `{lr}`, `{pc}`) and 4
        //     of the store's 11 (the same, less `{pc}`, which a store has
        //     already refused). So each of the 64 list-form *load* halfwords
        //     (op = 01/10, L = 1) decodes 12, and each of the 64 *store* ones
        //     decodes 7: 64 * 12 + 64 * 7 = 1216.
        //   * each of the 64 `RFE` halfwords (op = 00/11, L = 1) decodes the
        //     one list value that is its fixed `hw2`, 0xc000: 64.
        //   * `SRS` (op = 00/11, L = 0) additionally fixes `Rn` at `sp`, so
        //     only 4 of its 64 halfwords decode anything, and each takes the 3
        //     list values of the form `0xc0` + a 5-bit mode: 12.
        assert_eq!(lists.len(), 22);
        assert_eq!(decoded + undefined, 256 * lists.len());
        assert_eq!(
            decoded,
            1216 + 64 + 12,
            "unexpected number of defined encodings"
        );
        assert_eq!(undefined, 5632 - 1292);
    }

    /// Every row of Table A5-16 and Table A6-16, printed, with the syntax
    /// taken from each instruction page's assembler-syntax line.
    #[test]
    fn table_rows() {
        // op = 01, L = 0: `STM<c>.W <Rn>{!},<registers>`.
        let i = check(0xE8A0, 0x0006, "stm.w r0!, {r1, r2}");
        assert_eq!((i.mnemonic, i.encoding), ("stm", "T2"));
        check(0xE880, 0x0006, "stm.w r0, {r1, r2}");

        // op = 01, L = 1, W:Rn != 11101: `LDM<c>.W <Rn>{!},<registers>`.
        let i = check(0xE8B0, 0x0006, "ldm.w r0!, {r1, r2}");
        assert_eq!((i.mnemonic, i.encoding), ("ldm", "T2"));

        // op = 01, L = 1, W:Rn == 11101: `POP<c>.W <registers>`.
        let i = check(0xE8BD, 0x8010, "pop.w {r4, pc}");
        assert_eq!((i.mnemonic, i.encoding), ("pop", "T2"));

        // op = 10, L = 0, W:Rn != 11101: `STMDB<c> <Rn>{!},<registers>`.
        let i = check(0xE920, 0x0030, "stmdb r0!, {r4, r5}");
        assert_eq!((i.mnemonic, i.encoding), ("stmdb", "T1"));

        // op = 10, L = 0, W:Rn == 11101: `PUSH<c>.W <registers>`.
        let i = check(0xE92D, 0x4010, "push.w {r4, lr}");
        assert_eq!((i.mnemonic, i.encoding), ("push", "T2"));

        // op = 10, L = 1: `LDMDB<c> <Rn>{!},<registers>`.
        let i = check(0xE930, 0x0030, "ldmdb r0!, {r4, r5}");
        assert_eq!((i.mnemonic, i.encoding), ("ldmdb", "T1"));

        // op = 00, L = 0: `SRSDB<c> SP{!},#<mode>` (A/R only). 0x11 is FIQ
        // mode; `Operand::Imm` prints anything over 9 in hex.
        let i = check(0xE82D, 0xC011, "srsdb sp!, #0x11");
        assert_eq!((i.mnemonic, i.encoding), ("srsdb", "T1"));
        check(0xE80D, 0xC011, "srsdb sp, #0x11");

        // op = 00, L = 1: `RFEDB<c> <Rn>{!}` (A/R only).
        let i = check(0xE830, 0xC000, "rfedb r0!");
        assert_eq!((i.mnemonic, i.encoding), ("rfedb", "T1"));
        check(0xE810, 0xC000, "rfedb r0");

        // op = 11, L = 0: `SRS{IA}<c> SP{!},#<mode>` (A/R only).
        let i = check(0xE9AD, 0xC011, "srsia sp!, #0x11");
        assert_eq!((i.mnemonic, i.encoding), ("srsia", "T2"));

        // op = 11, L = 1: `RFE{IA}<c> <Rn>{!}` (A/R only).
        let i = check(0xE9B0, 0xC000, "rfeia r0!");
        assert_eq!((i.mnemonic, i.encoding), ("rfeia", "T2"));
    }

    /// The aliasing that gives this group its character: `W:Rn == 11101` in
    /// the two directions that have a stack spelling, and nowhere else.
    #[test]
    fn writeback_to_sp_is_push_and_pop() {
        // W = 1, Rn = sp, op = 01, L = 1 is `pop`, not `ldm`.
        let pop = dec(0xE8BD, 0x4030);
        assert_eq!(pop.mnemonic, "pop");
        assert_eq!(pop.to_string(), "pop.w {r4, r5, lr}");
        assert_eq!(pop.operands.len(), 1, "a pop has no base operand");

        // W = 1, Rn = sp, op = 10, L = 0 is `push`, not `stmdb`.
        let push = dec(0xE92D, 0x4030);
        assert_eq!(push.mnemonic, "push");
        assert_eq!(push.to_string(), "push.w {r4, r5, lr}");
        assert_eq!(push.operands.len(), 1);

        // Rn = sp *without* writeback is neither.
        assert_eq!(dec(0xE89D, 0x4030).to_string(), "ldm.w sp, {r4, r5, lr}");
        assert_eq!(dec(0xE90D, 0x4030).to_string(), "stmdb sp, {r4, r5, lr}");

        // Nor is writeback to `sp` in the other two directions: a pop
        // increments and a push decrements, and these do the opposite.
        assert_eq!(dec(0xE8AD, 0x4030).to_string(), "stm.w sp!, {r4, r5, lr}");
        assert_eq!(dec(0xE93D, 0x4030).to_string(), "ldmdb sp!, {r4, r5, lr}");

        // And writeback to anything else is an ordinary `ldm`/`stmdb`.
        assert_eq!(dec(0xE8BC, 0x4030).to_string(), "ldm.w r12!, {r4, r5, lr}");
        assert_eq!(dec(0xE92C, 0x4030).to_string(), "stmdb r12!, {r4, r5, lr}");

        // The re-encoder will not let the long spelling claim the short
        // spelling's bits.
        let mut long = dec(0xE8BC, 0x4030);
        long.operands = [Operand::Text("sp!"), Operand::RegList(0x4030)]
            .iter()
            .copied()
            .collect();
        assert_eq!(encode(&long), None, "`ldm sp!, {{…}}` is `pop`'s encoding");
    }

    /// `Insn::writes_pc` reads bit 15 of the list, which is why the list must
    /// be the real 16-bit mask.
    #[test]
    fn pop_with_pc_writes_pc() {
        let with_pc = dec(0xE8BD, 0x8010);
        assert!(with_pc.writes_pc(), "pop.w {{r4, pc}}");
        assert!(with_pc.is_branch());
        assert!(!with_pc.is_call());

        let without = dec(0xE8BD, 0x4010);
        assert!(!without.writes_pc(), "pop.w {{r4, lr}}");
        assert!(!without.is_branch());

        // The same is true of the `ldm` spellings `writes_pc` knows about.
        assert!(dec(0xE8B0, 0x8010).writes_pc(), "ldm.w r0!, {{r4, pc}}");
        assert!(dec(0xE930, 0x8010).writes_pc(), "ldmdb r0!, {{r4, pc}}");
        assert!(!dec(0xE8B0, 0x4010).writes_pc());

        // A push can never write pc — bit 15 is `(0)` in its encoding.
        assert!(!dec(0xE92D, 0x4010).writes_pc());
        assert!(decode(0xE92D, 0x8010, 0).is_none());
    }

    /// One assertion per UNPREDICTABLE rule in the instruction pages, saying
    /// which are refused (because the offending bit cannot be carried in an
    /// `Insn`) and which are decoded.
    #[test]
    fn unpredictable_rules() {
        // `sp` in any list: bit 13 is `(0)` in all six encodings. Refused.
        for hw1 in [0xE880u16, 0xE8B0, 0xE920, 0xE930, 0xE8BD, 0xE92D] {
            assert!(
                decode(hw1, 0x2010, 0).is_none(),
                "{hw1:#06x}: sp in the list"
            );
        }

        // `pc` in a store's list: bit 15 is `(0)` in `STM`/`STMDB`/`PUSH`.
        // Refused for the stores, decoded for the loads.
        assert!(decode(0xE880, 0x8010, 0).is_none(), "stm with pc");
        assert!(decode(0xE920, 0x8010, 0).is_none(), "stmdb with pc");
        assert!(decode(0xE92D, 0x8010, 0).is_none(), "push with pc");
        assert_eq!(dec(0xE890, 0x8010).to_string(), "ldm.w r0, {r4, pc}");

        // `BitCount(registers) < 2` is the third refused rule; it has a test
        // of its own below, because it is the only one that turns on what the
        // *text* would mean rather than on what the bits are.

        // `P == '1' && M == '1'` — `pc` and `lr` together in a load list.
        // Decoded.
        assert_eq!(dec(0xE8BD, 0xC010).to_string(), "pop.w {r4, lr, pc}");
        assert_eq!(dec(0xE8B0, 0xC010).to_string(), "ldm.w r0!, {r4, lr, pc}");

        // `n == 15` — `pc` as the base register. Decoded.
        assert_eq!(dec(0xE88F, 0x0006).to_string(), "stm.w pc, {r1, r2}");
        assert_eq!(dec(0xE83F, 0xC000).to_string(), "rfedb pc!");

        // `wback && registers<n> == '1'` — the base in its own list, with
        // writeback. Decoded; the stored value of the base is UNKNOWN unless
        // it is the lowest-numbered register in the list (A7.7.159).
        assert_eq!(dec(0xE8A0, 0x0007).to_string(), "stm.w r0!, {r0-r2}");
        assert_eq!(dec(0xE8B0, 0x0007).to_string(), "ldm.w r0!, {r0-r2}");
    }

    /// `BitCount(registers) < 2` — one rule, all six wide forms, and the
    /// single-register `PUSH`/`POP` question with it.
    ///
    /// The rule is not about the bits being unrepresentable; it is about the
    /// *text*. `e92d 0001` is a `PUSH` T2 of `{r0}`, and A7.7.101 says a
    /// one-register list assembles to T1 or T3, so `push.w {r0}` comes back
    /// from an assembler as T3 — `f84d 0d04`, the `STR <Rt>,[SP,#-4]!` form —
    /// which is not the halfword pair we started from. `{}` is worse still:
    /// no assembler parses an empty list at all. Both are therefore refused,
    /// in `decode` and in `encode` alike.
    #[test]
    fn a_wide_list_needs_two_registers() {
        // One first halfword per wide form, and the mnemonic it prints.
        let forms: [(u16, &str); 6] = [
            (0xE880, "stm.w"),
            (0xE8B0, "ldm.w"),
            (0xE920, "stmdb"),
            (0xE930, "ldmdb"),
            (0xE8BD, "pop.w"),
            (0xE92D, "push.w"),
        ];
        for (hw1, mnemonic) in forms {
            // The empty list.
            assert!(decode(hw1, 0x0000, 0).is_none(), "{mnemonic} {{}}");

            // Exactly one register, in each field that can hold one on its
            // own: an ordinary list bit, and bit 14 (`M`, i.e. `lr`), which
            // all six encodings permit.
            for one in [0x0001u16, 0x0010, 0x4000] {
                assert!(
                    decode(hw1, one, 0).is_none(),
                    "{mnemonic} of one register, list {one:#06x}"
                );
            }

            // Exactly two is the shortest list this group encodes, and it is
            // the boundary: `{r0, r4}` decodes and round-trips.
            let two = dec(hw1, 0x0011);
            assert!(
                two.to_string().starts_with(mnemonic),
                "{two} should be a {mnemonic}"
            );
            assert_eq!(encode(&two), Some((hw1, 0x0011)));
        }

        // `pop.w {pc}` is the case a reader will look for: a wide
        // single-register pop in a function epilogue is real firmware, and it
        // is `ldr pc, [sp], #4` (A7.7.99's T3), not this encoding.
        assert!(decode(0xE8BD, 0x8000, 0).is_none(), "pop.w {{pc}}");
        assert!(decode(0xE8B0, 0x8000, 0).is_none(), "ldm.w r0!, {{pc}}");

        // The re-encoder obeys the same rule from the other side: an `Insn`
        // assembled by hand with a short list is refused rather than turned
        // into halfwords `decode` would not hand back.
        let stm = dec(0xE880, 0x0011);
        for short in [0x0000u16, 0x0001, 0x4000] {
            let mut mangled = stm;
            mangled.operands = [Operand::Reg(Reg(0)), Operand::RegList(short)]
                .iter()
                .copied()
                .collect();
            assert_eq!(encode(&mangled), None, "stm of list {short:#06x}");
        }
        let push = dec(0xE92D, 0x0011);
        for short in [0x0000u16, 0x0001, 0x4000] {
            let mut mangled = push;
            mangled.operands = [Operand::RegList(short)].iter().copied().collect();
            assert_eq!(encode(&mangled), None, "push of list {short:#06x}");
        }
    }

    /// `decode` refuses halfwords outside its own group. The dispatcher in
    /// `mod.rs` already filters on `hw1`, so nothing in the crate reaches this
    /// guard — but `decode` is callable on its own, and a group test that
    /// never asks what happens off the edge of the group is not a group test.
    #[test]
    fn decode_refuses_halfwords_outside_the_group() {
        // `hw1[15:11] != 0b11101`: a 16-bit halfword, and the neighbouring
        // 32-bit groups either side (`0xE700` is not a 32-bit prefix at all,
        // `0xEA00` is data-processing (shifted register)).
        for hw1 in [0x0000u16, 0x4770, 0xE700, 0xEA00, 0xF000] {
            assert!(decode(hw1, 0x0011, 0).is_none(), "{hw1:#06x}");
        }
        // `hw1[10:9] != 0b00` — Table A5-9's other `op2` rows reached through
        // the same `op1 == 01`: `0xE860` is load/store dual and exclusive,
        // `0xE8C0` is the other half of it.
        assert!(decode(0xE860, 0x0011, 0).is_none());
        assert!(decode(0xE8C0, 0x0011, 0).is_none());
        // `hw1[6] != 0` — the bit Table A5-16 fixes at zero between `op` and
        // `W`, which is `op2[2]` in Table A5-9's `00xx0xx` pattern.
        assert!(decode(0xE8C0 | 0x0040, 0x0011, 0).is_none());
        assert!(decode(0xE8A0 | 0x0040, 0x0011, 0).is_none());

        // The three tests above are each one clause of the same `if`, and the
        // halfwords they use fail the other two clauses as well — so none of
        // them shows that a clause is doing any work on its own. These do:
        // each fails exactly one clause, and each has `op == 01` and a
        // register list that would otherwise decode as a perfectly ordinary
        // `ldm.w r0, {r1, r2}`.
        //
        // `0xEA90 0x0006` is `eors.w r0, r0, r6`, from Table A5-9's
        // data-processing (shifted register) row — the group's own `op1`,
        // the wrong `op2`. `0xF090 0x0006` is `eors r0, r0, #6`, from
        // data-processing (modified immediate) — the wrong `op1` entirely,
        // but `op2[1:0]` and `hw1[6]` that this group would accept. Neither
        // is a load-multiple, and neither would be noticed if this module
        // claimed it, because `mod.rs` never routes them here.
        for (hw1, what) in [(0xEA90u16, "eors.w"), (0xF090, "eors")] {
            assert!(
                decode(hw1, 0x0006, 0).is_none(),
                "{hw1:#06x} is `{what}`, not a load/store-multiple"
            );
        }
        // …and the same `op`/`W`/`L`/`Rn` bits under the group's own prefix
        // do decode, so the rejections above are of the prefix and the `op2`
        // row, not of the rest of the halfword.
        assert_eq!(dec(0xE890, 0x0006).to_string(), "ldm.w r0, {r1, r2}");
    }

    /// The A/R-only rows carry fixed second halfwords, and every deviation
    /// from them is UNDEFINED rather than a differently-decoded instruction.
    #[test]
    fn srs_and_rfe_fixed_fields() {
        // RFE's `hw2` is `(1)(1)` followed by fourteen `(0)`s.
        assert!(
            decode(0xE830, 0xC001, 0).is_none(),
            "rfe hw2 must be 0xc000"
        );
        assert!(decode(0xE830, 0x0000, 0).is_none());
        assert!(decode(0xE830, 0xE000, 0).is_none());

        // SRS's `hw2` holds a five-bit mode and nothing else, and its `Rn`
        // field is fixed at `sp`.
        assert!(decode(0xE82D, 0xC020, 0).is_none(), "srs hw2 bit 5");
        assert!(decode(0xE82C, 0xC011, 0).is_none(), "srs base must be sp");
        for mode in 0u16..32 {
            let i = dec(0xE82D, 0xC000 | mode);
            assert_eq!(i.operands.get(1), Some(Operand::Imm(i64::from(mode))));
            assert_eq!(encode(&i), Some((0xE82D, 0xC000 | mode)));
        }

        // `RFE` is an exception return: it loads the pc from memory, so it
        // branches. `SRS` stores and does not. See the module docs.
        assert!(dec(0xE830, 0xC000).is_branch());
        assert!(dec(0xE830, 0xC000).writes_pc());
        assert!(!dec(0xE830, 0xC000).is_call());
        assert!(!dec(0xE82D, 0xC011).is_branch());
        assert!(!dec(0xE82D, 0xC011).writes_pc());
    }

    /// The re-encoder refuses shapes it did not produce.
    #[test]
    fn encode_rejects_foreign_forms() {
        let i = dec(0xE8A0, 0x0006);

        // A narrow `stm` is A5.2.4's encoding, not this group's.
        let mut narrow = i;
        narrow.width = Width::Narrow;
        assert_eq!(encode(&narrow), None);

        // Nothing here sets flags.
        let mut flags = i;
        flags.sets_flags = true;
        assert_eq!(encode(&flags), None);

        // A foreign mnemonic, and a foreign encoding name for a local one.
        let mut foreign = i;
        foreign.mnemonic = "ldr";
        assert_eq!(encode(&foreign), None);
        let mut wrong_enc = i;
        wrong_enc.encoding = "T1";
        assert_eq!(encode(&wrong_enc), None, "`stm` has no T1 in this group");

        // `SRS` and `RFE` number the decrement-before direction T1 and the
        // increment-after one T2, so for them the encoding name is not
        // decoration — it is the `op` field. A mnemonic carrying the other
        // direction's name is refused rather than silently encoded as the
        // direction the *name* says, which would flip `op` behind the caller.
        let mut srs = dec(0xE82D, 0xC011);
        srs.encoding = "T2";
        assert_eq!(encode(&srs), None, "`srsdb` is T1; T2 is `srsia`");
        let mut rfe = dec(0xE830, 0xC000);
        rfe.encoding = "T2";
        assert_eq!(encode(&rfe), None, "`rfedb` is T1; T2 is `rfeia`");

        // A list with `sp` in it, or `pc` in a store's.
        let mut with_sp = i;
        with_sp.operands = [Operand::Text("r0!"), Operand::RegList(0x2006)]
            .iter()
            .copied()
            .collect();
        assert_eq!(encode(&with_sp), None);
        let mut store_pc = i;
        store_pc.operands = [Operand::Text("r0!"), Operand::RegList(0x8006)]
            .iter()
            .copied()
            .collect();
        assert_eq!(encode(&store_pc), None);
        let mut load_pc = dec(0xE8B0, 0x0006);
        load_pc.operands = [Operand::Text("r0!"), Operand::RegList(0x8006)]
            .iter()
            .copied()
            .collect();
        assert_eq!(encode(&load_pc), Some((0xE8B0, 0x8006)), "a load may");

        // An operand shape that is neither a register nor a writeback marker.
        let mut odd = i;
        odd.operands = [Operand::Imm(0), Operand::RegList(0x0006)]
            .iter()
            .copied()
            .collect();
        assert_eq!(encode(&odd), None);

        // A mode number that does not fit `hw2[4:0]`.
        let mut mode = dec(0xE82D, 0xC011);
        mode.operands = [Operand::Text("sp!"), Operand::Imm(32)]
            .iter()
            .copied()
            .collect();
        assert_eq!(encode(&mode), None);
    }

    /// The re-encoder refuses a wrong *number* or *shape* of operands in every
    /// arm, rather than encoding whatever happens to be in slot 0.
    ///
    /// `Insn` is a public struct with public fields, so a consumer — or a
    /// consumer's mistake — can hand `encode` any shape at all. Silently
    /// encoding the wrong one is the failure mode that matters here: these
    /// halfwords get written into a firmware image.
    #[test]
    fn encode_rejects_wrong_operand_counts_and_shapes() {
        /// An `Insn` of this group with `ops` substituted for its operands.
        fn with(template: Insn, ops: &[Operand]) -> Insn {
            let mut insn = template;
            insn.operands = ops.iter().copied().collect();
            insn
        }

        let list = Operand::RegList(0x0011);
        let push = dec(0xE92D, 0x0011);
        let stm = dec(0xE880, 0x0011);
        let srs = dec(0xE82D, 0xC011);
        let rfe = dec(0xE830, 0xC000);

        // `push`/`pop` take exactly one operand, and it must be a list.
        assert_eq!(encode(&with(push, &[])), None, "push with no operands");
        assert_eq!(
            encode(&with(push, &[list, Operand::Reg(Reg::SP)])),
            None,
            "push with a spare operand"
        );
        assert_eq!(
            encode(&with(push, &[Operand::Reg(Reg(0))])),
            None,
            "push of a register, not a list"
        );
        // `sp` and `pc` in a `push` list, from the encoder's side.
        assert_eq!(encode(&with(push, &[Operand::RegList(0x2011)])), None);
        assert_eq!(encode(&with(push, &[Operand::RegList(0x8011)])), None);
        // A `pop` may take `pc`; only the `push` half refuses it.
        let pop = dec(0xE8BD, 0x0011);
        assert_eq!(
            encode(&with(pop, &[Operand::RegList(0x8011)])),
            Some((0xE8BD, 0x8011))
        );
        // Neither has a T1 or T3 in this group.
        let mut narrow_encoding = push;
        narrow_encoding.encoding = "T3";
        assert_eq!(
            encode(&narrow_encoding),
            None,
            "`push` T3 is not this group"
        );

        // The four base-register forms take exactly two.
        assert_eq!(encode(&with(stm, &[])), None, "stm with no operands");
        assert_eq!(
            encode(&with(stm, &[Operand::Reg(Reg(0))])),
            None,
            "stm with no list"
        );
        assert_eq!(
            encode(&with(stm, &[Operand::Reg(Reg(0)), list, Operand::Imm(0)])),
            None,
            "stm with a spare operand"
        );

        // `SRS` takes a base and a mode; `RFE` takes only a base. Both read
        // the base through `base_of`, which refuses anything that is neither a
        // register nor a `"rN!"` writeback marker.
        assert_eq!(encode(&with(srs, &[])), None, "srs with no operands");
        assert_eq!(
            encode(&with(srs, &[Operand::Text("sp"), Operand::Imm(0x11)])),
            None,
            "`\"sp\"` is not a writeback marker, and `Reg` is how a bare base is spelt"
        );
        assert_eq!(
            encode(&with(
                srs,
                &[Operand::Text("sp!"), Operand::Imm(0x11), Operand::Imm(0)]
            )),
            None,
            "srs with a spare operand"
        );
        assert_eq!(encode(&with(rfe, &[])), None, "rfe with no operands");
        assert_eq!(
            encode(&with(rfe, &[Operand::Imm(0)])),
            None,
            "rfe whose base is not a register"
        );
        assert_eq!(
            encode(&with(rfe, &[Operand::Text("r0!"), Operand::Imm(0)])),
            None,
            "rfe with a spare operand"
        );
    }

    /// The dispatcher in `mod.rs` actually reaches this module: `op1 == 01`
    /// with `op2` matching `00xx0xx` (Table A5-9). Decoding through the
    /// public entry point is the only way to catch a routing mistake, since
    /// every test above calls `decode` directly.
    #[test]
    fn reachable_through_the_dispatcher() {
        for (hw1, hw2, text) in [
            (0xE92Du16, 0x4010u16, "push.w {r4, lr}"),
            (0xE8BD, 0x8010, "pop.w {r4, pc}"),
            (0xE8A0, 0x0006, "stm.w r0!, {r1, r2}"),
            (0xE930, 0x0030, "ldmdb r0!, {r4, r5}"),
            (0xE82D, 0xC011, "srsdb sp!, #0x11"),
            (0xE9B0, 0xC000, "rfeia r0!"),
        ] {
            let routed = super::super::decode_halfwords(hw1, hw2, 0x1000, Target::Union);
            assert!(
                routed.is_some(),
                "{hw1:#06x} {hw2:#06x} did not reach this module"
            );
            let insn = routed.unwrap();
            assert_eq!(insn.to_string(), text);
            assert_eq!(insn.width, Width::Wide);
        }
    }

    /// Writeback is carried on the base operand itself, and survives the trip
    /// out and back.
    #[test]
    fn writeback_operand() {
        let with = dec(0xE8A0, 0x0006);
        assert_eq!(with.operands.get(0), Some(Operand::Text("r0!")));
        let without = dec(0xE880, 0x0006);
        assert_eq!(without.operands.get(0), Some(Operand::Reg(Reg(0))));
        assert_ne!(with, without, "the `!` is not cosmetic");

        // Every register, in both states.
        for n in 0u16..16 {
            let hw1 = 0xE880 | (1 << 5) | n;
            let insn = dec(hw1, 0x0006);
            assert_eq!(
                base_of(insn.operands.get(0).unwrap()),
                Some((Reg(n as u8), true))
            );
            assert_eq!(encode(&insn), Some((hw1, 0x0006)));
            let insn = dec(0xE880 | n, 0x0006);
            assert_eq!(
                base_of(insn.operands.get(0).unwrap()),
                Some((Reg(n as u8), false))
            );
        }
    }
}
