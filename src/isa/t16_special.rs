//! Special data instructions and branch and exchange — `hw1[15:10] == 0b010001`
//! (ARM DDI 0403E.e A5.2.3, Table A5-4; ARM DDI 0406C A6.2.3, Table A6-4).
//!
//! This is the one corner of the 16-bit space that can name `r8`–`r15`, and it
//! pays for that with the most irregular field layout in Thumb. Every encoding
//! here is `0100 01 opcode(4) …`, but the `opcode` field is *not* a clean
//! operation selector: its bottom two bits overlap the operands.
//!
//! ```text
//!  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
//!   0  1  0  0  0  1 <-- opcode -->
//!   0  1  0  0  0  1  0  0 DN <---- Rm ----> <Rdn>   ADD (register) T2
//!   0  1  0  0  0  1  0  1  N <---- Rm ----> <-Rn->   CMP (register) T2
//!   0  1  0  0  0  1  1  0  D <---- Rm ----> <-Rd->   MOV (register) T1
//!   0  1  0  0  0  1  1  1  0 <---- Rm ---->(0)(0)(0) BX T1
//!   0  1  0  0  0  1  1  1  1 <---- Rm ---->(0)(0)(0) BLX (register) T1
//! ```
//!
//! So `opcode[1]` is the high-register bit (`DN`, `N` or `D`, or the `BX`/`BLX`
//! selector) and `opcode[0]` is `Rm[3]`. That is why Table A5-4 spends three
//! of its sixteen rows on `CMP` (`0101` and `011x`): those are the `N`/`Rm[3]`
//! combinations in which at least one operand is high. The fourth combination,
//! `opcode == 0100`, is `N == 0` with `Rm < 8` — both operands low — and the
//! architecture declares it UNPREDICTABLE, because `CMP (register)` T1
//! (A5.2.2, `0100 0010 10 Rm Rn`) already encodes that case. `CMP (register)`
//! T2's own pseudocode agrees: *`if n < 8 && m < 8 then UNPREDICTABLE`*. We
//! therefore decode `0x4500..=0x453F` as `None`.
//!
//! # The high-register bit
//!
//! The destination or first operand is the 4-bit value `opcode[1]:field[2:0]`,
//! **not** the 3-bit field alone — `DN:Rdn`, `N:Rn`, `D:Rd` in the manual's own
//! notation. `Rm` is a full 4-bit field at `[6:3]`, so it needs no such trick.
//! Hence `add r10, r3` is `0x449A` (`DN = 1`, `Rdn = 0b010`, `Rm = 0b0011`) and
//! `mov r8, r3` is `0x4698`.
//!
//! # Flags
//!
//! `ADD (register)` T2 and `MOV (register)` T1 have `setflags = FALSE`
//! unconditionally (A7.7.4, A7.7.77) — no `S` bit, no IT-block dependence.
//! They exist *because* the low-register forms in A5.2.1 are flag-setting, so a
//! compiler needs some 16-bit way to move or add without destroying a pending
//! comparison. `CMP` writes N, Z, C and V by definition but carries no `S`
//! suffix in UAL. [`Insn::sets_flags`] models the printed suffix (`Display`
//! appends `"s"` when it is set), so every instruction this module produces has
//! it `false` — including `cmp`, which would otherwise print as `cmps`.
//!
//! # `sp` and `pc`
//!
//! `ADD (register)` T2's pseudocode redirects two cases away from itself:
//! *`if (DN:Rdn) == '1101' || Rm == '1101' then SEE ADD (SP plus register)`*.
//! Both of those halfwords are in this group, and both are decoded here, as the
//! `ADD (SP plus register)` forms they are (A7.7.6):
//!
//! * `Rm == 1101` is encoding T1, `add <Rdm>, sp, <Rdm>` — three operands,
//!   with the destination doubling as the added register.
//! * `DN:Rdn == 1101` (with `Rm != 1101`) is encoding T2, `add sp, <Rm>`.
//! * `0x44ED` matches both diagrams; T2's *`if Rm == '1101' then SEE encoding
//!   T1`* breaks the tie in favour of T1, so it reads `add sp, sp, sp`.
//!
//! Both are two-operand-shaped in the plain-`ADD` sense (`add sp, r7` is
//! literally `DN:Rdn == 13`), which is why the re-encoder needs only one
//! formula for the two-operand case.
//!
//! `pc` is legal as `Rd`/`Rdn`/`Rm` here (`MOV`) or as `Rm`/`Rdn` (`ADD`), and
//! `mov pc, rm` *is a branch* — A7.7.77: "If `<Rd>` is the PC … the instruction
//! causes a branch to the address moved to the PC". [`Insn::writes_pc`] spots
//! that by looking at operand 0, so the destination is always pushed first.
//! Arm deprecates, but does not forbid, `sp`/`pc` combinations such as
//! `mov sp, pc`; a few UNPREDICTABLE operand combinations are likewise decoded
//! rather than rejected, because a disassembler analysing a firmware image is
//! more useful reporting the halfword that is there than refusing to:
//!
//! * `ADD` T2 with `d == 15 && m == 15` (`0x44FF`) — UNPREDICTABLE (A7.7.4).
//! * `CMP` T2 with `n == 15 || m == 15` — UNPREDICTABLE (A7.7.28).
//! * `BLX` with `m == 15` (`0x47F8`) — UNPREDICTABLE (A7.7.19).
//!
//! The one operand-level rejection is the `(0)(0)(0)` field of `BX`/`BLX`. A
//! bit drawn as `(0)` that is not zero makes the instruction UNPREDICTABLE
//! (ARM DDI 0403E.e D6.1), and unlike the cases above the offending bits cannot
//! be carried in an [`Insn`] — so decoding `0x4701` as `bx r0` would silently
//! discard information and re-encode to a different halfword. We return `None`,
//! which also keeps the round-trip total exact. (LLVM is lenient here and
//! prints `bx r0`; this is a deliberate divergence, not an oversight.)
//!
//! # Availability
//!
//! Table A6-4 in ARM DDI 0406C carries the variant column the M-profile manual
//! omits, and two rows of it matter to anyone reading pre-Cortex firmware:
//!
//! | opcode | form | from |
//! |---|---|---|
//! | `0000` | `ADD` with both registers low | v6T2 (UNPREDICTABLE earlier) |
//! | `0001`, `001x` | `ADD` with a high register | v4T |
//! | `0101`, `011x` | `CMP` with a high register | v4T |
//! | `1000` | `MOV` with both registers low | v6 (UNPREDICTABLE earlier) |
//! | `1001`, `101x` | `MOV` with a high register | v4T |
//! | `110x` | `BX` | v4T |
//! | `111x` | `BLX (register)` | v5T |
//!
//! Both of the "both registers low" rows are decoded — this crate does not
//! model a target variant — but `0x4400..=0x4407` (`add r0-r7, r0-r7`) and
//! `0x4600..=0x4607` (`mov r0-r7, r0-r7`) appearing in an ARM7TDMI image are a
//! strong hint that the bytes are data, not code.

use super::{Insn, Operand, Reg, Width};

/// Decode one halfword of this group, or `None` if `hw1` is not in it or is one
/// of the two UNPREDICTABLE patterns this module refuses (see the module docs).
///
/// `hw2` is unused: every encoding here is 16 bits.
pub(crate) fn decode(hw1: u16, _hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 >> 10 != 0b010001 {
        return None;
    }

    // `opcode[3:2]` selects the operation; `opcode[1]` is the high-register bit
    // (or the BX/BLX selector) and `opcode[0]` is `Rm[3]`, already folded into
    // `rm` below.
    let op = (hw1 >> 8) & 0b11;
    let hi = ((hw1 >> 7) & 1) as u8;
    let rm = Reg(((hw1 >> 3) & 0xF) as u8);
    let low3 = (hw1 & 0b111) as u8;
    let rdn = Reg((hi << 3) | low3);

    Some(match op {
        // 00xx: ADD (register) T2, or ADD (SP plus register) T1/T2.
        0b00 => {
            if rm.num() == 13 {
                // `Rm == '1101'`: ADD (SP plus register) T1, `add rdm, sp, rdm`.
                narrow(
                    "add",
                    "T1",
                    addr,
                    &[Operand::Reg(rdn), Operand::Reg(Reg::SP), Operand::Reg(rdn)],
                )
            } else {
                // `add rdn, rm`. When `DN:Rdn == 1101` this is ADD (SP plus
                // register) T2, whose syntax `add sp, <Rm>` is the same shape.
                narrow("add", "T2", addr, &[Operand::Reg(rdn), Operand::Reg(rm)])
            }
        }
        // 01xx: CMP (register) T2 — except `0100`, both operands low, which is
        // UNPREDICTABLE (Table A5-4, and A7.7.28's `n < 8 && m < 8`).
        0b01 => {
            if hi == 0 && rm.is_low() {
                return None;
            }
            narrow("cmp", "T2", addr, &[Operand::Reg(rdn), Operand::Reg(rm)])
        }
        // 10xx: MOV (register) T1. Destination first, so that `mov pc, rm` is
        // visible to `Insn::writes_pc`.
        0b10 => narrow("mov", "T1", addr, &[Operand::Reg(rdn), Operand::Reg(rm)]),
        // 11xx: BX (opcode 110x) and BLX (register) (opcode 111x). Bits [2:0]
        // are `(0)(0)(0)`; non-zero is UNPREDICTABLE and not representable.
        _ => {
            if low3 != 0 {
                return None;
            }
            let mnemonic = if hi == 0 { "bx" } else { "blx" };
            narrow(mnemonic, "T1", addr, &[Operand::Reg(rm)])
        }
    })
}

/// Re-encode an instruction this module decoded, back to its halfword.
///
/// Returns `None` for anything outside this group, which includes the
/// flag-setting look-alikes from A5.2.1/A5.2.2 (`adds`, `movs`, and the
/// both-registers-low `cmp` T1) — those are another module's encodings, and
/// refusing them here is what keeps the two from silently trading patterns.
///
/// [`Insn::cond`] is ignored rather than rejected: nothing in this group has a
/// condition field, so a condition can only have come from an enclosing `IT`
/// block, which does not change the instruction's own bits.
pub(crate) fn encode(insn: &Insn) -> Option<u16> {
    if insn.width != Width::Narrow || insn.sets_flags {
        return None;
    }
    let (a, b, c) = (
        insn.operands.get(0),
        insn.operands.get(1),
        insn.operands.get(2),
    );
    match (insn.mnemonic, a, b, c) {
        // `add rdm, sp, rdm` — ADD (SP plus register) T1. The destination and
        // the added register are one field, so they must agree.
        ("add", Some(Operand::Reg(d)), Some(Operand::Reg(n)), Some(Operand::Reg(m)))
            if n.num() == 13 && m.num() == d.num() =>
        {
            Some(0x4400 | high(d) | (13 << 3) | low(d))
        }
        // `add rdn, rm` — ADD (register) T2, and (when `rdn` is `sp`) ADD (SP
        // plus register) T2, which shares the formula because `add sp, rm` is
        // just `DN:Rdn == 1101`. `rm == sp` is not encodable this way: that
        // halfword is the three-operand T1 above.
        ("add", Some(Operand::Reg(d)), Some(Operand::Reg(m)), None) if m.num() != 13 => {
            Some(0x4400 | high(d) | (u16::from(m.num()) << 3) | low(d))
        }
        // `cmp rn, rm` — T2, high registers only.
        ("cmp", Some(Operand::Reg(n)), Some(Operand::Reg(m)), None)
            if !n.is_low() || !m.is_low() =>
        {
            Some(0x4500 | high(n) | (u16::from(m.num()) << 3) | low(n))
        }
        // `mov rd, rm` — T1.
        ("mov", Some(Operand::Reg(d)), Some(Operand::Reg(m)), None) => {
            Some(0x4600 | high(d) | (u16::from(m.num()) << 3) | low(d))
        }
        ("bx", Some(Operand::Reg(m)), None, None) => Some(0x4700 | (u16::from(m.num()) << 3)),
        ("blx", Some(Operand::Reg(m)), None, None) => Some(0x4780 | (u16::from(m.num()) << 3)),
        _ => None,
    }
}

/// Build a 16-bit, unconditional, flag-preserving instruction of this group.
fn narrow(mnemonic: &'static str, encoding: &'static str, addr: u32, ops: &[Operand]) -> Insn {
    Insn {
        mnemonic,
        encoding,
        addr,
        width: Width::Narrow,
        cond: None,
        sets_flags: false,
        explicit_width: false,
        operands: ops.iter().copied().collect(),
    }
}

/// `r`'s bit 3, placed at bit 7 — the `DN`/`N`/`D` high-register bit.
fn high(r: Reg) -> u16 {
    u16::from(r.num() & 0b1000) << 4
}

/// `r`'s bits `[2:0]`, the three-bit part of a `DN:Rdn`-style field.
fn low(r: Reg) -> u16 {
    u16::from(r.num() & 0b111)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a halfword of this group, panicking with the pattern if it does
    /// not decode — a failing assertion should name the encoding it tripped on.
    fn dec(hw1: u16) -> Insn {
        let decoded = decode(hw1, 0, 0x1000);
        // `assert!` rather than `unwrap_or_else(|| panic!(…))`: the closure in
        // the latter is a function that never runs, and this crate's coverage
        // gate is 100% of functions.
        assert!(decoded.is_some(), "{hw1:#06x} failed to decode");
        decoded.unwrap()
    }

    #[test]
    fn exhaustive_round_trip() {
        let mut decoded = 0;
        let mut round_tripped = 0;
        for hw1 in 0x4400u16..=0x47FF {
            // No `let … else`: this crate's MSRV is 1.58 (that is 1.65).
            if let Some(insn) = decode(hw1, 0, 0x2000) {
                decoded += 1;
                assert_eq!(
                    encode(&insn),
                    Some(hw1),
                    "{hw1:#06x} re-encoded wrongly as `{insn}`"
                );
                round_tripped += 1;
            }
        }

        // 1024 halfwords, 288 of which do not decode:
        //   * 64 for `opcode == 0100` (`0x4500..=0x453F`), UNPREDICTABLE
        //     because `CMP (register)` T1 already encodes two low registers;
        //   * 224 `BX`/`BLX` patterns with a non-zero `(0)(0)(0)` field
        //     (`0x4700..=0x47FF` is 256 halfwords, of which only the 32 with
        //     `hw1[2:0] == 0` are architecturally defined).
        assert_eq!(decoded, 736, "unexpected number of defined encodings");
        assert_eq!(round_tripped, decoded);

        for hw1 in 0x4500u16..=0x453F {
            assert!(decode(hw1, 0, 0).is_none(), "{hw1:#06x} is UNPREDICTABLE");
        }
        for hw1 in 0x4700u16..=0x47FF {
            assert_eq!(
                decode(hw1, 0, 0).is_some(),
                hw1 & 0b111 == 0,
                "{hw1:#06x}: BX/BLX bits [2:0] must be 000"
            );
        }
    }

    #[test]
    fn bx_lr_is_0x4770() {
        // The most common instruction in ARM firmware: `0100 0111 0 1110 000`.
        let insn = dec(0x4770);
        assert_eq!(insn.mnemonic, "bx");
        assert_eq!(insn.encoding, "T1");
        assert_eq!(insn.operands.get(0), Some(Operand::Reg(Reg::LR)));
        assert_eq!(insn.to_string(), "bx lr");
        assert_eq!(encode(&insn), Some(0x4770));
    }

    #[test]
    fn high_register_cases() {
        // mov r8, r3: `0100 0110 D=1 Rm=0011 Rd=000`.
        let mov = dec(0x4698);
        assert_eq!((mov.mnemonic, mov.encoding), ("mov", "T1"));
        assert_eq!(mov.to_string(), "mov r8, r3");
        assert!(!mov.sets_flags, "MOV (register) T1 preserves the flags");

        // add r10, r3: `0100 0100 DN=1 Rm=0011 Rdn=010`.
        let add = dec(0x449A);
        assert_eq!((add.mnemonic, add.encoding), ("add", "T2"));
        assert_eq!(add.to_string(), "add r10, r3");
        assert!(!add.sets_flags, "ADD (register) T2 preserves the flags");

        // cmp r9, r10: `0100 0101 N=1 Rm=1010 Rn=001`.
        let cmp = dec(0x45D1);
        assert_eq!((cmp.mnemonic, cmp.encoding), ("cmp", "T2"));
        assert_eq!(cmp.to_string(), "cmp r9, r10");
        assert!(
            !cmp.sets_flags,
            "CMP writes the flags but takes no S suffix, and `sets_flags` is the suffix"
        );

        // blx r3: `0100 0111 1 Rm=0011 000`.
        let blx = dec(0x4798);
        assert_eq!((blx.mnemonic, blx.encoding), ("blx", "T1"));
        assert_eq!(blx.to_string(), "blx r3");

        // The `D`/`N`/`DN` bit is the register's bit 3 and nothing else: build
        // `mov rn, rn` for every register from the two halves of the field and
        // check both operands come back as that register.
        for n in 0u8..16 {
            let hw1 = 0x4600 | (u16::from(n & 8) << 4) | (u16::from(n) << 3) | u16::from(n & 7);
            let mov = dec(hw1);
            assert_eq!(
                mov.operands.get(0),
                Some(Operand::Reg(Reg(n))),
                "{hw1:#06x}"
            );
            assert_eq!(
                mov.operands.get(1),
                Some(Operand::Reg(Reg(n))),
                "{hw1:#06x}"
            );
            assert_eq!(encode(&mov), Some(hw1));
        }
    }

    #[test]
    fn sp_forms() {
        // `Rm == 1101` is ADD (SP plus register) T1, three operands.
        assert_eq!(dec(0x4468).to_string(), "add r0, sp, r0");
        // `DN:Rdn == 1101` is ADD (SP plus register) T2, `add sp, <Rm>`.
        assert_eq!(dec(0x44BD).to_string(), "add sp, r7");
        // Both at once: T2 defers to T1 (A7.7.6), so this is `add sp, sp, sp`.
        assert_eq!(dec(0x44ED).to_string(), "add sp, sp, sp");
        // Plain high-register ADD is unaffected by any of that.
        assert_eq!(dec(0x4478).to_string(), "add r0, pc");
    }

    #[test]
    fn pc_writes_are_branches() {
        assert!(dec(0x4770).writes_pc(), "bx lr");
        assert!(dec(0x46F7).writes_pc(), "mov pc, lr");
        assert!(dec(0x44F7).writes_pc(), "add pc, lr");
        assert!(!dec(0x4608).writes_pc(), "mov r0, r1");
        assert!(!dec(0x4541).writes_pc(), "cmp r1, r8");
        // No operand of any of these is a resolvable absolute address.
        assert_eq!(dec(0x4770).branch_target(), None);
    }

    #[test]
    fn classification() {
        let bx = dec(0x4770);
        assert!(
            bx.is_branch() && !bx.is_call(),
            "bx is a branch, not a call"
        );

        let blx = dec(0x4798);
        assert!(blx.is_branch() && blx.is_call(), "blx r3 is a call");

        // `mov pc, rm` is a branch only by virtue of writing pc.
        assert!(dec(0x46F7).is_branch());
        assert!(!dec(0x46F7).is_call());
        assert!(!dec(0x4608).is_branch(), "mov r0, r1");
    }

    #[test]
    fn encode_rejects_foreign_forms() {
        // Both-low `cmp` is CMP (register) T1, from A5.2.2, not this group.
        let mut low_cmp = dec(0x45D1);
        low_cmp.operands = [Operand::Reg(Reg(1)), Operand::Reg(Reg(2))]
            .iter()
            .copied()
            .collect();
        assert_eq!(encode(&low_cmp), None);

        // A flag-setting `add` is `ADDS`, an A5.2.1 encoding.
        let mut adds = dec(0x449A);
        adds.sets_flags = true;
        assert_eq!(encode(&adds), None);

        // `add rdn, sp` two-operand-shaped is not encodable: that halfword is
        // the three-operand ADD (SP plus register) T1.
        let mut add_sp = dec(0x449A);
        add_sp.operands = [Operand::Reg(Reg(1)), Operand::Reg(Reg::SP)]
            .iter()
            .copied()
            .collect();
        assert_eq!(encode(&add_sp), None);

        // Nothing wide belongs here.
        let mut wide = dec(0x4698);
        wide.width = Width::Wide;
        assert_eq!(encode(&wide), None);
    }

    #[test]
    fn decode_ignores_other_groups_and_hw2() {
        assert!(decode(0x4000, 0, 0).is_none(), "A5.2.2 data processing");
        assert!(decode(0x4800, 0, 0).is_none(), "LDR (literal)");
        // hw2 is not consulted, and neither is the address.
        assert_eq!(decode(0x4770, 0xFFFF, 0), decode(0x4770, 0x0000, 0));
        assert_eq!(decode(0x4770, 0, 0x8000).unwrap().addr, 0x8000);
    }
}
