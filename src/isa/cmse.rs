//! Armv8-M Security Extension (CMSE): `SG`, `BXNS`, `BLXNS` and the `TT`
//! family (ARM DDI 0553B.y B4.3, and the instruction pages in C2.4).
//!
//! # Why this is a profile-owned slice and not another group module
//!
//! Every one of these encodings is *already spoken for* in Armv7. They are not
//! new rows in an unallocated part of the map; they are patterns Armv7 gives to
//! other instructions, which Armv8-M reassigns when the Security Extension is
//! present. That makes this module the same shape as [`super::thumbee`] — a
//! slice owned by a decode mode — rather than a nineteenth sibling of the
//! `t32_*` groups, and it is why [`owns`] exists.
//!
//! What the Armv7 decoders make of them, which is what this crate returned
//! before this module existed:
//!
//! | Armv8-M | halfwords | what Armv7 calls it |
//! |---|---|---|
//! | `sg` | `0xE97F 0xE97F` | `ldrd lr, r9, [pc, #-508]!` |
//! | `tt r0, r1` | `0xE841 0xF000` | `strex r0, pc, [r1]` |
//! | `bxns`/`blxns` | `0x47.4` | nothing — `t16_special` refuses `hw1[2:0] != 0` |
//!
//! The first two are the dangerous ones, and they are dangerous in the way
//! this crate exists to prevent: not a refusal, but a confident wrong answer.
//! `SG` is the mandatory first instruction of every secure-gateway veneer, so
//! *every* TrustZone-M image contains one; read as `ldrd` it carries a
//! resolved pc-relative target, and [`crate::analysis::literal_value`] will
//! duly read a pool word that is not there. `BXNS` is the standard non-secure
//! return, so it ends every secure entry function; decoded as `None` it stops
//! [`super::Decoder`] dead, and `analysis::reachable` reports a function with
//! a truncated body and no exit.
//!
//! # Why `Target::V8M` is opt-in rather than folded into the union
//!
//! The rest of this crate decodes the *union* of the profiles, because for
//! most of the map the profiles disagree only about which patterns are
//! UNDEFINED, and a union decoder is then strictly more useful to someone
//! reverse-engineering an unknown image. That reasoning fails here, because
//! these patterns collide: `0xE97F 0xE97F` cannot be both `SG` and `LDRD`, and
//! nothing in the halfwords says which. Only the target does.
//!
//! So the union keeps the Armv7 answer, unchanged, and this module is reached
//! only when the caller says [`Target::V8M`](super::Target::V8M). That is a
//! deliberate choice of *compatibility* over *coverage*: a caller who does not
//! know their target gets exactly what they got before, and a caller who does
//! know gets the right answer.
//!
//! # What is not here
//!
//! `CLRM`, `VSCCLRM`, `VLLDM` and `VLSTM` are Armv8.1-M, not Armv8-M — LLVM
//! rejects `clrm` for `armv8-m.main` with "instruction requires:
//! armv8.1m.main". They belong with the rest of the 8.1-M work (MVE, the
//! low-overhead loops), which needs a second predication state machine
//! alongside `ITSTATE` and is a project rather than a table.

use super::insn::{Insn, Operand, Operands, Reg, Width};

/// Whether this halfword pair is one of the Security Extension's, and so must
/// not be offered to the Armv7 groups.
///
/// Answering as a predicate rather than as a third return variant of [`decode`]
/// keeps the dispatcher's contract identical to [`super::thumbee`]'s: the
/// module that implements the table owns the fact of what the table covers.
///
/// Both 16-bit forms are the `hw1[2:0] == 0b100` corner of the `BX`/`BLX`
/// space, which Armv7 requires to be `0b000`. Armv7 therefore refuses exactly
/// the patterns Armv8-M allocates, so the two never disagree about a halfword
/// either of them would decode — the reassignment costs nothing here.
pub(crate) fn owns(hw1: u16, hw2: u16) -> bool {
    // `BXNS`/`BLXNS`: `0100 0111 x Rm 100`.
    if hw1 & 0xFF07 == 0x4704 {
        return true;
    }
    // `SG`: a single fixed 32-bit pattern, not a family.
    if hw1 == 0xE97F && hw2 == 0xE97F {
        return true;
    }
    // `TT`/`TTT`/`TTA`/`TTAT`: `1110 1000 0100 Rn`, `1111 Rt A Z 000000`.
    hw1 & 0xFFF0 == 0xE840 && hw2 & 0xF03F == 0xF000
}

/// Decode a Security Extension instruction.
///
/// Only ever called for halfwords [`owns`] claimed, so a `None` here means
/// "mine, and UNDEFINED" rather than "ask the ordinary groups" — the same
/// three-way contract [`super::thumbee`] documents. Falling through instead
/// would hand a reserved `TT` encoding back as the `STREX` Armv8-M does not
/// have at that pattern.
pub(crate) fn decode(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 & 0xFF07 == 0x4704 {
        let rm = Reg(((hw1 >> 3) & 0xF) as u8);
        // `BLXNS` requires a non-banked register: `Rm` of 13 or 15 is
        // UNPREDICTABLE, and 14 is too, because the call would overwrite the
        // return address it is about to use.
        let blx = hw1 & 0x0080 != 0;
        if blx && (rm.num() >= 13) {
            return None;
        }
        // `BXNS pc` is UNPREDICTABLE: the whole point is a state change on
        // return, and `pc` names no return address.
        if !blx && rm.num() == 15 {
            return None;
        }
        return Some(narrow(
            if blx { "blxns" } else { "bxns" },
            addr,
            &[Operand::Reg(rm)],
        ));
    }

    if hw1 == 0xE97F && hw2 == 0xE97F {
        // No operands, and no register fields to misread: `SG` is one
        // pattern. Its *address* is its meaning — it marks the entry point of
        // a secure gateway in the NSC region — which is why `relocate` must
        // refuse to move it rather than relocate it correctly.
        return Some(wide("sg", addr, &[]));
    }

    let rn = Reg((hw1 & 0xF) as u8);
    let rt = Reg(((hw2 >> 8) & 0xF) as u8);
    // `Rn` of 15 is UNPREDICTABLE (`pc` is not an address to test), and so is
    // `Rt` of 13 or 15.
    if rn.num() == 15 || rt.num() == 13 || rt.num() == 15 {
        return None;
    }
    let a = hw2 & 0x0080 != 0;
    let z = hw2 & 0x0040 != 0;
    // `A` selects the alternate-domain test and `Z` the unprivileged one; the
    // four combinations are four mnemonics rather than suffixes, which is how
    // the manual spells them and what an assembler will read back.
    let mnemonic = match (a, z) {
        (false, false) => "tt",
        (false, true) => "ttt",
        (true, false) => "tta",
        (true, true) => "ttat",
    };
    Some(wide(mnemonic, addr, &[Operand::Reg(rt), Operand::Reg(rn)]))
}

/// Re-encode an instruction this module decoded.
///
/// Returns `None` for anything outside the group. There is no overlap to
/// guard against in the other direction: no Armv7 module claims these
/// mnemonics, so an `Insn` reaching here either is one of these five or is
/// not this module's business.
pub(crate) fn encode(insn: &Insn) -> Option<(u16, u16)> {
    if insn.sets_flags {
        return None;
    }
    let (a, b) = (insn.operands.get(0), insn.operands.get(1));
    match (insn.mnemonic, a, b) {
        ("bxns", Some(Operand::Reg(m)), None) | ("blxns", Some(Operand::Reg(m)), None) => {
            if insn.width != Width::Narrow {
                return None;
            }
            let blx = insn.mnemonic == "blxns";
            if blx && m.num() >= 13 {
                return None;
            }
            if !blx && m.num() == 15 {
                return None;
            }
            let base = if blx { 0x4784 } else { 0x4704 };
            Some((base | (u16::from(m.num()) << 3), 0))
        }
        ("sg", None, None) => {
            if insn.width != Width::Wide {
                return None;
            }
            Some((0xE97F, 0xE97F))
        }
        ("tt", Some(Operand::Reg(t)), Some(Operand::Reg(n)))
        | ("ttt", Some(Operand::Reg(t)), Some(Operand::Reg(n)))
        | ("tta", Some(Operand::Reg(t)), Some(Operand::Reg(n)))
        | ("ttat", Some(Operand::Reg(t)), Some(Operand::Reg(n))) => {
            if insn.width != Width::Wide || insn.operands.get(2).is_some() {
                return None;
            }
            if n.num() == 15 || t.num() == 13 || t.num() == 15 {
                return None;
            }
            let (a, z) = match insn.mnemonic {
                "tt" => (0, 0),
                "ttt" => (0, 0x0040),
                "tta" => (0x0080, 0),
                _ => (0x0080, 0x0040),
            };
            Some((
                0xE840 | u16::from(n.num()),
                0xF000 | (u16::from(t.num()) << 8) | a | z,
            ))
        }
        _ => None,
    }
}

fn narrow(mnemonic: &'static str, addr: u32, ops: &[Operand]) -> Insn {
    Insn {
        mnemonic,
        encoding: "T1",
        addr,
        width: Width::Narrow,
        cond: None,
        sets_flags: false,
        explicit_width: false,
        operands: ops.iter().copied().collect(),
    }
}

fn wide(mnemonic: &'static str, addr: u32, ops: &[Operand]) -> Insn {
    Insn {
        mnemonic,
        encoding: "T1",
        addr,
        width: Width::Wide,
        cond: None,
        sets_flags: false,
        explicit_width: false,
        operands: ops.iter().copied().collect::<Operands>(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::{decode_halfwords, encode, Target};

    /// Every encoding in this module, with the bytes LLVM assembles for it.
    ///
    /// Taken from `llvm-mc -triple=thumbv8m.main-none-eabi -mcpu=cortex-m33`
    /// rather than read off the manual twice, so this table is an independent
    /// implementation's answer and not a restatement of `decode`'s.
    const VECTORS: &[(u16, u16, &str)] = &[
        (0x4704, 0x0000, "bxns r0"),
        (0x473C, 0x0000, "bxns r7"),
        (0x4774, 0x0000, "bxns lr"),
        (0x4784, 0x0000, "blxns r0"),
        (0x47BC, 0x0000, "blxns r7"),
        (0xE97F, 0xE97F, "sg"),
        (0xE841, 0xF000, "tt r0, r1"),
        (0xE849, 0xF340, "ttt r3, r9"),
        (0xE841, 0xF080, "tta r0, r1"),
        (0xE841, 0xF0C0, "ttat r0, r1"),
    ];

    #[test]
    fn every_security_extension_encoding_decodes_and_re_encodes() {
        for &(hw1, hw2, text) in VECTORS {
            // Compared as `Option`s rather than unwrapped: an `unwrap` or a
            // `panic!` arm is a region a passing test never reaches, and this
            // crate gates on 100%.
            let decoded = decode_halfwords(hw1, hw2, 0x1000, Target::V8M);
            assert_eq!(
                decoded.map(|i| i.to_string()).as_deref(),
                Some(text),
                "{hw1:#06x} {hw2:#06x}"
            );
            let round_tripped = decoded.and_then(|i| {
                let wide = i.width == Width::Wide;
                encode(&i).map(|got| (got, (hw1, if wide { hw2 } else { 0 })))
            });
            assert_eq!(
                round_tripped.map(|(got, want)| got == want),
                Some(true),
                "{text} did not re-encode to the bytes it came from"
            );
        }
    }

    /// The whole reason `Target` exists: these patterns mean something else in
    /// Armv7, and the union keeps the Armv7 reading.
    ///
    /// `SG` and `TT` are the dangerous pair — not refusals but confident wrong
    /// answers, and `SG` opens every secure-gateway veneer in every
    /// TrustZone-M image. Pinning the Armv7 text here is what makes a future
    /// change to that behaviour visible rather than silent.
    #[test]
    fn the_union_still_reads_these_patterns_the_way_armv7_does() {
        for &(hw1, hw2, armv7) in &[
            // Note the resolved target: read as `LDRD` this carries a
            // pc-relative literal address that does not exist in the image.
            (0xE97F, 0xE97F, Some("ldrd lr, r9, [pc, #-508]!, 0xe08")),
            (0xE841, 0xF000, Some("strex r0, pc, [r1]")),
            (0x4774, 0x0000, None),
            (0x4784, 0x0000, None),
        ] {
            let got = decode_halfwords(hw1, hw2, 0x1000, Target::Union);
            assert_eq!(
                got.map(|i| i.to_string()).as_deref(),
                armv7,
                "{hw1:#06x} {hw2:#06x} under Target::Union"
            );
        }
    }

    /// `owns` must claim exactly what `decode` can answer for, and nothing
    /// else — a halfword it claims but cannot decode becomes `None` for the
    /// whole decoder rather than falling through to the Armv7 groups.
    #[test]
    fn owns_claims_the_group_and_declines_its_neighbours() {
        for &(hw1, hw2, _) in VECTORS {
            assert!(owns(hw1, hw2), "{hw1:#06x} {hw2:#06x} not claimed");
        }
        for &(hw1, hw2) in &[
            (0x4700u16, 0x0000u16), // plain `bx r0` — bits[2:0] clear
            (0x4780, 0x0000),       // plain `blx r0`
            (0x4705, 0x0000),       // bits[2:0] = 0b101, not the CMSE corner
            (0xE97F, 0xE97E),       // `SG` is one pattern, not a family
            (0xE97E, 0xE97F),
            (0xE841, 0xF001), // `TT` with a should-be-zero bit set
            (0xE850, 0xF000), // not the `TT` hw1 row
        ] {
            assert!(!owns(hw1, hw2), "{hw1:#06x} {hw2:#06x} wrongly claimed");
        }
    }

    /// The UNPREDICTABLE operand choices this group refuses.
    ///
    /// Each is claimed by `owns` and answered `None` by `decode`, which is the
    /// "mine, and UNDEFINED" case — falling through to Armv7 instead would
    /// hand a reserved Armv8-M pattern back as the `STREX` or `LDRD` that
    /// pattern means on a profile this image is not.
    #[test]
    fn decode_refuses_the_unpredictable_register_choices() {
        for &(hw1, hw2, why) in &[
            (0x47EC, 0x0000u16, "blxns sp is UNPREDICTABLE"),
            (
                0x47F4,
                0x0000,
                "blxns lr would clobber its own return address",
            ),
            (0x47FC, 0x0000, "blxns pc is UNPREDICTABLE"),
            (0x477C, 0x0000, "bxns pc names no return address"),
            (0xE84F, 0xF000, "tt with Rn = pc"),
            (0xE841, 0xFD00, "tt with Rt = sp"),
            (0xE841, 0xFF00, "tt with Rt = pc"),
        ] {
            assert!(
                owns(hw1, hw2),
                "{why}: not claimed, so not this test's case"
            );
            assert_eq!(
                decode_halfwords(hw1, hw2, 0x1000, Target::V8M),
                None,
                "{why}"
            );
        }
    }

    /// The central verifier still has the last word over this group.
    ///
    /// `cmse::encode` is deliberately permissive about everything the
    /// halfwords do not carry, so it will happily produce bytes for an `Insn`
    /// asking for `tt.w`. Nothing in the group has a wide/narrow choice — `TT`
    /// is only ever the 32-bit encoding — so a request for an explicit width
    /// suffix is a request this group cannot honour, and `faithful` is what
    /// turns that into a refusal rather than bytes that print differently
    /// from what was asked for.
    #[test]
    fn a_candidate_this_group_builds_can_still_be_rejected_by_faithful() {
        let mut tt = decode_halfwords(0xE841, 0xF000, 0x1000, Target::V8M).unwrap();
        tt.explicit_width = true;
        // The group itself is content: the bytes are right for the operands.
        assert!(super::encode(&tt).is_some(), "the group builds a candidate");
        // The verifier is not: re-decoding gives `explicit_width: false`.
        assert_eq!(
            crate::isa::encode(&tt),
            None,
            "an explicit width suffix this group cannot print must be refused"
        );
    }

    /// `Target::Union` is the default, which is what keeps every pre-`Target`
    /// caller on exactly the behaviour they had.
    #[test]
    fn the_default_target_is_the_union() {
        assert_eq!(Target::default(), Target::Union);
    }

    /// `encode` refuses what `decode` refuses, and anything outside the group.
    #[test]
    fn encode_refuses_what_decode_refuses() {
        let tt = decode_halfwords(0xE841, 0xF000, 0x1000, Target::V8M).unwrap();
        let bxns = decode_halfwords(0x4704, 0, 0x1000, Target::V8M).unwrap();
        let sg = decode_halfwords(0xE97F, 0xE97F, 0x1000, Target::V8M).unwrap();

        // Flag-setting: nothing in this group has an `S` bit.
        let mut f = tt;
        f.sets_flags = true;
        assert_eq!(super::encode(&f), None, "no encoding here sets flags");

        // Widths are fixed per mnemonic; a mismatched one is not this group's.
        let mut w = bxns;
        w.width = Width::Wide;
        assert_eq!(super::encode(&w), None, "bxns is narrow");
        let mut n = sg;
        n.width = Width::Narrow;
        assert_eq!(super::encode(&n), None, "sg is wide");
        let mut tn = tt;
        tn.width = Width::Narrow;
        assert_eq!(super::encode(&tn), None, "tt is wide");

        // The same UNPREDICTABLE register choices, asked the other way round.
        let mut bad = tt;
        bad.operands = [Operand::Reg(Reg(0)), Operand::Reg(Reg(15))]
            .iter()
            .copied()
            .collect();
        assert_eq!(super::encode(&bad), None, "tt with Rn = pc");
        let mut bad_t = tt;
        bad_t.operands = [Operand::Reg(Reg(13)), Operand::Reg(Reg(1))]
            .iter()
            .copied()
            .collect();
        assert_eq!(super::encode(&bad_t), None, "tt with Rt = sp");

        let mut blxns_sp = bxns;
        blxns_sp.mnemonic = "blxns";
        blxns_sp.operands = [Operand::Reg(Reg(13))].iter().copied().collect();
        assert_eq!(super::encode(&blxns_sp), None, "blxns sp");
        let mut bxns_pc = bxns;
        bxns_pc.operands = [Operand::Reg(Reg(15))].iter().copied().collect();
        assert_eq!(super::encode(&bxns_pc), None, "bxns pc");

        // A third operand is not a `TT`.
        let mut three = tt;
        three.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Reg(Reg(2)),
        ]
        .iter()
        .copied()
        .collect();
        assert_eq!(super::encode(&three), None, "tt takes two registers");

        // Not this group at all.
        let mut other = tt;
        other.mnemonic = "strex";
        assert_eq!(super::encode(&other), None, "strex is not this group");
        let mut sg_ops = sg;
        sg_ops.operands = [Operand::Reg(Reg(0))].iter().copied().collect();
        assert_eq!(super::encode(&sg_ops), None, "sg takes no operands");
    }
}
