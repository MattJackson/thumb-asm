//! Which condition flags an instruction reads and writes, and which are live
//! at a point in an image.
//!
//! # Why this is not a bool
//!
//! [`Insn::sets_flags`] answers "does this carry the `S` suffix", which is a
//! question about the *encoding*. The question a rewrite needs answered is
//! "which of N, Z, C and V does this destroy", and the two are not the same:
//!
//! ```text
//! if setflags then
//!     APSR.N = result<31>;
//!     APSR.Z = IsZeroBit(result);
//!     APSR.C = carry;
//!     // APSR.V unchanged        <- ARM DDI 0403E.e A7.7.9, AND (register)
//! ```
//!
//! Every logical and shift operation is like that: `ANDS`, `ORRS`, `EORS`,
//! `BICS`, `MVNS`, `LSLS`, `LSRS`, `ASRS`, `RORS`, `RRXS` and `TST`/`TEQ`
//! write N, Z and C and leave V exactly as they found it. The arithmetic
//! operations and the comparisons — `ADDS`, `SUBS`, `RSBS`, `ADCS`, `SBCS`,
//! `CMP`, `CMN` — write all four.
//!
//! That distinction is the whole reason this module exists. The obvious
//! liveness rule, "a flag dies at the next instruction with `sets_flags`", is
//! wrong for V, and wrong in the direction that matters: it would report V as
//! dead after an `ANDS`, licensing a rewrite that clobbers a V somebody is
//! still going to branch on.
//!
//! # Reads are not just conditions either
//!
//! A conditional instruction reads the flags its condition names, which is the
//! obvious case. The non-obvious one is that `ADC`, `SBC`, `RSC` and `RRX`
//! read the carry flag *unconditionally* — they are defined in terms of
//! `APSR.C` (`Shift_C(R[m], shift_t, shift_n, APSR.C)`, A7.7.11) — and carry
//! `cond: None` when they are not in an IT block. A rule based on
//! `insn.cond.is_some()` misses every one of them.
//!
//! # What this is for
//!
//! Rewriting an instruction into a sequence that does not have the same flag
//! behaviour. The motivating case is `CBZ`/`CBNZ`, which this crate refuses to
//! relocate out of range ([`RelocateError::ForwardOnlyBranch`]) because the
//! natural rewrite —
//!
//! ```text
//! cbz rn, target   ->   cmp rn, #0
//!                       beq.w target
//! ```
//!
//! — writes all four flags where `CBZ` writes none. That rewrite is correct
//! only where all four are dead, and *no* `S`-suffixed logical operation makes
//! them so, because V survives it.
//!
//! [`Insn::sets_flags`]: crate::isa::insn::Insn::sets_flags
//! [`RelocateError::ForwardOnlyBranch`]: crate::relocate::RelocateError::ForwardOnlyBranch

use crate::isa::insn::{Insn, Operand, ShiftKind};
use crate::isa::{self, Target};

/// A set of condition flags.
///
/// Used for three different things — what an instruction reads, what it
/// writes, and what is live at a point — which are all the same shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Flags {
    /// Negative.
    pub n: bool,
    /// Zero.
    pub z: bool,
    /// Carry.
    pub c: bool,
    /// Overflow.
    pub v: bool,
}

impl Flags {
    /// No flags.
    pub const NONE: Flags = Flags {
        n: false,
        z: false,
        c: false,
        v: false,
    };
    /// All four.
    pub const ALL: Flags = Flags {
        n: true,
        z: true,
        c: true,
        v: true,
    };
    /// N, Z and C — what a logical or shift operation writes, leaving V.
    pub const NZC: Flags = Flags {
        n: true,
        z: true,
        c: true,
        v: false,
    };
    /// N and Z only.
    pub const NZ: Flags = Flags {
        n: true,
        z: true,
        c: false,
        v: false,
    };
    /// Carry alone — what `ADC`, `SBC` and `RRX` read.
    pub const C: Flags = Flags {
        n: false,
        z: false,
        c: true,
        v: false,
    };

    /// Whether no flag is set.
    pub fn is_empty(self) -> bool {
        self == Flags::NONE
    }

    /// Whether every flag in `other` is also in `self`.
    pub fn contains(self, other: Flags) -> bool {
        (!other.n || self.n) && (!other.z || self.z) && (!other.c || self.c) && (!other.v || self.v)
    }

    /// The union.
    pub fn union(self, other: Flags) -> Flags {
        Flags {
            n: self.n || other.n,
            z: self.z || other.z,
            c: self.c || other.c,
            v: self.v || other.v,
        }
    }

    /// `self` with everything in `other` removed.
    pub fn without(self, other: Flags) -> Flags {
        Flags {
            n: self.n && !other.n,
            z: self.z && !other.z,
            c: self.c && !other.c,
            v: self.v && !other.v,
        }
    }
}

/// The flags this instruction writes.
///
/// The `S` suffix says *that* flags are written; the mnemonic says *which*.
/// An instruction without `sets_flags` writes nothing here, with two
/// exceptions that carry no `S` because they have no non-flag-setting form:
/// `CMP`, `CMN`, `TST` and `TEQ` exist only to write flags.
///
/// `MSR` writing `APSR` is treated as writing all four, which is true for the
/// `nzcvq` and `nzcvqg` spellings and conservative for the rest.
pub fn writes(insn: &Insn) -> Flags {
    match insn.mnemonic {
        // Comparisons: no `S` suffix, always write. `CMP`/`CMN` are
        // subtraction and addition, so all four; `TST`/`TEQ` are `AND` and
        // `EOR`, so V survives.
        "cmp" | "cmn" => Flags::ALL,
        "tst" | "teq" => Flags::NZC,
        // Writing the flags register directly — but only the spellings that
        // name the condition bits. Table B5-2 (DDI 0403E.e, B5.2) gives three
        // `<bits>` encodings for `MSR APSR`: `_nzcvq` writes N, Z, C, V and Q;
        // `_g` writes **only** GE[3:0] and touches no condition flag; `_nzcvqg`
        // writes both.
        //
        // Claiming `_g` writes all four would be the expensive direction of
        // wrong: `live_from` resolves a flag the moment something writes it, so
        // an over-claim here reports a live flag as dead and licenses
        // clobbering it. Anything that is not a recognised APSR spelling —
        // `PRIMASK`, `CONTROL`, a register this crate does not know — writes no
        // condition flag at all.
        // The `<bits>` suffix decides, not the register stem. The decoder
        // spells these `APSR_g`, `APSR_nzcvq`, `APSR_nzcvqg` and the same
        // three suffixes on the composite PSRs — `IAPSR_nzcvq`,
        // `EAPSR_nzcvqg`, `XPSR_g` and so on — all of which carry the APSR
        // bits. Matching on the stem would miss every composite form; matching
        // on the suffix is what the mask field actually encodes.
        //
        // Anything with no such suffix — `PRIMASK`, `BASEPRI`, `CONTROL`, a
        // bare `APSR` — writes no condition flag.
        "msr" => match insn.operands.get(0) {
            Some(Operand::SpecialReg(name)) => {
                let n = name.to_ascii_lowercase();
                if n.ends_with("_nzcvq") || n.ends_with("_nzcvqg") {
                    Flags::ALL
                } else {
                    Flags::NONE
                }
            }
            _ => Flags::NONE,
        },
        _ if !insn.sets_flags => Flags::NONE,
        // Logical and shift: N, Z, C, and V untouched (A7.7.9 and siblings).
        "and" | "orr" | "eor" | "bic" | "orn" | "mvn" | "lsl" | "lsr" | "asr" | "ror" | "rrx" => {
            Flags::NZC
        }
        // `MOV`/`MOVS` is a logical operation for flag purposes: it sets N and
        // Z from the result and C from the shifter, and leaves V.
        "mov" => Flags::NZC,
        // Multiplies set only N and Z (A7.7.74: "APSR.C unchanged,
        // APSR.V unchanged" in the Armv7-M form).
        "mul" | "mla" | "mls" => Flags::NZ,
        // Everything else with an `S` is arithmetic: all four.
        _ => Flags::ALL,
    }
}

/// The flags this instruction reads.
///
/// Two independent sources, and a rule that looks at only the first is the
/// classic way to get this wrong:
///
/// - Its condition, if it has one — from its own encoding or from an
///   enclosing `IT` block. Which flags a condition consults depends on the
///   condition: `EQ` reads only Z, `MI` only N, `HI` reads C and Z.
/// - Carry as a *datum*. `ADC`, `SBC`, `RSC` and `RRX` add or shift the carry
///   bit in, with no condition involved.
pub fn reads(insn: &Insn) -> Flags {
    let from_cond = insn.cond.map_or(Flags::NONE, cond_reads);
    let from_operation = match insn.mnemonic {
        "adc" | "sbc" | "rsc" | "rrx" => Flags::C,
        // `MRS` reading `APSR` observes all of them.
        "mrs" => Flags::ALL,
        _ => Flags::NONE,
    };
    // ...and `RRX` as a *shift applied to an operand* of some other
    // instruction. `and.w r0, r1, r2, rrx` rotates `r2` right through carry,
    // so it reads C while its mnemonic is `and`. Looking only at the mnemonic
    // — which this function did until the audit caught it — misses every one
    // of these, and the module doc names this as the case it exists to get
    // right.
    let from_shift = insn
        .operands
        .as_slice()
        .find_map(|o| match o {
            Operand::RegShifted(_, sh) if sh.kind == ShiftKind::Rrx => Some(Flags::C),
            _ => None,
        })
        .unwrap_or(Flags::NONE);
    from_cond.union(from_operation).union(from_shift)
}

/// Which flags a condition code consults (ARM DDI 0403E.e A7.3, Table A7-3).
fn cond_reads(cond: crate::Cond) -> Flags {
    use crate::Cond::*;
    const N: Flags = Flags {
        n: true,
        z: false,
        c: false,
        v: false,
    };
    const Z: Flags = Flags {
        n: false,
        z: true,
        c: false,
        v: false,
    };
    const V: Flags = Flags {
        n: false,
        z: false,
        c: false,
        v: true,
    };
    const CZ: Flags = Flags {
        n: false,
        z: true,
        c: true,
        v: false,
    };
    const NV: Flags = Flags {
        n: true,
        z: false,
        c: false,
        v: true,
    };
    const NZV: Flags = Flags {
        n: true,
        z: true,
        c: false,
        v: true,
    };
    match cond {
        // `EQ`/`NE` test `Z`.
        Eq | Ne => Z,
        // `HS`/`LO` — also spelled `CS`/`CC` — test `C`.
        Hs | Lo => Flags::C,
        // `MI`/`PL` test `N`.
        Mi | Pl => N,
        // `VS`/`VC` test `V`.
        Vs | Vc => V,
        // `HI`/`LS` test `C == 1 && Z == 0`.
        Hi | Ls => CZ,
        // `GE`/`LT` test `N == V`.
        Ge | Lt => NV,
        // `GT`/`LE` test `Z == 0 && N == V`.
        Gt | Le => NZV,
        // `AL` is unconditional and reads nothing.
        Al => Flags::NONE,
    }
}

/// Which flags are still live immediately after the instruction at `at`.
///
/// "Live" means some instruction reachable from here may read the flag before
/// anything overwrites it. The answer is an **over-approximation**: a flag
/// reported live may in truth be dead, but a flag reported dead is dead on
/// every path this function could see. That asymmetry is deliberate — the
/// caller is asking in order to decide whether clobbering is safe, and the
/// expensive mistake is the other direction.
///
/// The walk stops and reports everything still unresolved as live when it
/// reaches something it cannot follow:
///
/// - any branch, call or return — the flags may be read at a destination this
///   function does not follow, and following them is a control-flow analysis
///   rather than a peephole;
/// - an undecodable halfword, since what follows is unknown;
/// - the end of the image;
/// - `limit` instructions, so a long straight line cannot make this
///   unbounded.
///
/// # Example
///
/// ```
/// use thumb_asm::flags::{live_after, Flags};
/// use thumb_asm::isa::Target;
///
/// // nop / adds r3, r4, r5 / adds r0, r1, r2 / bx lr
/// // The first `adds` resolves all four flags, so nothing survives to the
/// // `bx` that ends the walk.
/// let image = [0x00, 0xbf, 0xe3, 0x19, 0x88, 0x18, 0x70, 0x47];
/// assert_eq!(live_after(&image, 0, Target::Union, 8), Flags::NONE);
///
/// // nop / ands r0, r1 / bx lr
/// // `ANDS` writes N, Z and C but leaves V, and the `bx` ends the walk with
/// // V still unresolved — so V is reported live and must not be clobbered.
/// let logical = [0x00, 0xbf, 0x08, 0x40, 0x70, 0x47];
/// let live = live_after(&logical, 0, Target::Union, 8);
/// assert!(live.v && !live.n && !live.z && !live.c);
/// ```
pub fn live_after(image: &[u8], at: usize, target: Target, limit: usize) -> Flags {
    let here = match isa::decode_at_with(image, at, at as u32, target) {
        Some(i) => i,
        None => return Flags::ALL,
    };

    // The fall-through path.
    let mut live = live_from(image, at + here.len(), target, limit);

    // ...and the taken path, when the instruction at `at` is itself a branch.
    //
    // This is not an optional refinement. The motivating caller is rewriting a
    // `CBZ`, which *is* a conditional branch, so half of what happens after it
    // is at its target. Walking only the fall-through would miss a flag read
    // on the taken path and report it dead — the one direction that turns a
    // refusal into a silent miscompile.
    if here.is_branch() {
        // `branch_target()` is not a control-flow edge on its own. A
        // pc-relative *literal* access carries a `Target` too — the resolved
        // address of the pool word — and `Insn::branch_target`'s own contract
        // says so: "A consumer building a control-flow graph must treat a
        // `Target` as a branch destination only when the instruction has no
        // `Operand::Mem`."
        //
        // `ldr pc, [pc, #8]` is exactly that case and is an ordinary dispatch
        // idiom: `is_branch()` is true, and the `Target` is the address of the
        // word *holding* the destination. Following it would walk into the
        // literal pool and decode data as code — and could then report a flag
        // dead on the strength of bytes that are not instructions at all,
        // which inverts this function's one-directional guarantee.
        let loads_its_destination = here
            .operands
            .as_slice()
            .any(|o| matches!(o, Operand::Mem(_)));
        if loads_its_destination {
            return Flags::ALL;
        }
        match here.branch_target() {
            // A target inside the image is followed, one level. Anything it
            // reaches that branches again resolves to `Flags::ALL` there, so
            // this does not need to recurse.
            Some(t) if (t as usize) < image.len() => {
                live = live.union(live_from(image, t as usize, target, limit));
            }
            // A target outside the image, or one that cannot be resolved from
            // the encoding, is code this cannot see.
            _ => return Flags::ALL,
        }
    }
    live
}

/// Walk forward from `pos`, reporting which flags are read before they are
/// rewritten.
///
/// Uses [`Decoder`](isa::Decoder), not [`isa::decode_at_with`], and the
/// difference is load-bearing rather than stylistic. The stateless decode
/// knows nothing about an enclosing `IT` block, and an `IT` block breaks this
/// walk in *both* directions at once:
///
/// - A governed instruction comes back with `cond: None`, so [`reads`] sees no
///   condition and reports no flag read. `itt eq` / `addeq` reads Z, and a
///   stateless walk cannot tell.
/// - `setflags = !InITBlock()` (A7.7.4 and every narrow data-processing page)
///   means a governed `adds` does **not** write the flags — but the stateless
///   decode reports `sets_flags: true`, so [`writes`] resolves flags that are
///   in fact untouched.
///
/// Both mistakes point the same way: fewer flags reported live. That is the
/// direction that licenses a rewrite to clobber something still in use, and it
/// inverts the guarantee [`live_after`] makes.
///
/// `Decoder` tracks `ITSTATE` forward from `pos`, which fixes every block that
/// *begins* within the walk. A block already in progress at `pos` cannot be
/// detected from `pos` alone — a Thumb stream does not decode backwards — so
/// `pos` is required to be an instruction boundary outside any `IT` block.
/// The in-crate caller satisfies this: `detour` refuses a site inside an `IT`
/// block before it ever asks about flags.
fn live_from(image: &[u8], pos: usize, target: Target, limit: usize) -> Flags {
    let mut unresolved = Flags::ALL;
    let mut live = Flags::NONE;

    let mut decoder = isa::Decoder::at(image, pos, pos as u32).target(target);
    let mut seen = 0usize;
    while seen < limit {
        if unresolved.is_empty() {
            break;
        }
        let insn = match decoder.next() {
            Some(i) => i,
            // Unknown bytes or the end of the image: anything still unresolved
            // has to be assumed read.
            None => return live.union(unresolved),
        };
        seen += 1;

        // A flag read before it is written is live. Only flags still
        // unresolved count — one already overwritten holds a different value.
        live = live.union(reads(&insn).intersect(unresolved));
        // A flag written here is resolved: whatever it held is gone.
        unresolved = unresolved.without(writes(&insn));

        // A branch ends the straight line. `is_branch` covers calls and
        // returns too, which is what we want: past any of them the flags
        // belong to code this is not following.
        if insn.is_branch() || insn.writes_pc() {
            return live.union(unresolved);
        }
    }
    live.union(unresolved)
}

impl Flags {
    /// The intersection.
    pub fn intersect(self, other: Flags) -> Flags {
        Flags {
            n: self.n && other.n,
            z: self.z && other.z,
            c: self.c && other.c,
            v: self.v && other.v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::decode_halfwords;

    fn at(hw1: u16, hw2: u16) -> Insn {
        decode_halfwords(hw1, hw2, 0x1000, Target::Union).expect("decodes")
    }

    /// The rule this whole module exists for: an `S`-suffixed logical or shift
    /// operation writes N, Z and C and leaves V alone.
    ///
    /// Treating `sets_flags` as "all four die here" would report V dead after
    /// every one of these, which would licence a `CBZ` rewrite that destroys a
    /// V the following code still branches on. The manual says so in as many
    /// words — `// APSR.V unchanged`, DDI 0403E.e A7.7.9 and siblings.
    #[test]
    fn logical_and_shift_operations_leave_the_overflow_flag_alone() {
        for (hw1, hw2, what) in [
            (0x4008u16, 0x0000u16, "ands r0, r1"),
            (0x4048, 0x0000, "eors r0, r1"),
            (0x4308, 0x0000, "orrs r0, r1"),
            (0x4388, 0x0000, "bics r0, r1"),
            (0x43C8, 0x0000, "mvns r0, r1"),
            (0x0088, 0x0000, "lsls r0, r1, #2"),
            (0x0888, 0x0000, "lsrs r0, r1, #2"),
            (0x1088, 0x0000, "asrs r0, r1, #2"),
        ] {
            let w = writes(&at(hw1, hw2));
            assert_eq!(w, Flags::NZC, "{what} should write N, Z, C and not V");
            assert!(!w.v, "{what} must not be reported as writing V");
        }
    }

    /// Arithmetic and the comparisons write all four, which is what makes the
    /// distinction meaningful rather than academic.
    #[test]
    fn arithmetic_and_comparisons_write_every_flag() {
        for (hw1, hw2, what) in [
            (0x1888u16, 0x0000u16, "adds r0, r1, r2"),
            (0x1A88, 0x0000, "subs r0, r1, r2"),
            (0x4148, 0x0000, "adcs r0, r1"),
            (0x4188, 0x0000, "sbcs r0, r1"),
            (0x4288, 0x0000, "cmp r0, r1"),
            (0x42C8, 0x0000, "cmn r0, r1"),
        ] {
            assert_eq!(writes(&at(hw1, hw2)), Flags::ALL, "{what}");
        }
    }

    /// `TST` and `TEQ` write flags with no `S` suffix — and, being `AND` and
    /// `EOR`, still leave V.
    #[test]
    fn the_test_instructions_write_flags_without_an_s_suffix() {
        let tst = at(0x4208, 0x0000); // tst r0, r1
        assert!(!tst.sets_flags, "TST carries no S suffix");
        assert_eq!(writes(&tst), Flags::NZC, "TST is an AND: V survives");
    }

    /// `MOVS` and the multiplies are the two families where "arithmetic
    /// writes all four" would be wrong.
    ///
    /// `MOVS` takes its C from the shifter and leaves V, exactly as the
    /// logical operations do. The multiplies write only N and Z — the Armv7-M
    /// form says "APSR.C unchanged, APSR.V unchanged" outright.
    #[test]
    fn moves_and_multiplies_write_less_than_the_arithmetic_operations() {
        assert_eq!(writes(&at(0x2001, 0x0000)), Flags::NZC, "movs r0, #1");
        assert_eq!(writes(&at(0x4348, 0x0000)), Flags::NZ, "muls r0, r1, r0");
        assert_eq!(
            writes(&at(0xFB01, 0x3002)),
            Flags::NONE,
            "mla has no S here"
        );
    }

    /// Moving the flags register in or out is a read or a write of all four.
    #[test]
    fn the_status_register_transfers_touch_every_flag() {
        let mrs = at(0xF3EF, 0x8000); // mrs r0, apsr
        assert_eq!(mrs.mnemonic, "mrs");
        assert_eq!(reads(&mrs), Flags::ALL, "MRS observes the whole APSR");

        let msr = at(0xF380, 0x8800); // msr apsr_nzcvq, r0
        assert_eq!(msr.mnemonic, "msr");
        assert_eq!(writes(&msr), Flags::ALL, "MSR replaces the whole APSR");
    }

    /// An `IT` block must not make its governed instructions' flag reads
    /// invisible.
    ///
    /// This is the defect a stateless walk has, and it is unsafe in two ways
    /// at once. `addeq` reads Z, but decoded without `ITSTATE` it carries
    /// `cond: None` and looks like it reads nothing. And
    /// `setflags = !InITBlock()` means a governed `add` does *not* write the
    /// flags, yet the stateless decode reports `sets_flags: true` and so
    /// resolves flags that were never touched. Both errors report fewer flags
    /// live — the direction that licenses clobbering one still in use.
    #[test]
    fn a_conditional_instruction_inside_an_it_block_still_reads_its_flags() {
        // nop / itt eq / addeq r1,#1 / addeq r2,#1 / bx lr
        //
        // Nothing writes the flags before the block, so Z reaches the `addeq`
        // still holding whatever the caller set — which is exactly when a
        // rewrite must not clobber it.
        let image = [0x00, 0xbf, 0x04, 0xbf, 0x01, 0x31, 0x01, 0x32, 0x70, 0x47];
        let live = live_after(&image, 0, Target::Union, 12);
        assert!(
            live.z,
            "the IT block's condition is EQ, which reads Z — a stateless walk \
             would miss it and report Z dead"
        );
    }

    /// `MSR APSR_g` writes the GE bits and no condition flag at all.
    ///
    /// Table B5-2 (DDI 0403E.e B5.2) gives three `<bits>` spellings: `_nzcvq`
    /// writes N, Z, C, V and Q; `_g` writes **only** GE[3:0]; `_nzcvqg`
    /// writes both. Claiming `_g` writes the condition flags is the expensive
    /// direction of wrong — `live_from` resolves a flag the moment something
    /// writes it, so an over-claim reports a live flag as dead.
    #[test]
    fn the_ge_only_spelling_of_msr_writes_no_condition_flag() {
        let ge = at(0xF380, 0x8400); // msr apsr_g, r0
        assert_eq!(ge.mnemonic, "msr");
        assert_eq!(
            writes(&ge),
            Flags::NONE,
            "APSR_g writes GE[3:0] and nothing else"
        );

        let nzcvq = at(0xF380, 0x8800); // msr apsr_nzcvq, r0
        assert_eq!(writes(&nzcvq), Flags::ALL, "APSR_nzcvq writes all four");

        // The composite PSRs carry the same suffixes and the same bits, so
        // classifying on the register stem rather than the suffix would miss
        // them.
        let iapsr = at(0xF380, 0x8801); // msr iapsr_nzcvq, r0
        assert_eq!(iapsr.mnemonic, "msr");
        assert_eq!(
            writes(&iapsr),
            Flags::ALL,
            "IAPSR_nzcvq carries the APSR bits too"
        );

        // A system register with no `<bits>` suffix writes no condition flag.
        let primask = at(0xF380, 0x8810); // msr primask, r0
        assert_eq!(writes(&primask), Flags::NONE, "PRIMASK is not the APSR");

        // ...and a hand-built `Insn` whose first operand is not a special
        // register at all is not an APSR write either.
        let mut odd = nzcvq;
        odd.operands = [Operand::Reg(crate::isa::insn::Reg(0))]
            .iter()
            .copied()
            .collect();
        assert_eq!(writes(&odd), Flags::NONE);
    }

    /// `RRX` applied as a *shift to an operand* reads carry, even though the
    /// mnemonic is something else entirely.
    ///
    /// `and.w r0, r1, r2, rrx` rotates `r2` right through carry. A rule that
    /// inspects only `insn.mnemonic` sees `"and"` and reports no read — which
    /// is what this function did until an audit caught it, despite the module
    /// doc naming this as the case it exists to get right.
    #[test]
    fn rrx_as_a_shift_operand_reads_carry() {
        let shifted = at(0xEA01, 0x0032); // and.w r0, r1, r2, rrx
        assert_eq!(shifted.mnemonic, "and");
        assert_eq!(shifted.cond, None, "no condition, so no read from that");
        assert!(
            reads(&shifted).c,
            "the RRX shift consumes carry regardless of the mnemonic"
        );
    }

    /// An instruction that *loads* its destination is not a control-flow edge
    /// this can follow.
    ///
    /// `ldr.w pc, [pc]` makes `is_branch()` true, but its `Target` is the
    /// address of the word *holding* the destination, not the destination —
    /// `Insn::branch_target`'s own contract says a `Target` is a branch
    /// destination only when the instruction has no `Operand::Mem`. Following
    /// it would walk into the literal pool and decode data as code, and could
    /// then report a flag dead on the strength of bytes that are not
    /// instructions.
    #[test]
    fn an_instruction_that_loads_its_destination_is_not_followed() {
        // ldr.w pc, [pc] at 0, then bytes that happen to decode as an `adds`
        // — which, if followed as code, would resolve every flag and wrongly
        // report them dead.
        let image = [0xdf, 0xf8, 0x00, 0xf0, 0xd1, 0x18, 0xd1, 0x18];
        let insn = crate::isa::decode_at_with(&image, 0, 0, Target::Union).expect("decodes");
        assert!(insn.is_branch(), "writing pc makes this a branch");
        assert_eq!(
            live_after(&image, 0, Target::Union, 8),
            Flags::ALL,
            "the destination is loaded from memory, so no path is visible"
        );
    }

    /// A branch whose target is outside the image is code this cannot see, so
    /// every flag is reported live rather than assumed dead.
    #[test]
    fn a_branch_leaving_the_image_resolves_nothing() {
        // cbz r0, +0x7e — far past the end of this four-byte image.
        let image = [0xf8, 0xb3, 0x70, 0x47];
        assert_eq!(
            live_after(&image, 0, Target::Union, 8),
            Flags::ALL,
            "the taken path leaves the image, so it cannot be cleared"
        );
    }

    /// `ADC`, `SBC` and `RRX` read carry with no condition attached, so a rule
    /// built on `insn.cond.is_some()` would miss them entirely.
    #[test]
    fn the_carry_consuming_instructions_read_it_unconditionally() {
        let adc = at(0x4148, 0x0000); // adcs r0, r1
        assert_eq!(adc.cond, None, "not in an IT block, so no condition");
        assert!(
            reads(&adc).c,
            "ADC adds the carry bit in; it reads C regardless of any condition"
        );
        let sbc = at(0x4188, 0x0000);
        assert!(reads(&sbc).c, "SBC likewise");
    }

    /// Each condition reads exactly the flags its test names.
    #[test]
    fn a_condition_reads_only_the_flags_its_test_names() {
        use crate::Cond::*;
        for (cond, want, why) in [
            (
                Eq,
                Flags {
                    n: false,
                    z: true,
                    c: false,
                    v: false,
                },
                "EQ tests Z",
            ),
            (Hs, Flags::C, "HS tests C"),
            (
                Mi,
                Flags {
                    n: true,
                    z: false,
                    c: false,
                    v: false,
                },
                "MI tests N",
            ),
            (
                Vs,
                Flags {
                    n: false,
                    z: false,
                    c: false,
                    v: true,
                },
                "VS tests V",
            ),
            (
                Hi,
                Flags {
                    n: false,
                    z: true,
                    c: true,
                    v: false,
                },
                "HI tests C and Z",
            ),
            (
                Ge,
                Flags {
                    n: true,
                    z: false,
                    c: false,
                    v: true,
                },
                "GE tests N == V",
            ),
            (
                Gt,
                Flags {
                    n: true,
                    z: true,
                    c: false,
                    v: true,
                },
                "GT tests Z and N == V",
            ),
            (Al, Flags::NONE, "AL tests nothing"),
        ] {
            assert_eq!(cond_reads(cond), want, "{why}");
        }
    }

    /// The headline consequence, stated as a test: an `ANDS` does **not**
    /// make a `CBZ` rewrite safe, because V survives it while `CMP` writes V.
    ///
    /// The contrast is the point. Both sequences end in a `bx lr`, which stops
    /// the walk and reports everything still unresolved as live. After the
    /// arithmetic `ADDS` nothing is unresolved, so nothing is live and a
    /// rewrite may clobber freely. After the logical `ANDS`, V is still
    /// unresolved — and a model that read `sets_flags` as "all four die here"
    /// would report it dead and licence destroying it.
    #[test]
    fn an_ands_does_not_make_the_overflow_flag_dead() {
        // nop / adds r0, r1, r2 / bx lr
        let arithmetic = [0x00, 0xbf, 0x88, 0x18, 0x70, 0x47];
        assert_eq!(
            live_after(&arithmetic, 0, Target::Union, 8),
            Flags::NONE,
            "ADDS resolves all four, so nothing survives to the return"
        );

        // nop / ands r0, r1 / bx lr
        let logical = [0x00, 0xbf, 0x08, 0x40, 0x70, 0x47];
        let live = live_after(&logical, 0, Target::Union, 8);
        assert!(live.v, "ANDS does not write V, so V is still live");
        assert!(
            !live.n && !live.z && !live.c,
            "ANDS does write N, Z and C, so those are dead"
        );
    }

    /// A flag written before it is read is dead; one read first is live.
    #[test]
    fn a_flag_is_dead_once_something_overwrites_it_unread() {
        // adds r0, r1, r2  /  adds r3, r4, r5  /  bx lr
        let image = [0x88, 0x18, 0xe3, 0x19, 0x70, 0x47];
        assert_eq!(
            live_after(&image, 0, Target::Union, 8),
            Flags::NONE,
            "the second ADDS overwrites all four before anything reads them"
        );

        // adds r0, r1, r2  /  beq +N  — Z is read before being rewritten.
        let read_first = [0x88, 0x18, 0x00, 0xd0];
        let live = live_after(&read_first, 0, Target::Union, 8);
        assert!(live.z, "the BEQ reads Z");
    }

    /// Anything the walk cannot follow reports every unresolved flag as live.
    ///
    /// The over-approximation is deliberate and one-directional: a flag called
    /// live may really be dead, but a flag called dead is dead on every path
    /// this can see. The caller is asking in order to decide whether
    /// clobbering is safe, so the expensive mistake is the other way.
    #[test]
    fn what_cannot_be_followed_is_assumed_to_read_everything() {
        // adds r0, r1, r2  /  b +N  — the branch destination is not followed.
        let branch = [0x88, 0x18, 0x00, 0xe0];
        assert_eq!(
            live_after(&branch, 0, Target::Union, 8),
            Flags::ALL,
            "past a branch the flags belong to code this does not follow"
        );

        // adds r0, r1, r2, then bytes that do not decode.
        let junk = [0x88, 0x18, 0xff, 0xff];
        assert_eq!(live_after(&junk, 0, Target::Union, 8), Flags::ALL);

        // Running out of image is the same situation.
        let short = [0x88, 0x18];
        assert_eq!(live_after(&short, 0, Target::Union, 8), Flags::ALL);

        // And so is running out of budget.
        let long = [0x00, 0xbf, 0x00, 0xbf, 0x00, 0xbf, 0x00, 0xbf];
        assert_eq!(live_after(&long, 0, Target::Union, 1), Flags::ALL);
    }

    /// Asking about bytes that are not an instruction answers "everything is
    /// live" rather than guessing a length.
    #[test]
    fn an_undecodable_site_resolves_nothing() {
        assert_eq!(live_after(&[0xff, 0xff], 0, Target::Union, 8), Flags::ALL);
    }

    /// The set algebra, which everything above rests on.
    #[test]
    fn the_flag_set_operations_behave() {
        assert!(Flags::NONE.is_empty());
        assert!(!Flags::C.is_empty());
        assert!(Flags::ALL.contains(Flags::NZC));
        assert!(!Flags::NZC.contains(Flags::ALL));
        assert!(Flags::NZC.contains(Flags::NZ));
        // Per-flag `other=set, self=empty` cases — one for each of N, Z, C.
        // Without these the three `!other.x || self.x` clauses in `contains`
        // each look like a no-op: `Flags::NZC.contains(Flags::ALL)` already
        // distinguishes the V clause, so it is the only one under test until
        // these lines land.
        let n_only = Flags { n: true, z: false, c: false, v: false };
        let z_only = Flags { n: false, z: true, c: false, v: false };
        let c_only = Flags { n: false, z: false, c: true, v: false };
        assert!(!Flags::NONE.contains(n_only));
        assert!(!Flags::NONE.contains(z_only));
        assert!(!Flags::NONE.contains(c_only));
        assert_eq!(Flags::NZ.union(Flags::C), Flags::NZC);
        assert_eq!(
            Flags::ALL.without(Flags::NZC),
            Flags {
                n: false,
                z: false,
                c: false,
                v: true
            }
        );
        assert_eq!(Flags::ALL.intersect(Flags::NZ), Flags::NZ);
        assert_eq!(Flags::default(), Flags::NONE);
    }
}
