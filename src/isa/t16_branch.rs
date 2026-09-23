//! A5.2.6 "Conditional branch, and Supervisor Call", plus the three
//! neighbouring single-encoding entries of Table A5-1 that share this corner of
//! the 16-bit map: `STM` T1 (`11000x`), `LDM` T1 (`11001x`) and the
//! unconditional `B` T2 (`11100x`).
//!
//! The dispatcher's final arm hands this module every 16-bit halfword from
//! `hw1[15:10] == 0b110000` upward, and Thumb's length rule
//! ([`crate::isa::insn_len`]) keeps `0xE800` and above out — so the range that
//! actually arrives here is exactly `0xC000..=0xE7FF`, and that is what
//! [`decode`] implements. Anything outside it yields `None` rather than being
//! decoded speculatively.
//!
//! # Why `1101xx` is not simply "the conditional branches"
//!
//! Table A5-8 (ARM DDI 0403E.e A5-136, and identically Table A6-8 of DDI 0406B
//! A6.2.6) splits the `1101` space three ways, and the `B` pseudocode on
//! A7-205 opens by diverting two of them:
//!
//! ```text
//! if cond == '1110' then SEE UDF;
//! if cond == '1111' then SEE SVC;
//! ```
//!
//! So `0xDE**` is the *permanently* undefined `UDF #<imm8>` — DDI 0406B adds
//! "this space will not be allocated in future", which is what makes it usable
//! as a deliberate trap — and `0xDF**` is `SVC #<imm8>`. Treating the whole of
//! `0xD000..=0xDFFF` as `B<cond>` mis-decodes 512 halfwords, and does so in the
//! worst possible way: it invents control flow where the hardware takes an
//! exception. [`crate::Cond::from_bits`] is the guard for the `SVC` half (it
//! returns `None` for `0b1111` by design); the `UDF` half is checked
//! explicitly, because `0b1110` *is* a valid condition (`AL`) everywhere except
//! here.
//!
//! # pc-relative arithmetic
//!
//! Every target in this group is `PC + imm32` where Thumb's `PC` reads as the
//! instruction's own address plus four (A7.7.12's `BranchWritePC(PC + imm32)`,
//! with `PC` defined by A7.3 as `Align(instruction address + 4, 4)` — for a
//! 16-bit instruction at an even address that is just `addr + 4`). Targets are
//! resolved here and handed out as [`Operand::Target`] so no consumer has to
//! remember that offset.

use super::{Insn, Operand, Operands, Reg, Width};
use crate::Cond;

/// The first halfword this module owns.
const RANGE_LO: u16 = 0xC000;

/// The last halfword this module owns. `0xE800` and above is the start of a
/// 32-bit encoding (`hw1[15:11] == 0b11101`) and never reaches us.
const RANGE_HI: u16 = 0xE7FF;

/// UAL spellings of the eight low base registers with the writeback `!`
/// already attached.
///
/// [`Insn`] has no writeback flag, and [`Insn`]'s `Display` joins operands with
/// `", "`, so a trailing `Operand::Text("!")` would print
/// `stmia r0, !, {r1, r2}`. `Operand::Mem` would print brackets — `[r0, #0]!`
/// in [`super::AddrMode::PreIndex`], `[r0]!` in
/// [`super::AddrMode::PostIncrement`] — which is the load/store-single and
/// Advanced SIMD syntax, not the load/store-multiple syntax. The base register of a 16-bit `LDM`/`STM` is a
/// 3-bit field, so there are only eight spellings to pre-render — which makes
/// [`Operand::Text`] both exact and cheap here, and keeps the writeback
/// visible to `Display` and recoverable by [`encode`].
const BASE_WRITEBACK: [&str; 8] = ["r0!", "r1!", "r2!", "r3!", "r4!", "r5!", "r6!", "r7!"];

/// Sign-extend the low `bits` bits of `value`.
///
/// Written as a shift up then an arithmetic shift down so that the sign bit is
/// whichever bit the *encoding* says it is, never bit 31 of some wider
/// intermediate. Getting this wrong by one bit position turns a short backward
/// branch into a target megabytes away, and the error is invisible to any test
/// that only exercises small forward displacements.
fn sign_extend(value: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    ((value << shift) as i32) >> shift
}

/// The absolute target of a pc-relative branch at `addr` with byte
/// displacement `off`.
///
/// Wrapping, not saturating or checked: the architecture's pc is a 32-bit
/// value and `BranchWritePC` truncates to 32 bits, so a backward branch from
/// near address 0 legitimately lands near `0xFFFF_FFFF`. Reporting that
/// honestly is more useful than clamping to 0, which would silently claim a
/// target the hardware would never reach.
fn target_of(addr: u32, off: i32) -> u32 {
    addr.wrapping_add(4).wrapping_add(off as u32)
}

/// The byte displacement an instruction at `addr` needs to reach `target`.
///
/// The inverse of [`target_of`], and wrapping for the same reason: the
/// difference of two `u32` addresses reinterpreted as `i32` is the true
/// displacement whenever that displacement fits in 32 bits, which it always
/// does for the ±2KB forms here.
fn disp_to(addr: u32, target: u32) -> i32 {
    target.wrapping_sub(addr.wrapping_add(4)) as i32
}

/// Build an [`Insn`] with this group's invariants already set: always 16-bit,
/// never flag-setting, never width-suffixed.
///
/// None of `B`, `B<cond>`, `UDF`, `SVC`, `LDM` or `STM` touch `APSR`, so
/// `sets_flags` is unconditionally false; and every one of them is the only
/// 16-bit encoding of its operation, so none needs a `.n` suffix to
/// disambiguate from a wide form when re-assembled.
fn insn(
    mnemonic: &'static str,
    encoding: &'static str,
    addr: u32,
    cond: Option<Cond>,
    operands: Operands,
) -> Insn {
    Insn {
        mnemonic,
        encoding,
        addr,
        width: Width::Narrow,
        cond,
        sets_flags: false,
        explicit_width: false,
        operands,
    }
}

/// Decode an instruction in this group, or `None` if `hw1` does not belong to
/// it.
///
/// `_hw2` is unused: everything here is a single halfword.
pub(crate) fn decode(hw1: u16, _hw2: u16, addr: u32) -> Option<Insn> {
    if !(RANGE_LO..=RANGE_HI).contains(&hw1) {
        return None;
    }

    match hw1 >> 11 {
        // `1100 0 Rn register_list` — STM, STMIA, STMEA T1 (A7.7.159).
        0b11000 => decode_stm(hw1, addr),
        // `1100 1 Rn register_list` — LDM, LDMIA, LDMFD T1 (A7.7.41).
        0b11001 => decode_ldm(hw1, addr),
        // `1101 cond imm8` — B T1 / UDF T1 / SVC T1 (Table A5-8).
        0b11010 | 0b11011 => decode_cond_branch(hw1, addr),
        // `1110 0 imm11` — B T2 (A7.7.12), and the only value left: the range
        // check above admits `0xC000..=0xE7FF`, whose top five bits are
        // `0b11000`, `0b11001`, `0b11010`, `0b11011` and `0b11100`, so there
        // is no sixth case for a `None` arm to catch.
        _ => decode_b_t2(hw1, addr),
    }
}

/// `STM<c> <Rn>!, <registers>` — T1, `1100 0 Rn(3) register_list(8)`.
///
/// The encoding's own pseudocode is `wback = TRUE` with no `W` bit to turn it
/// off, and the assembler syntax line for T1 is `STM<c> <Rn>!,<registers>`
/// with the `!` non-optional (A7-383): there is no non-writeback 16-bit `STM`.
/// The base is therefore always rendered from [`BASE_WRITEBACK`].
///
/// `BitCount(registers) < 1` is UNPREDICTABLE, so an empty list is rejected —
/// it has no UAL spelling that would re-assemble (`{}` is not a register list),
/// and a firmware scanner is better served by "not an instruction" than by an
/// operand it cannot act on.
fn decode_stm(hw1: u16, addr: u32) -> Option<Insn> {
    let rn = ((hw1 >> 8) & 0b111) as usize;
    let list = hw1 & 0xFF;
    if list == 0 {
        return None;
    }
    let mut ops = Operands::new();
    ops.push(Operand::Text(BASE_WRITEBACK[rn]));
    ops.push(Operand::RegList(list));
    Some(insn("stmia", "T1", addr, None, ops))
}

/// `LDM<c> <Rn>{!}, <registers>` — T1, `1100 1 Rn(3) register_list(8)`.
///
/// The subtlety is that T1 has no `W` bit either, but unlike `STM` its
/// writeback is *derived*: A7-242 gives `wback = (registers<n> == '0')`, and the
/// syntax lines spell out both cases —
///
/// ```text
/// LDM<c> <Rn>!,<registers>   <Rn> not included in <registers>
/// LDM<c> <Rn>,<registers>    <Rn> included in <registers>
/// ```
///
/// The reason is the `Operation` epilogue: writing the base back after having
/// just loaded it from memory would discard the loaded value, so the
/// architecture suppresses the writeback instead of making the encoding
/// UNPREDICTABLE. A decoder that always prints `!` claims a base-register
/// update that does not happen.
///
/// The register list is 8 bits wide (`r0`–`r7`), so `pc` — and `sp` and `lr` —
/// simply cannot appear in it. A 16-bit `ldmia` therefore never writes `pc`,
/// which is why [`Insn::writes_pc`] can never fire on an instruction from this
/// function; the `pc`-in-list return idiom needs `POP` (A5.2.5) or `LDM` T2.
fn decode_ldm(hw1: u16, addr: u32) -> Option<Insn> {
    let rn = ((hw1 >> 8) & 0b111) as usize;
    let list = hw1 & 0xFF;
    if list == 0 {
        return None;
    }
    let wback = list & (1 << rn) == 0;
    let mut ops = Operands::new();
    if wback {
        ops.push(Operand::Text(BASE_WRITEBACK[rn]));
    } else {
        ops.push(Operand::Reg(Reg(rn as u8)));
    }
    ops.push(Operand::RegList(list));
    Some(insn("ldmia", "T1", addr, None, ops))
}

/// `1101 cond(4) imm8` — the three-way split of Table A5-8.
///
/// `cond == 0b1110` is `UDF #<imm8>` (A7.7.194) and `cond == 0b1111` is
/// `SVC #<imm8>` (A7.7.178); everything else is `B<cond>` T1 (A7.7.12) with
/// `imm32 = SignExtend(imm8:'0', 32)`, giving even displacements in
/// **-256 to +254** — note the asymmetry, a signed 8-bit field scaled by two
/// reaches one halfword further backward than forward.
///
/// `B` T1 is "Not permitted in IT block" outright (`if InITBlock() then
/// UNPREDICTABLE`), because its condition already lives in its own encoding.
/// That condition goes in [`Insn::cond`], never in the mnemonic: `Insn`'s
/// `Display` appends [`Cond::suffix`] itself, so a mnemonic of `"beq"` would
/// print `beqeq`.
///
/// `UDF` and `SVC` take `ZeroExtend(imm8, 32)` — an opaque constant the
/// processor ignores, carried only so disassembly round-trips — and are
/// deliberately *not* branches: neither appears in [`Insn::is_branch`]'s
/// mnemonic set, and neither carries an [`Operand::Target`].
fn decode_cond_branch(hw1: u16, addr: u32) -> Option<Insn> {
    let cond_bits = ((hw1 >> 8) & 0xF) as u8;
    let imm8 = (hw1 & 0xFF) as u32;

    // `0b1111` is not a condition at all; `Cond::from_bits` says so, and it is
    // asked once — asking again below for the branch rows would be a second
    // `None` arm that the first one has already made unreachable.
    let cond = match Cond::from_bits(cond_bits) {
        Some(c) => c,
        None => {
            let mut ops = Operands::new();
            ops.push(Operand::Imm(imm8 as i64));
            return Some(insn("svc", "T1", addr, None, ops));
        }
    };
    // `0b1110` *is* a condition (`AL`) — but not in this encoding, where
    // Table A5-8 allocates it to the permanently-undefined space.
    if cond == Cond::Al {
        let mut ops = Operands::new();
        ops.push(Operand::Imm(imm8 as i64));
        return Some(insn("udf", "T1", addr, None, ops));
    }

    // SignExtend(imm8:'0', 32): concatenate the zero bit first, then extend
    // the resulting 9-bit field. Doing it in the other order would extend an
    // 8-bit field and then shift the sign bit up, which happens to agree here
    // but not for the encodings that concatenate more than one low bit.
    let off = sign_extend(imm8 << 1, 9);
    let mut ops = Operands::new();
    ops.push(Operand::Target(target_of(addr, off)));
    Some(insn("b", "T1", addr, Some(cond), ops))
}

/// `1110 0 imm11` — `B` T2, unconditional (A7.7.12).
///
/// `imm32 = SignExtend(imm11:'0', 32)`: even displacements in **-2048 to
/// +2046**, again asymmetric.
///
/// T2 carries no condition field, so [`Insn::cond`] is left `None` here and
/// only [`super::Decoder`] may fill it in from `ITSTATE`. Unlike T1, T2 *is*
/// permitted in an IT block — but only as the last instruction in one:
/// `if InITBlock() && !LastInITBlock() then UNPREDICTABLE`. That is what the
/// syntax line "Outside or last in IT block" means, and it is why T1 and T2 are
/// never both available to an assembler for the same source line.
fn decode_b_t2(hw1: u16, addr: u32) -> Option<Insn> {
    let imm11 = (hw1 & 0x7FF) as u32;
    let off = sign_extend(imm11 << 1, 12);
    let mut ops = Operands::new();
    ops.push(Operand::Target(target_of(addr, off)));
    Some(insn("b", "T2", addr, None, ops))
}

/// Re-encode an instruction this module decoded, back to its halfword.
///
/// Returns `None` for anything this module does not own, and — importantly —
/// for an instruction whose [`Operand::Target`] no longer fits the encoding's
/// displacement field. A caller that has relocated code needs to be told that
/// a branch has outgrown its narrow form so it can widen it; silently
/// truncating the displacement would produce a branch to the wrong place.
///
/// [`Insn::cond`] is only consulted for `B` T1, the one encoding here with a
/// condition field of its own. For the rest, a condition can only have come
/// from an enclosing `IT` block, which lives in a separate instruction and is
/// not this halfword's business.
pub(crate) fn encode(insn: &Insn) -> Option<u16> {
    match (insn.mnemonic, insn.encoding) {
        ("stmia", "T1") => encode_stm_ldm(insn, 0xC000, true),
        ("ldmia", "T1") => encode_stm_ldm(insn, 0xC800, false),
        ("b", "T1") => {
            // `AL` and the non-condition `0b1111` are both unencodable here:
            // their slots are `UDF` and `SVC`.
            let cond = insn.cond?;
            if cond == Cond::Al {
                return None;
            }
            let imm8 = fit_disp(insn, 8)?;
            Some(0xD000 | ((cond.bits() as u16) << 8) | imm8)
        }
        ("b", "T2") => Some(0xE000 | fit_disp(insn, 11)?),
        ("udf", "T1") => Some(0xDE00 | imm8_of(insn)?),
        ("svc", "T1") => Some(0xDF00 | imm8_of(insn)?),
        _ => None,
    }
}

/// The signed displacement field of a branch whose scaled range is
/// `-(1 << bits) ..= (1 << bits) - 2` bytes, or `None` if the target no longer
/// fits or is not halfword-aligned.
fn fit_disp(insn: &Insn, bits: u32) -> Option<u16> {
    let target = insn.branch_target()?;
    let off = disp_to(insn.addr, target);
    if off & 1 != 0 {
        return None;
    }
    let half = off >> 1;
    let limit = 1i32 << (bits - 1);
    if half < -limit || half >= limit {
        return None;
    }
    Some((half as u16) & ((1u16 << bits) - 1))
}

/// The `imm8` of a `UDF` or `SVC`, or `None` if it has grown past eight bits.
fn imm8_of(insn: &Insn) -> Option<u16> {
    match insn.operands.get(0)? {
        Operand::Imm(v) if (0..=0xFF).contains(&v) => Some(v as u16),
        _ => None,
    }
}

/// Re-encode `STM`/`LDM` T1 from `base | Rn << 8 | register_list`.
///
/// Also re-checks the writeback invariant the decoder derived, so that an
/// `Insn` built by hand cannot encode to a halfword that would decode back
/// differently: `STM` T1 always writes back, and `LDM` T1 writes back exactly
/// when `Rn` is absent from the list.
fn encode_stm_ldm(insn: &Insn, base: u16, always_wback: bool) -> Option<u16> {
    let (rn, wback) = match insn.operands.get(0)? {
        Operand::Text(s) => (BASE_WRITEBACK.iter().position(|w| *w == s)? as u16, true),
        Operand::Reg(r) if r.is_low() => (r.num() as u16, false),
        _ => return None,
    };
    let list = match insn.operands.get(1)? {
        Operand::RegList(bits) if bits != 0 && bits <= 0xFF => bits,
        _ => return None,
    };
    let expected_wback = always_wback || list & (1 << rn) == 0;
    if wback != expected_wback {
        return None;
    }
    Some(base | (rn << 8) | list)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a halfword at `addr` through this module directly.
    fn dec(hw1: u16, addr: u32) -> Option<Insn> {
        decode(hw1, 0, addr)
    }

    /// Every halfword in `0xC000..=0xE7FF` that decodes must re-encode to the
    /// identical halfword, and the ones that do not decode must be exactly the
    /// 16 `STM`/`LDM` encodings with an empty register list.
    #[test]
    fn exhaustive_round_trip() {
        // Several addresses, including 0 (backward branches wrap below zero)
        // and the very top of the address space (forward branches wrap past
        // it), because the displacement recovery is modular arithmetic and a
        // non-wrapping implementation would pass only in the middle.
        for addr in [0u32, 2, 0x8000, 0xFFFF_FFFC] {
            let mut decoded = 0usize;
            let mut rejected = Vec::new();
            for hw in RANGE_LO..=RANGE_HI {
                match dec(hw, addr) {
                    Some(i) => {
                        decoded += 1;
                        assert_eq!(encode(&i), Some(hw), "{hw:#06x} at {addr:#x} -> {i}");
                        assert_eq!(i.len(), 2, "{hw:#06x} must be narrow");
                        assert!(!i.sets_flags, "{hw:#06x} must not set flags");
                    }
                    None => rejected.push(hw),
                }
            }

            // 10240 halfwords in range; 16 are the empty-register-list forms
            // (`register_list == 0`, UNPREDICTABLE per A7-383/A7-242), one per
            // base register for each of STM and LDM.
            assert_eq!(rejected.len(), 16);
            assert_eq!(decoded, 10240 - 16);
            assert_eq!(decoded, 10224);
            for hw in &rejected {
                assert_eq!(hw & 0xFF, 0, "{hw:#06x} rejected for the wrong reason");
                assert!((0xC000..=0xCFFF).contains(hw), "{hw:#06x} out of STM/LDM");
            }
            let expected: Vec<u16> = (0..8)
                .map(|n| 0xC000 | (n << 8))
                .chain((0..8).map(|n| 0xC800 | (n << 8)))
                .collect();
            let mut sorted = rejected.clone();
            sorted.sort_unstable();
            let mut expected_sorted = expected;
            expected_sorted.sort_unstable();
            assert_eq!(sorted, expected_sorted);
        }
    }

    /// The whole range is accounted for: each halfword lands in exactly the
    /// mnemonic Table A5-1/A5-8 says it should.
    #[test]
    fn range_partition() {
        for hw in RANGE_LO..=RANGE_HI {
            let expect = match hw {
                0xC000..=0xC7FF => "stmia",
                0xC800..=0xCFFF => "ldmia",
                0xD000..=0xDDFF => "b",
                0xDE00..=0xDEFF => "udf",
                0xDF00..=0xDFFF => "svc",
                _ => "b",
            };
            if let Some(i) = dec(hw, 0x1000) {
                assert_eq!(i.mnemonic, expect, "{hw:#06x}");
            }
        }
        // And nothing outside the range is claimed.
        assert!(dec(0xBFFF, 0).is_none());
        assert!(dec(0xE800, 0).is_none());
        assert!(dec(0xFFFF, 0).is_none());
    }

    /// Hand-computed extremes for `B<cond>` T1.
    ///
    /// `imm8 = 0x7F` is the largest positive field: `SignExtend(0xFE, 9)` =
    /// +254, so from `0x1000` the target is `0x1000 + 4 + 254 = 0x1102`.
    /// `imm8 = 0x80` is the most negative: `SignExtend(0x100, 9)` = -256, so
    /// the target is `0x1000 + 4 - 256 = 0x0F04`. The range is -256..+254, not
    /// ±254 — the field is signed, so backward reaches one halfword further.
    #[test]
    fn bcond_t1_extremes() {
        let fwd = dec(0xD07F, 0x1000).unwrap(); // beq
        assert_eq!(fwd.mnemonic, "b");
        assert_eq!(fwd.cond, Some(Cond::Eq));
        assert_eq!(fwd.branch_target(), Some(0x1102));
        assert_eq!(fwd.to_string(), "beq 0x1102");
        assert_eq!(encode(&fwd), Some(0xD07F));

        let back = dec(0xD080, 0x1000).unwrap();
        assert_eq!(back.branch_target(), Some(0x0F04));
        assert_eq!(0x1000u32 + 4 - 256, 0x0F04);
        assert_eq!(encode(&back), Some(0xD080));

        // One step less in each direction, to pin the scaling factor of two.
        assert_eq!(dec(0xD07E, 0x1000).unwrap().branch_target(), Some(0x1100));
        assert_eq!(dec(0xD081, 0x1000).unwrap().branch_target(), Some(0x0F06));
        // And the zero displacement: a branch to the following instruction+2.
        assert_eq!(dec(0xD000, 0x1000).unwrap().branch_target(), Some(0x1004));
    }

    /// Hand-computed extremes for `B` T2.
    ///
    /// `imm11 = 0x3FF` gives `SignExtend(0x7FE, 12)` = +2046, so from `0x1000`
    /// the target is `0x1000 + 4 + 2046 = 0x1802`. `imm11 = 0x400` gives
    /// `SignExtend(0x800, 12)` = -2048, so the target is
    /// `0x1000 + 4 - 2048 = 0x0804`.
    #[test]
    fn b_t2_extremes() {
        let fwd = dec(0xE3FF, 0x1000).unwrap();
        assert_eq!(fwd.mnemonic, "b");
        assert_eq!(fwd.encoding, "T2");
        assert_eq!(fwd.cond, None);
        assert_eq!(fwd.branch_target(), Some(0x1802));
        assert_eq!(fwd.to_string(), "b 0x1802");
        assert_eq!(encode(&fwd), Some(0xE3FF));

        let back = dec(0xE400, 0x1000).unwrap();
        assert_eq!(back.branch_target(), Some(0x0804));
        assert_eq!(0x1000u32 + 4 - 2048, 0x0804);
        assert_eq!(encode(&back), Some(0xE400));

        assert_eq!(dec(0xE3FE, 0x1000).unwrap().branch_target(), Some(0x1800));
        assert_eq!(dec(0xE401, 0x1000).unwrap().branch_target(), Some(0x0806));
        assert_eq!(dec(0xE000, 0x1000).unwrap().branch_target(), Some(0x1004));
    }

    /// A backward branch from near address 0 wraps modulo 2^32 rather than
    /// saturating, matching `BranchWritePC`'s 32-bit pc. The wrapped target
    /// still re-encodes, because the displacement is recovered modularly too.
    #[test]
    fn wraps_below_zero() {
        // beq at 0x0000 with imm8 = 0x80: 0 + 4 - 256 = -252 = 0xFFFFFF04.
        let b = dec(0xD080, 0x0000).unwrap();
        assert_eq!(b.branch_target(), Some(0xFFFF_FF04));
        assert_eq!(encode(&b), Some(0xD080));

        // b at 0x0002 with imm11 = 0x400: 2 + 4 - 2048 = -2042 = 0xFFFFF806.
        let b2 = dec(0xE400, 0x0002).unwrap();
        assert_eq!(b2.branch_target(), Some(0xFFFF_F806));
        assert_eq!(encode(&b2), Some(0xE400));

        // And forward off the top of the address space.
        let up = dec(0xE3FF, 0xFFFF_FFFC).unwrap();
        assert_eq!(up.branch_target(), Some(0x7FE));
        assert_eq!(encode(&up), Some(0xE3FF));
    }

    /// `encode` refuses a displacement that no longer fits rather than
    /// truncating it.
    #[test]
    fn encode_rejects_out_of_range() {
        let mut b = dec(0xD000, 0x1000).unwrap();
        // +254 is the last encodable forward target; +256 is not.
        b.operands = core::iter::once(Operand::Target(0x1000 + 4 + 254)).collect();
        assert_eq!(encode(&b), Some(0xD07F));
        b.operands = core::iter::once(Operand::Target(0x1000 + 4 + 256)).collect();
        assert_eq!(encode(&b), None);
        // -256 is encodable, -258 is not.
        b.operands = core::iter::once(Operand::Target(0x1000 + 4 - 256)).collect();
        assert_eq!(encode(&b), Some(0xD080));
        b.operands = core::iter::once(Operand::Target(0x1000 + 4 - 258)).collect();
        assert_eq!(encode(&b), None);
        // An odd target is not a Thumb instruction address.
        b.operands = core::iter::once(Operand::Target(0x1000 + 4 + 3)).collect();
        assert_eq!(encode(&b), None);

        let mut t2 = dec(0xE000, 0x1000).unwrap();
        t2.operands = core::iter::once(Operand::Target(0x1000 + 4 + 2046)).collect();
        assert_eq!(encode(&t2), Some(0xE3FF));
        t2.operands = core::iter::once(Operand::Target(0x1000 + 4 + 2048)).collect();
        assert_eq!(encode(&t2), None);
        t2.operands = core::iter::once(Operand::Target(0x1000 + 4 - 2048)).collect();
        assert_eq!(encode(&t2), Some(0xE400));
        t2.operands = core::iter::once(Operand::Target(0x1000 + 4 - 2050)).collect();
        assert_eq!(encode(&t2), None);
    }

    /// `0xDE**` is `UDF` and `0xDF**` is `SVC`; neither is a branch, and
    /// neither has a target. This is the single most common error in
    /// hand-rolled Thumb tooling.
    #[test]
    fn de_is_udf_df_is_svc() {
        let udf = dec(0xDE00, 0x1000).unwrap();
        assert_eq!(udf.mnemonic, "udf");
        assert_eq!(udf.encoding, "T1");
        assert_eq!(udf.cond, None);
        assert!(!udf.is_branch());
        assert!(!udf.writes_pc());
        assert_eq!(udf.branch_target(), None);
        assert_eq!(udf.to_string(), "udf #0");
        assert_eq!(encode(&udf), Some(0xDE00));

        let svc = dec(0xDF00, 0x1000).unwrap();
        assert_eq!(svc.mnemonic, "svc");
        assert_eq!(svc.cond, None);
        assert!(!svc.is_branch());
        assert!(!svc.writes_pc());
        assert_eq!(svc.branch_target(), None);
        assert_eq!(svc.to_string(), "svc #0");
        assert_eq!(encode(&svc), Some(0xDF00));

        // The immediate is carried, not discarded.
        assert_eq!(dec(0xDEAB, 0).unwrap().to_string(), "udf #0xab");
        assert_eq!(dec(0xDF2A, 0).unwrap().to_string(), "svc #0x2a");
        assert_eq!(dec(0xDFFF, 0).unwrap().to_string(), "svc #0xff");

        // No halfword in either 256-byte block is a branch.
        for hw in 0xDE00u16..=0xDFFF {
            let i = dec(hw, 0x1000).unwrap();
            assert!(!i.is_branch(), "{hw:#06x} must not be a branch");
            assert!(i.cond.is_none(), "{hw:#06x} must carry no condition");
        }
    }

    /// All fourteen encodable conditions, in Table A7-1 order, and none of
    /// them printed into the mnemonic.
    #[test]
    fn fourteen_conditions() {
        let expect = [
            (0x0u16, Cond::Eq, "beq"),
            (0x1, Cond::Ne, "bne"),
            (0x2, Cond::Hs, "bhs"),
            (0x3, Cond::Lo, "blo"),
            (0x4, Cond::Mi, "bmi"),
            (0x5, Cond::Pl, "bpl"),
            (0x6, Cond::Vs, "bvs"),
            (0x7, Cond::Vc, "bvc"),
            (0x8, Cond::Hi, "bhi"),
            (0x9, Cond::Ls, "bls"),
            (0xA, Cond::Ge, "bge"),
            (0xB, Cond::Lt, "blt"),
            (0xC, Cond::Gt, "bgt"),
            (0xD, Cond::Le, "ble"),
        ];
        for (bits, cond, text) in expect {
            let hw = 0xD000 | (bits << 8);
            let i = dec(hw, 0x1000).unwrap();
            assert_eq!(
                i.mnemonic, "b",
                "{hw:#06x} keeps the condition out of the mnemonic"
            );
            assert_eq!(i.cond, Some(cond), "{hw:#06x}");
            assert!(i.is_branch());
            assert_eq!(i.to_string(), format!("{text} 0x1004"));
            assert_eq!(encode(&i), Some(hw));
        }
        // `beq`, not `beqeq` and not a bare `b`.
        let beq = dec(0xD000, 0x1000).unwrap();
        assert!(beq.to_string().starts_with("beq "));
        assert!(!beq.to_string().starts_with("beqeq"));
        assert_ne!(beq.to_string().split(' ').next(), Some("b"));

        // `AL` has no 16-bit conditional-branch encoding: its slot is `UDF`.
        let mut al = beq;
        al.cond = Some(Cond::Al);
        assert_eq!(encode(&al), None);
    }

    /// `branch_target()` is the method consumers use; it must agree with the
    /// hand arithmetic for both forms at several addresses.
    #[test]
    fn branch_target_agrees() {
        for &(hw, addr, want) in &[
            (0xD005u16, 0x0000u32, 0x000Eu32), // beq +10 from 0: 0+4+10
            (0xD1FE, 0x2000, 0x2000 + 4 - 4),  // bne -4 from 0x2000
            (0xE010, 0x0100, 0x0100 + 4 + 32), // b +32 from 0x100
            (0xE7FE, 0x4444, 0x4444 + 4 - 4),  // b -4: the classic self-loop
        ] {
            let i = dec(hw, addr).unwrap();
            assert_eq!(i.branch_target(), Some(want), "{hw:#06x} at {addr:#x}");
            assert!(i.is_branch());
            assert_eq!(encode(&i), Some(hw));
        }
        // `0xE7FE` is `b .` — the infinite loop every fault handler ends in.
        assert_eq!(dec(0xE7FE, 0x4444).unwrap().branch_target(), Some(0x4444));
    }

    /// `STM`/`LDM` T1 printing, including the mandatory writeback `!` and the
    /// one case where `LDM` suppresses it.
    #[test]
    fn stm_ldm_printing() {
        // stmia r0!, {r1, r2} = 0xC000 | 0<<8 | 0b0000_0110
        let stm = dec(0xC006, 0x1000).unwrap();
        assert_eq!(stm.to_string(), "stmia r0!, {r1, r2}");
        assert_eq!(stm.mnemonic, "stmia");
        assert_eq!(stm.encoding, "T1");
        assert!(!stm.is_branch());
        assert!(!stm.writes_pc());
        assert_eq!(encode(&stm), Some(0xC006));

        // ldmia r0!, {r1-r3} = 0xC800 | 0<<8 | 0b0000_1110
        let ldm = dec(0xC80E, 0x1000).unwrap();
        assert_eq!(ldm.to_string(), "ldmia r0!, {r1-r3}");
        assert!(!ldm.is_branch());
        assert!(!ldm.writes_pc());
        assert_eq!(encode(&ldm), Some(0xC80E));

        // Runs collapse and singletons do not: {r0, r4-r7}
        assert_eq!(
            dec(0xC4F1, 0).unwrap().to_string(),
            "stmia r4!, {r0, r4-r7}"
        );

        // STM always writes back, even with the base in the list.
        assert_eq!(dec(0xC301, 0).unwrap().to_string(), "stmia r3!, {r0}");
        assert_eq!(dec(0xC308, 0).unwrap().to_string(), "stmia r3!, {r3}");

        // LDM suppresses writeback exactly when Rn is in the list
        // (A7-242: `wback = (registers<n> == '0')`).
        assert_eq!(dec(0xCB08, 0).unwrap().to_string(), "ldmia r3, {r3}");
        assert_eq!(dec(0xCB09, 0).unwrap().to_string(), "ldmia r3, {r0, r3}");
        assert_eq!(dec(0xCB01, 0).unwrap().to_string(), "ldmia r3!, {r0}");
        for rn in 0u16..8 {
            let with = dec(0xC800 | (rn << 8) | (1 << rn), 0).unwrap();
            assert_eq!(with.operands.get(0), Some(Operand::Reg(Reg(rn as u8))));
            let without = dec(0xC800 | (rn << 8) | (1 << ((rn + 1) % 8)), 0).unwrap();
            assert_eq!(
                without.operands.get(0),
                Some(Operand::Text(BASE_WRITEBACK[rn as usize])),
                "Rn absent from the list means writeback, spelled `!`"
            );
        }

        // The 16-bit register list is 8 bits wide, so pc/lr/sp can never be in
        // it and a narrow `ldmia` can never write pc.
        for hw in 0xC000u16..=0xCFFF {
            if let Some(i) = dec(hw, 0) {
                // The list is looked for across all the operands rather than
                // at a fixed index, so "there is no register list at all" is
                // an answer this assertion can make rather than a panic arm
                // that never runs.
                let list = i.operands.as_slice().find_map(|o| match o {
                    Operand::RegList(bits) => Some(bits),
                    _ => None,
                });
                assert_eq!(
                    list.map(|bits| bits & 0xFF00),
                    Some(0),
                    "{hw:#06x} has no register list, or names a high register"
                );
                assert!(!i.writes_pc(), "{hw:#06x}");
            }
        }
    }

    /// An empty register list is UNPREDICTABLE and has no UAL spelling, so it
    /// is not decoded — and a hand-built `Insn` carrying one will not encode.
    #[test]
    fn empty_reglist_rejected() {
        for rn in 0u16..8 {
            assert!(dec(0xC000 | (rn << 8), 0).is_none());
            assert!(dec(0xC800 | (rn << 8), 0).is_none());
        }
        let mut stm = dec(0xC006, 0).unwrap();
        stm.operands = [Operand::Text("r0!"), Operand::RegList(0)]
            .into_iter()
            .collect();
        assert_eq!(encode(&stm), None);
        // A high register in the list does not fit the 8-bit field either.
        stm.operands = [Operand::Text("r0!"), Operand::RegList(1 << 15)]
            .into_iter()
            .collect();
        assert_eq!(encode(&stm), None);
        // Nor does a base register outside r0-r7 — any of them, for either
        // mnemonic. `Rn` is three bits here and `hw1[11]` above it is the
        // `L` bit, so `stmia r8, {r1, r2}` shifted straight into the field
        // would come out as `0xC806`: not a malformed store-multiple but a
        // valid `ldmia r0!, {r1, r2}`, a load where a store was asked for
        // and a base register nobody named.
        //
        // Two guards say so, and the second says it alone. `is_low` refuses
        // the register first; then the writeback invariant refuses it again,
        // and unconditionally. `Rn` reaches that invariant as `r.num()`, so
        // a high base is 8..=15, `1 << rn` is at least `0x100`, and the list
        // has already been capped at `0xFF` — `list & (1 << rn)` is zero, so
        // `expected_wback` is `true`, while a bare `Operand::Reg` means
        // `wback == false`. Deleting `is_low` therefore changes no answer
        // this function can give: it is an equivalent mutation, and these
        // assertions hold with the guard and without it. They are here as
        // the behaviour written down over the whole of r8-r15 and both
        // mnemonics, not as a test of the guard.
        for r in 8u8..16 {
            for (base, mnemonic) in [(0xC006u16, "stmia"), (0xC806, "ldmia")] {
                let mut high = dec(base, 0).unwrap();
                assert_eq!(high.mnemonic, mnemonic);
                high.operands = [Operand::Reg(Reg(r)), Operand::RegList(0b110)]
                    .into_iter()
                    .collect();
                assert_eq!(encode(&high), None, "{mnemonic} through r{r}");
            }
        }
    }

    /// Every operand `encode` reads, offered something it cannot read.
    ///
    /// [`crate::isa::encode`] hands each narrow instruction to every group in
    /// turn, so these are not hypothetical shapes: they are what this group
    /// sees when another group's instruction — or one built by hand from the
    /// public `Insn` fields — comes past. Each must be declined rather than
    /// mangled into a halfword that decodes as something else.
    #[test]
    fn encode_reads_no_operand_it_has_not_checked() {
        let base = dec(0xD000, 0x1000).unwrap(); // beq
        let no_ops = Operands::new();

        // `B` T1 carries its own condition; without one there is no `cond`
        // field to fill, and `AL` and `0b1111` name `UDF` and `SVC` instead.
        let mut b = base;
        b.cond = None;
        assert_eq!(encode(&b), None, "B T1 has a condition field");
        b.cond = Some(Cond::Al);
        assert_eq!(encode(&b), None, "0b1110 is UDF's row");

        // A branch with no target has no displacement to encode.
        for encoding in ["T1", "T2"] {
            let mut bare = base;
            bare.encoding = encoding;
            bare.operands = no_ops;
            assert_eq!(encode(&bare), None, "B {encoding} with no target");
            let mut wrong = base;
            wrong.encoding = encoding;
            wrong.operands = [Operand::Imm(4)].into_iter().collect();
            assert_eq!(encode(&wrong), None, "B {encoding} with an immediate");
        }

        // `UDF`/`SVC` carry an eight-bit immediate, and nothing else.
        for (mnemonic, hw) in [("udf", 0xDE00u16), ("svc", 0xDF00)] {
            let base = dec(hw, 0x1000).unwrap();
            assert_eq!(base.mnemonic, mnemonic);
            let mut bare = base;
            bare.operands = no_ops;
            assert_eq!(encode(&bare), None, "{mnemonic} with no immediate");
            for imm in [-1i64, 256, 0x1_0000] {
                let mut big = base;
                big.operands = [Operand::Imm(imm)].into_iter().collect();
                assert_eq!(encode(&big), None, "{mnemonic} #{imm} is not 8 bits");
            }
            let mut wrong = base;
            wrong.operands = [Operand::Target(0x1004)].into_iter().collect();
            assert_eq!(encode(&wrong), None, "{mnemonic} takes an immediate");
            // …and the in-range immediate still encodes, so each rejection
            // above is about the operand and not about the row.
            let mut ok = base;
            ok.operands = [Operand::Imm(0xAB)].into_iter().collect();
            assert_eq!(encode(&ok), Some(hw | 0xAB));
        }

        // `STM`/`LDM` T1: a base, a register list, and a writeback that has to
        // agree with what the architecture derives from the list.
        let stm = dec(0xC006, 0).unwrap(); // stmia r0!, {r1, r2}
        let ldm = dec(0xC806, 0).unwrap(); // ldmia r0!, {r1, r2}
        let mut bare = stm;
        bare.operands = no_ops;
        assert_eq!(encode(&bare), None, "no base register");
        let mut base_only = stm;
        base_only.operands = [Operand::Text("r0!")].into_iter().collect();
        assert_eq!(encode(&base_only), None, "no register list");
        let mut unknown_base = stm;
        unknown_base.operands = [Operand::Text("r9!"), Operand::RegList(0b110)]
            .into_iter()
            .collect();
        assert_eq!(encode(&unknown_base), None, "r9 is not a three-bit field");
        let mut imm_base = stm;
        imm_base.operands = [Operand::Imm(0), Operand::RegList(0b110)]
            .into_iter()
            .collect();
        assert_eq!(encode(&imm_base), None, "the base is a register");
        let mut imm_list = stm;
        imm_list.operands = [Operand::Text("r0!"), Operand::Imm(6)]
            .into_iter()
            .collect();
        assert_eq!(encode(&imm_list), None, "the list is a register list");

        // The writeback invariant, both ways round. `STM` T1 has no `W` bit —
        // A7-383 spells the syntax `STM<c> <Rn>!,<registers>` with the `!`
        // non-optional — so a non-writeback `stmia` names an encoding that
        // does not exist. `LDM` T1 derives it: `wback = (registers<n> == '0')`
        // (A7-242), so a writeback `ldmia r0!, {r0}` contradicts its own list.
        let mut stm_no_wback = stm;
        stm_no_wback.operands = [Operand::Reg(Reg(0)), Operand::RegList(0b110)]
            .into_iter()
            .collect();
        assert_eq!(encode(&stm_no_wback), None, "STM T1 always writes back");
        let mut ldm_wback_in_list = ldm;
        ldm_wback_in_list.operands = [Operand::Text("r0!"), Operand::RegList(0b1)]
            .into_iter()
            .collect();
        assert_eq!(
            encode(&ldm_wback_in_list),
            None,
            "LDM T1 suppresses writeback when Rn is loaded"
        );
        // And the agreeing pair encodes.
        let mut ldm_no_wback = ldm;
        ldm_no_wback.operands = [Operand::Reg(Reg(0)), Operand::RegList(0b1)]
            .into_iter()
            .collect();
        assert_eq!(encode(&ldm_no_wback), Some(0xC801));
    }

    /// `encode` declines instructions from other groups, so a caller can use
    /// it as a membership test.
    #[test]
    fn encode_is_scoped() {
        let mut b = dec(0xD000, 0x1000).unwrap();
        b.encoding = "T3"; // the 32-bit B<cond>.W, not ours
        assert_eq!(encode(&b), None);
        b.encoding = "T1";
        b.mnemonic = "bl";
        assert_eq!(encode(&b), None);
        let mut udf = dec(0xDE00, 0).unwrap();
        udf.encoding = "T2"; // the 32-bit UDF.W
        assert_eq!(encode(&udf), None);
        udf.encoding = "T1";
        udf.operands = core::iter::once(Operand::Imm(0x100)).collect();
        assert_eq!(encode(&udf), None);
    }

    /// The dispatcher's contract: `super::decode_halfwords` must route the
    /// whole of `0xC000..=0xE7FF` here and nothing else, and `insn_len` must
    /// keep the 32-bit space (`0xE800` and above) away from us. If a sibling
    /// group's range ever overlaps ours, this is where it shows up.
    #[test]
    fn dispatch_boundary() {
        for hw in RANGE_LO..=RANGE_HI {
            assert_eq!(super::super::insn_len(hw), 2, "{hw:#06x}");
            let via_dispatch = super::super::decode_halfwords(hw, 0, 0x1000, false);
            assert_eq!(via_dispatch, dec(hw, 0x1000), "{hw:#06x} routed elsewhere");
        }
        // The first halfword past our range is the start of a 32-bit encoding.
        assert_eq!(super::super::insn_len(0xE800), 4);
    }

    /// End to end through the public API: a short image of one instruction from
    /// each form disassembles to the expected UAL text at the expected
    /// addresses.
    #[test]
    fn disassembles_in_context() {
        // 0x1000: stmia r0!, {r1, r2}
        // 0x1002: ldmia r0!, {r1-r3}
        // 0x1004: beq   0x1008   (imm8 = 0, target = 0x1004 + 4)
        // 0x1006: b     0x100a   (imm11 = 0, target = 0x1006 + 4)
        // 0x1008: svc   #0x2a
        // 0x100a: udf   #0xff
        let hws: [u16; 6] = [0xC006, 0xC80E, 0xD000, 0xE000, 0xDF2A, 0xDEFF];
        let mut image = Vec::new();
        for hw in hws {
            image.extend_from_slice(&hw.to_le_bytes());
        }
        let text = super::super::disassemble(&image, 0, 0x1000, 6);
        assert_eq!(
            text,
            vec![
                "00001000: stmia r0!, {r1, r2}".to_string(),
                "00001002: ldmia r0!, {r1-r3}".to_string(),
                "00001004: beq 0x1008".to_string(),
                "00001006: b 0x100a".to_string(),
                "00001008: svc #0x2a".to_string(),
                "0000100a: udf #0xff".to_string(),
            ]
        );
    }

    /// The sign extension itself, at the two widths this module needs.
    #[test]
    fn sign_extension() {
        assert_eq!(sign_extend(0, 9), 0);
        assert_eq!(sign_extend(0xFE, 9), 254);
        assert_eq!(sign_extend(0x100, 9), -256);
        assert_eq!(sign_extend(0x1FE, 9), -2);
        assert_eq!(sign_extend(0x7FE, 12), 2046);
        assert_eq!(sign_extend(0x800, 12), -2048);
        assert_eq!(sign_extend(0xFFE, 12), -2);
    }
}
