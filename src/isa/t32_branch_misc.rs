//! 32-bit branches and miscellaneous control — `hw1[15:11] == 0b11110` with
//! `hw2[15] == 1` (ARM DDI 0403E.e A5.3.4, Table A5-13; ARM DDI 0406B A6.3.4,
//! Table A6-13).
//!
//! `hw1 = 11110 op(7) …`, `hw2 = 1 op1(3) …`, and `op1` — `hw2[14:12]` — makes
//! the first cut:
//!
//! | `op1`  | `hw2` base | instruction                                    |
//! |--------|------------|------------------------------------------------|
//! | `0x0`  | `0x8000`   | `B<cond>.W` T3, or (`op == 0111xxx`) the control block |
//! | `0x1`  | `0x9000`   | `B.W` T4                                       |
//! | `1x0`  | `0xC000`   | `BLX (immediate)` T2 — A/R only                |
//! | `1x1`  | `0xD000`   | `BL` T1                                        |
//!
//! # T3 and T4 do not pack their immediates the same way
//!
//! This is the trap in the group, and it is worth stating in full because the
//! two encodings differ only in `hw2[12]` yet resolve the *same* `hw1`/`hw2`
//! bits to different addresses:
//!
//! * `B.W` T4, `BL` T1 and `BLX` T2 use `S:I1:I2:imm10:imm11` with
//!   `I1 = NOT(J1 EOR S)` and `I2 = NOT(J2 EOR S)` — a ten-bit high field and
//!   two *inverted* J bits, giving ±16 MB (A7.7.12 encoding T4, A7.7.18
//!   encoding T1, A8.6.23 encoding T2).
//! * `B<cond>.W` T3 uses `S:J2:J1:imm6:imm11` — a **six**-bit high field, the
//!   J bits in the **opposite order**, and **no inversion at all**, giving
//!   ±1 MB (A7.7.12 encoding T3, verified character by character against the
//!   `imm32 = SignExtend(S:J2:J1:imm6:imm11:'0', 32)` line on page A7-205 of
//!   `spec/ARMv7-M.txt`).
//!
//! Reusing the T4 arithmetic for T3 yields a target that is plausible, wrong,
//! and roughly 12 MB away. [`crate::decode_bl`] and [`crate::decode_b_cond`]
//! already encode both rules; this module is cross-checked against them in
//! its own tests.
//!
//! # Two profiles in one table
//!
//! The M profile (DDI 0403E.e) and the A/R profiles (DDI 0406B) allocate this
//! space differently, and this crate decodes the union:
//!
//! * M only: `UDF.W`, `CSDB`, `SSBB`, `PSSBB`, and the `SYSm`-numbered special
//!   registers (`PRIMASK`, `BASEPRI`, `CONTROL`, …) named by `MSR`/`MRS`.
//! * A/R only: `BLX (immediate)` T2 (there is no ARM state to change to in the
//!   M profile), `BXJ`, `SUBS PC, LR, #imm`, `SMC`, the 32-bit `CPS`, the
//!   `CPSR_<fields>`/`SPSR_<fields>` forms of `MSR`/`MRS`, and
//!   `ENTERX`/`LEAVEX`.
//!
//! Where the two profiles give one encoding two names, the name that is legal
//! in both is used: `MSR` with `SYSm == 0` and `mask == 0b1000` prints as
//! `APSR_nzcvq`, which DDI 0406B B6.1.7 states *is* `CPSR_f`.
//!
//! # Strictness
//!
//! Bits the manual writes as `(0)` or `(1)` — "should be zero/one, else
//! UNPREDICTABLE" — are required to hold their nominal value; an encoding that
//! violates one decodes as `None`. That is what makes [`decode`] and
//! [`encode`] exact inverses: a decoder that ignored those bits would have
//! nowhere to put them on the way back, and would silently rewrite the
//! instruction. UNPREDICTABLE *operand* choices that are fully encoded (a
//! `BXJ pc`, an `MSR` from `sp`) do decode, because disassembling what the
//! bytes say is the whole job.

use super::{Insn, Operand, Operands, Reg, Width};
use crate::Cond;

/// Sign-extend `value`, whose sign bit is bit `top`, to 32 bits.
fn sign_extend(value: u32, top: u32) -> u32 {
    if value & (1 << top) != 0 {
        value | (!0u32 << top)
    } else {
        value
    }
}

/// A one-operand list.
fn one(op: Operand) -> Operands {
    [op].into_iter().collect()
}

/// The shape every encoding in this group shares: 32 bits wide, unconditional
/// in its own right, no flag update, no width suffix. The handful of forms
/// that differ override the field with struct-update syntax, so each
/// difference is visible at its own site.
fn wide(mnemonic: &'static str, encoding: &'static str, addr: u32, operands: Operands) -> Insn {
    Insn {
        mnemonic,
        encoding,
        addr,
        width: Width::Wide,
        cond: None,
        sets_flags: false,
        explicit_width: false,
        operands,
    }
}

/// Decode an instruction in this group, or `None` if `hw1`/`hw2` do not
/// belong to it.
pub(crate) fn decode(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 >> 11 != 0b11110 || hw2 >> 15 != 1 {
        return None;
    }
    let op = (hw1 >> 4) & 0b1111111;
    match (hw2 >> 12) & 0b111 {
        0b001 | 0b011 => b_t4(hw1, hw2, addr),
        0b100 | 0b110 => blx_t2(hw1, hw2, addr),
        0b101 | 0b111 => bl_t1(hw1, hw2, addr),
        // `op1 == 0x0`: conditional branch, the control block, and — with
        // `op == 1111111` — the two permanently-special encodings. `op1` here
        // is `000` or `010` because `hw2[13]` is `J1` for the branch and a
        // should-be-zero bit for everything else.
        op1 => {
            if op == 0b1111111 {
                // Table A5-13/A6-13: `op1 == 000` is `SMC` (A/R, Security
                // Extensions), `op1 == 010` is the permanently UNDEFINED space.
                if op1 == 0b000 {
                    smc(hw1, hw2, addr)
                } else {
                    udf_w(hw1, hw2, addr)
                }
            } else if let Some(cond) = t3_cond(hw1) {
                // A condition there *is* — "not x111xxx", the same test as the
                // B pseudocode's `if cond<3:1> == '111' then SEE "Related
                // encodings"`, expressed as the condition lookup itself.
                Some(b_t3(hw1, hw2, addr, cond))
            } else if op1 == 0b000 {
                control(hw1, hw2, addr, op)
            } else {
                None
            }
        }
    }
}

// ---------------------------------------------------------------- branches

/// The `S:I1:I2:…:'0'` displacement shared by `B.W` T4, `BL` T1 and `BLX` T2,
/// sign-extended to 32 bits.
///
/// `BLX` needs no special case: its `imm10L:'0'` occupies exactly the bits
/// `BL`'s `imm11` does, and its low bit is architecturally zero, so the same
/// shift places `imm10L:'00'` correctly.
fn wide_imm(hw1: u16, hw2: u16) -> u32 {
    let s = ((hw1 >> 10) & 1) as u32;
    let imm10 = (hw1 & 0x3FF) as u32;
    let j1 = ((hw2 >> 13) & 1) as u32;
    let j2 = ((hw2 >> 11) & 1) as u32;
    let imm11 = (hw2 & 0x7FF) as u32;
    let i1 = !(j1 ^ s) & 1;
    let i2 = !(j2 ^ s) & 1;
    sign_extend(
        (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1),
        24,
    )
}

/// The condition `B<cond>.W` T3 encodes in `hw1[9:6]`, or `None` for the two
/// patterns the architecture's own "SEE Related encodings" sends elsewhere.
///
/// `cond<3:1> == '111'` is exactly `AL` (`0b1110`) and the reserved `0b1111`,
/// so this one lookup *is* the `x111xxx` test that splits the conditional
/// branch from the control block — and because it is, [`b_t3`] can take a
/// condition it does not have to re-derive or re-check.
fn t3_cond(hw1: u16) -> Option<Cond> {
    let cond = Cond::from_bits(((hw1 >> 6) & 0xF) as u8)?;
    if cond == Cond::Al {
        None
    } else {
        Some(cond)
    }
}

/// `B<cond>.W`, encoding T3 (A7.7.12, DDI 0406B A8.6.16) — ±1 MB, condition in the
/// encoding.
///
/// The condition goes in [`Insn::cond`], not in the mnemonic: `Display`
/// appends the suffix itself, so a mnemonic of `"beq"` would print `beqeq`.
/// It arrives already narrowed by [`t3_cond`], which is why this is infallible.
///
/// Not permitted in an IT block (A7-206: "encodings T1 and T3 are conditional
/// in their own right"), so a consumer that finds one inside an IT block has
/// found an UNPREDICTABLE encoding, not a doubly-conditional branch.
fn b_t3(hw1: u16, hw2: u16, addr: u32, cond: Cond) -> Insn {
    let s = ((hw1 >> 10) & 1) as u32;
    let imm6 = (hw1 & 0x3F) as u32;
    let j1 = ((hw2 >> 13) & 1) as u32;
    let j2 = ((hw2 >> 11) & 1) as u32;
    let imm11 = (hw2 & 0x7FF) as u32;
    // S:J2:J1:imm6:imm11:'0' — J2 above J1, six-bit high field, no inversion.
    let imm = sign_extend(
        (s << 20) | (j2 << 19) | (j1 << 18) | (imm6 << 12) | (imm11 << 1),
        20,
    );
    Insn {
        cond: Some(cond),
        explicit_width: true,
        ..wide(
            "b",
            "T3",
            addr,
            one(Operand::Target(addr.wrapping_add(4).wrapping_add(imm))),
        )
    }
}

/// `B.W`, encoding T4 (A7.7.12) — ±16 MB, unconditional in its own encoding.
///
/// Permitted in an IT block only as the last instruction
/// (`InITBlock() && !LastInITBlock()` is UNPREDICTABLE), which is why
/// [`Insn::cond`] stays `None` here and is filled in by
/// [`crate::isa::Decoder`] when an `IT` governs it.
fn b_t4(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let target = addr.wrapping_add(4).wrapping_add(wide_imm(hw1, hw2));
    Some(Insn {
        explicit_width: true,
        ..wide("b", "T4", addr, one(Operand::Target(target)))
    })
}

/// `BL (immediate)`, encoding T1 (A7.7.18, A8.6.23) — ±16 MB.
///
/// Permitted in an IT block only as the last instruction, like `B.W` T4.
fn bl_t1(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let target = addr.wrapping_add(4).wrapping_add(wide_imm(hw1, hw2));
    Some(wide("bl", "T1", addr, one(Operand::Target(target))))
}

/// `BLX (immediate)`, encoding T2 (A8.6.23) — A/R only, ±16 MB, target
/// four-byte aligned.
///
/// Two things separate this from `BL`. It branches from `Align(PC,4)`, not
/// `PC`, so a `BLX` at an address that is 2 mod 4 reaches two bytes lower than
/// the same immediate in a `BL`; and `hw2[0]` is a literal `0` in the encoding
/// diagram (DDI 0406B A8.6.23 encoding T2; DDI 0406C spells the same
/// restriction as `H == '1'` being UNDEFINED), because the instruction changes
/// to ARM state and an ARM instruction is word-aligned. A `1` there is not a
/// `BLX`, so it decodes as `None` rather than as a `BLX` to an odd halfword.
///
/// The M profile has no ARM state and leaves `op1 == 1x0` UNDEFINED
/// (Table A5-13 has no row for it); decoding it is the union behaviour. It is
/// also UNDEFINED in ThumbEE state (A9.1), and — like `BL` — permitted in an
/// IT block only as the last instruction.
fn blx_t2(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw2 & 1 != 0 {
        return None;
    }
    let pc = addr.wrapping_add(4) & !3;
    let target = pc.wrapping_add(wide_imm(hw1, hw2));
    Some(wide("blx", "T2", addr, one(Operand::Target(target))))
}

// ------------------------------------------------- control block (op1 = 000)

/// Table A5-13/A6-13's `op == 0111xxx` rows, reached only with `op1 == 000`.
fn control(hw1: u16, hw2: u16, addr: u32, op: u16) -> Option<Insn> {
    match op {
        0b0111000 | 0b0111001 => msr(hw1, hw2, addr),
        0b0111010 => hint_or_cps(hw1, hw2, addr),
        0b0111011 => misc_control(hw1, hw2, addr),
        0b0111100 => bxj(hw1, hw2, addr),
        0b0111101 => subs_pc_lr(hw1, hw2, addr),
        0b0111110 | 0b0111111 => mrs(hw1, hw2, addr),
        // `op == 1111xxx` other than `1111111`: UNDEFINED in both profiles.
        _ => None,
    }
}

/// `MSR (register)` — `hw1 = 11110 011100 R Rn`, `hw2 = 10 (0) 0 mask(4) SYSm(8)`
/// (A7.7.83/B5.2.3 for the M profile, A8.6.104/B6.1.7 for A/R).
///
/// The two profiles overlay the same sixteen bits differently: the M profile
/// puts a two-bit `mask` in `hw2[11:10]`, requires `hw2[9:8]` to be zero and
/// names the register with `SYSm` in `hw2[7:0]`; A/R puts a four-bit field
/// mask in `hw2[11:8]` and requires `hw2[7:0]` to be zero. [`msr_dest`] picks
/// between them on exactly those bits.
fn msr(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let name = msr_dest(
        (hw1 >> 4) & 1 == 1,
        ((hw2 >> 8) & 0xF) as u8,
        (hw2 & 0xFF) as u8,
    )?;
    let mut operands = Operands::new();
    operands.push(Operand::SpecialReg(name));
    operands.push(Operand::Reg(Reg((hw1 & 0xF) as u8)));
    Some(wide("msr", "T1", addr, operands))
}

/// `MRS` — `hw1 = 11110 011111 R (1111)`, `hw2 = 10 (0) 0 Rd SYSm(8)`
/// (A7.7.82/B5.2.2, A8.6.102/B6.1.5).
fn mrs(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 & 0xF != 0xF {
        return None;
    }
    let name = mrs_src((hw1 >> 4) & 1 == 1, (hw2 & 0xFF) as u8)?;
    let mut operands = Operands::new();
    operands.push(Operand::Reg(Reg(((hw2 >> 8) & 0xF) as u8)));
    operands.push(Operand::SpecialReg(name));
    Some(wide("mrs", "T1", addr, operands))
}

/// `BXJ <Rm>` — A/R only (A8.6.26), `hw1 = 11110 0111100 Rm`, `hw2 = 0x8F00`.
///
/// `Rm` of 13 or 15 is UNPREDICTABLE but fully encoded, so it decodes.
fn bxj(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw2 != 0x8F00 {
        return None;
    }
    Some(wide(
        "bxj",
        "T1",
        addr,
        one(Operand::Reg(Reg((hw1 & 0xF) as u8))),
    ))
}

/// `SUBS PC, LR, #<imm8>` — A/R exception return (B6.1.13),
/// `hw1 = 0xF3DE`, `hw2 = 10 (0) 0 (1111) imm8`.
///
/// The only encoding in this group that sets flags (it copies `SPSR` to
/// `CPSR`), so it is the only one with `sets_flags: true` — `Display` turns
/// `"sub"` into `subs`. With `imm8 == 0` this is the same encoding a processor
/// with the Virtualization Extensions calls `ERET`, and the same one pre-UAL
/// assembly wrote as `MOVS PC, LR`; the canonical DDI 0406B syntax line
/// `SUBS<c><q> PC, LR, #<const>` is what gets printed, since it is the form
/// that is correct on every A/R processor.
fn subs_pc_lr(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 & 0xF != 0b1110 || hw2 >> 8 != 0x8F {
        return None;
    }
    let mut operands = Operands::new();
    operands.push(Operand::Reg(Reg::PC));
    operands.push(Operand::Reg(Reg::LR));
    operands.push(Operand::Imm((hw2 & 0xFF) as i64));
    Some(Insn {
        sets_flags: true,
        ..wide("sub", "T1", addr, operands)
    })
}

/// `SMC #<imm4>` — A/R Security Extensions (B6.1.9), `hw1 = 11110 1111111 imm4`,
/// `hw2` all zero below bit 15.
fn smc(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw2 != 0x8000 {
        return None;
    }
    Some(wide(
        "smc",
        "T1",
        addr,
        one(Operand::Imm((hw1 & 0xF) as i64)),
    ))
}

/// `UDF.W #<imm16>` — the permanently-undefined 32-bit encoding (A7.7.194
/// encoding T2), `hw1 = 11110 1111111 imm4`, `hw2 = 1010 imm12`.
///
/// Decoded rather than rejected because a consumer scanning firmware wants to
/// see it: it is what a compiler emits for a trap, and telling it apart from
/// "bytes I could not decode" is the difference between a deliberate
/// instruction and a mis-synchronised disassembly. The `.w` is part of the
/// syntax line (`UDF<c>.W #<imm16>`) — the 16-bit T1 takes only an 8-bit
/// immediate, so the suffix is what makes the printed form re-assemble.
fn udf_w(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let imm16 = ((hw1 & 0xF) as i64) << 12 | (hw2 & 0xFFF) as i64;
    Some(Insn {
        explicit_width: true,
        ..wide("udf", "T2", addr, one(Operand::Imm(imm16)))
    })
}

// -------------------------------------------------------- hints, CPS, misc

/// Table A5-14/A6-14: `hw1 = 0xF3AF`, `hw2 = 10 (0) 0 (0) op1(3) op2(8)`.
///
/// `op1 != 000` is the 32-bit `CPS` on A/R and UNDEFINED on M; `op1 == 000`
/// selects a hint by `op2`.
fn hint_or_cps(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 != 0xF3AF || hw2 & 0x0800 != 0 {
        return None;
    }
    let op1 = (hw2 >> 8) & 0b111;
    let op2 = (hw2 & 0xFF) as u8;
    if op1 != 0 {
        return cps(op1, op2, addr);
    }
    if op2 & 0xF0 == 0xF0 {
        // `DBG #<option>` (A7.7.32, A8.6.40).
        return Some(wide(
            "dbg",
            "T1",
            addr,
            one(Operand::Imm((op2 & 0xF) as i64)),
        ));
    }
    let mnemonic = hint_name(op2)?;
    Some(Insn {
        explicit_width: true,
        ..wide(mnemonic, hint_encoding(mnemonic), addr, Operands::new())
    })
}

/// The architectural encoding name that goes with a hint mnemonic.
///
/// `CSDB` has no 16-bit encoding, so its 32-bit form is encoding T1; the five
/// NOP-compatible hints all have one, so theirs is T2. Both print `.w`: the
/// syntax lines are `NOP<c>.W` (A7.7.88) and `CSDB{<c>}.W` (A7.7.31), and a
/// bare `nop` would assemble back to the 16-bit encoding.
fn hint_encoding(mnemonic: &str) -> &'static str {
    if mnemonic == "csdb" {
        "T1"
    } else {
        "T2"
    }
}

/// Table A5-14/A6-14's named hints. Unallocated values "execute as NOP" but
/// are reserved, and printing them as `nop.w` would throw away the `op2` bits
/// that make them distinguishable, so they decode as `None`.
fn hint_name(op2: u8) -> Option<&'static str> {
    Some(match op2 {
        0x00 => "nop",
        0x01 => "yield",
        0x02 => "wfe",
        0x03 => "wfi",
        0x04 => "sev",
        0x14 => "csdb",
        _ => return None,
    })
}

/// `CPS` encoding T2 — A/R only (B6.1.1), `hw2 = 10 (0) 0 (0) imod(2) M A I F mode(5)`.
///
/// Three syntactic forms: `CPSIE.W <iflags>{,#<mode>}`, `CPSID.W <iflags>{,#<mode>}`
/// and `CPS #<mode>`. `imod == 01` is UNPREDICTABLE, an effect with no
/// interrupt flags has no syntax to print, and `M == 0` leaves the `mode`
/// field zero — each of those decodes as `None` so that what does decode
/// re-encodes bit for bit.
fn cps(op1: u16, op2: u8, addr: u32) -> Option<Insn> {
    let imod = (op1 >> 1) & 0b11;
    let m = op1 & 1 == 1;
    let a = op2 & 0x80 != 0;
    let i = op2 & 0x40 != 0;
    let f = op2 & 0x20 != 0;
    let mode = (op2 & 0x1F) as i64;
    if imod == 0b01 {
        return None;
    }
    if imod == 0b00 {
        // `op1 != 0` got us here, so `M` is set: this is `CPS #<mode>`, which
        // changes no interrupt flag.
        if a || i || f {
            return None;
        }
        return Some(wide("cps", "T2", addr, one(Operand::Imm(mode))));
    }
    if !m && mode != 0 {
        return None;
    }
    let mut operands = Operands::new();
    operands.push(Operand::Text(iflags(a, i, f)?));
    if m {
        operands.push(Operand::Imm(mode));
    }
    Some(Insn {
        explicit_width: true,
        ..wide(
            if imod == 0b10 { "cpsie" } else { "cpsid" },
            "T2",
            addr,
            operands,
        )
    })
}

/// The `<iflags>` spelling of the `A`, `I` and `F` bits. All three clear has
/// no spelling — `CPS<effect>` requires at least one flag.
fn iflags(a: bool, i: bool, f: bool) -> Option<&'static str> {
    Some(match (a, i, f) {
        (false, false, false) => return None,
        (true, false, false) => "a",
        (false, true, false) => "i",
        (false, false, true) => "f",
        (true, true, false) => "ai",
        (true, false, true) => "af",
        (false, true, true) => "if",
        (true, true, true) => "aif",
    })
}

/// Table A5-15/A6-15: `hw1 = 0xF3BF`, `hw2 = 10 (0) 0 (1111) opc(4) option(4)`.
fn misc_control(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 != 0xF3BF || hw2 >> 8 != 0x8F {
        return None;
    }
    let opc = (hw2 >> 4) & 0xF;
    let option = (hw2 & 0xF) as u8;
    let bare = |mnemonic| Some(wide(mnemonic, "T1", addr, Operands::new()));
    match opc {
        // ThumbEE state changes (A9.3.1). Their `option` field is `(1111)`.
        0b0000 | 0b0001 if option == 0xF => bare(if opc == 0 { "leavex" } else { "enterx" }),
        0b0010 if option == 0xF => bare("clrex"),
        0b0100 => match option {
            // Armv7-M (DDI 0403E.e Table A5-15) names two `DSB` options; on
            // A/R they are reserved `DSB` options that execute as a full
            // system `DSB`. The named forms are strictly more informative and
            // cannot be confused with anything else, so the union decodes them.
            0b0000 => bare("ssbb"),
            0b0100 => bare("pssbb"),
            _ => Some(wide("dsb", "T1", addr, one(barrier_operand(option, true)))),
        },
        0b0101 => Some(wide("dmb", "T1", addr, one(barrier_operand(option, true)))),
        // `ISB` defines only `SY`; its other `option` values are RESERVED and
        // carry none of `DSB`'s shareability meaning, so they print as a bare
        // immediate rather than borrowing a name that is not theirs.
        0b0110 => Some(wide("isb", "T1", addr, one(barrier_operand(option, false)))),
        _ => None,
    }
}

/// The named `option` values of `DSB`/`DMB` (A8.6.41, A8.6.42 — the M profile
/// defines only `SY`, the A/R profiles the full shareability set).
fn barrier_option(bits: u8) -> Option<&'static str> {
    Some(match bits {
        0b0010 => "oshst",
        0b0011 => "osh",
        0b0110 => "nshst",
        0b0111 => "nsh",
        0b1010 => "ishst",
        0b1011 => "ish",
        0b1110 => "st",
        0b1111 => "sy",
        _ => return None,
    })
}

/// The printed `option` operand: a name where the barrier defines one,
/// otherwise the raw `#<option>` of the encoding's own syntax line.
fn barrier_operand(bits: u8, shareability: bool) -> Operand {
    let name = if shareability {
        barrier_option(bits)
    } else if bits == 0b1111 {
        Some("sy")
    } else {
        None
    };
    match name {
        Some(n) => Operand::Option(n),
        None => Operand::Imm(bits as i64),
    }
}

// ------------------------------------------------- special-register naming

/// The `<spec_reg>` an `MSR` writes, from the `R` bit, `hw2[11:8]` and
/// `hw2[7:0]`.
///
/// The branch order is the profile discriminator. `SYSm != 0` can only be the
/// M profile, whose `mask` is `hw2[11:10]` with `hw2[9:8]` zero; a `mask` with
/// either low bit set can only be A/R, whose `SYSm` byte is all zero. Where
/// both readings are legal — `SYSm == 0`, low `mask` bits clear — the
/// `APSR_<bits>` name is used, because DDI 0406B B6.1.7 states outright that
/// `APSR_nzcvq` *is* `CPSR_f`, `APSR_g` *is* `CPSR_s` and `APSR_nzcvqg` *is*
/// `CPSR_fs`, and recommends the `APSR` spelling.
fn msr_dest(spsr: bool, mask: u8, sysm: u8) -> Option<&'static str> {
    if spsr {
        // `SPSR_<fields>` (A/R, system level). The `SYSm` byte is `(0)`.
        return if sysm == 0 {
            psr_fields(true, mask)
        } else {
            None
        };
    }
    if mask & 0b0011 == 0 {
        m_profile_write(mask >> 2, sysm)
    } else if sysm == 0 {
        psr_fields(false, mask)
    } else {
        None
    }
}

/// The `<spec_reg>` an `MRS` reads, from the `R` bit and `SYSm`.
fn mrs_src(spsr: bool, sysm: u8) -> Option<&'static str> {
    if spsr {
        // A/R `MRS <Rd>, SPSR` (B6.1.5). The M profile has no `R` bit — the
        // position holds a `(0)` — so this reading is A/R only.
        return if sysm == 0 { Some("SPSR") } else { None };
    }
    m_profile_read(sysm)
}

/// Armv7-M Table B5-1, on the `MSR` side, where writes to the four xPSR
/// composites carry the `_<bits>` qualifier that `mask` encodes (Table B5-2:
/// `01` = `_g`, `10` = `_nzcvq`, `11` = `_nzcvqg`).
///
/// Every other special register requires `mask == 0b10`
/// (B5.2.3: `mask != '10' && !(UInt(SYSm) IN {0..3})` is UNPREDICTABLE), so
/// any other value has no name to print and decodes as `None`.
fn m_profile_write(mask: u8, sysm: u8) -> Option<&'static str> {
    Some(match (sysm, mask) {
        (0, 0b01) => "APSR_g",
        (0, 0b10) => "APSR_nzcvq",
        (0, 0b11) => "APSR_nzcvqg",
        (1, 0b01) => "IAPSR_g",
        (1, 0b10) => "IAPSR_nzcvq",
        (1, 0b11) => "IAPSR_nzcvqg",
        (2, 0b01) => "EAPSR_g",
        (2, 0b10) => "EAPSR_nzcvq",
        (2, 0b11) => "EAPSR_nzcvqg",
        (3, 0b01) => "XPSR_g",
        (3, 0b10) => "XPSR_nzcvq",
        (3, 0b11) => "XPSR_nzcvqg",
        (5, 0b10) => "IPSR",
        (6, 0b10) => "EPSR",
        (7, 0b10) => "IEPSR",
        (8, 0b10) => "MSP",
        (9, 0b10) => "PSP",
        (16, 0b10) => "PRIMASK",
        (17, 0b10) => "BASEPRI",
        (18, 0b10) => "BASEPRI_MAX",
        (19, 0b10) => "FAULTMASK",
        (20, 0b10) => "CONTROL",
        _ => return None,
    })
}

/// Armv7-M Table B5-1 on the `MRS` side, where no `_<bits>` qualifier applies
/// because nothing is being written. `SYSm == 0` is `APSR`, which is also the
/// A/R `MRS <Rd>, APSR` (A8.6.102) — the A/R `CPSR` spelling shares the
/// encoding and is the one the manual deprecates for application code.
fn m_profile_read(sysm: u8) -> Option<&'static str> {
    Some(match sysm {
        0 => "APSR",
        1 => "IAPSR",
        2 => "EAPSR",
        3 => "XPSR",
        5 => "IPSR",
        6 => "EPSR",
        7 => "IEPSR",
        8 => "MSP",
        9 => "PSP",
        16 => "PRIMASK",
        17 => "BASEPRI",
        18 => "BASEPRI_MAX",
        19 => "FAULTMASK",
        20 => "CONTROL",
        _ => return None,
    })
}

/// `SPSR_<fields>`, indexed by the A/R four-bit field mask (B6.1.7: `c` is
/// `mask<0>`, `x` is `mask<1>`, `s` is `mask<2>`, `f` is `mask<3>`, written
/// high field first). Entry 0 is empty: `mask == 0000` is UNPREDICTABLE and
/// has no spelling.
const SPSR_FIELDS: [&str; 16] = [
    "",
    "SPSR_c",
    "SPSR_x",
    "SPSR_xc",
    "SPSR_s",
    "SPSR_sc",
    "SPSR_sx",
    "SPSR_sxc",
    "SPSR_f",
    "SPSR_fc",
    "SPSR_fx",
    "SPSR_fxc",
    "SPSR_fs",
    "SPSR_fsc",
    "SPSR_fsx",
    "SPSR_fsxc",
];

/// `CPSR_<fields>`, indexed as [`SPSR_FIELDS`] is.
///
/// Four entries are deliberately empty. `mask == 0000` is UNPREDICTABLE, and
/// the three masks whose low two bits are both clear — `0100`, `1000` and
/// `1100` — are the ones DDI 0406B B6.1.7 states outright *are* `APSR_g`,
/// `APSR_nzcvq` and `APSR_nzcvqg`. [`msr_dest`] sends those to the `APSR`
/// spelling the manual recommends, so `CPSR_s`, `CPSR_f` and `CPSR_fs` are
/// names this crate never prints — and, because [`msr_dest_bits`] searches
/// this same table, never accepts either.
const CPSR_FIELDS: [&str; 16] = [
    "",
    "CPSR_c",
    "CPSR_x",
    "CPSR_xc",
    "",
    "CPSR_sc",
    "CPSR_sx",
    "CPSR_sxc",
    "",
    "CPSR_fc",
    "CPSR_fx",
    "CPSR_fxc",
    "",
    "CPSR_fsc",
    "CPSR_fsx",
    "CPSR_fsxc",
];

/// The `CPSR_<fields>`/`SPSR_<fields>` name a four-bit field mask spells, or
/// `None` where its table entry is empty.
fn psr_fields(spsr: bool, mask: u8) -> Option<&'static str> {
    let table = if spsr { &SPSR_FIELDS } else { &CPSR_FIELDS };
    match table[(mask & 0xF) as usize] {
        "" => None,
        name => Some(name),
    }
}

// ------------------------------------------------------------------ encode

/// Re-encode an instruction this module decoded, back to its two halfwords.
///
/// Deliberately strict, and the inverse of [`decode`] on the nose: the
/// architectural encoding name must match, the width must be `Wide`, the
/// operand shape must be the one [`decode`] produces, and a displacement that
/// no longer fits returns `None` rather than wrapping into a plausible branch
/// somewhere else entirely.
///
/// [`Insn::addr`] is load-bearing for every branch here — the encoded field is
/// a displacement from `addr + 4` — so re-encoding an instruction at a new
/// address means setting `addr` first, not adjusting the target.
///
/// [`Insn::cond`] is consulted only for `B<cond>.W` T3, the one encoding that
/// holds a condition. Everything else is unconditional in its own right, and
/// an instruction made conditional by an enclosing `IT` block must re-encode
/// to the same halfwords it decoded from.
// reaches this and `-D warnings` would reject the group on `dead_code`.
pub(crate) fn encode(insn: &Insn) -> Option<(u16, u16)> {
    if insn.width != Width::Wide {
        return None;
    }
    let imm = |i: usize, max: i64| match insn.operands.get(i) {
        Some(Operand::Imm(v)) if (0..=max).contains(&v) => Some(v as u16),
        _ => None,
    };
    // The hints are dispatched by the inverse lookup rather than by a list of
    // mnemonics, so that the list cannot fall out of step with [`hint_name`]
    // and so that "this is not a hint" is one decision made in one place.
    if let Some(op2) = hint_bits(insn.mnemonic, insn.encoding) {
        if !insn.explicit_width || insn.sets_flags || !insn.operands.is_empty() {
            return None;
        }
        return Some((0xF3AF, 0x8000 | op2));
    }
    match (insn.mnemonic, insn.encoding) {
        ("b", "T3") => encode_b_t3(insn),
        ("b", "T4") => encode_branch(insn, 0x9000, 2, true),
        ("bl", "T1") => encode_branch(insn, 0xD000, 2, false),
        ("blx", "T2") => encode_branch(insn, 0xC000, 4, false),
        ("udf", "T2") => {
            if !insn.explicit_width || insn.sets_flags || insn.operands.len() != 1 {
                return None;
            }
            let v = imm(0, 0xFFFF)?;
            Some((0xF7F0 | (v >> 12), 0xA000 | (v & 0xFFF)))
        }
        ("smc", "T1") => {
            if insn.explicit_width || insn.sets_flags || insn.operands.len() != 1 {
                return None;
            }
            Some((0xF7F0 | imm(0, 0xF)?, 0x8000))
        }
        ("msr", "T1") => {
            if insn.explicit_width || insn.sets_flags || insn.operands.len() != 2 {
                return None;
            }
            let name = match insn.operands.get(0) {
                Some(Operand::SpecialReg(n)) => n,
                _ => return None,
            };
            let rn = match insn.operands.get(1) {
                Some(Operand::Reg(r)) => r.num() as u16,
                _ => return None,
            };
            let (r, mask, sysm) = msr_dest_bits(name)?;
            Some((0xF380 | (r << 4) | rn, 0x8000 | (mask << 8) | sysm))
        }
        ("mrs", "T1") => {
            if insn.explicit_width || insn.sets_flags || insn.operands.len() != 2 {
                return None;
            }
            let rd = match insn.operands.get(0) {
                Some(Operand::Reg(r)) => r.num() as u16,
                _ => return None,
            };
            let name = match insn.operands.get(1) {
                Some(Operand::SpecialReg(n)) => n,
                _ => return None,
            };
            let (r, sysm) = mrs_src_bits(name)?;
            Some((0xF3EF | (r << 4), 0x8000 | (rd << 8) | sysm))
        }
        ("bxj", "T1") => {
            if insn.explicit_width || insn.sets_flags || insn.operands.len() != 1 {
                return None;
            }
            match insn.operands.get(0) {
                Some(Operand::Reg(rm)) => Some((0xF3C0 | rm.num() as u16, 0x8F00)),
                _ => None,
            }
        }
        ("sub", "T1") => {
            // `SUBS PC, LR, #<imm8>` and nothing else: the mnemonic is shared
            // with half the instruction set, so the whole operand shape has to
            // match before this claims it.
            if insn.explicit_width || !insn.sets_flags || insn.operands.len() != 3 {
                return None;
            }
            if insn.operands.get(0) != Some(Operand::Reg(Reg::PC))
                || insn.operands.get(1) != Some(Operand::Reg(Reg::LR))
            {
                return None;
            }
            Some((0xF3DE, 0x8F00 | imm(2, 0xFF)?))
        }
        ("dbg", "T1") => {
            if insn.explicit_width || insn.sets_flags || insn.operands.len() != 1 {
                return None;
            }
            Some((0xF3AF, 0x80F0 | imm(0, 0xF)?))
        }
        ("cps" | "cpsie" | "cpsid", "T2") => encode_cps(insn),
        ("clrex" | "enterx" | "leavex", "T1") => {
            if insn.explicit_width || insn.sets_flags || !insn.operands.is_empty() {
                return None;
            }
            let opc = match insn.mnemonic {
                "leavex" => 0x0,
                "enterx" => 0x1,
                _ => 0x2,
            };
            Some((0xF3BF, 0x8F0F | (opc << 4)))
        }
        ("ssbb" | "pssbb", "T1") => {
            if insn.explicit_width || insn.sets_flags || !insn.operands.is_empty() {
                return None;
            }
            Some((0xF3BF, 0x8F40 | if insn.mnemonic == "ssbb" { 0 } else { 4 }))
        }
        ("dsb" | "dmb" | "isb", "T1") => {
            if insn.explicit_width || insn.sets_flags || insn.operands.len() != 1 {
                return None;
            }
            let (opc, shareability) = match insn.mnemonic {
                "dsb" => (0x4, true),
                "dmb" => (0x5, true),
                _ => (0x6, false),
            };
            let option = barrier_bits(insn.operands.get(0), shareability)?;
            // `SSBB`/`PSSBB` own those two `DSB` encodings, so `dsb #0` and
            // `dsb #4` are not re-encodable as `DSB` — they would decode back
            // to a different mnemonic.
            if opc == 0x4 && (option == 0 || option == 4) {
                return None;
            }
            Some((0xF3BF, 0x8F00 | (opc << 4) | option))
        }
        _ => None,
    }
}

/// Encode `B.W` T4, `BL` T1 or `BLX` T2 — the `S:I1:I2:…` forms.
///
/// `align` is 2 for `B.W`/`BL` and 4 for `BLX`, which both rounds the pc down
/// (`BLX` branches from `Align(PC,4)`) and rejects a target that is not
/// word-aligned, since `BLX` switches to ARM state.
fn encode_branch(insn: &Insn, base: u16, align: u32, explicit_width: bool) -> Option<(u16, u16)> {
    if insn.explicit_width != explicit_width || insn.sets_flags || insn.operands.len() != 1 {
        return None;
    }
    let target = match insn.operands.get(0) {
        Some(Operand::Target(t)) => t,
        _ => return None,
    };
    let mut pc = insn.addr.wrapping_add(4);
    if align == 4 {
        pc &= !3;
    }
    let off = target.wrapping_sub(pc) as i32;
    if !(-(1 << 24)..(1 << 24)).contains(&off) || off & (align as i32 - 1) != 0 {
        return None;
    }
    let imm = (off >> 1) as u32 & 0x00ff_ffff;
    let s = (imm >> 23) & 1;
    let i1 = (imm >> 22) & 1;
    let i2 = (imm >> 21) & 1;
    let j1 = !(i1 ^ s) & 1;
    let j2 = !(i2 ^ s) & 1;
    let hw1 = 0xF000 | ((s as u16) << 10) | ((imm >> 11) & 0x3FF) as u16;
    let hw2 = base | ((j1 as u16) << 13) | ((j2 as u16) << 11) | (imm & 0x7FF) as u16;
    Some((hw1, hw2))
}

/// Encode `B<cond>.W` T3 — `S:J2:J1:imm6:imm11`, no inversion, ±1 MB.
fn encode_b_t3(insn: &Insn) -> Option<(u16, u16)> {
    if !insn.explicit_width || insn.sets_flags || insn.operands.len() != 1 {
        return None;
    }
    let cond = insn.cond?;
    // `AL` is `0b1110`, which T3 does not encode: `cond<3:1> == '111'` is a
    // different instruction class. Use `B.W` T4 for an unconditional branch.
    if cond == Cond::Al {
        return None;
    }
    let target = match insn.operands.get(0) {
        Some(Operand::Target(t)) => t,
        _ => return None,
    };
    let off = target.wrapping_sub(insn.addr.wrapping_add(4)) as i32;
    if !(-(1 << 20)..(1 << 20)).contains(&off) || off & 1 != 0 {
        return None;
    }
    let imm = (off >> 1) as u32 & 0x000f_ffff;
    let s = ((imm >> 19) & 1) as u16;
    let j2 = ((imm >> 18) & 1) as u16;
    let j1 = ((imm >> 17) & 1) as u16;
    let hw1 = 0xF000 | (s << 10) | ((cond.bits() as u16) << 6) | ((imm >> 11) & 0x3F) as u16;
    let hw2 = 0x8000 | (j1 << 13) | (j2 << 11) | (imm & 0x7FF) as u16;
    Some((hw1, hw2))
}

/// Encode the 32-bit `CPS` (A/R, B6.1.1 encoding T2).
fn encode_cps(insn: &Insn) -> Option<(u16, u16)> {
    let (imod, wide_suffix) = match insn.mnemonic {
        "cps" => (0b00u16, false),
        "cpsie" => (0b10, true),
        _ => (0b11, true),
    };
    if insn.explicit_width != wide_suffix || insn.sets_flags {
        return None;
    }
    let mode_at = |i: usize| match insn.operands.get(i) {
        Some(Operand::Imm(v)) if (0..=0x1F).contains(&v) => Some(v as u16),
        _ => None,
    };
    let (m, mode, flags) = if imod == 0b00 {
        if insn.operands.len() != 1 {
            return None;
        }
        (1u16, mode_at(0)?, 0u16)
    } else {
        let name = match insn.operands.get(0) {
            Some(Operand::Text(t)) => t,
            _ => return None,
        };
        let bits =
            (0u16..8).find(|b| iflags(b & 4 != 0, b & 2 != 0, b & 1 != 0) == Some(name))? << 5;
        match insn.operands.len() {
            1 => (0, 0, bits),
            2 => (1, mode_at(1)?, bits),
            _ => return None,
        }
    };
    Some((0xF3AF, 0x8000 | (imod << 9) | (m << 8) | flags | mode))
}

/// The `R`, `mask` and `SYSm` fields an `MSR` destination name encodes.
///
/// Found by searching [`msr_dest`] rather than by a second table, so the two
/// directions cannot drift apart; the space is 420 combinations, which is
/// nothing next to a decode.
fn msr_dest_bits(name: &str) -> Option<(u16, u16, u16)> {
    for spsr in [false, true] {
        for mask in 1u8..16 {
            for sysm in [0u8, 1, 2, 3, 5, 6, 7, 8, 9, 16, 17, 18, 19, 20] {
                if msr_dest(spsr, mask, sysm) == Some(name) {
                    return Some((spsr as u16, mask as u16, sysm as u16));
                }
            }
        }
    }
    None
}

/// The `R` and `SYSm` fields an `MRS` source name encodes.
fn mrs_src_bits(name: &str) -> Option<(u16, u16)> {
    for spsr in [false, true] {
        for sysm in 0u8..=20 {
            if mrs_src(spsr, sysm) == Some(name) {
                return Some((spsr as u16, sysm as u16));
            }
        }
    }
    None
}

/// The `option` field a decoded barrier operand came from, or `None` if the
/// operand is absent or is not one [`barrier_operand`] produces.
fn barrier_bits(op: Option<Operand>, shareability: bool) -> Option<u16> {
    (0u8..16)
        .find(|&bits| Some(barrier_operand(bits, shareability)) == op)
        .map(u16::from)
}

/// The `op2` field a hint mnemonic encodes, if `encoding` is the one
/// [`hint_encoding`] pairs with that mnemonic.
///
/// Searched rather than tabulated a second time, so [`hint_name`] stays the
/// single source of truth for Table A5-14's names and the two directions
/// cannot drift apart. 256 comparisons of `&'static str` pointers is nothing
/// next to a decode.
fn hint_bits(mnemonic: &str, encoding: &str) -> Option<u16> {
    if encoding != hint_encoding(mnemonic) {
        return None;
    }
    (0u8..=0xFF)
        .find(|&op2| hint_name(op2) == Some(mnemonic))
        .map(u16::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode_b_wide, decode_bl, encode_b_wide, encode_bl};

    /// The printed UAL form of a 32-bit encoding decoded at address 0.
    fn ual(hw1: u16, hw2: u16) -> String {
        dec(hw1, hw2, 0).to_string()
    }

    /// Decode, panicking with the pattern if it does not — a failing assertion
    /// should name the encoding it tripped on.
    ///
    /// `assert!` rather than `unwrap_or_else(|| panic!(…))`: the closure in the
    /// latter is a function that never runs, and this crate's coverage gate is
    /// 100% of functions.
    fn dec(hw1: u16, hw2: u16, addr: u32) -> Insn {
        let decoded = decode(hw1, hw2, addr);
        assert!(decoded.is_some(), "{hw1:#06x} {hw2:#06x} did not decode");
        decoded.unwrap()
    }

    /// Decode, assert it round-trips, and hand back the instruction.
    fn round_trip(hw1: u16, hw2: u16, addr: u32) -> Insn {
        let insn = dec(hw1, hw2, addr);
        assert_eq!(
            encode(&insn),
            Some((hw1, hw2)),
            "round-trip of {hw1:#06x} {hw2:#06x} ({insn})"
        );
        insn
    }

    /// A decoded instruction of this group with its operand list swapped for
    /// another — the shortest way to ask [`encode`] about an operand shape
    /// [`decode`] never produces, without hand-building every other field.
    fn with_operands(hw1: u16, hw2: u16, operands: &[Operand]) -> Insn {
        let mut insn = dec(hw1, hw2, 0);
        insn.operands = operands.iter().copied().collect();
        insn
    }

    /// The two halfwords of a 4-byte little-endian encoding.
    fn halfwords(bytes: [u8; 4]) -> (u16, u16) {
        (
            u16::from_le_bytes([bytes[0], bytes[1]]),
            u16::from_le_bytes([bytes[2], bytes[3]]),
        )
    }

    /// Sites and targets spanning forward, backward, zero, and both extremes
    /// of the ±16 MB range, for the oracle cross-check.
    const WIDE_CASES: [(u32, u32); 9] = [
        (0x0000_1000, 0x0000_2000),               // forward
        (0x0000_2000, 0x0000_1000),               // backward
        (0x0000_1000, 0x0000_1004),               // zero displacement
        (0x0000_1000, 0x0000_1006),               // +2
        (0x0000_1000, 0x0000_1002),               // -2
        (0x0000_0000, 0x0100_0002),               // max forward: 4 + 0xFFFFFE
        (0x0100_0000, 0x0000_0004),               // max backward: 4 - 0x1000000
        (0x0800_0000, 0x0800_0004 + 0x00FF_FFFE), // max forward, high base
        (0x0800_0000, 0x0800_0004 - 0x0100_0000), // max backward, high base
    ];

    #[test]
    fn bl_agrees_with_the_existing_oracle() {
        for (site, target) in WIDE_CASES {
            let encoded = encode_bl(site as usize, target);
            assert!(
                encoded.is_some(),
                "oracle rejected {site:#x} -> {target:#x}"
            );
            let bytes = encoded.unwrap();
            let (hw1, hw2) = halfwords(bytes);
            let insn = round_trip(hw1, hw2, site);
            assert_eq!(insn.mnemonic, "bl");
            assert_eq!(insn.encoding, "T1");
            assert_eq!(
                insn.branch_target(),
                decode_bl(&bytes, 0).map(|t| t.wrapping_add(site)),
                "target disagreement at {site:#x} -> {target:#x}"
            );
            assert_eq!(insn.branch_target(), Some(target));
            // And the bytes agree in the other direction.
            let mut relocated = insn;
            relocated.addr = site;
            assert_eq!(encode(&relocated), Some((hw1, hw2)));
        }
    }

    #[test]
    fn b_wide_agrees_with_the_existing_oracle() {
        for (site, target) in WIDE_CASES {
            let bytes = encode_b_wide(site as usize, target).unwrap();
            let (hw1, hw2) = halfwords(bytes);
            let insn = round_trip(hw1, hw2, site);
            assert_eq!(insn.mnemonic, "b");
            assert_eq!(insn.encoding, "T4");
            assert_eq!(
                insn.branch_target(),
                decode_b_wide(&bytes, 0).map(|t| t.wrapping_add(site)),
                "target disagreement at {site:#x} -> {target:#x}"
            );
            assert_eq!(insn.branch_target(), Some(target));
        }
    }

    /// Bytes emitted by a real assembler, and what this module makes of them.
    ///
    /// Produced by `clang -target thumbv7m-none-eabi` and
    /// `clang -target thumbv7a-none-eabi -mcpu=cortex-a15` over the manual's
    /// own syntax lines, then disassembled with `objdump -d`. This is the
    /// check the spec cannot give: that the *whole* chain — table dispatch,
    /// field extraction, naming — agrees with a production toolchain on
    /// concrete bytes.
    #[test]
    fn assembler_verified_encodings() {
        #[rustfmt::skip]
        let cases: [(u16, u16, u32, &str); 24] = [
            // thumbv7m
            (0xF383, 0x8810, 0, "msr PRIMASK, r3"),
            (0xF380, 0x8800, 0, "msr APSR_nzcvq, r0"),
            (0xF3EF, 0x8010, 0, "mrs r0, PRIMASK"),
            (0xF3EF, 0x8100, 0, "mrs r1, APSR"),
            (0xF3AF, 0x8000, 0, "nop.w"),
            (0xF3AF, 0x8014, 0, "csdb.w"),
            (0xF3AF, 0x80FF, 0, "dbg #0xf"),
            (0xF3BF, 0x8F4F, 0, "dsb sy"),
            (0xF3BF, 0x8F4B, 0, "dsb ish"),
            (0xF3BF, 0x8F52, 0, "dmb oshst"),
            (0xF3BF, 0x8F6F, 0, "isb sy"),
            (0xF3BF, 0x8F2F, 0, "clrex"),
            (0xF7F1, 0xA234, 0, "udf.w #0x1234"),
            (0xF000, 0xB800, 0x34, "b.w 0x38"),
            (0xF000, 0xF800, 0x38, "bl 0x3c"),
            (0xF43F, 0xAFFE, 0x3C, "beq.w 0x3c"),
            // thumbv7a
            (0xF3C5, 0x8F00, 0, "bxj r5"),
            (0xF3DE, 0x8F04, 0, "subs pc, lr, #4"),
            (0xF380, 0x8900, 0, "msr CPSR_fc, r0"),
            (0xF394, 0x8100, 0, "msr SPSR_c, r4"),
            (0xF3FF, 0x8200, 0, "mrs r2, SPSR"),
            (0xF3AF, 0x8793, 0, "cpsid.w a, #0x13"),
            (0xF7F5, 0x8000, 0, "smc #5"),
            (0xF7FF, 0xEFFE, 0x08, "blx 0x8"),
        ];
        for (hw1, hw2, addr, text) in cases {
            assert_eq!(round_trip(hw1, hw2, addr).to_string(), text);
        }
    }

    #[test]
    fn oracle_decoders_are_offset_relative_and_still_agree_bit_for_bit() {
        // `decode_bl`/`decode_b_wide` resolve against the *file offset* they
        // are given, so decoding at offset `off` inside a buffer is the same
        // arithmetic as decoding at address `off`. Sweeping every J1/J2/S
        // combination checks the inversion rule, not just one displacement.
        let mut image = [0u8; 4];
        for s in 0..2u16 {
            for j1 in 0..2u16 {
                for j2 in 0..2u16 {
                    for (imm10, imm11) in [(0u16, 0u16), (0x3FF, 0x7FF), (1, 1), (0x200, 0x400)] {
                        let hw1 = 0xF000 | (s << 10) | imm10;
                        for (base, oracle) in [
                            (0xD000u16, decode_bl as fn(&[u8], usize) -> Option<u32>),
                            (0x9000, decode_b_wide),
                        ] {
                            let hw2 = base | (j1 << 13) | (j2 << 11) | imm11;
                            image[0..2].copy_from_slice(&hw1.to_le_bytes());
                            image[2..4].copy_from_slice(&hw2.to_le_bytes());
                            let insn = round_trip(hw1, hw2, 0x40);
                            assert_eq!(
                                insn.branch_target(),
                                oracle(&image, 0).map(|t| t.wrapping_add(0x40)),
                                "{hw1:#06x} {hw2:#06x}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn b_cond_wide_agrees_with_decode_b_cond() {
        // `decode_b_cond` (src/lib.rs) is the other half of the oracle: it
        // already implements the T3 `S:J2:J1:imm6:imm11` packing.
        let mut image = [0u8; 4];
        for s in 0..2u16 {
            for j1 in 0..2u16 {
                for j2 in 0..2u16 {
                    for cond in 0..14u16 {
                        for (imm6, imm11) in [(0u16, 0u16), (0x3F, 0x7FF), (1, 1), (0x20, 0x400)] {
                            let hw1 = 0xF000 | (s << 10) | (cond << 6) | imm6;
                            let hw2 = 0x8000 | (j1 << 13) | (j2 << 11) | imm11;
                            image[0..2].copy_from_slice(&hw1.to_le_bytes());
                            image[2..4].copy_from_slice(&hw2.to_le_bytes());
                            let insn = round_trip(hw1, hw2, 0x40);
                            let oracle = crate::decode_b_cond(&image, 0).unwrap();
                            assert_eq!(oracle.len, 4);
                            assert_eq!(insn.cond, Some(oracle.cond), "{hw1:#06x} {hw2:#06x}");
                            assert_eq!(
                                insn.branch_target(),
                                Some(oracle.target.wrapping_add(0x40)),
                                "{hw1:#06x} {hw2:#06x}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn t3_and_t4_pack_their_immediates_differently() {
        // The same `hw1` and the same J bits; only `hw2[12]` differs.
        //   hw1 = 0xF001: S = 0, cond = 0b0000 (eq), imm6 = 1, imm10 = 1.
        //   hw2 = 0x8000 (T3) / 0x9000 (T4): J1 = J2 = 0, imm11 = 0.
        let t3 = round_trip(0xF001, 0x8000, 0x1000);
        let t4 = round_trip(0xF001, 0x9000, 0x1000);

        // T3: S:J2:J1:imm6:imm11:'0' = 0:0:0:000001:00000000000:0 = 0x1000.
        assert_eq!(t3.cond, Some(Cond::Eq));
        assert_eq!(t3.encoding, "T3");
        assert_eq!(t3.branch_target(), Some(0x1004 + 0x1000));
        assert_eq!(t3.to_string(), "beq.w 0x2004");

        // T4: I1 = NOT(0 EOR 0) = 1, I2 = 1, so
        // S:I1:I2:imm10:imm11:'0' = 0:1:1:0000000001:00000000000:0 = 0xC01000.
        assert_eq!(t4.cond, None);
        assert_eq!(t4.encoding, "T4");
        assert_eq!(t4.branch_target(), Some(0x1004 + 0xC0_1000));
        assert_eq!(t4.to_string(), "b.w 0xc02004");

        // The bug this test exists for: reading T3 with the T4 rule.
        assert_ne!(t3.branch_target(), t4.branch_target());
        assert_ne!(t3.branch_target(), Some(0x1004 + 0xC0_1000));
    }

    #[test]
    fn hand_computed_range_vectors() {
        // Ranges from A7-206: T3 is -1048576..=1048574, T4 -16777216..=16777214;
        // `BLX` T2 is -16777216..=16777212 in multiples of four (A8-59).
        let site = 0x0200_0000u32;
        let pc = site + 4;

        // --- B<cond>.W T3, ±1 MB.
        // Max forward: imm = 0x7FFFF, S = 0, J2 = J1 = 1, imm6 = 0x3F,
        // imm11 = 0x7FF -> hw1 = 0xF03F (cond = eq), hw2 = 0xAFFF.
        let fwd = round_trip(0xF03F, 0xAFFF, site);
        assert_eq!(fwd.branch_target(), Some(pc + 1_048_574));
        // Max backward: S = 1, everything else zero.
        let back = round_trip(0xF400, 0x8000, site);
        assert_eq!(back.branch_target(), Some(pc - 1_048_576));
        // One past either end must fail to encode, not wrap.
        let mut over = fwd;
        over.operands = one(Operand::Target(pc + 1_048_576));
        assert_eq!(encode(&over), None);
        let mut under = back;
        under.operands = one(Operand::Target(pc - 1_048_578));
        assert_eq!(encode(&under), None);
        // And an odd displacement is not encodable at all.
        let mut odd = fwd;
        odd.operands = one(Operand::Target(pc + 3));
        assert_eq!(encode(&odd), None);

        // --- B.W T4 and BL T1, ±16 MB.
        for (base, mnemonic) in [(0x9000u16, "b"), (0xD000, "bl")] {
            // Max forward: S = 0, imm10 = 0x3FF, imm11 = 0x7FF, I1 = I2 = 1 so
            // J1 = J2 = 0 -> hw1 = 0xF3FF, hw2 = base | 0x7FF.
            let fwd = round_trip(0xF3FF, base | 0x7FF, site);
            assert_eq!(fwd.mnemonic, mnemonic);
            assert_eq!(fwd.branch_target(), Some(pc + 16_777_214));
            // Max backward: S = 1, I1 = I2 = 0 so J1 = J2 = 0.
            let back = round_trip(0xF400, base, site);
            assert_eq!(back.branch_target(), Some(pc - 16_777_216));

            let mut over = fwd;
            over.operands = one(Operand::Target(pc + 16_777_216));
            assert_eq!(encode(&over), None);
            let mut under = back;
            under.operands = one(Operand::Target(pc - 16_777_218));
            assert_eq!(encode(&under), None);
        }

        // --- BLX T2, ±16 MB in multiples of four, from Align(PC,4).
        // Max forward: imm10L = 0x3FF so hw2 = 0xC000 | 0x7FE.
        let fwd = round_trip(0xF3FF, 0xC7FE, site);
        assert_eq!(fwd.branch_target(), Some((pc & !3) + 16_777_212));
        let back = round_trip(0xF400, 0xC000, site);
        assert_eq!(back.branch_target(), Some((pc & !3) - 16_777_216));
        let mut over = fwd;
        over.operands = one(Operand::Target((pc & !3) + 16_777_216));
        assert_eq!(encode(&over), None);
        let mut misaligned = fwd;
        misaligned.operands = one(Operand::Target((pc & !3) + 2));
        assert_eq!(encode(&misaligned), None);
    }

    #[test]
    fn blx_branches_from_the_word_aligned_pc() {
        // At a site that is 2 mod 4 the pc rounds *down*, so the same
        // immediate reaches two bytes lower than `BL` would.
        // `J1 = J2 = 1` with `S = 0` is the zero displacement — `I1 = I2 = 0`.
        let insn = round_trip(0xF000, 0xE800, 0x1002);
        assert_eq!(insn.branch_target(), Some(0x1004));
        assert_eq!(
            decode(0xF000, 0xF800, 0x1002).unwrap().branch_target(),
            Some(0x1006)
        );
        // `hw2` bit 0 set is not a `BLX`: it would name an odd ARM target.
        assert!(decode(0xF000, 0xC001, 0).is_none());
        assert!(decode(0xF3FF, 0xC7FF, 0).is_none());
    }

    #[test]
    fn systematic_sweep_round_trips() {
        // Exhaustive over 2^27 is not feasible, so: every `op` value, four
        // `Rn`/`imm4` values, every `op1`, and `hw2` low halves chosen to hit
        // both immediate extremes and every control encoding.
        let hw2_low: [u16; 26] = [
            0x000, 0x001, 0x002, 0x003, 0x004, 0x014, 0x0F0, 0x0FF, 0x110, 0x400, 0x460, 0x500,
            0x793, 0x7FE, 0x7FF, 0x800, 0x810, 0x8FF, 0xA34, 0xF00, 0xF0F, 0xF1F, 0xF2F, 0xF40,
            0xF4B, 0xFFF,
        ];
        let mut decoded = 0usize;
        for addr in [0u32, 0x0800_1234, 0xFFFF_FFF0] {
            for op in 0..128u16 {
                for rn in [0u16, 1, 0xE, 0xF] {
                    let hw1 = 0xF000 | (op << 4) | rn;
                    for op1 in 0..8u16 {
                        for low in hw2_low {
                            let hw2 = 0x8000 | (op1 << 12) | low;
                            if let Some(insn) = decode(hw1, hw2, addr) {
                                decoded += 1;
                                assert_eq!(insn.width, Width::Wide);
                                assert_eq!(insn.len(), 4);
                                assert_eq!(
                                    encode(&insn),
                                    Some((hw1, hw2)),
                                    "round-trip of {hw1:#06x} {hw2:#06x} at {addr:#x} ({insn})"
                                );
                            }
                        }
                    }
                }
            }
        }
        assert!(decoded > 30_000, "sweep decoded only {decoded} encodings");
    }

    #[test]
    fn branch_j_bit_sweep_round_trips() {
        // Every S/J1/J2 combination against boundary immediates, for all four
        // branch forms, at an address where the BLX pc-alignment matters.
        for addr in [0x1000u32, 0x1002] {
            for s in 0..2u16 {
                for j1 in 0..2u16 {
                    for j2 in 0..2u16 {
                        for hi in [0u16, 1, 0x20, 0x3E, 0x3F] {
                            for lo in [0u16, 1, 2, 0x7FE, 0x7FF] {
                                for base in [0x8000u16, 0x9000, 0xC000, 0xD000] {
                                    let hw1 = 0xF000 | (s << 10) | hi;
                                    let hw2 = base | (j1 << 13) | (j2 << 11) | lo;
                                    if decode(hw1, hw2, addr).is_some() {
                                        round_trip(hw1, hw2, addr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn branch_predicates_are_right_for_each_form() {
        let b_cond = decode(0xF100, 0x8000, 0x1000).unwrap(); // bmi.w, imm = 0
        let b_wide = decode(0xF000, 0x9000, 0x1000).unwrap();
        let bl = decode(0xF000, 0xD000, 0x1000).unwrap();
        let blx = decode(0xF000, 0xC000, 0x1000).unwrap();

        for insn in [b_cond, b_wide, bl, blx] {
            assert!(insn.is_branch(), "{insn}");
            assert!(insn.branch_target().is_some(), "{insn}");
        }
        assert!(!b_cond.is_call());
        assert!(!b_wide.is_call());
        assert!(bl.is_call());
        assert!(blx.is_call());
        assert_eq!(b_cond.branch_target(), Some(0x1004));
        assert_eq!(b_wide.branch_target(), Some(0x1004 + 0xC0_0000));
        assert_eq!(bl.branch_target(), Some(0x1004 + 0xC0_0000));
        assert_eq!(blx.branch_target(), Some(0x1004 + 0xC0_0000));

        // `BXJ` and the exception return branch, but nowhere statically known.
        let bxj = decode(0xF3C5, 0x8F00, 0).unwrap();
        assert!(bxj.is_branch() && !bxj.is_call() && bxj.branch_target().is_none());
        let eret = decode(0xF3DE, 0x8F00, 0).unwrap();
        assert!(eret.is_branch() && !eret.is_call() && eret.branch_target().is_none());

        // Nothing else in the group is a branch.
        for (hw1, hw2) in [
            (0xF3AFu16, 0x8000u16), // nop.w
            (0xF3BF, 0x8F4F),       // dsb sy
            (0xF380, 0x8810),       // msr PRIMASK, r0
            (0xF3EF, 0x8010),       // mrs r0, PRIMASK
            (0xF7F0, 0xA000),       // udf.w #0
            (0xF7F0, 0x8000),       // smc #0
        ] {
            let insn = decode(hw1, hw2, 0).unwrap();
            assert!(!insn.is_branch(), "{insn}");
            assert!(!insn.is_call(), "{insn}");
        }
    }

    #[test]
    fn conditional_branch_carries_its_condition_in_the_field() {
        for bits in 0..14u16 {
            let insn = round_trip(0xF000 | (bits << 6), 0x8000, 0);
            assert_eq!(insn.cond, Cond::from_bits(bits as u8));
            assert_eq!(insn.mnemonic, "b", "the condition is not in the mnemonic");
        }
        assert_eq!(ual(0xF000, 0x8000), "beq.w 0x4");
        assert_eq!(ual(0xF2C0, 0x8000), "blt.w 0x4");
        // `cond<3:1> == 111` is a different instruction class, not `b.w`.
        assert_ne!(decode(0xF380, 0x8000, 0).map(|i| i.mnemonic), Some("b"));
        assert_ne!(decode(0xF3C0, 0x8000, 0).map(|i| i.mnemonic), Some("b"));
    }

    #[test]
    fn msr_and_mrs_name_both_profiles_registers() {
        // M profile, Table B5-1 / B5-2 (`spec/ARMv7-M.txt` B5-670).
        assert_eq!(ual(0xF383, 0x8810), "msr PRIMASK, r3");
        assert_eq!(ual(0xF381, 0x8811), "msr BASEPRI, r1");
        assert_eq!(ual(0xF380, 0x8814), "msr CONTROL, r0");
        assert_eq!(ual(0xF385, 0x8808), "msr MSP, r5");
        assert_eq!(ual(0xF380, 0x8800), "msr APSR_nzcvq, r0");
        assert_eq!(ual(0xF380, 0x8400), "msr APSR_g, r0");
        assert_eq!(ual(0xF380, 0x8C00), "msr APSR_nzcvqg, r0");
        assert_eq!(ual(0xF382, 0x8C03), "msr XPSR_nzcvqg, r2");
        assert_eq!(ual(0xF3EF, 0x8010), "mrs r0, PRIMASK");
        assert_eq!(ual(0xF3EF, 0x8100), "mrs r1, APSR");
        assert_eq!(ual(0xF3EF, 0x8512), "mrs r5, BASEPRI_MAX");

        // Table B5-1 entire, in both directions: every `SYSm` the M profile
        // allocates, and — for the four xPSR composites — every `mask` that
        // carries a `_<bits>` qualifier (Table B5-2). Exhaustive rather than
        // representative, because a row that is missing here is an `MSR`/`MRS`
        // a firmware disassembly drops on the floor instead of naming, and
        // one that [`encode`] could never put back.
        #[rustfmt::skip]
        let m_profile: [(u16, u16, &str); 36] = [
            (0xF380, 0x8400, "msr APSR_g, r0"),
            (0xF380, 0x8800, "msr APSR_nzcvq, r0"),
            (0xF380, 0x8C00, "msr APSR_nzcvqg, r0"),
            (0xF380, 0x8401, "msr IAPSR_g, r0"),
            (0xF380, 0x8801, "msr IAPSR_nzcvq, r0"),
            (0xF380, 0x8C01, "msr IAPSR_nzcvqg, r0"),
            (0xF380, 0x8402, "msr EAPSR_g, r0"),
            (0xF380, 0x8802, "msr EAPSR_nzcvq, r0"),
            (0xF380, 0x8C02, "msr EAPSR_nzcvqg, r0"),
            (0xF380, 0x8403, "msr XPSR_g, r0"),
            (0xF380, 0x8803, "msr XPSR_nzcvq, r0"),
            (0xF380, 0x8C03, "msr XPSR_nzcvqg, r0"),
            (0xF380, 0x8805, "msr IPSR, r0"),
            (0xF380, 0x8806, "msr EPSR, r0"),
            (0xF380, 0x8807, "msr IEPSR, r0"),
            (0xF380, 0x8808, "msr MSP, r0"),
            (0xF380, 0x8809, "msr PSP, r0"),
            (0xF380, 0x8810, "msr PRIMASK, r0"),
            (0xF380, 0x8811, "msr BASEPRI, r0"),
            (0xF380, 0x8812, "msr BASEPRI_MAX, r0"),
            (0xF380, 0x8813, "msr FAULTMASK, r0"),
            (0xF380, 0x8814, "msr CONTROL, r0"),
            (0xF3EF, 0x8000, "mrs r0, APSR"),
            (0xF3EF, 0x8001, "mrs r0, IAPSR"),
            (0xF3EF, 0x8002, "mrs r0, EAPSR"),
            (0xF3EF, 0x8003, "mrs r0, XPSR"),
            (0xF3EF, 0x8005, "mrs r0, IPSR"),
            (0xF3EF, 0x8006, "mrs r0, EPSR"),
            (0xF3EF, 0x8007, "mrs r0, IEPSR"),
            (0xF3EF, 0x8008, "mrs r0, MSP"),
            (0xF3EF, 0x8009, "mrs r0, PSP"),
            (0xF3EF, 0x8010, "mrs r0, PRIMASK"),
            (0xF3EF, 0x8011, "mrs r0, BASEPRI"),
            (0xF3EF, 0x8012, "mrs r0, BASEPRI_MAX"),
            (0xF3EF, 0x8013, "mrs r0, FAULTMASK"),
            (0xF3EF, 0x8014, "mrs r0, CONTROL"),
        ];
        for (hw1, hw2, text) in m_profile {
            assert_eq!(round_trip(hw1, hw2, 0).to_string(), text);
        }

        // A/R, B6.1.7 — `<fields>` is any subset of `c`, `x`, `s`, `f`.
        assert_eq!(ual(0xF380, 0x8900), "msr CPSR_fc, r0", "mask 1001");
        assert_eq!(ual(0xF384, 0x8F00), "msr CPSR_fsxc, r4");
        assert_eq!(ual(0xF390, 0x8F00), "msr SPSR_fsxc, r0");
        assert_eq!(ual(0xF394, 0x8100), "msr SPSR_c, r4");
        assert_eq!(ual(0xF3FF, 0x8200), "mrs r2, SPSR");

        // Undecodable overlays: an M-profile `SYSm` with A/R's low mask bits
        // set is neither profile's instruction, and `mask == 0` is
        // UNPREDICTABLE in both.
        assert!(decode(0xF380, 0x8B10, 0).is_none());
        assert!(decode(0xF380, 0x8000, 0).is_none());
        // `SYSm` values Table B5-1 does not allocate.
        assert!(decode(0xF380, 0x8804, 0).is_none());
        assert!(decode(0xF3EF, 0x8015, 0).is_none());
        // `MSR` to a non-xPSR register with `mask != 0b10` is UNPREDICTABLE.
        assert!(decode(0xF380, 0x8410, 0).is_none());
    }

    #[test]
    fn hints_print_with_their_width_suffix() {
        // A5.3.4 Table A5-14, and the `NOP<c>.W` syntax lines: a bare `nop`
        // is the 16-bit T1, so the suffix is what round-trips.
        assert_eq!(ual(0xF3AF, 0x8000), "nop.w");
        assert_eq!(ual(0xF3AF, 0x8001), "yield.w");
        assert_eq!(ual(0xF3AF, 0x8002), "wfe.w");
        assert_eq!(ual(0xF3AF, 0x8003), "wfi.w");
        assert_eq!(ual(0xF3AF, 0x8004), "sev.w");
        assert_eq!(ual(0xF3AF, 0x8014), "csdb.w");
        assert_eq!(ual(0xF3AF, 0x80F0), "dbg #0");
        assert_eq!(ual(0xF3AF, 0x80FF), "dbg #0xf");
        // Which architectural encoding each hint *is* — not decoration, and
        // not derivable from the printed form. The five NOP-compatible hints
        // have a 16-bit T1 to be told apart from, so their wide form is T2
        // (A7.7.88); `CSDB` has no 16-bit encoding at all, so its wide form
        // is T1 (A7.7.31). Naming them alike, or swapping the two, would let
        // `encode` accept an `Insn` this module never decoded.
        assert_eq!(dec(0xF3AF, 0x8000, 0).encoding, "T2", "nop.w");
        assert_eq!(dec(0xF3AF, 0x8004, 0).encoding, "T2", "sev.w");
        assert_eq!(dec(0xF3AF, 0x8014, 0).encoding, "T1", "csdb.w");
        assert_eq!(dec(0xF3AF, 0x80F0, 0).encoding, "T1", "dbg #0");
        for (hw1, hw2) in [
            (0xF3AFu16, 0x8000u16),
            (0xF3AF, 0x8004),
            (0xF3AF, 0x8014),
            (0xF3AF, 0x80F5),
        ] {
            round_trip(hw1, hw2, 0);
        }
        // Unallocated hints execute as NOP but are reserved; printing them as
        // `nop.w` would lose `op2`.
        assert!(decode(0xF3AF, 0x8005, 0).is_none());
        assert!(decode(0xF3AF, 0x8013, 0).is_none());
        // `hw1[3:0]` is `(1111)`: anything else is UNPREDICTABLE.
        assert!(decode(0xF3AE, 0x8000, 0).is_none());
    }

    #[test]
    fn misc_control_prints_named_barrier_options() {
        // Table A5-15, and the `<opt>` values from A8.6.41/A8.6.42.
        assert_eq!(ual(0xF3BF, 0x8F2F), "clrex");
        assert_eq!(ual(0xF3BF, 0x8F4F), "dsb sy");
        assert_eq!(ual(0xF3BF, 0x8F4E), "dsb st");
        assert_eq!(ual(0xF3BF, 0x8F4B), "dsb ish");
        assert_eq!(ual(0xF3BF, 0x8F4A), "dsb ishst");
        assert_eq!(ual(0xF3BF, 0x8F47), "dsb nsh");
        assert_eq!(ual(0xF3BF, 0x8F46), "dsb nshst");
        assert_eq!(ual(0xF3BF, 0x8F43), "dsb osh");
        assert_eq!(ual(0xF3BF, 0x8F42), "dsb oshst");
        assert_eq!(ual(0xF3BF, 0x8F49), "dsb #9", "reserved option, no name");
        assert_eq!(ual(0xF3BF, 0x8F5F), "dmb sy");
        assert_eq!(ual(0xF3BF, 0x8F52), "dmb oshst");
        assert_eq!(ual(0xF3BF, 0x8F6F), "isb sy");
        assert_eq!(ual(0xF3BF, 0x8F60), "isb #0");
        // Armv7-M's two named `DSB` options (Table A5-15).
        assert_eq!(ual(0xF3BF, 0x8F40), "ssbb");
        assert_eq!(ual(0xF3BF, 0x8F44), "pssbb");
        // ThumbEE state changes (A9.3.1), A/R only.
        assert_eq!(ual(0xF3BF, 0x8F0F), "leavex");
        assert_eq!(ual(0xF3BF, 0x8F1F), "enterx");

        for option in 0..16u16 {
            for opc in [0x0u16, 0x1, 0x2, 0x4, 0x5, 0x6] {
                let hw2 = 0x8F00 | (opc << 4) | option;
                if decode(0xF3BF, hw2, 0).is_some() {
                    round_trip(0xF3BF, hw2, 0);
                }
            }
        }
        // `opc` values Table A5-15 does not allocate, and a `CLREX` whose
        // `(1111)` option bits are not all ones.
        assert!(decode(0xF3BF, 0x8F30, 0).is_none());
        assert!(decode(0xF3BF, 0x8F2E, 0).is_none());
    }

    #[test]
    fn a_profile_only_control_encodings() {
        assert_eq!(ual(0xF3C5, 0x8F00), "bxj r5");
        assert_eq!(ual(0xF3DE, 0x8F00), "subs pc, lr, #0");
        assert_eq!(ual(0xF3DE, 0x8F04), "subs pc, lr, #4");
        assert_eq!(ual(0xF3DE, 0x8F10), "subs pc, lr, #0x10");
        assert_eq!(ual(0xF7F5, 0x8000), "smc #5");
        assert_eq!(ual(0xF7FF, 0x8000), "smc #0xf");
        // 32-bit CPS (B6.1.1 encoding T2).
        assert_eq!(ual(0xF3AF, 0x8460), "cpsie.w if");
        assert_eq!(ual(0xF3AF, 0x8680), "cpsid.w a");
        assert_eq!(ual(0xF3AF, 0x8793), "cpsid.w a, #0x13");
        assert_eq!(ual(0xF3AF, 0x8110), "cps #0x10");
        for hw2 in [0x8460u16, 0x8680, 0x8793, 0x8110, 0x85E0, 0x87E3] {
            round_trip(0xF3AF, hw2, 0);
        }
        // `imod == 01` is UNPREDICTABLE; an effect with no flags has no
        // syntax; `CPS #<mode>` changes no flag.
        assert!(decode(0xF3AF, 0x8260, 0).is_none());
        assert!(decode(0xF3AF, 0x8400, 0).is_none());
        assert!(decode(0xF3AF, 0x8160, 0).is_none());
        // Each of `A`, `I` and `F` on its own, not only two at a time: the
        // `CPS #<mode>` syntax line has nowhere to print an interrupt flag,
        // so one set bit is already an encoding that cannot round-trip —
        // decoding it would print `cps #0x10` and throw the flag away.
        assert!(decode(0xF3AF, 0x8190, 0).is_none(), "A set");
        assert!(decode(0xF3AF, 0x8150, 0).is_none(), "I set");
        assert!(decode(0xF3AF, 0x8130, 0).is_none(), "F set");
        // `BXJ`/`SUBS PC,LR` have fixed bits that must hold.
        assert!(decode(0xF3C5, 0x8F01, 0).is_none());
        assert!(decode(0xF3DD, 0x8F00, 0).is_none());
        assert!(decode(0xF7F5, 0x8001, 0).is_none());
    }

    #[test]
    fn udf_wide_decodes_and_keeps_its_immediate() {
        assert_eq!(ual(0xF7F1, 0xA234), "udf.w #0x1234");
        assert_eq!(ual(0xF7F0, 0xA000), "udf.w #0");
        assert_eq!(ual(0xF7FF, 0xAFFF), "udf.w #0xffff");
        round_trip(0xF7F1, 0xA234, 0);
        round_trip(0xF7FF, 0xAFFF, 0);
        // `SMC` and `UDF.W` share `hw1`; only `hw2[13]` tells them apart.
        assert_eq!(decode(0xF7F1, 0x8000, 0).unwrap().mnemonic, "smc");
        assert_eq!(decode(0xF7F1, 0xA000, 0).unwrap().mnemonic, "udf");
    }

    #[test]
    fn outside_the_group_is_not_ours() {
        // `hw1[15:11] != 0b11110`.
        assert!(decode(0xE800, 0x8000, 0).is_none());
        assert!(decode(0xF800, 0x8000, 0).is_none());
        // `hw2[15] == 0` is the data-processing half of `op1 == 10`.
        assert!(decode(0xF000, 0x0000, 0).is_none());
        // `op1 == 010` with a control `op` puts a 1 in a should-be-zero bit.
        assert!(decode(0xF3AF, 0xA000, 0).is_none());
        assert!(decode(0xF3BF, 0xAF4F, 0).is_none());
    }

    #[test]
    fn encode_rejects_what_this_group_cannot_hold() {
        let bl = decode(0xF000, 0xD000, 0x1000).unwrap();

        // A mnemonic from another group, and the same mnemonic under another
        // encoding name.
        let mut foreign = bl;
        foreign.mnemonic = "add";
        assert_eq!(encode(&foreign), None);
        let mut renamed = bl;
        renamed.encoding = "T2";
        assert_eq!(encode(&renamed), None);

        // The hints are named the same way. `CSDB` has no 16-bit form, so its
        // wide encoding is T1 where the five NOP-compatible hints are T2
        // (A7.7.31, A7.7.88) — and the pairing is part of the identity, not a
        // label: a `nop` claiming T1 is an encoding this module never decoded,
        // and re-encoding it would emit `0xF3AF 0x8000`, which is `nop.w` T2.
        let mut nop_as_t1 = decode(0xF3AF, 0x8000, 0).unwrap();
        nop_as_t1.encoding = "T1";
        assert_eq!(encode(&nop_as_t1), None);
        let mut csdb_as_t2 = decode(0xF3AF, 0x8014, 0).unwrap();
        csdb_as_t2.encoding = "T2";
        assert_eq!(encode(&csdb_as_t2), None);

        // The narrow encodings of `b` and `nop` belong to other modules.
        let mut narrow = bl;
        narrow.width = Width::Narrow;
        assert_eq!(encode(&narrow), None);
        let mut narrow_nop = decode(0xF3AF, 0x8000, 0).unwrap();
        narrow_nop.width = Width::Narrow;
        assert_eq!(encode(&narrow_nop), None);

        // Width suffixes that do not match the decoded form.
        let mut suffixed = bl;
        suffixed.explicit_width = true;
        assert_eq!(encode(&suffixed), None);
        let mut unsuffixed = decode(0xF000, 0x9000, 0).unwrap();
        unsuffixed.explicit_width = false;
        assert_eq!(encode(&unsuffixed), None);

        // Nothing here sets flags except `SUBS PC, LR`.
        let mut flagged = bl;
        flagged.sets_flags = true;
        assert_eq!(encode(&flagged), None);
        let mut unflagged = decode(0xF3DE, 0x8F00, 0).unwrap();
        unflagged.sets_flags = false;
        assert_eq!(encode(&unflagged), None);

        // `B<cond>.W` needs a condition, and `AL` is not one it can hold.
        let mut uncond = decode(0xF000, 0x8000, 0).unwrap();
        uncond.cond = None;
        assert_eq!(encode(&uncond), None);
        let mut always = decode(0xF000, 0x8000, 0).unwrap();
        always.cond = Some(Cond::Al);
        assert_eq!(encode(&always), None);

        // Wrong operand shapes.
        let mut wrong_kind = bl;
        wrong_kind.operands = one(Operand::Imm(4));
        assert_eq!(encode(&wrong_kind), None);
        let mut too_many = bl;
        too_many.operands = [Operand::Target(0x2000), Operand::Imm(0)]
            .into_iter()
            .collect();
        assert_eq!(encode(&too_many), None);
        let mut unknown_reg = decode(0xF380, 0x8810, 0).unwrap();
        unknown_reg.operands = [Operand::SpecialReg("MECR"), Operand::Reg(Reg(0))]
            .into_iter()
            .collect();
        assert_eq!(encode(&unknown_reg), None);
        let mut bad_option = decode(0xF3BF, 0x8F4F, 0).unwrap();
        bad_option.operands = one(Operand::Option("full"));
        assert_eq!(encode(&bad_option), None);

        // Immediates out of their field's range.
        let mut big_udf = decode(0xF7F0, 0xA000, 0).unwrap();
        big_udf.operands = one(Operand::Imm(0x1_0000));
        assert_eq!(encode(&big_udf), None);
        let mut big_smc = decode(0xF7F0, 0x8000, 0).unwrap();
        big_smc.operands = one(Operand::Imm(16));
        assert_eq!(encode(&big_smc), None);
        let mut big_eret = decode(0xF3DE, 0x8F00, 0).unwrap();
        big_eret.operands = [
            Operand::Reg(Reg::PC),
            Operand::Reg(Reg::LR),
            Operand::Imm(256),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&big_eret), None);

        // `dsb #0`/`dsb #4` are `SSBB`/`PSSBB`, so they must not re-encode as
        // a `DSB` that would decode back under a different mnemonic.
        let mut ssbb_as_dsb = decode(0xF3BF, 0x8F4F, 0).unwrap();
        ssbb_as_dsb.operands = one(Operand::Imm(0));
        assert_eq!(encode(&ssbb_as_dsb), None);
        // Both of them, not just `#0`: `dsb #4` would emit `0xF3BF 0x8F44`,
        // which Table A5-15 reads back as `pssbb`.
        let mut pssbb_as_dsb = decode(0xF3BF, 0x8F4F, 0).unwrap();
        pssbb_as_dsb.operands = one(Operand::Imm(4));
        assert_eq!(encode(&pssbb_as_dsb), None);
    }

    #[test]
    fn encode_refuses_every_operand_shape_decode_cannot_produce() {
        // `encode` is the exact inverse of `decode`, so it has to refuse an
        // operand list `decode` never builds rather than assemble something
        // plausible out of the fields it does recognise: a re-encode that
        // "fixes up" a malformed operand writes an instruction the caller did
        // not ask for, into firmware. Each row is a real instruction of this
        // group whose operands have been replaced with a shape the manual's
        // syntax line has nowhere to put.
        let reg = Operand::Reg(Reg(0));
        let imm = Operand::Imm(0);
        let neg = Operand::Imm(-1);
        let pc = Operand::Reg(Reg::PC);
        let lr = Operand::Reg(Reg::LR);
        let primask = Operand::SpecialReg("PRIMASK");
        let cases: [(u16, u16, &[Operand], &str); 25] = [
            // `UDF<c>.W #<imm16>` (A7.7.194) — exactly one immediate.
            (0xF7F0, 0xA000, &[imm, imm], "udf.w takes one immediate"),
            // Every immediate field in this group is unsigned in its own
            // syntax line, and [`Operand::Imm`] is signed, so the low end of
            // each range is load-bearing: `-1` narrowed to the field width is
            // all ones, which would silently assemble `udf.w #-1` as
            // `udf.w #0xffff`, `smc #-1` as `smc #0xf` and `dbg #-1` as
            // `dbg #0xf` — a different instruction with a valid-looking
            // encoding.
            (0xF7F0, 0xA000, &[neg], "udf.w's #<imm16> is unsigned"),
            // `SMC{<c>}{<q>} #<imm4>` (B6.1.9).
            (0xF7F0, 0x8000, &[], "smc takes one immediate"),
            (0xF7F0, 0x8000, &[imm, imm], "smc takes one, not two"),
            (0xF7F0, 0x8000, &[neg], "smc's #<imm4> is unsigned"),
            // `MSR<c> <spec_reg>, <Rn>` (A7.7.83, B6.1.7).
            (0xF383, 0x8810, &[primask], "msr takes two operands"),
            (0xF383, 0x8810, &[reg, reg], "msr writes a special register"),
            (0xF383, 0x8810, &[primask, imm], "msr reads a core register"),
            (
                0xF383,
                0x8810,
                &[primask, reg, imm],
                "msr takes two operands",
            ),
            (
                0xF383,
                0x8810,
                &[Operand::SpecialReg("MECR"), reg],
                "no SYSm/mask spells MECR",
            ),
            // `MRS<c> <Rd>, <spec_reg>` (A7.7.82, B6.1.5).
            (
                0xF3EF,
                0x8010,
                &[reg, primask, imm],
                "mrs takes two operands",
            ),
            (
                0xF3EF,
                0x8010,
                &[primask, primask],
                "mrs writes a core register",
            ),
            (0xF3EF, 0x8010, &[reg, reg], "mrs reads a special register"),
            (
                0xF3EF,
                0x8010,
                &[reg, Operand::SpecialReg("MECR")],
                "no SYSm spells MECR",
            ),
            // `BXJ<c> <Rm>` (A8.6.26).
            (0xF3C5, 0x8F00, &[], "bxj takes one register"),
            (0xF3C5, 0x8F00, &[reg, reg], "bxj takes one, not two"),
            (0xF3C5, 0x8F00, &[imm], "bxj branches to a register"),
            // `SUBS<c><q> PC, LR, #<const>` (B6.1.13) — and nothing else that
            // happens to be spelled `sub` and to set flags.
            (0xF3DE, 0x8F04, &[reg, lr, imm], "the destination is pc"),
            (0xF3DE, 0x8F04, &[pc, reg, imm], "the source is lr"),
            (
                0xF3DE,
                0x8F04,
                &[pc, lr, imm, imm],
                "subs pc, lr takes three, not four",
            ),
            (0xF3DE, 0x8F04, &[pc, lr, neg], "the #<const> is unsigned"),
            // `DBG<c> #<option>` (A7.7.32) — one four-bit immediate.
            (0xF3AF, 0x80F0, &[], "dbg takes one immediate"),
            (0xF3AF, 0x80F0, &[imm, imm], "dbg takes one, not two"),
            (
                0xF3AF,
                0x80F0,
                &[Operand::Imm(16)],
                "dbg's option is four bits",
            ),
            (0xF3AF, 0x80F0, &[neg], "dbg's option is unsigned"),
        ];
        for (hw1, hw2, operands, why) in cases {
            let insn = with_operands(hw1, hw2, operands);
            assert_eq!(encode(&insn), None, "{why} ({hw1:#06x} {hw2:#06x})");
        }

        // `B<cond>.W` is the only branch here whose target is not reachable
        // through `encode_branch`, so its operand check needs its own case.
        let beq = with_operands(0xF000, 0x8000, &[imm]);
        assert_eq!(encode(&beq), None, "b<cond>.w branches to a target");
        // A *surplus* operand is the only way to reach that length check —
        // with too few, the slot read refuses first — and `beq.w 0x4, #0` is
        // not a syntax line: encoding it would drop the second operand and
        // write a branch the caller never asked for.
        let beq_plus = with_operands(0xF000, 0x8000, &[Operand::Target(4), imm]);
        assert_eq!(encode(&beq_plus), None, "b<cond>.w takes one target");

        // The `.w` suffix is part of the syntax line, not decoration: `NOP.W`
        // (A7.7.88) and `UDF.W` (A7.7.194) print it because their 16-bit
        // encodings would otherwise win, and `SMC`, `BXJ`, `CLREX`, `SSBB`,
        // `DSB` and `CPS #<mode>` have no wide form to distinguish. Flipping it
        // therefore names an instruction that is not this one.
        for (hw1, hw2, suffixed) in [
            (0xF7F0u16, 0x8000u16, false), // smc #0
            (0xF3C5, 0x8F00, false),       // bxj r5
            (0xF3BF, 0x8F2F, false),       // clrex
            (0xF3BF, 0x8F40, false),       // ssbb
            (0xF3BF, 0x8F4F, false),       // dsb sy
            (0xF3AF, 0x8110, false),       // cps #0x10
            (0xF7F0, 0xA000, true),        // udf.w #0
            (0xF3AF, 0x8000, true),        // nop.w
            (0xF3AF, 0x8014, true),        // csdb.w
            (0xF000, 0x8000, true),        // beq.w
            (0xF3AF, 0x8680, true),        // cpsid.w a
        ] {
            let mut flipped = dec(hw1, hw2, 0);
            assert_eq!(
                flipped.explicit_width, suffixed,
                "{hw1:#06x} {hw2:#06x} decoded with the wrong width suffix"
            );
            flipped.explicit_width = !suffixed;
            assert_eq!(encode(&flipped), None, "{hw1:#06x} {hw2:#06x}");
        }

        // `SUBS PC, LR` is the only encoding in the group that sets flags
        // (it restores `CPSR` from `SPSR`). A stray `sets_flags` anywhere else
        // would print `smcs`, `mrss`, `nops.w` — so it must not re-encode.
        for (hw1, hw2) in [
            (0xF7F0u16, 0x8000u16), // smc #0
            (0xF383, 0x8810),       // msr PRIMASK, r3
            (0xF3EF, 0x8010),       // mrs r0, PRIMASK
            (0xF3C5, 0x8F00),       // bxj r5
            (0xF3AF, 0x80F0),       // dbg #0
            (0xF3AF, 0x8000),       // nop.w
            (0xF3BF, 0x8F2F),       // clrex
            (0xF3BF, 0x8F40),       // ssbb
            (0xF3BF, 0x8F4F),       // dsb sy
            (0xF7F0, 0xA000),       // udf.w #0
            (0xF3AF, 0x8110),       // cps #0x10
            (0xF000, 0x8000),       // beq.w
        ] {
            let mut flagged = dec(hw1, hw2, 0);
            assert!(!flagged.sets_flags, "{hw1:#06x} {hw2:#06x}");
            flagged.sets_flags = true;
            assert_eq!(encode(&flagged), None, "{hw1:#06x} {hw2:#06x}");
        }

        // The hints and the barrier-like encodings take no operands at all.
        for (hw1, hw2) in [
            (0xF3AFu16, 0x8000u16), // nop.w
            (0xF3BF, 0x8F2F),       // clrex
            (0xF3BF, 0x8F40),       // ssbb
        ] {
            let extra = with_operands(hw1, hw2, &[imm]);
            assert_eq!(
                encode(&extra),
                None,
                "{hw1:#06x} {hw2:#06x} has no operands"
            );
        }
        // …and `DSB`/`DMB`/`ISB` take exactly one.
        let bare_dsb = with_operands(0xF3BF, 0x8F4F, &[]);
        assert_eq!(encode(&bare_dsb), None, "dsb takes one <option>");
        let sy = Operand::Option("sy");
        let wordy_dsb = with_operands(0xF3BF, 0x8F4F, &[sy, sy]);
        assert_eq!(encode(&wordy_dsb), None, "dsb takes one <option>, not two");
    }

    #[test]
    fn cps_holds_only_the_three_syntactic_forms_b6_1_1_defines() {
        // B6.1.1 gives `CPS #<mode>`, `CPSIE.W <iflags>{, #<mode>}` and
        // `CPSID.W <iflags>{, #<mode>}`, and the encoding has room for nothing
        // else: `imod`, `M` and the interrupt flags are not independent.

        // `M == 0` leaves `mode` with no syntax to print it in, so a non-zero
        // `mode` field is not a `CPSIE`/`CPSID` at all — decoding it would
        // silently drop five bits that `encode` could never put back.
        // `imod = 10, M = 0, A = 0, I = F = 1, mode = 00001`.
        assert!(decode(0xF3AF, 0x8461, 0).is_none());
        // The same encoding with `mode == 0` is an ordinary `cpsie.w if`, and
        // with `M == 1` the mode has somewhere to go.
        assert_eq!(ual(0xF3AF, 0x8460), "cpsie.w if");
        assert_eq!(ual(0xF3AF, 0x8561), "cpsie.w if, #1");

        let a = Operand::Text("a");
        let cases: [(u16, &[Operand], &str); 9] = [
            // `CPS #<mode>` — exactly one immediate, five bits wide.
            (0x8110, &[], "cps takes one mode"),
            (
                0x8110,
                &[Operand::Imm(0x10), Operand::Imm(0)],
                "cps takes one mode",
            ),
            (0x8110, &[a], "cps' mode is an immediate"),
            (0x8110, &[Operand::Imm(0x20)], "mode is five bits"),
            (0x8110, &[Operand::Imm(-1)], "mode is unsigned"),
            // `CPSIE`/`CPSID` — an `<iflags>` spelling, then an optional mode.
            (0x8680, &[Operand::Imm(0)], "the first operand is <iflags>"),
            (
                0x8680,
                &[Operand::Text("z")],
                "z is not an <iflags> spelling",
            ),
            (0x8680, &[a, a], "the mode is an immediate"),
            (
                0x8680,
                &[a, Operand::Imm(0), Operand::Imm(0)],
                "at most two operands",
            ),
        ];
        for (hw2, operands, why) in cases {
            let insn = with_operands(0xF3AF, hw2, operands);
            assert_eq!(encode(&insn), None, "{why} ({hw2:#06x})");
        }
    }

    #[test]
    fn re_encoding_at_a_new_address_moves_the_displacement() {
        // The target stays put, so the encoded displacement must change.
        let at_1000 = decode(0xF000, 0xD000, 0x1000).unwrap();
        let target = at_1000.branch_target().unwrap();
        let mut at_2000 = at_1000;
        at_2000.addr = 0x2000;
        let (hw1, hw2) = encode(&at_2000).unwrap();
        assert_ne!((hw1, hw2), (0xF000, 0xD000));
        assert_eq!(
            decode(hw1, hw2, 0x2000).unwrap().branch_target(),
            Some(target)
        );
        // Which is exactly what the standalone oracle produces.
        assert_eq!(
            Some((hw1, hw2)),
            encode_bl(0x2000, target).map(halfwords),
            "disagreement with encode_bl after relocation"
        );
    }
}
