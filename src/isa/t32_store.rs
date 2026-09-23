//! Store single data item — `hw1[15:11] == 0b11111`, `hw1[10:4]` matching
//! `000xxx0` (ARM DDI 0403E.e A5.3.10, Table A5-21; ARM DDI 0406B A6.3.10,
//! Table A6-21).
//!
//! ```text
//!  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
//!   1  1  1  1  1  0  0  0 <-op1-->  0 <---- Rn ---->   hw1
//!  <---- Rt ----> <------ op2 ------>                   hw2
//! ```
//!
//! `op1` is two fields wearing one name: `op1[2]` picks the *shape* of the
//! second halfword, and `op1[1:0]` the access size — `00` byte, `01` halfword,
//! `10` word, `11` nothing at all (no row of Table A5-21 has it, so it is
//! UNDEFINED). With `op1[2] == 1` the whole of `hw2[11:0]` is a 12-bit unsigned
//! offset; with `op1[2] == 0`, `op2 = hw2[11:6]` splits further, and that split
//! is the interesting part of this group:
//!
//! | `op2` | form | `hw2[11:0]` |
//! |---|---|---|
//! | `000000` | register offset | `000000 imm2 Rm` |
//! | `0xxxxx`, non-zero | UNDEFINED | - |
//! | `1PUW xx` | immediate, 8-bit | `1 P U W imm8` |
//!
//! So `op2 = 1 P U W imm8[7:6]`, and Table A6-21 — which is finer-grained than
//! the M-profile's A5-21 — spells the `P`/`U`/`W` allocation out row by row:
//! `1xx1xx` (`W == 1`) is the writeback form, `1100xx` (`P:U:W == 100`) the
//! negative-offset form, `1110xx` (`P:U:W == 110`) the *unprivileged*
//! `STRT`/`STRBT`/`STRHT` family, and what is left — `10x0xx`, i.e.
//! `P == 0 && W == 0` — is UNDEFINED, exactly as each instruction page's
//! *`if Rn == '1111' || (P == '0' && W == '0') then UNDEFINED`* says.
//!
//! The unprivileged corner is therefore `P == 1 && U == 1 && W == 0`, not
//! `P == 0 && W == 0`: the redirect is *`if P == '1' && U == '1' && W == '0'
//! then SEE STRT`* (A7.7.161, A7.7.163, A7.7.170; ARM DDI 0406B A8.6.193 and
//! friends agree). Both manuals, both profiles.
//!
//! # `P`, `U`, `W` and [`AddrMode`]
//!
//! `P` indexes, `W` writes back, `U` adds rather than subtracts:
//!
//! | `P` | `W` | [`AddrMode`] | syntax |
//! |---|---|---|---|
//! | 1 | 0 | [`AddrMode::Offset`] | `[rn, #-imm8]` |
//! | 1 | 1 | [`AddrMode::PreIndex`] | `[rn, #+/-imm8]!` |
//! | 0 | 1 | [`AddrMode::PostIndex`] | `[rn], #+/-imm8` |
//! | 0 | 0 | — | UNDEFINED |
//!
//! `U` is [`Mem::add`] verbatim; [`Mem::offset`] is the magnitude. The offset
//! row is listed as negative-only because it is: its `U == 1` half is where
//! `STRT` lives, which is why the manual's syntax line for the 8-bit offset
//! form reads `STR<c> <Rt>,[<Rn>,#-<imm8>]` with the minus sign already
//! printed.
//!
//! That is what makes `imm8 == 0` unremarkable here. `[rn, #-0]!` and
//! `[rn, #0]!` are architecturally different encodings ("Different
//! instructions are generated for #0 and #-0", A7.7.161), and they are two
//! different [`Mem`] values — `add: false` and `add: true` over the same zero
//! magnitude — printing as `[rn, #-0]!` and `[rn, #0]!`. An earlier revision
//! of this module stored a sign-corrected `i32`, where `-0 == 0`, and had to
//! canonicalise 450 encodings onto their `U == 1` twin; nothing is
//! canonicalised now, and `tests::minus_zero_is_its_own_encoding` pins that
//! down.
//!
//! # Offsets here are *not* scaled
//!
//! Every 16-bit store scales its immediate by the access size: `STRH` T1
//! encodes `imm5 = offset/2`, `STR` T1 encodes `imm5 = offset/4` (A5.2.4).
//! **None of the 32-bit encodings do.** All of them say
//! `imm32 = ZeroExtend(imm12, 32)` or `ZeroExtend(imm8, 32)` — plain bytes,
//! identical for `STRB`, `STRH` and `STR` — so `strh.w r0, [r1, #4]` puts a
//! literal `4` in the field, where the narrow `strh r0, [r1, #4]` puts a `2`.
//! Assuming the wide space mirrors the narrow one silently halves or quarters
//! every halfword and word offset in a disassembly;
//! `tests::offsets_are_unscaled` hand-checks all three sizes against that.
//!
//! # `Rn == 1111` and `Rt == 1111`
//!
//! `Rn == 1111` is UNDEFINED in every row of this table — there is no "store to
//! a literal", and the pc-relative half of the load space (`LDR (literal)`,
//! `PLD (literal)`) has no counterpart here. We return `None`.
//!
//! `Rt == 1111` is UNPREDICTABLE in every row too (`if t == 15` for `STR`,
//! `if t IN {13,15}` for the byte, halfword and unprivileged forms), and we
//! return `None` for it as well — the one operand-level rejection this module
//! makes. The reason is [`Insn::writes_pc`], which is shared, cannot be
//! changed from here, and ends with *"operand 0 is `pc`"*: that heuristic is
//! right for a load, whose operand 0 is its destination, and exactly wrong for
//! a store, whose operand 0 is its source. Decoding `str pc, [r0]` would make
//! [`Insn::is_branch`] report a branch that is not one, in the crate whose
//! reason for existing is to stop a firmware scan from inventing branches.
//! Reporting those four bytes as undefined is both more honest and more useful.
//!
//! Other UNPREDICTABLE operand combinations *are* decoded, since they are
//! representable, they re-encode exactly, and a disassembler is more use
//! reporting the halfword that is there than refusing to:
//!
//! * `Rt == 1101` (`strb sp, …`, `strh sp, …`, and the unprivileged forms) —
//!   UNPREDICTABLE. `STR` alone permits `sp` as `Rt`.
//! * `Rm IN {13,15}` in a register-offset form — UNPREDICTABLE.
//! * `wback && n == t` (`str r0, [r0, #4]!`) — UNPREDICTABLE.
//!
//! # `push` hiding in the store table
//!
//! `STR (immediate)` T4 carries one redirect that is easy to miss: *`if
//! Rn == '1101' && P == '1' && U == '0' && W == '1' && imm8 == '00000100' then
//! SEE PUSH`* (A7.7.161). `str rt, [sp, #-4]!` **is** `PUSH` encoding T3, the
//! one-register push, and Arm's own assembler syntax for that halfword pair is
//! `PUSH<c>.W <registers>`. `f84d 4d04` disassembles as `push.w {r4}`, not as
//! `str r4, [sp, #-4]!`, and this module decodes it that way. The multi-
//! register `PUSH` T2 is a different encoding group entirely (A5.3.5) and lives
//! in `t32_ldm_stm`; the two are told apart by [`Insn::encoding`], `"T3"` here
//! and `"T2"` there.
//!
//! # Flags and width
//!
//! No store sets flags: every [`Insn`] from here has `sets_flags == false`.
//!
//! [`Insn::explicit_width`] is `true` for exactly the encodings whose manual
//! syntax line carries `.W` — the 12-bit immediate forms and the register form,
//! all of which have a 16-bit counterpart an assembler would otherwise pick.
//! The 8-bit immediate forms and the unprivileged forms have no narrow
//! equivalent (nothing 16-bit subtracts, writes back, or drops privilege), so
//! their syntax lines have no `.W` and neither do we.

use super::{AddrMode, Insn, Mem, Operand, Reg, Shift, ShiftAmount, ShiftKind, Width};

/// Decode one instruction of this group, or `None` if `hw1`/`hw2` are not in
/// it, are one of its UNDEFINED holes, or name `pc` as `Rt` (see the module
/// docs for why that last one is a rejection).
pub(crate) fn decode(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    // `11111 000 op1(3) 0 Rn(4)` — the bits outside `op1`/`Rn` are what makes
    // this the store table rather than one of the load tables next door.
    if hw1 >> 11 != 0b11111 || (hw1 >> 8) & 0b111 != 0 || (hw1 >> 4) & 1 != 0 {
        return None;
    }

    let op1 = (hw1 >> 5) & 0b111;
    let size = op1 & 0b11;
    let rn = Reg((hw1 & 0xF) as u8);
    let rt = Reg(((hw2 >> 12) & 0xF) as u8);

    // `op1[1:0] == 11` is in no row of Table A5-21; `Rn == 1111` is UNDEFINED
    // in every row; `Rt == 1111` is UNPREDICTABLE in every row and would lie to
    // `Insn::writes_pc`.
    if size == 0b11 || rn.num() == 15 || rt.num() == 15 {
        return None;
    }
    let mnemonic = SIZED[size as usize];

    // `op1[2] == 1`: the 12-bit unsigned offset forms, `STRB`/`STRH` T2 and
    // `STR` T3. Offset addressing only — no `P`, `U` or `W` to be had.
    if op1 & 0b100 != 0 {
        let mem = Mem {
            base: rn,
            index: None,
            offset: u32::from(hw2 & 0x0FFF),
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        };
        let encoding = if size == WORD { "T3" } else { "T2" };
        return Some(wide(
            mnemonic,
            encoding,
            addr,
            true,
            &[Operand::Reg(rt), Operand::Mem(mem)],
        ));
    }

    let op2 = (hw2 >> 6) & 0b11_1111;
    if op2 & 0b10_0000 == 0 {
        // Register offset, `STRB`/`STRH`/`STR (register)` T2. The encoding
        // diagram fixes `hw2[11:6]` at `000000`; Table A5-21's `0xxxxx` row is
        // wider than the diagram it points at, and the rest of it is UNDEFINED.
        if op2 != 0 {
            return None;
        }
        // The index shift is always `LSL`, by `imm2` and nothing else. A shift
        // of zero is *omitted* rather than carried, so `Mem`'s `Display`
        // prints `[r0, r1]`; `[r0, r1, lsl #0]` is the same instruction but
        // not the form Arm's syntax line writes, and `{,LSL #<imm2>}` is
        // optional precisely because zero is the default.
        let imm2 = ((hw2 >> 4) & 0b11) as u8;
        let mem = Mem {
            base: rn,
            index: Some((
                Reg((hw2 & 0xF) as u8),
                if imm2 == 0 {
                    None
                } else {
                    Some(Shift {
                        kind: ShiftKind::Lsl,
                        amount: ShiftAmount::Imm(imm2),
                    })
                },
            )),
            offset: 0,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        };
        return Some(wide(
            mnemonic,
            "T2",
            addr,
            true,
            &[Operand::Reg(rt), Operand::Mem(mem)],
        ));
    }

    // `op2 = 1 P U W imm8[7:6]`: the 8-bit immediate forms.
    let p = (hw2 >> 10) & 1 == 1;
    let u = (hw2 >> 9) & 1 == 1;
    let w = (hw2 >> 8) & 1 == 1;
    let imm8 = u32::from(hw2 & 0xFF);

    // `P:U:W == 110` is the unprivileged family, which is an offset form with
    // no sign, no writeback and a mnemonic of its own.
    if p && u && !w {
        let mem = Mem {
            base: rn,
            index: None,
            offset: imm8,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        };
        return Some(wide(
            UNPRIV[size as usize],
            "T1",
            addr,
            false,
            &[Operand::Reg(rt), Operand::Mem(mem)],
        ));
    }
    // `P == 0 && W == 0` would be "no index and no writeback", which computes
    // an address and then ignores it. UNDEFINED.
    if !p && !w {
        return None;
    }
    // `str rt, [sp, #-4]!` is `PUSH` T3 (A7.7.161's second redirect).
    if size == WORD && rn.num() == 13 && p && !u && w && imm8 == 4 {
        return Some(wide(
            "push",
            "T3",
            addr,
            true,
            &[Operand::RegList(1 << rt.num())],
        ));
    }

    let mem = Mem {
        base: rn,
        index: None,
        offset: imm8,
        add: u,
        align: 0,
        mode: if !p {
            AddrMode::PostIndex
        } else if w {
            AddrMode::PreIndex
        } else {
            AddrMode::Offset
        },
    };
    let encoding = if size == WORD { "T4" } else { "T3" };
    Some(wide(
        mnemonic,
        encoding,
        addr,
        false,
        &[Operand::Reg(rt), Operand::Mem(mem)],
    ))
}

/// Re-encode an instruction this module decoded, back to its two halfwords.
///
/// [`Insn::encoding`] is the authority for which of an operation's several
/// encodings to rebuild, because the operand shapes overlap: `strb.w r0,
/// [r1, #4]` is T2 and `strb r0, [r1, #4]!` is T3, and the only difference
/// visible in the operands is an addressing mode that T2 cannot express at all.
/// `STRB`/`STRH`'s immediate T2 and their register T2 share even the encoding
/// name, and are told apart by whether the [`Mem`] has an index register.
///
/// Returns `None` for anything outside this group, including offsets too large
/// for the named encoding and the `U == 1`/`P == 1`/`W == 0` combination, which
/// is not a plain offset store at all but `STRT`.
///
/// [`Insn::cond`] is ignored rather than rejected: nothing in this group has a
/// condition field, so a condition can only have come from an enclosing `IT`
/// block, which does not change the instruction's own bits.
pub(crate) fn encode(insn: &Insn) -> Option<(u16, u16)> {
    if insn.width != Width::Wide || insn.sets_flags {
        return None;
    }

    // `PUSH` T3 — the one form here with a register list rather than a `Mem`.
    if insn.mnemonic == "push" {
        if insn.encoding != "T3" || insn.operands.len() != 1 {
            return None;
        }
        return match insn.operands.get(0) {
            Some(Operand::RegList(bits)) if bits.count_ones() == 1 && bits & 0x8000 == 0 => {
                Some((0xF84D, (bits.trailing_zeros() as u16) << 12 | 0x0D04))
            }
            _ => None,
        };
    }

    let size = match insn.mnemonic {
        "strb" | "strbt" => 0u16,
        "strh" | "strht" => 1,
        "str" | "strt" => 2,
        _ => return None,
    };
    let (rt, mem) = match (insn.operands.get(0), insn.operands.get(1)) {
        (Some(Operand::Reg(t)), Some(Operand::Mem(m))) => (t, m),
        _ => return None,
    };
    if insn.operands.len() != 2 || rt.num() == 15 || mem.base.num() == 15 {
        return None;
    }
    let hw1 = 0xF800 | (size << 5) | u16::from(mem.base.num());
    let rt_field = u16::from(rt.num()) << 12;

    // Unprivileged: `P:U:W == 110`, plain positive offset.
    if matches!(insn.mnemonic, "strt" | "strbt" | "strht") {
        if insn.encoding != "T1" || mem.index.is_some() || mem.mode != AddrMode::Offset {
            return None;
        }
        // `U == 1` is part of what makes this the unprivileged row, so a
        // subtracting offset — `#-0` included — is not one of its spellings.
        if !mem.add {
            return None;
        }
        let imm = u16::try_from(mem.offset).ok()?;
        if imm > 0xFF {
            return None;
        }
        return Some((hw1, rt_field | 0x0E00 | imm));
    }

    // Register offset. Only ever `LSL #0..=3`, and zero is carried as no shift
    // at all — so `Some(lsl #0)` is refused rather than silently accepted, to
    // keep one instruction to one `Insn`.
    if let Some((rm, shift)) = mem.index {
        // A register index has no `U` field, so `add` must be nominal.
        if insn.encoding != "T2" || mem.mode != AddrMode::Offset || mem.offset != 0 || !mem.add {
            return None;
        }
        let imm2 = match shift {
            None => 0u16,
            Some(Shift {
                kind: ShiftKind::Lsl,
                amount: ShiftAmount::Imm(n),
            }) if (1..=3).contains(&n) => u16::from(n),
            _ => return None,
        };
        return Some((hw1, rt_field | (imm2 << 4) | u16::from(rm.num())));
    }

    let (imm12_name, imm8_name) = if size == WORD {
        ("T3", "T4")
    } else {
        ("T2", "T3")
    };
    if insn.encoding == imm12_name {
        // The 12-bit field is unsigned and there is no `U` bit beside it.
        if mem.mode != AddrMode::Offset || !mem.add {
            return None;
        }
        let imm = u16::try_from(mem.offset).ok()?;
        if imm > 0x0FFF {
            return None;
        }
        return Some((hw1 | 0x0080, rt_field | imm));
    }
    if insn.encoding != imm8_name {
        return None;
    }
    let magnitude = u16::try_from(mem.offset).ok()?;
    if magnitude > 0xFF {
        return None;
    }
    // `U` is `Mem::add` verbatim — except in the offset form, where `U == 1`
    // is `STRT`'s encoding, so an *adding* offset (`#0` included) is not
    // encodable here at all and `[rn, #-0]` is.
    let (p, w) = match mem.mode {
        AddrMode::Offset => (1u16, 0u16),
        AddrMode::PreIndex => (1, 1),
        AddrMode::PostIndex => (0, 1),
        // `[<Rn>]!` with an implicit increment is Advanced SIMD only.
        AddrMode::PostIncrement => return None,
    };
    if mem.mode == AddrMode::Offset && mem.add {
        return None;
    }
    let u = u16::from(mem.add);
    Some((
        hw1,
        rt_field | 0x0800 | (p << 10) | (u << 9) | (w << 8) | magnitude,
    ))
}

/// `op1[1:0] == 0b10` — the word-sized column, which is the one that names its
/// encodings T3/T4 rather than T2/T3 (the narrow `STR` has two encodings to
/// `STRB`'s one) and the only one with a `PUSH` redirect.
const WORD: u16 = 0b10;

/// The ordinary mnemonics, indexed by `op1[1:0]`.
const SIZED: [&str; 3] = ["strb", "strh", "str"];

/// The unprivileged mnemonics, indexed by `op1[1:0]`.
const UNPRIV: [&str; 3] = ["strbt", "strht", "strt"];

/// Build a 32-bit, unconditional, flag-preserving store.
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
        assert!(!insn.sets_flags, "no store sets flags");
        insn
    }

    /// The second halfwords worth sweeping: every shape this group can take,
    /// at the boundaries of every field. Exhaustive in `P`/`U`/`W` and in the
    /// shift amount, and at both ends of every immediate.
    fn hw2_sweep() -> Vec<u16> {
        let mut out = Vec::new();
        for rt in [0u16, 1, 7, 12, 13, 15] {
            let rt = rt << 12;
            // 12-bit immediate, and the same bits read as a `1PUWxx` op2.
            for imm in [0u16, 1, 2, 4, 0x7FF, 0x800, 0xFFE, 0xFFF] {
                out.push(rt | imm);
            }
            // 8-bit immediate: all eight P/U/W combinations.
            for puw in 0u16..8 {
                for imm8 in [0u16, 1, 4, 0x7F, 0x80, 0xFF] {
                    out.push(rt | 0x0800 | (puw << 8) | imm8);
                }
            }
            // Register offset, including the `op2 != 0` holes around it.
            for imm2 in 0u16..4 {
                for rm in [0u16, 1, 2, 13, 15] {
                    out.push(rt | (imm2 << 4) | rm);
                }
            }
            for op2 in [1u16, 2, 0x1F, 0x20] {
                out.push(rt | (op2 << 6));
            }
        }
        out
    }

    #[test]
    fn systematic_round_trip() {
        let mut exact = 0;
        let mut minus_zero = 0;
        let mut undefined = 0;
        let sweep = hw2_sweep();
        for op1 in 0u16..8 {
            for rn in 0u16..16 {
                let hw1 = 0xF800 | (op1 << 5) | rn;
                for &hw2 in &sweep {
                    // No `let … else`: this crate's MSRV is 1.58 (that is 1.65).
                    if let Some(insn) = decode(hw1, hw2, 0x2000) {
                        // Every encoding in this group goes back to itself,
                        // `#-0` included; there is no exception left to carve
                        // out. Compared as an `Option` rather than unwrapped,
                        // so that "did not re-encode at all" and "re-encoded
                        // to the wrong bytes" are one assertion and there is
                        // no `unwrap_or_else` closure that never runs.
                        assert_eq!(
                            encode(&insn),
                            Some((hw1, hw2)),
                            "{hw1:#06x} {hw2:#06x} re-encoded wrongly as `{insn}`"
                        );
                        exact += 1;
                        // The encodings that used to be canonicalised: an
                        // 8-bit `U == 0`, `imm8 == 0` row, counted so that the
                        // sweep is known to reach them.
                        if op1 & 0b100 == 0 && hw2 & 0x0BFF == 0x0900 {
                            minus_zero += 1;
                            assert!(
                                insn.to_string().contains("#-0"),
                                "{hw1:#06x} {hw2:#06x} is `#-0` and must print so"
                            );
                        }
                    } else {
                        undefined += 1;
                    }
                }
            }
        }
        // 8 op1 values x 16 Rn x 480 hw2 patterns, covering every op1/op2
        // combination and every P/U/W at both ends of every immediate field.
        assert_eq!(sweep.len(), 480);
        assert_eq!(exact + undefined, 8 * 16 * sweep.len());
        // 31_500 exact plus the 450 that used to be canonicalised: every
        // defined encoding in the group now round-trips byte for byte.
        assert_eq!(exact, 31_950, "unexpected number of defined encodings");
        assert_eq!(
            minus_zero, 450,
            "the #-0 writeback and post-indexed forms, and only those"
        );
        assert_eq!(undefined, 29_490);
    }

    /// The `#-0` forms — `[rn, #-0]`, `[rn, #-0]!` and `[rn], #-0` — are
    /// distinct encodings (A7.7.161: "Different instructions are generated for
    /// #0 and #-0"), print as themselves, and re-encode to their own bytes.
    ///
    /// This is the regression test for [`Mem`]'s representation: with a
    /// sign-corrected `i32` offset the first two assertions below were
    /// `assert_eq!`, because `-0 == 0` collapsed the pair.
    #[test]
    fn minus_zero_is_its_own_encoding() {
        // `str r0, [r1, #-0]!`: P=1, U=0, W=1, imm8=0.
        let minus = dec(0xF841, 0x0D00);
        let plus = dec(0xF841, 0x0F00);
        assert_ne!(minus, plus, "#-0 and #+0 are different instructions");
        assert_eq!(minus.to_string(), "str r0, [r1, #-0]!");
        assert_eq!(plus.to_string(), "str r0, [r1, #0]!");
        assert_eq!(encode(&minus), Some((0xF841, 0x0D00)));
        assert_eq!(encode(&plus), Some((0xF841, 0x0F00)));

        // `str r0, [r1], #-0` and `[r1], #0`: P=0, W=1. The post-indexed zero
        // prints its offset, because `[r1]` would read back as the offset form.
        let post_minus = dec(0xF841, 0x0900);
        let post_plus = dec(0xF841, 0x0B00);
        assert_eq!(post_minus.to_string(), "str r0, [r1], #-0");
        assert_eq!(post_plus.to_string(), "str r0, [r1], #0");
        assert_eq!(encode(&post_minus), Some((0xF841, 0x0900)));
        assert_eq!(encode(&post_plus), Some((0xF841, 0x0B00)));

        // The *offset* form has only the one spelling: `U == 1` there is
        // `STRT`, so `[r1, #-0]` is the only `imm8 == 0` offset encoding.
        let off = dec(0xF841, 0x0C00);
        assert_eq!(off.to_string(), "str r0, [r1, #-0]");
        assert_eq!(encode(&off), Some((0xF841, 0x0C00)));
        // And the 12-bit form, which has no `U` bit at all, is where a plain
        // `[r1]` comes from.
        assert_eq!(dec(0xF8C1, 0x0000).to_string(), "str.w r0, [r1]");
    }

    /// One row of Table A5-21 per assertion, in the table's own order, with
    /// the syntax taken from each instruction page's assembler-syntax line.
    #[test]
    fn table_a5_21_rows() {
        // op1 = 100: STRB (immediate) T2, `STRB<c>.W <Rt>,[<Rn>,#<imm12>]`.
        let i = check(0xF881, 0x0020, "strb.w r0, [r1, #32]");
        assert_eq!((i.mnemonic, i.encoding), ("strb", "T2"));

        // op1 = 000, op2 = 1xxxxx: STRB (immediate) T3,
        // `STRB<c> <Rt>,[<Rn>,#-<imm8>]`.
        let i = check(0xF803, 0x2C05, "strb r2, [r3, #-5]");
        assert_eq!((i.mnemonic, i.encoding), ("strb", "T3"));

        // op1 = 000, op2 = 0xxxxx: STRB (register) T2,
        // `STRB<c>.W <Rt>,[<Rn>,<Rm>{,LSL #<imm2>}]`.
        let i = check(0xF801, 0x0002, "strb.w r0, [r1, r2]");
        assert_eq!((i.mnemonic, i.encoding), ("strb", "T2"));

        // op1 = 101: STRH (immediate) T2.
        let i = check(0xF8A1, 0x0020, "strh.w r0, [r1, #32]");
        assert_eq!((i.mnemonic, i.encoding), ("strh", "T2"));

        // op1 = 001, op2 = 1xxxxx: STRH (immediate) T3.
        let i = check(0xF823, 0x2C05, "strh r2, [r3, #-5]");
        assert_eq!((i.mnemonic, i.encoding), ("strh", "T3"));

        // op1 = 001, op2 = 0xxxxx: STRH (register) T2.
        let i = check(0xF821, 0x0002, "strh.w r0, [r1, r2]");
        assert_eq!((i.mnemonic, i.encoding), ("strh", "T2"));

        // op1 = 110: STR (immediate) T3, `STR<c>.W <Rt>,[<Rn>,#<imm12>]`.
        let i = check(0xF8C0, 0x3004, "str.w r3, [r0, #4]");
        assert_eq!((i.mnemonic, i.encoding), ("str", "T3"));

        // op1 = 010, op2 = 1xxxxx: STR (immediate) T4.
        let i = check(0xF843, 0x2C05, "str r2, [r3, #-5]");
        assert_eq!((i.mnemonic, i.encoding), ("str", "T4"));

        // op1 = 010, op2 = 0xxxxx: STR (register) T2.
        let i = check(0xF841, 0x0002, "str.w r0, [r1, r2]");
        assert_eq!((i.mnemonic, i.encoding), ("str", "T2"));
    }

    /// The three unprivileged forms, which Table A5-21 folds into the `1xxxxx`
    /// rows and Table A6-21 breaks out as `1110xx`.
    #[test]
    fn unprivileged_forms() {
        // `STRBT<c><q> <Rt>, [<Rn> {, #<imm>}]` — P:U:W = 110.
        let i = check(0xF803, 0x2E05, "strbt r2, [r3, #5]");
        assert_eq!((i.mnemonic, i.encoding), ("strbt", "T1"));

        // `STRHT<c><q> <Rt>, [<Rn> {, #<imm>}]`.
        let i = check(0xF823, 0x2E05, "strht r2, [r3, #5]");
        assert_eq!((i.mnemonic, i.encoding), ("strht", "T1"));

        // `STRT<c><q> <Rt>, [<Rn> {, #<imm>}]`, and its "`<imm>` can be
        // omitted, meaning an offset of 0" form.
        let i = check(0xF843, 0x2E05, "strt r2, [r3, #5]");
        assert_eq!((i.mnemonic, i.encoding), ("strt", "T1"));
        check(0xF843, 0x2E00, "strt r2, [r3]");

        // No `.w`: there is no 16-bit unprivileged store to be ambiguous with.
        assert!(!i.explicit_width);
    }

    /// Offset, pre-indexed, post-indexed and negative-offset printed forms,
    /// one of each, against the manual's addressing-mode syntax lines.
    #[test]
    fn addressing_modes() {
        // Offset: index == TRUE, wback == FALSE. P=1 U=0 W=0.
        let i = check(0xF841, 0x0C08, "str r0, [r1, #-8]");
        assert_eq!(
            i.operands.get(1),
            Some(Operand::Mem(Mem {
                base: Reg(1),
                index: None,
                offset: 8,
                add: false,
                align: 0,
                mode: AddrMode::Offset,
            }))
        );

        // Pre-indexed: `[<Rn>, #+/-<imm>]!`. P=1 W=1, both signs.
        check(0xF841, 0x0F08, "str r0, [r1, #8]!");
        check(0xF841, 0x0D08, "str r0, [r1, #-8]!");

        // Post-indexed: `[<Rn>], #+/-<imm>`. P=0 W=1, both signs.
        check(0xF841, 0x0B08, "str r0, [r1], #8");
        check(0xF841, 0x0908, "str r0, [r1], #-8");

        // The 12-bit form is offset-only and unsigned; `#0` prints as nothing.
        check(0xF8C1, 0x0000, "str.w r0, [r1]");
        check(0xF8C1, 0x0FFF, "str.w r0, [r1, #4095]");

        // A shift of zero is omitted, a non-zero one is printed.
        check(0xF841, 0x0002, "str.w r0, [r1, r2]");
        check(0xF841, 0x0032, "str.w r0, [r1, r2, lsl #3]");
    }

    /// The offsets in this group are plain byte counts. Every one of these
    /// would decode to a different number if the 16-bit space's scaling rule
    /// (`imm5 = offset/2` for `STRH`, `/4` for `STR`) applied here.
    #[test]
    fn offsets_are_unscaled() {
        // `str.w r0, [r1, #4]`: the field holds 4, not 4/4 == 1. Were it
        // scaled, `0xF8C1 0x0004` would have to print `[r1, #16]`.
        let i = dec(0xF8C1, 0x0004);
        assert_eq!(i.to_string(), "str.w r0, [r1, #4]");

        // `strh.w r0, [r1, #4]`: 4, not 4/2 == 2 — and identical bits to the
        // word case above but for `op1`, which is the whole point.
        assert_eq!(dec(0xF8A1, 0x0004).to_string(), "strh.w r0, [r1, #4]");
        assert_eq!(dec(0xF881, 0x0004).to_string(), "strb.w r0, [r1, #4]");

        // The three sizes agree at the top of the field as well: 4095 bytes,
        // not 4095 words. A scaled word form would reach 16380.
        for (hw1, text) in [
            (0xF8C1u16, "str.w r0, [r1, #4095]"),
            (0xF8A1, "strh.w r0, [r1, #4095]"),
            (0xF881, "strb.w r0, [r1, #4095]"),
        ] {
            assert_eq!(dec(hw1, 0x0FFF).to_string(), text);
        }

        // And an odd offset is representable for a word store, which a scaled
        // encoding could not express at all.
        assert_eq!(dec(0xF8C1, 0x0001).to_string(), "str.w r0, [r1, #1]");

        // The 8-bit forms are unscaled too: 255, not 1020.
        assert_eq!(dec(0xF841, 0x0FFF).to_string(), "str r0, [r1, #255]!");
    }

    /// The UNDEFINED holes, each from its own rule.
    #[test]
    fn undefined_holes() {
        // `op1[1:0] == 11`: no row of Table A5-21.
        assert!(decode(0xF861, 0x0000, 0).is_none(), "op1 = 011");
        assert!(decode(0xF8E1, 0x0000, 0).is_none(), "op1 = 111");

        // `Rn == 1111`: there is no store to a literal.
        for op1 in 0u16..8 {
            let hw1 = 0xF80F | (op1 << 5);
            assert!(decode(hw1, 0x0004, 0).is_none(), "{hw1:#06x}: Rn = pc");
            assert!(decode(hw1, 0x0C04, 0).is_none(), "{hw1:#06x}: Rn = pc");
        }

        // `P == 0 && W == 0` in an 8-bit form.
        for u in [0u16, 1] {
            let hw2 = 0x0800 | (u << 9) | 4;
            assert!(decode(0xF841, hw2, 0).is_none(), "P = 0, W = 0");
        }

        // `op2` in `0xxxxx` but not `000000`: outside the register form's
        // encoding diagram.
        for op2 in 1u16..0x20 {
            let hw2 = op2 << 6;
            assert!(decode(0xF841, hw2, 0).is_none(), "op2 = {op2:#08b}");
        }

        // `Rt == 1111`, rejected so that `Insn::writes_pc` cannot be told that
        // a store to memory writes the program counter.
        assert!(decode(0xF8C1, 0xF004, 0).is_none(), "str pc, [r1, #4]");
        assert!(decode(0xF841, 0xF002, 0).is_none(), "str pc, [r1, r2]");
        assert!(decode(0xF801, 0xF004, 0).is_none(), "strb pc, [r1, r2]");
    }

    /// `str rt, [sp, #-4]!` is `PUSH` T3, per `STR (immediate)`'s second
    /// redirect, and only for that exact `Rn`/`P`/`U`/`W`/`imm8` combination.
    #[test]
    fn single_register_push() {
        let i = check(0xF84D, 0x4D04, "push.w {r4}");
        assert_eq!((i.mnemonic, i.encoding), ("push", "T3"));
        assert_eq!(i.operands.get(0), Some(Operand::RegList(1 << 4)));
        assert_eq!(i.operands.len(), 1);
        assert!(!i.writes_pc(), "a push never writes pc");

        // One bit different in any of the five constrained fields and it is an
        // ordinary `STR` again.
        assert_eq!(dec(0xF84D, 0x4D08).to_string(), "str r4, [sp, #-8]!");
        assert_eq!(dec(0xF84C, 0x4D04).to_string(), "str r4, [r12, #-4]!");
        assert_eq!(dec(0xF84D, 0x4F04).to_string(), "str r4, [sp, #4]!");
        assert_eq!(dec(0xF84D, 0x4904).to_string(), "str r4, [sp], #-4");
        // Byte and halfword stores have no such redirect.
        assert_eq!(dec(0xF80D, 0x4D04).to_string(), "strb r4, [sp, #-4]!");
    }

    /// UNPREDICTABLE operand combinations that are nonetheless representable,
    /// and so are decoded rather than refused.
    #[test]
    fn unpredictable_but_decoded() {
        // `t IN {13,15}` for a byte store: `sp` decodes, `pc` does not.
        assert_eq!(dec(0xF881, 0xD004).to_string(), "strb.w sp, [r1, #4]");
        // `m IN {13,15}` in a register form.
        assert_eq!(dec(0xF841, 0x000D).to_string(), "str.w r0, [r1, sp]");
        assert_eq!(dec(0xF841, 0x000F).to_string(), "str.w r0, [r1, pc]");
        // `wback && n == t`.
        assert_eq!(dec(0xF840, 0x0F04).to_string(), "str r0, [r0, #4]!");
    }

    /// The re-encoder refuses shapes it did not produce, which is what stops
    /// two encoding groups from silently trading patterns.
    #[test]
    fn encode_rejects_foreign_forms() {
        let mut i = dec(0xF8C1, 0x0004);

        // A narrow `str` is A5.2.4's encoding, not this group's.
        let mut narrow = i;
        narrow.width = Width::Narrow;
        assert_eq!(encode(&narrow), None);

        // No store sets flags.
        let mut flags = i;
        flags.sets_flags = true;
        assert_eq!(encode(&flags), None);

        // An offset too wide for the named encoding.
        i.operands = [
            Operand::Reg(Reg(0)),
            Operand::Mem(Mem {
                base: Reg(1),
                index: None,
                offset: 0x1000,
                add: true,
                align: 0,
                mode: AddrMode::Offset,
            }),
        ]
        .iter()
        .copied()
        .collect();
        assert_eq!(encode(&i), None);

        // `[rn, #+imm8]` in the 8-bit form is `STRT`'s encoding, so the 8-bit
        // form cannot express a positive plain offset.
        let mut t4 = dec(0xF841, 0x0C08);
        assert_eq!(encode(&t4), Some((0xF841, 0x0C08)));
        t4.operands = [
            Operand::Reg(Reg(0)),
            Operand::Mem(Mem {
                base: Reg(1),
                index: None,
                offset: 8,
                add: true,
                align: 0,
                mode: AddrMode::Offset,
            }),
        ]
        .iter()
        .copied()
        .collect();
        assert_eq!(encode(&t4), None);

        // An explicit `lsl #0` is not how a zero shift is carried.
        let mut zero_shift = dec(0xF841, 0x0002);
        zero_shift.operands = [
            Operand::Reg(Reg(0)),
            Operand::Mem(Mem {
                base: Reg(1),
                index: Some((
                    Reg(2),
                    Some(Shift {
                        kind: ShiftKind::Lsl,
                        amount: ShiftAmount::Imm(0),
                    }),
                )),
                offset: 0,
                add: true,
                align: 0,
                mode: AddrMode::Offset,
            }),
        ]
        .iter()
        .copied()
        .collect();
        assert_eq!(encode(&zero_shift), None);

        // A foreign mnemonic, and a foreign encoding name for a local one.
        let mut foreign = dec(0xF8C1, 0x0004);
        foreign.mnemonic = "ldr";
        assert_eq!(encode(&foreign), None);
        let mut wrong_enc = dec(0xF8C1, 0x0004);
        wrong_enc.encoding = "T1";
        assert_eq!(encode(&wrong_enc), None);
    }

    /// The re-encoder refuses every operand shape [`decode`] cannot produce,
    /// row by row.
    ///
    /// [`Insn`] and [`Mem`] are public structs with public fields, so a
    /// consumer — or a consumer's arithmetic mistake — can hand `encode` an
    /// offset wider than the field, an addressing mode the row has no bits
    /// for, or a `pc` where the row forbids one. There is exactly one safe
    /// answer to each, `None`. The dangerous answer is a silent truncation:
    /// these halfwords get written into a firmware image, and an offset of
    /// `0x10000` quietly becoming `#0` is a store to the wrong address.
    #[test]
    fn encode_rejects_shapes_the_decoder_cannot_produce() {
        /// A [`Mem`] with no index, for the immediate rows.
        fn at(base: u8, offset: u32, add: bool, mode: AddrMode) -> Operand {
            Operand::Mem(Mem {
                base: Reg(base),
                index: None,
                offset,
                add,
                align: 0,
                mode,
            })
        }
        /// A `[rn, rm]` operand, for the register-offset row.
        fn indexed(base: u8, offset: u32, add: bool, mode: AddrMode) -> Operand {
            Operand::Mem(Mem {
                base: Reg(base),
                index: Some((Reg(2), None)),
                offset,
                add,
                align: 0,
                mode,
            })
        }
        let rt = Operand::Reg(Reg(0));
        let plain = at(1, 4, true, AddrMode::Offset);

        // --- `PUSH` T3, the one row with a register list ---
        let push = dec(0xF84D, 0x4D04);
        let mut t4_push = push;
        t4_push.encoding = "T4";
        assert_eq!(encode(&t4_push), None, "the single-register push is T3");
        assert_eq!(encode(&wide("push", "T3", 0, true, &[])), None, "no list");
        assert_eq!(
            encode(&wide(
                "push",
                "T3",
                0,
                true,
                &[Operand::RegList(0x0010), rt]
            )),
            None,
            "push with a spare operand"
        );
        // A list is what T3 takes, and it holds exactly one register that is
        // not `pc`: two registers is `PUSH` T2's encoding (A7.7.101), and
        // A7.7.101's list may not name `pc` at all.
        assert_eq!(encode(&wide("push", "T3", 0, true, &[rt])), None);
        assert_eq!(
            encode(&wide("push", "T3", 0, true, &[Operand::RegList(0x0030)])),
            None,
            "two registers is `PUSH` T2, not T3"
        );
        assert_eq!(
            encode(&wide("push", "T3", 0, true, &[Operand::RegList(0x8000)])),
            None,
            "`pc` cannot be pushed"
        );

        // --- the shared `<Rt>, <mem>` gate ---
        assert_eq!(
            encode(&wide("str", "T3", 0, true, &[plain, rt])),
            None,
            "the transfer register comes first, then the address"
        );
        assert_eq!(
            encode(&wide("str", "T3", 0, true, &[rt, Operand::Imm(4)])),
            None,
            "the second operand is an address, not an immediate"
        );
        assert_eq!(
            encode(&wide("str", "T3", 0, true, &[rt, plain, Operand::Imm(0)])),
            None,
            "a store takes two operands"
        );
        // `Rt == pc` is UNPREDICTABLE in every row of Table A5-21 and `Rn ==
        // pc` is UNDEFINED in all of them, so `decode` refuses both and this
        // must not manufacture them.
        assert_eq!(
            encode(&wide("str", "T3", 0, true, &[Operand::Reg(Reg::PC), plain])),
            None,
            "`str pc, …` is UNPREDICTABLE"
        );
        assert_eq!(
            encode(&wide(
                "str",
                "T3",
                0,
                true,
                &[rt, at(15, 4, true, AddrMode::Offset)]
            )),
            None,
            "`Rn == 1111` is UNDEFINED, not a literal store"
        );

        // --- the unprivileged row, `P:U:W == 110` and an 8-bit offset ---
        for (mnemonic, ops, why) in [
            (
                "strt",
                [rt, indexed(1, 0, true, AddrMode::Offset)],
                "no unprivileged store takes a register index",
            ),
            (
                "strt",
                [rt, at(1, 4, true, AddrMode::PreIndex)],
                "`U`, `P` and `W` are fixed, so there is no writeback form",
            ),
            (
                "strbt",
                [rt, at(1, 4, false, AddrMode::Offset)],
                "`U == 1` is part of the row; `#-4` and `#-0` are not spellings of it",
            ),
            (
                "strht",
                [rt, at(1, 0x1_0000, true, AddrMode::Offset)],
                "an offset past the end of a u16 must not wrap into the field",
            ),
            (
                "strt",
                [rt, at(1, 0x100, true, AddrMode::Offset)],
                "the field is eight bits",
            ),
        ] {
            assert_eq!(encode(&wide(mnemonic, "T1", 0, false, &ops)), None, "{why}");
        }
        let mut t2_strt = dec(0xF803, 0x2E05);
        t2_strt.encoding = "T2";
        assert_eq!(encode(&t2_strt), None, "the unprivileged forms are T1 only");

        // --- the register-offset row, whose `Mem` has no `U` and no offset ---
        for (encoding, mem, why) in [
            (
                "T3",
                indexed(1, 0, true, AddrMode::Offset),
                "T2 is its name",
            ),
            (
                "T2",
                indexed(1, 0, true, AddrMode::PreIndex),
                "a register index has no writeback encoding here",
            ),
            (
                "T2",
                indexed(1, 4, true, AddrMode::Offset),
                "there is nowhere to put an immediate beside the index",
            ),
            (
                "T2",
                indexed(1, 0, false, AddrMode::Offset),
                "every register index is added; there is no `U` bit",
            ),
        ] {
            assert_eq!(
                encode(&wide("str", encoding, 0, true, &[rt, mem])),
                None,
                "{why}"
            );
        }

        // --- the 12-bit immediate row: unsigned, adding, offset only ---
        for (mem, why) in [
            (
                at(1, 4, true, AddrMode::PreIndex),
                "the 12-bit row has no `P`/`W`; writeback is the 8-bit row",
            ),
            (
                at(1, 4, false, AddrMode::Offset),
                "the 12-bit field has no `U` beside it and cannot subtract",
            ),
            (
                at(1, 0x1_0000, true, AddrMode::Offset),
                "an offset past the end of a u16 must not wrap into the field",
            ),
        ] {
            assert_eq!(
                encode(&wide("str", "T3", 0, true, &[rt, mem])),
                None,
                "{why}"
            );
        }

        // --- the 8-bit immediate row: `P`/`U`/`W`, magnitude and sign apart ---
        for (mem, why) in [
            (
                at(1, 0x1_0000, false, AddrMode::Offset),
                "an offset past the end of a u16 must not wrap into the field",
            ),
            (
                at(1, 0x100, false, AddrMode::PreIndex),
                "the field is eight bits",
            ),
            (
                at(1, 4, false, AddrMode::PostIncrement),
                "`[rn]!` with an implicit increment is Advanced SIMD's mode, not a store's",
            ),
        ] {
            assert_eq!(
                encode(&wide("str", "T4", 0, false, &[rt, mem])),
                None,
                "{why}"
            );
        }
    }

    /// `decode` refuses halfwords outside its own group.
    ///
    /// The dispatcher in `mod.rs` filters on `hw1` before routing here, so
    /// nothing in the crate reaches this guard — but `decode` is callable on
    /// its own, and each of the three conditions is a different neighbour it
    /// would otherwise steal encodings from.
    #[test]
    fn decode_refuses_halfwords_outside_the_group() {
        // `hw1[15:11] != 0b11111`: a 16-bit halfword, and the two other
        // 32-bit prefixes.
        for hw1 in [0x0000u16, 0x4770, 0xE800, 0xF000] {
            assert!(decode(hw1, 0x0004, 0).is_none(), "{hw1:#06x}");
        }
        // `hw1[10:8] != 0b000` — Table A5-9's other `op2` rows under
        // `op1 == 11`: `0xF900` is the store/load-signed column, `0xFB00` the
        // multiplies.
        assert!(decode(0xF900, 0x0004, 0).is_none());
        assert!(decode(0xFB00, 0x0004, 0).is_none());
        // `hw1[4] != 0` is the load half of the same table: `0xF8D1 0x0004` is
        // `ldr.w r0, [r1, #4]`, which belongs to `t32_load`.
        assert!(decode(0xF8D1, 0x0004, 0).is_none(), "that is an `ldr`");
        assert!(decode(0xF811, 0x0004, 0).is_none(), "that is an `ldrb`");
    }

    /// The dispatcher in `mod.rs` actually reaches this module: `op1 == 11`
    /// with `op2` matching `000xxx0` (Table A5-9). Decoding through the
    /// public entry point is the only way to catch a routing mistake, since
    /// every test above calls `decode` directly.
    #[test]
    fn reachable_through_the_dispatcher() {
        for (hw1, hw2, text) in [
            (0xF8C0u16, 0x3004u16, "str.w r3, [r0, #4]"),
            (0xF84D, 0x4D04, "push.w {r4}"),
            (0xF803, 0x2E05, "strbt r2, [r3, #5]"),
            (0xF821, 0x0032, "strh.w r0, [r1, r2, lsl #3]"),
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

    /// Nothing in this group is a branch, and nothing in it sets flags.
    #[test]
    fn classification() {
        for (hw1, hw2) in [
            (0xF8C1u16, 0x0004u16),
            (0xF841, 0x0C08),
            (0xF843, 0x2E05),
            (0xF84D, 0x4D04),
        ] {
            let i = dec(hw1, hw2);
            assert!(!i.is_branch(), "`{i}` is not a branch");
            assert!(!i.writes_pc(), "`{i}` does not write pc");
            assert!(!i.is_call(), "`{i}` is not a call");
            assert!(!i.sets_flags, "`{i}` does not set flags");
            assert_eq!(i.len(), 4);
        }
    }
}
