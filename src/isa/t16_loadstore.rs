//! 16-bit load/store of a single data item — `hw1[15:10]` in
//! `0b010010..=0b100111` and `0b101000..=0b101011`, that is `hw1` in
//! `0x4800..=0xAFFF` (ARM DDI 0403E.e A5.2.4 and Table A5-5; identically
//! ARM DDI 0406B A6.2.4 and Table A6-5, which allocate the same sixteen rows).
//!
//! A5.2.4 proper is `opA` of `0b0101`, `0b011x` and `0b100x`. The dispatcher
//! folds in the three single-encoding rows of Table A5-1 that share this file's
//! one concern — forming an address — namely `LDR (literal)` T1 (`01001x`,
//! A7.7.44), `ADR` T1 (`10100x`, A7.7.7) and `ADD (SP plus immediate)` T1
//! (`10101x`, A7.7.5). The first two compute their address by the same
//! `Align(PC,4)` rule, so keeping them beside each other keeps that rule in one
//! place instead of two.
//!
//! Every one of the 26,624 halfwords in the range decodes. Table A5-5 leaves no
//! `opA`/`opB` hole; every register field is three bits wide and so cannot name
//! anything but `r0`–`r7`; no immediate value is reserved. There is no
//! UNDEFINED and no UNPREDICTABLE encoding in this space — `LDR (literal)`'s
//! `t == 15` caveat cannot arise from a 3-bit `Rt` — so [`decode`] fails only
//! its range check, and [`encode`] is a total inverse of it.
//!
//! # Scaling is the whole trick
//!
//! Each immediate-offset form scales its immediate by its own access size, and
//! the encoded field is five bits in every case, so the *byte* range differs
//! per row: 0–124 for the word forms, 0–62 for the halfword forms, 0–31 for the
//! byte forms. [`Mem::offset`] is therefore stored already multiplied out, in
//! bytes. That is the point of the type: a consumer computing an effective
//! address must not have to know which row of Table A5-5 it came from, and a
//! decoder that forwarded the raw `imm5` would silently make `ldr r0,[r1,#4]`
//! and `ldrb r0,[r1,#4]` look like the same offset when they are not.
//!
//! [`Mem::add`] is `true` on every operand this module builds. There is no `U`
//! bit in 16 bits, so `#-0` — a distinct encoding wherever `U` exists — is not
//! one of this space's spellings, and [`encode`] refuses it rather than
//! quietly writing the `#0` halfword instead.
//!
//! # `Align(PC, 4)`
//!
//! Thumb's pc reads as the instruction's address plus four, and the pc-relative
//! forms here additionally force that value word-aligned: `base = Align(PC,4)`
//! in the operation pseudocode of both `LDR (literal)` (A7.7.44) and `ADR`
//! (A7.7.7), defined in A4.2.2 as "its PC value ANDed with `0xFFFFFFFC`". The
//! two steps do not commute. At a 4-aligned address the `AND` changes nothing,
//! so a decoder that omits it still looks right; at a 2-mod-4 address it
//! subtracts two, and every resolved literal address comes out two too high.
//! Half of all real instructions sit at a 2-mod-4 address. [`literal_base`] is
//! the single place that arithmetic happens, and [`encode`] re-derives the
//! immediate from the resolved [`Operand::Target`] and cross-checks it against
//! the syntactic `[pc, #imm]` — so a mistake in it cannot round-trip.
//!
//! Both pc-relative forms also carry an [`Operand::Target`] holding the
//! absolute address, precisely so that no consumer redoes any of the above.
//!
//! # What this group does not have
//!
//! No pre- or post-indexed form and no writeback: [`Mem::mode`] is
//! [`AddrMode::Offset`] for all sixteen rows, because the 16-bit encoding space
//! has nowhere to put a `P`/`W` bit. No negative offsets, for the same reason —
//! there is no `U` bit either. No `S` bit, so `sets_flags` is `false`
//! throughout; [`Insn`]'s `Display` appends an `"s"` when it is set, and a
//! stray `true` here would print `ldrs`. And no 16-bit signed-immediate load:
//! `LDRSB` and `LDRSH` appear only in the register-offset row, so a 16-bit
//! decode that produced `ldrsb r0,[r1,#4]` would be inventing an encoding.

use super::{AddrMode, Insn, Mem, Operand, Operands, Reg, Width};

/// The register-offset row of Table A5-5 (`opA == 0b0101`), indexed by
/// `opB` = `hw1[11:9]`.
///
/// The order is not alphabetical and not store-then-load: it is Arm's, and the
/// two signed loads sit at `011` and `111` with no signed *store* counterpart,
/// because signedness is a property of the widening a load does and a store has
/// nothing to widen.
const REG_OFFSET: [&str; 8] = [
    "str",   // 000 STR (register) T1, A7.7.158
    "strh",  // 001 STRH (register) T1, A7.7.171
    "strb",  // 010 STRB (register) T1, A7.7.163
    "ldrsb", // 011 LDRSB (register) T1, A7.7.61
    "ldr",   // 100 LDR (register) T1, A7.7.45
    "ldrh",  // 101 LDRH (register) T1, A7.7.57
    "ldrb",  // 110 LDRB (register) T1, A7.7.49
    "ldrsh", // 111 LDRSH (register) T1, A7.7.65
];

/// The base-register immediate-offset rows of Table A5-5, indexed by
/// `opA - 0b0110`: the store mnemonic, the load mnemonic (`opA[0]`, i.e.
/// `hw1[11]`, selects), and the scale the architecture applies to `imm5`.
///
/// The scale *is* the access size in bytes, which is why it also serves as the
/// modulus [`encode`] checks a byte offset against.
const IMM_OFFSET: [(&str, &str, u32); 3] = [
    ("str", "ldr", 4),   // 0110 0xx / 0110 1xx — A7.7.161 / A7.7.43, imm5*4
    ("strb", "ldrb", 1), // 0111 0xx / 0111 1xx — A7.7.162 / A7.7.48, imm5*1
    ("strh", "ldrh", 2), // 1000 0xx / 1000 1xx — A7.7.170 / A7.7.56, imm5*2
];

/// `Align(PC, 4)` for the instruction at `addr` (A4.2.2): the pc value —
/// `addr + 4` in Thumb — forced word-aligned.
///
/// Wrapping, not saturating: an instruction at `0xFFFF_FFFE` is pathological
/// but its pc value is architecturally defined to wrap, and panicking on it
/// would make the decoder unusable for scanning arbitrary bytes.
fn literal_base(addr: u32) -> u32 {
    addr.wrapping_add(4) & !3
}

/// Build the shape every instruction in this group shares: narrow, no
/// condition of its own, no flag update, no explicit width suffix.
fn narrow(mnemonic: &'static str, encoding: &'static str, addr: u32, operands: Operands) -> Insn {
    Insn {
        mnemonic,
        encoding,
        addr,
        width: Width::Narrow,
        cond: None,
        sets_flags: false,
        explicit_width: false,
        operands,
    }
}

/// `<Rt>, [<Rn>, …]` — the operand pair every transfer in this group prints,
/// assembled from a register and a fully-formed memory operand.
fn transfer(rt: Reg, mem: Mem) -> Operands {
    let mut operands = Operands::new();
    operands.push(Operand::Reg(rt));
    operands.push(Operand::Mem(mem));
    operands
}

/// Decode an instruction in this group, or `None` if `hw1`/`hw2` do not
/// belong to it.
///
/// `hw2` is unused: every encoding here is 16-bit. `addr` is consulted only by
/// the two pc-relative forms, and only through [`literal_base`].
pub(crate) fn decode(hw1: u16, _hw2: u16, addr: u32) -> Option<Insn> {
    // `hw1[15:11]` separates every row of the group, including the load/store
    // bit of the immediate forms, so one match covers the whole space.
    match hw1 >> 11 {
        0b01001 => Some(decode_literal(hw1, addr)),
        0b01010 | 0b01011 => Some(decode_register(hw1, addr)),
        0b01100..=0b10001 => Some(decode_immediate(hw1, addr)),
        0b10010 | 0b10011 => Some(decode_sp_relative(hw1, addr)),
        0b10100 => Some(decode_adr(hw1, addr)),
        0b10101 => Some(decode_add_sp(hw1, addr)),
        _ => None,
    }
}

/// `LDR (literal)` T1 — `01001 Rt(3) imm8`, A7.7.44.
///
/// Carries both the syntactic `[pc, #imm]` and the resolved absolute address.
/// The manual's own normal syntax is `LDR<c> <Rt>,<label>`, which a
/// disassembler cannot print without a symbol table; the pair here is that
/// syntax's two halves, and together they are what an assembler needs to
/// reproduce the instruction at a different address.
fn decode_literal(hw1: u16, addr: u32) -> Insn {
    let rt = Reg(((hw1 >> 8) & 0b111) as u8);
    let offset = (hw1 & 0xFF) as u32 * 4;
    let mut operands = transfer(
        rt,
        Mem {
            base: Reg::PC,
            index: None,
            offset,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        },
    );
    operands.push(Operand::Target(literal_base(addr).wrapping_add(offset)));
    narrow("ldr", "T1", addr, operands)
}

/// The register-offset row — `0101 opB(3) Rm(3) Rn(3) Rt(3)`, Table A5-5.
///
/// The index carries no [`super::Shift`]: `shift_n = 0` in all eight
/// encoding-specific operations, and UAL spells them `<Rt>,[<Rn>,<Rm>]` with no
/// shift operand. The 32-bit T2 forms are the ones that can scale an index.
fn decode_register(hw1: u16, addr: u32) -> Insn {
    let opb = ((hw1 >> 9) & 0b111) as usize;
    let rm = Reg(((hw1 >> 6) & 0b111) as u8);
    let rn = Reg(((hw1 >> 3) & 0b111) as u8);
    let rt = Reg((hw1 & 0b111) as u8);
    let operands = transfer(
        rt,
        Mem {
            base: rn,
            index: Some((rm, None)),
            offset: 0,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        },
    );
    narrow(REG_OFFSET[opb], "T1", addr, operands)
}

/// The base-register immediate-offset rows — `011x`/`1000` `imm5(5) Rn(3)
/// Rt(3)`, Table A5-5, with the offset multiplied out to bytes.
fn decode_immediate(hw1: u16, addr: u32) -> Insn {
    let (store, load, scale) = IMM_OFFSET[(hw1 >> 12) as usize - 0b0110];
    let mnemonic = if hw1 & 0x0800 != 0 { load } else { store };
    let offset = ((hw1 >> 6) & 0x1F) as u32 * scale;
    let rn = Reg(((hw1 >> 3) & 0b111) as u8);
    let rt = Reg((hw1 & 0b111) as u8);
    let operands = transfer(
        rt,
        Mem {
            base: rn,
            index: None,
            offset,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        },
    );
    narrow(mnemonic, "T1", addr, operands)
}

/// `STR`/`LDR (immediate)` T2 — `1001 L Rt(3) imm8`, A7.7.161 / A7.7.43.
///
/// The `T2` encoding name is not a formality: the same mnemonic, the same
/// operand shape and a base of `sp` also describe encoding T1 with `Rn == 13`,
/// which is *not* encodable in 16 bits (T1's `Rn` is three bits). Recording
/// which encoding this was is what lets [`encode`] pick the `1001` row without
/// guessing.
fn decode_sp_relative(hw1: u16, addr: u32) -> Insn {
    let mnemonic = if hw1 & 0x0800 != 0 { "ldr" } else { "str" };
    let rt = Reg(((hw1 >> 8) & 0b111) as u8);
    let operands = transfer(
        rt,
        Mem {
            base: Reg::SP,
            index: None,
            offset: u32::from(hw1 & 0xFF) * 4,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        },
    );
    narrow(mnemonic, "T2", addr, operands)
}

/// `ADR` T1 — `10100 Rd(3) imm8`, A7.7.7.
///
/// Printed `adr <Rd>, <label>`, so the operands are the destination and the
/// resolved address: the `add <Rd>, pc, #<const>` spelling is the manual's
/// *alternative* syntax, which A7.7.7's own note recommends avoiding. No
/// [`Operand::Mem`] is emitted because `ADR` touches no memory — it is
/// arithmetic on `Align(PC,4)`.
fn decode_adr(hw1: u16, addr: u32) -> Insn {
    let rd = Reg(((hw1 >> 8) & 0b111) as u8);
    let target = literal_base(addr).wrapping_add((hw1 & 0xFF) as u32 * 4);
    let mut operands = Operands::new();
    operands.push(Operand::Reg(rd));
    operands.push(Operand::Target(target));
    narrow("adr", "T1", addr, operands)
}

/// `ADD (SP plus immediate)` T1 — `10101 Rd(3) imm8`, A7.7.5.
///
/// Syntax `ADD<c> <Rd>,SP,#<imm8>`, where A7.7.5's `<const>` description gives
/// the permitted values as multiples of four in the range 0–1020 — so the
/// printed immediate is the byte value, not the encoded field. No pc and no
/// `Align` here, and `setflags = FALSE` in the encoding-specific operation, so
/// this is `add`, never `adds`.
fn decode_add_sp(hw1: u16, addr: u32) -> Insn {
    let rd = Reg(((hw1 >> 8) & 0b111) as u8);
    let mut operands = Operands::new();
    operands.push(Operand::Reg(rd));
    operands.push(Operand::Reg(Reg::SP));
    operands.push(Operand::Imm((hw1 & 0xFF) as i64 * 4));
    narrow("add", "T1", addr, operands)
}

/// The 3-bit field value for a low-register operand, or `None` for anything
/// else — every explicit register field in this group is three bits wide, so a
/// high register is not merely unusual here, it is unencodable.
fn low_reg(op: Option<Operand>) -> Option<u16> {
    match op {
        Some(Operand::Reg(r)) if r.is_low() => Some(r.num() as u16),
        _ => None,
    }
}

/// The `imm8` field for a byte quantity the architecture encodes as
/// `imm8:'00'`, or `None` if it is not a multiple of four or does not fit.
///
/// Shared by all four `*4`-scaled 8-bit forms: `LDR (literal)`, `ADR`,
/// `ADD (SP plus immediate)` and the SP-relative transfers.
fn scaled_imm8(bytes: u32) -> Option<u16> {
    if bytes % 4 != 0 || bytes / 4 > 0xFF {
        return None;
    }
    Some((bytes / 4) as u16)
}

/// Re-encode an instruction this module decoded, back to its halfword.
///
/// Deliberately strict, because these mnemonics are the most heavily reused in
/// the instruction set: `ldr` alone names five 16-bit and four 32-bit
/// encodings. A match therefore requires the narrow width, the exact encoding
/// name [`decode`] recorded, the exact operand count and shape, low registers
/// in every explicit field, an offset that is a multiple of the access size and
/// in range, and — for the pc-relative forms — a [`Operand::Target`] that is
/// consistent with `insn.addr` under [`literal_base`]. `cond` is not consulted:
/// the halfword has no condition field, and an instruction made conditional by
/// an enclosing `IT` block encodes identically.
///
/// `insn.addr` is load-bearing here. `ADR` carries no immediate at all — only
/// the resolved address — so its `imm8` can be recovered in no other way.
pub(crate) fn encode(insn: &Insn) -> Option<u16> {
    if insn.width != Width::Narrow || insn.sets_flags || insn.explicit_width {
        return None;
    }
    match insn.mnemonic {
        "adr" => encode_adr(insn),
        "add" => encode_add_sp(insn),
        _ => encode_transfer(insn),
    }
}

/// `ADR` T1: `10100 Rd(3) imm8`, with `imm8` recovered from the resolved
/// target relative to `Align(PC,4)`.
fn encode_adr(insn: &Insn) -> Option<u16> {
    if insn.encoding != "T1" || insn.operands.len() != 2 {
        return None;
    }
    let rd = low_reg(insn.operands.get(0))?;
    let target = match insn.operands.get(1) {
        Some(Operand::Target(t)) => t,
        _ => return None,
    };
    // T1 cannot subtract: a target below Align(PC,4) is encoding T2's job.
    let imm8 = scaled_imm8(target.checked_sub(literal_base(insn.addr))?)?;
    Some(0xA000 | (rd << 8) | imm8)
}

/// `ADD (SP plus immediate)` T1: `10101 Rd(3) imm8`.
fn encode_add_sp(insn: &Insn) -> Option<u16> {
    if insn.encoding != "T1" || insn.operands.len() != 3 {
        return None;
    }
    let rd = low_reg(insn.operands.get(0))?;
    if insn.operands.get(1) != Some(Operand::Reg(Reg::SP)) {
        return None;
    }
    let imm = match insn.operands.get(2) {
        Some(Operand::Imm(v)) => u32::try_from(v).ok()?,
        _ => return None,
    };
    Some(0xA800 | (rd << 8) | scaled_imm8(imm)?)
}

/// Every row that moves data: `<Rt>` and one [`Operand::Mem`], dispatched on
/// the shape of that memory operand rather than on the mnemonic, since the base
/// register is what distinguishes the literal, SP-relative and plain
/// immediate-offset forms from each other.
fn encode_transfer(insn: &Insn) -> Option<u16> {
    let rt = low_reg(insn.operands.get(0))?;
    let mem = match insn.operands.get(1) {
        Some(Operand::Mem(m)) => m,
        _ => return None,
    };
    // Nothing in the 16-bit space writes its base back.
    if mem.mode != AddrMode::Offset {
        return None;
    }

    if let Some((rm, shift)) = mem.index {
        if shift.is_some() || mem.offset != 0 || !mem.add || insn.operands.len() != 2 {
            return None;
        }
        if insn.encoding != "T1" || !mem.base.is_low() || !rm.is_low() {
            return None;
        }
        let opb = REG_OFFSET.iter().position(|m| *m == insn.mnemonic)? as u16;
        return Some(
            0x5000 | (opb << 9) | ((rm.num() as u16) << 6) | ((mem.base.num() as u16) << 3) | rt,
        );
    }

    // No `U` bit anywhere in this group, so a subtracting offset — `#-0`
    // included — is unencodable.
    if !mem.add {
        return None;
    }
    let offset = mem.offset;

    if mem.base == Reg::PC {
        // `LDR (literal)` T1: Rt, the syntactic [pc, #imm], and the target.
        if insn.mnemonic != "ldr" || insn.encoding != "T1" || insn.operands.len() != 3 {
            return None;
        }
        let target = match insn.operands.get(2) {
            Some(Operand::Target(t)) => t,
            _ => return None,
        };
        // The two views of the same address must agree. This is the check that
        // fails loudly if `Align(PC,4)` is ever computed wrongly, because the
        // two are derived by different routes.
        if target != literal_base(insn.addr).wrapping_add(offset) {
            return None;
        }
        return Some(0x4800 | (rt << 8) | scaled_imm8(offset)?);
    }

    if mem.base == Reg::SP {
        // `STR`/`LDR (immediate)` T2, the SP-relative row.
        if insn.encoding != "T2" || insn.operands.len() != 2 {
            return None;
        }
        let load = match insn.mnemonic {
            "ldr" => 1u16,
            "str" => 0u16,
            _ => return None,
        };
        return Some(0x9000 | (load << 11) | (rt << 8) | scaled_imm8(offset)?);
    }

    // The base-register immediate-offset rows.
    if insn.encoding != "T1" || insn.operands.len() != 2 || !mem.base.is_low() {
        return None;
    }
    let (row, load) = IMM_OFFSET
        .iter()
        .enumerate()
        .find_map(|(i, (store, load, _))| {
            if *store == insn.mnemonic {
                Some((i, 0u16))
            } else if *load == insn.mnemonic {
                Some((i, 1u16))
            } else {
                None
            }
        })?;
    let scale = IMM_OFFSET[row].2;
    if offset % scale != 0 {
        return None;
    }
    let imm5 = offset / scale;
    if imm5 > 0x1F {
        return None;
    }
    let opa = 0b0110 + row as u16;
    Some((opa << 12) | (load << 11) | ((imm5 as u16) << 6) | ((mem.base.num() as u16) << 3) | rt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::{Shift, ShiftAmount, ShiftKind};

    /// The first and last halfword `super::super::decode_halfwords` routes to
    /// this module: `hw1[15:10]` in `0b010010..=0b100111` (0x4800..=0x9FFF) then
    /// `0b101000..=0b101011` (0xA000..=0xAFFF), which is one contiguous run.
    const FIRST: u16 = 0x4800;
    /// The last halfword in the group's range.
    const LAST: u16 = 0xAFFF;

    /// A 4-aligned address, where `Align(PC,4)` is a no-op.
    const ALIGNED: u32 = 0x1000;
    /// A 2-mod-4 address, where `Align(PC,4)` subtracts two from the pc value.
    const UNALIGNED: u32 = 0x1002;

    /// The printed UAL form of `hw1`, decoded at `addr`.
    fn ual(hw1: u16, addr: u32) -> String {
        decode(hw1, 0, addr)
            .expect("every halfword in A5.2.4 decodes")
            .to_string()
    }

    /// The memory operand of a decoded transfer, printed on its own — the
    /// `[<Rn>, …]` half of the syntax lines in A7.7.
    ///
    /// Searched for rather than taken from a fixed index, so that "this
    /// instruction has no memory operand" is something the assertion below can
    /// say rather than a panic arm that never runs.
    fn mem_of(hw1: u16, addr: u32) -> String {
        let mem = decode(hw1, 0, addr)
            .expect("every halfword in A5.2.4 decodes")
            .operands
            .as_slice()
            .find_map(|o| match o {
                Operand::Mem(m) => Some(m.to_string()),
                _ => None,
            });
        mem.unwrap_or_else(String::new)
    }

    #[test]
    fn group_is_fully_allocated_and_round_trips_at_both_alignments() {
        // Table A5-5 leaves no hole in this group, stated over the whole range
        // rather than as a per-halfword branch that can never be taken.
        let holes: Vec<u16> = (FIRST..=LAST)
            .filter(|hw1| decode(*hw1, 0, ALIGNED).is_none())
            .collect();
        assert_eq!(holes, Vec::new(), "Table A5-5 leaves no hole");

        let mut decoded = 0usize;
        for hw1 in FIRST..=LAST {
            for addr in [ALIGNED, UNALIGNED] {
                let insn = decode(hw1, 0, addr).expect("the group is fully allocated");
                decoded += 1;
                assert_eq!(insn.width, Width::Narrow, "{hw1:#06x}");
                assert_eq!(insn.len(), 2, "{hw1:#06x}");
                assert_eq!(insn.addr, addr, "{hw1:#06x}");
                assert!(insn.cond.is_none(), "{hw1:#06x} carries no condition");
                // A5.2.4 has no `S` bit; `Display` would print `ldrs`.
                assert!(!insn.sets_flags, "{hw1:#06x} must not print an S suffix");
                assert!(!insn.explicit_width, "{hw1:#06x}");
                for op in insn.operands.as_slice() {
                    if let Operand::Mem(m) = op {
                        // No `P`/`W` bits in 16 bits, and no `U` bit either,
                        // so every offset adds and no `#-0` can appear.
                        assert_eq!(m.mode, AddrMode::Offset, "{hw1:#06x}");
                        assert!(m.add, "{hw1:#06x}");
                        assert_eq!(m.align, 0, "{hw1:#06x}");
                        // Signed loads exist only in the register-offset row.
                        if matches!(insn.mnemonic, "ldrsb" | "ldrsh") {
                            assert!(m.index.is_some(), "{hw1:#06x} signed 16-bit immediate load");
                        }
                    }
                }
                assert_eq!(
                    encode(&insn),
                    Some(hw1),
                    "round-trip of {hw1:#06x} at {addr:#x}"
                );
            }
            // `Align(PC,4)` maps an address and that address plus two onto the
            // same word, so a pc-relative form resolves to the *same* absolute
            // address at both. A decoder that dropped the `& !3` would report
            // two different ones.
            assert_eq!(
                decode(hw1, 0, ALIGNED).unwrap().branch_target(),
                decode(hw1, 0, UNALIGNED).unwrap().branch_target(),
                "Align(PC,4) of {hw1:#06x}"
            );
        }
        // 0xAFFF - 0x4800 + 1 = 0x6800 halfwords, every one of them allocated,
        // decoded at two alignments each.
        assert_eq!(decoded, 2 * 0x6800);
    }

    #[test]
    fn outside_the_group_is_not_ours() {
        // One below: special data / branch-and-exchange (A5.2.3).
        assert!(decode(0x47FF, 0, 0).is_none());
        // One above: miscellaneous 16-bit (A5.2.5).
        assert!(decode(0xB000, 0, 0).is_none());
    }

    #[test]
    fn register_offset_row_prints_as_rt_rn_rm() {
        // Rm = r2, Rn = r1, Rt = r0, so the three fields are distinguishable:
        // `0101 opB 010 001 000`.
        let hw = |opb: u16| 0x5000 | (opb << 9) | (2 << 6) | (1 << 3);
        // Table A5-5, `opA == 0b0101`, and A7.7's `<Rt>,[<Rn>,<Rm>]`.
        assert_eq!(ual(hw(0b000), 0), "str r0, [r1, r2]");
        assert_eq!(ual(hw(0b001), 0), "strh r0, [r1, r2]");
        assert_eq!(ual(hw(0b010), 0), "strb r0, [r1, r2]");
        assert_eq!(ual(hw(0b011), 0), "ldrsb r0, [r1, r2]");
        assert_eq!(ual(hw(0b100), 0), "ldr r0, [r1, r2]");
        assert_eq!(ual(hw(0b101), 0), "ldrh r0, [r1, r2]");
        assert_eq!(ual(hw(0b110), 0), "ldrb r0, [r1, r2]");
        assert_eq!(ual(hw(0b111), 0), "ldrsh r0, [r1, r2]");
    }

    #[test]
    fn immediate_rows_scale_by_access_size() {
        // The same encoded `imm5 == 1` in every row, so only the scale differs.
        // `Rn = r1`, `Rt = r0`: `opA 00001 001 000`.
        let hw = |opa: u16, load: u16| (opa << 12) | (load << 11) | (1 << 6) | (1 << 3);
        assert_eq!(ual(hw(0b0110, 0), 0), "str r0, [r1, #4]");
        assert_eq!(ual(hw(0b0110, 1), 0), "ldr r0, [r1, #4]");
        assert_eq!(ual(hw(0b0111, 0), 0), "strb r0, [r1, #1]");
        assert_eq!(ual(hw(0b0111, 1), 0), "ldrb r0, [r1, #1]");
        assert_eq!(ual(hw(0b1000, 0), 0), "strh r0, [r1, #2]");
        assert_eq!(ual(hw(0b1000, 1), 0), "ldrh r0, [r1, #2]");
        // The SP-relative row scales by four and takes an 8-bit field, so the
        // same *encoded* 1 is again four bytes: `1001 L 000 00000001`.
        assert_eq!(ual(0x9001, 0), "str r0, [sp, #4]");
        assert_eq!(ual(0x9801, 0), "ldr r0, [sp, #4]");
        // `[<Rn>{,#<imm5>}]`: the offset is syntactically optional, so a zero
        // one is not printed.
        assert_eq!(ual(0x6008, 0), "str r0, [r1]");
        assert_eq!(ual(0x9000, 0), "str r0, [sp]");
    }

    #[test]
    fn immediate_rows_reach_the_top_of_their_range() {
        // imm5 = 31 in each row, plus imm8 = 255 in the SP-relative one.
        let hw = |opa: u16, load: u16| (opa << 12) | (load << 11) | (0x1F << 6) | (1 << 3);
        assert_eq!(ual(hw(0b0110, 0), 0), "str r0, [r1, #124]");
        assert_eq!(ual(hw(0b0110, 1), 0), "ldr r0, [r1, #124]");
        assert_eq!(ual(hw(0b0111, 0), 0), "strb r0, [r1, #31]");
        assert_eq!(ual(hw(0b0111, 1), 0), "ldrb r0, [r1, #31]");
        assert_eq!(ual(hw(0b1000, 0), 0), "strh r0, [r1, #62]");
        assert_eq!(ual(hw(0b1000, 1), 0), "ldrh r0, [r1, #62]");
        assert_eq!(ual(0x98FF, 0), "ldr r0, [sp, #1020]");
        assert_eq!(ual(0x90FF, 0), "str r0, [sp, #1020]");
    }

    #[test]
    fn literal_load_resolves_against_aligned_pc() {
        // `ldr r3, [pc, #16]`: 0x4800 | 3 << 8 | 4.
        let hw = 0x4B04;
        // At 0x102 the pc value is 0x106, and Align(PC,4) is 0x104.
        assert_eq!(mem_of(hw, 0x102), "[pc, #16]");
        assert_eq!(decode(hw, 0, 0x102).unwrap().branch_target(), Some(0x114));
        // At 0x104 it is 0x108 — a different literal, four bytes further on.
        assert_eq!(decode(hw, 0, 0x104).unwrap().branch_target(), Some(0x118));
        // 0x102 and 0x100 share a word and so share a literal address.
        assert_eq!(decode(hw, 0, 0x100).unwrap().branch_target(), Some(0x114));
        // Both operands are present, in `<Rt>` then memory order, with the
        // resolved address last.
        let insn = decode(hw, 0, 0x102).unwrap();
        assert_eq!(insn.mnemonic, "ldr");
        assert_eq!(insn.encoding, "T1");
        assert_eq!(insn.operands.len(), 3);
        assert_eq!(insn.operands.get(0), Some(Operand::Reg(Reg(3))));
        assert_eq!(insn.operands.get(2), Some(Operand::Target(0x114)));
        assert_eq!(insn.to_string(), "ldr r3, [pc, #16], 0x114");
        // A zero offset is printed on this form, not omitted: the bare
        // `[pc]` does not say which encoding it came from, and an assembler
        // reads it back as the 32-bit `LDR (literal)` T2 — different bytes.
        // The LLVM conformance sweep caught this on all eight of `0x4800`,
        // `0x4900` … `0x4F00` (A7.7.44).
        //
        // The rule belongs to the *instruction*, not to the operand: a `Mem`
        // of `[pc]` is also what `strex pc, r0, [pc]` carries, and that one is
        // unambiguous and must stay bare. So the bare operand still prints
        // bare, and `Insn`'s `Display` — which knows the encoding is narrow
        // and that a resolved literal address sits beside it — is what forces
        // the displacement.
        assert_eq!(mem_of(0x4B00, 0x102), "[pc]");
        assert_eq!(
            decode(0x4B00, 0, 0x102).unwrap().to_string(),
            "ldr r3, [pc, #0], 0x104"
        );
        assert_eq!(
            decode(0x4B00, 0, 0x102).unwrap().branch_target(),
            Some(0x104)
        );
        // The top of the range: imm8 = 255 is 1020 bytes.
        assert_eq!(mem_of(0x4BFF, 0), "[pc, #1020]");
    }

    #[test]
    fn adr_and_add_sp_print_their_ual_forms() {
        // `ADR<c> <Rd>,<label>` (A7.7.7): 0xA000 | 0 << 8 | 2, so the label is
        // Align(PC,4) + 8.
        assert_eq!(ual(0xA002, 0x1000), "adr r0, 0x100c");
        assert_eq!(ual(0xA002, 0x1002), "adr r0, 0x100c");
        assert_eq!(ual(0xA002, 0x1004), "adr r0, 0x1010");
        assert_eq!(ual(0xA7FF, 0), "adr r7, 0x400");
        // `ADD<c> <Rd>,SP,#<imm8>` (A7.7.5), with the immediate in bytes: no pc,
        // so the address is irrelevant.
        assert_eq!(ual(0xA801, 0x1002), "add r0, sp, #4");
        assert_eq!(ual(0xAFFF, 0), "add r7, sp, #0x3fc");
        assert_eq!(ual(0xA800, 0), "add r0, sp, #0");
        // Neither sets flags: `add`, not `adds`.
        assert!(!decode(0xA801, 0, 0).unwrap().sets_flags);
    }

    #[test]
    fn encode_rejects_what_this_group_cannot_hold() {
        let base = decode(0x6048, 0, 0).unwrap(); // str r0, [r1, #4]
        assert_eq!(encode(&base), Some(0x6048));

        // A mnemonic from another group.
        let mut foreign = base;
        foreign.mnemonic = "stm";
        assert_eq!(encode(&foreign), None);

        // The 32-bit encoding of the same operation.
        let mut wide = base;
        wide.width = Width::Wide;
        assert_eq!(encode(&wide), None);

        // A flag suffix no encoding here has.
        let mut flags = base;
        flags.sets_flags = true;
        assert_eq!(encode(&flags), None);

        // Writeback, which the 16-bit space cannot express.
        let mut pre = base;
        pre.operands = transfer(
            Reg(0),
            Mem {
                base: Reg(1),
                index: None,
                offset: 4,
                add: true,
                align: 0,
                mode: AddrMode::PreIndex,
            },
        );
        assert_eq!(encode(&pre), None);

        // An offset that is not a multiple of the access size, one past the
        // top of the range, and a subtracting one — including `#-0`, which
        // there is no `U` bit here to encode.
        for (bad, add) in [(2u32, true), (128, true), (4, false), (0, false)] {
            let mut off = base;
            off.operands = transfer(
                Reg(0),
                Mem {
                    base: Reg(1),
                    index: None,
                    offset: bad,
                    add,
                    align: 0,
                    mode: AddrMode::Offset,
                },
            );
            assert_eq!(encode(&off), None, "offset {bad} add {add}");
        }

        // A high base register: `Rn` is three bits.
        let mut high = base;
        high.operands = transfer(
            Reg(8),
            Mem {
                base: Reg(9),
                index: None,
                offset: 4,
                add: true,
                align: 0,
                mode: AddrMode::Offset,
            },
        );
        assert_eq!(encode(&high), None);

        // A shifted index, which is the 32-bit T2 register form's privilege.
        let mut shifted = decode(0x5888, 0, 0).unwrap(); // ldr r0, [r1, r2]
        assert_eq!(encode(&shifted), Some(0x5888));
        shifted.operands = transfer(
            Reg(0),
            Mem {
                base: Reg(1),
                index: Some((
                    Reg(2),
                    Some(super::super::Shift {
                        kind: super::super::ShiftKind::Lsl,
                        amount: super::super::ShiftAmount::Imm(2),
                    }),
                )),
                offset: 0,
                add: true,
                align: 0,
                mode: AddrMode::Offset,
            },
        );
        assert_eq!(encode(&shifted), None);

        // A literal load whose resolved target disagrees with its own
        // `[pc, #imm]` — the inconsistency `Align(PC,4)` bugs produce.
        let mut literal = decode(0x4B04, 0, 0x102).unwrap();
        assert_eq!(encode(&literal), Some(0x4B04));
        literal.operands = {
            let mut ops = transfer(
                Reg(3),
                Mem {
                    base: Reg::PC,
                    index: None,
                    offset: 16,
                    add: true,
                    align: 0,
                    mode: AddrMode::Offset,
                },
            );
            ops.push(Operand::Target(0x116)); // would be right without the `& !3`
            ops
        };
        assert_eq!(encode(&literal), None);

        // An `ADR` whose label lies below Align(PC,4): encoding T2's job, and
        // T2 is 32-bit.
        let mut adr = decode(0xA002, 0, 0x1000).unwrap();
        assert_eq!(encode(&adr), Some(0xA002));
        adr.operands = {
            let mut ops = Operands::new();
            ops.push(Operand::Reg(Reg(0)));
            ops.push(Operand::Target(0x0FFC));
            ops
        };
        assert_eq!(encode(&adr), None);

        // `add rd, sp, #imm` outside 0-1020, or not a multiple of four.
        for bad in [1024i64, 6, -4] {
            let mut add = decode(0xA801, 0, 0).unwrap();
            let mut ops = Operands::new();
            ops.push(Operand::Reg(Reg(0)));
            ops.push(Operand::Reg(Reg::SP));
            ops.push(Operand::Imm(bad));
            add.operands = ops;
            assert_eq!(encode(&add), None, "add sp immediate {bad}");
        }

        // The SP-relative row is encoding T2; claiming T1 for it must not
        // silently re-encode as the low-register immediate row.
        let mut sp = decode(0x9801, 0, 0).unwrap();
        assert_eq!(encode(&sp), Some(0x9801));
        sp.encoding = "T1";
        assert_eq!(encode(&sp), None);
    }

    /// One case per guard in `encode`, because each guard is what keeps an
    /// instruction belonging to *another* group from being re-encoded as one
    /// of these.
    ///
    /// [`crate::isa::encode`] offers every narrow instruction to every group in
    /// turn, so all of these shapes really do arrive here: an `add` that is not
    /// SP-relative, a transfer through a high base, a `[pc, …]` that is not a
    /// literal load. A `Some` for any of them would emit a halfword that
    /// decodes as a different instruction.
    #[test]
    fn encode_declines_every_shape_that_is_not_this_groups() {
        let mem = |base: Reg, offset, add, mode| Mem {
            base,
            index: None,
            offset,
            add,
            align: 0,
            mode,
        };
        let r0 = Operand::Reg(Reg(0));
        let sp = Operand::Reg(Reg::SP);
        let ops = |items: &[Operand]| items.iter().copied().collect::<Operands>();

        // `ADR` T1 is the only `adr` here; the wide T2/T3 forms and any other
        // operand shape are declined.
        let adr = decode(0xA002, 0, 0x1000).unwrap();
        for (encoding, operands, why) in [
            ("T2", ops(&[r0, Operand::Target(0x1008)]), "T2 is 32-bit"),
            ("T1", ops(&[r0]), "a label is required"),
            (
                "T1",
                ops(&[r0, Operand::Target(0x1008), Operand::Imm(0)]),
                "two operands only",
            ),
            ("T1", ops(&[r0, Operand::Imm(8)]), "the label is resolved"),
            (
                "T1",
                ops(&[Operand::Reg(Reg(8)), Operand::Target(0x1008)]),
                "Rd is three bits",
            ),
            (
                "T1",
                ops(&[r0, Operand::Target(0x1006)]),
                "labels are word-aligned multiples of four",
            ),
        ] {
            let bad = Insn {
                encoding,
                operands,
                ..adr
            };
            assert_eq!(encode(&bad), None, "`{bad}`: {why}");
        }

        // `ADD (SP plus immediate)` T1 shares its mnemonic and encoding name
        // with `ADD (immediate)` T1 (A7.7.3), which names a register where
        // this one names the SP. Inside an IT block that one carries
        // `sets_flags == false` and so reaches this far — and must be turned
        // away here, or `addeq r0, r1, #4` re-encodes as `add r0, sp, #4`.
        let add_sp = decode(0xA801, 0, 0).unwrap();
        for (operands, why) in [
            (
                ops(&[r0, Operand::Reg(Reg(1)), Operand::Imm(4)]),
                "the second operand must be the SP",
            ),
            (ops(&[r0, sp]), "three operands"),
            (
                ops(&[r0, sp, Operand::Reg(Reg(1))]),
                "the third operand is an immediate",
            ),
            (
                ops(&[Operand::Reg(Reg(9)), sp, Operand::Imm(4)]),
                "Rd is three bits",
            ),
        ] {
            let bad = Insn { operands, ..add_sp };
            assert_eq!(encode(&bad), None, "`{bad}`: {why}");
        }

        // The encoding name and the operand count are two separate
        // conditions, and neither is implied by the other. `ADD (SP plus
        // immediate)` also has a T3 (`add.w <Rd>,SP,#<const>`) and a T4
        // (`addw`), both of which spell the same three operands and both of
        // which are four bytes long: answering for one of them with this
        // two-byte halfword would shorten the instruction in place and leave
        // two bytes of the old one behind as data. A fourth operand is the
        // other way round — the encoding name is right, the shape is not —
        // and must not be silently dropped.
        let mut renamed = add_sp;
        renamed.encoding = "T3";
        assert_eq!(encode(&renamed), None, "T3 is `add.w`, four bytes");
        let mut trailing = add_sp;
        trailing.operands = ops(&[r0, sp, Operand::Imm(4), Operand::Imm(0)]);
        assert_eq!(encode(&trailing), None, "a fourth operand is not ours");

        // The register-offset row: `[<Rn>,<Rm>]`, both low, no shift, and only
        // for the eight mnemonics of Table A5-5's `0101` row.
        let reg_off = decode(0x5088, 0, 0).unwrap(); // str r0, [r1, r2]
        assert_eq!(encode(&reg_off), Some(0x5088));
        let indexed = |base: Reg, index| {
            ops(&[
                r0,
                Operand::Mem(Mem {
                    index: Some(index),
                    ..mem(base, 0, true, AddrMode::Offset)
                }),
            ])
        };
        for (mnemonic, encoding, operands, why) in [
            (
                "strex",
                "T1",
                indexed(Reg(1), (Reg(2), None)),
                "not a row of Table A5-5",
            ),
            (
                "str",
                "T2",
                indexed(Reg(1), (Reg(2), None)),
                "T2 is the wide row",
            ),
            (
                "str",
                "T1",
                indexed(Reg(9), (Reg(2), None)),
                "Rn is three bits",
            ),
            (
                "str",
                "T1",
                indexed(Reg(1), (Reg(9), None)),
                "Rm is three bits",
            ),
            (
                "str",
                "T1",
                indexed(
                    Reg(1),
                    (
                        Reg(2),
                        Some(Shift {
                            kind: ShiftKind::Lsl,
                            amount: ShiftAmount::Imm(2),
                        }),
                    ),
                ),
                "only the wide forms scale an index",
            ),
        ] {
            let bad = Insn {
                mnemonic,
                encoding,
                operands,
                ..reg_off
            };
            assert_eq!(encode(&bad), None, "`{bad}`: {why}");
        }

        // The rest of the memory operand, one field at a time. Table A5-5's
        // `0101` row is `0101 opB Rm Rn Rt` and that is the whole halfword:
        // there is no displacement field beside `Rm` and no `U` bit, so a
        // `Mem` that carries either has no encoding here. Both would
        // otherwise come back as the plain `str r0, [r1, r2]` — the first
        // storing four bytes below where it was asked to, the second at
        // `r1 + r2` instead of `r1 - r2`.
        let indexed_mem = |offset, add| {
            ops(&[
                r0,
                Operand::Mem(Mem {
                    index: Some((Reg(2), None)),
                    ..mem(Reg(1), offset, add, AddrMode::Offset)
                }),
            ])
        };
        for (operands, why) in [
            (
                indexed_mem(4, true),
                "no field holds a displacement beside Rm",
            ),
            (
                indexed_mem(0, false),
                "no U bit: a register index is always added",
            ),
        ] {
            let bad = Insn {
                operands,
                ..reg_off
            };
            assert_eq!(encode(&bad), None, "`{bad}`: {why}");
        }

        // The pc-relative row is `LDR (literal)` T1 and nothing else: one
        // mnemonic, one encoding, and the resolved address alongside.
        let literal = decode(0x4B01, 0, 0x1000).unwrap();
        assert_eq!(encode(&literal), Some(0x4B01));
        let pc_mem = |offset| Operand::Mem(mem(Reg::PC, offset, true, AddrMode::Offset));
        for (mnemonic, encoding, operands, why) in [
            (
                "str",
                "T1",
                ops(&[r0, pc_mem(4), Operand::Target(0x1008)]),
                "there is no pc-relative store",
            ),
            (
                "ldr",
                "T2",
                ops(&[r0, pc_mem(4), Operand::Target(0x1008)]),
                "T2 is the SP-relative row",
            ),
            (
                "ldr",
                "T1",
                ops(&[r0, pc_mem(4)]),
                "the resolved address is part of the form",
            ),
            (
                "ldr",
                "T1",
                ops(&[r0, pc_mem(4), Operand::Imm(0x1008)]),
                "the third operand is a resolved target",
            ),
            (
                "ldr",
                "T1",
                ops(&[r0, pc_mem(6), Operand::Target(0x100A)]),
                "imm8:'00' is a multiple of four",
            ),
            (
                "ldr",
                "T1",
                ops(&[r0, pc_mem(1024), Operand::Target(0x1404)]),
                "imm8:'00' reaches 1020",
            ),
        ] {
            let bad = Insn {
                mnemonic,
                encoding,
                operands,
                ..literal
            };
            assert_eq!(encode(&bad), None, "`{bad}`: {why}");
        }

        // The SP-relative row carries only `LDR`/`STR` T2 — the byte and
        // halfword transfers have no SP-relative 16-bit form at all.
        let sp_rel = decode(0x9801, 0, 0).unwrap();
        for (mnemonic, offset, why) in [
            ("ldrb", 4u32, "no SP-relative byte load"),
            ("strh", 4, "no SP-relative halfword store"),
            ("ldr", 2, "imm8:'00' is a multiple of four"),
            ("ldr", 1024, "imm8:'00' reaches 1020"),
        ] {
            let bad = Insn {
                mnemonic,
                operands: ops(&[
                    r0,
                    Operand::Mem(mem(Reg::SP, offset, true, AddrMode::Offset)),
                ]),
                ..sp_rel
            };
            assert_eq!(encode(&bad), None, "`{bad}`: {why}");
        }

        // …and the base-register rows need a low base and exactly the two
        // operands of `<Rt>, [<Rn>, #<imm>]`.
        let imm_off = decode(0x6048, 0, 0).unwrap(); // str r0, [r1, #4]
        for (encoding, operands, why) in [
            (
                "T1",
                ops(&[r0, Operand::Mem(mem(Reg(9), 4, true, AddrMode::Offset))]),
                "Rn is three bits",
            ),
            (
                "T2",
                ops(&[r0, Operand::Mem(mem(Reg(1), 4, true, AddrMode::Offset))]),
                "T2 is the SP-relative row",
            ),
            (
                "T1",
                ops(&[
                    r0,
                    Operand::Mem(mem(Reg(1), 4, true, AddrMode::Offset)),
                    Operand::Imm(0),
                ]),
                "two operands only",
            ),
        ] {
            let bad = Insn {
                encoding,
                operands,
                ..imm_off
            };
            assert_eq!(encode(&bad), None, "`{bad}`: {why}");
        }
    }

    #[test]
    fn a_condition_from_an_it_block_does_not_change_the_halfword() {
        // `Decoder` fills `cond` in after the fact for instructions inside an
        // IT block; the encoding is unchanged, so `encode` must ignore it.
        let mut insn = decode(0x6848, 0, 0).unwrap(); // ldr r0, [r1, #4]
        insn.cond = Some(crate::Cond::Eq);
        assert_eq!(insn.to_string(), "ldreq r0, [r1, #4]");
        assert_eq!(encode(&insn), Some(0x6848));
    }
}
