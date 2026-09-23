//! Load/store dual or exclusive, and table branch — the 32-bit encodings with
//! `hw1[15:11] == 0b11101` and `hw1[10:4]` matching `00xx1xx` (ARM DDI 0403E.e
//! A5.3.6 and Table A5-17).
//!
//! ARM DDI 0406C A6.3.6 and Table A6-17 allocate exactly the same rows and add
//! two of their own — `LDREXD` and `STREXD`, the doubleword exclusives, which
//! no M-profile core implements. This module decodes the union, because a
//! decoder that refused them would misreport an A/R image, and each row below
//! names the profile that defines it.
//!
//! # One field layout, four opcode bits
//!
//! Every encoding in the group shares one first halfword:
//!
//! ```text
//! hw1 = 1110 100 P U 1 W L Rn
//! ```
//!
//! and Table A5-17's `op1`/`op2` are those four bits regrouped — `op1 = P:U`,
//! `op2 = W:L`. Reading them as `P`, `U`, `W` and `L` rather than as table
//! indices is what makes the table's otherwise baffling shape obvious:
//!
//! * `P`/`W` are the addressing mode of the dual transfers — `10` offset,
//!   `11` pre-indexed, `01` post-indexed. The fourth combination, `P == 0 &&
//!   W == 0`, names no addressing mode at all, and that is precisely the hole
//!   the architecture fills with the exclusives and the table branches. Both
//!   `LDRD (immediate)` (A7.7.50) and `STRD (immediate)` (A7.7.166) open with
//!   `if P == '0' && W == '0' then SEE "Related encodings"`, which is the same
//!   statement from the other side. Table A5-17's rows `0x 10`, `1x x0`,
//!   `0x 11` and `1x x1` are just "not `P == 0 && W == 0`", split by `L`.
//! * `L` is load versus store, throughout — including in the exclusive space,
//!   where it separates `STREX*` from `LDREX*`/`TBB`/`TBH`.
//! * `U` is add-versus-subtract for the dual transfers; inside the exclusive
//!   space it instead separates the plain word exclusives (`U == 0`) from the
//!   sized exclusives and the table branches (`U == 1`), which are then told
//!   apart by `op3 = hw2[7:4]`.
//!
//! The second halfword differs per row, and `(1)`/`(0)` below are the
//! manuals' SHOULD-BE-ONE and SHOULD-BE-ZERO fields:
//!
//! ```text
//! STREX    Rt Rd         imm8            A7.7.167 / A8.6.202   Armv6T2
//! LDREX    Rt (1)(1)(1)(1) imm8          A7.7.52  / A8.6.69    Armv6T2
//! STRD     Rt Rt2        imm8            A7.7.166 / A8.6.200   Armv6T2
//! LDRD     Rt Rt2        imm8            A7.7.50  / A8.6.66    Armv6T2
//! STREXB   Rt (1)(1)(1)(1) 0100 Rd       A7.7.168 / A8.6.203   Armv7
//! STREXH   Rt (1)(1)(1)(1) 0101 Rd       A7.7.169 / A8.6.205   Armv7
//! STREXD   Rt Rt2          0111 Rd       A8.6.204              Armv7 A/R only
//! TBB      (1)(1)(1)(1) (0)(0)(0)(0) 0000 Rm   A7.7.185 / A8.6.226   Armv6T2
//! TBH      (1)(1)(1)(1) (0)(0)(0)(0) 0001 Rm   A7.7.185 / A8.6.226   Armv6T2
//! LDREXB   Rt (1)(1)(1)(1) 0100 (1)(1)(1)(1)   A7.7.53 / A8.6.70    Armv7
//! LDREXH   Rt (1)(1)(1)(1) 0101 (1)(1)(1)(1)   A7.7.54 / A8.6.72    Armv7
//! LDREXD   Rt Rt2          0111 (1)(1)(1)(1)   A8.6.71               Armv7 A/R only
//! ```
//!
//! # Operand order is the thing to get wrong
//!
//! The load and store exclusives are not mirror images. From the assembler
//! syntax lines of A7.7.52 and A7.7.167:
//!
//! ```text
//! LDREX<c><q>  <Rt>, [<Rn> {,#<imm>}]
//! STREX<c><q>  <Rd>, <Rt>, [<Rn> {,#<imm>}]
//! ```
//!
//! The store carries an extra *first* operand, `<Rd>`, which receives the
//! success status (0 if memory was updated, 1 if not) — it is a destination on
//! a store. The same asymmetry runs through the sized forms
//! (`STREXB<c><q> <Rd>, <Rt>, [<Rn>]`, A7.7.168, against
//! `LDREXB<c><q> <Rt>, [<Rn>]`, A7.7.53) and through the A/R doubleword pair
//! (`STREXD<c><q> <Rd>, <Rt>, <Rt2>, [<Rn>]`, A8.6.204, four operands, against
//! `LDREXD<c><q> <Rt>, <Rt2>, [<Rn>]`, A8.6.71). Transposing `<Rd>` and `<Rt>`
//! produces text that assembles and stores the wrong register, so the tests
//! assert the operand *count* as well as the order.
//!
//! Only `STREX` and `LDREX` take an immediate: `imm8:'00'`, a multiple of four
//! in the range 0–1020. `STREXB`/`STREXH`/`STREXD` and
//! `LDREXB`/`LDREXH`/`LDREXD` have none — their operation pseudocode is a bare
//! `address = R[n]` — so their syntax is `[<Rn>]` with no optional offset, and
//! the bits an offset would occupy hold `op3` and a register instead.
//!
//! # `TBB`/`TBH` branch, but nowhere in particular
//!
//! `TBB [<Rn>, <Rm>]` and `TBH [<Rn>, <Rm>, LSL #1]` (A7.7.185) load a branch
//! length from a table at `R[n]` and add twice it to the pc. The target
//! therefore depends on memory this crate has not been given, so no
//! [`Operand::Target`] is emitted: [`Insn::branch_target`] returns `None`
//! while [`Insn::is_branch`], which special-cases the two mnemonics, returns
//! `true`. That pairing is the honest answer — "control leaves here, and I
//! cannot tell you where" — and it is what keeps a caller from treating a
//! table branch as fallthrough.
//!
//! The `LSL #1` of `TBH` is not an optional shift a disassembler may drop: it
//! is part of the syntax line, and it is real (`R[n] + LSL(R[m],1)`, because
//! the table holds halfwords). It is modelled as the index shift of the
//! [`Mem`], so it prints; `TBB`'s index carries no shift at all.
//!
//! # Scaling, the `U` bit, and `Align(PC, 4)`
//!
//! The dual transfers encode `imm32 = ZeroExtend(imm8:'00', 32)` — a byte
//! offset that is a multiple of four in the range 0–1020 — and `U` selects
//! `R[n] + imm32` or `R[n] - imm32`. [`Mem::offset`] holds that multiplied-out
//! value as an unsigned magnitude and [`Mem::add`] is `U` itself, so no
//! information is lost at zero; a consumer computing an effective address
//! reads [`Mem::displacement`] and is done.
//!
//! `LDRD` with `Rn == 1111` is `LDRD (literal)` (A7.7.51 / A8.6.67), whose
//! address is `Align(PC,4) ± imm32`: the pc value is the instruction's address
//! plus four, then forced word-aligned. Both steps matter and they do not
//! commute — at a 2-mod-4 address the alignment subtracts two, and a decoder
//! that skipped it resolves every literal two bytes too high while still
//! passing every test run at a 4-aligned address. A/R states the `Align`
//! outright; the M profile instead makes a non-word-aligned pc UNPREDICTABLE
//! for this instruction (`if PC<1:0> != '00' then UNPREDICTABLE`), so
//! computing `Align(PC,4)` agrees with A/R exactly and agrees with M wherever
//! M defines anything at all. The resolved address is emitted as an
//! [`Operand::Target`] beside the syntactic `[pc, #±imm]`, and [`encode`]
//! re-derives the immediate from it and cross-checks the two, so an alignment
//! bug cannot round-trip.
//!
//! `STRD` has no literal form — A7.7.166 makes `Rn == 15` UNPREDICTABLE — so a
//! pc-based `STRD` decodes with its `[pc, #imm]` and no target.
//!
//! # What decodes, and what does not
//!
//! Three rules, applied consistently:
//!
//! * **Representable and merely UNPREDICTABLE: decode it.** `LDRD r0, r0,
//!   [r1]` has `Rt == Rt2`, which A7.7.50 calls UNPREDICTABLE, as it does
//!   `Rt`/`Rt2` of 13 or 15, `Rn == 13` in `TBB`, and writeback onto a
//!   transfer register. None of that is UNDEFINED: the encoding exists, a real
//!   image can contain it, and a disassembler's job is to report what the bits
//!   say. All of it decodes and round-trips.
//! * **Not representable: refuse it.** The `(1)` and `(0)` fields carry no
//!   information — [`Insn`] has nowhere to put a non-nominal value — and an
//!   encoding that violates one is UNPREDICTABLE by construction. Accepting it
//!   would mean claiming "this is `ldrexb`" about bits the architecture
//!   declines to define, *and* would break the round-trip, since [`encode`]
//!   could only write the nominal pattern back. So a should-be-one field that
//!   is not all-ones, or a should-be-zero field that is not all-zeros, does not
//!   decode.
//! * **`#-0` is its own encoding, and is kept as one.** `U == 0` with
//!   `imm8 == 0` is a *defined* dual encoding — A7.7.50 says in as many words
//!   that "different instructions are generated for `#0` and `#-0`", and
//!   A7.7.51 lists `LDRD<c> <Rt>,<Rt2>,[PC,#-0]` as a special case. It denotes
//!   the same address as `#0`, which is why an earlier revision of this module
//!   canonicalised it away: [`Mem::offset`] was an `i32`, and an `i32` has no
//!   negative zero. It is now a magnitude beside [`Mem::add`], so the two
//!   spellings are two [`Mem`] values, print as `[r2]` and `[r2, #-0]`, and
//!   each re-encodes to the halfword it came from. Every encoding in this
//!   group now round-trips to itself; there is no lossy case left.
//!
//! # Flags, width and condition
//!
//! Nothing here has an `S` bit, so `sets_flags` is `false` throughout —
//! [`Insn`]'s `Display` appends an `"s"` when it is set, and a stray `true`
//! would print `ldrds`. Nothing here has a condition field either; a member of
//! an IT block gets its condition filled in by [`super::Decoder`] and encodes
//! identically, so [`encode`] ignores `cond`.
//!
//! Every encoding is [`Width::Wide`], and `explicit_width` is `false` for all
//! of them. The `.w` suffix exists to tell an assembler which of two encodings
//! of the same operation to pick; no operation in this group has a 16-bit
//! encoding, so there is nothing to disambiguate and the manuals' syntax lines
//! carry only the optional `<q>`. Printing `ldrd.w` would be a suffix no
//! assembler needs and no listing shows.

use super::{AddrMode, Insn, Mem, Operand, Operands, Reg, Shift, ShiftAmount, ShiftKind, Width};

/// The bits of `hw1` that are fixed for the whole group, as a mask:
/// `hw1[15:11]` (the 32-bit prefix `11101`), `hw1[10:9]` and `hw1[6]`, which
/// together are Table A5-17's `00xx1xx`.
const HW1_MASK: u16 = 0xFE40;

/// The value [`HW1_MASK`] must select: `1110 1000 01xx xxxx`.
const HW1_FIXED: u16 = 0xE840;

/// `op3 == 0b0100` — the byte-sized exclusives, `STREXB`/`LDREXB`.
const OP3_BYTE: u16 = 0b0100;

/// `op3 == 0b0101` — the halfword-sized exclusives, `STREXH`/`LDREXH`.
const OP3_HALF: u16 = 0b0101;

/// `op3 == 0b0111` — the doubleword exclusives, `STREXD`/`LDREXD`. Table A6-17
/// only: the M profile leaves this `op3` value UNDEFINED.
const OP3_DOUBLE: u16 = 0b0111;

/// `Align(PC, 4)` for the instruction at `addr` (A4.2.2): Thumb's pc value,
/// which is the instruction's address plus four, forced word-aligned.
///
/// Wrapping, not saturating: an instruction sitting at the very top of the
/// address space still has an architecturally-defined (wrapping) pc value, and
/// a decoder that panicked on one would be useless for scanning arbitrary
/// bytes.
fn literal_base(addr: u32) -> u32 {
    addr.wrapping_add(4) & !3
}

/// Build the shape every instruction in this group shares: wide, encoding
/// `T1` (the only one any of these mnemonics has in Thumb), no condition of
/// its own, no flag update, no explicit width suffix.
fn wide(mnemonic: &'static str, addr: u32, operands: Operands) -> Insn {
    Insn {
        mnemonic,
        encoding: "T1",
        addr,
        width: Width::Wide,
        cond: None,
        sets_flags: false,
        explicit_width: false,
        operands,
    }
}

/// `[<Rn>{, #<imm>}]` — base plus constant, no index, no writeback. The
/// offset is a magnitude; every caller here adds.
fn offset_mem(base: Reg, offset: u32) -> Mem {
    Mem {
        base,
        index: None,
        offset,
        add: true,
        align: 0,
        mode: AddrMode::Offset,
    }
}

/// `<Rd>, <Rt>{, <Rt2>}, [<Rn>]` — the store-exclusive operand order, status
/// register first (A7.7.167/A7.7.168/A7.7.169, A8.6.204).
fn store_excl(rd: Reg, rt: Reg, rt2: Option<Reg>, rn: Reg) -> Operands {
    let mut operands = Operands::new();
    operands.push(Operand::Reg(rd));
    operands.push(Operand::Reg(rt));
    if let Some(rt2) = rt2 {
        operands.push(Operand::Reg(rt2));
    }
    operands.push(Operand::Mem(offset_mem(rn, 0)));
    operands
}

/// `<Rt>{, <Rt2>}, [<Rn>]` — the load-exclusive operand order, with no status
/// register (A7.7.52/A7.7.53/A7.7.54, A8.6.71).
fn load_excl(rt: Reg, rt2: Option<Reg>, rn: Reg) -> Operands {
    let mut operands = Operands::new();
    operands.push(Operand::Reg(rt));
    if let Some(rt2) = rt2 {
        operands.push(Operand::Reg(rt2));
    }
    operands.push(Operand::Mem(offset_mem(rn, 0)));
    operands
}

/// Decode an instruction in this group, or `None` if `hw1`/`hw2` do not
/// belong to it — or if they land on one of Table A5-17's UNDEFINED holes, or
/// violate a should-be-one/should-be-zero field (see the module documentation).
///
/// `addr` is consulted only by `LDRD (literal)`, and only through
/// [`literal_base`].
pub(crate) fn decode(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 & HW1_MASK != HW1_FIXED {
        return None;
    }
    // `P == 0 && W == 0` is not an addressing mode, so it is where the
    // exclusives and the table branches live (A7.7.50's `SEE "Related
    // encodings"`); everything else in the group is a dual transfer.
    let p = (hw1 >> 8) & 1;
    let w = (hw1 >> 5) & 1;
    if p == 0 && w == 0 {
        decode_sync(hw1, hw2, addr)
    } else {
        Some(decode_dual(hw1, hw2, addr))
    }
}

/// The `P == 0 && W == 0` sub-space: the exclusives and the table branches.
///
/// `U` (`hw1[7]`) separates the plain word exclusives from the sized ones and
/// the table branches; `L` (`hw1[4]`) separates store from load; `op3`
/// (`hw2[7:4]`) picks the row within each.
fn decode_sync(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let rn = Reg((hw1 & 0xF) as u8);
    let rt = Reg((hw2 >> 12) as u8);
    let mid = (hw2 >> 8) & 0xF;
    let op3 = (hw2 >> 4) & 0xF;
    let lo = hw2 & 0xF;
    let sized = (hw1 >> 7) & 1 == 1;
    let load = (hw1 >> 4) & 1 == 1;

    match (sized, load) {
        // `op1 == 00`, `op2 == 00`: STREX, `hw2 = Rt Rd imm8`. The only
        // exclusive whose `hw2` has no fixed field at all, which is why the
        // table lets `op3` be anything here — those bits are `imm8[7:4]`.
        (false, false) => {
            let imm32 = u32::from(hw2 & 0xFF) * 4;
            let mut operands = Operands::new();
            operands.push(Operand::Reg(Reg(mid as u8)));
            operands.push(Operand::Reg(rt));
            operands.push(Operand::Mem(offset_mem(rn, imm32)));
            Some(wide("strex", addr, operands))
        }
        // `op1 == 00`, `op2 == 01`: LDREX, `hw2 = Rt (1)(1)(1)(1) imm8`.
        (false, true) => {
            if mid != 0xF {
                return None;
            }
            let imm32 = u32::from(hw2 & 0xFF) * 4;
            let mut operands = Operands::new();
            operands.push(Operand::Reg(rt));
            operands.push(Operand::Mem(offset_mem(rn, imm32)));
            Some(wide("ldrex", addr, operands))
        }
        // `op1 == 01`, `op2 == 00`: the sized store exclusives, `Rd` in
        // `hw2[3:0]` rather than `hw2[11:8]` — the one place the two halves of
        // Table A5-17 disagree about where a register lives.
        (true, false) => match op3 {
            OP3_BYTE | OP3_HALF => {
                if mid != 0xF {
                    return None;
                }
                let mnemonic = if op3 == OP3_BYTE { "strexb" } else { "strexh" };
                Some(wide(
                    mnemonic,
                    addr,
                    store_excl(Reg(lo as u8), rt, None, rn),
                ))
            }
            OP3_DOUBLE => Some(wide(
                "strexd",
                addr,
                store_excl(Reg(lo as u8), rt, Some(Reg(mid as u8)), rn),
            )),
            _ => None,
        },
        // `op1 == 01`, `op2 == 01`: the table branches and the sized load
        // exclusives, which share a row only because `op3` tells them apart.
        (true, true) => match op3 {
            0b0000 | 0b0001 => {
                if rt.num() != 0xF || mid != 0 {
                    return None;
                }
                let shift = if op3 == 1 {
                    // `TBH`'s `LSL #1` is mandatory syntax, not decoration.
                    Some(Shift {
                        kind: ShiftKind::Lsl,
                        amount: ShiftAmount::Imm(1),
                    })
                } else {
                    None
                };
                let mut operands = Operands::new();
                operands.push(Operand::Mem(Mem {
                    base: rn,
                    index: Some((Reg(lo as u8), shift)),
                    offset: 0,
                    add: true,
                    align: 0,
                    mode: AddrMode::Offset,
                }));
                // No `Operand::Target`: the branch length comes from memory.
                Some(wide(if op3 == 1 { "tbh" } else { "tbb" }, addr, operands))
            }
            OP3_BYTE | OP3_HALF => {
                if mid != 0xF || lo != 0xF {
                    return None;
                }
                let mnemonic = if op3 == OP3_BYTE { "ldrexb" } else { "ldrexh" };
                Some(wide(mnemonic, addr, load_excl(rt, None, rn)))
            }
            OP3_DOUBLE => {
                if lo != 0xF {
                    return None;
                }
                Some(wide(
                    "ldrexd",
                    addr,
                    load_excl(rt, Some(Reg(mid as u8)), rn),
                ))
            }
            _ => None,
        },
    }
}

/// The dual transfers — every encoding in the group with `P == 1 || W == 1`.
///
/// Total: Table A5-17 allocates all four `op3` bits to `imm8` here, so there
/// is no hole to fall into and no should-be-one field to check.
fn decode_dual(hw1: u16, hw2: u16, addr: u32) -> Insn {
    let p = (hw1 >> 8) & 1;
    let u = (hw1 >> 7) & 1;
    let w = (hw1 >> 5) & 1;
    let load = (hw1 >> 4) & 1 == 1;
    let rn = Reg((hw1 & 0xF) as u8);
    let rt = Reg((hw2 >> 12) as u8);
    let rt2 = Reg(((hw2 >> 8) & 0xF) as u8);

    // `imm32 = ZeroExtend(imm8:'00', 32)`. `U` is kept as `U`, not folded
    // into a sign, so `#-0` survives the round trip.
    let offset = u32::from(hw2 & 0xFF) * 4;
    let add = u == 1;
    // `index = (P == '1')`, `wback = (W == '1')`; `P == 0 && W == 0` never
    // reaches here.
    let mode = if p == 0 {
        AddrMode::PostIndex
    } else if w == 1 {
        AddrMode::PreIndex
    } else {
        AddrMode::Offset
    };

    let mut operands = Operands::new();
    operands.push(Operand::Reg(rt));
    operands.push(Operand::Reg(rt2));
    operands.push(Operand::Mem(Mem {
        base: rn,
        index: None,
        offset,
        add,
        align: 0,
        mode,
    }));
    // `LDRD` with `Rn == 1111` is the literal form and resolves against
    // `Align(PC,4)`; `STRD` has no literal form (A7.7.166 makes `Rn == 15`
    // UNPREDICTABLE), so it gets no target.
    if load && rn.num() == 0xF {
        operands.push(Operand::Target(literal_base(addr).wrapping_add(if add {
            offset
        } else {
            offset.wrapping_neg()
        })));
    }
    wide(if load { "ldrd" } else { "strd" }, addr, operands)
}

/// The 4-bit field for a plain register operand.
fn reg_field(op: Option<Operand>) -> Option<u16> {
    match op? {
        Operand::Reg(r) => Some(r.num() as u16),
        _ => None,
    }
}

/// The memory operand at `op`, if it is one.
fn mem_field(op: Option<Operand>) -> Option<Mem> {
    match op? {
        Operand::Mem(m) => Some(m),
        _ => None,
    }
}

/// `Rn` for the forms whose address is a bare `[<Rn>]` — every exclusive but
/// `STREX`/`LDREX`. Anything else (an index, an offset, writeback) is not
/// encodable, because those bits hold `op3` and a register.
fn bare_base(mem: &Mem) -> Option<u16> {
    if mem.index.is_some() || mem.offset != 0 || !mem.add || mem.mode != AddrMode::Offset {
        return None;
    }
    Some(mem.base.num() as u16)
}

/// `(Rn, imm8)` for `STREX`/`LDREX`, whose offset is `imm8:'00'` — a
/// non-negative multiple of four up to 1020. There is no `U` bit on these two,
/// so a negative offset is unencodable rather than merely out of range.
fn scaled_base(mem: &Mem) -> Option<(u16, u16)> {
    if mem.index.is_some() || mem.mode != AddrMode::Offset || !mem.add {
        return None;
    }
    let bytes = mem.offset;
    if bytes % 4 != 0 || bytes / 4 > 0xFF {
        return None;
    }
    Some((mem.base.num() as u16, (bytes / 4) as u16))
}

/// Re-encode an instruction this module decoded, back to its two halfwords.
///
/// Returns `None` for anything that is not this group's, which matters because
/// [`super::encode`] tries the group modules in turn: a greedy `encode` that
/// accepted another group's instruction on mnemonic alone would silently
/// mis-encode it. Hence the guards on width, encoding name, flag suffix,
/// operand count and the exact shape of the memory operand — and hence, too,
/// the cross-check of `LDRD (literal)`'s resolved target against its own
/// `[pc, #±imm]`, which are derived by different routes and must agree.
///
/// `cond` is deliberately not consulted: an instruction made conditional by an
/// enclosing IT block encodes identically.
pub(crate) fn encode(insn: &Insn) -> Option<(u16, u16)> {
    if insn.width != Width::Wide || insn.sets_flags || insn.explicit_width || insn.encoding != "T1"
    {
        return None;
    }
    match insn.mnemonic {
        "strex" => encode_strex(insn),
        "ldrex" => encode_ldrex(insn),
        "strexb" => encode_store_excl(insn, OP3_BYTE, false),
        "strexh" => encode_store_excl(insn, OP3_HALF, false),
        "strexd" => encode_store_excl(insn, OP3_DOUBLE, true),
        "ldrexb" => encode_load_excl(insn, OP3_BYTE, false),
        "ldrexh" => encode_load_excl(insn, OP3_HALF, false),
        "ldrexd" => encode_load_excl(insn, OP3_DOUBLE, true),
        "tbb" => encode_table_branch(insn, false),
        "tbh" => encode_table_branch(insn, true),
        "strd" => encode_dual(insn, false),
        "ldrd" => encode_dual(insn, true),
        _ => None,
    }
}

/// `STREX <Rd>, <Rt>, [<Rn>{, #<imm>}]` — `hw1 = 1110 1000 0100 Rn`,
/// `hw2 = Rt Rd imm8`.
fn encode_strex(insn: &Insn) -> Option<(u16, u16)> {
    if insn.operands.len() != 3 {
        return None;
    }
    let rd = reg_field(insn.operands.get(0))?;
    let rt = reg_field(insn.operands.get(1))?;
    let (rn, imm8) = scaled_base(&mem_field(insn.operands.get(2))?)?;
    Some((HW1_FIXED | rn, (rt << 12) | (rd << 8) | imm8))
}

/// `LDREX <Rt>, [<Rn>{, #<imm>}]` — `hw1 = 1110 1000 0101 Rn`,
/// `hw2 = Rt (1)(1)(1)(1) imm8`.
fn encode_ldrex(insn: &Insn) -> Option<(u16, u16)> {
    if insn.operands.len() != 2 {
        return None;
    }
    let rt = reg_field(insn.operands.get(0))?;
    let (rn, imm8) = scaled_base(&mem_field(insn.operands.get(1))?)?;
    Some((HW1_FIXED | 0x0010 | rn, (rt << 12) | 0x0F00 | imm8))
}

/// The sized and doubleword store exclusives — `hw1 = 1110 1000 1100 Rn`,
/// `hw2 = Rt Rt2-or-(1)(1)(1)(1) op3 Rd`, with `<Rd>` first in the syntax.
fn encode_store_excl(insn: &Insn, op3: u16, dual: bool) -> Option<(u16, u16)> {
    let rd = reg_field(insn.operands.get(0))?;
    let rt = reg_field(insn.operands.get(1))?;
    // `STREXD` names both source registers; the byte and halfword forms leave
    // the field should-be-one.
    let (rt2, at) = if dual {
        (reg_field(insn.operands.get(2))?, 3)
    } else {
        (0xF, 2)
    };
    if insn.operands.len() != at + 1 {
        return None;
    }
    let rn = bare_base(&mem_field(insn.operands.get(at))?)?;
    Some((
        HW1_FIXED | 0x0080 | rn,
        (rt << 12) | (rt2 << 8) | (op3 << 4) | rd,
    ))
}

/// The sized and doubleword load exclusives — `hw1 = 1110 1000 1101 Rn`,
/// `hw2 = Rt Rt2-or-(1)(1)(1)(1) op3 (1)(1)(1)(1)`, with no status register.
fn encode_load_excl(insn: &Insn, op3: u16, dual: bool) -> Option<(u16, u16)> {
    let rt = reg_field(insn.operands.get(0))?;
    let (rt2, at) = if dual {
        (reg_field(insn.operands.get(1))?, 2)
    } else {
        (0xF, 1)
    };
    if insn.operands.len() != at + 1 {
        return None;
    }
    let rn = bare_base(&mem_field(insn.operands.get(at))?)?;
    Some((
        HW1_FIXED | 0x0090 | rn,
        (rt << 12) | (rt2 << 8) | (op3 << 4) | 0xF,
    ))
}

/// `TBB [<Rn>, <Rm>]` / `TBH [<Rn>, <Rm>, LSL #1]` — `hw1 = 1110 1000 1101 Rn`,
/// `hw2 = (1)(1)(1)(1) (0)(0)(0)(0) 000 H Rm`.
///
/// The shift is checked, not ignored: a `TBH` whose index lost its `LSL #1`,
/// or a `TBB` that acquired one, is not this encoding.
fn encode_table_branch(insn: &Insn, halfword: bool) -> Option<(u16, u16)> {
    if insn.operands.len() != 1 {
        return None;
    }
    let mem = mem_field(insn.operands.get(0))?;
    if mem.offset != 0 || !mem.add || mem.mode != AddrMode::Offset {
        return None;
    }
    let (rm, shift) = mem.index?;
    let want = if halfword {
        Some(Shift {
            kind: ShiftKind::Lsl,
            amount: ShiftAmount::Imm(1),
        })
    } else {
        None
    };
    if shift != want {
        return None;
    }
    Some((
        HW1_FIXED | 0x0090 | mem.base.num() as u16,
        0xF000 | (u16::from(halfword) << 4) | rm.num() as u16,
    ))
}

/// `LDRD`/`STRD <Rt>, <Rt2>, [<Rn>…]` — `hw1 = 1110 100 P U 1 W L Rn`,
/// `hw2 = Rt Rt2 imm8`.
///
/// `P`/`W` come from [`AddrMode`], which cannot produce the reserved `00`;
/// `U` is [`Mem::add`] and `imm8` the magnitude, so `#-0` encodes back to the
/// `U == 0` halfword it came from.
fn encode_dual(insn: &Insn, load: bool) -> Option<(u16, u16)> {
    let rt = reg_field(insn.operands.get(0))?;
    let rt2 = reg_field(insn.operands.get(1))?;
    let mem = mem_field(insn.operands.get(2))?;
    if mem.index.is_some() {
        return None;
    }
    let magnitude = mem.offset;
    if magnitude % 4 != 0 || magnitude / 4 > 0xFF {
        return None;
    }
    let imm8 = (magnitude / 4) as u16;
    let u = u16::from(mem.add);
    let (p, w) = match mem.mode {
        AddrMode::Offset => (1, 0),
        AddrMode::PreIndex => (1, 1),
        AddrMode::PostIndex => (0, 1),
        // `[<Rn>]!` with an implicit increment belongs to Advanced SIMD; no
        // dual transfer has that shape.
        AddrMode::PostIncrement => return None,
    };

    // The literal form carries its resolved address as a fourth operand; every
    // other shape has exactly three.
    if load && mem.base == Reg::PC {
        if insn.operands.len() != 4 {
            return None;
        }
        // `get(3)` is folded into the wildcard rather than being a `?` of its
        // own: the length check above already guarantees it is `Some`, so a
        // separate `?` would be a branch nothing can take.
        let target = match insn.operands.get(3) {
            Some(Operand::Target(t)) => t,
            _ => return None,
        };
        if target != literal_base(insn.addr).wrapping_add(mem.displacement() as u32) {
            return None;
        }
    } else if insn.operands.len() != 3 {
        return None;
    }

    let l = u16::from(load);
    Some((
        HW1_FIXED | (p << 8) | (u << 7) | (w << 5) | (l << 4) | mem.base.num() as u16,
        (rt << 12) | (rt2 << 8) | imm8,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 4-aligned address, where `Align(PC,4)` is a no-op.
    const ALIGNED: u32 = 0x1000;
    /// A 2-mod-4 address, where `Align(PC,4)` subtracts two from the pc value
    /// — the alignment that a decoder omitting the `& !3` gets wrong.
    const UNALIGNED: u32 = 0x1002;

    /// `hw1 = 1110 100 op1(2) 1 op2(2) Rn(4)`, the group's only first-halfword
    /// shape (A5.3.6).
    fn hw1_of(op1: u16, op2: u16, rn: u16) -> u16 {
        HW1_FIXED | (op1 << 7) | (op2 << 4) | rn
    }

    /// The printed UAL form of an encoding that must decode.
    fn ual(hw1: u16, hw2: u16, addr: u32) -> String {
        let decoded = decode(hw1, hw2, addr);
        // `assert!` rather than `unwrap_or_else(|| panic!(…))`: the closure in
        // the latter is a function that never runs, and this crate's coverage
        // gate is 100% of functions.
        assert!(
            decoded.is_some(),
            "{hw1:#06x} {hw2:#06x} is in Table A5-17 and must decode"
        );
        decoded.unwrap().to_string()
    }

    /// The bare `[<Rn>]` that every exclusive but `STREX`/`LDREX` takes, and
    /// that a table branch's base is before its index is added.
    ///
    /// Asserting against a whole `Operand` rather than `matches!`-ing the
    /// variant and reading one field off it pins `offset`, `add`, `align` and
    /// `mode` too — and leaves no never-taken "that was not a memory operand"
    /// arm for the coverage gate to find.
    fn bare(rn: u8) -> Operand {
        Operand::Mem(Mem {
            base: Reg(rn),
            index: None,
            offset: 0,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        })
    }

    /// `[<Rn>, #<imm>]` — the address of the two word exclusives, the only
    /// members of this group whose `hw2` has room for an immediate.
    fn scaled(rn: u8, offset: u32) -> Operand {
        Operand::Mem(Mem {
            base: Reg(rn),
            index: None,
            offset,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        })
    }

    /// `[<Rn>, <Rm>{, LSL #1}]` — a table branch's address.
    fn table(rn: u8, rm: u8, halfword: bool) -> Operand {
        Operand::Mem(Mem {
            base: Reg(rn),
            index: Some((
                Reg(rm),
                if halfword {
                    Some(Shift {
                        kind: ShiftKind::Lsl,
                        amount: ShiftAmount::Imm(1),
                    })
                } else {
                    None
                },
            )),
            offset: 0,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        })
    }

    /// Table A5-17 and Table A6-17 re-expressed from the manuals rather than
    /// from [`decode`]: the mnemonic the architecture allocates to
    /// `(op1, op2, op3)`, or `None` where it says UNDEFINED.
    ///
    /// Two independent readings of the same table are the point of the sweep;
    /// this one is written in the tables' own terms — `op1`/`op2`/`op3` — and
    /// [`decode`] is written in the encodings' terms (`P`, `U`, `W`, `L`), so
    /// they agree only if both are right.
    fn table_row(op1: u16, op2: u16, op3: u16) -> Option<&'static str> {
        // Rows `0x 10`, `1x x0` (store) and `0x 11`, `1x x1` (load).
        if op1 >> 1 == 1 || op2 >> 1 == 1 {
            return Some(if op2 & 1 == 1 { "ldrd" } else { "strd" });
        }
        match (op1, op2, op3) {
            (0b00, 0b00, _) => Some("strex"),
            (0b00, 0b01, _) => Some("ldrex"),
            (0b01, 0b00, 0b0100) => Some("strexb"),
            (0b01, 0b00, 0b0101) => Some("strexh"),
            (0b01, 0b00, 0b0111) => Some("strexd"), // Table A6-17 only
            (0b01, 0b01, 0b0000) => Some("tbb"),
            (0b01, 0b01, 0b0001) => Some("tbh"),
            (0b01, 0b01, 0b0100) => Some("ldrexb"),
            (0b01, 0b01, 0b0101) => Some("ldrexh"),
            (0b01, 0b01, 0b0111) => Some("ldrexd"), // Table A6-17 only
            _ => None,
        }
    }

    /// The should-be-one and should-be-zero fields of each row's `hw2`, as a
    /// `(mask, value)` pair read off the A7.7 and A8.6 encoding diagrams.
    /// Rows that name a register in every field have an empty mask.
    fn sbo_fields(mnemonic: &str) -> (u16, u16) {
        match mnemonic {
            "ldrex" | "strexb" | "strexh" => (0x0F00, 0x0F00),
            "ldrexb" | "ldrexh" => (0x0F0F, 0x0F0F),
            "ldrexd" => (0x000F, 0x000F),
            "tbb" | "tbh" => (0xFF00, 0xF000),
            _ => (0x0000, 0x0000),
        }
    }

    #[test]
    fn sweep_round_trips_and_matches_the_tables() {
        // Every `op1`/`op2`/`Rn` — the whole first halfword of the group —
        // against a second halfword sweeping `op3` exhaustively and each of
        // the other three nibbles over `{0, 1, 14, 15}`. The nibble set is
        // chosen so that `op3:lo` covers the boundary `imm8` values 0, 1, 254
        // and 255 for the rows that carry an immediate, and so that every
        // should-be-one field is hit both with and without its nominal value.
        let mut decoded = 0usize;
        let mut undecoded = 0usize;
        let mut minus_zero = 0usize;
        for addr in [ALIGNED, UNALIGNED] {
            for op1 in 0..4u16 {
                for op2 in 0..4u16 {
                    for rn in 0..16u16 {
                        let hw1 = hw1_of(op1, op2, rn);
                        for rt in [0u16, 15] {
                            for mid in [0u16, 1, 14, 15] {
                                for op3 in 0..16u16 {
                                    for lo in [0u16, 1, 14, 15] {
                                        let hw2 = (rt << 12) | (mid << 8) | (op3 << 4) | lo;
                                        let want = table_row(op1, op2, op3).filter(|m| {
                                            let (mask, value) = sbo_fields(m);
                                            hw2 & mask == value
                                        });
                                        let got = decode(hw1, hw2, addr);
                                        assert_eq!(
                                            got.map(|i| i.mnemonic),
                                            want,
                                            "{hw1:#06x} {hw2:#06x}"
                                        );
                                        let insn = match got {
                                            None => {
                                                undecoded += 1;
                                                continue;
                                            }
                                            Some(i) => i,
                                        };
                                        decoded += 1;
                                        assert_eq!(insn.width, Width::Wide, "{hw1:#06x}");
                                        assert_eq!(insn.len(), 4, "{hw1:#06x}");
                                        assert_eq!(insn.encoding, "T1", "{hw1:#06x}");
                                        assert_eq!(insn.addr, addr, "{hw1:#06x}");
                                        assert!(insn.cond.is_none(), "{hw1:#06x}");
                                        // No `S` bit anywhere here; `Display`
                                        // would print `ldrds`.
                                        assert!(!insn.sets_flags, "{hw1:#06x}");
                                        // No 16-bit counterpart, so no `.w`.
                                        assert!(!insn.explicit_width, "{hw1:#06x}");

                                        // `#-0` used to be the group's one
                                        // lossy case. It is counted here so
                                        // that the sweep is known to cover
                                        // it, and it is asserted through the
                                        // same byte-identity as everything
                                        // else.
                                        let is_dual = matches!(insn.mnemonic, "ldrd" | "strd");
                                        if is_dual && op1 & 1 == 0 && hw2 & 0xFF == 0 {
                                            minus_zero += 1;
                                            assert!(
                                                insn.to_string().contains("#-0"),
                                                "{hw1:#06x} {hw2:#06x} is `#-0` and must print so"
                                            );
                                        }
                                        assert_eq!(
                                            encode(&insn),
                                            Some((hw1, hw2)),
                                            "round-trip of {hw1:#06x} {hw2:#06x} at {addr:#x}"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 4 op1 x 4 op2 x 16 Rn = 256 first halfwords, each against
        // 2 x 4 x 16 x 4 = 512 second halfwords, at two addresses.
        assert_eq!(decoded + undecoded, 2 * 256 * 512);

        // Every decoding and non-decoding pair, accounted for against the
        // tables row by row: how many of the swept encodings each row admits is
        // the product of the swept values its own fields leave free — `pairs`
        // op1/op2 combinations, all 16 `Rn`, and then one factor per `hw2`
        // nibble (the sweep offers 2 values for `hw2[15:12]`, 4 for `hw2[11:8]`,
        // 16 for `op3` and 4 for `hw2[3:0]`, and a should-be-one or
        // should-be-zero field pins its nibble to exactly one of them).
        let row = |pairs: usize, rt: usize, mid: usize, op3: usize, lo: usize| {
            pairs * 16 * rt * mid * op3 * lo
        };
        // The dual rows — 12 of the 16 op1/op2 pairs, everything but
        // `P == 0 && W == 0` — spend all four `op3` bits on `imm8` and fix
        // nothing, so every second halfword decodes.
        let dual = row(12, 2, 4, 16, 4);
        // `op1 == 00`, `op2 == 00`: STREX, likewise nothing fixed.
        let strex = row(1, 2, 4, 16, 4);
        // `op1 == 00`, `op2 == 01`: LDREX, `hw2[11:8]` should-be-one.
        let ldrex = row(1, 2, 1, 16, 4);
        // `op1 == 01`, `op2 == 00`: STREXB and STREXH at `op3` 0100 and 0101
        // with `hw2[11:8]` should-be-one, plus STREXD at 0111 with nothing
        // fixed (`hw2[11:8]` is its `Rt2`).
        let sized_stores = 2 * row(1, 2, 1, 1, 4) + row(1, 2, 4, 1, 4);
        // `op1 == 01`, `op2 == 01`: TBB and TBH at `op3` 0000 and 0001 with
        // `hw2[15:12]` should-be-one and `hw2[11:8]` should-be-zero, LDREXB and
        // LDREXH at 0100 and 0101 with `hw2[11:8]` and `hw2[3:0]`
        // should-be-one, LDREXD at 0111 with only `hw2[3:0]` should-be-one.
        let sized_loads = 2 * row(1, 1, 1, 1, 4) + 2 * row(1, 2, 1, 1, 1) + row(1, 2, 4, 1, 1);
        assert_eq!(
            decoded,
            2 * (dual + strex + ldrex + sized_stores + sized_loads)
        );
        assert_eq!(decoded, 2 * 109_632);
        assert_eq!(undecoded, 2 * 21_440);

        // The `#-0` encodings: 6 of the 16 op1/op2 pairs are dual with
        // `U == 0`, times 16 Rn, times the 8 second halfwords with
        // `imm8 == 0`. All 1_536 of them now round-trip to themselves, which
        // is asserted above with every other encoding rather than excepted.
        assert_eq!(minus_zero, 2 * 6 * 16 * 8);
    }

    #[test]
    fn outside_the_group_is_not_ours() {
        // `hw1[6] == 0` is Load/store multiple (A5.3.5), the table next door.
        assert!(decode(0xE800, 0, 0).is_none());
        assert!(decode(0xE8C0 & !0x40, 0, 0).is_none());
        // `hw1[9] == 1` is data processing (shifted register), A5.3.11.
        assert!(decode(0xEA40, 0, 0).is_none());
        // A 16-bit halfword, and the other two 32-bit prefixes.
        assert!(decode(0x4770, 0, 0).is_none());
        assert!(decode(0xF040, 0, 0).is_none());
        assert!(decode(0xF840, 0, 0).is_none());
    }

    #[test]
    fn table_a5_17_rows_print_their_ual_syntax() {
        // One row of Table A5-17 per assertion, with the text taken from the
        // `Assembler syntax` line of the instruction's own page.

        // `STREX<c><q> <Rd>, <Rt>, [<Rn> {,#<imm>}]` — A7.7.167.
        assert_eq!(ual(0xE842, 0x1002, 0), "strex r0, r1, [r2, #8]");
        assert_eq!(ual(0xE842, 0x1000, 0), "strex r0, r1, [r2]");
        assert_eq!(ual(0xE842, 0x10FF, 0), "strex r0, r1, [r2, #1020]");
        // `LDREX<c><q> <Rt>, [<Rn> {,#<imm>}]` — A7.7.52.
        assert_eq!(ual(0xE851, 0x0F02, 0), "ldrex r0, [r1, #8]");
        assert_eq!(ual(0xE851, 0x0F00, 0), "ldrex r0, [r1]");
        // `STRD<c><q> <Rt>,<Rt2>,[<Rn>{,#+/-<imm>}]` and its indexed forms —
        // A7.7.166.
        assert_eq!(ual(0xE9C2, 0x0102, 0), "strd r0, r1, [r2, #8]");
        assert_eq!(ual(0xE9E2, 0x0102, 0), "strd r0, r1, [r2, #8]!");
        assert_eq!(ual(0xE8E2, 0x0102, 0), "strd r0, r1, [r2], #8");
        assert_eq!(ual(0xE942, 0x0102, 0), "strd r0, r1, [r2, #-8]");
        // `LDRD<c><q> <Rt>,<Rt2>,[<Rn>{,#+/-<imm>}]` — A7.7.50.
        assert_eq!(ual(0xE9D2, 0x0102, 0), "ldrd r0, r1, [r2, #8]");
        assert_eq!(ual(0xE9F2, 0x0102, 0), "ldrd r0, r1, [r2, #8]!");
        assert_eq!(ual(0xE8F2, 0x0102, 0), "ldrd r0, r1, [r2], #8");
        assert_eq!(ual(0xE9D2, 0x01FF, 0), "ldrd r0, r1, [r2, #1020]");
        // `LDRD<c><q> <Rt>, <Rt2>, <label>` — A7.7.51, printed as the
        // syntactic `[PC,#+/-<imm>]` alternative plus the resolved address.
        assert_eq!(ual(0xE9DF, 0x0102, 0x1002), "ldrd r0, r1, [pc, #8], 0x100c");
        // `STREXB<c><q> <Rd>, <Rt>, [<Rn>]` — A7.7.168.
        assert_eq!(ual(0xE8C2, 0x1F40, 0), "strexb r0, r1, [r2]");
        // `STREXH<c><q> <Rd>, <Rt>, [<Rn>]` — A7.7.169.
        assert_eq!(ual(0xE8C2, 0x1F50, 0), "strexh r0, r1, [r2]");
        // `TBB<c><q> [<Rn>, <Rm>]` and `TBH<c><q> [<Rn>, <Rm>, LSL #1]` —
        // A7.7.185.
        assert_eq!(ual(0xE8D0, 0xF001, 0), "tbb [r0, r1]");
        assert_eq!(ual(0xE8D0, 0xF011, 0), "tbh [r0, r1, lsl #1]");
        // `LDREXB<c><q> <Rt>, [<Rn>]` — A7.7.53.
        assert_eq!(ual(0xE8D1, 0x0F4F, 0), "ldrexb r0, [r1]");
        // `LDREXH<c><q> <Rt>, [<Rn>]` — A7.7.54.
        assert_eq!(ual(0xE8D1, 0x0F5F, 0), "ldrexh r0, [r1]");
        // The two rows Table A6-17 adds and Table A5-17 does not have:
        // `STREXD<c><q> <Rd>, <Rt>, <Rt2>, [<Rn>]` — A8.6.204 — and
        // `LDREXD<c><q> <Rt>, <Rt2>, [<Rn>]` — A8.6.71.
        assert_eq!(ual(0xE8C3, 0x1270, 0), "strexd r0, r1, r2, [r3]");
        assert_eq!(ual(0xE8D2, 0x017F, 0), "ldrexd r0, r1, [r2]");
        // High registers print architecturally: sp, lr, pc.
        assert_eq!(ual(0xE9CD, 0xE102, 0), "strd lr, r1, [sp, #8]");
    }

    #[test]
    fn table_branches_branch_but_have_no_target() {
        for (hw2, text) in [
            (0xF001u16, "tbb [r0, r1]"),
            (0xF011, "tbh [r0, r1, lsl #1]"),
        ] {
            let insn = decode(0xE8D0, hw2, 0x1000).unwrap();
            assert_eq!(insn.to_string(), text);
            // `Insn::is_branch` names both mnemonics: control leaves here.
            assert!(insn.is_branch(), "{text}");
            // But the branch length is read from a table in memory, so there
            // is no statically-known destination and no `Operand::Target`.
            assert_eq!(insn.branch_target(), None, "{text}");
            assert!(!insn.is_call(), "{text}");
            assert!(!insn.writes_pc(), "{text}");
            // One operand, the table address: base, index, and for `TBH` the
            // mandatory `LSL #1` that scales the index to halfwords.
            assert_eq!(insn.operands.len(), 1);
            assert_eq!(insn.operands.get(0), Some(table(0, 1, hw2 & 0x10 != 0)));
            assert_eq!(encode(&insn), Some((0xE8D0, hw2)));
        }
        // `TBH`'s `LSL #1` is mandatory syntax, and it is the index shift that
        // prints it.
        let tbh = decode(0xE8D0, 0xF011, 0).unwrap();
        assert!(tbh.to_string().ends_with("lsl #1]"));
        assert_eq!(tbh.operands.get(0), Some(table(0, 1, true)));
        // `TBB` has no shift at all, and the base may be the PC (A7.7.185:
        // "This register can be the PC. If it is, the table immediately
        // follows this instruction").
        assert_eq!(ual(0xE8DF, 0xF002, 0), "tbb [pc, r2]");
    }

    #[test]
    fn exclusive_operand_order_matches_the_manual() {
        // `STREX <Rd>, <Rt>, [<Rn>]`: three operands, the status register
        // first. `LDREX <Rt>, [<Rn>]`: two, no status register.
        let strex = decode(0xE842, 0x1002, 0).unwrap();
        assert_eq!(strex.operands.len(), 3);
        assert_eq!(strex.operands.get(0), Some(Operand::Reg(Reg(0)))); // Rd
        assert_eq!(strex.operands.get(1), Some(Operand::Reg(Reg(1)))); // Rt
                                                                       // The word forms are the two with an immediate, and it is scaled:
                                                                       // `imm8 == 2` in `hw2` is `#8` in the syntax (A7.7.167).
        assert_eq!(strex.operands.get(2), Some(scaled(2, 8)));

        let ldrex = decode(0xE851, 0x0F02, 0).unwrap();
        assert_eq!(ldrex.operands.len(), 2);
        assert_eq!(ldrex.operands.get(0), Some(Operand::Reg(Reg(0)))); // Rt
        assert_eq!(ldrex.operands.get(1), Some(scaled(1, 8)));

        // The same asymmetry in the sized forms, where `Rd` moves to
        // `hw2[3:0]` while `Rt` stays in `hw2[15:12]`: the fields are not
        // where the word forms put them.
        let strexb = decode(0xE8C2, 0x3F40, 0).unwrap();
        assert_eq!(strexb.to_string(), "strexb r0, r3, [r2]");
        assert_eq!(strexb.operands.len(), 3);
        let ldrexb = decode(0xE8D1, 0x3F4F, 0).unwrap();
        assert_eq!(ldrexb.to_string(), "ldrexb r3, [r1]");
        assert_eq!(ldrexb.operands.len(), 2);

        // And in the A/R doubleword pair: four operands against three.
        let strexd = decode(0xE8C3, 0x1270, 0).unwrap();
        assert_eq!(strexd.operands.len(), 4);
        assert_eq!(strexd.operands.get(0), Some(Operand::Reg(Reg(0)))); // Rd
        assert_eq!(strexd.operands.get(1), Some(Operand::Reg(Reg(1)))); // Rt
        assert_eq!(strexd.operands.get(2), Some(Operand::Reg(Reg(2)))); // Rt2
        let ldrexd = decode(0xE8D2, 0x017F, 0).unwrap();
        assert_eq!(ldrexd.operands.len(), 3);
        assert_eq!(ldrexd.operands.get(0), Some(Operand::Reg(Reg(0)))); // Rt
        assert_eq!(ldrexd.operands.get(1), Some(Operand::Reg(Reg(1)))); // Rt2

        // Only the word forms take an immediate; the sized ones spend those
        // bits on `op3` and a register, so their address is a bare `[<Rn>]`.
        for (hw1, hw2) in [
            (0xE8C2u16, 0x1F40u16),
            (0xE8C2, 0x1F50),
            (0xE8D1, 0x0F4F),
            (0xE8D1, 0x0F5F),
            (0xE8C3, 0x1270),
            (0xE8D2, 0x017F),
        ] {
            let insn = decode(hw1, hw2, 0).unwrap();
            assert_eq!(
                insn.operands.get(insn.operands.len() - 1),
                Some(bare((hw1 & 0xF) as u8)),
                "{} should end in a bare [<Rn>]",
                insn.mnemonic
            );
        }
    }

    #[test]
    fn ldrd_literal_resolves_against_aligned_pc() {
        // `ldrd r0, r1, [pc, #8]`, U == 1: hw1 = 1110 1001 1101 1111.
        let add = 0xE9DFu16;
        // `ldrd r0, r1, [pc, #-8]`, U == 0.
        let sub = 0xE95Fu16;
        let hw2 = 0x0102u16;

        // At 0x1000 the pc value is 0x1004 and is already word-aligned.
        assert_eq!(
            decode(add, hw2, 0x1000).unwrap().branch_target(),
            Some(0x100C)
        );
        assert_eq!(
            decode(sub, hw2, 0x1000).unwrap().branch_target(),
            Some(0x0FFC)
        );
        // At 0x1002 the pc value is 0x1006 and `Align(PC,4)` takes it back to
        // 0x1004 — the same literal. Without the `& !3` these would come out
        // as 0x100e and 0x0ffe.
        assert_eq!(
            decode(add, hw2, 0x1002).unwrap().branch_target(),
            Some(0x100C)
        );
        assert_eq!(
            decode(sub, hw2, 0x1002).unwrap().branch_target(),
            Some(0x0FFC)
        );
        // At 0x1004 it is a different word, and so a different literal.
        assert_eq!(
            decode(add, hw2, 0x1004).unwrap().branch_target(),
            Some(0x1010)
        );
        assert_eq!(
            decode(sub, hw2, 0x1004).unwrap().branch_target(),
            Some(0x1000)
        );

        // The syntactic memory operand and the resolved address are both
        // present, in that order, and both round-trip.
        for addr in [0x1000u32, 0x1002, 0x1004] {
            for hw1 in [add, sub] {
                let insn = decode(hw1, hw2, addr).unwrap();
                assert_eq!(insn.operands.len(), 4);
                // Operand 2 is the syntactic `[pc, #±8]` — `U` as `Mem::add`
                // over a magnitude, not a signed offset — and operand 3 is the
                // address it resolves to. Compared whole, so nothing about
                // either is left unstated.
                assert_eq!(
                    insn.operands.get(2),
                    Some(Operand::Mem(Mem {
                        base: Reg::PC,
                        index: None,
                        offset: 8,
                        add: hw1 == add,
                        align: 0,
                        mode: AddrMode::Offset,
                    })),
                    "{hw1:#06x} at {addr:#x}"
                );
                let resolved = literal_base(addr).wrapping_add(if hw1 == add {
                    8
                } else {
                    8u32.wrapping_neg()
                });
                assert_eq!(
                    insn.operands.get(3),
                    Some(Operand::Target(resolved)),
                    "{hw1:#06x} at {addr:#x}"
                );
                assert_eq!(encode(&insn), Some((hw1, hw2)), "{hw1:#06x} at {addr:#x}");
            }
        }
        assert_eq!(
            decode(sub, hw2, 0x1002).unwrap().to_string(),
            "ldrd r0, r1, [pc, #-8], 0xffc"
        );

        // A target that disagrees with the instruction's own `[pc, #imm]` —
        // the shape an `Align(PC,4)` bug produces — does not encode.
        let mut wrong = decode(add, hw2, 0x1002).unwrap();
        let mut operands = Operands::new();
        operands.push(Operand::Reg(Reg(0)));
        operands.push(Operand::Reg(Reg(1)));
        operands.push(Operand::Mem(offset_mem(Reg::PC, 8)));
        operands.push(Operand::Target(0x100E)); // right without the `& !3`
        wrong.operands = operands;
        assert_eq!(encode(&wrong), None);

        // `STRD` has no literal form — A7.7.166 makes `Rn == 15`
        // UNPREDICTABLE — so a pc-based store gets no target, and still
        // round-trips.
        let strd = decode(0xE9CF, hw2, 0x1002).unwrap();
        assert_eq!(strd.to_string(), "strd r0, r1, [pc, #8]");
        assert_eq!(strd.branch_target(), None);
        assert_eq!(strd.operands.len(), 3);
        assert_eq!(encode(&strd), Some((0xE9CF, hw2)));
    }

    #[test]
    fn unpredictable_register_choices_still_decode() {
        // A7.7.50: `if t IN {13,15} || t2 IN {13,15} || t == t2 then
        // UNPREDICTABLE`. UNPREDICTABLE is not UNDEFINED — the encoding
        // exists and an image can contain it — so it decodes, prints what the
        // bits say, and round-trips. Naming it anything else, or refusing it,
        // would hide a real instruction from a disassembly.
        let same = decode(0xE9D2, 0x0002, 0).unwrap(); // Rt == Rt2 == r0
        assert_eq!(same.to_string(), "ldrd r0, r0, [r2, #8]");
        assert_eq!(encode(&same), Some((0xE9D2, 0x0002)));
        // Writeback onto the base, also UNPREDICTABLE (`wback && n == t`).
        let wb = decode(0xE9F2, 0x2102, 0).unwrap();
        assert_eq!(wb.to_string(), "ldrd r2, r1, [r2, #8]!");
        assert_eq!(encode(&wb), Some((0xE9F2, 0x2102)));
        // `Rt` of 13 or 15 likewise. A `ldrd pc, ...` reads as a pc write, so
        // `Insn::writes_pc` — which looks at the first operand — says so.
        let pc = decode(0xE9D2, 0xF102, 0).unwrap();
        assert_eq!(pc.to_string(), "ldrd pc, r1, [r2, #8]");
        assert!(pc.writes_pc());
        assert_eq!(encode(&pc), Some((0xE9D2, 0xF102)));
        // A7.7.185: `TBB` with `Rn == 13`.
        assert_eq!(ual(0xE8DD, 0xF001, 0), "tbb [sp, r1]");
    }

    #[test]
    fn should_be_one_and_should_be_zero_fields_are_required() {
        // Each row's fixed `hw2` field, cleared or set against its nominal
        // value. These encodings are UNPREDICTABLE by construction and carry
        // information `Insn` cannot hold, so they do not decode — see the
        // module documentation.
        assert!(decode(0xE851, 0x0F02, 0).is_some()); // ldrex, hw2[11:8] = 1111
        assert!(decode(0xE851, 0x0E02, 0).is_none());
        assert!(decode(0xE8C2, 0x1F40, 0).is_some()); // strexb
        assert!(decode(0xE8C2, 0x1B40, 0).is_none());
        assert!(decode(0xE8D1, 0x0F4F, 0).is_some()); // ldrexb, hw2[3:0] too
        assert!(decode(0xE8D1, 0x0F4E, 0).is_none());
        assert!(decode(0xE8D1, 0x0D4F, 0).is_none());
        assert!(decode(0xE8D2, 0x017F, 0).is_some()); // ldrexd
        assert!(decode(0xE8D2, 0x0170, 0).is_none());
        assert!(decode(0xE8D0, 0xF001, 0).is_some()); // tbb: SBO then SBZ
        assert!(decode(0xE8D0, 0xE001, 0).is_none());
        assert!(decode(0xE8D0, 0xF101, 0).is_none());
        // `STREX` and `STREXD` fix nothing in `hw2`, so nothing is rejected.
        assert!(decode(0xE842, 0xFFFF, 0).is_some());
        assert!(decode(0xE8C3, 0xFF7F, 0).is_some());

        // Table A5-17's UNDEFINED holes: the `op3` values the sized rows do
        // not allocate. Tested against each row's own nominal fixed fields,
        // since falling into a hole and violating a should-be-one field are
        // different failures that must not stand in for one another.
        for op3 in 0..16u16 {
            // `Rt` = 0, then all-ones for `Rt2`-or-should-be-one and for
            // `Rd`-or-should-be-one: the sized exclusives' shape.
            let sized = 0x0F0Fu16 | (op3 << 4);
            // `TBB`/`TBH`'s should-be-one `hw2[15:12]`, should-be-zero
            // `hw2[11:8]`, and `Rm`.
            let table = 0xF00Fu16 | (op3 << 4);
            let named = matches!(op3, OP3_BYTE | OP3_HALF | OP3_DOUBLE);
            assert_eq!(
                decode(0xE8C0, sized, 0).is_some(),
                named,
                "store op3 {op3:04b}"
            );
            assert_eq!(
                decode(0xE8D0, sized, 0).is_some(),
                named,
                "load op3 {op3:04b}"
            );
            // The table branches share the load row, and need the
            // should-be-zero `hw2[11:8]` that the sized loads fill with ones.
            // `op3 == 0111` decodes here too, because `LDREXD` fixes only
            // `hw2[3:0]` — `hw2[11:8]` is its `Rt2`.
            assert_eq!(
                decode(0xE8D0, table, 0).is_some(),
                matches!(op3, 0b0000 | 0b0001 | OP3_DOUBLE),
                "table op3 {op3:04b}"
            );
        }
    }

    /// A7.7.50: "Different instructions are generated for #0 and #-0". The
    /// regression test for the representation: the two must be *different*
    /// [`Mem`] values, print differently, and each go back to its own bytes.
    #[test]
    fn minus_zero_is_a_different_instruction_from_plus_zero() {
        let plus = decode(0xE9C2, 0x0100, 0).unwrap(); // U == 1, imm8 == 0
        let minus = decode(0xE942, 0x0100, 0).unwrap(); // U == 0, imm8 == 0
        assert_eq!(plus.to_string(), "strd r0, r1, [r2]");
        assert_eq!(minus.to_string(), "strd r0, r1, [r2, #-0]");
        assert_ne!(plus.operands, minus.operands);
        let mem = |i: &Insn| mem_field(i.operands.get(2)).unwrap();
        assert!(mem(&plus).add && mem(&plus).offset == 0);
        assert!(!mem(&minus).add && mem(&minus).offset == 0);
        // Both address `R[2]`, which is why the distinction is invisible in
        // the effective address and must live in the fields instead.
        assert_eq!(mem(&plus).displacement(), mem(&minus).displacement());
        assert_eq!(encode(&plus), Some((0xE9C2, 0x0100)));
        assert_eq!(encode(&minus), Some((0xE942, 0x0100)));
        // A non-zero offset keeps its sign and round-trips exactly.
        assert_eq!(
            encode(&decode(0xE942, 0x0101, 0).unwrap()),
            Some((0xE942, 0x0101))
        );
        // The post-indexed `#0`, which `Display` must not shorten to `[r2]`:
        // the writeback is the whole point of the mode.
        let post = decode(0xE8E2, 0x0100, 0).unwrap(); // P == 0, U == 1, W == 1
        assert_eq!(post.to_string(), "strd r0, r1, [r2], #0");
        assert_eq!(encode(&post), Some((0xE8E2, 0x0100)));
        let post_minus = decode(0xE862, 0x0100, 0).unwrap(); // P == 0, U == 0
        assert_eq!(post_minus.to_string(), "strd r0, r1, [r2], #-0");
        assert_eq!(encode(&post_minus), Some((0xE862, 0x0100)));
    }

    /// Every operand slot of every mnemonic in the group, mangled one at a
    /// time, and every operand count one either side of the right one.
    ///
    /// [`Insn`] is a public struct with public fields, so `encode` is
    /// reachable with any operand list a consumer cares to build. The failure
    /// that matters here is not a panic but a `Some`: halfwords assembled
    /// from a slot the encoder never checked, written into a firmware image.
    /// This group is where that is easiest to get wrong, because the operand
    /// order is not the field order — `STREX` puts its status register first
    /// and its `Rd` field in `hw2[11:8]`, while `STREXB` puts the same
    /// register in `hw2[3:0]`.
    #[test]
    fn encode_rejects_every_mangled_operand_slot() {
        for (hw1, hw2, addr) in [
            (0xE842u16, 0x1002u16, 0u32), // strex  Rd, Rt, [Rn, #imm]
            (0xE851, 0x0F02, 0),          // ldrex  Rt, [Rn, #imm]
            (0xE8C2, 0x1F40, 0),          // strexb Rd, Rt, [Rn]
            (0xE8C2, 0x1F50, 0),          // strexh Rd, Rt, [Rn]
            (0xE8C3, 0x1270, 0),          // strexd Rd, Rt, Rt2, [Rn]
            (0xE8D1, 0x0F4F, 0),          // ldrexb Rt, [Rn]
            (0xE8D1, 0x0F5F, 0),          // ldrexh Rt, [Rn]
            (0xE8D2, 0x017F, 0),          // ldrexd Rt, Rt2, [Rn]
            (0xE8D0, 0xF001, 0),          // tbb    [Rn, Rm]
            (0xE8D0, 0xF011, 0),          // tbh    [Rn, Rm, lsl #1]
            (0xE9C2, 0x0102, 0),          // strd   Rt, Rt2, [Rn, #imm]
            (0xE9D2, 0x0102, 0),          // ldrd   Rt, Rt2, [Rn, #imm]
            (0xE9DF, 0x0102, ALIGNED),    // ldrd   Rt, Rt2, [pc, #imm], target
        ] {
            let insn = decode(hw1, hw2, addr).unwrap();
            assert_eq!(
                encode(&insn),
                Some((hw1, hw2)),
                "`{insn}` should round-trip before anything is mangled"
            );
            let arity = insn.operands.len();

            // One slot at a time, replaced by an operand of a kind that slot
            // can never hold: an immediate where a register belongs, a
            // register where an address or a resolved target belongs.
            for slot in 0..arity {
                let mut mangled = insn;
                mangled.operands = (0..arity)
                    .map(|i| {
                        let op = insn.operands.get(i).unwrap();
                        if i != slot {
                            op
                        } else {
                            match op {
                                Operand::Reg(_) => Operand::Imm(0),
                                _ => Operand::Reg(Reg(0)),
                            }
                        }
                    })
                    .collect();
                assert_eq!(encode(&mangled), None, "`{insn}`, operand {slot} mangled");
            }

            // One operand too few, and one too many. The counts are bound
            // first and interpolated by name: a positional `assert_eq!`
            // argument is an expression evaluated only when the assertion
            // fails, which is a region no passing test can reach.
            let (fewer, more) = (arity - 1, arity + 1);
            let mut short = insn;
            short.operands = (0..fewer).map(|i| insn.operands.get(i).unwrap()).collect();
            assert_eq!(encode(&short), None, "`{insn}` with {fewer} operands");
            let mut long = insn;
            long.operands = (0..more)
                .map(|i| insn.operands.get(i).unwrap_or(Operand::Imm(0)))
                .collect();
            assert_eq!(encode(&long), None, "`{insn}` with {more} operands");

            // No operands at all. The exclusives read their register slots
            // before they count operands, so an empty list has to be refused
            // by the slot read rather than by the count — and a slot read
            // that could not fail would be a guard that never runs.
            let mut empty = insn;
            empty.operands = Operands::new();
            assert_eq!(encode(&empty), None, "`{insn}` with no operands");
        }

        // The *load* exclusives reach the same two address checks as their
        // store counterparts, by a different route: `encode_ldrex` and
        // `encode_load_excl` are separate functions, so a rule enforced in
        // one says nothing about the other.
        let mut ldrex = decode(0xE851, 0x0F02, 0).unwrap();
        ldrex.operands = [
            Operand::Reg(Reg(0)),
            // `LDREX`'s offset is `imm8:'00'`, so 2 is not a multiple of four
            // and there is no `U` bit to make it negative.
            Operand::Mem(offset_mem(Reg(1), 2)),
        ]
        .iter()
        .copied()
        .collect();
        assert_eq!(encode(&ldrex), None, "`ldrex` offsets are word-scaled");
        let mut ldrexb = decode(0xE8D1, 0x0F4F, 0).unwrap();
        ldrexb.operands = [
            Operand::Reg(Reg(0)),
            // The sized forms spend those bits on `op3`, so they take no
            // offset at all.
            Operand::Mem(offset_mem(Reg(1), 4)),
        ]
        .iter()
        .copied()
        .collect();
        assert_eq!(encode(&ldrexb), None, "`ldrexb` takes a bare `[<Rn>]`");

        // A table branch's brackets hold a base and an index and nothing
        // else: the bits an offset would need hold `op3` and `Rm`, and there
        // is no `U` and no `W` (A7.7.185).
        let tbb = decode(0xE8D0, 0xF001, 0).unwrap();
        let indexed = Mem {
            base: Reg(0),
            index: Some((Reg(1), None)),
            offset: 0,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        };
        for (mem, why) in [
            (offset_mem(Reg(0), 0), "`tbb [r0]` names no table column"),
            (
                Mem {
                    offset: 4,
                    ..indexed
                },
                "there is nowhere to put an immediate beside the index",
            ),
            (
                Mem {
                    add: false,
                    ..indexed
                },
                "a table index is added; there is no `U` bit",
            ),
            (
                Mem {
                    mode: AddrMode::PreIndex,
                    ..indexed
                },
                "a table branch does not write its base back",
            ),
        ] {
            let mut bad = tbb;
            bad.operands = [Operand::Mem(mem)].iter().copied().collect();
            assert_eq!(encode(&bad), None, "{why}");
        }

        // `[<Rn>]!` with an increment the encoding does not carry is Advanced
        // SIMD's addressing mode (A7.7.1); no dual transfer has that shape.
        let mut post_inc = decode(0xE9D2, 0x0102, 0).unwrap();
        post_inc.operands = [
            Operand::Reg(Reg(0)),
            Operand::Reg(Reg(1)),
            Operand::Mem(Mem {
                mode: AddrMode::PostIncrement,
                ..offset_mem(Reg(2), 8)
            }),
        ]
        .iter()
        .copied()
        .collect();
        assert_eq!(encode(&post_inc), None);
    }

    #[test]
    fn encode_rejects_what_this_group_cannot_hold() {
        let base = decode(0xE9D2, 0x0102, 0).unwrap(); // ldrd r0, r1, [r2, #8]
        assert_eq!(encode(&base), Some((0xE9D2, 0x0102)));

        // Another group's mnemonic, so that `super::encode`'s chain of
        // `or_else` does not stop here.
        let mut foreign = base;
        foreign.mnemonic = "ldm";
        assert_eq!(encode(&foreign), None);
        for mnemonic in ["ldr", "str", "ldrb", "push", "b", "add"] {
            let mut other = base;
            other.mnemonic = mnemonic;
            assert_eq!(encode(&other), None, "{mnemonic}");
        }

        // The narrow width, a flag suffix and an explicit `.w` are all
        // impossible for this group.
        let mut narrow = base;
        narrow.width = Width::Narrow;
        assert_eq!(encode(&narrow), None);
        let mut flags = base;
        flags.sets_flags = true;
        assert_eq!(encode(&flags), None);
        let mut widened = base;
        widened.explicit_width = true;
        assert_eq!(encode(&widened), None);
        let mut renamed = base;
        renamed.encoding = "T2";
        assert_eq!(encode(&renamed), None);

        // An offset that is not a multiple of four, or past 1020.
        for bad in [1u32, 2, 1024, 6] {
            let mut off = base;
            let mut operands = Operands::new();
            operands.push(Operand::Reg(Reg(0)));
            operands.push(Operand::Reg(Reg(1)));
            operands.push(Operand::Mem(offset_mem(Reg(2), bad)));
            off.operands = operands;
            assert_eq!(encode(&off), None, "offset {bad}");
        }

        // A register index, which no encoding in this group has: `LDRD
        // (register)` exists only as an ARM-state A1 encoding (A8.6.68).
        let mut indexed = base;
        let mut operands = Operands::new();
        operands.push(Operand::Reg(Reg(0)));
        operands.push(Operand::Reg(Reg(1)));
        operands.push(Operand::Mem(Mem {
            base: Reg(2),
            index: Some((Reg(3), None)),
            offset: 0,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        }));
        indexed.operands = operands;
        assert_eq!(encode(&indexed), None);

        // The exclusives have no `U` bit and no writeback, so a negative
        // offset or an indexed mode is unencodable rather than out of range.
        let strex = decode(0xE842, 0x1002, 0).unwrap();
        assert_eq!(encode(&strex), Some((0xE842, 0x1002)));
        for mem in [
            Mem {
                add: false,
                ..offset_mem(Reg(2), 8)
            },
            offset_mem(Reg(2), 2),
            Mem {
                base: Reg(2),
                index: None,
                offset: 8,
                add: true,
                align: 0,
                mode: AddrMode::PreIndex,
            },
        ] {
            let mut bad = strex;
            let mut operands = Operands::new();
            operands.push(Operand::Reg(Reg(0)));
            operands.push(Operand::Reg(Reg(1)));
            operands.push(Operand::Mem(mem));
            bad.operands = operands;
            assert_eq!(encode(&bad), None, "{mem}");
        }

        // The sized exclusives take no offset at all.
        let mut strexb = decode(0xE8C2, 0x1F40, 0).unwrap();
        assert_eq!(encode(&strexb), Some((0xE8C2, 0x1F40)));
        let mut operands = Operands::new();
        operands.push(Operand::Reg(Reg(0)));
        operands.push(Operand::Reg(Reg(1)));
        operands.push(Operand::Mem(offset_mem(Reg(2), 4)));
        strexb.operands = operands;
        assert_eq!(encode(&strexb), None);

        // A `TBH` whose mandatory `LSL #1` has gone missing, and a `TBB` that
        // has acquired one.
        let mut tbh = decode(0xE8D0, 0xF011, 0).unwrap();
        let mut operands = Operands::new();
        operands.push(Operand::Mem(Mem {
            base: Reg(0),
            index: Some((Reg(1), None)),
            offset: 0,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        }));
        tbh.operands = operands;
        assert_eq!(encode(&tbh), None);
        let mut tbb = decode(0xE8D0, 0xF001, 0).unwrap();
        let mut operands = Operands::new();
        operands.push(Operand::Mem(Mem {
            base: Reg(0),
            index: Some((
                Reg(1),
                Some(Shift {
                    kind: ShiftKind::Lsl,
                    amount: ShiftAmount::Imm(1),
                }),
            )),
            offset: 0,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        }));
        tbb.operands = operands;
        assert_eq!(encode(&tbb), None);

        // Operand counts: the store exclusives' extra status register is not
        // optional, and the literal's target is not either.
        let mut short = decode(0xE842, 0x1002, 0).unwrap();
        let mut operands = Operands::new();
        operands.push(Operand::Reg(Reg(1)));
        operands.push(Operand::Mem(offset_mem(Reg(2), 8)));
        short.operands = operands;
        assert_eq!(encode(&short), None);

        let mut literal = decode(0xE9DF, 0x0102, 0x1002).unwrap();
        let mut operands = Operands::new();
        operands.push(Operand::Reg(Reg(0)));
        operands.push(Operand::Reg(Reg(1)));
        operands.push(Operand::Mem(offset_mem(Reg::PC, 8)));
        literal.operands = operands;
        assert_eq!(encode(&literal), None);
    }

    #[test]
    fn a_condition_from_an_it_block_does_not_change_the_halfwords() {
        // `Decoder` fills `cond` in for instructions inside an IT block; the
        // halfwords are unchanged, so `encode` must ignore it.
        let mut insn = decode(0xE9D2, 0x0102, 0).unwrap();
        insn.cond = Some(crate::Cond::Eq);
        assert_eq!(insn.to_string(), "ldrdeq r0, r1, [r2, #8]");
        assert_eq!(encode(&insn), Some((0xE9D2, 0x0102)));
    }
}
