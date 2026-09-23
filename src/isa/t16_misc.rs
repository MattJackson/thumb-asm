//! Miscellaneous 16-bit instructions — `hw1[15:12] == 0b1011`.
//!
//! ARM DDI 0403E.e Table A5-6 (§A5.2.5) for the M profile, ARM DDI 0406B
//! Table A6-6 (§A6.2.5) for A/R, and the shared sub-table of if-then and hint
//! encodings (Table A5-7 / Table A6-7). The discriminator is
//! `opcode = hw1[11:5]`; everything the two tables leave out is UNDEFINED.
//!
//! This module implements the **union** of the two tables, because the crate is
//! used to read images for both profiles and a decoder that knows only one of
//! them mis-reads the other. The union differs from Table A5-6 in exactly one
//! row: `opcode == 0b0110010` is `SETEND`, which exists only on A/R (ARMv6 and
//! later) and is UNDEFINED on the M profile — an M-profile consumer that cares
//! must reject `setend` itself, since the halfword carries nothing that
//! distinguishes the profiles. `CPS` is in both tables, but its A/R encoding has
//! an `A` bit where M has a should-be-zero bit; the A/R field placement is the
//! superset, so it is the one decoded here.
//!
//! # What this group does *not* do
//!
//! Nothing here sets the condition flags, and nothing here has a wide (32-bit)
//! twin that would need a `.n` suffix to disambiguate — so every [`Insn`] this
//! module produces has `sets_flags: false` and `explicit_width: false`. A stray
//! `true` in either is visible in the printed form, which is what the UAL
//! assertions in this module's tests are for.
//!
//! # UNPREDICTABLE encodings, and why some of them are rejected
//!
//! Arm's bit diagrams mark bits that carry no information as `(0)` or `(1)`;
//! an encoding whose value differs there is UNPREDICTABLE. [`Insn`] has no room
//! to carry such a bit, so accepting one would mean silently normalising it and
//! breaking this module's round-trip guarantee (`encode(decode(hw)) == hw` for
//! every `hw` that decodes). This module therefore **rejects** encodings whose
//! should-be-zero/one bits are wrong, and rejects UNPREDICTABLE encodings for
//! which UAL has no spelling at all:
//!
//! * `SETEND` (`1011 0110 010 (1) E (0)(0)(0)`) — only `0xB650` and `0xB658`.
//! * `CPS` (`1011 0110 011 im (0) A I F`) — bit 3 must be zero, and `A:I:F` must
//!   not be `000`: `<iflags>` is "a sequence of one or more" flags (DDI 0406B
//!   B6.1.1), and the M-profile definition adds
//!   `if I == '0' && F == '0' then UNPREDICTABLE` (DDI 0403E.e B5.2.1).
//! * `IT` with `firstcond == 0b1111`, or with `firstcond == 0b1110` (`AL`) and
//!   `BitCount(mask) != 1` — both UNPREDICTABLE per A7.7.38, and in both cases
//!   there is no `IT{x{y{z}}} <firstcond>` that names them (`E` may not be used
//!   with `AL`, and `0b1111` is not a condition).
//! * Unallocated hints (`1011 1111 opA 0000` with `opA > 0b0100`). A5.2.5 says
//!   they "execute as NOPs, but software must not use them" — they are hints,
//!   not `NOP`, and they have no mnemonic. Decoding them *as* `nop` would throw
//!   away `opA` and make `encode` unable to reproduce the halfword, so they are
//!   rejected and a disassembler renders them as data. This is the one place
//!   where this module is deliberately stricter than a "just print something"
//!   decoder.
//!
//!   The choice was re-taken against LLVM, which prints `hint #5` for these
//!   eleven halfwords, and kept. `HINT` is not a mnemonic either profile's
//!   manual defines for T32 — it is an AArch64 spelling LLVM reuses — so
//!   decoding one would mean this crate naming an instruction Arm does not,
//!   and carrying `opA` in an operand of that invented mnemonic. `.short
//!   0xbf50` says exactly what the halfword is: an allocated encoding with no
//!   architectural assembly form. The instruction-length walk is unaffected
//!   either way, because [`super::insn_len`] reads `hw1[15:11]` and never
//!   consults the decode result.
//! * `PUSH`/`POP` T1 with an empty register list (`0xB400` / `0xBC00`).
//!   `if BitCount(registers) < 1 then UNPREDICTABLE` (A7.7.101, A7.7.99), and
//!   `push {}` is not something any assembler will read back — `{}` is not a
//!   register list. This module used to decode them, on the grounds that the
//!   `Insn` describes the halfword exactly and that rejecting them would
//!   desynchronise a stream walker. The second half of that argument was
//!   wrong — `insn_len` is what keeps a walker in phase, and it does not look
//!   at the decode — and the first half proves too much, since the same could
//!   be said of every should-be-zero bit above. Refusing them makes this
//!   module consistent with itself and with [`super::t16_branch`], which has
//!   always refused `STM`/`LDM` T1 with an empty list under the same clause.
//!   Found by the LLVM conformance sweep.

use super::{Insn, Operand, Operands, Reg, Width};
use crate::Cond;

/// Build a narrow, unconditional, non-flag-setting instruction — which is every
/// instruction in this group except `BKPT` (see [`decode_bkpt`]).
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

/// Collect a fixed-size operand array into [`Operands`].
fn ops<const N: usize>(items: [Operand; N]) -> Operands {
    items.into_iter().collect()
}

/// The eight `A:I:F` combinations of `CPS`, spelled as UAL's `<iflags>`.
///
/// A lookup rather than a built string: [`Operand::Text`] holds a
/// `&'static str` so that [`Insn`] stays `Copy` and allocation-free, which
/// rules out assembling `"aif"` a character at a time. Eight entries is the
/// whole domain, so the constraint costs nothing. Index 0 (`A:I:F == 000`) has
/// no UAL spelling and is never handed out — see the module docs.
const CPS_IFLAGS: [&str; 8] = ["", "f", "i", "if", "a", "af", "ai", "aif"];

/// Decode an instruction in this group, or `None` if `hw1`/`hw2` do not
/// belong to it.
pub(crate) fn decode(hw1: u16, _hw2: u16, addr: u32) -> Option<Insn> {
    if hw1 & 0xF000 != 0xB000 {
        return None;
    }
    // `1011 opcode(7) …` — ARM DDI 0403E.e Table A5-6.
    match (hw1 >> 5) & 0x7F {
        0b000_0000..=0b000_0011 => Some(decode_adjust_sp(hw1, addr, "add", "T2")),
        0b000_0100..=0b000_0111 => Some(decode_adjust_sp(hw1, addr, "sub", "T1")),
        0b000_1000..=0b000_1111 => Some(decode_cb(hw1, addr)),
        0b001_0000..=0b001_0111 => Some(decode_extend(hw1, addr)),
        0b001_1000..=0b001_1111 => Some(decode_cb(hw1, addr)),
        0b010_0000..=0b010_1111 => decode_push_pop(hw1, addr, "push", 14),
        0b011_0010 => decode_setend(hw1, addr),
        0b011_0011 => decode_cps(hw1, addr),
        0b100_1000..=0b100_1111 => Some(decode_cb(hw1, addr)),
        0b101_0000..=0b101_0111 => decode_reverse(hw1, addr),
        0b101_1000..=0b101_1111 => Some(decode_cb(hw1, addr)),
        0b110_0000..=0b110_1111 => decode_push_pop(hw1, addr, "pop", 15),
        0b111_0000..=0b111_0111 => Some(decode_bkpt(hw1, addr)),
        0b111_1000..=0b111_1111 => decode_it_or_hint(hw1, addr),
        _ => None,
    }
}

/// `ADD (SP plus immediate)` T2 and `SUB (SP minus immediate)` T1 —
/// `1011 0000 op imm7`, A7.7.5 and A7.7.176.
///
/// `imm32 = ZeroExtend(imm7:'00')`, so the range is multiples of four from 0 to
/// 508. UAL's standard syntax is `ADD{S}<c><q> {<Rd>,} SP, #<const>` with `Rd`
/// omitted when it is `SP`, which it always is in these two encodings — hence
/// the two-operand `add sp, #imm` rather than a three-operand form.
fn decode_adjust_sp(hw1: u16, addr: u32, mnemonic: &'static str, encoding: &'static str) -> Insn {
    let imm = i64::from(hw1 & 0x7F) * 4;
    narrow(
        mnemonic,
        encoding,
        addr,
        ops([Operand::Reg(Reg::SP), Operand::Imm(imm)]),
    )
}

/// `CBZ` / `CBNZ` T1 — `1011 op 0 i 1 imm5 Rn`, A7.7.21.
///
/// The offset is `ZeroExtend(i:imm5:'0')`: **unsigned**, so these branch only
/// forward, 0 to 126 bytes. Sign-extending here is the classic bug — it is
/// invisible for `i == 0` and wrong for every offset of 64 bytes or more, which
/// is exactly the range a compiler reaches for when the branch is worth a `CBZ`
/// at all. The target is `PC + imm32`, and Thumb's `PC` reads as the
/// instruction's address plus four.
///
/// Note the bit positions: `op` (zero vs non-zero) is bit 11 and `i` is bit 9,
/// with a fixed `1` at bit 8. Reading them off Table A5-6's opcode column
/// instead of the bit diagram puts `i` in the wrong place, because the column
/// only shows `hw1[11:5]`.
fn decode_cb(hw1: u16, addr: u32) -> Insn {
    let nonzero = hw1 & (1 << 11) != 0;
    let i = (hw1 >> 9) & 1;
    let imm5 = (hw1 >> 3) & 0x1F;
    let offset = u32::from((i << 6) | (imm5 << 1));
    let target = addr.wrapping_add(4).wrapping_add(offset);
    narrow(
        if nonzero { "cbnz" } else { "cbz" },
        "T1",
        addr,
        ops([
            Operand::Reg(Reg((hw1 & 0x7) as u8)),
            Operand::Target(target),
        ]),
    )
}

/// `SXTH` / `SXTB` / `UXTH` / `UXTB` T1 — `1011 0010 op Rm Rd`,
/// A7.7.184/A7.7.183/A7.7.219/A7.7.218.
///
/// Two low registers and nothing else: the 16-bit forms have no `<rotation>`
/// operand (that is the T2 encodings' `rotate` field) and do not set flags.
fn decode_extend(hw1: u16, addr: u32) -> Insn {
    let mnemonic = match (hw1 >> 6) & 0b11 {
        0b00 => "sxth",
        0b01 => "sxtb",
        0b10 => "uxth",
        _ => "uxtb",
    };
    narrow(mnemonic, "T1", addr, decode_rd_rm(hw1))
}

/// `REV` / `REV16` / `REVSH` T1 — `1011 1010 op Rm Rd`,
/// A7.7.113/A7.7.114/A7.7.115.
///
/// `op == 0b10` is absent from Table A5-6 (there is no 16-bit `RBIT`) and is
/// therefore UNDEFINED, which is why this returns an `Option` where
/// [`decode_extend`] does not.
fn decode_reverse(hw1: u16, addr: u32) -> Option<Insn> {
    let mnemonic = match (hw1 >> 6) & 0b11 {
        0b00 => "rev",
        0b01 => "rev16",
        0b10 => return None,
        _ => "revsh",
    };
    Some(narrow(mnemonic, "T1", addr, decode_rd_rm(hw1)))
}

/// The `<Rd>, <Rm>` operand pair shared by the extends and the byte reverses:
/// `Rm` at bits 5:3, `Rd` at bits 2:0, both low registers.
fn decode_rd_rm(hw1: u16) -> Operands {
    ops([
        Operand::Reg(Reg((hw1 & 0x7) as u8)),
        Operand::Reg(Reg(((hw1 >> 3) & 0x7) as u8)),
    ])
}

/// `PUSH` T1 (`1011 010 M register_list`, A7.7.101) and `POP` T1
/// (`1011 110 P register_list`, A7.7.99).
///
/// The extra bit is bit 8 of the halfword but **not** bit 8 of the register
/// list: `PUSH` forms `registers = '0':M:'000000':register_list`, putting `M` at
/// bit 14 (`lr`), and `POP` forms `registers = P:'0000000':register_list`,
/// putting `P` at bit 15 (`pc`). Reproducing the halfword's own bit 8 in the
/// mask would name `r8`, which neither encoding can reach — and would defeat
/// [`Insn::writes_pc`], which asks whether a `pop`'s list contains bit 15. Every
/// consumer's control-flow analysis rests on that one bit.
///
/// An empty list is refused: `if BitCount(registers) < 1 then UNPREDICTABLE`
/// (A7.7.101, A7.7.99), and `push {}` has no UAL spelling that re-assembles.
/// That is one halfword each, `0xB400` and `0xBC00`.
fn decode_push_pop(hw1: u16, addr: u32, mnemonic: &'static str, extra_bit: u8) -> Option<Insn> {
    let list = (hw1 & 0xFF) | (((hw1 >> 8) & 1) << extra_bit);
    if list == 0 {
        return None;
    }
    Some(narrow(mnemonic, "T1", addr, ops([Operand::RegList(list)])))
}

/// `SETEND` T1 — `1011 0110 010 (1) E (0)(0)(0)`, ARM DDI 0406B A8.6.157.
///
/// **A/R profile only.** Table A5-6 does not allocate `opcode == 0b0110010`, so
/// on the M profile this halfword is UNDEFINED; it is decoded here because the
/// crate reads A/R images too, and a consumer that must be strict can reject
/// the `"setend"` mnemonic. `SETEND` must be unconditional and is not permitted
/// in an IT block.
fn decode_setend(hw1: u16, addr: u32) -> Option<Insn> {
    // Bit 4 is SBO, bits 2:0 SBZ; bit 3 is E.
    if hw1 & 0x17 != 0x10 {
        return None;
    }
    let endian = if hw1 & (1 << 3) != 0 { "be" } else { "le" };
    Some(narrow("setend", "T1", addr, ops([Operand::Text(endian)])))
}

/// `CPS` T1 — `1011 0110 011 im (0) A I F`, ARM DDI 0406B B6.1.1 and
/// DDI 0403E.e B5.2.1.
///
/// `im` selects the mnemonic — `cpsie` enables (clears the mask bits), `cpsid`
/// disables — and `A:I:F` selects the `<iflags>` string. The `A` bit at position
/// 2 is the A/R encoding; the M profile has a should-be-zero bit there and only
/// `I` and `F`, so an `a` in the flags means the halfword is meaningful only on
/// A/R. `CPS` must be unconditional and is not permitted in an IT block.
fn decode_cps(hw1: u16, addr: u32) -> Option<Insn> {
    if hw1 & (1 << 3) != 0 {
        return None; // SBZ bit set.
    }
    let iflags = CPS_IFLAGS[(hw1 & 0b111) as usize];
    if iflags.is_empty() {
        return None; // `A:I:F == 000` has no <iflags> to print.
    }
    let mnemonic = if hw1 & (1 << 4) != 0 {
        "cpsid"
    } else {
        "cpsie"
    };
    Some(narrow(mnemonic, "T1", addr, ops([Operand::Text(iflags)])))
}

/// `BKPT` T1 — `1011 1110 imm8`, A7.7.17.
///
/// The one instruction in this group that carries a condition: A7.7.17 states
/// that "BKPT is an unconditional instruction and executes as such both inside
/// and outside an IT instruction block". [`super::Decoder`] attaches the
/// enclosing IT block's condition to any instruction whose `cond` is `None`, so
/// leaving it `None` here would make a `BKPT` inside an IT block come back
/// conditional — wrong, and wrong in a way that changes how a debugger reads
/// the block. Setting [`Cond::Al`] states the truth (it always executes),
/// prints as nothing, and stops the `Decoder` from overwriting it.
///
/// `imm8` is ignored by hardware; it exists so a debugger can tag the
/// breakpoint, and is preserved here for exactly that reason.
fn decode_bkpt(hw1: u16, addr: u32) -> Insn {
    let mut insn = narrow(
        "bkpt",
        "T1",
        addr,
        ops([Operand::Imm(i64::from(hw1 & 0xFF))]),
    );
    insn.cond = Some(Cond::Al);
    insn
}

/// `IT` and the hint instructions — `1011 1111 opA opB`, Table A5-7.
///
/// `opB` (bits 3:0) is `IT`'s `mask`, and `mask == 0b0000` is *not* an `IT`: it
/// is the hint space, where `opA` names `NOP`/`YIELD`/`WFE`/`WFI`/`SEV`. `opA`
/// is `IT`'s `firstcond`. Those positions are the same ones
/// [`super::it_state_from`] reads, and the same ones A7.7.38's operation
/// pseudocode assigns from: `ITSTATE.IT<7:0> = firstcond:mask`.
fn decode_it_or_hint(hw1: u16, addr: u32) -> Option<Insn> {
    let firstcond = ((hw1 >> 4) & 0xF) as u8;
    let mask = (hw1 & 0xF) as u8;

    if mask == 0 {
        let mnemonic = match firstcond {
            0b0000 => "nop",
            0b0001 => "yield",
            0b0010 => "wfe",
            0b0011 => "wfi",
            0b0100 => "sev",
            // Unallocated hint: executes as a NOP but has no mnemonic, and
            // decoding it as one would lose `opA`. See the module docs.
            _ => return None,
        };
        return Some(narrow(mnemonic, "T1", addr, Operands::new()));
    }

    // `if firstcond == '1111' || (firstcond == '1110' && BitCount(mask) != 1)
    //  then UNPREDICTABLE` — A7.7.38.
    let cond = Cond::from_bits(firstcond)?;
    if cond == Cond::Al && mask.count_ones() != 1 {
        return None;
    }
    let (len, letters) = it_letters_from_mask(firstcond, mask);
    let mnemonic = it_spelling(len, letters);

    // `Cond::suffix()` renders `AL` as the empty string, which is right for a
    // mnemonic suffix and wrong here: A7.7.38's syntax makes `<firstcond>` an
    // operand, and the Table A7-1 footnote that lets `AL` be omitted
    // explicitly excepts `IT`. So `it al` is spelled out.
    let operand = if cond == Cond::Al {
        Operand::Text("al")
    } else {
        Operand::Cond(cond)
    };
    Some(narrow(mnemonic, "T1", addr, ops([operand])))
}

/// Recover `IT`'s `<x><y><z>` letters from `firstcond` and `mask`, as the
/// number of letters and a `true`-is-`T` flag for each.
///
/// The inverse of Table A7-3 (A7.7.38). That table is sixteen rows, but the rule
/// behind it is two sentences: `mask` is the letters, most significant first,
/// terminated by a single `1` bit — so the position of the lowest set bit gives
/// the count, `3 - trailing_zeros(mask)` — and each letter bit is `firstcond[0]`
/// for `T` and its complement for `E`, because `E` means "the same condition
/// with its least significant bit inverted". Check it against the table's
/// extremes: `mask == 0b1000` has its terminator at bit 3 and so no letters
/// (`IT`), and `mask == 0bxyz1` has three (`IT{x}{y}{z}`).
fn it_letters_from_mask(firstcond: u8, mask: u8) -> (u8, [bool; 3]) {
    let fc0 = firstcond & 1;
    let len = 3 - (mask.trailing_zeros().min(3) as u8);
    let mut letters = [true; 3];
    for (i, letter) in letters.iter_mut().enumerate().take(len as usize) {
        *letter = (mask >> (3 - i)) & 1 == fc0;
    }
    (len, letters)
}

/// The fifteen `IT` spellings of Table A7-3, indexed by
/// `(1 << len) - 1 + letters`, where `letters` reads the `T`/`E` flags most
/// significant first with `T` as 1.
///
/// A table rather than a match, because a match on `(len, [bool; 3])` cannot
/// be exhaustive without an arm for the `len > 3` that
/// [`it_letters_from_mask`] cannot produce — and an unreachable arm claiming
/// there is a sixteenth case is worse than the arithmetic that replaces it.
/// The arithmetic is checked against the rule, spelling by spelling, in
/// `it_spellings_match_table_a7_3`.
const IT_SPELLINGS: [&str; 15] = [
    "it", // no letters
    "ite", "itt", // one
    "itee", "itet", "itte", "ittt", // two
    "iteee", "iteet", "itete", "itett", "ittee", "ittet", "ittte", "itttt", // three
];

/// The UAL mnemonic for an `IT` with `len` `T`/`E` letters.
///
/// `len` is at most 3 — it is `3 - trailing_zeros(mask).min(3)` — so the index
/// is at most `2^4 - 2`, inside the table.
fn it_spelling(len: u8, letters: [bool; 3]) -> &'static str {
    let len = usize::from(len);
    let mut index = (1usize << len) - 1;
    for (i, letter) in letters.iter().enumerate().take(len) {
        index += usize::from(*letter) << (len - 1 - i);
    }
    IT_SPELLINGS[index]
}

/// The inverse of [`it_spelling`].
fn it_letters_from_name(name: &str) -> Option<(u8, [bool; 3])> {
    let (len, letters) = match name {
        "it" => (0, [true, true, true]),
        "itt" => (1, [true, true, true]),
        "ite" => (1, [false, true, true]),
        "ittt" => (2, [true, true, true]),
        "itte" => (2, [true, false, true]),
        "itet" => (2, [false, true, true]),
        "itee" => (2, [false, false, true]),
        "itttt" => (3, [true, true, true]),
        "ittte" => (3, [true, true, false]),
        "ittet" => (3, [true, false, true]),
        "ittee" => (3, [true, false, false]),
        "itett" => (3, [false, true, true]),
        "itete" => (3, [false, true, false]),
        "iteet" => (3, [false, false, true]),
        "iteee" => (3, [false, false, false]),
        _ => return None,
    };
    Some((len, letters))
}

/// Re-encode an instruction this module decoded, back to its halfword.
///
/// Returns `None` for anything this module did not produce, and for an operand
/// that cannot be expressed in the 16-bit encoding — an out-of-range immediate,
/// a high register where only `r0`–`r7` fit, a `push` list naming a register
/// other than `r0`–`r7`/`lr`, or a `CBZ` whose target is not an even 0–126
/// bytes ahead. `insn.addr` is what `CBZ`/`CBNZ` targets are resolved against,
/// so re-encoding at a different address deliberately fails rather than
/// silently relocating the branch.
pub(crate) fn encode(insn: &Insn) -> Option<u16> {
    match insn.mnemonic {
        "add" if insn.encoding == "T2" => encode_adjust_sp(insn, 0xB000),
        "sub" if insn.encoding == "T1" => encode_adjust_sp(insn, 0xB080),
        "cbz" => encode_cb(insn, 0xB100),
        "cbnz" => encode_cb(insn, 0xB900),
        "sxth" => encode_rd_rm(insn, 0xB200),
        "sxtb" => encode_rd_rm(insn, 0xB240),
        "uxth" => encode_rd_rm(insn, 0xB280),
        "uxtb" => encode_rd_rm(insn, 0xB2C0),
        "push" => encode_push_pop(insn, 0xB400, 14),
        "setend" => match insn.operands.get(0) {
            Some(Operand::Text("le")) => Some(0xB650),
            Some(Operand::Text("be")) => Some(0xB658),
            _ => None,
        },
        "cpsie" => encode_cps(insn, 0xB660),
        "cpsid" => encode_cps(insn, 0xB670),
        "rev" => encode_rd_rm(insn, 0xBA00),
        "rev16" => encode_rd_rm(insn, 0xBA40),
        "revsh" => encode_rd_rm(insn, 0xBAC0),
        "pop" => encode_push_pop(insn, 0xBC00, 15),
        "bkpt" => match insn.operands.get(0) {
            Some(Operand::Imm(v)) if (0..=255).contains(&v) => Some(0xBE00 | (v as u16)),
            _ => None,
        },
        "nop" => Some(0xBF00),
        "yield" => Some(0xBF10),
        "wfe" => Some(0xBF20),
        "wfi" => Some(0xBF30),
        "sev" => Some(0xBF40),
        _ => encode_it(insn),
    }
}

/// `ADD SP, #imm` / `SUB SP, #imm` — multiples of four, 0 to 508.
fn encode_adjust_sp(insn: &Insn, base: u16) -> Option<u16> {
    if insn.operands.len() != 2 || insn.operands.get(0) != Some(Operand::Reg(Reg::SP)) {
        return None;
    }
    match insn.operands.get(1) {
        Some(Operand::Imm(v)) if (0..=508).contains(&v) && v % 4 == 0 => {
            Some(base | (v as u16 / 4))
        }
        _ => None,
    }
}

/// `CBZ` / `CBNZ` — forward only, even, at most 126 bytes.
fn encode_cb(insn: &Insn, base: u16) -> Option<u16> {
    let rn = match insn.operands.get(0) {
        Some(Operand::Reg(r)) if r.is_low() => u16::from(r.num()),
        _ => return None,
    };
    let target = match insn.operands.get(1) {
        Some(Operand::Target(t)) => t,
        _ => return None,
    };
    let offset = target.wrapping_sub(insn.addr.wrapping_add(4));
    if offset > 126 || offset % 2 != 0 {
        return None;
    }
    let offset = offset as u16;
    Some(base | ((offset & 0x40) << 3) | ((offset & 0x3E) << 2) | rn)
}

/// The `<Rd>, <Rm>` extends and byte reverses.
fn encode_rd_rm(insn: &Insn, base: u16) -> Option<u16> {
    match (insn.operands.get(0), insn.operands.get(1)) {
        (Some(Operand::Reg(rd)), Some(Operand::Reg(rm))) if rd.is_low() && rm.is_low() => {
            Some(base | (u16::from(rm.num()) << 3) | u16::from(rd.num()))
        }
        _ => None,
    }
}

/// `PUSH` / `POP`, folding the register list's bit 14 (`lr`) or bit 15 (`pc`)
/// back into the halfword's bit 8.
fn encode_push_pop(insn: &Insn, base: u16, extra_bit: u8) -> Option<u16> {
    let list = match insn.operands.get(0) {
        Some(Operand::RegList(bits)) => bits,
        _ => return None,
    };
    let allowed = 0x00FF | (1u16 << extra_bit);
    // An empty list is UNPREDICTABLE and no longer decodes, so it must not
    // encode either — otherwise `encode` would hand back a halfword this
    // module's own `decode` refuses.
    if list == 0 || list & !allowed != 0 {
        return None;
    }
    Some(base | (list & 0xFF) | (((list >> extra_bit) & 1) << 8))
}

/// `CPSIE` / `CPSID`, mapping `<iflags>` back to `A:I:F`.
fn encode_cps(insn: &Insn, base: u16) -> Option<u16> {
    let flags = match insn.operands.get(0) {
        Some(Operand::Text(s)) => s,
        _ => return None,
    };
    let aif = CPS_IFLAGS
        .iter()
        .position(|f| *f == flags)
        .filter(|i| *i != 0)?;
    Some(base | aif as u16)
}

/// `IT{x{y{z}}} <firstcond>`, rebuilding `mask` from the mnemonic's letters and
/// `firstcond[0]` per Table A7-3.
fn encode_it(insn: &Insn) -> Option<u16> {
    let (len, letters) = it_letters_from_name(insn.mnemonic)?;
    // `0b1111` needs no check of its own here: `Cond::from_bits` refuses it,
    // so no `Cond` can hold it and `Cond::bits()` never returns it — the
    // condition that is not a condition cannot arrive through either arm.
    let firstcond = match insn.operands.get(0) {
        Some(Operand::Cond(c)) => c.bits(),
        Some(Operand::Text("al")) => Cond::Al.bits(),
        _ => return None,
    };
    let fc0 = firstcond & 1;
    let mut mask = 1u8 << (3 - len);
    for (i, letter) in letters.iter().enumerate().take(len as usize) {
        let bit = if *letter { fc0 } else { fc0 ^ 1 };
        mask |= bit << (3 - i);
    }
    // `AL` admits no `E`, which is exactly `BitCount(mask) == 1` — A7.7.38.
    if firstcond == Cond::Al.bits() && mask.count_ones() != 1 {
        return None;
    }
    Some(0xBF00 | (u16::from(firstcond) << 4) | u16::from(mask))
}

#[cfg(test)]
mod tests {
    use super::super::{it_state_from, ItState};
    use super::*;

    /// A fixed decode address, deliberately not zero so that a `CBZ` target
    /// which forgot to add `PC` would not accidentally match.
    const ADDR: u32 = 0x1000;

    fn dis(hw1: u16) -> String {
        decode(hw1, 0, ADDR).expect("should decode").to_string()
    }

    /// Every halfword in `0xB000..=0xBFFF` that decodes must re-encode to
    /// itself, and the number that decode is a claim about where this group's
    /// UNDEFINED holes are — see `undefined_holes_are_accounted_for`.
    #[test]
    fn exhaustive_round_trip() {
        let mut decoded = 0usize;
        for hw in 0xB000u32..=0xBFFFu32 {
            let hw = hw as u16;
            if let Some(insn) = decode(hw, 0, ADDR) {
                decoded += 1;
                assert_eq!(
                    encode(&insn),
                    Some(hw),
                    "{hw:#06x} decoded as `{insn}` did not re-encode"
                );
                assert!(!insn.sets_flags, "{hw:#06x} `{insn}` must not set flags");
                assert!(!insn.explicit_width, "{hw:#06x} `{insn}` is never .n/.w");
                assert_eq!(insn.width, Width::Narrow);
                assert_eq!(insn.addr, ADDR);
            }
        }
        // 4096 halfwords in `0xB000..=0xBFFF`, less the 855 the next test
        // accounts for one group at a time.
        assert_eq!(decoded, 3241);
    }

    /// The 855 halfwords that do not decode, one group at a time. Every one of
    /// them is either an opcode Table A5-6/A6-6 leaves out, or an encoding
    /// whose should-be-zero bits or UNPREDICTABLE-ness the module docs explain.
    #[test]
    fn undefined_holes_are_accounted_for() {
        let mut undecoded: Vec<u16> = (0xB000u32..=0xBFFF)
            .map(|hw| hw as u16)
            .filter(|hw| decode(*hw, 0, ADDR).is_none())
            .collect();
        assert_eq!(undecoded.len(), 855);
        undecoded.sort_unstable();

        let mut expected: Vec<u16> = Vec::new();
        // 24 unallocated opcodes x 32 halfwords each = 768.
        let unallocated_opcodes: Vec<u16> = (0b011_0000..=0b011_0001)
            .chain(0b011_0100..=0b011_0111) // rest of 0110xxx
            .chain(0b011_1000..=0b011_1111) // 0111xxx
            .chain(0b100_0000..=0b100_0111) // 1000xxx
            .chain(0b101_0100..=0b101_0101) // 101010x: no 16-bit RBIT
            .collect();
        assert_eq!(unallocated_opcodes.len(), 24);
        for op in unallocated_opcodes {
            expected.extend((0..32).map(|low| 0xB000 | (op << 5) | low));
        }
        // SETEND: 32 halfwords at opcode 0110010, only two canonical.
        expected.extend((0xB640..=0xB65F).filter(|hw| *hw != 0xB650 && *hw != 0xB658));
        // CPS: 32 halfwords at opcode 0110011; bit 3 must be 0 (16 gone) and
        // A:I:F must not be 000 (2 more).
        expected.extend((0xB660..=0xB67F).filter(|hw| *hw & 8 != 0 || *hw & 7 == 0));
        // PUSH/POP with an empty register list: `BitCount(registers) < 1` is
        // UNPREDICTABLE (A7.7.101, A7.7.99), one halfword each.
        expected.push(0xB400);
        expected.push(0xBC00);
        // IT/hints: 11 unallocated hints, 15 with firstcond == 0b1111, and 11
        // with firstcond == AL and more than one mask bit set.
        expected.extend((0b0101..=0b1111).map(|opa: u16| 0xBF00 | (opa << 4)));
        expected.extend(0xBFF1..=0xBFFF);
        expected.extend(
            (1u16..=15)
                .filter(|m| m.count_ones() != 1)
                .map(|m| 0xBFE0 | m),
        );

        expected.sort_unstable();
        assert_eq!(expected.len(), 768 + 30 + 18 + 2 + 37);
        assert_eq!(undecoded, expected);
    }

    /// Per-row decode counts, so a mistake in one row cannot be hidden by a
    /// compensating mistake in another.
    #[test]
    fn per_row_decode_counts() {
        let mut counts = std::collections::BTreeMap::new();
        for hw in 0xB000u32..=0xBFFF {
            if let Some(insn) = decode(hw as u16, 0, ADDR) {
                *counts.entry(insn.mnemonic).or_insert(0usize) += 1;
            }
        }
        // `it` counts only the bare spelling; the 15 ITxyz spellings are summed
        // separately below.
        for (mnemonic, want) in [
            ("add", 128),
            ("sub", 128),
            ("cbz", 512),
            ("cbnz", 512),
            ("sxth", 64),
            ("sxtb", 64),
            ("uxth", 64),
            ("uxtb", 64),
            // 512 halfwords in each row, less the empty register list.
            ("push", 511),
            ("setend", 2),
            ("cpsie", 7),
            ("cpsid", 7),
            ("rev", 64),
            ("rev16", 64),
            ("revsh", 64),
            ("pop", 511),
            ("bkpt", 256),
            ("nop", 1),
            ("yield", 1),
            ("wfe", 1),
            ("wfi", 1),
            ("sev", 1),
        ] {
            assert_eq!(counts.get(mnemonic), Some(&want), "count for {mnemonic}");
        }
        let its: usize = counts
            .iter()
            .filter(|(m, _)| m.starts_with("it"))
            .map(|(_, n)| *n)
            .sum();
        // 16 firstcond x 15 non-zero masks, less firstcond == 0b1111 (15) and
        // less AL with more than one mask bit (11).
        assert_eq!(its, 16 * 15 - 15 - 11);
    }

    /// One printed-UAL assertion per row of Table A5-6/A6-6, with the expected
    /// text taken from each instruction's `Assembler syntax` section.
    #[test]
    fn printed_ual_covers_every_row() {
        // ADD (SP plus immediate) T2 / SUB (SP minus immediate) T1: imm7*4.
        assert_eq!(dis(0xB000), "add sp, #0");
        assert_eq!(dis(0xB005), "add sp, #0x14");
        assert_eq!(dis(0xB07F), "add sp, #0x1fc"); // 508, the maximum
        assert_eq!(dis(0xB080), "sub sp, #0");
        assert_eq!(dis(0xB085), "sub sp, #0x14");
        assert_eq!(dis(0xB0FF), "sub sp, #0x1fc");

        // CBZ / CBNZ: `CB{N}Z <Rn>, <label>`, forward only.
        assert_eq!(dis(0xB108), "cbz r0, 0x1006");
        assert_eq!(dis(0xB908), "cbnz r0, 0x1006");

        // SXTH/SXTB/UXTH/UXTB, REV/REV16/REVSH: `<mnemonic> <Rd>, <Rm>`.
        assert_eq!(dis(0xB211), "sxth r1, r2");
        assert_eq!(dis(0xB251), "sxtb r1, r2");
        assert_eq!(dis(0xB291), "uxth r1, r2");
        assert_eq!(dis(0xB2D1), "uxtb r1, r2");
        assert_eq!(dis(0xBA11), "rev r1, r2");
        assert_eq!(dis(0xBA51), "rev16 r1, r2");
        assert_eq!(dis(0xBAD1), "revsh r1, r2");
        assert!(decode(0xBA91, 0, ADDR).is_none(), "101010x is UNDEFINED");

        // PUSH / POP: `<mnemonic> <registers>`.
        assert_eq!(dis(0xB410), "push {r4}");
        assert_eq!(dis(0xB5F0), "push {r4-r7, lr}");
        assert_eq!(dis(0xBC10), "pop {r4}");
        assert_eq!(dis(0xBDF0), "pop {r4-r7, pc}");

        // SETEND (A/R only): `SETEND <endian_specifier>`.
        assert_eq!(dis(0xB650), "setend le");
        assert_eq!(dis(0xB658), "setend be");

        // CPS: `CPS<effect> <iflags>`.
        assert_eq!(dis(0xB661), "cpsie f");
        assert_eq!(dis(0xB662), "cpsie i");
        assert_eq!(dis(0xB663), "cpsie if");
        assert_eq!(dis(0xB667), "cpsie aif");
        assert_eq!(dis(0xB672), "cpsid i");
        assert_eq!(dis(0xB674), "cpsid a");

        // BKPT: `BKPT #<imm8>`.
        assert_eq!(dis(0xBE00), "bkpt #0");
        assert_eq!(dis(0xBEAB), "bkpt #0xab");

        // IT and hints: `IT{x{y{z}}} <firstcond>`, and the five named hints.
        assert_eq!(dis(0xBF08), "it eq");
        assert_eq!(dis(0xBF00), "nop");
        assert_eq!(dis(0xBF10), "yield");
        assert_eq!(dis(0xBF20), "wfe");
        assert_eq!(dis(0xBF30), "wfi");
        assert_eq!(dis(0xBF40), "sev");
        assert!(decode(0xBF50, 0, ADDR).is_none(), "unallocated hint");
    }

    /// `push {lr}` / `pop {pc}` — the standard ARM prologue and epilogue, and
    /// the place where mistaking the halfword's bit 8 for register-list bit 8
    /// would silently break every consumer's control-flow analysis.
    #[test]
    fn prologue_and_epilogue() {
        let push = decode(0xB500, 0, ADDR).unwrap();
        assert_eq!(push.to_string(), "push {lr}");
        assert_eq!(push.operands.get(0), Some(Operand::RegList(1 << 14)));
        assert!(!push.writes_pc());

        let pop = decode(0xBD00, 0, ADDR).unwrap();
        assert_eq!(pop.to_string(), "pop {pc}");
        assert_eq!(pop.operands.get(0), Some(Operand::RegList(1 << 15)));
        assert!(pop.writes_pc(), "pop {{pc}} must be seen to write pc");
        assert!(pop.is_branch());

        // The full-width variants keep lr/pc where write_reglist can name them.
        assert_eq!(dis(0xB5FF), "push {r0-r7, lr}");
        assert_eq!(dis(0xBDFF), "pop {r0-r7, pc}");

        // `BitCount(registers) < 1` is UNPREDICTABLE (A7.7.101, A7.7.99) and
        // has no UAL spelling: `push {}` is not something an assembler reads.
        // Both halfwords are refused, and they are the only two in the two
        // rows that are — `push {r0}` and `pop {pc}` are one bit away.
        assert_eq!(
            decode(0xB400, 0, ADDR),
            None,
            "`push {{}}` is not an instruction"
        );
        assert_eq!(
            decode(0xBC00, 0, ADDR),
            None,
            "`pop {{}}` is not an instruction"
        );
        assert_eq!(dis(0xB401), "push {r0}");
        assert_eq!(dis(0xB500), "push {lr}");
        assert_eq!(dis(0xBC01), "pop {r0}");
        assert_eq!(dis(0xBD00), "pop {pc}");
        // …and a hand-built one does not encode either, so `encode` cannot
        // produce a halfword `decode` refuses.
        let empty = Insn {
            operands: ops([Operand::RegList(0)]),
            ..decode(0xB500, 0, ADDR).unwrap()
        };
        assert_eq!(encode(&empty), None);
    }

    /// `CBZ`'s offset is zero-extended, so the target is always forward and the
    /// `i` bit adds 64 rather than sign-extending.
    #[test]
    fn cbz_is_forward_only() {
        // i = 0, imm5 = 1: +2 bytes from PC.
        let insn = decode(0xB108, 0, ADDR).unwrap();
        assert_eq!(insn.branch_target(), Some(ADDR + 4 + 2));
        // i = 1, imm5 = 0: +64. A sign-extending decoder would say -64.
        let insn = decode(0xB300, 0, ADDR).unwrap();
        assert_eq!(insn.branch_target(), Some(ADDR + 4 + 64));
        assert_eq!(insn.to_string(), "cbz r0, 0x1044");
        // i = 1, imm5 = 31: +126, the maximum permitted offset.
        let insn = decode(0xB3F8, 0, ADDR).unwrap();
        assert_eq!(insn.branch_target(), Some(ADDR + 4 + 126));
        assert!(insn.is_branch());
        // Nothing in the group can reach backwards or past +126.
        for hw in 0xB000u32..=0xBFFF {
            if let Some(i) = decode(hw as u16, 0, ADDR) {
                if let Some(t) = i.branch_target() {
                    assert!((ADDR + 4..=ADDR + 4 + 126).contains(&t), "{hw:#06x}");
                }
            }
        }
        // Re-encoding at a different address must not silently relocate: moved
        // past its own target, the offset is unencodable rather than wrapping
        // round into a backward branch.
        let insn = decode(0xB3F8, 0, ADDR).unwrap();
        let moved = Insn {
            addr: ADDR + 128,
            ..insn
        };
        assert_eq!(encode(&moved), None, "target is behind the instruction");
        let moved = Insn {
            addr: ADDR - 2,
            ..insn
        };
        assert_eq!(encode(&moved), None, "+128 exceeds the 126-byte reach");
        let moved = Insn {
            addr: ADDR + 2,
            ..insn
        };
        assert_eq!(encode(&moved), Some(0xB3F0), "one imm5 step closer");
    }

    /// The `IT{x{y{z}}}` spelling rule of Table A7-3: the letters live in
    /// `mask`, most significant first, terminated by a single set bit, and each
    /// is `T` when it equals `firstcond[0]`.
    #[test]
    fn it_spellings() {
        // firstcond = EQ (0b0000), so firstcond[0] == 0 and a zero bit is `T`.
        assert_eq!(dis(0xBF08), "it eq"); // mask 1000
        assert_eq!(dis(0xBF04), "itt eq"); // mask 0100
        assert_eq!(dis(0xBF0C), "ite eq"); // mask 1100
        assert_eq!(dis(0xBF02), "ittt eq"); // mask 0010
        assert_eq!(dis(0xBF06), "itte eq"); // mask 0110
        assert_eq!(dis(0xBF0A), "itet eq"); // mask 1010
        assert_eq!(dis(0xBF0E), "itee eq"); // mask 1110
        assert_eq!(dis(0xBF01), "itttt eq"); // mask 0001
        assert_eq!(dis(0xBF0F), "iteee eq"); // mask 1111

        // firstcond = NE (0b0001) inverts the sense of every mask bit — the
        // same mask that spells `itt eq` spells `ite ne`.
        assert_eq!(dis(0xBF18), "it ne");
        assert_eq!(dis(0xBF14), "ite ne");
        assert_eq!(dis(0xBF1C), "itt ne");
        assert_eq!(dis(0xBF12), "itee ne");

        // AL admits no `E`, i.e. exactly one mask bit may be set.
        assert_eq!(dis(0xBFE8), "it al");
        assert_eq!(dis(0xBFE4), "itt al");
        assert_eq!(dis(0xBFE2), "ittt al");
        assert_eq!(dis(0xBFE1), "itttt al");
        assert!(
            decode(0xBFEC, 0, ADDR).is_none(),
            "`ite al` is UNPREDICTABLE"
        );
        assert!(decode(0xBFF8, 0, ADDR).is_none(), "firstcond 0b1111");
    }

    /// The cross-module invariant: what this module calls an `IT` must agree
    /// with [`super::it_state_from`], which reads `firstcond` from bits 7:4 and
    /// `mask` from bits 3:0 — A7.7.38's `ITSTATE.IT<7:0> = firstcond:mask`.
    #[test]
    fn it_agrees_with_it_state() {
        for (hw, cond, mask, governed) in [
            (0xBF08u16, 0b0000u8, 0b1000u8, 1usize), // it eq
            (0xBF04, 0b0000, 0b0100, 2),             // itt eq
            (0xBF0C, 0b0000, 0b1100, 2),             // ite eq
            (0xBF02, 0b0000, 0b0010, 3),             // ittt eq
            (0xBF01, 0b0000, 0b0001, 4),             // itttt eq
            (0xBF1C, 0b0001, 0b1100, 2),             // itt ne
            (0xBFE8, 0b1110, 0b1000, 1),             // it al
        ] {
            let insn = decode(hw, 0, ADDR).unwrap();
            assert!(insn.mnemonic.starts_with("it"), "{hw:#06x} {insn}");
            let state = it_state_from(hw);
            assert_eq!(state, ItState { cond, mask }, "{hw:#06x} `{insn}`");
            assert_eq!(state.current(), Cond::from_bits(cond));

            // An `IT` with n letters governs n+1 instructions; walking
            // `advance()` to inactivity is how `Decoder` counts them.
            let mut state = state;
            let mut n = 0;
            while state.active() {
                n += 1;
                state = state.advance();
                assert!(n <= 4, "{hw:#06x} `{insn}` never ends");
            }
            assert_eq!(n, governed, "{hw:#06x} `{insn}` block length");
        }
        assert_eq!(it_state_from(0xBF00), ItState::INACTIVE);
    }

    /// `BKPT` executes unconditionally inside an IT block (A7.7.17), so it
    /// carries `AL` to stop `Decoder` from conditionalising it — and `AL`
    /// prints as nothing, so the UAL is unaffected.
    #[test]
    fn bkpt_is_unconditional() {
        let insn = decode(0xBE00, 0, ADDR).unwrap();
        assert_eq!(insn.cond, Some(Cond::Al));
        assert_eq!(insn.to_string(), "bkpt #0");
        // Everything else in the group carries no condition of its own.
        for hw in 0xB000u32..=0xBFFF {
            if let Some(i) = decode(hw as u16, 0, ADDR) {
                if i.mnemonic != "bkpt" {
                    assert_eq!(i.cond, None, "{hw:#06x} `{i}`");
                }
            }
        }
    }

    /// `encode` must refuse what the 16-bit encodings cannot express, rather
    /// than truncating it.
    #[test]
    fn encode_rejects_inexpressible() {
        let base = decode(0xB000, 0, ADDR).unwrap();
        for imm in [-4i64, 2, 510, 512] {
            let bad = Insn {
                operands: ops([Operand::Reg(Reg::SP), Operand::Imm(imm)]),
                ..base
            };
            assert_eq!(encode(&bad), None, "add sp, #{imm}");
        }
        // PUSH cannot name pc, POP cannot name lr, neither can name r8.
        let push = decode(0xB500, 0, ADDR).unwrap();
        for bits in [1u16 << 15, 1 << 8, 1 << 13] {
            let bad = Insn {
                operands: ops([Operand::RegList(bits)]),
                ..push
            };
            assert_eq!(encode(&bad), None, "push {bits:#x}");
        }
        let pop = decode(0xBD00, 0, ADDR).unwrap();
        let bad = Insn {
            operands: ops([Operand::RegList(1 << 14)]),
            ..pop
        };
        assert_eq!(encode(&bad), None, "pop cannot name lr");
        // A foreign mnemonic is not ours to encode.
        let alien = Insn {
            mnemonic: "bl",
            ..base
        };
        assert_eq!(encode(&alien), None);

        // `add sp, #imm` and `sub sp, #imm` are told from their siblings by
        // the encoding name alone: the operand list is identical in all of
        // them. `ADD (SP plus immediate)` is T2 here, T3 (`add.w`) and T4
        // (`addw`) in the 32-bit space; `SUB (SP minus immediate)` is T1 here
        // and T2/T3 there (A7.7.5, A7.7.176). The wide ones are four bytes
        // long, so answering for one of them with this halfword would shrink
        // an instruction in place and leave two bytes of the old encoding
        // behind as data — and the mnemonic alone cannot tell them apart.
        for (hw, mine, theirs) in [(0xB002u16, "T2", "T3"), (0xB082, "T1", "T2")] {
            let right = decode(hw, 0, ADDR).unwrap();
            assert_eq!(right.encoding, mine, "`{right}` is {mine}");
            assert_eq!(encode(&right), Some(hw));
            let renamed = Insn {
                encoding: theirs,
                ..right
            };
            assert_eq!(encode(&renamed), None, "`{renamed}` as {theirs} is wide");
        }
    }

    /// The spelling table against the rule it encodes (A7.7.38, Table A7-3):
    /// `mask` holds the letters most significant first, terminated by a single
    /// set bit, and a letter is `T` when it equals `firstcond[0]`.
    ///
    /// The table replaced a fifteen-arm match, so the rule it was derived from
    /// is asserted here rather than lost — every one of the 30 `(firstcond[0],
    /// mask)` combinations, against a spelling built character by character.
    #[test]
    fn it_spellings_match_table_a7_3() {
        for fc0 in [0u8, 1] {
            for mask in 1u8..=15 {
                let len = 3 - mask.trailing_zeros().min(3);
                let mut expected = String::from("it");
                for i in 0..len {
                    let bit = (mask >> (3 - i)) & 1;
                    expected.push(if bit == fc0 { 't' } else { 'e' });
                }
                let (n, letters) = it_letters_from_mask(fc0, mask);
                assert_eq!(u32::from(n), len, "mask {mask:#06b} letter count");
                assert_eq!(
                    it_spelling(n, letters),
                    expected,
                    "fc0 {fc0} mask {mask:#06b}"
                );
                // …and the inverse agrees, which is what `encode` relies on.
                assert_eq!(
                    it_letters_from_name(&expected),
                    Some((n, letters_of(n, letters))),
                    "{expected} does not read back"
                );
            }
        }
    }

    /// The letters beyond `len` are not part of the spelling, so the inverse
    /// only promises to reproduce the first `len` of them.
    fn letters_of(len: u8, letters: [bool; 3]) -> [bool; 3] {
        let mut out = [true; 3];
        out[..usize::from(len)].copy_from_slice(&letters[..usize::from(len)]);
        out
    }

    /// Every operand `encode` reads, offered something it cannot read.
    ///
    /// [`crate::isa::encode`] hands each narrow instruction to every group in
    /// turn, so a group that read past a guard would emit a halfword for an
    /// instruction belonging to someone else. `add sp, #imm` is the sharp
    /// case: A5.2.1's `ADD (immediate)` T2 shares both mnemonic and encoding
    /// name with A7.7.5's `ADD (SP plus immediate)` T2, and inside an IT block
    /// it carries `sets_flags == false` and so reaches this module — where the
    /// SP check is all that stops `addeq r1, #4` from being re-encoded as
    /// `add sp, #4`.
    #[test]
    fn encode_reads_no_operand_it_has_not_checked() {
        let r0 = Operand::Reg(Reg(0));
        let sp = Operand::Reg(Reg::SP);
        let imm = Operand::Imm(4);
        let cases: &[(u16, &[Operand], &str)] = &[
            // ADD/SUB SP: `<Rd>` is always the SP, and the immediate is a
            // multiple of four in 0..=508.
            (0xB001, &[r0, imm], "the first operand is the SP"),
            (0xB001, &[sp], "two operands"),
            (0xB001, &[sp, imm, imm], "two operands"),
            (0xB001, &[sp, r0], "the second operand is an immediate"),
            (0xB081, &[r0, imm], "SUB's first operand is the SP too"),
            // CBZ/CBNZ: a low register and a resolved forward target.
            (
                0xB108,
                &[Operand::Reg(Reg(8)), Operand::Target(0x1006)],
                "Rn is three bits",
            ),
            (0xB108, &[imm, Operand::Target(0x1006)], "Rn is a register"),
            (0xB108, &[r0, imm], "the target is resolved, not an offset"),
            (0xB108, &[r0], "two operands"),
            // The extends and byte reverses: two low registers.
            (0xB211, &[Operand::Reg(Reg(8)), r0], "Rd is three bits"),
            (0xB211, &[r0, Operand::Reg(Reg(8))], "Rm is three bits"),
            (0xB211, &[r0, imm], "Rm is a register"),
            (0xB211, &[r0], "two operands"),
            (0xBA11, &[r0, imm], "REV takes two registers"),
            // PUSH/POP: a register list, and only registers the row can name.
            (0xB500, &[r0], "the operand is a register list"),
            (0xBD00, &[imm], "the operand is a register list"),
            // SETEND: `le` or `be`, and nothing else.
            (0xB650, &[imm], "the operand is an endianness"),
            (0xB650, &[Operand::Text("mid")], "only `le` and `be` exist"),
            // CPS: one of the seven non-empty `<iflags>` spellings.
            (0xB661, &[imm], "the operand is an iflags string"),
            (
                0xB661,
                &[Operand::Text("")],
                "`A:I:F == 000` has no spelling",
            ),
            (0xB661, &[Operand::Text("fi")], "the order is a, i, f"),
            // BKPT: an eight-bit immediate.
            (0xBE00, &[r0], "the operand is an immediate"),
            (0xBE00, &[Operand::Imm(256)], "imm8 holds 0..=255"),
            (0xBE00, &[Operand::Imm(-1)], "imm8 is unsigned"),
            // IT: a condition, spelled `al` when it is AL.
            (0xBF08, &[imm], "the operand is a condition"),
            (0xBF08, &[Operand::Text("eq")], "only AL is spelled as text"),
        ];
        for &(hw, operands, why) in cases {
            let base = decode(hw, 0, ADDR).expect("the base halfword decodes");
            let bad = Insn {
                operands: operands.iter().copied().collect(),
                ..base
            };
            assert_eq!(encode(&bad), None, "`{bad}` from {hw:#06x}: {why}");
        }

        // `AL` admits no `E` — `BitCount(mask) == 1` (A7.7.38) — so the
        // spellings with an else-arm have no `al` form to encode, even though
        // the mnemonic and the operand are each individually fine.
        for mnemonic in ["ite", "itee", "iteee", "itte"] {
            let bad = Insn {
                mnemonic,
                operands: ops([Operand::Text("al")]),
                ..decode(0xBF08, 0, ADDR).unwrap()
            };
            assert_eq!(encode(&bad), None, "`{mnemonic} al` is UNPREDICTABLE");
        }
        // …while the all-`T` spellings do encode with `al`.
        for (mnemonic, hw) in [("it", 0xBFE8u16), ("itt", 0xBFE4), ("ittt", 0xBFE2)] {
            let good = Insn {
                mnemonic,
                operands: ops([Operand::Text("al")]),
                ..decode(0xBF08, 0, ADDR).unwrap()
            };
            assert_eq!(encode(&good), Some(hw), "`{mnemonic} al`");
        }
    }

    /// Anything outside `0xB000..=0xBFFF` belongs to another group.
    #[test]
    fn rejects_other_groups() {
        for hw in [0x0000u16, 0x4770, 0xAFFF, 0xC000, 0xD000, 0xFFFF] {
            assert!(decode(hw, 0, ADDR).is_none(), "{hw:#06x}");
        }
    }
}
