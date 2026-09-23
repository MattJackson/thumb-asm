//! 32-bit loads and memory hints — `hw1[15:11] == 0b11111` with `hw1[10:4]` in
//! `00xx001` (byte), `00xx011` (halfword) or `00xx101` (word), that is the
//! three sibling tables A5-18, A5-19 and A5-20 (ARM DDI 0403E.e A5.3.7,
//! A5.3.8, A5.3.9; identically ARM DDI 0406B A6.3.7–A6.3.9 and Tables
//! A6-18–A6-20).
//!
//! One file for three tables because they are one table with a size field.
//! Every row of all three has the same shape:
//!
//! ```text
//!  hw1: 1 1 1 1 1 0 0 | S | L | size(3) |   Rn(4)
//!  hw2:       Rt(4)   |        op2(6)   |     …
//! ```
//!
//! where `size` is `001`/`011`/`101` for byte/halfword/word (`111` is
//! UNDEFINED and `hw1[4] == 0` is the store space, A5.3.10, which is another
//! module's), `S` = `hw1[8]` selects the signed load, and `L` = `hw1[7]` is
//! `op1[0]` — which means three different things depending on the row, and
//! that is the first trap in this space:
//!
//! * with `Rn == 1111` it is the literal form's `U` (add/subtract) bit,
//! * otherwise `1` selects the 12-bit unsigned immediate form,
//! * otherwise `0` selects the `op2`-dispatched forms (register index, 8-bit
//!   immediate with `P`/`U`/`W`, unprivileged).
//!
//! `S` with `size == 101` is UNDEFINED: there is no signed word load, because
//! a word needs no widening. Getting `S` inverted swaps `LDRB` with `LDRSB` and
//! `LDRH` with `LDRSH`, which decodes to something plausible and wrong, so it
//! is asserted on directly in this module's tests.
//!
//! # `Rn == 1111` is pc-relative, not "base register r15"
//!
//! Every row whose `Rn` is `1111` is the *literal* form, whatever `op2` says —
//! `op2` is then part of `imm12`. Its base is `Align(PC,4)` (A4.2.2): Thumb's
//! pc reads as the instruction's address plus four, then forced word-aligned.
//! The two steps do not commute, and at a 2-mod-4 address — half of all real
//! instructions — omitting the alignment puts every resolved literal two bytes
//! high. [`literal_base`] is the only place that arithmetic happens, and the
//! tests check it at both alignments.
//!
//! The resolved absolute address is handed out as an [`Operand::Target`]
//! beside the syntactic `[pc, #±imm]` [`Operand::Mem`], so no consumer redoes
//! the arithmetic, and so [`encode`] can cross-check the two.
//!
//! # `Rt == 1111` is a memory hint, not a load into pc
//!
//! In the byte and halfword spaces `Rt == 1111` does not name a destination
//! register: it selects a hint, and Tables A5-19 and A5-20 spell out, row by
//! row, which. (The word space has no such rule — Table A5-18 has no `Rt`
//! column at all — so `ldr.w pc, [r0]` is a real, branching load and is decoded
//! as one.) The tables split those encodings three ways, and this module
//! returns something different for each:
//!
//! 1. **A real hint.** Table A5-20's `Rt == 1111` rows are `PLD` (immediate,
//!    literal, register) and `PLI` (immediate/literal, register). They are
//!    decoded as the instructions they are — mnemonic `pld`/`pli`, no `Rt`
//!    operand, the memory operand alone — and re-encode exactly.
//! 2. **"Unallocated memory hint, treat as NOP."** These are Table A5-19's
//!    `Rt == 1111` rows, in the halfword space. Table A6-19 of DDI 0406B
//!    allocates exactly three of them — `op1 == 01`, and `op1 == 00` with
//!    `op2` of `1100xx` or `000000`, all with `Rn != 1111` — to `PLDW`,
//!    preload-with-intent-to-write, under the ARMv7 Multiprocessing
//!    Extensions; the halfword space *is* the `W` bit of `PLD, PLDW`. This
//!    crate decodes both profiles, so those three decode as `pldw` and
//!    re-encode exactly, with the caveat that an M-profile core executes them
//!    as a NOP. The remaining "treat as NOP" rows (`op1 == 11`; `op1 == 10`
//!    with `op2` of `1100xx` or `000000`; and `op1 == 1x` with `Rn == 1111`)
//!    are allocated by no profile, have no syntax to print and nothing to
//!    re-assemble, so [`decode`] returns `None` for them — a caller stepping
//!    over four bytes sees exactly the NOP-shaped hole the architecture
//!    describes.
//! 3. **UNPREDICTABLE.** The `Rt == 1111` rows the tables mark so — the
//!    writeback and unprivileged rows of both spaces (`op2` of `1xx1xx` or
//!    `1110xx` with `Rn != 1111`), plus the halfword literal rows
//!    (`op1 == 0x`, `Rn == 1111`) — return `None`. The architecture permits a
//!    conforming core to do anything at all with them, including treating them
//!    as UNDEFINED, and naming an instruction here would assert a behaviour no
//!    core owes the caller.
//!
//! # `P`/`U`/`W`, and the row that is not an addressing mode
//!
//! In the 8-bit immediate forms `hw2[10:8]` is `P`/`U`/`W`, and it maps onto
//! [`AddrMode`] and [`Mem::add`], which is `U` verbatim — the offset beside it
//! is an unsigned magnitude, so nothing about `U` is lost when that magnitude
//! is zero:
//!
//! | `P` | `U` | `W` | row | result |
//! |---|---|---|---|---|
//! | 1 | 0 | 0 | `1100xx` | [`AddrMode::Offset`], negative — `[rn, #-imm8]` |
//! | 1 | 1 | 0 | `1110xx` | the unprivileged `LDR*T` forms |
//! | 1 | `U` | 1 | `1xx1xx` | [`AddrMode::PreIndex`] — `[rn, #±imm8]!` |
//! | 0 | `U` | 1 | `1xx1xx` | [`AddrMode::PostIndex`] — `[rn], #±imm8` |
//! | 0 | `U` | 0 | `10x0xx` | UNDEFINED |
//!
//! Note the last two rows against a common misreading: `P == 0 && W == 0` is
//! *not* the unprivileged form, it is UNDEFINED ("`if P == '0' && W == '0'
//! then UNDEFINED`", A7.7.43 encoding T4). The unprivileged form is
//! `P == 1 && U == 1 && W == 0` ("`if P == '1' && U == '1' && W == '0' then
//! SEE LDRT`"), which is why `LDRT` can only ever add.
//!
//! # Offsets here are unscaled
//!
//! Every immediate in this group is a plain byte offset:
//! `imm32 = ZeroExtend(imm12, 32)` and `imm32 = ZeroExtend(imm8, 32)` in every
//! encoding-specific operation from A7.7.43 to A7.7.67. That is the *opposite*
//! of the 16-bit load/store space (A5.2.4), where each immediate is scaled by
//! the access size, so `ldrh.w r0, [r1, #4]` and `ldrh r0, [r1, #4]` put a very
//! different field in the halfword. Assuming symmetry with the narrow space
//! would quadruple every wide word offset; the tests pin the wide offsets
//! against literal byte values for each size.
//!
//! # `#-0`
//!
//! The architecture distinguishes `#0` from `#-0` ("Different instructions are
//! generated for #0 and #-0", and A7.7.44 lists `LDR<c> <Rt>,[PC,#-0]` as a
//! case in its own right). The distinction is unobservable in the effective
//! address — both compute `R[n] ± 0` — and only two row families can express it
//! at all: the literal forms with `imm12 == 0`, and the writeback forms with
//! `imm8 == 0`.
//!
//! It is nevertheless a distinction in the bits, and [`Mem`] keeps it: the
//! offset is an unsigned magnitude and [`Mem::add`] is `U` itself, so `#-0` is
//! `add: false, offset: 0`, prints as `#-0`, and re-encodes to the `U == 0`
//! halfword it came from. An earlier revision stored a sign-corrected `i32`,
//! where `-0 == 0`, and had to map all 328 of these onto their `U == 1` twin;
//! nothing is canonicalised now, every encoding in the group round-trips to
//! itself, and the sweep in this module's tests counts the `#-0` cases only to
//! prove it reaches them.
//!
//! # No flags, and when `.w` is printed
//!
//! Nothing here has an `S` bit in the [`Insn::sets_flags`] sense — `hw1[8]` is
//! the *signedness* of the load, not a flag-setting bit — so `sets_flags` is
//! `false` on every row. `Display` appends an `"s"` when it is set, and `ldrs`
//! is a real mnemonic elsewhere in the architecture, so a stray `true` would
//! print something that looks like an instruction.
//!
//! [`Insn::explicit_width`] follows the manual's own assembler syntax lines: it
//! is set exactly for the encodings Arm spells `LDR<c>.W` — the 12-bit
//! immediate forms of `LDR`/`LDRB`/`LDRH`, the register forms of all five
//! loads, and `LDR (literal)` T2 — which are the ones with a 16-bit
//! counterpart an assembler could otherwise pick. The forms with no narrow
//! twin (`LDRSB`/`LDRSH` immediate, the non-`LDR` literals, every `P`/`U`/`W`
//! form, the unprivileged forms and the hints) print bare.

use super::{AddrMode, Insn, Mem, Operand, Operands, Reg, Shift, ShiftAmount, ShiftKind, Width};

/// `hw1[6:4]` of the byte space — Table A5-20, A5.3.9.
const BYTE: u16 = 0b001;
/// `hw1[6:4]` of the halfword space — Table A5-19, A5.3.8.
const HALF: u16 = 0b011;
/// `hw1[6:4]` of the word space — Table A5-18, A5.3.7.
const WORD: u16 = 0b101;

/// Which shape of address a row uses.
///
/// This is the axis the three tables share: pick a size and a signedness and
/// every table offers the same five forms, so the mnemonic/encoding lookup is
/// one function of `(size, S, hint, form)` rather than three tables of rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// `Rn == 1111`: pc-relative, 12-bit immediate, `U` from `hw1[7]`.
    Literal,
    /// 12-bit unsigned immediate offset, always added.
    Imm12,
    /// 8-bit immediate with `P`/`U`/`W` — offset, pre- or post-indexed.
    Imm8,
    /// Register index, optionally shifted left by `imm2`.
    Register,
    /// The unprivileged `LDR*T` row, `P:U:W == 110`.
    Unpriv,
}

/// The mnemonic, architectural encoding name and `.w` policy for one row of
/// Tables A5-18/A5-19/A5-20, or `None` where the tables allocate no
/// instruction.
///
/// `hint` is `Rt == 1111` in the byte or halfword space. The `None` arms are
/// the whole of this group's "not an instruction" surface bar the two
/// structural UNDEFINEDs (`size == 111`, and a signed word load), and each is
/// annotated with which of the three table categories it comes from.
fn row(
    size: u16,
    signed: bool,
    hint: bool,
    form: Form,
) -> Option<(&'static str, &'static str, bool)> {
    Some(match (size, signed, hint) {
        // Table A5-18. LDR is the only word load, and `Rt == 1111` is a
        // branching load rather than a hint, so there is one row family here.
        (WORD, false, false) => match form {
            Form::Literal => ("ldr", "T2", true),  // A7.7.44
            Form::Imm12 => ("ldr", "T3", true),    // A7.7.43
            Form::Imm8 => ("ldr", "T4", false),    // A7.7.43
            Form::Register => ("ldr", "T2", true), // A7.7.45
            Form::Unpriv => ("ldrt", "T1", false), // A7.7.67
        },
        (BYTE, false, false) => match form {
            Form::Literal => ("ldrb", "T1", false), // A7.7.47
            Form::Imm12 => ("ldrb", "T2", true),    // A7.7.46
            Form::Imm8 => ("ldrb", "T3", false),    // A7.7.46
            Form::Register => ("ldrb", "T2", true), // A7.7.48
            Form::Unpriv => ("ldrbt", "T1", false), // A7.7.49
        },
        (BYTE, true, false) => match form {
            Form::Literal => ("ldrsb", "T1", false), // A7.7.60
            Form::Imm12 => ("ldrsb", "T1", false),   // A7.7.59
            Form::Imm8 => ("ldrsb", "T2", false),    // A7.7.59
            Form::Register => ("ldrsb", "T2", true), // A7.7.61
            Form::Unpriv => ("ldrsbt", "T1", false), // A7.7.62
        },
        (HALF, false, false) => match form {
            Form::Literal => ("ldrh", "T1", false), // A7.7.56
            Form::Imm12 => ("ldrh", "T2", true),    // A7.7.55
            Form::Imm8 => ("ldrh", "T3", false),    // A7.7.55
            Form::Register => ("ldrh", "T2", true), // A7.7.57
            Form::Unpriv => ("ldrht", "T1", false), // A7.7.58
        },
        (HALF, true, false) => match form {
            Form::Literal => ("ldrsh", "T1", false), // A7.7.64
            Form::Imm12 => ("ldrsh", "T1", false),   // A7.7.63
            Form::Imm8 => ("ldrsh", "T2", false),    // A7.7.63
            Form::Register => ("ldrsh", "T2", true), // A7.7.65
            Form::Unpriv => ("ldrsht", "T1", false), // A7.7.66
        },
        // Table A5-20's hint rows: real instructions, with no `Rt` operand.
        (BYTE, false, true) => match form {
            Form::Literal => ("pld", "T1", false), // A7.7.95, PLD (literal)
            Form::Imm12 => ("pld", "T1", false),   // A7.7.94
            Form::Imm8 => ("pld", "T2", false),    // A7.7.94, always `#-imm8`
            Form::Register => ("pld", "T1", false), // A7.7.96
            Form::Unpriv => return None,           // UNPREDICTABLE
        },
        (BYTE, true, true) => match form {
            Form::Literal => ("pli", "T3", false),  // A7.7.97 encoding T3
            Form::Imm12 => ("pli", "T1", false),    // A7.7.97 encoding T1
            Form::Imm8 => ("pli", "T2", false),     // A7.7.97 encoding T2
            Form::Register => ("pli", "T1", false), // A7.7.98
            Form::Unpriv => return None,            // UNPREDICTABLE
        },
        // Table A5-19's hint rows. Unallocated in the M profile; the three
        // forms DDI 0406B Table A6-19 gives to PLDW are decoded as PLDW, the
        // rest are `None` (see this module's header).
        (HALF, false, true) => match form {
            Form::Literal => return None,            // UNPREDICTABLE
            Form::Imm12 => ("pldw", "T1", false),    // DDI 0406B A8.6.117
            Form::Imm8 => ("pldw", "T2", false),     // DDI 0406B A8.6.117
            Form::Register => ("pldw", "T1", false), // DDI 0406B A8.6.119
            Form::Unpriv => return None,             // UNPREDICTABLE
        },
        // Signed halfword space with `Rt == 1111`: an unallocated hint in
        // every profile, and UNPREDICTABLE in the writeback and unprivileged
        // rows. It is spelt `_` rather than `(HALF, true, true)` because the
        // only other tuples a `(u16, bool, bool)` admits cannot occur, and
        // writing them out as arms of their own would state cases that never
        // arise: `decode` rejects a `size` outside the three named values and
        // a signed word load before it reaches here, `hint` is defined as
        // `size != WORD && Rt == 1111` so the word space has no hint row, and
        // `classify` produces only the thirteen mnemonics' tuples. One
        // wildcard that does run beats four arms of which three cannot.
        _ => return None,
    })
}

/// The `(size, S, hint, unprivileged)` a mnemonic implies — the inverse of
/// [`row`] over its mnemonics, used by [`encode`] to pick a space before it
/// looks at operands.
fn classify(mnemonic: &str) -> Option<(u16, bool, bool, bool)> {
    Some(match mnemonic {
        "ldr" => (WORD, false, false, false),
        "ldrt" => (WORD, false, false, true),
        "ldrb" => (BYTE, false, false, false),
        "ldrbt" => (BYTE, false, false, true),
        "ldrsb" => (BYTE, true, false, false),
        "ldrsbt" => (BYTE, true, false, true),
        "ldrh" => (HALF, false, false, false),
        "ldrht" => (HALF, false, false, true),
        "ldrsh" => (HALF, true, false, false),
        "ldrsht" => (HALF, true, false, true),
        "pld" => (BYTE, false, true, false),
        "pli" => (BYTE, true, true, false),
        "pldw" => (HALF, false, true, false),
        _ => return None,
    })
}

/// `Align(PC, 4)` for the instruction at `addr` (A4.2.2): the pc value —
/// `addr + 4` in Thumb — forced word-aligned.
///
/// Wrapping, not saturating: the pc value of an instruction near the top of
/// the address space is architecturally defined to wrap, and panicking on it
/// would make the decoder unusable for scanning arbitrary bytes.
fn literal_base(addr: u32) -> u32 {
    addr.wrapping_add(4) & !3
}

/// `hw1` from its fields: the group's fixed prefix, `S`, `op1[0]`, the size
/// field and `Rn`.
fn hw1_of(size: u16, signed: bool, op1_low: bool, rn: Reg) -> u16 {
    0xF800
        | (u16::from(signed) << 8)
        | (u16::from(op1_low) << 7)
        | (size << 4)
        | u16::from(rn.num())
}

/// `hw2` of an 8-bit immediate form: `Rt`, the mandatory `1` of `hw2[11]`,
/// `P`/`U`/`W`, and `imm8`.
fn imm8_hw2(rt: u16, p: bool, u: bool, w: bool, imm8: u16) -> u16 {
    rt | 0x0800 | (u16::from(p) << 10) | (u16::from(u) << 9) | (u16::from(w) << 8) | imm8
}

/// The halfword fields every row of the three tables shares, extracted once.
struct Fields {
    /// The instruction's first halfword, still needed for `hw1[7]`.
    hw1: u16,
    /// The instruction's second halfword.
    hw2: u16,
    /// The address the instruction was decoded from.
    addr: u32,
    /// `hw1[6:4]`: [`BYTE`], [`HALF`] or [`WORD`].
    size: u16,
    /// `hw1[8]`: the signed-load bit, `op1[1]`.
    signed: bool,
    /// `hw1[3:0]`, already known not to be `1111` in the non-literal paths.
    rn: Reg,
    /// `hw2[15:12]`.
    rt: Reg,
    /// `Rt == 1111` in the byte or halfword space: this row is a memory hint
    /// and has no destination register.
    hint: bool,
}

impl Fields {
    /// Assemble one row's [`Insn`], or `None` where [`row`] has no allocation.
    ///
    /// The operand order is the UAL one: `<Rt>, <mem>` for a load, `<mem>`
    /// alone for a hint, and the resolved [`Operand::Target`] last for the
    /// pc-relative forms.
    fn build(&self, form: Form, mem: Mem, target: Option<u32>) -> Option<Insn> {
        let (mnemonic, encoding, explicit_width) = row(self.size, self.signed, self.hint, form)?;
        let mut operands = Operands::new();
        if !self.hint {
            operands.push(Operand::Reg(self.rt));
        }
        operands.push(Operand::Mem(mem));
        if let Some(t) = target {
            operands.push(Operand::Target(t));
        }
        Some(Insn {
            mnemonic,
            encoding,
            addr: self.addr,
            width: Width::Wide,
            cond: None,
            sets_flags: false,
            explicit_width,
            operands,
        })
    }

    /// The `Rn == 1111` rows: `Align(PC,4) ± imm12`, with `U` taken from
    /// `hw1[7]` because in this form `op1[0]` *is* the `U` bit.
    fn literal(&self) -> Option<Insn> {
        let mem = Mem {
            base: Reg::PC,
            index: None,
            offset: u32::from(self.hw2 & 0x0FFF),
            add: self.hw1 & 0x0080 != 0,
            align: 0,
            mode: AddrMode::Offset,
        };
        // `as u32` wraps, which is exactly the subtraction we want.
        let target = literal_base(self.addr).wrapping_add(mem.displacement() as u32);
        self.build(Form::Literal, mem, Some(target))
    }

    /// The 12-bit immediate rows: unsigned, always added, never indexed.
    fn imm12(&self) -> Option<Insn> {
        let mem = Mem {
            base: self.rn,
            index: None,
            offset: u32::from(self.hw2 & 0x0FFF),
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        };
        self.build(Form::Imm12, mem, None)
    }

    /// The `op2 == 000000` rows: `[<Rn>, <Rm>{, LSL #<imm2>}]`.
    ///
    /// `LSL` is the only encodable shift — there is no shift-type field, only
    /// `imm2` — and a shift of zero is dropped entirely so that UAL prints
    /// `[r0, r1]` rather than `[r0, r1, lsl #0]`.
    fn register(&self) -> Option<Insn> {
        let imm2 = ((self.hw2 >> 4) & 0b11) as u8;
        let shift = if imm2 == 0 {
            None
        } else {
            Some(Shift {
                kind: ShiftKind::Lsl,
                amount: ShiftAmount::Imm(imm2),
            })
        };
        let mem = Mem {
            base: self.rn,
            index: Some((Reg((self.hw2 & 0xF) as u8), shift)),
            offset: 0,
            add: true,
            align: 0,
            mode: AddrMode::Offset,
        };
        self.build(Form::Register, mem, None)
    }

    /// The `hw2[11] == 1` rows: an 8-bit immediate steered by `P`/`U`/`W`.
    fn imm8(&self) -> Option<Insn> {
        let p = self.hw2 & 0x0400 != 0;
        let u = self.hw2 & 0x0200 != 0;
        let w = self.hw2 & 0x0100 != 0;
        let imm = u32::from(self.hw2 & 0x00FF);
        if !w {
            if !p {
                return None; // `if P == '0' && W == '0' then UNDEFINED`.
            }
            let mem = Mem {
                base: self.rn,
                index: None,
                offset: imm,
                add: u,
                align: 0,
                mode: AddrMode::Offset,
            };
            // P:U:W == 110 is the unprivileged row, which can only add; 100 is
            // the plain offset row, which can only subtract.
            return self.build(if u { Form::Unpriv } else { Form::Imm8 }, mem, None);
        }
        if self.hint {
            // Tables A5-19/A5-20: every writeback row with `Rt == 1111` is
            // UNPREDICTABLE, in both the byte and the halfword space.
            return None;
        }
        let mem = Mem {
            base: self.rn,
            index: None,
            offset: imm,
            add: u,
            align: 0,
            mode: if p {
                AddrMode::PreIndex
            } else {
                AddrMode::PostIndex
            },
        };
        self.build(Form::Imm8, mem, None)
    }
}

/// Decode an instruction in this group, or `None` if `hw1`/`hw2` do not
/// belong to it.
///
/// `None` covers four distinct architectural verdicts, deliberately not
/// distinguished in the return type because no consumer can act differently on
/// them: outside the group, UNDEFINED, UNPREDICTABLE, and the unallocated
/// memory hints this module's header describes.
pub(crate) fn decode(hw1: u16, hw2: u16, addr: u32) -> Option<Insn> {
    let size = (hw1 >> 4) & 0b111;
    // `hw1[10:9] == 00` and `hw1[4] == 1` (folded into the size test) are what
    // separate this group from the stores of A5.3.10 and the SIMD element
    // loads of A5.3.11; the dispatcher checks them too, but `decode` is public
    // to the crate and must not decode a neighbour's encoding.
    if hw1 >> 11 != 0b11111 || hw1 & 0x0600 != 0 || !matches!(size, BYTE | HALF | WORD) {
        return None;
    }
    let signed = hw1 & 0x0100 != 0;
    if size == WORD && signed {
        // `op1 == 1x` in Table A5-18: there is no signed word load.
        return None;
    }
    let rt = Reg(((hw2 >> 12) & 0xF) as u8);
    let f = Fields {
        hw1,
        hw2,
        addr,
        size,
        signed,
        rn: Reg((hw1 & 0xF) as u8),
        rt,
        hint: size != WORD && rt.num() == 15,
    };

    if f.rn.num() == 15 {
        // Whatever `op2` holds, it is part of `imm12`.
        return f.literal();
    }
    if hw1 & 0x0080 != 0 {
        return f.imm12();
    }
    let op2 = (hw2 >> 6) & 0b11_1111;
    if op2 == 0 {
        return f.register();
    }
    if op2 & 0b10_0000 == 0 {
        // `op2 == 0xxxxx` other than `000000` appears in no row of any of the
        // three tables: UNDEFINED.
        return None;
    }
    f.imm8()
}

/// Re-encode an instruction this module decoded, back to its two halfwords.
///
/// Deliberately strict, and strict by construction: the candidate halfwords
/// are decoded again and the result compared field for field with `insn`, so
/// `encode` can only ever return bits that [`decode`] maps back to exactly the
/// instruction it was given. That closes the gap a hand-written inverse leaves
/// open — an encoder that agrees with the manual about `U` but not about which
/// row it lands in would still produce *an* instruction, just not this one.
///
/// `insn.addr` is load-bearing for the literal forms: their `Operand::Target`
/// is checked against `Align(PC,4)` of that address, so moving an instruction
/// without re-resolving its target fails to encode rather than silently
/// pointing somewhere else.
///
/// `cond` is not consulted. No halfword in this group has a condition field;
/// an instruction made conditional by an enclosing `IT` block encodes
/// identically.
///
/// One consequence is worth stating, because it decides what is worth
/// testing here. Every `Some` this function can return leaves through
/// [`verify`], so the early returns below it are a fast path and a statement
/// of which shapes this group can express — they are not what makes the
/// answer right. Disable any one of them — the width and flag check, the
/// `unpriv`/mode/offset/`add` checks guarding a register index, the `1..=3`
/// bound on that index's `LSL`, the literal row's mode check, the
/// unprivileged row's mode/`add`/range check — and the candidate merely
/// reaches `verify`, which decodes it, finds an `Insn` that is not the one it
/// was given, and returns `None` anyway. Each of those guards is therefore an
/// equivalent mutation: no input tells its presence from its absence, and
/// none of them carries a test of its own. The guards that do change answers
/// are the ones inside [`decode`], which `verify` is measured against.
pub(crate) fn encode(insn: &Insn) -> Option<(u16, u16)> {
    if insn.width != Width::Wide || insn.sets_flags {
        return None;
    }
    let (size, signed, hint, unpriv) = classify(insn.mnemonic)?;
    let (rt, mem, has_target) = operands_of(insn, hint)?;

    // A pc base with no index is the literal form, and the literal form is the
    // only one that carries a resolved target. Anything else is an operand
    // list this module never produced.
    let literal = mem.base.num() == 15 && mem.index.is_none();
    if literal != has_target {
        return None;
    }

    if let Some((rm, shift)) = mem.index {
        // A register index has no `U` field, so `add` must be nominal.
        if unpriv || mem.mode != AddrMode::Offset || mem.offset != 0 || !mem.add {
            return None;
        }
        // `decode` omits a zero shift, so a `Some` shift of zero is not
        // something it can have produced.
        let imm2 = match shift {
            None => 0,
            Some(Shift {
                kind: ShiftKind::Lsl,
                amount: ShiftAmount::Imm(n),
            }) if (1..=3).contains(&n) => u16::from(n),
            _ => return None,
        };
        let hw2 = rt | (imm2 << 4) | u16::from(rm.num());
        return verify(insn, hw1_of(size, signed, false, mem.base), hw2);
    }

    if literal {
        if unpriv || mem.mode != AddrMode::Offset {
            return None;
        }
        if mem.offset > 0x0FFF {
            return None;
        }
        // `op1[0]` is `U` here, and it is `Mem::add` verbatim — including for
        // `[pc, #-0]`, A7.7.44's named special case.
        let hw1 = hw1_of(size, signed, mem.add, Reg::PC);
        return verify(insn, hw1, rt | mem.offset as u16);
    }

    if unpriv {
        // `P:U:W == 110`: the unprivileged row can only add, so `#-0` is not
        // one of its spellings.
        if mem.mode != AddrMode::Offset || !mem.add || mem.offset > 255 {
            return None;
        }
        let hw1 = hw1_of(size, signed, false, mem.base);
        return verify(
            insn,
            hw1,
            imm8_hw2(rt, true, true, false, mem.offset as u16),
        );
    }

    let indexed = hw1_of(size, signed, false, mem.base);
    let imm = mem.offset;
    match mem.mode {
        // An adding plain offset is the 12-bit form, and only that: the 8-bit
        // plain-offset row is `P:U:W == 100`, which subtracts, so `[rn, #0]`
        // and `[rn, #-0]` land in different rows rather than competing for
        // one.
        AddrMode::Offset if mem.add => {
            if imm > 0x0FFF {
                return None;
            }
            verify(insn, hw1_of(size, signed, true, mem.base), rt | imm as u16)
        }
        AddrMode::Offset => {
            if imm > 0xFF {
                return None;
            }
            verify(insn, indexed, imm8_hw2(rt, true, false, false, imm as u16))
        }
        AddrMode::PreIndex | AddrMode::PostIndex => {
            if imm > 0xFF {
                return None;
            }
            let p = mem.mode == AddrMode::PreIndex;
            let hw2 = imm8_hw2(rt, p, mem.add, true, imm as u16);
            verify(insn, indexed, hw2)
        }
        // `[<Rn>]!` with an implicit increment is Advanced SIMD only.
        AddrMode::PostIncrement => None,
    }
}

/// Split an operand list into the `Rt` field, the memory operand and whether a
/// resolved target follows it, rejecting any shape [`decode`] never emits.
///
/// A hint has no `Rt` operand at all, and its `Rt` field is the `1111` that
/// made it a hint in the first place.
fn operands_of(insn: &Insn, hint: bool) -> Option<(u16, Mem, bool)> {
    let (rt, at) = if hint {
        (0xF000, 0)
    } else {
        match insn.operands.get(0)? {
            Operand::Reg(r) => (u16::from(r.num()) << 12, 1),
            _ => return None,
        }
    };
    let mem = match insn.operands.get(at)? {
        Operand::Mem(m) => m,
        _ => return None,
    };
    let target = match insn.operands.get(at + 1) {
        None => false,
        Some(Operand::Target(_)) => true,
        Some(_) => return None,
    };
    if insn.operands.len() != at + 1 + usize::from(target) {
        return None;
    }
    Some((rt, mem, target))
}

/// Accept `hw1`/`hw2` only if [`decode`] maps them back to exactly `insn`.
fn verify(insn: &Insn, hw1: u16, hw2: u16) -> Option<(u16, u16)> {
    let mut back = decode(hw1, hw2, insn.addr)?;
    back.cond = insn.cond;
    if back == *insn {
        Some((hw1, hw2))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::Target;

    /// A 4-aligned address: `Align(PC,4)` changes nothing here.
    const ALIGNED: u32 = 0x1000;
    /// A 2-mod-4 address: `Align(PC,4)` subtracts two from the pc value, and a
    /// decoder that skipped the alignment resolves every literal two high.
    const UNALIGNED: u32 = 0x1002;

    /// The printed UAL of one encoding, or a panic naming the halfwords.
    fn ual(hw1: u16, hw2: u16, addr: u32) -> String {
        let decoded = decode(hw1, hw2, addr);
        // `assert!` rather than a panicking match arm: the arm would be a
        // branch nothing ever takes, and this crate's coverage gate is 100%
        // of regions.
        assert!(decoded.is_some(), "{hw1:#06x} {hw2:#06x} did not decode");
        decoded.unwrap().to_string()
    }

    /// Assert an encoding is not an instruction — UNDEFINED, UNPREDICTABLE or
    /// an unallocated memory hint, per this module's documented contract.
    fn none(hw1: u16, hw2: u16) {
        assert!(
            decode(hw1, hw2, ALIGNED).is_none(),
            "{hw1:#06x} {hw2:#06x} should not decode"
        );
    }

    /// `hw1` for one space: `size`, `S` = `signed`, `op1[0]` = `low`, `Rn`.
    fn hw1(size: u16, signed: bool, low: bool, rn: u16) -> u16 {
        0xF800 | (u16::from(signed) << 8) | (u16::from(low) << 7) | (size << 4) | rn
    }

    /// `hw2` of an 8-bit immediate row, from `P`/`U`/`W` given as a 3-bit
    /// `op2[4:2]` and an `imm8`.
    fn puw(rt: u16, bits: u16, imm8: u16) -> u16 {
        (rt << 12) | 0x0800 | (bits << 8) | imm8
    }

    /// Every `hw1` the sweep covers: all three sizes, both `S`, both `op1[0]`,
    /// and a spread of `Rn` including `1111`.
    fn hw1_sweep() -> Vec<u16> {
        let mut out = Vec::new();
        for size in [BYTE, HALF, WORD] {
            for signed in [false, true] {
                for low in [false, true] {
                    for rn in [0, 1, 7, 13, 15] {
                        out.push(hw1(size, signed, low, rn));
                    }
                }
            }
        }
        out
    }

    /// Every `hw2` the sweep covers: all four `Rt` classes (including `1111`),
    /// every `P`/`U`/`W`, every `imm2`, and the boundary values 0, 1, max-1 and
    /// max of both immediate field widths.
    fn hw2_sweep() -> Vec<u16> {
        let mut out = Vec::new();
        for rt in [0u16, 3, 13, 15] {
            let rt_bits = rt << 12;
            for imm12 in [0u16, 1, 4094, 4095] {
                out.push(rt_bits | imm12);
            }
            for bits in 0..8u16 {
                for imm8 in [0u16, 1, 254, 255] {
                    out.push(puw(rt, bits, imm8));
                }
            }
            for imm2 in 0..4u16 {
                for rm in [0u16, 2, 13, 15] {
                    out.push(rt_bits | (imm2 << 4) | rm);
                }
            }
            // `op2 == 010000`: in the hole between `000000` and `1xxxxx`.
            out.push(rt_bits | 0x0400);
        }
        out
    }

    /// Whether an encoding spells `#-0` — `U == 0` with a zero immediate, in
    /// one of the two row families that can express it. See this module's
    /// `#-0` section.
    ///
    /// These used to be the group's only non-identity round trips, canonicalised
    /// onto their `U == 1` twin. They are counted rather than excepted now: the
    /// sweep asserts byte identity for them like everything else, and this
    /// predicate only proves the sweep reaches them.
    fn spells_negative_zero(hw1: u16, hw2: u16) -> bool {
        let literal = hw1 & 0xF == 0xF;
        if literal {
            return hw1 & 0x0080 == 0 && hw2 & 0x0FFF == 0;
        }
        // A writeback row, `U == 0`, `imm8 == 0`.
        hw1 & 0x0080 == 0
            && hw2 & 0x0800 != 0
            && hw2 & 0x0100 != 0
            && hw2 & 0x0200 == 0
            && hw2 & 0x00FF == 0
    }

    #[test]
    fn round_trips_at_both_alignments() {
        let hw1s = hw1_sweep();
        let hw2s = hw2_sweep();
        let (mut decoded, mut rejected, mut twins) = (0u32, 0u32, 0u32);
        for &addr in &[ALIGNED, UNALIGNED] {
            for &hw1 in &hw1s {
                for &hw2 in &hw2s {
                    let insn = match decode(hw1, hw2, addr) {
                        Some(i) => i,
                        None => {
                            rejected += 1;
                            continue;
                        }
                    };
                    decoded += 1;

                    // Invariants of the whole group.
                    assert_eq!(insn.width, Width::Wide, "{hw1:#06x} {hw2:#06x}");
                    assert_eq!(insn.len(), 4, "{hw1:#06x} {hw2:#06x}");
                    assert_eq!(insn.addr, addr, "{hw1:#06x} {hw2:#06x}");
                    assert!(insn.cond.is_none(), "{hw1:#06x} {hw2:#06x}");
                    // `hw1[8]` is signedness, not an S bit: `ldrs` is a real
                    // mnemonic elsewhere and must never be printed from here.
                    assert!(!insn.sets_flags, "{hw1:#06x} {hw2:#06x} printed an S");

                    // Compared as an `Option` rather than unwrapped, so that
                    // "did not re-encode at all" and "re-encoded to the wrong
                    // bytes" are one assertion and there is no
                    // `unwrap_or_else` closure that never runs.
                    assert_eq!(
                        encode(&insn),
                        Some((hw1, hw2)),
                        "{hw1:#06x} {hw2:#06x} decoded to `{insn}` and did not round-trip"
                    );
                    if spells_negative_zero(hw1, hw2) {
                        twins += 1;
                        assert!(
                            insn.to_string().contains("#-0"),
                            "{hw1:#06x} {hw2:#06x} is `#-0` and must print so"
                        );
                    }
                }
            }
        }
        // 60 first halfwords x 212 second halfwords x 2 addresses.
        assert_eq!(decoded + rejected, 2 * 60 * 212);
        // 18,032 of the 25,440 sweep points are instructions; the other 7,408
        // are the group's four flavours of hole (outside the group is not
        // among them — every `hw1` here is in it). The counts are pinned so
        // that a change in *what* decodes shows up as a failing census and not
        // as a silently larger or smaller round trip.
        assert_eq!((decoded, rejected), (18_032, 7_408));
        // 328 `#-0` encodings: 72 literal (5 `hw1` rows that decode with
        // `U == 0`, times the `imm12 == 0` bodies, times two addresses), 240
        // writeback rows with `imm8 == 0` and a real `Rt`, and 16 more where
        // that `Rt` is pc — legal in the word space, which has no hint rows.
        // All 328 are now inside the byte-identity assertion above.
        assert_eq!(twins, 328);
    }

    #[test]
    fn not_this_group() {
        // Store space (A5.3.10): `hw1[4] == 0`.
        assert!(decode(0xF841, 0x0004, 0).is_none());
        // `size == 111` — UNDEFINED, and routed to nobody.
        assert!(decode(0xF871, 0x0004, 0).is_none());
        // `hw1[10:9] != 00`: the coprocessor/SIMD half of the `11` space.
        assert!(decode(0xFA51, 0x0004, 0).is_none());
        // A 16-bit halfword.
        assert!(decode(0x6800, 0, 0).is_none());
    }

    // ---------------------------------------------------------------
    // Table A5-18 — Load word (A5.3.7).
    // ---------------------------------------------------------------

    #[test]
    fn table_a5_18_load_word() {
        // `Rn = r1`, `Rt = r0`, `Rm = r2`, offset 4 throughout, so only the
        // row under test varies.
        let imm12 = hw1(WORD, false, true, 1); // op1 = 01
        let other = hw1(WORD, false, false, 1); // op1 = 00

        // op1 = 01, Rn != 1111 — LDR (immediate) T3, A7.7.43.
        assert_eq!(ual(imm12, 0x0004, ALIGNED), "ldr.w r0, [r1, #4]");
        // op1 = 00, op2 = 1xx1xx — LDR (immediate) T4, the writeback rows.
        assert_eq!(ual(other, puw(0, 0b111, 4), ALIGNED), "ldr r0, [r1, #4]!");
        assert_eq!(ual(other, puw(0, 0b011, 4), ALIGNED), "ldr r0, [r1], #4");
        // op1 = 00, op2 = 1100xx — LDR (immediate) T4, offset, subtracting.
        assert_eq!(ual(other, puw(0, 0b100, 4), ALIGNED), "ldr r0, [r1, #-4]");
        // op1 = 00, op2 = 1110xx — LDRT, A7.7.67.
        assert_eq!(ual(other, puw(0, 0b110, 4), ALIGNED), "ldrt r0, [r1, #4]");
        // op1 = 00, op2 = 000000 — LDR (register) T2, A7.7.45.
        assert_eq!(ual(other, 0x0002, ALIGNED), "ldr.w r0, [r1, r2]");
        assert_eq!(ual(other, 0x0012, ALIGNED), "ldr.w r0, [r1, r2, lsl #1]");
        // op1 = 0x, Rn = 1111 — LDR (literal) T2, A7.7.44, `U` from op1[0].
        assert_eq!(
            ual(hw1(WORD, false, true, 15), 0x0004, ALIGNED),
            "ldr.w r0, [pc, #4], 0x1008"
        );
        assert_eq!(
            ual(hw1(WORD, false, false, 15), 0x0004, ALIGNED),
            "ldr.w r0, [pc, #-4], 0x1000"
        );

        // Rows outside the table. `op1 = 1x`: no signed word load.
        none(hw1(WORD, true, false, 1), 0x0004);
        none(hw1(WORD, true, true, 1), 0x0004);
        none(hw1(WORD, true, false, 15), 0x0004);
        // `P == 0 && W == 0` — UNDEFINED, not the unprivileged row.
        none(other, puw(0, 0b010, 4));
        none(other, puw(0, 0b000, 4));
        // `op2 = 0xxxxx` other than `000000`.
        none(other, 0x0400);

        // Table A5-18 has no `Rt` column: `Rt == 1111` is a branching load,
        // not a hint, and the same row decodes with pc as its destination.
        assert_eq!(ual(imm12, 0xF004, ALIGNED), "ldr.w pc, [r1, #4]");
        assert!(decode(imm12, 0xF004, ALIGNED).unwrap().writes_pc());
        assert_eq!(ual(other, 0xF002, ALIGNED), "ldr.w pc, [r1, r2]");
        assert_eq!(ual(other, puw(15, 0b110, 4), ALIGNED), "ldrt pc, [r1, #4]");
    }

    // ---------------------------------------------------------------
    // Table A5-19 — Load halfword, memory hints (A5.3.8).
    // ---------------------------------------------------------------

    #[test]
    fn table_a5_19_load_halfword() {
        let imm12 = hw1(HALF, false, true, 1); // op1 = 01
        let other = hw1(HALF, false, false, 1); // op1 = 00
        let simm12 = hw1(HALF, true, true, 1); // op1 = 11
        let sother = hw1(HALF, true, false, 1); // op1 = 10

        // 0x xxxxxx 1111 not 1111 — LDRH (literal) T1, A7.7.56.
        assert_eq!(
            ual(hw1(HALF, false, true, 15), 0x0004, ALIGNED),
            "ldrh r0, [pc, #4], 0x1008"
        );
        assert_eq!(
            ual(hw1(HALF, false, false, 15), 0x0004, ALIGNED),
            "ldrh r0, [pc, #-4], 0x1000"
        );
        // 00 1xx1xx / 1100xx, 01 xxxxxx — LDRH (immediate) T3/T2, A7.7.55.
        assert_eq!(ual(other, puw(0, 0b111, 4), ALIGNED), "ldrh r0, [r1, #4]!");
        assert_eq!(ual(other, puw(0, 0b011, 4), ALIGNED), "ldrh r0, [r1], #4");
        assert_eq!(ual(other, puw(0, 0b100, 4), ALIGNED), "ldrh r0, [r1, #-4]");
        assert_eq!(ual(imm12, 0x0004, ALIGNED), "ldrh.w r0, [r1, #4]");
        // 00 000000 — LDRH (register) T2, A7.7.57.
        assert_eq!(ual(other, 0x0002, ALIGNED), "ldrh.w r0, [r1, r2]");
        // 00 1110xx — LDRHT, A7.7.58.
        assert_eq!(ual(other, puw(0, 0b110, 4), ALIGNED), "ldrht r0, [r1, #4]");

        // 00 000000 / 00 1100xx / 01 xxxxxx, Rn != 1111, Rt == 1111 —
        // "Unallocated memory hint, treat as NOP" in Table A5-19; PLDW in
        // Table A6-19 under the Multiprocessing Extensions.
        assert_eq!(ual(other, 0xF002, ALIGNED), "pldw [r1, r2]");
        assert_eq!(ual(other, puw(15, 0b100, 4), ALIGNED), "pldw [r1, #-4]");
        assert_eq!(ual(imm12, 0xF004, ALIGNED), "pldw [r1, #4]");
        // 00 1xx1xx / 00 1110xx, Rt == 1111 — UNPREDICTABLE.
        none(other, puw(15, 0b111, 4));
        none(other, puw(15, 0b011, 4));
        none(other, puw(15, 0b110, 4));
        // 0x xxxxxx 1111 1111 — UNPREDICTABLE.
        none(hw1(HALF, false, true, 15), 0xF004);
        none(hw1(HALF, false, false, 15), 0xF004);

        // 10 1xx1xx / 1100xx, 11 xxxxxx — LDRSH (immediate) T2/T1, A7.7.63.
        assert_eq!(
            ual(sother, puw(0, 0b111, 4), ALIGNED),
            "ldrsh r0, [r1, #4]!"
        );
        assert_eq!(ual(sother, puw(0, 0b011, 4), ALIGNED), "ldrsh r0, [r1], #4");
        assert_eq!(
            ual(sother, puw(0, 0b100, 4), ALIGNED),
            "ldrsh r0, [r1, #-4]"
        );
        assert_eq!(ual(simm12, 0x0004, ALIGNED), "ldrsh r0, [r1, #4]");
        // 1x xxxxxx 1111 not 1111 — LDRSH (literal) T1, A7.7.64.
        assert_eq!(
            ual(hw1(HALF, true, true, 15), 0x0004, ALIGNED),
            "ldrsh r0, [pc, #4], 0x1008"
        );
        assert_eq!(
            ual(hw1(HALF, true, false, 15), 0x0004, ALIGNED),
            "ldrsh r0, [pc, #-4], 0x1000"
        );
        // 10 000000 — LDRSH (register) T2, A7.7.65.
        assert_eq!(ual(sother, 0x0002, ALIGNED), "ldrsh.w r0, [r1, r2]");
        // 10 1110xx — LDRSHT, A7.7.66.
        assert_eq!(
            ual(sother, puw(0, 0b110, 4), ALIGNED),
            "ldrsht r0, [r1, #4]"
        );

        // 10 000000 / 10 1100xx / 1x … 1111 / 11 xxxxxx, Rt == 1111 —
        // unallocated memory hints with no allocation in any profile.
        none(sother, 0xF002);
        none(sother, puw(15, 0b100, 4));
        none(hw1(HALF, true, true, 15), 0xF004);
        none(hw1(HALF, true, false, 15), 0xF004);
        none(simm12, 0xF004);
        // 10 1xx1xx / 10 1110xx, Rt == 1111 — UNPREDICTABLE.
        none(sother, puw(15, 0b111, 4));
        none(sother, puw(15, 0b011, 4));
        none(sother, puw(15, 0b110, 4));

        // Not in the table at all: `P == 0 && W == 0`, and `op2 = 0xxxxx`.
        none(other, puw(0, 0b010, 4));
        none(sother, puw(0, 0b000, 4));
        none(other, 0x0400);
    }

    // ---------------------------------------------------------------
    // Table A5-20 — Load byte, memory hints (A5.3.9).
    // ---------------------------------------------------------------

    #[test]
    fn table_a5_20_load_byte() {
        let imm12 = hw1(BYTE, false, true, 1); // op1 = 01
        let other = hw1(BYTE, false, false, 1); // op1 = 00
        let simm12 = hw1(BYTE, true, true, 1); // op1 = 11
        let sother = hw1(BYTE, true, false, 1); // op1 = 10

        // 0x xxxxxx 1111 not 1111 — LDRB (literal) T1, A7.7.47.
        assert_eq!(
            ual(hw1(BYTE, false, true, 15), 0x0004, ALIGNED),
            "ldrb r0, [pc, #4], 0x1008"
        );
        assert_eq!(
            ual(hw1(BYTE, false, false, 15), 0x0004, ALIGNED),
            "ldrb r0, [pc, #-4], 0x1000"
        );
        // 01 xxxxxx / 00 1xx1xx / 00 1100xx — LDRB (immediate) T2/T3, A7.7.46.
        assert_eq!(ual(imm12, 0x0004, ALIGNED), "ldrb.w r0, [r1, #4]");
        assert_eq!(ual(other, puw(0, 0b111, 4), ALIGNED), "ldrb r0, [r1, #4]!");
        assert_eq!(ual(other, puw(0, 0b011, 4), ALIGNED), "ldrb r0, [r1], #4");
        assert_eq!(ual(other, puw(0, 0b100, 4), ALIGNED), "ldrb r0, [r1, #-4]");
        // 00 1110xx — LDRBT, A7.7.49.
        assert_eq!(ual(other, puw(0, 0b110, 4), ALIGNED), "ldrbt r0, [r1, #4]");
        // 00 000000 — LDRB (register) T2, A7.7.48.
        assert_eq!(ual(other, 0x0002, ALIGNED), "ldrb.w r0, [r1, r2]");

        // 1x xxxxxx 1111 not 1111 — LDRSB (literal) T1, A7.7.60.
        assert_eq!(
            ual(hw1(BYTE, true, true, 15), 0x0004, ALIGNED),
            "ldrsb r0, [pc, #4], 0x1008"
        );
        assert_eq!(
            ual(hw1(BYTE, true, false, 15), 0x0004, ALIGNED),
            "ldrsb r0, [pc, #-4], 0x1000"
        );
        // 11 xxxxxx / 10 1xx1xx / 10 1100xx — LDRSB (immediate) T1/T2, A7.7.59.
        assert_eq!(ual(simm12, 0x0004, ALIGNED), "ldrsb r0, [r1, #4]");
        assert_eq!(
            ual(sother, puw(0, 0b111, 4), ALIGNED),
            "ldrsb r0, [r1, #4]!"
        );
        assert_eq!(ual(sother, puw(0, 0b011, 4), ALIGNED), "ldrsb r0, [r1], #4");
        assert_eq!(
            ual(sother, puw(0, 0b100, 4), ALIGNED),
            "ldrsb r0, [r1, #-4]"
        );
        // 10 1110xx — LDRSBT, A7.7.62.
        assert_eq!(
            ual(sother, puw(0, 0b110, 4), ALIGNED),
            "ldrsbt r0, [r1, #4]"
        );
        // 10 000000 — LDRSB (register) T2, A7.7.61.
        assert_eq!(ual(sother, 0x0002, ALIGNED), "ldrsb.w r0, [r1, r2]");

        // 0x xxxxxx 1111 1111 — PLD (literal) T1, A7.7.95.
        assert_eq!(
            ual(hw1(BYTE, false, true, 15), 0xF004, ALIGNED),
            "pld [pc, #4], 0x1008"
        );
        assert_eq!(
            ual(hw1(BYTE, false, false, 15), 0xF004, ALIGNED),
            "pld [pc, #-4], 0x1000"
        );
        // 01 xxxxxx / 00 1100xx, Rn != 1111, Rt == 1111 — PLD (immediate)
        // T1/T2, A7.7.94. The T2 row can only subtract.
        assert_eq!(ual(imm12, 0xF004, ALIGNED), "pld [r1, #4]");
        assert_eq!(ual(other, puw(15, 0b100, 4), ALIGNED), "pld [r1, #-4]");
        // 00 000000 — PLD (register) T1, A7.7.96.
        assert_eq!(ual(other, 0xF002, ALIGNED), "pld [r1, r2]");
        assert_eq!(ual(other, 0xF032, ALIGNED), "pld [r1, r2, lsl #3]");
        // 00 1xx1xx / 00 1110xx, Rt == 1111 — UNPREDICTABLE.
        none(other, puw(15, 0b111, 4));
        none(other, puw(15, 0b011, 4));
        none(other, puw(15, 0b110, 4));

        // 1x xxxxxx 1111 1111 — PLI (immediate, literal) T3, A7.7.97.
        assert_eq!(
            ual(hw1(BYTE, true, true, 15), 0xF004, ALIGNED),
            "pli [pc, #4], 0x1008"
        );
        assert_eq!(
            ual(hw1(BYTE, true, false, 15), 0xF004, ALIGNED),
            "pli [pc, #-4], 0x1000"
        );
        // 11 xxxxxx / 10 1100xx, Rn != 1111, Rt == 1111 — PLI T1/T2.
        assert_eq!(ual(simm12, 0xF004, ALIGNED), "pli [r1, #4]");
        assert_eq!(ual(sother, puw(15, 0b100, 4), ALIGNED), "pli [r1, #-4]");
        // 10 000000 — PLI (register) T1, A7.7.98.
        assert_eq!(ual(sother, 0xF002, ALIGNED), "pli [r1, r2]");
        // 10 1xx1xx / 10 1110xx, Rt == 1111 — UNPREDICTABLE.
        none(sother, puw(15, 0b111, 4));
        none(sother, puw(15, 0b011, 4));
        none(sother, puw(15, 0b110, 4));

        // Not in the table: `P == 0 && W == 0`, and `op2 = 0xxxxx`.
        none(other, puw(0, 0b010, 4));
        none(sother, puw(15, 0b000, 4));
        none(other, 0x0400);
    }

    #[test]
    fn signed_and_unsigned_differ_by_one_bit() {
        // The same encoding with `hw1[8]` flipped, in all four forms that have
        // both. Inverting `S` decodes to something plausible and wrong, so
        // each pair is asserted to differ in exactly the mnemonic.
        for (size, unsigned, signed) in [(BYTE, "ldrb", "ldrsb"), (HALF, "ldrh", "ldrsh")] {
            // 12-bit immediate.
            let u = hw1(size, false, true, 1);
            let s = hw1(size, true, true, 1);
            assert_eq!(s, u | 0x0100);
            assert_eq!(decode(u, 0x0004, 0).unwrap().mnemonic, unsigned);
            assert_eq!(decode(s, 0x0004, 0).unwrap().mnemonic, signed);
            // Register.
            let u = hw1(size, false, false, 1);
            let s = hw1(size, true, false, 1);
            assert_eq!(decode(u, 0x0002, 0).unwrap().mnemonic, unsigned);
            assert_eq!(decode(s, 0x0002, 0).unwrap().mnemonic, signed);
            // Writeback, and the unprivileged row, where the suffix moves.
            assert_eq!(
                decode(u, puw(0, 0b111, 4), 0).unwrap().mnemonic,
                unsigned,
                "{unsigned} pre-indexed"
            );
            assert_eq!(decode(s, puw(0, 0b111, 4), 0).unwrap().mnemonic, signed);
            assert_eq!(
                decode(u, puw(0, 0b110, 4), 0).unwrap().mnemonic,
                format!("{unsigned}t")
            );
            assert_eq!(
                decode(s, puw(0, 0b110, 4), 0).unwrap().mnemonic,
                format!("{signed}t")
            );
            // Literal.
            let u = hw1(size, false, true, 15);
            let s = hw1(size, true, true, 15);
            assert_eq!(decode(u, 0x0004, 0).unwrap().mnemonic, unsigned);
            assert_eq!(decode(s, 0x0004, 0).unwrap().mnemonic, signed);
        }
        // And the hint spaces are split by the same bit: PLD versus PLI.
        let n = hw1(BYTE, false, true, 1);
        assert_eq!(decode(n, 0xF004, 0).unwrap().mnemonic, "pld");
        assert_eq!(decode(n | 0x0100, 0xF004, 0).unwrap().mnemonic, "pli");
    }

    #[test]
    fn addressing_modes_print_as_ual_writes_them() {
        let base = hw1(WORD, false, false, 0); // LDR, op1 = 00, Rn = r0
                                               // Offset, subtracting — the only plain-offset row in the 8-bit space.
        assert_eq!(ual(base, puw(0, 0b100, 4), 0), "ldr r0, [r0, #-4]");
        // Offset, adding, from the 12-bit row.
        assert_eq!(
            ual(hw1(WORD, false, true, 0), 0x0004, 0),
            "ldr.w r0, [r0, #4]"
        );
        // Pre-indexed and post-indexed, both signs.
        assert_eq!(ual(base, puw(0, 0b111, 4), 0), "ldr r0, [r0, #4]!");
        assert_eq!(ual(base, puw(0, 0b101, 4), 0), "ldr r0, [r0, #-4]!");
        assert_eq!(ual(base, puw(0, 0b011, 4), 0), "ldr r0, [r0], #4");
        assert_eq!(ual(base, puw(0, 0b001, 4), 0), "ldr r0, [r0], #-4");
        // A zero offset still prints in the writeback modes, because their
        // syntax lines do not brace it: `[<Rn>,#+/-<imm8>]!` and
        // `[<Rn>],#+/-<imm8>` (A7.7.43 encoding T4). Omitting it would make
        // the post-indexed form read back as the plain offset form, which is a
        // different encoding.
        assert_eq!(ual(base, puw(0, 0b111, 0), 0), "ldr r0, [r0, #0]!");
        assert_eq!(ual(base, puw(0, 0b101, 0), 0), "ldr r0, [r0, #-0]!");
        assert_eq!(ual(base, puw(0, 0b011, 0), 0), "ldr r0, [r0], #0");
        assert_eq!(ual(base, puw(0, 0b001, 0), 0), "ldr r0, [r0], #-0");
        // The plain-offset form does brace it (`[<Rn>{,#+/-<imm8>}]`), so an
        // adding zero is elided — and a subtracting one is not, since `#-0` is
        // the whole of what that encoding says.
        assert_eq!(ual(base, puw(0, 0b100, 0), 0), "ldr r0, [r0, #-0]");
        assert_eq!(ual(hw1(WORD, false, true, 0), 0x0000, 0), "ldr.w r0, [r0]");
        // The `AddrMode` itself, not just its rendering — and every other
        // field of the `Mem` with it. Comparing the whole operand rather than
        // extracting the `Mem` and reading one field off it is both the
        // stronger assertion and the one with no never-taken "that was not a
        // memory operand" arm.
        let expect = |hw2, add, mode| {
            let m = Mem {
                base: Reg(0),
                index: None,
                offset: 4,
                add,
                align: 0,
                mode,
            };
            assert_eq!(
                decode(base, hw2, 0).unwrap().operands.get(1),
                Some(Operand::Mem(m)),
                "{hw2:#06x}"
            );
            m
        };
        // `U` is `Mem::add` and the offset is its magnitude, so `P`/`W` pick
        // the mode and `U` alone picks the sign. `P:U:W == 110` is absent
        // because it is not an `LDR` at all — it is the unprivileged `LDRT`
        // row, which `unprivileged_forms` covers.
        expect(puw(0, 0b100, 4), false, AddrMode::Offset);
        expect(puw(0, 0b111, 4), true, AddrMode::PreIndex);
        expect(puw(0, 0b101, 4), false, AddrMode::PreIndex);
        expect(puw(0, 0b011, 4), true, AddrMode::PostIndex);
        expect(puw(0, 0b001, 4), false, AddrMode::PostIndex);
        // `displacement` is where the sign and the magnitude are recombined.
        assert_eq!(
            expect(puw(0, 0b101, 4), false, AddrMode::PreIndex).displacement(),
            -4
        );
    }

    #[test]
    fn offsets_are_byte_offsets_not_scaled() {
        // The same encoded 4 in every size: a byte offset in all three, unlike
        // the 16-bit space where the field is scaled by the access size.
        assert_eq!(
            ual(hw1(WORD, false, true, 1), 0x0004, 0),
            "ldr.w r0, [r1, #4]"
        );
        assert_eq!(
            ual(hw1(HALF, false, true, 1), 0x0004, 0),
            "ldrh.w r0, [r1, #4]"
        );
        assert_eq!(
            ual(hw1(BYTE, false, true, 1), 0x0004, 0),
            "ldrb.w r0, [r1, #4]"
        );
        // Both field widths at their maxima, again unscaled.
        assert_eq!(
            ual(hw1(WORD, false, true, 1), 0x0FFF, 0),
            "ldr.w r0, [r1, #4095]"
        );
        assert_eq!(
            ual(hw1(WORD, false, false, 1), puw(0, 0b111, 255), 0),
            "ldr r0, [r1, #255]!"
        );
        assert_eq!(
            ual(hw1(WORD, false, false, 1), puw(0, 0b100, 255), 0),
            "ldr r0, [r1, #-255]"
        );
    }

    #[test]
    fn register_index_shifts_only_by_lsl() {
        let base = hw1(WORD, false, false, 1);
        // A zero shift is omitted entirely, so UAL prints `[r1, r2]`.
        assert_eq!(ual(base, 0x0002, 0), "ldr.w r0, [r1, r2]");
        for n in 1..=3u16 {
            assert_eq!(
                ual(base, (n << 4) | 2, 0),
                format!("ldr.w r0, [r1, r2, lsl #{n}]")
            );
        }
        // There is no shift-type field: `imm2` is the whole of `op2[1:0]`, so
        // the shift is always `LSL` and there is no immediate offset beside
        // the index. Asserted as the whole operand rather than by extracting
        // the `Mem` and reading fields off it: an extraction needs a "that
        // was not a memory operand" arm that never runs, and comparing the
        // operand pins every field at once, `align` and `add` included.
        assert_eq!(
            decode(base, 0x0032, 0).unwrap().operands.get(1),
            Some(Operand::Mem(Mem {
                base: Reg(1),
                index: Some((
                    Reg(2),
                    Some(Shift {
                        kind: ShiftKind::Lsl,
                        amount: ShiftAmount::Imm(3),
                    })
                )),
                offset: 0,
                add: true,
                align: 0,
                mode: AddrMode::Offset,
            }))
        );
    }

    #[test]
    fn literals_resolve_against_aligned_pc() {
        // At 0x1000 the pc value is 0x1004 and already aligned; at 0x1002 it is
        // 0x1006, which `Align(PC,4)` drops to 0x1004. Both therefore resolve
        // to the same absolute address, which is the check a decoder missing
        // the `& !3` fails at exactly one of the two.
        let add = hw1(WORD, false, true, 15); // U = 1
        let sub = hw1(WORD, false, false, 15); // U = 0
        assert_eq!(
            ual(add, 0x0010, ALIGNED),
            "ldr.w r0, [pc, #16], 0x1014" // 0x1004 + 16
        );
        assert_eq!(ual(add, 0x0010, UNALIGNED), "ldr.w r0, [pc, #16], 0x1014");
        assert_eq!(
            ual(sub, 0x0010, ALIGNED),
            "ldr.w r0, [pc, #-16], 0xff4" // 0x1004 - 16
        );
        assert_eq!(ual(sub, 0x0010, UNALIGNED), "ldr.w r0, [pc, #-16], 0xff4");
        // A different word, to show the base really does move with the address.
        assert_eq!(ual(add, 0x0010, 0x1004), "ldr.w r0, [pc, #16], 0x1018");
        assert_eq!(ual(add, 0x0010, 0x1006), "ldr.w r0, [pc, #16], 0x1018");

        // The full 12-bit reach, both ways, in every size and both hints.
        assert_eq!(
            ual(hw1(BYTE, false, true, 15), 0x0FFF, ALIGNED),
            "ldrb r0, [pc, #4095], 0x2003"
        );
        assert_eq!(
            ual(hw1(HALF, true, false, 15), 0x0FFF, ALIGNED),
            "ldrsh r0, [pc, #-4095], 0x5"
        );
        assert_eq!(
            ual(hw1(BYTE, false, false, 15), 0xF001, UNALIGNED),
            "pld [pc, #-1], 0x1003"
        );
        assert_eq!(
            ual(hw1(BYTE, true, true, 15), 0xF001, UNALIGNED),
            "pli [pc, #1], 0x1005"
        );

        // The resolved address is reachable as a branch target, and equal at
        // both alignments — the same invariant, checked through the API a
        // consumer actually uses.
        for hw2 in [0x0000, 0x0001, 0x0FFF] {
            assert_eq!(
                decode(add, hw2, ALIGNED).unwrap().branch_target(),
                decode(add, hw2, UNALIGNED).unwrap().branch_target()
            );
        }
    }

    #[test]
    fn literal_encode_checks_the_resolved_target() {
        // Moving an instruction without re-resolving its target must fail to
        // encode rather than quietly point somewhere else.
        let insn = decode(hw1(WORD, false, true, 15), 0x0010, ALIGNED).unwrap();
        assert_eq!(encode(&insn), Some((hw1(WORD, false, true, 15), 0x0010)));
        let mut moved = insn;
        moved.addr = ALIGNED + 8;
        assert_eq!(encode(&moved), None);
        // And a target that no longer matches its syntactic offset is refused.
        let mut bent = insn;
        bent.operands = insn
            .operands
            .as_slice()
            .map(|o| match o {
                Operand::Target(t) => Operand::Target(t + 4),
                other => other,
            })
            .collect();
        assert_eq!(encode(&bent), None);
    }

    #[test]
    fn encode_refuses_what_this_group_cannot_say() {
        let insn = decode(hw1(WORD, false, true, 1), 0x0004, ALIGNED).unwrap();
        // Narrow, or flag-setting: not this group.
        let mut narrow = insn;
        narrow.width = Width::Narrow;
        assert_eq!(encode(&narrow), None);
        let mut flags = insn;
        flags.sets_flags = true;
        assert_eq!(encode(&flags), None);
        // A mnemonic from a neighbouring group.
        let mut store = insn;
        store.mnemonic = "str";
        assert_eq!(encode(&store), None);
        // An offset past the 12-bit field.
        let mut far = insn;
        far.operands = [
            Operand::Reg(Reg(0)),
            Operand::Mem(Mem {
                base: Reg(1),
                index: None,
                offset: 4096,
                add: true,
                align: 0,
                mode: AddrMode::Offset,
            }),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&far), None);
        // An 8-bit form whose offset does not fit either.
        let mut wide_imm8 = insn;
        wide_imm8.encoding = "T4";
        wide_imm8.explicit_width = false;
        wide_imm8.operands = [
            Operand::Reg(Reg(0)),
            Operand::Mem(Mem {
                base: Reg(1),
                index: None,
                offset: 256,
                add: true,
                align: 0,
                mode: AddrMode::PreIndex,
            }),
        ]
        .into_iter()
        .collect();
        assert_eq!(encode(&wide_imm8), None);
        // A shift that is not LSL, and an LSL past 3.
        for shift in [
            Shift {
                kind: ShiftKind::Lsr,
                amount: ShiftAmount::Imm(1),
            },
            Shift {
                kind: ShiftKind::Lsl,
                amount: ShiftAmount::Imm(4),
            },
            Shift {
                kind: ShiftKind::Lsl,
                amount: ShiftAmount::Imm(0),
            },
        ] {
            let mut bad = insn;
            bad.encoding = "T2";
            bad.operands = [
                Operand::Reg(Reg(0)),
                Operand::Mem(Mem {
                    base: Reg(1),
                    index: Some((Reg(2), Some(shift))),
                    offset: 0,
                    add: true,
                    align: 0,
                    mode: AddrMode::Offset,
                }),
            ]
            .into_iter()
            .collect();
            assert_eq!(encode(&bad), None);
        }
        // A hint with a destination register, and a load without one.
        let mut hinted = insn;
        hinted.mnemonic = "pld";
        assert_eq!(encode(&hinted), None);
        let pld = decode(hw1(BYTE, false, true, 1), 0xF004, ALIGNED).unwrap();
        let mut loaded = pld;
        loaded.mnemonic = "ldrb";
        assert_eq!(encode(&loaded), None);
    }

    /// Every operand *shape* [`decode`] never emits, row by row.
    ///
    /// [`Insn`] and [`Mem`] are public structs with public fields, so a
    /// consumer can hand `encode` an operand list this module could not have
    /// produced — a base register where an address belongs, an addressing
    /// mode the row has no bits for, a resolved target on a form that has no
    /// literal encoding. There is one safe answer to each, `None`; the
    /// dangerous answer is halfwords that decode back to a *different*
    /// instruction, which is what [`verify`] exists to stop.
    #[test]
    fn encode_refuses_operand_shapes_the_decoder_never_emits() {
        /// An `Insn` of this group with `ops` in place of its operands.
        fn with(template: Insn, ops: &[Operand]) -> Insn {
            let mut insn = template;
            insn.operands = ops.iter().copied().collect();
            insn
        }
        /// A memory operand with no register index.
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
        /// A `[rn, r2]` operand, for the register-offset row.
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
        let imm12 = decode(hw1(WORD, false, true, 1), 0x0004, ALIGNED).unwrap();
        let imm8 = decode(hw1(WORD, false, false, 1), puw(0, 0b111, 4), ALIGNED).unwrap();
        let reg = decode(hw1(WORD, false, false, 1), 0x0002, ALIGNED).unwrap();
        let unpriv = decode(hw1(WORD, false, false, 1), puw(0, 0b110, 4), ALIGNED).unwrap();
        let literal = decode(hw1(WORD, false, true, 15), 0x0010, ALIGNED).unwrap();
        let target = Operand::Target(0x1014);

        // --- operand list shape, before any row is chosen ---
        assert_eq!(encode(&with(imm12, &[])), None, "no operands at all");
        assert_eq!(
            encode(&with(imm12, &[rt])),
            None,
            "a load with a destination and no address"
        );
        assert_eq!(
            encode(&with(imm12, &[at(1, 4, true, AddrMode::Offset), rt])),
            None,
            "the destination comes first, then the address"
        );
        assert_eq!(
            encode(&with(
                imm12,
                &[rt, at(1, 4, true, AddrMode::Offset), Operand::Imm(0)]
            )),
            None,
            "the only operand that may follow an address is a resolved target"
        );
        assert_eq!(
            encode(&with(
                literal,
                &[rt, at(15, 16, true, AddrMode::Offset), target, target]
            )),
            None,
            "one target, not two"
        );

        // --- the target and the literal row imply each other ---
        assert_eq!(
            encode(&with(
                imm12,
                &[rt, at(1, 4, true, AddrMode::Offset), target]
            )),
            None,
            "only a pc base with no index resolves a target"
        );
        assert_eq!(
            encode(&with(literal, &[rt, at(15, 16, true, AddrMode::Offset)])),
            None,
            "a literal load without its resolved target is not one this module built"
        );

        // --- the literal row: 12-bit, plain offset, `U` in `hw1[7]` ---
        assert_eq!(
            encode(&with(
                literal,
                &[rt, at(15, 16, true, AddrMode::PreIndex), target]
            )),
            None,
            "there is no writeback literal: `Rn == 1111` leaves no `P`/`W`"
        );
        let mut literal_t: Insn = with(literal, &[rt, at(15, 16, true, AddrMode::Offset), target]);
        literal_t.mnemonic = "ldrt";
        assert_eq!(
            encode(&literal_t),
            None,
            "the unprivileged row has no `Rn == 1111` encoding"
        );

        // --- the register-offset row: no `U`, no immediate, no writeback ---
        for (mem, why) in [
            (
                indexed(1, 0, true, AddrMode::PreIndex),
                "a register index has no writeback encoding here",
            ),
            (
                indexed(1, 4, true, AddrMode::Offset),
                "there is nowhere to put an immediate beside the index",
            ),
            (
                indexed(1, 0, false, AddrMode::Offset),
                "every register index is added; there is no `U` bit",
            ),
        ] {
            assert_eq!(encode(&with(reg, &[rt, mem])), None, "{why}");
        }
        let mut unpriv_indexed = with(reg, &[rt, indexed(1, 0, true, AddrMode::Offset)]);
        unpriv_indexed.mnemonic = "ldrt";
        assert_eq!(
            encode(&unpriv_indexed),
            None,
            "the unprivileged row has no register-index encoding"
        );

        // --- the unprivileged row: `P:U:W == 110`, 8 bits, adding only ---
        for (mem, why) in [
            (
                at(1, 4, true, AddrMode::PreIndex),
                "`P`, `U` and `W` are all fixed, so there is no writeback form",
            ),
            (
                at(1, 4, false, AddrMode::Offset),
                "`U == 1` is part of the row; `#-4` and `#-0` are not spellings of it",
            ),
            (
                at(1, 256, true, AddrMode::Offset),
                "the field is eight bits",
            ),
        ] {
            assert_eq!(encode(&with(unpriv, &[rt, mem])), None, "{why}");
        }

        // --- the 8-bit immediate row ---
        assert_eq!(
            encode(&with(imm8, &[rt, at(1, 256, false, AddrMode::Offset)])),
            None,
            "a subtracting plain offset is the 8-bit row, and its field is eight bits"
        );
        assert_eq!(
            encode(&with(imm8, &[rt, at(1, 4, true, AddrMode::PostIncrement)])),
            None,
            "`[rn]!` with an implicit increment is Advanced SIMD's mode, not a load's"
        );

        // --- `verify` catches an `Insn` whose halfwords decode to nothing ---
        //
        // `PLDW (literal)` does not exist: DDI 0406B Table A6-19 leaves
        // `Rn == 1111` in the preload-write row UNPREDICTABLE, so [`row`]
        // refuses `(HALF, false, true, Form::Literal)`. Every gate in `encode`
        // passes for it — the mnemonic classifies, the operands are a hint's,
        // the base is `pc` and the target is present and correctly resolved —
        // and the halfwords it would emit decode to `None`. Nothing but the
        // re-decode in `verify` stops it.
        let pldw = decode(hw1(HALF, false, true, 1), 0xF004, ALIGNED).unwrap();
        assert_eq!(pldw.mnemonic, "pldw");
        assert_eq!(
            encode(&with(
                pldw,
                &[at(15, 16, true, AddrMode::Offset), Operand::Target(0x1014)]
            )),
            None,
            "there is no `pldw` literal encoding to emit"
        );
    }

    /// `#0` and `#-0` are different instructions (A7.7.43, A7.7.44), and the
    /// regression test for that is that they decode to *different* [`Mem`]
    /// values and each re-encode to its own halfwords.
    ///
    /// The two families that can express the distinction are the literal forms
    /// with `imm12 == 0` and the writeback forms with `imm8 == 0`. Both used to
    /// collapse onto their `U == 1` twin, because [`Mem::offset`] was a
    /// sign-corrected `i32` and an `i32` has no negative zero.
    #[test]
    fn negative_zero_is_a_different_instruction() {
        // `[pc, #-0]` — A7.7.44's named special case. `op1[0]` is `U` here.
        let sub = hw1(WORD, false, false, 15);
        let add = hw1(WORD, false, true, 15);
        let minus = decode(sub, 0x0000, ALIGNED).unwrap();
        let plus = decode(add, 0x0000, ALIGNED).unwrap();
        assert_ne!(minus, plus);
        assert!(minus.to_string().starts_with("ldr.w r0, [pc, #-0]"));
        // The wide form is unambiguous already: `.w` is what selects it, and
        // `ldr.w r0, [pc]` assembles back to these bytes, so the adding zero
        // is elided as the manual's braces write it. Only the *narrow*
        // `LDR (literal)` T1 forces its zero displacement to print, and for
        // the opposite reason — `ldr r0, [pc]` reads back as the wide form.
        // `Insn`'s `Display` gates that on narrow width, a pc-based `Mem` and
        // a resolved `Operand::Target` beside it, all three together.
        assert!(plus.to_string().starts_with("ldr.w r0, [pc]"));
        assert_eq!(encode(&minus), Some((sub, 0x0000)));
        assert_eq!(encode(&plus), Some((add, 0x0000)));
        // Both resolve to the same pool word, which is why the distinction is
        // invisible in the target and has to live in the fields.
        assert_eq!(minus.branch_target(), plus.branch_target());

        // `[r1, #-0]!` and `[r1], #-0`, the writeback rows.
        let base = hw1(WORD, false, false, 1);
        for u_bits in [0b111u16, 0b011] {
            let plus = decode(base, puw(0, u_bits, 0), ALIGNED).unwrap();
            let minus = decode(base, puw(0, u_bits & !0b010, 0), ALIGNED).unwrap();
            assert_ne!(plus, minus, "{u_bits:03b}");
            assert_eq!(encode(&plus), Some((base, puw(0, u_bits, 0))));
            assert_eq!(
                encode(&minus),
                Some((base, puw(0, u_bits & !0b010, 0))),
                "{u_bits:03b}"
            );
        }

        // The plain-offset row: `U == 1` there is the unprivileged
        // instruction, a different mnemonic, so `[r1, #-0]` is the only
        // `imm8 == 0` offset encoding.
        let zero = decode(base, puw(0, 0b100, 0), ALIGNED).unwrap();
        assert_eq!(zero.to_string(), "ldr r0, [r1, #-0]");
        assert_eq!(zero.encoding, "T4");
        assert_eq!(encode(&zero), Some((base, puw(0, 0b100, 0))));
        // And the 12-bit row, which has no `U` bit, is where a bare `[r1]`
        // comes from — so the two no longer compete for one spelling.
        let t3 = decode(hw1(WORD, false, true, 1), 0x0000, ALIGNED).unwrap();
        assert_eq!(t3.to_string(), "ldr.w r0, [r1]");
        assert_eq!(t3.encoding, "T3");
        assert_eq!(encode(&t3), Some((hw1(WORD, false, true, 1), 0x0000)));
    }

    #[test]
    fn round_trips_through_the_group_dispatcher() {
        // The same round trip through the crate's own entry points, so that a
        // neighbouring group claiming one of these mnemonics — `ldr` alone is
        // spelled by five other tables — shows up here rather than in a
        // consumer's output. One encoding of every form in all three tables.
        let cases = [
            (hw1(WORD, false, true, 1), 0x0004), // LDR (immediate) T3
            (hw1(WORD, false, false, 1), puw(0, 0b111, 4)), // LDR T4 pre-indexed
            (hw1(WORD, false, false, 1), puw(0, 0b011, 4)), // LDR T4 post-indexed
            (hw1(WORD, false, false, 1), puw(0, 0b100, 4)), // LDR T4 offset
            (hw1(WORD, false, false, 1), puw(0, 0b110, 4)), // LDRT
            (hw1(WORD, false, false, 1), 0x0012), // LDR (register) T2
            (hw1(WORD, false, true, 15), 0x0010), // LDR (literal) T2
            (hw1(BYTE, false, true, 1), 0x0004), // LDRB (immediate) T2
            (hw1(BYTE, true, true, 1), 0x0004),  // LDRSB (immediate) T1
            (hw1(BYTE, false, false, 1), puw(0, 0b110, 4)), // LDRBT
            (hw1(BYTE, true, false, 1), puw(0, 0b110, 4)), // LDRSBT
            (hw1(HALF, false, true, 1), 0x0004), // LDRH (immediate) T2
            (hw1(HALF, true, true, 1), 0x0004),  // LDRSH (immediate) T1
            (hw1(HALF, false, false, 1), puw(0, 0b110, 4)), // LDRHT
            (hw1(HALF, true, false, 1), puw(0, 0b110, 4)), // LDRSHT
            (hw1(HALF, true, false, 15), 0x0010), // LDRSH (literal) T1
            (hw1(BYTE, false, true, 1), 0xF004), // PLD (immediate) T1
            (hw1(BYTE, false, false, 1), 0xF002), // PLD (register) T1
            (hw1(BYTE, false, true, 15), 0xF010), // PLD (literal) T1
            (hw1(BYTE, true, true, 1), 0xF004),  // PLI (immediate) T1
            (hw1(BYTE, true, false, 1), 0xF002), // PLI (register) T1
            (hw1(BYTE, true, false, 15), 0xF010), // PLI (immediate, literal) T3
            (hw1(HALF, false, true, 1), 0xF004), // PLDW (immediate) T1
            (hw1(HALF, false, false, 1), 0xF002), // PLDW (register) T1
        ];
        for &addr in &[ALIGNED, UNALIGNED] {
            for (hw1, hw2) in cases {
                let mine = decode(hw1, hw2, addr).expect("this module decodes it");
                let theirs = crate::isa::decode_halfwords(hw1, hw2, addr, Target::Union);
                assert_eq!(theirs, Some(mine), "dispatch of {hw1:#06x} {hw2:#06x}");
                assert_eq!(
                    crate::isa::encode(&mine),
                    Some((hw1, hw2)),
                    "crate-level re-encode of {hw1:#06x} {hw2:#06x}"
                );
            }
        }
    }

    #[test]
    fn pop_alias_is_decoded_as_the_load_it_encodes() {
        // `ldr r3, [sp], #4` is also POP {r3} (A7.7.43's "SEE POP"). Table
        // A5-18 allocates the encoding to LDR (immediate), and that is what is
        // reported: the POP spelling is an assembler alias whose own encoding
        // (T3 of A7.7.99) belongs to another group, and decoding it here would
        // make the round trip ambiguous.
        let insn = decode(hw1(WORD, false, false, 13), puw(3, 0b011, 4), 0).unwrap();
        assert_eq!(insn.to_string(), "ldr r3, [sp], #4");
        assert_eq!(insn.mnemonic, "ldr");
        assert_eq!(encode(&insn), Some((hw1(WORD, false, false, 13), 0x3B04)));
    }
}
