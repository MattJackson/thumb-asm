//! Instruction-accurate Thumb decoding.
//!
//! The module is laid out to mirror Arm's own decode tree, one Rust module per
//! numbered sub-table of the architecture reference manual (ARM DDI 0403E.e
//! chapter A5 for the M profile, DDI 0406C chapter A6 for A/R). That mapping
//! is the point: a reviewer checking this crate against the specification can
//! put one table beside one file, and a decoding bug has exactly one place to
//! live.
//!
//! # Why instruction-accurate matters
//!
//! The obvious way to scan a firmware image for, say, every `BL` is to test
//! every even offset against the `BL` bit pattern. That is what this crate did
//! before, and it is wrong in both directions: the second halfword of a 32-bit
//! instruction can look exactly like the first halfword of a `BL`, and a
//! genuine `BL` can be skipped when the scan falls out of phase. Walking the
//! stream with [`Decoder`] — which knows that `hw1[15:11]` of `0b11101`,
//! `0b11110` or `0b11111` means "four bytes, not two" — removes that whole
//! class of false positive.
//!
//! # IT blocks
//!
//! [`Decoder`] tracks `ITSTATE`. Up to four instructions following an `IT`
//! execute conditionally without carrying any condition in their own
//! encoding, so a decoder that ignores `IT` reports them as unconditional —
//! silently, and in the one place where being wrong changes control flow.
//! Instructions decoded inside an IT block come back with [`Insn::cond`]
//! already filled in.

pub mod insn;

pub use insn::{
    AddrMode, FpReg, Insn, Mem, Operand, Operands, Reg, Shift, ShiftAmount, ShiftKind, Width,
    MAX_OPERANDS,
};

use crate::Cond;

// One module per encoding group, named for the sub-table it implements.
mod t16_branch;
mod t16_dataproc;
mod t16_loadstore;
mod t16_misc;
mod t16_shift;
mod t16_special;
mod t32_branch_misc;
mod t32_coproc;
mod t32_dp_modimm;
mod t32_dp_plainimm;
mod t32_dp_reg;
mod t32_dp_shiftreg;
mod t32_dual_excl;
mod t32_ldm_stm;
mod t32_load;
mod t32_multiply;
mod t32_simd;
mod t32_store;
mod thumbee;

/// The length in bytes of the instruction beginning with halfword `hw1`.
///
/// This is the whole of Thumb's length rule (ARM DDI 0403E.e A5.1): the top
/// five bits decide, and nothing else is consulted. Any other approach to
/// walking a Thumb stream — scanning at a fixed stride, or inferring length
/// from what an instruction "looks like" — is guesswork.
///
/// ```
/// use thumb_asm::isa::insn_len;
///
/// assert_eq!(insn_len(0x4770), 2); // bx lr
/// assert_eq!(insn_len(0xF000), 4); // first half of a bl
/// ```
pub fn insn_len(hw1: u16) -> usize {
    match hw1 >> 11 {
        0b11101..=0b11111 => 4,
        _ => 2,
    }
}

/// Decode the single instruction at byte offset `at`, treating `at` as its
/// address.
///
/// Returns `None` if the bytes are not a defined instruction, or if the slice
/// is too short to hold it. This is the *stateless* decode: it does not know
/// about any enclosing IT block, so an instruction made conditional by a
/// preceding `IT` comes back with [`Insn::cond`] of `None`. Use [`Decoder`]
/// when walking a run of instructions.
pub fn decode_at(image: &[u8], at: usize) -> Option<Insn> {
    decode_at_with(image, at, at as u32, false)
}

/// Decode one instruction, stating its address explicitly.
///
/// `addr` is what pc-relative operands resolve against, which is what lets a
/// caller decode a buffer that was loaded somewhere other than its file
/// offset. `thumbee` selects the ThumbEE variant of the encoding space, in
/// which part of the 16-bit map is re-used (ARM DDI 0406C chapter A9).
pub fn decode_at_with(image: &[u8], at: usize, addr: u32, thumbee: bool) -> Option<Insn> {
    let hw1 = read_hw(image, at)?;
    let len = insn_len(hw1);
    let hw2 = if len == 4 { read_hw(image, at + 2)? } else { 0 };
    decode_halfwords(hw1, hw2, addr, thumbee)
}

/// Decode from halfwords already in hand.
///
/// Exposed because a consumer that has its own stream reader should not have
/// to marshal bytes back into a slice to use this crate's decoder.
pub fn decode_halfwords(hw1: u16, hw2: u16, addr: u32, thumbee: bool) -> Option<Insn> {
    if insn_len(hw1) == 2 {
        // ThumbEE does not *extend* the 16-bit map, it re-assigns a slice of
        // it: `0xC000..=0xCFFF` is `STM`/`LDM` T1 in Thumb state and chapter
        // A9's handler branches, bounds check and frame accesses in ThumbEE
        // state, and A9.1 deletes the `LDM`/`STM` forms outright. So inside
        // that slice this module's answer is final — including its `None`,
        // which means Table A9-2's UNDEFINED row (`0xC100..=0xC1FF`) and not
        // "try the ordinary groups". Falling through would hand those 256
        // halfwords back as the `stmia` ThumbEE does not have.
        //
        // Which halfwords those are is `thumbee::owns`' business, not this
        // function's: the module that implements Table A9-2 owns the fact of
        // what the table covers. See its docs for why the answer arrives as a
        // predicate rather than as a third variant of `decode`'s return type,
        // which is the signature all nineteen group modules share.
        if thumbee && thumbee::owns(hw1) {
            return thumbee::decode(hw1, hw2, addr);
        }
        return match hw1 >> 10 {
            0b000000..=0b001111 => t16_shift::decode(hw1, hw2, addr),
            0b010000 => t16_dataproc::decode(hw1, hw2, addr),
            0b010001 => t16_special::decode(hw1, hw2, addr),
            0b010010..=0b100111 => t16_loadstore::decode(hw1, hw2, addr),
            0b101000..=0b101011 => t16_loadstore::decode(hw1, hw2, addr),
            0b101100..=0b101111 => t16_misc::decode(hw1, hw2, addr),
            _ => t16_branch::decode(hw1, hw2, addr),
        };
    }

    // 32-bit: `111 op1 op2 … op …` (ARM DDI 0403E.e Table A5-9).
    let op1 = (hw1 >> 11) & 0b11;
    let op2 = (hw1 >> 4) & 0b111_1111;
    let op = (hw2 >> 15) & 1;

    match op1 {
        0b01 => match op2 {
            o if o & 0b110_0100 == 0b000_0000 => t32_ldm_stm::decode(hw1, hw2, addr),
            o if o & 0b110_0100 == 0b000_0100 => t32_dual_excl::decode(hw1, hw2, addr),
            o if o & 0b110_0000 == 0b010_0000 => t32_dp_shiftreg::decode(hw1, hw2, addr),
            // `op2[6]` set, and nothing else is left: the three arms above
            // partition every `op2` with bit 6 clear — bit 5 takes the
            // shifted-register row, then bit 2 splits load/store-multiple from
            // dual/exclusive — so this arm is the rest of the 7-bit field and
            // is written as the catch-all rather than as a mask with an
            // unreachable `None` behind it.
            //
            // The coprocessor space and Advanced SIMD data processing share
            // it: SIMD is `0xEF..`/`0xFF..`, which set the same `op2[6]`.
            // `t32_coproc` declines the SIMD encodings, so the chain is what
            // makes NEON reachable at all — without it every Advanced SIMD
            // data-processing instruction decodes as `None` no matter how
            // completely it is implemented.
            _ => t32_coproc::decode(hw1, hw2, addr).or_else(|| t32_simd::decode(hw1, hw2, addr)),
        },
        0b10 => {
            if op == 1 {
                t32_branch_misc::decode(hw1, hw2, addr)
            } else if op2 & 0b010_0000 == 0 {
                t32_dp_modimm::decode(hw1, hw2, addr)
            } else {
                t32_dp_plainimm::decode(hw1, hw2, addr)
            }
        }
        // `op1 == 0b00` cannot arrive here: it would mean `hw1[15:11]` of
        // `0b11000`, which `insn_len` calls a 16-bit instruction and which the
        // narrow path above has already answered. The three 32-bit prefixes
        // `0b11101`, `0b11110` and `0b11111` give `op1` of `0b01`, `0b10` and
        // `0b11`, so this is `0b11` and the match needs no unreachable arm.
        _ => match op2 {
            o if o & 0b111_0001 == 0b000_0000 => t32_store::decode(hw1, hw2, addr),
            o if o & 0b111_0001 == 0b001_0000 => t32_simd::decode(hw1, hw2, addr),
            o if o & 0b110_0111 == 0b000_0001 => t32_load::decode(hw1, hw2, addr),
            o if o & 0b110_0111 == 0b000_0011 => t32_load::decode(hw1, hw2, addr),
            o if o & 0b110_0111 == 0b000_0101 => t32_load::decode(hw1, hw2, addr),
            o if o & 0b110_0111 == 0b000_0111 => None, // UNDEFINED
            o if o & 0b111_0000 == 0b010_0000 => t32_dp_reg::decode(hw1, hw2, addr),
            o if o & 0b111_1000 == 0b011_0000 => t32_multiply::decode(hw1, hw2, addr),
            o if o & 0b111_1000 == 0b011_1000 => t32_multiply::decode(hw1, hw2, addr),
            // `op2[6]` set — the coprocessor and Advanced SIMD space again,
            // and again the only value left. With bit 6 clear, bits[5:4] of
            // `00`, `01`, `10` and `11` are taken by the nine arms above (the
            // first two splitting on bit 0, then bits[2:1] naming the three
            // load rows and the UNDEFINED one; the last on bit 3), so the
            // field is exhausted.
            _ => t32_coproc::decode(hw1, hw2, addr).or_else(|| t32_simd::decode(hw1, hw2, addr)),
        },
    }
}

/// The halfword at byte offset `at`, or `None` if the slice ends first.
///
/// `checked_add` rather than `at + 2`: `at` comes from a caller — through
/// [`decode_at`] or [`Decoder::skip`], which saturates — so an offset within
/// two of `usize::MAX` is reachable input, and `at + 2` would panic on it in a
/// debug build. The answer for an offset past the end is `None` either way.
fn read_hw(image: &[u8], at: usize) -> Option<u16> {
    let b = image.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// The state an `IT` instruction sets up: which condition, and how many
/// instructions it governs with which polarity.
///
/// Modelled exactly as the architecture models `ITSTATE[7:0]` — `cond` is
/// `ITSTATE[7:4]`, `mask` is `ITSTATE[3:0]` — so [`ItState::advance`] is the
/// spec's own `ITAdvance()` and can be checked against it line for line
/// (ARM DDI 0403E.e A7.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItState {
    /// `ITSTATE[7:4]`: the base condition, as raw bits.
    pub cond: u8,
    /// `ITSTATE[3:0]`: the remaining-instructions mask.
    pub mask: u8,
}

impl ItState {
    /// No IT block in effect.
    pub const INACTIVE: ItState = ItState { cond: 0, mask: 0 };

    /// Whether an IT block is currently in effect.
    pub fn active(self) -> bool {
        self.mask != 0
    }

    /// The condition the *next* instruction executes under, or `None` outside
    /// an IT block.
    ///
    /// `ITSTATE[4]` selects polarity: when it differs from the base
    /// condition's bit 0 the instruction runs on the inverted condition, which
    /// is how `ITE`/`ITT` chains are encoded.
    pub fn current(self) -> Option<Cond> {
        if !self.active() {
            return None;
        }
        Cond::from_bits(self.cond)
    }

    /// Consume one instruction's worth of IT state.
    ///
    /// The architecture's `ITAdvance()` is
    ///
    /// ```text
    /// if ITSTATE<2:0> == '000' then ITSTATE.IT = '00000000';
    /// else                         ITSTATE.IT<4:0> = LSL(ITSTATE.IT<4:0>, 1);
    /// ```
    ///
    /// Note what that shift spans: `ITSTATE<4>` is the **low bit of the
    /// condition**, not the top of the mask, so the shift crosses the
    /// cond/mask boundary and each step pulls `mask<3>` into `cond<0>`. That
    /// bit is the `T`/`E` selector — it is what makes the else-arms of an
    /// `ITE`/`ITTE`/… block run on the inverted condition. Shifting only the
    /// mask and leaving `cond` fixed looks right and is right for an all-`T`
    /// block, but hands back the un-inverted condition for every else-arm,
    /// which is a silent and consequential wrong answer about control flow.
    pub fn advance(self) -> ItState {
        if self.mask & 0b0111 == 0 {
            ItState::INACTIVE
        } else {
            ItState {
                cond: (self.cond & 0b1110) | ((self.mask >> 3) & 1),
                mask: (self.mask << 1) & 0xF,
            }
        }
    }
}

/// A walker that decodes a run of Thumb instructions in order, tracking IT
/// state as it goes.
///
/// ```
/// use thumb_asm::isa::Decoder;
///
/// // bx lr
/// let image = [0x70, 0x47];
/// let mut d = Decoder::new(&image);
/// let insn = d.next().unwrap();
/// assert_eq!(insn.mnemonic, "bx");
/// assert!(d.next().is_none());
/// ```
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    image: &'a [u8],
    pos: usize,
    base: u32,
    it: ItState,
    thumbee: bool,
}

impl<'a> Decoder<'a> {
    /// Decode `image` from its start, treating byte offset 0 as address 0.
    pub fn new(image: &'a [u8]) -> Self {
        Decoder {
            image,
            pos: 0,
            base: 0,
            it: ItState::INACTIVE,
            thumbee: false,
        }
    }

    /// Decode from byte offset `at`, treating that offset as address `addr`.
    pub fn at(image: &'a [u8], at: usize, addr: u32) -> Self {
        Decoder {
            image,
            pos: at,
            base: addr.wrapping_sub(at as u32),
            it: ItState::INACTIVE,
            thumbee: false,
        }
    }

    /// Decode in ThumbEE state rather than ordinary Thumb state.
    pub fn thumbee(mut self, yes: bool) -> Self {
        self.thumbee = yes;
        self
    }

    /// The byte offset the next instruction will be read from.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// The IT state in effect for the next instruction.
    pub fn it_state(&self) -> ItState {
        self.it
    }

    /// Skip `n` bytes — useful to resynchronise after an undefined encoding.
    pub fn skip(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n);
    }
}

impl Iterator for Decoder<'_> {
    type Item = Insn;

    fn next(&mut self) -> Option<Insn> {
        let hw1 = read_hw(self.image, self.pos)?;
        let len = insn_len(hw1);
        let addr = self.base.wrapping_add(self.pos as u32);
        // A wide instruction whose second halfword is past the end of the
        // image stops the walk, and `read_hw` is the whole of that check:
        // reading `pos` proved two bytes are there, reading `pos + 2` proves
        // the other two. An explicit `pos + len > image.len()` test in front
        // of it says the same thing twice and leaves one of the two paths
        // unreachable — with the truncated tail of a firmware image being
        // exactly the input that must not be mis-decoded, the check that runs
        // should be the one that is tested.
        let hw2 = if len == 4 {
            read_hw(self.image, self.pos + 2)?
        } else {
            0
        };
        let mut insn = decode_halfwords(hw1, hw2, addr, self.thumbee)?;

        // An instruction inside an IT block carries no condition of its own.
        if insn.cond.is_none() && self.it.active() {
            insn.cond = self.it.current();
            // Almost every 16-bit data-processing encoding specifies
            // `setflags = !InITBlock()`: the narrow forms write the flags only
            // *outside* an IT block, which is why UAL spells the conditional
            // form `lsleq` and not `lslseq`. The group decoders cannot know
            // this — they see one halfword, not the stream — so the
            // correction belongs here, where the IT state is known. The wide
            // encodings are untouched: they carry an explicit `S` bit whose
            // meaning does not depend on being inside an IT block.
            if insn.width == Width::Narrow {
                insn.sets_flags = false;
            }
        }
        // `starts_with`, not `==`: the `T`/`E` letters are part of the
        // mnemonic (`itt`, `ite`, `ittte`, …) because nothing else in `Insn`
        // can carry the mask, so an equality test here would match only a bare
        // `it` and silently stop tracking state for almost every real IT
        // block.
        self.it = if insn.mnemonic.starts_with("it") {
            it_state_from(hw1)
        } else {
            self.it.advance()
        };

        self.pos += len;
        Some(insn)
    }
}

/// Re-encode a decoded instruction back to its halfwords.
///
/// The inverse of [`decode_halfwords`], and the reason every group module
/// implements an `encode` alongside its `decode`: a round-trip over the whole
/// encoding space is the compliance proof this crate rests on. If an
/// instruction decodes but does not re-encode to the bytes it came from, one of
/// the two directions disagrees with the architecture, and the test says so
/// without anyone having to hand-write a vector for it.
///
/// Returns the instruction's halfwords — `(hw1, 0)` for a 16-bit encoding —
/// or `None` if the instruction is not one this crate can encode, or if an
/// operand no longer fits the encoding it claims (a branch whose target has
/// moved out of range, say).
pub fn encode(insn: &Insn) -> Option<(u16, u16)> {
    // Every candidate is *verified* before it is returned: the halfwords a
    // group produces are decoded again and compared against the instruction
    // asked for, and a mismatch is discarded so the next group gets a turn.
    //
    // This is not belt-and-braces, it is what makes the design safe. A mnemonic
    // does not identify an encoding group — `add` lives in five of them — so
    // dispatch has to try groups in turn, and with a bare `or_else` chain the
    // whole thing is only as correct as its least strict member. One group
    // accepting a neighbour's instruction would silently emit the wrong
    // encoding, and the neighbour's own tests would still pass, because the
    // collision only shows up through this function. Verifying centrally means
    // a greedy group can waste work but cannot produce a wrong answer.
    //
    // ThumbEE is tried first among the narrow groups and verified in ThumbEE
    // state, because its encodings deliberately shadow ordinary ones.
    if insn.width == Width::Narrow {
        if let Some(hw) = thumbee::encode(insn) {
            if faithful(insn, hw, 0, true) {
                return Some((hw, 0));
            }
        }
    }

    // Function pointers rather than an eagerly-built array, so a hit in the
    // first group does not pay for the other eleven.
    type NarrowEncoder = fn(&Insn) -> Option<u16>;
    type WideEncoder = fn(&Insn) -> Option<(u16, u16)>;
    const NARROW: [NarrowEncoder; 6] = [
        t16_shift::encode,
        t16_dataproc::encode,
        t16_special::encode,
        t16_loadstore::encode,
        t16_misc::encode,
        t16_branch::encode,
    ];
    const WIDE: [WideEncoder; 12] = [
        t32_dp_modimm::encode,
        t32_dp_plainimm::encode,
        t32_branch_misc::encode,
        t32_ldm_stm::encode,
        t32_dual_excl::encode,
        t32_load::encode,
        t32_store::encode,
        t32_dp_shiftreg::encode,
        t32_dp_reg::encode,
        t32_multiply::encode,
        t32_coproc::encode,
        t32_simd::encode,
    ];

    match insn.width {
        Width::Narrow => NARROW
            .iter()
            .filter_map(|f| f(insn))
            .map(|hw| (hw, 0))
            .find(|&(hw1, hw2)| faithful(insn, hw1, hw2, false)),
        Width::Wide => WIDE
            .iter()
            .filter_map(|f| f(insn))
            .find(|&(hw1, hw2)| faithful(insn, hw1, hw2, false)),
    }
}

/// Whether `hw1`/`hw2` decode back to the instruction they were encoded from.
///
/// `addr` and `cond` are excluded from the comparison, and deliberately:
/// `addr` is context the bytes do not carry, and a condition can have come from
/// an enclosing `IT` block rather than from the instruction's own encoding, so
/// neither is recoverable from the halfwords alone. Everything that *is* in the
/// bits must match exactly.
fn faithful(insn: &Insn, hw1: u16, hw2: u16, thumbee: bool) -> bool {
    match decode_halfwords(hw1, hw2, insn.addr, thumbee) {
        Some(back) => {
            // A conditional narrow instruction is allowed to disagree about
            // flag-setting, and must be: the 16-bit data-processing encodings
            // specify `setflags = !InITBlock()`, so `lsleq r0, r1, #2` and
            // `lsls r0, r1, #2` are *the same halfword* — one inside an IT
            // block, one not. `Decoder` clears `sets_flags` for the former, a
            // fresh decode of the bytes alone reports it set, and neither is
            // wrong. Requiring them to match here would make every conditional
            // narrow instruction unencodable.
            let flags_ok = back.sets_flags == insn.sets_flags
                || (insn.cond.is_some() && insn.width == Width::Narrow);
            back.mnemonic == insn.mnemonic
                && back.width == insn.width
                && flags_ok
                && back.explicit_width == insn.explicit_width
                && back.operands == insn.operands
        }
        None => false,
    }
}

/// Re-encode a decoded instruction to its little-endian bytes.
///
/// Word-invariant order: a 32-bit Thumb instruction is two little-endian
/// halfwords, `hw1` at the lower address — *not* a little-endian `u32`. Getting
/// that wrong byte-swaps every wide instruction, which is why this helper
/// exists rather than leaving it to each caller.
pub fn encode_bytes(insn: &Insn) -> Option<Vec<u8>> {
    let (hw1, hw2) = encode(insn)?;
    let mut out = Vec::with_capacity(insn.len());
    out.extend_from_slice(&hw1.to_le_bytes());
    if insn.width == Width::Wide {
        out.extend_from_slice(&hw2.to_le_bytes());
    }
    Some(out)
}

/// Extract the IT state an `IT` instruction (`1011 1111 firstcond mask`)
/// installs.
pub(crate) fn it_state_from(hw1: u16) -> ItState {
    ItState {
        cond: ((hw1 >> 4) & 0xF) as u8,
        mask: (hw1 & 0xF) as u8,
    }
}

/// Disassemble a run of instructions to UAL text, one per line, prefixed with
/// the address each was decoded at.
///
/// Undefined encodings are rendered as `.short 0x….`, and the walk resumes at
/// the next halfword — a disassembler that stops at the first byte it cannot
/// explain is of no use on a firmware image, which is full of data.
pub fn disassemble(image: &[u8], at: usize, addr: u32, count: usize) -> Vec<String> {
    // Capacity bounded by what the image can actually yield, not by `count`
    // alone: the shortest Thumb instruction is two bytes, so a slice can hold
    // at most `len / 2` of them however large a `count` the caller passes —
    // and `count` is frequently a value read out of the image (a claimed
    // function length, say), which would otherwise reserve gigabytes for a
    // walk that stops after three instructions.
    let ceiling = image.len().saturating_sub(at) / 2;
    let mut out = Vec::with_capacity(count.min(ceiling));
    let mut d = Decoder::at(image, at, addr);
    while out.len() < count {
        let pos = d.pos();
        if pos + 2 > image.len() {
            break;
        }
        match d.next() {
            Some(i) => out.push(format!("{:08x}: {}", i.addr, i)),
            None => {
                let hw = read_hw(image, pos).unwrap_or(0);
                out.push(format!("{pos:08x}: .short {hw:#06x}"));
                // Spelled as an explicit associated-function call: `Decoder`
                // implements `Iterator`, so `d.skip(2)` would resolve to the
                // by-value `Iterator::skip` adaptor — which consumes `d` —
                // rather than the inherent `&mut self` method meant here.
                Decoder::skip(&mut d, 2);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insn_len_follows_the_top_five_bits() {
        // The whole of Thumb's length rule (A5.1).
        assert_eq!(insn_len(0x4770), 2); // bx lr
        assert_eq!(insn_len(0xB500), 2); // push {lr}
        assert_eq!(insn_len(0xE7FE), 2); // b . — 0b11100 is still narrow
        assert_eq!(insn_len(0xE800), 4); // 0b11101
        assert_eq!(insn_len(0xF000), 4); // 0b11110
        assert_eq!(insn_len(0xF800), 4); // 0b11111
    }

    /// `ITAdvance()` shifts `ITSTATE<4:0>`, which straddles the cond/mask
    /// boundary — so each step pulls `mask<3>` into `cond<0>`, and that bit is
    /// what flips an else-arm to the inverted condition.
    #[test]
    fn it_advance_inverts_the_condition_on_else_arms() {
        // `ITE EQ` — encoded firstcond=0b0000, mask=0b1100 (halfword 0xBF0C).
        let it = it_state_from(0xBF0C);
        assert_eq!(
            it,
            ItState {
                cond: 0b0000,
                mask: 0b1100
            }
        );

        // First governed instruction runs on EQ …
        assert_eq!(it.current(), Some(Cond::Eq));
        // … and the second, the `E` arm, runs on NE. Shifting only the mask
        // would leave this as EQ, which is the bug this test exists for.
        let it = it.advance();
        assert_eq!(it.current(), Some(Cond::Ne));
        // Two instructions governed, then the block ends.
        assert_eq!(it.advance(), ItState::INACTIVE);
        assert_eq!(it.advance().current(), None);
    }

    #[test]
    fn it_advance_keeps_the_condition_on_then_arms() {
        // `ITT EQ` — firstcond=0b0000, mask=0b0100 (halfword 0xBF04).
        let it = it_state_from(0xBF04);
        assert_eq!(it.current(), Some(Cond::Eq));
        let it = it.advance();
        assert_eq!(it.current(), Some(Cond::Eq));
        assert_eq!(it.advance(), ItState::INACTIVE);
    }

    #[test]
    fn it_advance_handles_a_mixed_three_instruction_block() {
        // `ITTE NE` — firstcond=0b0001, mask=0b1010: NE, NE, EQ.
        let it = ItState {
            cond: 0b0001,
            mask: 0b1010,
        };
        assert_eq!(it.current(), Some(Cond::Ne));
        let it = it.advance();
        assert_eq!(it.current(), Some(Cond::Ne));
        let it = it.advance();
        assert_eq!(it.current(), Some(Cond::Eq));
        assert_eq!(it.advance(), ItState::INACTIVE);
    }

    /// Table A9-2's UNDEFINED row must be undefined *in ThumbEE state*, and
    /// must still be the `STM` it replaces in ordinary Thumb state.
    ///
    /// This is the regression test for the dispatcher's old fall-through.
    /// `thumbee::decode` answers `None` for `0xC100..=0xC1FF` — A9.2.1 assigns
    /// the row nothing — and the dispatcher used to read that `None` as "not a
    /// ThumbEE encoding, try the ordinary 16-bit groups", which handed all 256
    /// halfwords back as `stmia`: an instruction A9.1 deletes outright, so one
    /// that cannot appear in a ThumbEE image at all. `thumbee::owns` is what
    /// separates the two meanings of `None`.
    ///
    /// The row's first halfword is the one exception, and it is an exception
    /// in *both* states: `0xC100` is `STM` T1 with an empty register list,
    /// which A7.7.159 makes UNPREDICTABLE and `t16_branch` refuses.
    #[test]
    fn thumbee_undefined_row_is_undefined_only_in_thumbee_state() {
        for hw in 0xC100..=0xC1FFu16 {
            assert_eq!(
                decode_halfwords(hw, 0, 0x1000, true),
                None,
                "{hw:#06x} is UNDEFINED in ThumbEE state (Table A9-2)"
            );
            let plain = decode_halfwords(hw, 0, 0x1000, false);
            if hw == 0xC100 {
                assert_eq!(plain, None, "empty register list is UNPREDICTABLE");
            } else {
                assert_eq!(
                    plain.map(|i| i.mnemonic),
                    Some("stmia"),
                    "{hw:#06x} is STM T1 in Thumb state"
                );
            }
        }

        // And the boundary: one halfword below the row is `HBP`, one above is
        // `HB`, both of which ThumbEE state does define.
        assert!(decode_halfwords(0xC0FF, 0, 0x1000, true).is_some());
        assert!(decode_halfwords(0xC200, 0, 0x1000, true).is_some());
    }

    /// A short run walked through [`Decoder`] both ways, to pin where the two
    /// states disagree and — just as important — where they do not.
    ///
    /// The flag re-assigns `0xC000..=0xCFFF` and nothing else (ARM DDI 0406C
    /// A9.2.1), so a consumer that sets it wrongly gets a wrong answer for
    /// exactly the halfwords in that range: here a handler branch read as a
    /// store-multiple, and a frame load read as a load-multiple. Every other
    /// instruction in the run must decode identically, or the flag is doing
    /// more than the architecture says it does.
    #[test]
    fn thumbee_flag_changes_exactly_the_reassigned_range() {
        // bx lr · hb #7 · ldr r4, [r9, #16] · pop {r4, pc}
        let image = [0x70, 0x47, 0x07, 0xC2, 0x24, 0xCC, 0x10, 0xBD];

        let plain: Vec<String> = Decoder::new(&image).map(|i| i.to_string()).collect();
        let ee: Vec<String> = Decoder::new(&image)
            .thumbee(true)
            .map(|i| i.to_string())
            .collect();

        assert_eq!(
            plain,
            [
                "bx lr",
                "stmia r2!, {r0-r2}",
                "ldmia r4!, {r2, r5}",
                "pop {r4, pc}"
            ]
        );
        assert_eq!(ee, ["bx lr", "hb #7", "ldr r4, [r9, #16]", "pop {r4, pc}"]);

        // Stated as a partition so a future change cannot quietly widen it:
        // the two walks agree everywhere outside `0xC000..=0xCFFF`.
        for (n, (a, b)) in plain.iter().zip(&ee).enumerate() {
            if (1..=2).contains(&n) {
                assert_ne!(a, b, "instruction {n} is in the re-assigned range");
            } else {
                assert_eq!(a, b, "instruction {n} is not ThumbEE's to change");
            }
        }
    }

    /// The UNDEFINED row stops a ThumbEE walk where an ordinary walk carries
    /// on, which is the visible consequence of the fix for a consumer using
    /// [`Decoder`] rather than [`decode_halfwords`].
    #[test]
    fn thumbee_walk_halts_on_the_undefined_row() {
        // bx lr · 0xC1C0 · bx lr
        let image = [0x70, 0x47, 0xC0, 0xC1, 0x70, 0x47];

        let plain: Vec<&str> = Decoder::new(&image).map(|i| i.mnemonic).collect();
        assert_eq!(plain, ["bx", "stmia", "bx"]);

        let mut d = Decoder::new(&image).thumbee(true);
        assert_eq!(d.next().map(|i| i.mnemonic), Some("bx"));
        assert_eq!(d.next(), None, "0xC1C0 is UNDEFINED in ThumbEE state");
        // …and the caller resynchronises past it, exactly as `disassemble`
        // does for any undefined encoding.
        assert_eq!(d.pos(), 2);
        Decoder::skip(&mut d, 2);
        assert_eq!(d.next().map(|i| i.mnemonic), Some("bx"));
    }

    /// Advanced SIMD data processing lives at `0xEF..`/`0xFF..`, which set the
    /// same `op2[6]` as the coprocessor space and so arrive on the coprocessor
    /// arm. `t32_coproc` declines them, so unless that arm chains onward the
    /// entire NEON implementation is dead code reachable only by calling the
    /// group module directly — which is exactly what it was until this test
    /// existed. A count, not a spot check: one lucky encoding proves nothing
    /// about a whole space.
    #[test]
    fn advanced_simd_is_reachable_through_the_dispatcher() {
        let mut decoded = 0usize;
        for hw1 in (0xEF00u16..=0xEFFF).chain(0xFF00u16..=0xFFFF) {
            for hw2 in [0x0110u16, 0x0842, 0x0A10, 0x0F00] {
                if decode_halfwords(hw1, hw2, 0x1000, false).is_some() {
                    decoded += 1;
                }
            }
        }
        assert!(
            decoded > 1000,
            "only {decoded} Advanced SIMD encodings reachable via the dispatcher \
             — the coprocessor arm has stopped chaining to t32_simd"
        );
    }

    /// A firmware image does not end on an instruction boundary just because a
    /// decoder would like it to. Every entry point must answer `None` for a
    /// wide instruction whose second halfword is off the end, rather than
    /// reading past it or inventing a zero for it.
    #[test]
    fn a_truncated_instruction_at_the_end_of_an_image_is_not_decoded() {
        // `0xF000` is the first halfword of a 32-bit instruction (`insn_len`
        // says 4) with only two bytes behind it.
        let truncated = [0x00u8, 0xF0];
        assert_eq!(insn_len(0xF000), 4);
        assert_eq!(decode_at(&truncated, 0), None);
        assert_eq!(decode_at_with(&truncated, 0, 0x1000, false), None);
        assert_eq!(Decoder::new(&truncated).next(), None);
        // …and the same bytes with the missing halfword supplied do decode, so
        // the `None` above is about the length and nothing else.
        let whole = [0x00u8, 0xF0, 0x00, 0xF8];
        assert!(decode_at(&whole, 0).is_some());

        // An offset past the end, and one that is off the end of the address
        // space: `Decoder::skip` saturates, so `usize::MAX` is reachable input
        // and must answer `None` rather than overflow.
        assert_eq!(decode_at(&whole, 4), None);
        assert_eq!(decode_at(&whole, usize::MAX), None);
        let mut d = Decoder::new(&whole);
        Decoder::skip(&mut d, usize::MAX);
        assert_eq!(d.pos(), usize::MAX, "skip saturates rather than wrapping");
        assert_eq!(d.next(), None);

        // A half-instruction in the *middle* of a walk stops it where it is,
        // leaving `pos` on the halfword that could not be read whole.
        let tail = [0x70u8, 0x47, 0x00, 0xF0];
        let mut d = Decoder::new(&tail);
        assert_eq!(d.next().map(|i| i.mnemonic), Some("bx"));
        assert_eq!(d.next(), None);
        assert_eq!(d.pos(), 2);
    }

    /// `Decoder::at` decodes from an offset while reporting a different
    /// address, which is what lets a caller decode a slice of an image loaded
    /// somewhere other than its file offset.
    #[test]
    fn decoder_at_separates_the_offset_from_the_address() {
        // bx lr · bx lr, with the second one at file offset 2 and address
        // 0x8002.
        let image = [0x70u8, 0x47, 0x70, 0x47];
        let mut d = Decoder::at(&image, 2, 0x8002);
        assert_eq!(d.pos(), 2);
        assert_eq!(d.it_state(), ItState::INACTIVE);
        let insn = d.next().expect("bx lr");
        assert_eq!(insn.addr, 0x8002);
        assert_eq!(d.pos(), 4);
        assert_eq!(d.next(), None);

        // A pc-relative operand resolves against the stated address, not the
        // offset: `ldr r0, [pc, #0]` at 0x8000 names the word at 0x8004.
        let literal = [0x00u8, 0x48];
        let insn = Decoder::at(&literal, 0, 0x8000)
            .next()
            .expect("ldr literal");
        assert_eq!(insn.branch_target(), Some(0x8004));
    }

    /// The whole point of [`disassemble`]: an undefined halfword is rendered
    /// as data and the walk resumes two bytes later, because a firmware image
    /// is full of literal pools, jump tables and padding.
    #[test]
    fn disassemble_renders_undefined_halfwords_as_data_and_resynchronises() {
        // bx lr · 0xBF50 (a reserved hint, which this crate declines to name)
        // · bx lr.
        let image = [0x70u8, 0x47, 0x50, 0xBF, 0x70, 0x47];
        assert_eq!(decode_at(&image, 2), None, "0xbf50 is not decoded");
        assert_eq!(
            disassemble(&image, 0, 0x1000, 3),
            [
                "00001000: bx lr",
                "00000002: .short 0xbf50",
                "00001004: bx lr",
            ]
        );

        // The count is a maximum, not a promise: a run that reaches the end of
        // the image stops there rather than padding or looping.
        assert_eq!(disassemble(&image, 0, 0x1000, 99).len(), 3);
        // An odd trailing byte is not half a halfword, so the walk ends.
        assert_eq!(disassemble(&[0x70, 0x47, 0x00], 0, 0, 9).len(), 1);
        assert_eq!(disassemble(&[], 0, 0, 9), Vec::<String>::new());
        // Asking for nothing returns nothing, without decoding anything.
        assert_eq!(disassemble(&image, 0, 0x1000, 0), Vec::<String>::new());
    }

    /// [`encode`] tries the ThumbEE group first for a narrow instruction, and
    /// verifies the candidate *in ThumbEE state* — chapter A9's encodings
    /// deliberately shadow ordinary ones, so a candidate checked in ordinary
    /// Thumb state would decode back as the `stmia` that shares its halfword
    /// and be discarded.
    #[test]
    fn encode_reproduces_a_thumbee_instruction() {
        // `hb #7` — 0xC207 in ThumbEE state, `stmia r2!, {r0-r2}` in Thumb
        // state. The same bytes, two instructions, and `encode` must produce
        // the halfword for the one it was handed.
        let ee = decode_halfwords(0xC207, 0, 0x1000, true).expect("hb #7");
        assert_eq!(ee.mnemonic, "hb");
        assert_eq!(encode(&ee), Some((0xC207, 0)));
        assert_eq!(encode_bytes(&ee), Some(vec![0x07, 0xC2]));

        let plain = decode_halfwords(0xC207, 0, 0x1000, false).expect("stmia");
        assert_eq!(plain.mnemonic, "stmia");
        assert_eq!(encode(&plain), Some((0xC207, 0)));

        // The candidate a group offers is *verified* before it is returned,
        // and this is that check firing. `thumbee::encode` does not look at
        // `Mem::align` — no ThumbEE encoding has an alignment qualifier to
        // carry — so it answers a halfword for `ldr r0, [r9:64]`, and that
        // halfword decodes back to the same instruction *without* the
        // qualifier. The central comparison sees the difference and discards
        // the candidate, which is the whole reason groups may be greedy: this
        // instruction gets no encoding rather than a wrong one.
        let aligned = Insn {
            operands: [
                Operand::Reg(Reg(0)),
                Operand::Mem(Mem {
                    base: Reg(9),
                    index: None,
                    offset: 0,
                    add: true,
                    align: 64,
                    mode: AddrMode::Offset,
                }),
            ]
            .into_iter()
            .collect(),
            ..decode_halfwords(0xCC10, 0, 0x1000, true).expect("ldr r0, [r9, #8]")
        };
        assert_eq!(aligned.to_string(), "ldr r0, [r9:64]");
        assert_eq!(encode(&aligned), None);
        assert_eq!(encode_bytes(&aligned), None);

        // Every ThumbEE encoding round-trips through the public entry point,
        // not just the one: the group's own sweep calls `thumbee::encode`
        // directly and so cannot see the dispatcher dropping them.
        let mut checked = 0usize;
        for hw in 0xC000u16..=0xCFFF {
            if let Some(i) = decode_halfwords(hw, 0, 0x1000, true) {
                assert_eq!(encode(&i), Some((hw, 0)), "{hw:#06x} as `{i}`");
                checked += 1;
            }
        }
        assert_eq!(checked, 3840, "Table A9-2 less its 256 UNDEFINED halfwords");
    }

    /// `encode` answers `None` for an instruction no group claims, and
    /// [`encode_bytes`] propagates that rather than returning a truncated
    /// buffer.
    #[test]
    fn an_unencodable_instruction_yields_no_bytes() {
        let mut alien = decode_halfwords(0x4770, 0, 0, false).expect("bx lr");
        alien.mnemonic = "frobnicate";
        assert_eq!(encode(&alien), None);
        assert_eq!(encode_bytes(&alien), None);

        // A wide instruction that no group can express fails the same way —
        // and the wide path is a different arm of `encode`.
        let mut wide = decode_halfwords(0xF000, 0xF800, 0, false).expect("bl");
        wide.mnemonic = "frobnicate";
        assert_eq!(wide.width, Width::Wide);
        assert_eq!(encode(&wide), None);
        assert_eq!(encode_bytes(&wide), None);

        // A branch whose target has moved out of a narrow encoding's reach is
        // the same answer for a different reason: the caller is told to widen
        // it rather than handed a branch to the wrong place.
        let mut far = decode_halfwords(0xE7FE, 0, 0x1000, false).expect("b .");
        far.operands = [Operand::Target(0x9000)].into_iter().collect();
        assert_eq!(encode(&far), None);
    }

    /// `encode_bytes` emits word-invariant halfword order — `hw1` at the lower
    /// address, each halfword little-endian — and not a little-endian `u32`,
    /// which would byte-swap every 32-bit instruction.
    #[test]
    fn encode_bytes_is_word_invariant() {
        let narrow = decode_halfwords(0x4770, 0, 0, false).expect("bx lr");
        assert_eq!(encode_bytes(&narrow), Some(vec![0x70, 0x47]));

        // `bl` +0 — hw1 0xF000, hw2 0xF800.
        let wide = decode_halfwords(0xF000, 0xF800, 0, false).expect("bl");
        assert_eq!(encode(&wide), Some((0xF000, 0xF800)));
        assert_eq!(encode_bytes(&wide), Some(vec![0x00, 0xF0, 0x00, 0xF8]));
    }

    /// `faithful` rejects a candidate that does not decode at all, which is
    /// the guard that lets `encode` try groups in turn: a group that returns
    /// a halfword outside its own map must not have that halfword returned to
    /// the caller.
    #[test]
    fn a_candidate_that_does_not_decode_is_not_faithful() {
        let insn = decode_halfwords(0x4770, 0, 0, false).expect("bx lr");
        // `0xB651` is `SETEND` with a should-be-zero bit set; this crate
        // refuses it, so no instruction can be faithfully encoded to it.
        assert_eq!(decode_halfwords(0xB651, 0, 0, false), None);
        assert!(!faithful(&insn, 0xB651, 0, false));
        // And the instruction's own halfword is faithful, so the assertion
        // above is about the candidate and not about the comparison.
        assert!(faithful(&insn, 0x4770, 0, false));
    }

    /// An IT block conditionalises the instructions it governs, and clears
    /// `sets_flags` for the *narrow* ones only.
    ///
    /// Almost every 16-bit data-processing encoding specifies
    /// `setflags = !InITBlock()`, which is why UAL spells the conditional form
    /// `lsleq` and not `lslseq`. The wide encodings carry an explicit `S` bit
    /// whose meaning does not depend on the IT state, so `addseq.w` keeps its
    /// `s` — dropping it there would print an instruction that assembles to a
    /// different halfword, one that does not write the flags.
    #[test]
    fn an_it_block_clears_the_flags_of_narrow_instructions_only() {
        // itt eq · lsls r0, r1, #2 · adds.w r0, r1, #1
        let image = [0x04, 0xBF, 0x88, 0x00, 0x11, 0xF1, 0x01, 0x00];
        let text: Vec<String> = Decoder::new(&image).map(|i| i.to_string()).collect();
        assert_eq!(text, ["itt eq", "lsleq r0, r1, #2", "addseq.w r0, r1, #1"]);

        let decoded: Vec<Insn> = Decoder::new(&image).collect();
        assert_eq!(decoded.len(), 3);
        // The narrow one: conditional, and no longer flag-setting …
        assert_eq!(decoded[1].cond, Some(Cond::Eq));
        assert_eq!(decoded[1].width, Width::Narrow);
        assert!(!decoded[1].sets_flags);
        // … while a bare decode of the same halfword, with no IT state in
        // sight, reports the flags it sets outside a block.
        let bare = decode_halfwords(0x0088, 0, 0, false).expect("lsls");
        assert!(bare.sets_flags);
        // The wide one: conditional, and still flag-setting.
        assert_eq!(decoded[2].cond, Some(Cond::Eq));
        assert_eq!(decoded[2].width, Width::Wide);
        assert!(
            decoded[2].sets_flags,
            "the wide encodings carry their own S bit"
        );
        // Both re-encode to the halfwords they came from, which is the test
        // that the cleared flag is a printing rule and not a lost bit.
        assert_eq!(encode(&decoded[1]), Some((0x0088, 0)));
        assert_eq!(encode(&decoded[2]), Some((0xF111, 0x0001)));
    }

    #[test]
    fn inactive_it_state_yields_no_condition() {
        assert!(!ItState::INACTIVE.active());
        assert_eq!(ItState::INACTIVE.current(), None);
        assert_eq!(ItState::INACTIVE.advance(), ItState::INACTIVE);
    }
}
