//! A9 "ThumbEE" — the slice of the 16-bit map that ThumbEE state re-assigns.
//!
//! ThumbEE (Thumb Execution Environment) is a variant of the Thumb instruction
//! set introduced in ARMv7 as a compilation target for managed runtimes: code
//! generated ahead of, or during, execution from a bytecode or intermediate
//! form (ARM DDI 0406B A2.10, "Execution environment support"). It buys three
//! things a JIT wants and plain Thumb makes expensive — an implicit null check
//! on every load and store, an array-bounds check (`CHKA`), and a dense call
//! into a table of runtime handlers (`HB`, `HBL`, `HBP`, `HBLP`) — and pays for
//! them by deleting the three Thumb instructions it can least afford to keep:
//! `BLX (immediate)` and the 16-bit `LDM`/`STM` (A9.1).
//!
//! It is an **A/R-profile-only** extension: required in ARMv7-A, optional in
//! ARMv7-R (DDI 0406B A1.3 and B1.4.2), reported by `ID_ISAR3.ThumbEE_extn`,
//! absent from every M-profile core, and dropped altogether in ARMv8. Arm
//! deprecated it long before that, so in practice almost no image contains
//! ThumbEE code.
//!
//! # Why a consumer would ever turn this on
//!
//! Because the decode is *not* a superset — it is a re-assignment. A halfword
//! in `0xC000..=0xCFFF` is a 16-bit `STM`/`LDM` in Thumb state and something
//! entirely different in ThumbEE state, and nothing in the halfword itself says
//! which. Only the processor's `CPSR.{J,T}` does. So a caller that knows (from
//! a `ENTERX`, from a symbol, from the runtime it is reverse-engineering) that
//! a region executes in ThumbEE state must say so — [`super::Decoder::thumbee`]
//! — or every `HB` in it silently disassembles as a store-multiple. Getting
//! that backwards invents register traffic where the hardware takes a branch.
//!
//! # The dispatch contract
//!
//! In ThumbEE state a halfword has three possible fates, not two, and the
//! dispatcher needs all three: *mine, and here is the instruction*; *mine, and
//! UNDEFINED* (Table A9-2's `0xC100..=0xC1FF` hole); *not mine, ask the
//! ordinary groups*. A bare `Option<Insn>` carries only two, and folding the
//! middle case into `None` is precisely the bug this module used to have — the
//! 256 halfwords ThumbEE leaves undefined fell through and came back as the
//! `STM` that ThumbEE deletes, an instruction that does not exist in the state
//! being decoded.
//!
//! The third value is supplied by [`owns`], a predicate the dispatcher tests
//! *before* calling [`decode`]: inside the owned range whatever [`decode`]
//! answers is final, `None` included. Two alternatives were rejected. A
//! three-valued return type would change the `decode(hw1, hw2, addr) ->
//! Option<Insn>` signature that all eighteen other group modules share, and
//! which [`super::encode`]'s `faithful` check and this file's own tests call
//! directly — a wide change to express a fact about one module. Teaching
//! [`super::decode_halfwords`] the range `0xC000..=0xCFFF` itself would put the
//! knowledge of which encodings ThumbEE claims in the dispatcher, where a later
//! edit to Table A9-2's coverage here would silently disagree with it. [`owns`]
//! keeps that knowledge in this file, in one constant pair, adjacent to the
//! range test [`decode`] already performs — and makes it directly testable, so
//! `tests::owns_agrees_with_decode` can pin `decode(hw).is_some() =>
//! owns(hw)` over the whole halfword space.
//!
//! [`decode`] is still called *before* the ordinary 16-bit groups and only when
//! the ThumbEE flag is set, and it still range-tests first: a single
//! over-claimed halfword here removes an ordinary Thumb instruction from the
//! map for every ThumbEE consumer, which is why `tests::non_interference`
//! sweeps all 65536 values.
//!
//! # Encoding is not state-aware, and does not need to be
//!
//! The re-assignment has no encode-side twin. [`super::encode`] takes an
//! [`Insn`] and no state: the caller has already named the instruction it
//! wants, and `stmia r4!, {r2, r5}` names one that does not exist in ThumbEE
//! state — the answer "here are the bytes of the STM you asked for" is the only
//! one the signature can give, and refusing it would need a `thumbee: bool`
//! parameter on a public function that every group's encoder feeds. Nothing is
//! lost by leaving it out, because the two directions are not symmetric: decode
//! reads a halfword that genuinely means different things in the two states,
//! while encode is handed a mnemonic that belongs to exactly one of them. The
//! `E1`/`E2`/`E3` encoding names keep the two sets disjoint in practice (A6.1
//! reserves `E<n>` for ThumbEE encodings that are not also Thumb encodings), so
//! [`encode`] here never claims a Thumb instruction and the Thumb groups never
//! claim a ThumbEE one — `tests::encode_refuses_ordinary_thumb` sweeps that.
//! A consumer assembling for ThumbEE state must not ask for the three deleted
//! instructions (`BLX (immediate)`, 16-bit `LDM`/`STM`); this crate will encode
//! them if asked, as it will encode any other instruction the target core does
//! not implement.
//!
//! # What this module owns: exactly `0xC000..=0xCFFF`
//!
//! A9.2.1's Table A9-2 splits `1100 xxxx …` — Thumb's `11000x`/`11001x`
//! `STM`/`LDM` rows, and the footnote *a* to Table A6-1 that redirects them
//! here — on `hw1[11:8]`:
//!
//! | `hw1[11:8]` | halfwords | instruction | encoding |
//! |-------------|-----------|-------------|----------|
//! | `0000` | `0xC000..=0xC0FF` | `HBP #<imm3>, #<handler>` | `11000000 imm3 handler` |
//! | `0001` | `0xC100..=0xC1FF` | UNDEFINED | — |
//! | `001x` | `0xC200..=0xC3FF` | `HB`/`HBL #<handler>` | `1100001L handler` |
//! | `01xx` | `0xC400..=0xC7FF` | `HBLP #<imm5>, #<handler>` | `110001 imm5 handler` |
//! | `100x` | `0xC800..=0xC9FF` | `LDR <Rt>, [<Rn>, #-<imm>]` | `1100100 imm3 Rn Rt` |
//! | `1010` | `0xCA00..=0xCAFF` | `CHKA <Rn>, <Rm>` | `11001010 N Rm Rn` |
//! | `1011` | `0xCB00..=0xCBFF` | `LDR <Rt>, [r10, #<imm>]` | `11001011 imm5 Rt` |
//! | `110x` | `0xCC00..=0xCDFF` | `LDR <Rt>, [r9, #<imm>]` | `1100110 imm6 Rt` |
//! | `111x` | `0xCE00..=0xCFFF` | `STR <Rt>, [r9, #<imm>]` | `1100111 imm6 Rt` |
//!
//! ## A note on Table A9-2 itself
//!
//! The table's prose columns and the encoding diagrams on A9-19 disagree in
//! DDI 0406B: the table labels `100x` "Load Register from a frame" and `110x`
//! "Load Register (array operations)", while the `LDR (immediate)` diagrams
//! give `1100110 imm6 Rt` (`110x`) for the `R9` frame form and
//! `1100100 imm3 Rn Rt` (`100x`) for the array form. The diagrams and their
//! pseudocode (`n = 9` versus `n = UInt(Rn)`) are self-consistent and are what
//! this module implements; later revisions correct the table. Anyone checking
//! this file against that one table will see the transposition, so it is
//! recorded here rather than left to be rediscovered as a bug.
//!
//! # What this module does *not* own
//!
//! Three ThumbEE differences deliberately produce no code here, because the
//! encodings involved are unchanged and the dispatcher would have to steal them
//! from a sibling to express a difference that is not in the bits:
//!
//! * **Null checking (A9.1.2).** Every instruction whose mnemonic starts `LD`,
//!   `ST`, `VLD` or `VST`, plus `POP`, `PUSH`, `TBB`, `TBH`, `VPOP`, `VPUSH`,
//!   gains `NullCheckIfThumbEE(n)`: a zero base register branches to the
//!   NullCheck handler at `HandlerBase - 4` instead of accessing memory. Not
//!   one bit of any of those encodings changes, and [`super::Insn`] has no
//!   place to record "may trap"; the ordinary load/store groups decode them.
//! * **The scaled register-offset forms (A9.1.3, Table A9-1).** In ThumbEE
//!   `LDR`/`STR (register)` T1 shift `Rm` left by 2 and `LDRH`/`LDRSH`/`STRH`
//!   by 1, so `0101100 Rm Rn Rt` means `ldr rt, [rn, rm, lsl #2]` here and
//!   `ldr rt, [rn, rm]` in Thumb state. The halfword is *identical* — A9.4
//!   reprints it under "Encoding T1", not a new `E<n>` — so the difference is
//!   in the operation, not the encoding, and it stays with
//!   [`super::t16_loadstore`]. The cost is honest and worth stating: in
//!   ThumbEE state those five encodings print without the `lsl` the manual's
//!   syntax line shows. Expressing it would mean claiming `0x5000..=0x5FFF`
//!   wholesale and re-deriving five encodings that are otherwise identical,
//!   which trades a printing detail for exactly the over-claim this module
//!   exists to avoid.
//! * **`BLX (immediate)`, UNDEFINED in ThumbEE (A9.1).** A 32-bit encoding;
//!   [`super::decode_halfwords`] only routes 16-bit halfwords here, so it never
//!   reaches this module.
//!
//! By contrast the ThumbEE literal-pool load *is* an encoding-level change and
//! is claimed: A9.5.5's E2 form reads a word pool through `R10`, not through
//! `Align(PC,4)` as Thumb's `LDR (literal)` T1 does, and it has its own
//! halfword (`11001011 imm5 Rt`) in the re-assigned space. Same for the `R9`
//! frame loads and stores and the negative-offset array load: new encodings,
//! decoded here.
//!
//! # `ENTERX` and `LEAVEX`
//!
//! A9.3.1's state-switching pair is 32-bit (`1111 0011 1011 1111 10(0)0 (1)(1)(1)(1) 000J …`)
//! and lives in the miscellaneous-control space of Table A6-15, `op == 0000`
//! (`LEAVEX`, `J = 0`) and `op == 0001` (`ENTERX`, `J = 1`). Those are
//! [`super::t32_branch_misc`]'s, not this module's — the dispatcher sends only
//! single halfwords here — and they are available in *both* Thumb and ThumbEE
//! state, so they are not conditional on the ThumbEE flag at all.
//!
//! # The handler branches have no computable target
//!
//! `HB`, `HBL`, `HBP` and `HBLP` branch to `TEEHBR + handler:'00000'` — the
//! handler table based at `HandlerBase`, held in the ThumbEE Handler Base
//! Register and reachable only through `MRC p14, 6, <Rt>, c1, c0, 0`
//! (DDI 0406B A2.10.1). A decoder holding one halfword cannot know it, and
//! neither can a consumer holding a firmware image, so no [`Operand::Target`]
//! is emitted and [`Insn::branch_target`] correctly answers `None`. The
//! `handler` field is carried as a plain [`Operand::Imm`] — it is an index into
//! that table, not an address, and the manual's syntax spells it `#<HandlerID>`.
//! `CHKA` is the same shape: when the index is out of bounds it branches to
//! `TEEHBR - 8`, an address this crate cannot compute either.
//!
//! What the shared contract does say about them lives in [`super::insn`], and
//! is now complete: `hb`, `hbl`, `hbp`, `hblp` and `chka` are all in
//! [`Insn::is_branch`]'s mnemonic set, `hbl` and `hblp` are in
//! [`Insn::is_call`]'s (they alone write `LR` — A9.5.2's `generate_link` and
//! A9.5.3's unconditional `LR = next_instr_addr<31:1>:'1'`), and `chka` is
//! deliberately in neither `is_call` nor [`Insn::writes_pc`]: its `LR` value is
//! `PC`, four ahead of itself rather than the two `HBL` computes, so it is not
//! a return address, and its first operand is the array *size*, a source, which
//! `writes_pc`'s pc-destination heuristic would otherwise misread.

use super::{AddrMode, Insn, Mem, Operand, Operands, Reg, Width};

/// The first halfword this module owns — Thumb's `STM` T1 (`11000x`).
const RANGE_LO: u16 = 0xC000;

/// The last halfword this module owns — the end of Thumb's `LDM` T1
/// (`11001x`). Everything outside `RANGE_LO..=RANGE_HI` belongs to an ordinary
/// 16-bit group and must fall through untouched.
const RANGE_HI: u16 = 0xCFFF;

/// `R9`, the frame base of `LDR`/`STR (immediate)` E1 (A9.5.5, A9.5.6). Fixed
/// by the encoding: there is no `Rn` field in those halfwords.
const FRAME_BASE: Reg = Reg(9);

/// `R10`, the literal-pool base of `LDR (immediate)` E2 (A9.5.5). This is the
/// one place ThumbEE parts company with Thumb's pc-relative literal load: the
/// pool is addressed through a register the runtime sets up, not through
/// `Align(PC,4)`, so the target is not statically resolvable and no
/// [`Operand::Target`] accompanies the [`Operand::Mem`].
const POOL_BASE: Reg = Reg(10);

/// Build an [`Insn`] with this group's invariants already set.
///
/// Everything in A9.5 is a single halfword, so `width` is always
/// [`Width::Narrow`] and `explicit_width` always false — none of these
/// mnemonics has a wide encoding to disambiguate from. `sets_flags` is
/// unconditionally false: A9.5.1 says so of `CHKA` in as many words ("CHKA does
/// not modify the APSR condition code flags"), and none of the handler branches
/// or the loads and stores touches `APSR` either.
///
/// `cond` is always `None`. No ThumbEE encoding carries a condition field; the
/// `<c>` in every A9.5 syntax line comes from an enclosing `IT` block, which is
/// a different instruction and [`super::Decoder`]'s business, not this
/// halfword's.
fn insn(
    mnemonic: &'static str,
    encoding: &'static str,
    addr: u32,
    operands: Operands,
) -> Option<Insn> {
    Some(Insn {
        mnemonic,
        encoding,
        addr,
        width: Width::Narrow,
        cond: None,
        sets_flags: false,
        explicit_width: false,
        operands,
    })
}

/// A base-plus-constant memory operand with no index and no writeback — the
/// only shape any 16-bit ThumbEE load or store can express.
///
/// `add` is the architectural `add` flag of the encoding, which for
/// [`decode_ldr_array`] is `FALSE`. It is passed rather than assumed because
/// [`Mem`] keeps the direction as a flag beside an unsigned magnitude.
fn mem(base: Reg, add: bool, offset: u32) -> Operand {
    Operand::Mem(Mem {
        base,
        index: None,
        offset,
        add,
        align: 0,
        mode: AddrMode::Offset,
    })
}

/// Whether `hw1` falls in the halfword range ThumbEE re-assigns, and so is
/// this module's to answer for.
///
/// This is the predicate that makes [`decode`]'s `None` mean two different
/// things to [`super::decode_halfwords`]: outside this range it means "not a
/// ThumbEE encoding, try the ordinary 16-bit groups", and inside it means
/// UNDEFINED — Table A9-2's `0xC100..=0xC1FF` row, the one hole in the space
/// A9.2.1 re-assigns. Without the distinction those 256 halfwords decode in
/// ThumbEE state as the 16-bit `STM` that ThumbEE deletes (A9.1).
///
/// The range is the whole of Thumb's `11000x`/`11001x` `STM`/`LDM` block, which
/// footnote *a* to Table A6-1 redirects here in its entirety. It is stated
/// once, here, and used by both this module and the dispatcher: a consumer of
/// this crate that walks ThumbEE code does not have to know the number.
pub(crate) fn owns(hw1: u16) -> bool {
    (RANGE_LO..=RANGE_HI).contains(&hw1)
}

/// Decode a 16-bit ThumbEE instruction, or `None` if `hw1` is not one.
///
/// `_hw2` is unused: every encoding in A9.5 is a single halfword, and the
/// 32-bit `ENTERX`/`LEAVEX` pair of A9.3 is decoded by
/// [`super::t32_branch_misc`] instead.
///
/// The range test comes first and is absolute. This function is called on
/// *every* 16-bit halfword before the ordinary groups see it, so anything it
/// claims outside `0xC000..=0xCFFF` is an ordinary Thumb instruction stolen
/// from a sibling module.
pub(crate) fn decode(hw1: u16, _hw2: u16, addr: u32) -> Option<Insn> {
    if !owns(hw1) {
        return None;
    }

    // Table A9-2 keys on `hw1[11:8]`, the four bits below the constant `1100`.
    match (hw1 >> 8) & 0xF {
        0b0000 => decode_hbp(hw1, addr),
        // The one hole Table A9-2 leaves: "Other encodings in this space are
        // UNDEFINED". Rejected rather than folded into a neighbour, because a
        // ThumbEE image containing `0xC1xx` is data or corruption, and saying
        // so is more useful than inventing an `HB`. `owns` is what makes this
        // `None` reach the caller as UNDEFINED rather than as a fall-through
        // into the ordinary 16-bit groups, where it would resurface as `STM`.
        0b0001 => None,
        0b0010..=0b0011 => decode_hb(hw1, addr),
        0b0100..=0b0111 => decode_hblp(hw1, addr),
        0b1000..=0b1001 => decode_ldr_array(hw1, addr),
        0b1010 => decode_chka(hw1, addr),
        0b1011 => decode_ldr_pool(hw1, addr),
        0b1100..=0b1101 => decode_frame(hw1, addr, "ldr"),
        _ => decode_frame(hw1, addr, "str"),
    }
}

/// `HBP<c> #<imm>, #<HandlerID>` — E1, `11000000 imm3(3) handler(5)` (A9.5.4).
///
/// Handler Branch with Parameter: writes `ZeroExtend(imm3)` to `R8` and
/// branches to `TEEHBR + handler:'00000'`. Both fields are plain immediates —
/// the parameter is a value, the handler ID an index into the table at
/// `HandlerBase` — and the syntax line puts the parameter first, which is the
/// opposite of the bit order, so the operand order is taken from A9-18's
/// syntax line and not from the diagram.
///
/// The whole 256-halfword opcode row is `HBP`: every `imm3` and every
/// `handler` is valid, and there are no should-be-zero bits to check.
fn decode_hbp(hw1: u16, addr: u32) -> Option<Insn> {
    let imm3 = ((hw1 >> 5) & 0b111) as i64;
    let handler = (hw1 & 0b1_1111) as i64;
    let mut ops = Operands::new();
    ops.push(Operand::Imm(imm3));
    ops.push(Operand::Imm(handler));
    insn("hbp", "E1", addr, ops)
}

/// `HB{L}<c> #<HandlerID>` — E1, `1100001L handler(8)` (A9.5.2).
///
/// `L` (bit 8) alone separates the two: `HB` branches, `HBL` first writes the
/// return address to `LR` (`next_instr_addr = PC - 2`, i.e. the following
/// halfword, with bit 0 forced to 1 because ThumbEE never interworks to ARM
/// state). That makes `HBL` a call, and `HBL`'s eight-bit handler field is what
/// A9-16 means by "HB{L} makes a large number of handlers available" — 256 of
/// them, against 32 for the parameter-passing forms.
///
/// Both are branches to [`Insn::is_branch`]; only `hbl` is a call to
/// [`Insn::is_call`], which is the whole of the difference the `L` bit makes.
fn decode_hb(hw1: u16, addr: u32) -> Option<Insn> {
    let link = (hw1 >> 8) & 1 == 1;
    let handler = (hw1 & 0xFF) as i64;
    let mut ops = Operands::new();
    ops.push(Operand::Imm(handler));
    insn(if link { "hbl" } else { "hb" }, "E1", addr, ops)
}

/// `HBLP<c> #<imm>, #<HandlerID>` — E1, `110001 imm5(5) handler(5)` (A9.5.3).
///
/// Handler Branch with Link and Parameter: `R8 = ZeroExtend(imm5)`, `LR` gets
/// the return address, then the branch. It spends four opcode rows (`01xx`,
/// 1024 halfwords) because its parameter field is five bits wide rather than
/// `HBP`'s three, and it pays for that by halving nothing — both forms address
/// only 32 handlers.
fn decode_hblp(hw1: u16, addr: u32) -> Option<Insn> {
    let imm5 = ((hw1 >> 5) & 0b1_1111) as i64;
    let handler = (hw1 & 0b1_1111) as i64;
    let mut ops = Operands::new();
    ops.push(Operand::Imm(imm5));
    ops.push(Operand::Imm(handler));
    insn("hblp", "E1", addr, ops)
}

/// `CHKA<c> <Rn>, <Rm>` — E1, `11001010 N Rm(4) Rn(3)` (A9.5.1).
///
/// Check Array: if `UInt(R[n]) <= UInt(R[m])` — array size at or below the
/// index — it copies the return address to `LR` and branches to the IndexCheck
/// handler at `TEEHBR - 8`. Operand order matters and is *size first, index
/// second*; reversing it turns a bounds check into its negation.
///
/// Three bit-level details, all easy to get wrong:
///
/// * `Rn` is split. The encoding is `N:Rn` — bit 7 supplies the high bit of a
///   four-bit register number whose low three bits are `hw1[2:0]` — so `CHKA`
///   can name any of `r0`–`r14`, and A9-15 notes explicitly that "use of the SP
///   is permitted". `Rm` is a contiguous four-bit field at `hw1[6:3]`.
/// * It is not a data-processing instruction. `CHKA` does not modify the APSR
///   flags, so `sets_flags` stays false even though it compares two registers.
/// * The UNPREDICTABLE combinations — `n == 15`, and `BadReg(m)` meaning
///   `m == 13 || m == 15` — are still decoded. They are perfectly
///   representable, they re-encode to the halfword they came from, and this
///   module follows [`super::t16_special`]'s precedent of refusing only what
///   has no UAL spelling. Decoding `n == 15` used to have a side effect worth
///   recording: [`Insn::writes_pc`] keys on the first operand being `pc`, so
///   `chka pc, rm` reported a pc write — accidentally right about the taken
///   path and wrong about the reason, since `Rn` is the array size, a source.
///   `writes_pc` now excludes `chka` for exactly that reason, alongside `cmp`
///   and the stores, and the branch is reported by [`Insn::is_branch`] instead.
fn decode_chka(hw1: u16, addr: u32) -> Option<Insn> {
    let n = (((hw1 >> 4) & 0b1000) | (hw1 & 0b111)) as u8;
    let m = ((hw1 >> 3) & 0xF) as u8;
    let mut ops = Operands::new();
    ops.push(Operand::Reg(Reg(n)));
    ops.push(Operand::Reg(Reg(m)));
    insn("chka", "E1", addr, ops)
}

/// `LDR<c> <Rt>, [<Rn>{, #-<imm>}]` — E3, `1100100 imm3(3) Rn(3) Rt(3)`
/// (A9.5.5).
///
/// The array-access form: base in `r0`–`r7`, and `add = FALSE`, so the offset
/// *subtracts* — `imm3:'00'` gives 0, −4, … −28. The magnitude goes in
/// [`Mem::offset`] and the direction in [`Mem::add`], so a consumer reads
/// [`Mem::displacement`] and never has to know the encoding had no `U` bit.
///
/// `imm3 == 0` is the one value with no direction, and it is spelled `add =
/// TRUE`: there being no `U` bit, this encoding has no `#-0` for `add = FALSE`
/// to denote, and A9.5.5 braces the offset (`[<Rn>{, #-<imm>}]`) precisely so
/// that zero prints as a bare `[<Rn>]`.
fn decode_ldr_array(hw1: u16, addr: u32) -> Option<Insn> {
    let imm3 = u32::from((hw1 >> 6) & 0b111);
    let rn = ((hw1 >> 3) & 0b111) as u8;
    let rt = (hw1 & 0b111) as u8;
    let mut ops = Operands::new();
    ops.push(Operand::Reg(Reg(rt)));
    ops.push(mem(Reg(rn), imm3 == 0, imm3 * 4));
    insn("ldr", "E3", addr, ops)
}

/// `LDR<c> <Rt>, [r10{, #<imm>}]` — E2, `11001011 imm5(5) Rt(3)` (A9.5.5).
///
/// ThumbEE's literal-pool load, and the reason this encoding is claimed rather
/// than left to [`super::t16_loadstore`]: it reaches the pool through `R10`,
/// which the runtime points at the pool, where Thumb's `LDR (literal)` T1 uses
/// `Align(PC,4)`. Different base, different halfword, and — unlike a T1 literal
/// load — nothing a decoder can resolve to an address, so there is no
/// [`Operand::Target`] here.
///
/// Offsets are `imm5:'00'`, 0 to 124.
fn decode_ldr_pool(hw1: u16, addr: u32) -> Option<Insn> {
    let imm5 = u32::from((hw1 >> 3) & 0b1_1111);
    let rt = (hw1 & 0b111) as u8;
    let mut ops = Operands::new();
    ops.push(Operand::Reg(Reg(rt)));
    ops.push(mem(POOL_BASE, true, imm5 * 4));
    insn("ldr", "E2", addr, ops)
}

/// `LDR<c> <Rt>, [r9{, #<imm>}]` — E1, `1100110 imm6(6) Rt(3)` (A9.5.5) —
/// and `STR<c> <Rt>, [r9, #<imm>]` — E1, `1100111 imm6(6) Rt(3)` (A9.5.6).
///
/// One function for both because only `hw1[9]` differs: the frame forms share
/// the base (`R9`, fixed by the encoding — there is no `Rn` field), the field
/// widths, and the scaling. `imm6:'00'` gives offsets 0 to 252, the "up to 63
/// words" of A9-19.
///
/// The `STR` syntax line writes the offset as mandatory (`[R9, #<imm>]`) and
/// the `LDR` line as optional (`[R9{, #<imm>}]`), but both texts then say
/// "`<imm>` can be omitted, meaning an offset of 0", and [`Mem`]'s `Display`
/// elides an *adding* zero offset in [`AddrMode::Offset`] — so `str r0, [r9]`
/// prints, and re-encodes, as `imm6 == 0`.
fn decode_frame(hw1: u16, addr: u32, mnemonic: &'static str) -> Option<Insn> {
    let imm6 = u32::from((hw1 >> 3) & 0b11_1111);
    let rt = (hw1 & 0b111) as u8;
    let mut ops = Operands::new();
    ops.push(Operand::Reg(Reg(rt)));
    ops.push(mem(FRAME_BASE, true, imm6 * 4));
    insn(mnemonic, "E1", addr, ops)
}

/// Re-encode an instruction this module decoded, back to its halfword.
///
/// Strictness is the whole job. [`super::encode`] tries every narrow group in
/// turn until one answers, so a `Some` returned here for an ordinary Thumb
/// instruction would silently emit a ThumbEE halfword for code that is not in
/// ThumbEE state — the encode-side twin of over-claiming in [`decode`]. Three
/// layers guard against it: the `(mnemonic, encoding)` pair must match exactly
/// (the ThumbEE-only names `chka`/`hb`/`hbl`/`hbp`/`hblp`, or `ldr`/`str` with
/// one of A9's `E1`/`E2`/`E3` encoding names, which no Thumb encoding uses —
/// DDI 0406B A8.1.3 reserves `E<n>` for "ThumbEE encodings that are not also
/// Thumb encodings"), the operand count must be exact, and every field must fit
/// the width and scaling its encoding gives it.
///
/// [`Insn::cond`] is not consulted: no encoding here has a condition field, so
/// a condition can only have come from an enclosing `IT` block, which is a
/// different halfword.
pub(crate) fn encode(insn: &Insn) -> Option<u16> {
    if insn.width != Width::Narrow || insn.sets_flags || insn.explicit_width {
        return None;
    }
    match (insn.mnemonic, insn.encoding) {
        // `11000000 imm3 handler`.
        ("hbp", "E1") => {
            let imm3 = imm_field(insn, 0, 2, 0b111)?;
            let handler = imm_field(insn, 1, 2, 0b1_1111)?;
            Some(0xC000 | (imm3 << 5) | handler)
        }
        // `1100001L handler`, `L == 0`.
        ("hb", "E1") => Some(0xC200 | imm_field(insn, 0, 1, 0xFF)?),
        // `1100001L handler`, `L == 1`.
        ("hbl", "E1") => Some(0xC300 | imm_field(insn, 0, 1, 0xFF)?),
        // `110001 imm5 handler`.
        ("hblp", "E1") => {
            let imm5 = imm_field(insn, 0, 2, 0b1_1111)?;
            let handler = imm_field(insn, 1, 2, 0b1_1111)?;
            Some(0xC400 | (imm5 << 5) | handler)
        }
        // `11001010 N Rm Rn`, with `Rn` split across bit 7 and bits 2:0.
        ("chka", "E1") => {
            if insn.operands.len() != 2 {
                return None;
            }
            let n = any_reg(insn.operands.get(0))?;
            let m = any_reg(insn.operands.get(1))?;
            Some(0xCA00 | ((n & 0b1000) << 4) | (m << 3) | (n & 0b111))
        }
        // `1100110 imm6 Rt`, base `r9`, offsets 0..=252.
        ("ldr", "E1") => {
            let (rt, imm) = mem_field(insn, FRAME_BASE, 0, 252)?;
            Some(0xCC00 | (imm << 3) | rt)
        }
        // `11001011 imm5 Rt`, base `r10`, offsets 0..=124.
        ("ldr", "E2") => {
            let (rt, imm) = mem_field(insn, POOL_BASE, 0, 124)?;
            Some(0xCB00 | (imm << 3) | rt)
        }
        // `1100100 imm3 Rn Rt`, low base, offsets -28..=0.
        ("ldr", "E3") => {
            if insn.operands.len() != 2 {
                return None;
            }
            let rt = low_reg(insn.operands.get(0))?;
            let m = plain_mem(insn.operands.get(1))?;
            if !m.base.is_low() {
                return None;
            }
            let imm3 = neg_scaled_offset(&m, 28)?;
            Some(0xC800 | (imm3 << 6) | ((m.base.num() as u16) << 3) | rt)
        }
        // `1100111 imm6 Rt`, base `r9`, offsets 0..=252.
        ("str", "E1") => {
            let (rt, imm) = mem_field(insn, FRAME_BASE, 0, 252)?;
            Some(0xCE00 | (imm << 3) | rt)
        }
        _ => None,
    }
}

/// Operand `i` of an instruction that must have exactly `len` operands, as an
/// unsigned immediate no wider than `max`.
///
/// The arity check is part of the guard, not decoration: `hb #5` and a
/// hand-built `hb` carrying three operands must not encode to the same
/// halfword, because only one of them round-trips.
fn imm_field(insn: &Insn, i: usize, len: usize, max: i64) -> Option<u16> {
    if insn.operands.len() != len {
        return None;
    }
    match insn.operands.get(i) {
        Some(Operand::Imm(v)) if (0..=max).contains(&v) => Some(v as u16),
        _ => None,
    }
}

/// Any core register `r0`–`r15`, as a four-bit field.
///
/// An operand that is absent answers through the same arm as one that is not a
/// register: both mean "there is no register field to encode here", and the
/// arity checks above make the first of them unreachable anyway.
fn any_reg(op: Option<Operand>) -> Option<u16> {
    match op {
        Some(Operand::Reg(r)) => Some(r.num() as u16),
        _ => None,
    }
}

/// A low register `r0`–`r7`, as a three-bit field.
fn low_reg(op: Option<Operand>) -> Option<u16> {
    match op {
        Some(Operand::Reg(r)) if r.is_low() => Some(r.num() as u16),
        _ => None,
    }
}

/// A memory operand of the only shape these encodings can express: a base plus
/// a constant, no index register, no writeback.
fn plain_mem(op: Option<Operand>) -> Option<Mem> {
    match op {
        Some(Operand::Mem(m)) if m.index.is_none() && m.mode == AddrMode::Offset => Some(m),
        _ => None,
    }
}

/// The `(Rt, imm)` fields of a fixed-base frame or pool form: exactly two
/// operands, a low `Rt`, and a `[<base>, #<imm>]` whose base is the one the
/// encoding hard-wires and whose offset is a multiple of four within range.
fn mem_field(insn: &Insn, base: Reg, lo: u32, hi: u32) -> Option<(u16, u16)> {
    if insn.operands.len() != 2 {
        return None;
    }
    let rt = low_reg(insn.operands.get(0))?;
    let m = plain_mem(insn.operands.get(1))?;
    if m.base != base {
        return None;
    }
    Some((rt, scaled_offset(&m, lo, hi)?))
}

/// A byte offset in `lo..=hi` and a multiple of four, as the word count the
/// encoding actually stores.
///
/// Rejecting a misaligned or out-of-range offset rather than truncating it is
/// the same contract the branch groups keep for displacements: a caller that
/// has moved a frame slot out of reach needs to be told, not handed a halfword
/// that addresses the wrong word.
fn scaled_offset(mem: &Mem, lo: u32, hi: u32) -> Option<u16> {
    // These encodings have no `U` bit, so a subtracting offset — `#-0`
    // included — is not something they can hold.
    if !mem.add || mem.offset < lo || mem.offset > hi || mem.offset % 4 != 0 {
        return None;
    }
    Some((mem.offset / 4) as u16)
}

/// A *subtracting* byte offset of magnitude `0..=hi` and a multiple of four, as
/// the word count `imm3` stores — the array form's `add = FALSE` read back.
///
/// `add` must match what [`decode_ldr_array`] emits: `FALSE` for a real
/// subtraction, `TRUE` for the directionless zero. `[<Rn>, #-0]` is therefore
/// not encodable here, which is right — this encoding has no `U` bit for it to
/// come from.
fn neg_scaled_offset(mem: &Mem, hi: u32) -> Option<u16> {
    if mem.add != (mem.offset == 0) || mem.offset > hi || mem.offset % 4 != 0 {
        return None;
    }
    Some((mem.offset / 4) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::Target;
    use crate::isa::{decode_halfwords, Decoder};

    /// Decode a halfword through this module directly.
    fn dec(hw1: u16) -> Option<Insn> {
        decode(hw1, 0, 0x1000)
    }

    /// The one UNDEFINED opcode row of Table A9-2, `hw1[11:8] == 0b0001`.
    const UNDEFINED_LO: u16 = 0xC100;
    /// The last halfword of that row.
    const UNDEFINED_HI: u16 = 0xC1FF;

    /// Every halfword in the space A9.2.1 re-assigns must either decode and
    /// re-encode to itself, or be one of the 256 values Table A9-2 marks
    /// UNDEFINED. Nothing in between.
    ///
    /// Run at several addresses because [`Insn::addr`] is carried through the
    /// round trip; no ThumbEE encoding is pc-relative, so the halfword must
    /// come back identical regardless, and this pins that.
    #[test]
    fn exhaustive_round_trip() {
        for addr in [0u32, 2, 0x8000, 0xFFFF_FFFC] {
            let mut decoded = 0usize;
            let mut rejected = Vec::new();
            for hw in RANGE_LO..=RANGE_HI {
                match decode(hw, 0, addr) {
                    Some(i) => {
                        decoded += 1;
                        assert_eq!(encode(&i), Some(hw), "{hw:#06x} at {addr:#x} -> {i}");
                        assert_eq!(i.len(), 2, "{hw:#06x} must be narrow");
                        assert!(!i.sets_flags, "{hw:#06x} must not set flags");
                        assert!(!i.explicit_width, "{hw:#06x} needs no width suffix");
                        assert_eq!(i.cond, None, "{hw:#06x} has no condition field");
                        assert_eq!(i.addr, addr);
                    }
                    None => rejected.push(hw),
                }
            }

            // 4096 halfwords in `0xC000..=0xCFFF`; the 256 with
            // `hw1[11:8] == 0b0001` are the UNDEFINED row of Table A9-2.
            assert_eq!(rejected.len(), 256);
            assert_eq!(decoded, 4096 - 256);
            assert_eq!(decoded, 3840);
            let expected: Vec<u16> = (UNDEFINED_LO..=UNDEFINED_HI).collect();
            assert_eq!(rejected, expected);
        }
    }

    /// The test that matters most: over all 65536 halfword values, `decode`
    /// answers `Some` for exactly the encodings chapter A9 assigns and for
    /// nothing else.
    ///
    /// This module is consulted *before* every ordinary 16-bit group whenever
    /// the ThumbEE flag is set, so one halfword claimed in error here removes
    /// an ordinary Thumb instruction from the map for every ThumbEE consumer,
    /// silently and everywhere. No other test can see that.
    #[test]
    fn non_interference() {
        let mut claimed = 0usize;
        for hw in 0..=u16::MAX {
            let owned =
                (RANGE_LO..=RANGE_HI).contains(&hw) && !(UNDEFINED_LO..=UNDEFINED_HI).contains(&hw);
            match dec(hw) {
                Some(i) => {
                    assert!(owned, "{hw:#06x} is not ThumbEE's, decoded as {i}");
                    claimed += 1;
                }
                None => assert!(!owned, "{hw:#06x} is ThumbEE's and was refused"),
            }
        }
        assert_eq!(claimed, 3840);
    }

    /// Table A9-2's partition, checked row by row against the mnemonic and
    /// encoding name each halfword must produce.
    #[test]
    fn table_a9_2_partition() {
        for hw in RANGE_LO..=RANGE_HI {
            let expect = match hw {
                0xC000..=0xC0FF => Some(("hbp", "E1")),
                0xC100..=0xC1FF => None,
                0xC200..=0xC2FF => Some(("hb", "E1")),
                0xC300..=0xC3FF => Some(("hbl", "E1")),
                0xC400..=0xC7FF => Some(("hblp", "E1")),
                0xC800..=0xC9FF => Some(("ldr", "E3")),
                0xCA00..=0xCAFF => Some(("chka", "E1")),
                0xCB00..=0xCBFF => Some(("ldr", "E2")),
                0xCC00..=0xCDFF => Some(("ldr", "E1")),
                _ => Some(("str", "E1")),
            };
            let got = dec(hw).map(|i| (i.mnemonic, i.encoding));
            assert_eq!(got, expect, "{hw:#06x}");
        }
    }

    /// `encode` must refuse every ordinary Thumb instruction, because
    /// [`crate::isa::encode`] offers each narrow group the instruction in turn
    /// and the first `Some` wins.
    ///
    /// The sweep is over the crate's own non-ThumbEE decode of all 65536
    /// halfwords, which is the broadest set of genuine `Insn` values available:
    /// it includes the `stmia`/`ldmia` pair this module's space belongs to in
    /// Thumb state, which is exactly the collision to worry about.
    #[test]
    fn encode_refuses_ordinary_thumb() {
        let mut seen = 0usize;
        let mut seen_ldm_stm = 0usize;
        for hw in 0..=u16::MAX {
            if let Some(i) = decode_halfwords(hw, 0, 0x1000, Target::Union) {
                seen += 1;
                assert_eq!(encode(&i), None, "{hw:#06x} ({i}) is not ThumbEE's");
                if (RANGE_LO..=RANGE_HI).contains(&hw) {
                    seen_ldm_stm += 1;
                }
            }
        }
        // The sweep must actually have covered the contested space, or it
        // proves nothing: 4096 halfwords less the 16 empty-register-list forms
        // that `t16_branch` refuses as UNPREDICTABLE.
        assert_eq!(seen_ldm_stm, 4096 - 16);
        // A floor that `t16_branch` alone guarantees (`0xC000..=0xE7FF` less
        // those same 16), so the sweep cannot quietly become vacuous.
        assert!(seen >= 10_224, "sweep decoded only {seen} instructions");
    }

    /// Each field these encodings read, offered something that does not fit.
    ///
    /// Strictness is this module's whole job — [`crate::isa::encode`] tries it
    /// *first* for every narrow instruction, so a `Some` for a shape chapter A9
    /// cannot express would emit a ThumbEE halfword for code that is not in
    /// ThumbEE state. The arity checks are part of that: `hb #5` and a
    /// hand-built `hb` with two operands must not produce the same halfword,
    /// because only one of them round-trips.
    #[test]
    fn encode_refuses_operands_no_field_can_hold() {
        let ops = |items: &[Operand]| items.iter().copied().collect::<Operands>();
        let r0 = Operand::Reg(Reg(0));
        let imm = |v| Operand::Imm(v);
        let frame = |base: Reg, offset, add| {
            Operand::Mem(Mem {
                base,
                index: None,
                offset,
                add,
                align: 0,
                mode: AddrMode::Offset,
            })
        };

        let cases: &[(u16, &[Operand], &str)] = &[
            // `HBP` — `11000000 imm3 handler`, two immediates and no more.
            (0xC0E1, &[imm(7)], "HBP takes two operands"),
            (0xC0E1, &[imm(7), imm(1), imm(0)], "HBP takes two operands"),
            (0xC0E1, &[imm(8), imm(1)], "imm3 holds 0..=7"),
            (0xC0E1, &[imm(7), imm(32)], "handler is five bits"),
            (0xC0E1, &[r0, imm(1)], "the fields are immediates"),
            (0xC0E1, &[imm(7), r0], "the fields are immediates"),
            // `HB`/`HBL` — `1100001L handler`, one immediate.
            (0xC207, &[], "HB takes one operand"),
            (0xC207, &[imm(7), imm(0)], "HB takes one operand"),
            (0xC207, &[imm(256)], "handler is eight bits"),
            (0xC207, &[imm(-1)], "handler is unsigned"),
            (0xC307, &[imm(256)], "HBL's handler is eight bits"),
            // `HBLP` — `110001 imm5 handler`.
            (0xC7E0, &[imm(31)], "HBLP takes two operands"),
            (0xC7E0, &[imm(32), imm(0)], "imm5 holds 0..=31"),
            (0xC7E0, &[imm(31), imm(32)], "handler is five bits"),
            // `CHKA` — `11001010 N Rm Rn`, two registers, any of r0-r15.
            (0xCAFE, &[r0], "CHKA takes two operands"),
            (0xCAFE, &[r0, r0, r0], "CHKA takes two operands"),
            (0xCAFE, &[imm(0), r0], "Rn is a register"),
            (0xCAFE, &[r0, imm(0)], "Rm is a register"),
            // `LDR`/`STR` E1 — base `r9`, offsets 0..=252 in steps of four.
            (0xCC10, &[r0], "the frame forms take two operands"),
            (
                0xCC10,
                &[imm(0), frame(Reg(9), 8, true)],
                "Rt is a register",
            ),
            (
                0xCC10,
                &[Operand::Reg(Reg(8)), frame(Reg(9), 8, true)],
                "Rt is three bits",
            ),
            (0xCC10, &[r0, imm(8)], "the second operand is memory"),
            (0xCC10, &[r0, frame(Reg(1), 8, true)], "the base is r9"),
            (
                0xCC10,
                &[r0, frame(Reg(9), 256, true)],
                "imm6:'00' reaches 252",
            ),
            (
                0xCC10,
                &[r0, frame(Reg(9), 6, true)],
                "imm6:'00' is a multiple of four",
            ),
            (
                0xCC10,
                &[r0, frame(Reg(9), 8, false)],
                "no U bit to subtract with",
            ),
            (
                0xCE13,
                &[r0, frame(Reg(1), 8, true)],
                "STR's base is r9 too",
            ),
            // `LDR` E2 — base `r10`, offsets 0..=124.
            (
                0xCB08,
                &[r0, frame(Reg(9), 8, true)],
                "the pool base is r10",
            ),
            (
                0xCB08,
                &[r0, frame(Reg(10), 128, true)],
                "imm5:'00' reaches 124",
            ),
            // `LDR` E3 — a low base and a *subtracting* offset 0..=28.
            (0xC9D1, &[r0], "the array form takes two operands"),
            (0xC9D1, &[r0, r0], "the second operand is memory"),
            (
                0xC9D1,
                &[Operand::Reg(Reg(9)), frame(Reg(2), 28, false)],
                "Rt is three bits",
            ),
            (0xC9D1, &[r0, frame(Reg(9), 28, false)], "Rn is three bits"),
            (
                0xC9D1,
                &[r0, frame(Reg(2), 32, false)],
                "imm3:'00' reaches 28",
            ),
            (
                0xC9D1,
                &[r0, frame(Reg(2), 6, false)],
                "imm3:'00' is a multiple of four",
            ),
            (
                0xC9D1,
                &[r0, frame(Reg(2), 28, true)],
                "the array offset subtracts",
            ),
            (
                0xC9D1,
                &[r0, frame(Reg(2), 0, false)],
                "there is no #-0 here",
            ),
        ];
        for &(hw, operands, why) in cases {
            let base = dec(hw).expect("the base halfword decodes");
            let bad = Insn {
                operands: ops(operands),
                ..base
            };
            assert_eq!(encode(&bad), None, "`{bad}` from {hw:#06x}: {why}");
        }

        // A writeback or indexed memory operand is not a shape any of these
        // encodings has — there is no `P`/`W` bit and no `Rm` field in them.
        for mode in [
            AddrMode::PreIndex,
            AddrMode::PostIndex,
            AddrMode::PostIncrement,
        ] {
            let bad = Insn {
                operands: ops(&[
                    r0,
                    Operand::Mem(Mem {
                        base: Reg(9),
                        index: None,
                        offset: 8,
                        add: true,
                        align: 0,
                        mode,
                    }),
                ]),
                ..dec(0xCC10).unwrap()
            };
            assert_eq!(encode(&bad), None, "`{bad}` writes its base back");
        }
        let indexed = Insn {
            operands: ops(&[
                r0,
                Operand::Mem(Mem {
                    base: Reg(9),
                    index: Some((Reg(1), None)),
                    offset: 0,
                    add: true,
                    align: 0,
                    mode: AddrMode::Offset,
                }),
            ]),
            ..dec(0xCC10).unwrap()
        };
        assert_eq!(encode(&indexed), None, "no register index in chapter A9");
    }

    /// Printed UAL, one per A9.5 syntax line.
    ///
    /// Expected strings come from the manual's `Assembler syntax` sections,
    /// lower-cased to this crate's convention: immediates render through
    /// [`Operand`]'s `Display` (decimal below ten, hex above) and memory
    /// offsets through [`Mem`]'s (always decimal), which is why the two are
    /// spelled differently below.
    #[test]
    fn ual_text() {
        // CHKA<c><q> <Rn>, <Rm> — size first, index second.
        assert_eq!(dec(0xCA08).unwrap().to_string(), "chka r0, r1");
        // `N:Rn` reaches the high registers; A9-15 permits SP as <Rn>.
        assert_eq!(dec(0xCA9D).unwrap().to_string(), "chka sp, r3");

        // HB<c><q> #<HandlerID> / HBL<c><q> #<HandlerID>.
        assert_eq!(dec(0xC207).unwrap().to_string(), "hb #7");
        assert_eq!(dec(0xC2FF).unwrap().to_string(), "hb #0xff");
        assert_eq!(dec(0xC31F).unwrap().to_string(), "hbl #0x1f");

        // HBLP<c><q> #<imm>, #<HandlerID>.
        assert_eq!(dec(0xC443).unwrap().to_string(), "hblp #2, #3");

        // HBP<c><q> #<imm>, #<HandlerID>.
        assert_eq!(dec(0xC0FF).unwrap().to_string(), "hbp #7, #0x1f");

        // LDR<c><q> <Rt>, [R9{, #<imm>}] — 0 to 252 in steps of four.
        assert_eq!(dec(0xCC00).unwrap().to_string(), "ldr r0, [r9]");
        assert_eq!(dec(0xCDF8).unwrap().to_string(), "ldr r0, [r9, #252]");

        // LDR<c><q> <Rt>, [R10{, #<imm>}] — 0 to 124.
        assert_eq!(dec(0xCB00).unwrap().to_string(), "ldr r0, [r10]");
        assert_eq!(dec(0xCBFF).unwrap().to_string(), "ldr r7, [r10, #124]");

        // LDR<c><q> <Rt>, [<Rn>{, #-<imm>}] — -28 to 0, subtracting.
        assert_eq!(dec(0xC811).unwrap().to_string(), "ldr r1, [r2]");
        assert_eq!(dec(0xC9D1).unwrap().to_string(), "ldr r1, [r2, #-28]");

        // STR<c><q> <Rt>, [R9, #<imm>].
        assert_eq!(dec(0xCE13).unwrap().to_string(), "str r3, [r9, #8]");
        assert_eq!(dec(0xCFF8).unwrap().to_string(), "str r0, [r9, #252]");
    }

    /// Field extents, hand-computed from the encoding diagrams.
    #[test]
    fn field_extents() {
        // HBP: imm3 at [7:5], handler at [4:0].
        let hbp = dec(0xC0E1).unwrap();
        assert_eq!(hbp.operands.get(0), Some(Operand::Imm(7)));
        assert_eq!(hbp.operands.get(1), Some(Operand::Imm(1)));

        // HBLP: imm5 at [9:5], handler at [4:0]. 0xC7E0 = 110001 11111 00000.
        let hblp = dec(0xC7E0).unwrap();
        assert_eq!(hblp.operands.get(0), Some(Operand::Imm(31)));
        assert_eq!(hblp.operands.get(1), Some(Operand::Imm(0)));

        // CHKA: N at bit 7, Rm at [6:3], Rn at [2:0]. 0xCAFE => N=1, Rm=15,
        // Rn=6 => n = 0b1110 = lr, m = pc. Both UNPREDICTABLE (BadReg(m)) and
        // both still representable, so both decode.
        let chka = dec(0xCAFE).unwrap();
        assert_eq!(chka.operands.get(0), Some(Operand::Reg(Reg::LR)));
        assert_eq!(chka.operands.get(1), Some(Operand::Reg(Reg::PC)));
        assert_eq!(encode(&chka), Some(0xCAFE));

        // The `n == 15` corner, also UNPREDICTABLE: N=1, Rn=0b111.
        let chka_pc = dec(0xCA87).unwrap();
        assert_eq!(chka_pc.operands.get(0), Some(Operand::Reg(Reg::PC)));
        assert_eq!(encode(&chka_pc), Some(0xCA87));

        // Array LDR: every offset is a multiple of four in -28..=0.
        for imm3 in 0..8u16 {
            let i = dec(0xC800 | (imm3 << 6)).unwrap();
            // Searched for rather than indexed, so "this form has no memory
            // operand" is something the assertion can say.
            let m = i
                .operands
                .as_slice()
                .find_map(|o| match o {
                    Operand::Mem(m) => Some(m),
                    _ => None,
                })
                .expect("the array form carries a memory operand");
            // The magnitude is `imm3:'00'` and the direction is `add`, which
            // is `FALSE` for every non-zero offset and `TRUE` for the
            // directionless zero — this encoding has no `U` bit, so there is
            // no `#-0` for it to spell.
            assert_eq!(m.offset, 4 * u32::from(imm3));
            assert_eq!(m.displacement(), -4 * i64::from(imm3));
            assert_eq!(m.add, imm3 == 0);
            assert_eq!(m.base, Reg(0));
            assert_eq!(m.mode, AddrMode::Offset);
            assert!(m.index.is_none());
        }
    }

    /// No handler branch has a statically-resolvable target: the destination is
    /// `TEEHBR + handler:'00000'`, and `TEEHBR` is a system register this crate
    /// cannot see.
    ///
    /// `is_branch()` is deliberately not asserted — see the module docs for the
    /// gap in [`Insn::is_branch`]'s mnemonic set. What *is* asserted is that no
    /// [`Operand::Target`] is ever emitted, which is the part under this
    /// module's control.
    #[test]
    fn handler_branches_have_no_target() {
        for hw in 0xC000..=0xC7FFu16 {
            if let Some(i) = dec(hw) {
                assert_eq!(i.branch_target(), None, "{hw:#06x} ({i})");
                assert!(
                    !i.operands
                        .as_slice()
                        .any(|o| matches!(o, Operand::Target(_))),
                    "{hw:#06x} emitted a target"
                );
            }
        }
        // And `CHKA`, whose taken path also branches to a handler.
        for hw in 0xCA00..=0xCAFFu16 {
            assert_eq!(dec(hw).unwrap().branch_target(), None, "{hw:#06x}");
        }
    }

    /// `encode` rejects operand shapes the encodings cannot hold, rather than
    /// truncating them into a halfword that means something else.
    #[test]
    fn encode_rejects_unencodable() {
        let mut frame = dec(0xCC00).unwrap();
        // 252 is the last frame offset; 256 is past the end of `imm6`.
        frame.operands = [Operand::Reg(Reg(0)), mem(FRAME_BASE, true, 252)]
            .into_iter()
            .collect();
        assert_eq!(encode(&frame), Some(0xCDF8));
        frame.operands = [Operand::Reg(Reg(0)), mem(FRAME_BASE, true, 256)]
            .into_iter()
            .collect();
        assert_eq!(encode(&frame), None);
        // Unscaled offsets have no field to live in.
        frame.operands = [Operand::Reg(Reg(0)), mem(FRAME_BASE, true, 2)]
            .into_iter()
            .collect();
        assert_eq!(encode(&frame), None);
        // Subtracting offsets are E3's business, and E3 has no `r9` base.
        // `#-0` is unencodable anywhere in A9.5: no ThumbEE halfword has a `U`
        // bit for it to come from.
        frame.operands = [Operand::Reg(Reg(0)), mem(FRAME_BASE, false, 4)]
            .into_iter()
            .collect();
        assert_eq!(encode(&frame), None);
        frame.operands = [Operand::Reg(Reg(0)), mem(FRAME_BASE, false, 0)]
            .into_iter()
            .collect();
        assert_eq!(encode(&frame), None);
        // The base is hard-wired: an `r8`-based frame load is unencodable.
        frame.operands = [Operand::Reg(Reg(0)), mem(Reg(8), true, 4)]
            .into_iter()
            .collect();
        assert_eq!(encode(&frame), None);
        // The array form rejects a `#-0` too, for the same reason.
        let mut array = dec(0xC811).unwrap();
        array.operands = [Operand::Reg(Reg(1)), mem(Reg(2), false, 0)]
            .into_iter()
            .collect();
        assert_eq!(encode(&array), None);

        // Immediate fields are range-checked too.
        let mut hb = dec(0xC200).unwrap();
        hb.operands = core::iter::once(Operand::Imm(255)).collect();
        assert_eq!(encode(&hb), Some(0xC2FF));
        hb.operands = core::iter::once(Operand::Imm(256)).collect();
        assert_eq!(encode(&hb), None);
        hb.operands = core::iter::once(Operand::Imm(-1)).collect();
        assert_eq!(encode(&hb), None);

        // And a wide, or flag-setting, or width-suffixed instruction is never
        // one of ours whatever its mnemonic says.
        let mut wide = dec(0xCA08).unwrap();
        wide.width = Width::Wide;
        assert_eq!(encode(&wide), None);
        let mut flags = dec(0xCA08).unwrap();
        flags.sets_flags = true;
        assert_eq!(encode(&flags), None);

        // An unknown encoding name for a shared mnemonic is refused: this is
        // the guard that keeps `ldr` T1 out of ThumbEE's hands.
        let mut t1 = dec(0xCC00).unwrap();
        t1.encoding = "T1";
        assert_eq!(encode(&t1), None);
    }

    /// The dispatcher mechanism, end to end through the public [`Decoder`]:
    /// the same two bytes are an ordinary `LDM` in Thumb state and a ThumbEE
    /// frame load in ThumbEE state.
    #[test]
    fn decoder_flag_switches_the_map() {
        // 0xCC24 = 1100 1100 0010 0100.
        let image = [0x24, 0xCC];

        let plain = Decoder::new(&image).next().unwrap();
        assert_eq!(plain.mnemonic, "ldmia");
        assert_eq!(plain.to_string(), "ldmia r4!, {r2, r5}");

        let ee = Decoder::new(&image)
            .target(crate::isa::Target::ThumbEE)
            .next()
            .unwrap();
        assert_eq!(ee.mnemonic, "ldr");
        assert_eq!(ee.encoding, "E1");
        assert_eq!(ee.to_string(), "ldr r4, [r9, #16]");

        // A handler branch is a store-multiple to a Thumb-state decoder — the
        // mis-decode this flag exists to prevent.
        let hb_image = [0x07, 0xC2];
        assert_eq!(
            Decoder::new(&hb_image).next().unwrap().mnemonic,
            "stmia",
            "0xC207 is STM T1 in Thumb state"
        );
        let hb = Decoder::new(&hb_image)
            .target(crate::isa::Target::ThumbEE)
            .next()
            .unwrap();
        assert_eq!(hb.to_string(), "hb #7");

        // Outside the re-assigned space the flag changes nothing: `bx lr`
        // decodes identically either way.
        let bx = [0x70, 0x47];
        assert_eq!(
            Decoder::new(&bx).next().unwrap(),
            Decoder::new(&bx)
                .target(crate::isa::Target::ThumbEE)
                .next()
                .unwrap()
        );

        // The UNDEFINED row of Table A9-2, and the reason `owns` exists. This
        // module answers `None` for `0xC1C0` in both the "not mine" sense and
        // the "mine and undefined" sense, and only `owns` tells the dispatcher
        // which it is: inside the re-assigned range the `None` is final, so
        // ThumbEE state reports no instruction at all, while Thumb state still
        // decodes the `STM` the row holds there.
        let undef = [0xC0, 0xC1];
        assert!(dec(0xC1C0).is_none(), "0xC1C0 is not a ThumbEE encoding");
        assert!(owns(0xC1C0), "…but it is in the range ThumbEE re-assigns");
        assert_eq!(Decoder::new(&undef).next().unwrap().mnemonic, "stmia");
        assert_eq!(
            Decoder::new(&undef)
                .target(crate::isa::Target::ThumbEE)
                .next(),
            None,
            "A9.2.1's UNDEFINED row must not reappear as the Thumb encoding \
             ThumbEE replaced"
        );
    }

    /// [`owns`] and [`decode`] must agree: everything this module decodes is
    /// inside the range it claims, and everything outside that range it
    /// refuses.
    ///
    /// This is the invariant the dispatcher rests on. It reads `owns` to
    /// decide whether a `None` from `decode` means UNDEFINED or "not mine", so
    /// an `owns` narrower than `decode` would make a real ThumbEE instruction
    /// unreachable, and one wider than necessary would delete ordinary Thumb
    /// instructions — `non_interference` catches the first kind of drift, this
    /// catches the second.
    #[test]
    fn owns_agrees_with_decode() {
        let mut owned = 0usize;
        for hw in 0..=u16::MAX {
            if dec(hw).is_some() {
                assert!(owns(hw), "{hw:#06x} decoded but is not owned");
            }
            if owns(hw) {
                owned += 1;
                assert!(
                    (RANGE_LO..=RANGE_HI).contains(&hw),
                    "{hw:#06x} is owned but outside A9.2.1's range"
                );
            }
        }
        // The whole of Thumb's `11000x`/`11001x` block, and nothing else.
        assert_eq!(owned, 4096);
        // The owned halfwords `decode` refuses are exactly Table A9-2's hole.
        let undefined: Vec<u16> = (0..=u16::MAX)
            .filter(|&hw| owns(hw) && dec(hw).is_none())
            .collect();
        assert_eq!(undefined, (UNDEFINED_LO..=UNDEFINED_HI).collect::<Vec<_>>());
    }

    /// The dispatcher honours `owns` in both states, over the whole claimed
    /// range: in ThumbEE state every owned halfword decodes to this module's
    /// answer (or to nothing), and in Thumb state none of them does.
    #[test]
    fn dispatch_matches_state_over_the_whole_range() {
        for hw in RANGE_LO..=RANGE_HI {
            let ee = decode_halfwords(hw, 0, 0x1000, Target::ThumbEE);
            assert_eq!(ee, dec(hw), "{hw:#06x} in ThumbEE state");

            let plain = decode_halfwords(hw, 0, 0x1000, Target::Union);
            if let Some(i) = plain {
                assert!(
                    matches!(i.mnemonic, "stmia" | "ldmia"),
                    "{hw:#06x} is A5.2's STM/LDM in Thumb state, got {i}"
                );
            }
        }
    }

    /// Round-tripping through the crate's own [`crate::isa::encode`], which is
    /// what a consumer actually calls: the ThumbEE forms must survive being
    /// offered to every other narrow group first.
    #[test]
    fn round_trips_through_public_encode() {
        for hw in [
            0xC0FFu16, 0xC207, 0xC31F, 0xC443, 0xC811, 0xC9D1, 0xCA08, 0xCA9D, 0xCB7F, 0xCC00,
            0xCDF8, 0xCE13, 0xCFF8,
        ] {
            let i = decode_halfwords(hw, 0, 0x1000, Target::ThumbEE).unwrap();
            assert_eq!(crate::isa::encode(&i), Some((hw, 0)), "{hw:#06x} ({i})");
        }
    }
}
