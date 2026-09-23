//! Walking a Thumb instruction stream with `thumb_asm::isa::Decoder`.
//!
//! Run with `cargo run --example disassemble`.
//!
//! A firmware image is not a list of instructions, it is a bag of halfwords
//! with code in it. Three things separate a decoder you can build a patcher on
//! from a loop that reads two bytes at a time, and this example builds a small
//! function that exercises all three:
//!
//! 1. **Length.** `hw1[15:11]` is the whole of Thumb's length rule
//!    (ARM DDI 0403E.e A5.1). Get it wrong once and every subsequent halfword
//!    is read at the wrong phase.
//! 2. **`ITSTATE`.** The 1–4 instructions after an `IT` are conditional with
//!    nothing in their own encoding to say so (A7.3.2). A decoder that does not
//!    track the state reports them as unconditional — silently, about control
//!    flow.
//! 3. **Resynchronisation.** Real images have data between instructions. A
//!    disassembler that stops at the first halfword it cannot explain is of no
//!    use on one.

use thumb_asm::isa::{self, Decoder, Insn};
use thumb_asm::{Asm, Cond};

/// Where the function is assumed to live. Everything in this crate maps file
/// offset to load address 1:1, so this is both.
const BASE: u32 = 0x1000;

fn main() {
    let (image, code_len) = build_function();

    println!("thumb-asm · decoding a Thumb stream");
    println!("===================================\n");
    println!("{code_len} bytes of code assembled with `Asm`, loaded at {BASE:#06x}.\n");

    // --- 1. the walk ------------------------------------------------------

    let walk = disassemble(&image, BASE as usize, code_len);

    println!("  address    bytes          disassembly");
    println!("  ---------  -------------  --------------------------------");
    for step in &walk {
        println!("  {:08x}   {:<13}  {}", step.addr, step.bytes, step.text());
    }
    println!();

    let decoded: Vec<&Insn> = walk.iter().filter_map(|s| s.insn.as_ref()).collect();
    let undefined = walk.len() - decoded.len();

    // The count is the load-bearing assertion of this example: it can only be
    // right if the length rule, the IT tracking and the resynchronisation are
    // all right at once. Nine instructions and two halfwords of data.
    assert_eq!(decoded.len(), 9, "instructions decoded");
    assert_eq!(undefined, 2, "halfwords resynchronised past");
    assert_eq!(
        walk.iter().map(|s| s.len).sum::<usize>(),
        code_len,
        "the walk covers the code exactly, with no byte read twice or skipped"
    );

    // --- 2. length keeps the walk in phase --------------------------------

    // `movw r7, #0x470` is `f2 40 70 47`, and its *second halfword* is `47 70`
    // — the bytes of `bx lr`. A scan that reads a halfword every two bytes
    // finds a function return in the middle of a move, at an offset no
    // processor will ever execute from, and a caller that patches there
    // corrupts the move.
    let movw = decoded[4];
    let phantom = movw.addr as usize + 2;
    assert_eq!((movw.mnemonic, movw.len()), ("movw", 4));
    assert_eq!(isa::insn_len(0xf240), 4, "A5.1: 0b11110 means four bytes");
    assert_eq!(isa::insn_len(0x4770), 2);

    println!("instruction length (A5.1)");
    println!("-------------------------");
    println!(
        "  {:08x}   {:<13}  {:<20}  four bytes, so the next stop is {:08x}",
        movw.addr,
        hex(&image, movw.addr as usize, 4),
        movw.to_string(),
        movw.addr as usize + movw.len()
    );
    println!(
        "  {phantom:08x}   {:<13}  {:<20}  what a fixed two-byte stride reads there",
        hex(&image, phantom, 2),
        isa::decode_at(&image, phantom)
            .expect("the phantom decodes; that is the problem")
            .to_string(),
    );
    println!();

    assert_eq!(
        isa::decode_at(&image, phantom).map(|i| i.mnemonic),
        Some("bx"),
        "the phantom really is there in the bytes"
    );
    assert!(
        !walk.iter().any(|s| s.addr as usize == phantom),
        "the decoder must never arrive at an offset that is not an instruction boundary"
    );

    // --- 3. an IT block makes the next instructions conditional -----------

    // `ite eq` governs two instructions: the `T` arm on EQ, the `E` arm on the
    // *inverted* condition. Neither carries a condition in its own encoding, so
    // this is visible only to a decoder that tracks `ITSTATE` (A7.3.2) — which
    // `Decoder` does and the stateless `isa::decode_at` deliberately does not.
    let then_arm = decoded[6];
    let else_arm = decoded[7];

    println!("IT blocks (A7.3.2)");
    println!("------------------");
    println!("  address    bytes          Decoder (tracks IT)   decode_at (stateless)",);
    println!("  ---------  -------------  --------------------  ---------------------");
    for insn in [decoded[5], then_arm, else_arm] {
        let stateless =
            isa::decode_at(&image, insn.addr as usize).expect("same bytes, no IT state");
        println!(
            "  {:08x}   {:<13}  {:<20}  {}",
            insn.addr,
            hex(&image, insn.addr as usize, insn.len()),
            insn.to_string(),
            stateless
        );
    }
    println!();

    assert_eq!(then_arm.cond, Some(Cond::Eq), "the ITT arm runs on EQ");
    assert_eq!(
        else_arm.cond,
        Some(Cond::Ne),
        "ITAdvance() shifts ITSTATE<4:0> across the cond/mask boundary, so the \
         E arm runs on the inverted condition"
    );
    assert_eq!(then_arm.to_string(), "moveq r0, #1");
    assert_eq!(else_arm.to_string(), "movne r0, #2");
    // Not `movseq`: almost every narrow data-processing encoding specifies
    // `setflags = !InITBlock()`, so the same halfword is `movs` outside a block
    // and `mov<cond>` inside one. The stateless decode cannot know which.
    assert!(!then_arm.sets_flags);
    assert!(
        isa::decode_at(&image, then_arm.addr as usize)
            .expect("decodes")
            .sets_flags,
        "the bytes alone say `movs`; only the enclosing IT says otherwise"
    );

    // --- 4. undefined halfwords resynchronise -----------------------------

    // `0x4500` is `CMP (register)` T2 with both registers low, which A7.7.28
    // makes UNPREDICTABLE — so this crate refuses it rather than inventing a
    // disassembly for it. Whatever the four bytes are (a table entry, a
    // checksum, a pointer), the walk steps over them a halfword at a time and
    // picks the instruction stream back up, exactly as `isa::disassemble` does.
    let data: Vec<&Step> = walk.iter().filter(|s| s.insn.is_none()).collect();
    println!("resynchronisation");
    println!("-----------------");
    for step in &data {
        println!("  {:08x}   {:<13}  {}", step.addr, step.bytes, step.text());
    }
    let after = walk.last().expect("the walk is not empty");
    println!(
        "  {:08x}   {:<13}  {}   <- back in phase\n",
        after.addr,
        after.bytes,
        after.text()
    );

    assert_eq!(data.len(), 2);
    assert_eq!(data[0].addr + 2, data[1].addr, "one halfword at a time");
    assert_eq!(
        after.insn.as_ref().map(|i| i.mnemonic),
        Some("pop"),
        "the instruction after the data still decodes"
    );

    // `isa::disassemble` is the same walk, packaged: it renders an undefined
    // halfword as `.short` and carries on. Agreeing with it is the check that
    // this example is using the library rather than reimplementing it.
    let packaged = isa::disassemble(&image, BASE as usize, BASE, walk.len());
    assert_eq!(packaged.len(), walk.len());
    assert!(packaged[0].ends_with("push {r4, lr}"));

    println!(
        "proved: {} instructions and {undefined} halfwords of data over {code_len} bytes — \
         the length rule kept the walk in phase past a `bx lr` that is not one, \
         `ITSTATE` supplied the conditions on `{}` and `{}`, and undefined bytes \
         resynchronised instead of halting the walk.",
        decoded.len(),
        then_arm,
        else_arm,
    );
}

/// One stop of the walk: an instruction, or a halfword that is not one.
struct Step {
    addr: u32,
    len: usize,
    bytes: String,
    /// The leading halfword, kept so an undefined stop can still be named.
    hw1: u16,
    insn: Option<Insn>,
}

impl Step {
    fn text(&self) -> String {
        match &self.insn {
            Some(i) => i.to_string(),
            // What `isa::disassemble` emits, and the right rendering: naming
            // the halfword is a fact, naming an instruction would be a guess.
            None => format!(".short {:#06x}", self.hw1),
        }
    }
}

/// Walk `count` bytes of `image` from `at`, recording every stop.
///
/// This is `isa::disassemble`'s loop, spelled out so the example can show what
/// each stop cost in bytes. A consumer that only wants the text should call
/// `isa::disassemble`.
fn disassemble(image: &[u8], at: usize, len: usize) -> Vec<Step> {
    let end = at + len;
    let mut out = Vec::new();
    let mut d = Decoder::at(image, at, at as u32);
    while d.pos() + 2 <= end {
        let pos = d.pos();
        match d.next() {
            Some(insn) => {
                out.push(Step {
                    addr: insn.addr,
                    len: insn.len(),
                    bytes: hex(image, pos, insn.len()),
                    hw1: u16::from_le_bytes([image[pos], image[pos + 1]]),
                    insn: Some(insn),
                });
            }
            None => {
                out.push(Step {
                    addr: pos as u32,
                    len: 2,
                    bytes: hex(image, pos, 2),
                    hw1: u16::from_le_bytes([image[pos], image[pos + 1]]),
                    insn: None,
                });
                // Spelled as an associated function on purpose: `Decoder` is an
                // `Iterator`, so `d.skip(2)` resolves to the by-value
                // `Iterator::skip` adaptor, which consumes the decoder.
                Decoder::skip(&mut d, 2);
            }
        }
    }
    out
}

fn hex(image: &[u8], at: usize, len: usize) -> String {
    image[at..at + len]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Assemble the function and load it at [`BASE`]. Returns the image and the
/// length of the code, so the walk knows where the trailing literal pool — data,
/// not instructions — begins.
fn build_function() -> (Vec<u8>, usize) {
    let mut asm = Asm::new();
    let done = asm.label();

    // A compiler-shaped prologue. `push {r4, lr}` is what `analysis::function_start`
    // looks for (A7.7.99 `PUSH` T1: `1011 0101 register_list`, the `lr` bit being
    // what makes it a prologue rather than an ordinary register save).
    asm.push(0x110); // push {r4, lr} — bit 8 is lr, bit 4 is r4
    asm.ldr_lit(0, 0x2000_0001); // ldr r0, [pc, #n] — pool laid out by `finish`
    asm.cmp_imm(0, 0);
    asm.beq(done);

    // A 32-bit instruction whose second halfword is `47 70`, the bytes of
    // `bx lr`. `MOVW` T3 is `11110 i 100100 imm4 · 0 imm3 Rd imm8` (A7.7.76):
    // `imm3 = 0b100`, `Rd = r7`, `imm8 = 0x70` put `0x4770` in `hw2`. Nothing is
    // contrived about the collision — `hw2` of a wide instruction is
    // unconstrained, so any 16-bit encoding can appear there.
    asm.raw16(0xf240);
    asm.raw16(0x4770);

    // `ITE EQ` — `IT` T1, `1011 1111 firstcond mask` with `firstcond = 0b0000`
    // (EQ) and `mask = 0b1100` (A7.7.38). Two governed instructions, the second
    // on the inverted condition. `Asm` has no `it` helper, which is the honest
    // answer for an assembler this small: `raw16` is how you say a halfword it
    // does not model.
    asm.raw16(0xbf0c); // ite eq
    asm.raw16(0x2001); // movs r0, #1  -> `moveq r0, #1` inside the block
    asm.raw16(0x2002); // movs r0, #2  -> `movne r0, #2`, the E arm

    // Four bytes of data inlined in the code stream, which is the ordinary
    // shape of a firmware image, not an exotic one. `0x4500` is `CMP (register)`
    // T2 with `n < 8 && m < 8`, which A7.7.28 makes UNPREDICTABLE — so it has no
    // disassembly and the walk has to step over it.
    asm.raw16(0x4500);
    asm.raw16(0x4500);

    asm.bind(done);
    asm.pop(0x110); // pop {r4, pc}

    // Everything above is code; `finish` appends the 4-byte-aligned literal
    // pool after it. The pool is data and is deliberately outside the walk —
    // `0x2000_0001` would otherwise disassemble as two plausible instructions,
    // which is a true fact about the bytes and a misleading one about the
    // function.
    let code_len = asm.pos();
    let code = asm
        .finish()
        .expect("small, self-contained, always in range");

    let mut image = vec![0u8; 0x4000];
    // `Asm::finish` lays its pool out against `Align(PC, 4)` relative to the
    // start of the buffer, so the buffer has to land 4-aligned or every literal
    // load in it reads the wrong word. `BASE` is 4-aligned.
    assert_eq!(BASE % 4, 0);
    thumb_asm::write(&mut image, BASE as usize, &code);
    (image, code_len)
}
