//! The whole reverse-engineering loop, end to end: find something, corroborate
//! it, understand it, then redirect it and prove the bytes changed.
//!
//! Run with `cargo run --example patch_call_site`.
//!
//! The image below is synthetic, but the shape is the one every firmware
//! patching session has. There is a function you care about — call it the
//! *gate* — reached four different ways: by direct call, by tail call, through
//! a pointer stored in a dispatch table, and by an `adr` that materialises its
//! address into a register. Redirecting it means finding all four, deciding
//! which to patch, and patching each with the branch its site can survive.
//!
//! The step this example exists to make concrete is the second one. A firmware
//! image has no symbol table and no instruction boundaries marked anywhere, so
//! "who calls this function" is answered by scanning — and a scan at a fixed
//! stride is wrong in both directions (ARM DDI 0403E.e A5.1). `analysis::xrefs`
//! walks the stream instruction-accurately; the difference shows up here as a
//! call site that does not exist.

use thumb_asm::analysis::{self, Xref, XrefKind};
use thumb_asm::{
    encode_b_wide, encode_bl, find, find_bl_sites, install_branch, isa, read_u32, verify_branch,
    BranchKind, Needle,
};

/// The dispatch table: one 4-byte handler pointer, stored with the Thumb bit
/// set the way a pointer that will be reached by `blx` must be.
const TABLE: usize = 0x0080;
/// `bl gate` inside an ordinary function.
const CALL_A: usize = 0x1004;
/// A second `bl gate`.
const CALL_B: usize = 0x1044;
/// `b.w gate` — a tail call, so `lr` still belongs to the outer function.
const TAIL_CALL: usize = 0x1082;
/// A `tbb` and its branch table: data in the instruction stream, and the source
/// of the phantom call site below.
const JUMP_TABLE: usize = 0x1100;
/// `adr r0, gate` — the gate's address materialised into a register.
const ADR_SITE: usize = 0x11f0;
/// The function this example is about.
const GATE: u32 = 0x1200;
/// The replacement the call sites get redirected to.
const REPLACEMENT: u32 = 0x1300;

/// The signature: `ldr r0, [pc, #12]` followed by `cmp r0, #0x5a`. Two
/// instructions that load a configuration word and test it against a constant —
/// the sort of small, specific sequence a reverse engineer actually pins a
/// function with, because the constant is unlikely to recur by chance.
const SIGNATURE: [u8; 4] = [0x03, 0x48, 0x5a, 0x28];

fn main() {
    let mut image = build_image();

    println!("thumb-asm · redirecting a call site");
    println!("==================================\n");

    let (entry, policy) = locate(&image);
    let refs = who_references(&image, GATE);
    redirect(&mut image, &refs);
    confirm(&image);

    println!(
        "proved: a 4-byte signature resolved to the function entry at \
         {entry:#06x}, whose pc-relative load fetches {policy:#04x}; every \
         reference to it found instruction-accurately, including one a \
         fixed-stride scan reports and no processor will ever execute; and two \
         of those references repointed to {REPLACEMENT:#06x} with the branch \
         kind each site can survive, each verified by decoding the image back."
    );
}

// ---------------------------------------------------------------------------
// 1. find · 2. corroborate · 3. read
// ---------------------------------------------------------------------------

/// Signature → function entry → the constant the function actually loads.
fn locate(image: &[u8]) -> (usize, u32) {
    section("1. find the function");

    // `find` is the crate's one search primitive; `Needle::Bytes` is the
    // signature scan. It returns the offset of the match, and takes a `start`,
    // so a second call from just past the hit is how you prove the signature is
    // unique rather than merely present — which matters, because a signature
    // that matches twice has told you nothing.
    let hit = find(image, Needle::Bytes(&SIGNATURE), 0).expect("the signature is in the image");
    let again = find(image, Needle::Bytes(&SIGNATURE), hit + 1);
    println!("  signature {SIGNATURE:02x?}   (ldr r0, [pc, #12] · cmp r0, #0x5a)");
    println!("    first match  {hit:#06x}");
    println!("    next match   {}\n", maybe(again));
    assert_eq!(hit, 0x1202);
    assert_eq!(again, None);

    // A signature lands *inside* a function, never at its entry — the entry is
    // a prologue, and prologues are identical across every function in the
    // image, which is exactly why they make poor signatures. `function_start`
    // scans back for one.
    //
    // It is a heuristic and says so: a leaf function need not have a prologue
    // at all, and the backward scan steps by halfwords because nothing in the
    // Thumb encoding says where an instruction begins. So corroborate it — and
    // this example does, below, by showing the entry is also the target of a
    // `Call` xref.
    let entry = analysis::function_start(image, hit, 64).expect("a prologue within 64 bytes");
    println!("  function_start(image, {hit:#06x}, 64) -> {entry:#06x}");
    show(image, entry, entry as u32, 4);
    println!();
    assert_eq!(entry, GATE as usize);

    // The same call, from the handler pointer in the dispatch table. The
    // pointer is stored *odd* — bit 0 is the Thumb-state selector that
    // `bx`/`blx` reads (A4.1.1), not part of the address — and every address
    // comparison in `analysis` masks it off both sides, so a pointer read
    // straight out of a table can be passed as-is.
    let handler = read_u32(image, TABLE);
    let from_pointer = analysis::function_start(image, handler as usize, 64);
    println!("  dispatch table at {TABLE:#06x} holds {handler:#010x} (Thumb bit set)");
    println!(
        "  function_start(image, {handler:#06x}, 64) -> {}\n",
        maybe(from_pointer)
    );
    assert_eq!(handler, GATE | 1);
    assert_eq!(from_pointer, Some(GATE as usize));

    section("2. read what the function loads");

    // `ldr rt, [pc, #imm]` resolves against `Align(PC, 4)`, where Thumb's `PC`
    // reads as the instruction's address plus four (A7.7.44). At an address
    // that is 2 mod 4 the `Align` drops two bytes, so the hand-written
    // `(at + 4) + imm * 4` is off by two — silently, and only at every other
    // instruction. `literal_value` goes through the decoder, which has already
    // resolved the pool address, and reads the word there.
    let ldr = entry + 2;
    let policy = analysis::literal_value(image, ldr).expect("a pc-relative word load");
    println!("  {}", isa::disassemble(image, ldr, ldr as u32, 1)[0]);
    println!("  literal_value(image, {ldr:#06x}) -> {policy:#04x}");
    println!(
        "    the pool word lives at {:#06x} = Align({:#06x} + 4, 4) + 12\n",
        isa::decode_at(image, ldr)
            .and_then(|i| i.branch_target())
            .expect("the decoder resolves the pool address"),
        ldr,
    );
    assert_eq!(policy, 0x5a);
    assert_eq!(
        isa::decode_at(image, ldr).and_then(|i| i.branch_target()),
        Some(0x1210),
        "Align(0x1206, 4) is 0x1204, not 0x1206"
    );

    (entry, policy)
}

// ---------------------------------------------------------------------------
// 4. who references it
// ---------------------------------------------------------------------------

fn who_references(image: &[u8], target: u32) -> Vec<Xref> {
    section("3. every reference to it");

    let refs = analysis::xrefs(image, target);
    print_xrefs(image, &refs);

    // Four kinds, because an image names an address four ways and a rewriter
    // has to treat each differently. A `Call` expects control back; a `Branch`
    // does not, which is why a tail call landing in `Branch` is the truth about
    // the encoding rather than a classification error. A `LiteralPool` word is
    // data and is repointed by writing a word, not a branch. A
    // `PcRelativeAddress` puts the address in a register and what happens to it
    // next is not visible from here at all.
    let kinds: Vec<XrefKind> = refs.iter().map(|x| x.kind).collect();
    assert_eq!(
        kinds,
        [
            XrefKind::LiteralPool,       // 0x0080, the dispatch-table pointer
            XrefKind::Call,              // 0x1004, bl
            XrefKind::Call,              // 0x1044, bl
            XrefKind::Branch,            // 0x1082, b.w — a tail call
            XrefKind::PcRelativeAddress  // 0x11f0, adr
        ]
    );
    assert_eq!(refs[3].via, Some("b"), "a tail call is encoded as a branch");
    assert_eq!(
        refs[0].via, None,
        "a stored pointer is data and has no mnemonic"
    );

    // --- why this is a walk and not a scan ---

    // `find_bl_sites` tests `BL`'s bit pattern at every even offset, and its
    // own documentation admits the consequence. `BL`'s first halfword is only
    // constrained by `hw1[15:11] == 0b11110`, which one halfword in thirty-two
    // matches by chance — and the second halfword of a 32-bit instruction sits
    // at an even offset too.
    //
    // The image has a `tbb` at 0x1100 whose `hw2` is `0xf000`, followed by its
    // branch table. Read at the wrong phase those bytes are a perfectly
    // well-formed `bl 0x1200`. No processor will ever execute from 0x1102 — it
    // is the middle of a table branch — so a caller that "redirects" that call
    // site corrupts an unrelated instruction and changes no control flow at all.
    let scanned = find_bl_sites(image, target);
    let walked: Vec<usize> = refs
        .iter()
        .filter(|x| x.kind == XrefKind::Call)
        .map(|x| x.at)
        .collect();

    println!("  fixed-stride scan vs instruction-accurate walk");
    println!("  ----------------------------------------------");
    println!("    find_bl_sites -> {}", offsets(&scanned));
    println!("    xrefs (Call)  -> {}\n", offsets(&walked));
    for at in &scanned {
        if !walked.contains(at) {
            println!("    {at:#06x} is not an instruction boundary. In phase it reads:");
            show(image, JUMP_TABLE, JUMP_TABLE as u32, 2);
            println!("      …and out of phase, starting one halfword in:");
            println!("      {}", isa::disassemble(image, *at, *at as u32, 1)[0]);
            println!();
        }
    }

    assert_eq!(walked, [CALL_A, CALL_B]);
    assert_eq!(
        scanned,
        [CALL_A, CALL_B, JUMP_TABLE + 2],
        "the blind scan reports a third site"
    );
    // And the phantom is not merely extra — it is inside a real instruction.
    assert_eq!(
        isa::decode_at(image, JUMP_TABLE).map(|i| (i.mnemonic, i.len())),
        Some(("tbb", 4)),
        "0x1100..0x1104 is one instruction; 0x1102 is its second halfword"
    );

    refs
}

// ---------------------------------------------------------------------------
// 5. redirect
// ---------------------------------------------------------------------------

fn redirect(image: &mut [u8], refs: &[Xref]) {
    section("4. redirect two of them");

    // The direct call. `install_branch` is the whole install-a-detour pattern
    // in one call: encode, write, and decode the image back to confirm the
    // bytes now mean what was asked for. It writes nothing when the
    // displacement is out of range, odd, or past the end of the image.
    //
    // A `BL` is right here because the site is a call inside a function: the
    // replacement is expected to return, and `lr` is the caller's to clobber.
    let call = refs
        .iter()
        .find(|x| x.kind == XrefKind::Call)
        .expect("at least one direct call");
    let before = isa::disassemble(image, call.at, call.at as u32, 1)[0].clone();
    install_branch(image, call.at, BranchKind::Bl, REPLACEMENT | 1)
        .expect("a 4-byte site well within ±16 MB");
    println!("  {:#06x}  {before}", call.at);
    println!(
        "            -> {}\n",
        isa::disassemble(image, call.at, call.at as u32, 1)[0]
    );

    // `REPLACEMENT | 1` was passed with the Thumb bit set, and the decoded
    // target comes back even: a `BL` displacement is halfword-aligned and has
    // nowhere to put bit 0, so `install_branch` masks it and `verify_branch`
    // masks both sides before comparing.
    assert!(verify_branch(image, call.at, BranchKind::Bl, REPLACEMENT).is_ok());
    assert!(verify_branch(image, call.at, BranchKind::Bl, REPLACEMENT | 1).is_ok());

    // The tail call, and the reason it needs a different branch kind.
    //
    // At a tail-call site `lr` still holds the *outer* function's return
    // address, and the callee's `bx lr` is what returns through it. Installing
    // a `BL` here would set `lr` to `site + 4` — an address inside the outer
    // function — so the callee would return into the middle of the function
    // that tail-called it, running code the original firmware never reaches on
    // that path. `B.W` (T4) is the same four bytes and the same ±16 MB range
    // and differs only in bit 14 of `hw2`; it does not write `lr`.
    let tail = refs
        .iter()
        .find(|x| x.kind == XrefKind::Branch)
        .expect("the tail call");
    let before = isa::disassemble(image, tail.at, tail.at as u32, 1)[0].clone();
    install_branch(image, tail.at, BranchKind::BWide, REPLACEMENT).expect("same width, same range");
    println!("  {:#06x}  {before}", tail.at);
    println!(
        "            -> {}   (b.w, not bl: lr is the outer function's)\n",
        isa::disassemble(image, tail.at, tail.at as u32, 1)[0]
    );

    // The two encodings really are one bit apart, and that bit is the whole
    // difference between "returns here" and "returns to my caller".
    let as_bl = encode_bl(tail.at, REPLACEMENT).expect("in range");
    let as_bw = encode_b_wide(tail.at, REPLACEMENT).expect("in range");
    assert_eq!(as_bl[0..2], as_bw[0..2], "hw1 is identical");
    assert_eq!(
        u16::from_le_bytes([as_bl[2], as_bl[3]]) ^ u16::from_le_bytes([as_bw[2], as_bw[3]]),
        0x4000,
        "hw2 differs in bit 14 and nothing else"
    );
    assert!(verify_branch(image, tail.at, BranchKind::BWide, REPLACEMENT).is_ok());

    // Asking the wrong question at a patched site gets a definite `None`
    // rather than a plausible-looking answer: a `b.w` is not a `bl`, and
    // `verify_branch` says so instead of decoding one as the other.
    let wrong = verify_branch(image, tail.at, BranchKind::Bl, REPLACEMENT).unwrap_err();
    assert_eq!(wrong.found, None);

    // The dispatch-table pointer and the `adr` are deliberately left alone.
    // Repointing the table is a word write, not a branch, and repointing the
    // `adr` would need the replacement to sit within 1020 bytes of it — both
    // are real work with their own failure modes, and neither is a call site.
    println!("  left alone: the dispatch-table word at {TABLE:#06x} (data, not a branch)");
    println!("              the `adr` at {ADR_SITE:#06x} (±1020 bytes of Align(PC,4))\n");
}

// ---------------------------------------------------------------------------
// 6. confirm
// ---------------------------------------------------------------------------

fn confirm(image: &[u8]) {
    section("5. confirm, by reading the image back");

    let old = analysis::xrefs(image, GATE);
    let new = analysis::xrefs(image, REPLACEMENT);

    println!("  references to the gate at {GATE:#06x}:");
    print_xrefs(image, &old);
    println!("  references to the replacement at {REPLACEMENT:#06x}:");
    print_xrefs(image, &new);

    // The direct call and the tail call moved; the stored pointer, the second
    // call and the `adr` did not.
    assert_eq!(
        old.iter().map(|x| (x.at, x.kind)).collect::<Vec<_>>(),
        [
            (TABLE, XrefKind::LiteralPool),
            (CALL_B, XrefKind::Call),
            (ADR_SITE, XrefKind::PcRelativeAddress),
        ]
    );
    assert_eq!(
        new.iter().map(|x| (x.at, x.kind)).collect::<Vec<_>>(),
        [(CALL_A, XrefKind::Call), (TAIL_CALL, XrefKind::Branch)]
    );

    // The phantom is still there, because nothing about it was ever real: it is
    // the second halfword of the `tbb`, which no patch touched.
    assert_eq!(find_bl_sites(image, GATE), [CALL_B, JUMP_TABLE + 2]);
    println!();
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn section(title: &str) {
    println!("{title}");
    println!("{}\n", "-".repeat(title.chars().count()));
}

/// An optional offset, on one line.
fn maybe(o: Option<usize>) -> String {
    match o {
        Some(v) => format!("{v:#06x}"),
        None => "none".to_string(),
    }
}

/// A list of offsets, on one line: `[0x1004, 0x1044]`.
fn offsets(v: &[usize]) -> String {
    if v.is_empty() {
        return "none".to_string();
    }
    let items: Vec<String> = v.iter().map(|o| format!("{o:#06x}")).collect();
    format!("[{}]", items.join(", "))
}

fn show(image: &[u8], at: usize, addr: u32, count: usize) {
    for line in isa::disassemble(image, at, addr, count) {
        println!("      {line}");
    }
}

fn print_xrefs(image: &[u8], refs: &[Xref]) {
    println!("    offset    kind                via    what is there");
    println!("    --------  ------------------  -----  --------------------------");
    for x in refs {
        let what = match x.kind {
            // A pool word is data: rendering it as an instruction would be a
            // guess, so print the word.
            XrefKind::LiteralPool => format!(".word {:#010x}", read_u32(image, x.at)),
            _ => isa::decode_at(image, x.at)
                .map(|i| i.to_string())
                .unwrap_or_else(|| "?".to_string()),
        };
        println!(
            "    {:08x}  {:<18}  {:<5}  {}",
            x.at,
            format!("{:?}", x.kind),
            x.via.unwrap_or("-"),
            what
        );
    }
    println!();
}

// ---------------------------------------------------------------------------
// the synthetic image
// ---------------------------------------------------------------------------

/// A flat image, zero-filled, with a handful of hand-assembled functions.
///
/// Zero is `movs r0, r0` — `MOV (register)` T2 (A7.7.77) — not a hole, which is
/// why `analysis::nop_fill` exists for blanking code. Here it is harmless
/// filler that keeps the whole image decodable at a 2-byte cadence, so the one
/// place the instruction stream goes out of phase is the one this example
/// builds on purpose.
fn build_image() -> Vec<u8> {
    let mut image = vec![0u8; 0x4000];

    // The dispatch table's handler pointer: the gate, stored odd.
    thumb_asm::write(&mut image, TABLE, &(GATE | 1).to_le_bytes());

    // 0x1000 — an ordinary caller.
    put(&mut image, 0x1000, &[0xb510, 0x2000]); // push {r4, lr} · movs r0, #0
    bl(&mut image, CALL_A, GATE);
    put(&mut image, 0x1008, &[0xbd10]); // pop {r4, pc}

    // 0x1040 — a second caller, left unpatched so the "before" and "after"
    // xref listings differ by exactly the edges this example moves.
    put(&mut image, 0x1040, &[0xb510, 0x2001]);
    bl(&mut image, CALL_B, GATE);
    put(&mut image, 0x1048, &[0xbd10]);

    // 0x1080 — a tail call: set up an argument and *jump*, so the gate's return
    // goes to this function's caller.
    put(&mut image, 0x1080, &[0x2002]); // movs r0, #2
    thumb_asm::write(
        &mut image,
        TAIL_CALL,
        &encode_b_wide(TAIL_CALL, GATE).expect("in range"),
    );

    // 0x1100 — `tbb [r3, r0]`, `1110 1000 1101 Rn · 1111 0000 000H Rm`
    // (A7.7.185), followed by its byte table. A table branch is the canonical
    // "data immediately after an instruction" shape, and the two halfwords
    // written here are chosen so that reading them one halfword out of phase
    // gives `0xf000 0xf87d` — a well-formed `bl 0x1200`.
    //
    // Nothing is smuggled in: those are exactly the bytes `encode_bl` produces
    // for that site and target, which the assertion below states outright.
    put(&mut image, JUMP_TABLE, &[0xe8d3, 0xf000]);
    put(&mut image, JUMP_TABLE + 4, &[0xf87d]);
    assert_eq!(
        encode_bl(JUMP_TABLE + 2, GATE).expect("in range"),
        image[JUMP_TABLE + 2..JUMP_TABLE + 6],
        "the phantom is a real BL encoding at an address that is not one"
    );

    // 0x11f0 — `adr r0, gate`, i.e. `ADD (PC plus immediate)` T1,
    // `1010 0 Rd imm8` (A7.7.7), whose target is `Align(PC, 4) + imm8 * 4` =
    // `Align(0x11f4, 4) + 12` = 0x1200. The `Align` is why `imm8` is 3 and not
    // some function of `0x11f0` directly.
    put(&mut image, ADR_SITE, &[0xa003, 0x4770]); // adr r0, 0x1200 · bx lr

    // 0x1200 — the gate. Loads a policy word, compares it against 0x5a, and
    // returns 1 or 0.
    put(
        &mut image,
        GATE as usize,
        &[
            0xb510, // push {r4, lr}       A7.7.99  PUSH T1
            0x4803, // ldr r0, [pc, #12]   A7.7.44  LDR (literal) T1 -> 0x1210
            0x285a, // cmp r0, #0x5a       A7.7.27  CMP (immediate) T1
            0xd001, // beq 0x120c          A7.7.12  B T1
            0x2001, // movs r0, #1
            0xbd10, // pop {r4, pc}
            0x2000, // movs r0, #0
            0xbd10, // pop {r4, pc}
        ],
    );
    // The literal pool, 4-aligned, immediately after the code — the layout
    // `Asm::finish` also produces.
    thumb_asm::write(&mut image, 0x1210, &0x5au32.to_le_bytes());

    // 0x1300 — the replacement.
    put(&mut image, REPLACEMENT as usize, &[0xb510, 0x2000, 0xbd10]);

    image
}

fn bl(image: &mut [u8], at: usize, target: u32) {
    thumb_asm::write(image, at, &encode_bl(at, target).expect("in range"));
}

/// Write consecutive little-endian halfwords at `at`.
fn put(image: &mut [u8], at: usize, halfwords: &[u16]) {
    for (i, hw) in halfwords.iter().enumerate() {
        thumb_asm::write(image, at + i * 2, &hw.to_le_bytes());
    }
}
