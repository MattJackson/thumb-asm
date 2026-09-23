//! Installing a detour over live code with `thumb_asm::detour`, and — just as
//! important — watching it refuse.
//!
//! Run with `cargo run --example detour`.
//!
//! Patching a four-byte branch over an arbitrary address is the operation every
//! firmware patcher writes first and every firmware patcher gets wrong. The
//! branch cuts an instruction in half, or moves one out from under its `IT`, or
//! relocates a pc-relative instruction as a byte copy, or half-applies and
//! leaves an image that is corrupt *and* reported as unpatched. All four are
//! silent. `detour` decodes the site first, so the displaced region is a whole
//! number of instructions by construction; it tracks `ITSTATE`, so it can see
//! the second failure; it relocates through `thumb_asm::relocate`, so it can
//! see the third; and every fallible step happens before the first byte is
//! written, so the fourth cannot happen.
//!
//! The refusals are the feature. A detour that installs is a detour you can
//! test; a detour that refuses is one you never had to unbrick a device to find
//! out about.

use thumb_asm::detour::{detour, tramp, Convention, Detour, DetourError, DetourOptions};
use thumb_asm::relocate::RelocateError;
use thumb_asm::{decode_b_wide, decode_bl, isa, read_u32, verify_branch, BranchKind};

/// Live code lives below this; erased (`0xff`) flash above it. `detour`'s
/// free-space search only knows about runs of `0xff`, which is what an erased
/// flash sector reads as.
const FLASH_FREE: usize = 0x2000;

/// Ordinary function, detoured at its entry.
const LED_SET: usize = 0x1000;
/// A tail call — `movs` then `b.w` into a shared leaf, with `lr` still holding
/// the *outer* function's return address.
const TAIL_SITE: usize = 0x1102;
/// A function whose first instruction is a `cbz`.
const CBZ_FN: usize = 0x1300;
/// A function whose first instruction is an `ite`.
const IT_FN: usize = 0x1400;
/// Two hook functions, addressed with the Thumb bit set, as a function pointer
/// carries it.
const HOOK_A: u32 = 0x1801;
const HOOK_B: u32 = 0x1881;

fn main() {
    let mut image = build_image();
    let pristine = image.clone();

    println!("thumb-asm · installing a detour");
    println!("==============================\n");
    println!(
        "A {:#x}-byte image: code below {FLASH_FREE:#x}, erased flash above it.\n",
        image.len()
    );

    ordinary_detour(&mut image);
    tail_call_detour(&mut image);
    refusals(&mut image);
    the_blind_spot(&pristine);

    println!(
        "proved: two detours installed and readable back out of the bytes, two \
         refused for a named reason with the image left byte-identical, and one \
         site that is only refusable when `scan_from` says where the function \
         begins."
    );
}

// ---------------------------------------------------------------------------
// 1. The ordinary detour
// ---------------------------------------------------------------------------

fn ordinary_detour(image: &mut [u8]) {
    section("1. the ordinary detour — `tramp(image, site, hook)`");

    println!("  before, at the site:");
    show(image, LED_SET, LED_SET as u32, 4);

    // `tramp` is `detour` with the defaults: a `BL` at the site, and
    // call-then-continue, so the hook is an ordinary function that is called,
    // returns, and lets the original code run exactly as it would have.
    //
    // `HOOK_A` has bit 0 set. `detour` masks it off, because a `BL`'s
    // displacement is halfword-aligned and has no room for the Thumb bit —
    // which means a function pointer read straight out of a vector table can
    // be handed over as-is.
    let d = tramp(image, LED_SET, HOOK_A).expect("a 4-byte site and free flash above it");

    println!("\n  after, at the site:");
    show(image, LED_SET, LED_SET as u32, 3);
    println!("\n  the stub, in erased flash at {:#06x}:", d.stub);
    show(image, d.stub as usize, d.stub, 4);
    println!();
    describe(&d);

    // What the four bytes at the site now are, read back *out of the image*
    // rather than out of the return value.
    assert_eq!(decode_bl(image, LED_SET), Some(d.stub));
    assert!(verify_branch(image, d.site, d.kind, d.stub).is_ok());

    // Two 16-bit instructions were displaced, not "four bytes". The distinction
    // is the whole point: had the site held a 16-bit instruction followed by a
    // 32-bit one, `displaced` would be 6, and a blind four-byte patch would
    // have left the tail halfword of the second behind as rubble.
    assert_eq!((d.displaced, d.stub, d.stub_len), (4, 0x2000, 12));
    assert_eq!(d.resume(), (LED_SET + 4) as u32);
    assert_eq!(d.kind, BranchKind::Bl);

    // The stub, in full. `bl` to the hook, the displaced prologue re-executed
    // at its new address, then back to the instruction after the hook branch.
    assert_eq!(
        isa::disassemble(image, d.stub as usize, d.stub, 4),
        [
            "00002000: bl 0x1800",
            "00002004: push {r4, lr}",
            "00002006: movs r0, #1",
            "00002008: b.w 0x1004",
        ]
    );
    // The tail branch lands on the first byte the hook branch did *not*
    // overwrite, which is what makes the patch transparent to the rest of the
    // function.
    assert_eq!(decode_b_wide(image, d.stub as usize + 8), Some(d.resume()));
}

// ---------------------------------------------------------------------------
// 2. A tail call, where the branch kind and the convention both matter
// ---------------------------------------------------------------------------

fn tail_call_detour(image: &mut [u8]) {
    section("2. a tail-call site — `BranchKind::BWide` + `Convention::HookDecides`");

    println!("  before, at the site:");
    show(image, TAIL_SITE - 2, (TAIL_SITE - 2) as u32, 2);
    println!();

    // Two choices, and both are forced by what the site is.
    //
    // `BranchKind::BWide` rather than `Bl`: at a tail call, `lr` still holds
    // the *outer* function's return address, and the shared leaf's `bx lr` is
    // what returns through it. A `bl` installed here would overwrite `lr` with
    // `site + 4`, so the leaf's `bx lr` would land back inside the outer
    // function instead of at its caller — running code the original firmware
    // never reaches on that path. `B.W` (T4) has the same 4-byte width and the
    // same ±16 MB range as `BL` (T1) and differs only in bit 14 of `hw2`; it
    // does not write `lr`.
    //
    // `Convention::HookDecides` rather than `CallThenContinue`: a gate whose
    // answer can be "deny" has to be able to *skip* the original, which
    // call-then-continue cannot express. The stub loads the continuation
    // address into `r12` and jumps to the hook, so the hook may `bx r12` to run
    // the original or `bx lr` to return from the outer function without it.
    // Pairing this convention with `Bl` would be the trap the `Convention` docs
    // call out: the site's own `bl` would have destroyed the `lr` the hook
    // needs.
    let opts = DetourOptions::new()
        .with_kind(BranchKind::BWide)
        .with_convention(Convention::HookDecides);
    let d = detour(image, TAIL_SITE, HOOK_B, opts).expect("still room in erased flash");

    println!("  after, at the site:");
    show(image, TAIL_SITE - 2, (TAIL_SITE - 2) as u32, 2);
    println!("\n  the stub at {:#06x}:", d.stub);
    show(image, d.stub as usize, d.stub, 2);
    println!(
        "  {:08x}: .word {:#010x}        <- continuation, Thumb bit set",
        d.stub + 8,
        read_u32(image, d.stub as usize + 8)
    );
    show(image, d.stub as usize + 12, d.stub + 12, 3);
    println!();
    describe(&d);

    assert_eq!(d.kind, BranchKind::BWide);
    assert_eq!(decode_b_wide(image, TAIL_SITE), Some(d.stub));
    // No `bl` decodes at the site, which is the machine-checkable form of "`lr`
    // was not clobbered".
    assert_eq!(decode_bl(image, TAIL_SITE), None);

    // The continuation word is the address of the displaced code with bit 0
    // **set**: the hook reaches it with `bx r12`, and `BXWritePC` reads bit 0
    // as the instruction-set selector (A4.1.1). A clear bit 0 would request ARM
    // state — a UsageFault on an M-profile core.
    let continuation = read_u32(image, d.stub as usize + 8);
    assert_eq!(continuation & 1, 1, "Thumb bit set on the continuation");

    // Two bytes of `nop` sit between the continuation word and the displaced
    // code. They are not filler: `Align(PC, 4)` is the base of every
    // pc-relative literal access (A7.7.44) and steps in fours while an
    // instruction address steps in twos, so a displaced literal load keeps its
    // displacement only if it lands at the same address mod 4 it had at the
    // site. The stub buys that with one `nop`.
    assert_eq!(
        continuation as usize & !1,
        d.stub as usize + 14,
        "a nop was inserted to land the body at the site's alignment"
    );
    assert_eq!((continuation as usize & !1) % 4, TAIL_SITE % 4);
    assert_eq!(
        isa::disassemble(image, d.stub as usize + 12, d.stub + 12, 3),
        [
            format!("{:08x}: nop", d.stub + 12),
            // The displaced tail call, re-encoded so it still reaches the same
            // shared leaf from its new address. Relocation never re-does pc
            // arithmetic — the decoder already resolved the target to an
            // absolute address, so the target is held still and the new
            // displacement is recomputed.
            format!("{:08x}: b.w 0x1200", d.stub + 14),
            format!("{:08x}: b.w {:#x}", d.stub + 18, d.resume()),
        ]
    );
}

// ---------------------------------------------------------------------------
// 3. The refusals, and atomicity
// ---------------------------------------------------------------------------

fn refusals(image: &mut [u8]) {
    section("3. the refusals — and the image is untouched by each");

    // --- a displaced `cbz` ---
    println!("  {CBZ_FN:#06x}  a function whose first instruction is a `cbz`:");
    show(image, CBZ_FN, CBZ_FN as u32, 3);

    let before = image.to_vec();
    let err = tramp(image, CBZ_FN, HOOK_A).expect_err("a displaced cbz cannot be relocated");
    report(&err);

    // `CBZ`'s offset is `ZeroExtend(i:imm5:'0')` — *unsigned* (A7.7.21) — so it
    // reaches 0 to 126 bytes forward and has no backward form at all. A stub in
    // erased flash is essentially never within that window of the branch's
    // target, so this is reported as its own refusal rather than folded into a
    // generic "out of range", which would invite a caller to retry at a nearer
    // address. Rewriting the `cbz` as `cmp`/`b<cond>.w` is a different
    // operation from relocating it, and not this crate's to do silently.
    match err {
        DetourError::Relocate { at, source } => {
            assert_eq!(at, CBZ_FN as u32, "the offending instruction is named");
            assert_eq!(source.reason(), "forward-only-branch");
            assert_eq!(source.mnemonic(), "cbz");
            assert!(
                source.is_address_dependent(),
                "another stub address could in principle work — there just is \
                 no erased flash within 126 bytes below the branch target"
            );
            assert!(matches!(source, RelocateError::ForwardOnlyBranch { .. }));
        }
        other => panic!("expected a relocation refusal, got {other}"),
    }
    assert_eq!(err.reason(), "relocate");

    // This is the assertion that matters. Everything fallible in `detour` —
    // the decode, the IT checks, relocating every displaced instruction,
    // encoding all three branches, the free-space search, every bounds check —
    // happens in a planning phase that takes `&[u8]`. A patch that wrote a stub
    // and then discovered the branch was out of range would leave an image that
    // is corrupt and also reports itself as unpatched, which on flash is the
    // difference between a retry and a dead device.
    assert_eq!(image, &before[..], "refused, and not one byte written");
    println!(
        "     image after the refusal: byte-identical ({} bytes)\n",
        image.len()
    );

    // --- a displaced IT block ---
    println!("  {IT_FN:#06x}  a function whose first instruction is an `ite`:");
    show(image, IT_FN, IT_FN as u32, 4);

    let before = image.to_vec();
    let err = tramp(image, IT_FN, HOOK_A).expect_err("the displaced region splits the IT block");
    report(&err);

    // The four bytes at the site cover `ite eq` and its first governed
    // instruction; the second governed instruction stays behind. Moving a
    // governed instruction into the stub strips its condition — it has none of
    // its own (A7.3.2) — so it would run unconditionally there, while the
    // instruction left behind would be governed by an `IT` that is no longer in
    // front of it. Nothing about the resulting bytes looks wrong. This is the
    // failure mode only a decoder that tracks `ITSTATE` can see at all.
    assert_eq!(err.reason(), "splits-it-block");
    assert!(matches!(
        err,
        DetourError::SplitsItBlock { site, displaced } if site == IT_FN && displaced == 4
    ));
    assert_eq!(image, &before[..], "refused, and not one byte written");
    println!(
        "     image after the refusal: byte-identical ({} bytes)\n",
        image.len()
    );
}

// ---------------------------------------------------------------------------
// 4. What a local decode cannot see
// ---------------------------------------------------------------------------

fn the_blind_spot(pristine: &[u8]) {
    section("4. the blind spot — `DetourOptions::scan_from`");

    // A Thumb stream cannot be decoded backwards: nothing in the encoding says
    // where an instruction begins, and the only length rule runs forwards
    // (A5.1). So by default the IT state *entering* a site is assumed inactive,
    // and the site is assumed to be an instruction boundary. Neither can be
    // checked from the site alone.
    //
    // Here is what that costs. `IT_FN + 2` is the first instruction governed by
    // the `ite`, and detouring it strips its condition — exactly the bug
    // section 3 refused. Without `scan_from` the refusal is not available,
    // because the `ite` is two bytes behind the site and invisible.
    let site = IT_FN + 2;
    println!("  both calls below run against a fresh copy of the pristine image.\n");

    let mut blind = pristine.to_vec();
    let installed = tramp(&mut blind, site, HOOK_A);
    println!("  tramp(image, {site:#06x}, hook)");
    match &installed {
        Ok(d) => println!(
            "     -> installed a {} to {:#06x}; the `ite` two bytes back was \
             never in view\n",
            d.kind, d.stub
        ),
        Err(e) => println!("     -> refused: {e}\n"),
    }
    assert!(
        installed.is_ok(),
        "the default cannot see an IT block that starts before the site"
    );

    // Given a known instruction boundary at or before the site — a function
    // entry from `analysis::function_start`, say — the state is decoded rather
    // than assumed, and the same call is refused. The same option also catches
    // a site that is not an instruction boundary at all (`site-not-aligned`),
    // which is the other thing a backwards-undecodable stream hides.
    let mut told = pristine.to_vec();
    let opts = DetourOptions::new().with_scan_from(IT_FN);
    let err = detour(&mut told, site, HOOK_A, opts)
        .expect_err("with a starting point, the IT block is visible");
    println!("  tramp(image, {site:#06x}, hook).with_scan_from({IT_FN:#06x})");
    println!("     -> refused: {err}");
    println!("        reason: {:?}\n", err.reason());

    assert_eq!(err.reason(), "site-in-it-block");
    assert!(matches!(err, DetourError::SiteInItBlock { site: s } if s == site));
    assert_eq!(told, pristine, "refused, and not one byte written");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn section(title: &str) {
    println!("{title}");
    println!("{}\n", "-".repeat(title.chars().count()));
}

/// Disassemble `count` instructions at `at` and print them indented.
fn show(image: &[u8], at: usize, addr: u32, count: usize) {
    for line in isa::disassemble(image, at, addr, count) {
        println!("  {line}");
    }
}

fn describe(d: &Detour) {
    println!(
        "  site {:#06x}   displaced {} bytes ({})   stub {:#06x}..{:#06x}   resume {:#06x}",
        d.site,
        d.displaced,
        d.kind,
        d.stub,
        d.stub as usize + d.stub_len,
        d.resume(),
    );
    println!();
}

fn report(err: &DetourError) {
    println!("     -> refused: {err}");
    println!("        reason: {:?}", err.reason());
}

// ---------------------------------------------------------------------------
// the synthetic image
// ---------------------------------------------------------------------------

/// A flat image with a few hand-assembled functions in it. Every halfword is
/// commented with its UAL text; the disassembly this example prints is the
/// check that the comments are true.
fn build_image() -> Vec<u8> {
    let mut image = vec![0u8; 0x4000];
    for b in image[FLASH_FREE..].iter_mut() {
        *b = 0xff;
    }

    // 0x1000 `led_set` — an ordinary non-leaf function.
    put(&mut image, LED_SET, &[0xb510, 0x2001, 0x2102, 0xbd10]);
    //                          push     movs     movs     pop
    //                          {r4,lr}  r0,#1    r1,#2    {r4,pc}

    // 0x1100 a tail call: set up an argument, then *jump* into a shared leaf so
    // the leaf's `bx lr` returns to this function's caller. `B.W` T4 is
    // `11110 S imm10 · 10 J1 0 J2 imm11` (A7.7.12).
    put(&mut image, TAIL_SITE - 2, &[0x2002]); // movs r0, #2
    thumb_asm::write(
        &mut image,
        TAIL_SITE,
        &thumb_asm::encode_b_wide(TAIL_SITE, 0x1200).expect("in range"),
    );

    // 0x1200 the shared leaf the tail call jumps to.
    put(&mut image, 0x1200, &[0x2000, 0x4770]); // movs r0, #0 · bx lr

    // 0x1300 a function opening with `CBZ` — `1011 op 0 i 1 imm5 Rn`
    // (A7.7.21). `0xb108` is `cbz r0, +6`, i.e. to 0x1306.
    put(
        &mut image,
        CBZ_FN,
        &[0xb108, 0x2001, 0x4770, 0x2000, 0x4770],
    );

    // 0x1400 a function opening with `ITE EQ` — `IT` T1, `1011 1111 firstcond
    // mask` (A7.7.38), `firstcond = 0b0000`, `mask = 0b1100`: two governed
    // instructions, the second on the inverted condition.
    put(&mut image, IT_FN, &[0xbf0c, 0x2001, 0x2002, 0x4770]);

    // Two hooks. Nothing about them matters here except that they are at known,
    // reachable addresses; a hook is an ordinary function.
    put(&mut image, HOOK_A as usize & !1, &[0xb510, 0xbd10]);
    put(&mut image, HOOK_B as usize & !1, &[0xb510, 0xbd10]);

    image
}

/// Write consecutive little-endian halfwords at `at`.
fn put(image: &mut [u8], at: usize, halfwords: &[u16]) {
    for (i, hw) in halfwords.iter().enumerate() {
        thumb_asm::write(image, at + i * 2, &hw.to_le_bytes());
    }
}
