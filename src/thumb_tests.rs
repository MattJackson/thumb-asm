use super::*;

#[test]
fn find_bytes_word_and_start() {
    let img = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55];
    assert_eq!(find(&img, Needle::Bytes(&[0x22, 0x33]), 0), Some(2));
    // little-endian word 0x33221100 == bytes 00 11 22 33 at offset 0.
    assert_eq!(find(&img, Needle::Word(0x3322_1100), 0), Some(0));
    // `start` skips earlier matches.
    assert_eq!(find(&img, Needle::Bytes(&[0x22, 0x33]), 3), None);
}

#[test]
fn find_free_run_and_wrapper() {
    let mut img = vec![0u8; 32];
    for b in img.iter_mut().skip(10).take(8) {
        *b = 0xFF;
    }
    // find_free_space is exactly find(FreeRun, ..).
    assert_eq!(find_free_space(&img, 8, 1, 0), Some(10));
    assert_eq!(
        find(&img, Needle::FreeRun { len: 8, align: 1 }, 0),
        Some(10)
    );
    assert_eq!(find(&img, Needle::FreeRun { len: 9, align: 1 }, 0), None);
    // Nested/composed find: nothing more free past the run.
    let run = find(&img, Needle::FreeRun { len: 4, align: 1 }, 0).unwrap();
    assert_eq!(
        find(&img, Needle::FreeRun { len: 4, align: 1 }, run + 8),
        None
    );
}

#[test]
fn bl_encode_decode_roundtrip() {
    // Forward, backward, and a real observed site (0x9da80 -> 0x9bf50).
    let cases: &[(usize, u32)] = &[
        (0x9da80, 0x9bf50),
        (0x9e3f8, 0x9bf50),
        (0x1000, 0x1c3810),
        (0x1c3810, 0x1000),
        (0x100, 0x100 + 4), // minimal forward
    ];
    for &(site, target) in cases {
        let bytes = encode_bl(site, target).expect("in range");
        let mut img = vec![0u8; site + 8];
        img[site..site + 4].copy_from_slice(&bytes);
        assert_eq!(
            decode_bl(&img, site),
            Some(target),
            "roundtrip site=0x{site:x} target=0x{target:x}"
        );
    }
    // Out of BL range (> 16 MiB) is refused, never mis-encoded.
    assert_eq!(encode_bl(0, 0x0200_0000), None);
}

#[test]
fn find_bl_sites_locates_direct_calls() {
    // Two BL sites calling the same target, plus unrelated bytes between.
    let target = 0x1_5000u32;
    let mut img = vec![0u8; 0x8000];
    let a = 0x1000usize;
    let b = 0x2000usize;
    img[a..a + 4].copy_from_slice(&encode_bl(a, target).unwrap());
    img[b..b + 4].copy_from_slice(&encode_bl(b, target).unwrap());
    let sites = find_bl_sites(&img, target);
    assert!(sites.contains(&a) && sites.contains(&b), "sites: {sites:?}");
}

#[test]
fn asm_reproduces_kat_handler_bytes() {
    // The 3C-0E hijack handler, assembled through the dumb Asm verbs, must equal
    // the hand-built KAT bytes exactly (handler + literal pool). If the encoder
    // drifts one bit, this fails against a known-good artifact.
    const KAT: &str = "094b58780e280dd19878c0280ad1d878de2807d100b5\
0920f0210022034b9847022000bd024b1847380d00026b2d0a005bad0900";
    let mut a = Asm::new();
    let tail = a.label();
    a.ldr_lit(3, 0x0200_0d38); // ldr r3, =cdb_base
    a.ldrb_imm(0, 3, 1); // mode = cdb[1]
    a.cmp_imm(0, 0x0E);
    a.bne(tail);
    a.ldrb_imm(0, 3, 2); // cdb[2]
    a.cmp_imm(0, 0xC0);
    a.bne(tail);
    a.ldrb_imm(0, 3, 3); // cdb[3]
    a.cmp_imm(0, 0xDE);
    a.bne(tail);
    a.push(0x0100); // push {lr}
    a.movs_imm(0, 0x09);
    a.movs_imm(1, 0xF0);
    a.movs_imm(2, 0x00);
    a.ldr_lit(3, 0x000a_2d6b); // ldr r3, =sense_setter|1
    a.blx(3);
    a.movs_imm(0, 0x02);
    a.pop(0x0100); // pop {pc}
    a.bind(tail);
    a.ldr_lit(3, 0x0009_ad5b); // ldr r3, =oem_handler|1
    a.bx(3);
    let got = a.finish().expect("assemble");
    let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, KAT, "assembled handler drifted from the KAT");
}

#[test]
fn command_table_walk_follows_chain_and_stops_at_terminator() {
    // Two segments: base seg has one real record then a chain(flag=4) whose
    // handler field points at the second segment; second seg has one real record
    // then a terminator(flag=3).
    let stride = 8;
    let seg2 = 0x40usize;
    let mut img = vec![0u8; 0x80];
    // seg1[0]: opcode 0x12, flags 0x01, handler 0x1111
    img[0] = 0x12;
    img[1] = 0x01;
    img[4..8].copy_from_slice(&0x1111u32.to_le_bytes());
    // seg1[1]: chain, flags 0x04, handler = seg2 base
    img[8] = 0x00;
    img[9] = 0x04;
    img[12..16].copy_from_slice(&(seg2 as u32).to_le_bytes());
    // seg2[0]: opcode 0x3C, flags 0x01, handler 0x2222
    img[seg2] = 0x3C;
    img[seg2 + 1] = 0x01;
    img[seg2 + 4..seg2 + 8].copy_from_slice(&0x2222u32.to_le_bytes());
    // seg2[1]: terminator flags 0x03
    img[seg2 + 9] = 0x03;
    let t = CommandTable {
        base: 0,
        stride,
        opcode_off: 0,
        flags_off: 1,
        handler_off: 4,
        term_flag: 0x03,
        max_records: 64,
    };
    let recs = t.walk(&img, 0x04);
    assert_eq!(recs.len(), 2, "expected both segments' real records");
    assert_eq!((recs[0].opcode, recs[0].handler), (0x12, 0x1111));
    assert_eq!((recs[1].opcode, recs[1].handler), (0x3C, 0x2222));
}

#[test]
fn prologue_check_accepts_push_lr_rejects_data() {
    let mut img = vec![0u8; 16];
    img[4..6].copy_from_slice(&0xB5F0u16.to_le_bytes()); // push {r4-r7,lr}
    assert!(prologue_is_push_lr(&img, 4, 4));
    assert!(!prologue_is_push_lr(&img, 8, 4));
}

#[test]
fn prologue_check_looks_past_the_first_halfword_of_its_window() {
    // A real entry does not always push on its very first instruction: an
    // alignment nop or a cheap register setup often comes ahead of the frame
    // save. The window exists so those still count as function entries; a
    // check that only ever looked at `off` itself would reject every one of
    // them, and a handler pointer resolving to this address would be thrown
    // away as a coincidence.
    let mut img = vec![0u8; 16];
    img[0..2].copy_from_slice(&0x46C0u16.to_le_bytes()); // mov r8, r8 (nop)
    img[2..4].copy_from_slice(&0x46C0u16.to_le_bytes()); // mov r8, r8 (nop)
    img[4..6].copy_from_slice(&0xB5F0u16.to_le_bytes()); // push {r4-r7, lr}
    assert!(
        prologue_is_push_lr(&img, 0, 4),
        "the push two halfwords in is inside a four-halfword window"
    );
    // ...and a window that stops before it really does stop before it.
    assert!(!prologue_is_push_lr(&img, 0, 2));
}

#[test]
fn prologue_check_ignores_a_push_pattern_that_is_off_the_instruction_grid() {
    // Bytes `20 B5` are `push {r5, lr}` — but only when they start on a
    // halfword boundary. Here they sit at offset 1, so the halfwords the CPU
    // actually decodes are 0x2000 (`movs r0, #0`) and 0x00B5, neither of which
    // is a push. This is precisely the mid-instruction byte coincidence the
    // check exists to reject: accepting it confirms a bogus handler pointer as
    // a function entry, and the patch gets aimed one byte off.
    let mut img = vec![0u8; 16];
    img[1] = 0x20;
    img[2] = 0xB5;
    assert!(!prologue_is_push_lr(&img, 0, 4));
}

#[test]
fn prologue_check_reaches_the_last_halfword_and_reads_no_further() {
    // The function being cross-checked is the last thing in the dump, so its
    // prologue is the image's final two bytes. Requiring a halfword *past* the
    // prologue would make the last function in an image invisible.
    let mut img = vec![0u8; 6];
    img[4..6].copy_from_slice(&0xB500u16.to_le_bytes()); // push {lr}
    assert!(prologue_is_push_lr(&img, 4, 4));

    // The same window over an image with nothing in it: candidates 6, 8 and 10
    // run off the end and must simply not be read. The bound is on the end of
    // the halfword, not its start.
    assert!(!prologue_is_push_lr(&[0u8; 6], 4, 4));
}

#[test]
fn read_modify_insert() {
    let mut img = vec![0xFFu8; 16];
    write(&mut img, 4, &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(read_u32(&img, 4), 0xEFBE_ADDE);
    assert_eq!(read_u8(&img, 4), 0xDE);
    let addr = insert(&mut img, 8, &[1, 2, 3]);
    assert_eq!(addr, 8);
    assert_eq!(&img[8..11], &[1, 2, 3]);
}

// --- Asm::finish() range-check boundaries -------------------------------------
// A mis-encoded branch/ldr/adr immediate bricks a drive, so every `bail!` guard
// in `finish()` must actually fire when its immediate goes out of range. `0xBF00`
// (nop) is used as neutral filler to open the required distance.

#[test]
fn finish_bails_on_out_of_range_conditional_branch() {
    let mut a = Asm::new();
    let back = a.label();
    a.bind(back);
    for _ in 0..200 {
        a.raw16(0xBF00); // 200 halfwords back >> the ±127 conditional limit
    }
    a.beq(back);
    let err = a.finish().unwrap_err().to_string();
    assert!(
        err.contains("conditional branch out of range"),
        "unexpected error: {err}"
    );
}

#[test]
fn finish_accepts_in_range_conditional_branch() {
    let mut a = Asm::new();
    let back = a.label();
    a.bind(back);
    for _ in 0..50 {
        a.raw16(0xBF00); // ~52 halfwords back, within ±127
    }
    a.beq(back);
    assert!(a.finish().is_ok());
}

#[test]
fn finish_bails_on_out_of_range_unconditional_branch() {
    let mut a = Asm::new();
    let back = a.label();
    a.bind(back);
    for _ in 0..1100 {
        a.raw16(0xBF00); // >1023 halfwords back, past the unconditional limit
    }
    a.b(back);
    let err = a.finish().unwrap_err().to_string();
    assert!(
        err.contains("branch out of range"),
        "unexpected error: {err}"
    );
}

#[test]
fn finish_bails_on_out_of_range_ldr_literal() {
    let mut a = Asm::new();
    a.ldr_lit(0, 0xDEAD_BEEF);
    for _ in 0..600 {
        a.raw16(0xBF00); // pushes the literal pool >1020 bytes past the ldr
    }
    let err = a.finish().unwrap_err().to_string();
    assert!(
        err.contains("ldr literal out of range"),
        "unexpected error: {err}"
    );
}

#[test]
fn finish_bails_on_out_of_range_adr() {
    let mut a = Asm::new();
    let blob = a.data_blob(vec![0u8; 4]);
    a.adr(0, blob);
    for _ in 0..600 {
        a.raw16(0xBF00); // pushes the blob >1020 bytes past the adr
    }
    let err = a.finish().unwrap_err().to_string();
    assert!(
        err.contains("adr target out of range"),
        "unexpected error: {err}"
    );
}

// --- coverage: CommandTable::find / replace ------------------------------------

#[test]
fn command_table_find_locates_matching_opcode_and_misses_absent_one() {
    let mut img = vec![0u8; 16];
    // record 0: opcode 0x10, flags 0x01, handler 0xAAAA
    img[0] = 0x10;
    img[1] = 0x01;
    img[4..8].copy_from_slice(&0xAAAAu32.to_le_bytes());
    // record 1: terminator
    img[9] = 0x03;
    let t = CommandTable {
        base: 0,
        stride: 8,
        opcode_off: 0,
        flags_off: 1,
        handler_off: 4,
        term_flag: 0x03,
        max_records: 8,
    };
    assert_eq!(
        t.find(&img, 0x10),
        Some(CommandRecord {
            off: 0,
            opcode: 0x10,
            flags: 0x01,
            handler: 0xAAAA,
        })
    );
    // Scan stops at the terminator without a match.
    assert_eq!(t.find(&img, 0x99), None);
}

#[test]
fn command_table_find_gives_up_after_max_records_without_terminator() {
    // No terminator anywhere: find() must stop after max_records rather than
    // reading out of bounds or looping forever.
    let img = vec![0u8; 8]; // opcode 0, flags 0 (never == term_flag 0x03)
    let t = CommandTable {
        base: 0,
        stride: 8,
        opcode_off: 0,
        flags_off: 1,
        handler_off: 4,
        term_flag: 0x03,
        max_records: 1,
    };
    assert_eq!(t.find(&img, 0x10), None);
}

#[test]
fn command_table_replace_overwrites_handler_and_optionally_flags() {
    let mut img = vec![0u8; 16];
    img[0] = 0x10;
    img[1] = 0x01;
    let t = CommandTable {
        base: 0,
        stride: 8,
        opcode_off: 0,
        flags_off: 1,
        handler_off: 4,
        term_flag: 0x03,
        max_records: 8,
    };
    let rec = t.find(&img, 0x10).unwrap();

    t.replace(&mut img, &rec, 0x2000_1001, Some(0x02));
    assert_eq!(read_u32(&img, 4), 0x2000_1001);
    assert_eq!(img[1], 0x02);

    // flags = None leaves the flags byte untouched.
    t.replace(&mut img, &rec, 0x3000_2002, None);
    assert_eq!(read_u32(&img, 4), 0x3000_2002);
    assert_eq!(img[1], 0x02);
}

// --- coverage: CommandTable::walk edge cases ------------------------------------

#[test]
fn command_table_walk_stops_after_max_records_without_terminator_or_chain() {
    let mut img = vec![0u8; 16];
    img[0] = 0x11; // record 0: real, not chain/terminator
    img[1] = 0x01;
    img[8] = 0x22; // record 1: real, not chain/terminator
    img[9] = 0x01;
    let t = CommandTable {
        base: 0,
        stride: 8,
        opcode_off: 0,
        flags_off: 1,
        handler_off: 4,
        term_flag: 0x03,
        max_records: 2,
    };
    // Inner loop exhausts max_records without a chain/terminator/OOB hit, so
    // the outer loop's `!advanced` guard breaks and `out` returns normally.
    let recs = t.walk(&img, 0x04);
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].opcode, 0x11);
    assert_eq!(recs[1].opcode, 0x22);
}

#[test]
fn command_table_walk_breaks_on_chain_cycle() {
    // Segment A chains to B; B chains back to A. The `seen` guard must break
    // the outer loop on revisiting a base instead of looping forever.
    let seg_b = 0x40usize;
    let mut img = vec![0u8; 0x80];
    img[0] = 0x12; // A: one real record
    img[1] = 0x01;
    img[8] = 0x00; // A: chain to B
    img[9] = 0x04;
    img[12..16].copy_from_slice(&(seg_b as u32).to_le_bytes());
    img[seg_b] = 0x34; // B: one real record
    img[seg_b + 1] = 0x01;
    img[seg_b + 8] = 0x00; // B: chain back to A (base 0)
    img[seg_b + 9] = 0x04;
    img[seg_b + 12..seg_b + 16].copy_from_slice(&0u32.to_le_bytes());
    let t = CommandTable {
        base: 0,
        stride: 8,
        opcode_off: 0,
        flags_off: 1,
        handler_off: 4,
        term_flag: 0x03,
        max_records: 8,
    };
    let recs = t.walk(&img, 0x04);
    assert_eq!(
        recs.len(),
        2,
        "one real record from each segment before the cycle breaks"
    );
    assert_eq!((recs[0].opcode, recs[1].opcode), (0x12, 0x34));
}

#[test]
fn command_table_walk_returns_collected_records_when_run_exceeds_image_bounds() {
    // record 0 fits; a hypothetical record 1 would run past the image end
    // with neither a terminator nor a chain flag seen.
    let mut img = vec![0u8; 12];
    img[0] = 0x55;
    img[1] = 0x01;
    let t = CommandTable {
        base: 0,
        stride: 8,
        opcode_off: 0,
        flags_off: 1,
        handler_off: 4,
        term_flag: 0x03,
        max_records: 8,
    };
    let recs = t.walk(&img, 0x04);
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].opcode, 0x55);
}

// --- coverage: the "dumb" Thumb instruction emitters not exercised by the KAT --

#[test]
fn asm_data_processing_and_load_store_emitters_encode_expected_bits() {
    let mut a = Asm::new();
    assert_eq!(a.pos(), 0);
    a.ldr_imm(1, 2, 4);
    a.strh_imm(3, 4, 2);
    a.str_imm(5, 6, 8);
    a.bics(0, 1);
    a.orrs(2, 3);
    a.strb_imm(1, 2, 3);
    a.cmp_reg(4, 5);
    a.ldrb_reg(0, 1, 2);
    a.adds_imm(3, 7);
    a.subs_imm(2, 9);
    a.lsls_imm(1, 2, 3);
    a.lsrs_imm(4, 5, 6);
    a.adds_reg(1, 2, 3);
    a.mov_reg(6, 7);
    a.movs_reg(6, 7);
    assert_eq!(a.pos(), 30);

    // No fixups/ldrs/blobs were used, so finish() only pads to 4 bytes (already
    // aligned here) and returns the raw emitted bytes unchanged.
    let code = a.finish().expect("nothing to range-check");
    let hw = |i: usize| u16::from_le_bytes([code[i * 2], code[i * 2 + 1]]);
    assert_eq!(hw(0), 0x6800 | (1 << 6) | (2 << 3) | 1);
    assert_eq!(hw(1), 0x8000 | (1 << 6) | (4 << 3) | 3);
    assert_eq!(hw(2), 0x6000 | (2 << 6) | (6 << 3) | 5);
    assert_eq!(hw(3), 0x4380 | (1 << 3));
    assert_eq!(hw(4), 0x4300 | (3 << 3) | 2);
    assert_eq!(hw(5), 0x7000 | (3 << 6) | (2 << 3) | 1);
    assert_eq!(hw(6), 0x4280 | (5 << 3) | 4);
    assert_eq!(hw(7), 0x5C00 | (2 << 6) | (1 << 3));
    assert_eq!(hw(8), 0x3000 | (3 << 8) | 7);
    assert_eq!(hw(9), 0x3800 | (2 << 8) | 9);
    assert_eq!(hw(10), (3 << 6) | (2 << 3) | 1);
    assert_eq!(hw(11), 0x0800 | (6 << 6) | (5 << 3) | 4);
    assert_eq!(hw(12), 0x1800 | (3 << 6) | (2 << 3) | 1);
    // `MOV (register)` T1 (A5.2.3), *not* the 0.1.0 `adds rd, rm, #0` lowering.
    assert_eq!(hw(13), 0x4600 | (7 << 3) | 6);
    // `MOV (register)` T2 (A5.2.1) — the flag-setting form, low registers only.
    assert_eq!(hw(14), (7 << 3) | 6);
}

#[test]
fn asm_conditional_branch_emitters_cover_all_fourteen_conditions() {
    // Each conditional branch targets its own bind point (pos == target == 0),
    // so the encoded offset is always the same small negative value and only
    // the opcode's high byte (the thing under test) varies.
    type Emit = fn(&mut Asm, u16);
    let cases: &[(u16, Emit)] = &[
        (0xD000, |a, l| a.beq(l)),
        (0xD100, |a, l| a.bne(l)),
        (0xD200, |a, l| a.bhs(l)),
        (0xD300, |a, l| a.blo(l)),
        (0xD400, |a, l| a.bmi(l)),
        (0xD500, |a, l| a.bpl(l)),
        (0xD600, |a, l| a.bvs(l)),
        (0xD700, |a, l| a.bvc(l)),
        (0xD800, |a, l| a.bhi(l)),
        (0xD900, |a, l| a.bls(l)),
        (0xDA00, |a, l| a.bge(l)),
        (0xDB00, |a, l| a.blt(l)),
        (0xDC00, |a, l| a.bgt(l)),
        (0xDD00, |a, l| a.ble(l)),
    ];
    // Fourteen conditions, and the fourteen bases are exactly 0xD000..=0xDD00 —
    // 0xDE00 (UDF) and 0xDF00 (SVC) are not branches and have no emitter.
    assert_eq!(cases.len(), 14);
    for &(base, emit) in cases {
        let mut a = Asm::new();
        let here = a.label();
        a.bind(here);
        emit(&mut a, here);
        let code = a.finish().expect("self-branch is always in range");
        let hw = u16::from_le_bytes([code[0], code[1]]);
        assert_eq!(hw & 0xFF00, base, "base opcode for {base:#06x}");
    }
}

#[test]
fn asm_b_cond_always_lowers_to_the_unconditional_branch() {
    // `Cond::Al` has no conditional-branch encoding: 0b1110 is UDF in T1. The
    // emitter must produce `b` (0xE000 class), never 0xDE00.
    let mut a = Asm::new();
    let here = a.label();
    a.bind(here);
    a.b_cond(Cond::Al, here);
    let code = a.finish().expect("self-branch is always in range");
    let hw = u16::from_le_bytes([code[0], code[1]]);
    assert_eq!(hw & 0xF800, 0xE000);
    assert_ne!(hw & 0xFF00, 0xDE00);
}

// The placeholder halfword `ldr_lit` emits, `0x4800 | (rt << 8)`, is not
// observable and deliberately so: `ldr_lit` also records `(pos, value, rt)`,
// and `finish` overwrites the whole halfword at `pos` with
// `0x4800 | (rt << 8) | imm8` built from that recorded `rt` — it never reads
// the placeholder bytes back, unlike the b<cond> and adr fixups, which do
// recover the register field from what was emitted. `Asm` hands out no view of
// `code` before `finish` (`pos()` returns only its length), and every path
// that skips the patching step returns `Err` and drops the buffer. So the
// placeholder's `|` and its `<< 8` cannot be checked by any test: they are
// overwritten before anyone can see them. Verified 2026-09-23; this stops
// being true only if `finish` starts reading the placeholder or `Asm` grows an
// accessor for the code buffer.
#[test]
fn asm_ldr_lit_dedups_repeated_literal_values() {
    // Loading the same value twice must reuse one pool slot (the `Some` arm of
    // finish()'s dedup lookup), not append it twice.
    let mut a = Asm::new();
    a.ldr_lit(0, 0x1234_5678);
    a.ldr_lit(1, 0x1234_5678); // same value, different destination register
    let code = a.finish().expect("small, in-range pool");
    // Two 2-byte `ldr` instructions + one 4-byte pool entry = 8 bytes total,
    // not 12 — proof the second load reused the first's pool slot.
    assert_eq!(code.len(), 8);
    let pool = u32::from_le_bytes([code[4], code[5], code[6], code[7]]);
    assert_eq!(pool, 0x1234_5678);
}

// --- coverage: decode_bl / encode_bl / encode_b_wide / decode_b_wide edges -----

#[test]
fn decode_bl_rejects_non_bl_bytes_and_out_of_bounds_offset() {
    let img = [0u8; 4]; // all-zero halfwords never match the BL bit pattern
    assert_eq!(decode_bl(&img, 0), None);
    assert_eq!(decode_bl(&img, 1), None); // 1..5 would run past a 4-byte image
}

#[test]
fn encode_bl_rejects_odd_target_offset() {
    // Thumb instructions are 2-byte aligned; an odd site/target delta is refused.
    assert_eq!(encode_bl(0, 5), None);
}

#[test]
fn encode_decode_b_wide_roundtrip_and_rejections() {
    let cases: &[(usize, u32)] = &[(0x1000, 0x2000), (0x2000, 0x1000), (0x100, 0x104)];
    for &(site, target) in cases {
        let bytes = encode_b_wide(site, target).expect("in range");
        let mut img = vec![0u8; site + 8];
        img[site..site + 4].copy_from_slice(&bytes);
        assert_eq!(decode_b_wide(&img, site), Some(target));
        // A B.W is never mistaken for a BL: same hw1 prefix, different hw2 base.
        assert_eq!(decode_bl(&img, site), None);
    }
    // Same range/alignment rejections as encode_bl.
    assert_eq!(encode_b_wide(0, 0x0200_0000), None);
    assert_eq!(encode_b_wide(0, 5), None);
    // decode_b_wide rejects a too-short buffer and a real BL's bit pattern.
    assert_eq!(decode_b_wide(&[0u8; 2], 0), None);
    let bl = encode_bl(0, 0x1000).unwrap();
    assert_eq!(decode_b_wide(&bl, 0), None);
}

// --- coverage: find_bytes / find_free_run edge cases ---------------------------

#[test]
fn find_bytes_rejects_empty_pattern_and_out_of_range_start() {
    let img = [1u8, 2, 3, 4];
    assert_eq!(find(&img, Needle::Bytes(&[]), 0), None);
    assert_eq!(find(&img, Needle::Bytes(&[1]), 10), None);
}

#[test]
fn find_free_run_zero_length_matches_at_clamped_start() {
    let img = [0u8; 8];
    assert_eq!(find(&img, Needle::FreeRun { len: 0, align: 1 }, 3), Some(3));
    assert_eq!(
        find(&img, Needle::FreeRun { len: 0, align: 1 }, 100),
        Some(8)
    ); // clamped to image length
}

// --- coverage: CommandTable::find out-of-bounds run ----------------------------

#[test]
fn command_table_find_returns_none_when_run_exceeds_image_bounds() {
    // Record 0 fits; a hypothetical record 1 would run past the image end with
    // neither a match nor a terminator seen first.
    let mut img = vec![0u8; 12];
    img[0] = 0x55;
    img[1] = 0x01;
    let t = CommandTable {
        base: 0,
        stride: 8,
        opcode_off: 0,
        flags_off: 1,
        handler_off: 4,
        term_flag: 0x03,
        max_records: 8,
    };
    assert_eq!(t.find(&img, 0xAA), None);
}

#[test]
fn command_table_find_sees_a_record_that_ends_exactly_at_the_image_end() {
    // The table is the last thing in the dump, so the final record's handler
    // word is the image's final four bytes. An off-by-one on the bounds check
    // reports the opcode as absent, and a caller told "absent" goes looking for
    // somewhere to add a new record instead of repointing the one that is
    // already there.
    let mut img = vec![0u8; 16];
    img[0] = 0x10;
    img[1] = 0x01;
    img[4..8].copy_from_slice(&0xAAAAu32.to_le_bytes());
    img[8] = 0x2A;
    img[9] = 0x01;
    img[12..16].copy_from_slice(&0xBEEFu32.to_le_bytes());
    let t = CommandTable {
        base: 0,
        stride: 8,
        opcode_off: 0,
        flags_off: 1,
        handler_off: 4,
        term_flag: 0x03,
        max_records: 8,
    };
    assert_eq!(
        t.find(&img, 0x2A),
        Some(CommandRecord {
            off: 8,
            opcode: 0x2A,
            flags: 0x01,
            handler: 0xBEEF,
        }),
        "a record ending on the last byte of the image is still a record"
    );
}

#[test]
fn command_table_find_refuses_a_first_record_the_image_is_too_short_to_hold() {
    // A truncated dump: the base is inside the image but the record it points
    // at is not all there. The bounds check has to cover the *first* record as
    // well as the later ones — otherwise reading its handler word runs off the
    // end of the buffer.
    let mut img = vec![0u8; 4]; // one record needs 8
    img[0] = 0x10;
    img[1] = 0x01;
    let t = CommandTable {
        base: 0,
        stride: 8,
        opcode_off: 0,
        flags_off: 1,
        handler_off: 4,
        term_flag: 0x03,
        max_records: 8,
    };
    assert_eq!(t.find(&img, 0x10), None);
}

/// A two-record table whose geometry is deliberately *not* the worked example
/// in the docs: it starts at offset 8, the flags byte comes before the opcode,
/// and the opcode is the record's third byte. Firmwares lay records out
/// however they like, so every field has to be read from its own offset.
///
/// ```text
/// off  8: [ pad | flags 01 | opcode 11 | pad | handler = 0x1111 (LE) ]
/// off 16: [ pad | flags 01 | opcode 22 | pad | handler = 0x2222 (LE) ]
/// off 24: [ pad | flags 03 = terminator | ...                      ]
/// ```
fn table_with_the_opcode_inside_the_record() -> (Vec<u8>, CommandTable) {
    let mut img = vec![0u8; 40];
    img[9] = 0x01;
    img[10] = 0x11;
    img[12..16].copy_from_slice(&0x1111u32.to_le_bytes());
    img[17] = 0x01;
    img[18] = 0x22;
    img[20..24].copy_from_slice(&0x2222u32.to_le_bytes());
    img[25] = 0x03;
    let t = CommandTable {
        base: 8,
        stride: 8,
        opcode_off: 2,
        flags_off: 1,
        handler_off: 4,
        term_flag: 0x03,
        max_records: 8,
    };
    (img, t)
}

#[test]
fn command_table_find_steps_one_stride_and_reads_the_opcode_from_inside_the_record() {
    let (img, t) = table_with_the_opcode_inside_the_record();
    assert_eq!(
        t.find(&img, 0x22),
        Some(CommandRecord {
            off: 16,
            opcode: 0x22,
            flags: 0x01,
            handler: 0x2222,
        }),
        "the second record is exactly one stride past the base"
    );
    assert_eq!(t.find(&img, 0x11).map(|r| r.off), Some(8));
    // 0x00 is what every padding byte in this table holds, including the bytes
    // either side of each opcode slot. A scan that matches it is reading the
    // opcode from the wrong byte of the record, and repointing the record it
    // returns hijacks a command nobody asked about.
    assert_eq!(t.find(&img, 0x00), None);
}

#[test]
fn command_table_walk_reads_each_opcode_from_inside_its_own_record() {
    // walk() and find() have to agree about which byte of a record is the
    // opcode. A walk that reports the padding byte instead hands the caller an
    // inventory in which every command is 0x00.
    let (img, t) = table_with_the_opcode_inside_the_record();
    let recs = t.walk(&img, 0x04);
    assert_eq!(recs.len(), 2);
    assert_eq!(
        (recs[0].off, recs[0].opcode, recs[0].handler),
        (8, 0x11, 0x1111)
    );
    assert_eq!(
        (recs[1].off, recs[1].opcode, recs[1].handler),
        (16, 0x22, 0x2222)
    );
}

#[test]
fn command_table_walk_spends_one_budget_across_the_whole_scan() {
    // A table whose terminator was overwritten: no record ever says "stop".
    // `max_records` is the budget for the whole walk, so the scan gives up
    // after two records even though three more sit within the image. Without
    // that countdown the walk runs to the end of the dump and every byte
    // pattern past the real table comes back as a dispatch record.
    let mut img = vec![0u8; 40]; // five 8-byte records, no terminator anywhere
    img[0] = 0x10;
    img[1] = 0x01;
    img[8] = 0x11;
    img[9] = 0x01;
    img[16] = 0x12;
    img[17] = 0x01;
    img[24] = 0x13;
    img[25] = 0x01;
    img[32] = 0x14;
    img[33] = 0x01;
    let t = CommandTable {
        base: 0,
        stride: 8,
        opcode_off: 0,
        flags_off: 1,
        handler_off: 4,
        term_flag: 0x03,
        max_records: 2,
    };
    let recs = t.walk(&img, 0x04);
    assert_eq!(recs.len(), 2, "max_records caps the whole walk");
    assert_eq!((recs[0].opcode, recs[1].opcode), (0x10, 0x11));
}

// --- coverage: finish() success paths not reached by the bail-out tests -------

#[test]
fn finish_encodes_in_range_unconditional_branch() {
    let mut a = Asm::new();
    let target = a.label();
    a.raw16(0xBF00); // nop filler so the branch isn't targeting itself
    a.b(target);
    a.bind(target);
    let code = a.finish().expect("well within the +-1023 halfword range");
    let hw = u16::from_le_bytes([code[2], code[3]]);
    assert_eq!(hw & 0xF800, 0xE000); // unconditional B opcode class
}

#[test]
fn finish_bails_on_unbound_branch_label() {
    let mut a = Asm::new();
    let never_bound = a.label();
    a.beq(never_bound);
    let err = a.finish().unwrap_err().to_string();
    assert!(err.contains("unbound label"), "unexpected error: {err}");
}

#[test]
fn finish_bails_on_unbound_blob_label() {
    let mut a = Asm::new();
    // A label reserved but never passed to `data_blob`, so step 3 of finish()
    // never binds it — the `adr` fixup in step 4 must reject it by name.
    let never_bound = a.label();
    a.adr(0, never_bound);
    let err = a.finish().unwrap_err().to_string();
    assert!(
        err.contains("unbound blob label"),
        "unexpected error: {err}"
    );
}

#[test]
fn finish_pads_each_data_blob_to_four_byte_alignment_and_resolves_adr() {
    // blob1 is 3 bytes, so blob2 would start unaligned without the per-blob
    // padding loop in finish() running again for it.
    let mut a = Asm::new();
    let blob1 = a.data_blob(vec![0xAA, 0xBB, 0xCC]);
    let blob2 = a.data_blob(vec![0xDD, 0xEE, 0xFF, 0x11]);
    a.adr(0, blob1);
    a.adr(1, blob2);
    let code = a.finish().expect("small, in-range adr targets");
    assert_eq!(&code[4..7], &[0xAA, 0xBB, 0xCC]);
    assert_eq!(&code[8..12], &[0xDD, 0xEE, 0xFF, 0x11]); // padded up to the next 4-byte boundary
}

// ---------------------------------------------------------------------------
// 0.2.0 additions: checked reads, the conditional-branch codec, and the
// framework-agnostic install/verify pair.
// ---------------------------------------------------------------------------

#[test]
fn find_bl_sites_finds_a_bl_in_the_final_four_bytes() {
    // Regression for the 0.1.0 off-by-one: the scan bound was
    // `len.saturating_sub(4)` used exclusively, so offset `len - 4` — a legal
    // site — was never examined. Here the ONLY `BL` in the image occupies the
    // last four bytes, so the old code returned an empty vec.
    let target = 0x40u32;
    let mut img = vec![0u8; 0x20];
    let site = img.len() - 4;
    let bytes = encode_bl(site, target).expect("in range");
    img[site..].copy_from_slice(&bytes);
    assert_eq!(find_bl_sites(&img, target), vec![site]);
    // And with the Thumb bit set on the wanted target, which is masked off.
    assert_eq!(find_bl_sites(&img, target | 1), vec![site]);
}

#[test]
fn find_bl_sites_tolerates_images_too_short_to_hold_one() {
    for len in 0..4usize {
        assert!(
            find_bl_sites(&vec![0xFFu8; len], 0x100).is_empty(),
            "len {len}"
        );
    }
}

#[test]
fn read_u16_and_the_checked_read_family() {
    let img = [0x78u8, 0x56, 0x34, 0x12];
    assert_eq!(read_u16(&img, 0), 0x5678);
    assert_eq!(read_u16(&img, 2), 0x1234);
    assert_eq!(read_u8(&img, 3), 0x12);
    assert_eq!(read_u32(&img, 0), 0x1234_5678);

    // Checked siblings agree with the panicking ones in bounds …
    assert_eq!(try_read_u8(&img, 0), Some(0x78));
    assert_eq!(try_read_u16(&img, 2), Some(0x1234));
    assert_eq!(try_read_u32(&img, 0), Some(0x1234_5678));
    // … and return None at exactly the first offset that would run past the end.
    assert_eq!(try_read_u8(&img, 4), None);
    assert_eq!(try_read_u16(&img, 3), None);
    assert_eq!(try_read_u16(&img, 99), None);
    assert_eq!(try_read_u32(&img, 1), None);
    // The last legal offset for each width is len - width, not len - width - 1.
    assert!(try_read_u8(&img, 3).is_some());
    assert!(try_read_u16(&img, 2).is_some());
    assert!(try_read_u32(&img, 0).is_some());
    // Empty image: every read is None, nothing panics.
    assert_eq!(try_read_u8(&[], 0), None);
    assert_eq!(try_read_u16(&[], 0), None);
    assert_eq!(try_read_u32(&[], 0), None);
}

#[test]
fn decode_b_cond_t1_hand_computed_vector_and_all_conditions() {
    // 0xD40E = `bmi` with imm8 = 0x0E, so target = 0 + 4 + 14*2 = 0x20.
    let b = decode_b_cond(&[0x0E, 0xD4], 0).expect("a bmi");
    assert_eq!(b.cond, Cond::Mi);
    assert_eq!(b.target, 0x20);
    assert_eq!(b.len, 2);

    // Backward branch: imm8 = 0xFE = -2 → target = at + 4 - 4 = at.
    let at = 0x100;
    let mut img = vec![0u8; 0x200];
    img[at..at + 2].copy_from_slice(&0xD1FEu16.to_le_bytes());
    let b = decode_b_cond(&img, at).expect("a bne");
    assert_eq!((b.cond, b.target, b.len), (Cond::Ne, at as u32, 2));

    // Every one of the fourteen `cond` values decodes to its condition.
    for bits in 0u8..=0b1101 {
        let hw = 0xD000u16 | ((bits as u16) << 8);
        let got = decode_b_cond(&hw.to_le_bytes(), 0).expect("a branch");
        assert_eq!(got.cond, Cond::from_bits(bits).unwrap(), "cond {bits:#06b}");
        assert_eq!(got.target, 4); // imm8 == 0
    }
}

#[test]
fn decode_b_cond_rejects_udf_and_svc() {
    // A5.2.6 Table A5-8: cond 0b1110 is permanently UNDEFINED (UDF), cond
    // 0b1111 is SVC. Neither is a branch, so a decoder that treats the whole
    // 0xD0xx..=0xDFxx range as conditional branches reads an `svc #n` as a jump.
    assert_eq!(decode_b_cond(&[0x00, 0xDE], 0), None);
    assert_eq!(decode_b_cond(&[0x00, 0xDF], 0), None);
    // Not just imm8 == 0: the whole two sixteenths of the space.
    for imm8 in [0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
        assert_eq!(
            decode_b_cond(&[imm8, 0xDE], 0),
            None,
            "udf imm8 {imm8:#04x}"
        );
        assert_eq!(
            decode_b_cond(&[imm8, 0xDF], 0),
            None,
            "svc imm8 {imm8:#04x}"
        );
    }
    // The last real condition, 0xDD (ble), still decodes — the boundary is tight.
    assert_eq!(decode_b_cond(&[0x00, 0xDD], 0).unwrap().cond, Cond::Le);
}

#[test]
fn decode_b_cond_t3_hand_computed_vector() {
    // Hand-computed from A5.3.4 / A7.7.12, T3:
    //   hw1 = 11110 S cond imm6, hw2 = 10 J1 0 J2 imm11,
    //   imm32 = SignExtend(S:J2:J1:imm6:imm11:'0').
    //
    // Forward: site 0x1000, target 0x11004 → off = 0x10000, imm = off>>1 =
    // 0x8000. As a 20-bit field: S=0, J2=0, J1=0, imm6 = (0x8000>>11)&0x3F =
    // 0x10, imm11 = 0. cond = Mi = 0b0100 → hw1 = 0xF000|0x100|0x10 = 0xF110,
    // hw2 = 0x8000. Bytes (two LE halfwords, hw1 first): 10 F1 00 80.
    let at = 0x1000usize;
    let mut img = vec![0u8; 0x4000];
    img[at..at + 4].copy_from_slice(&[0x10, 0xF1, 0x00, 0x80]);
    let b = decode_b_cond(&img, at).expect("a bmi.w");
    assert_eq!(b.cond, Cond::Mi);
    assert_eq!(b.target, 0x1_1004);
    assert_eq!(b.len, 4);

    // Backward: site 0x2000, target 0x1F04 → off = -0x100, imm = -128, so as a
    // 20-bit field 0xFFF80: S=1, J2=1, J1=1, imm6 = 0x3F, imm11 = 0x780.
    // cond = Lt = 0b1011 → hw1 = 0xF000|0x400|0x2C0|0x3F = 0xF6FF,
    // hw2 = 0x8000|0x2000|0x0800|0x780 = 0xAF80. (-0x100 also fits T1, so this
    // is a legal but redundantly wide encoding — the sort an assembler emits
    // for an explicit `blt.w`. The decoder must read it; the encoder, which
    // picks the narrowest form, never produces it.)
    let at = 0x2000usize;
    img[at..at + 4].copy_from_slice(&[0xFF, 0xF6, 0x80, 0xAF]);
    let b = decode_b_cond(&img, at).expect("a blt.w");
    assert_eq!((b.cond, b.target, b.len), (Cond::Lt, 0x1F04, 4));

    // The J1/J2 order really is different from BL/B.W: reading these same bytes
    // with the `S:I1:I2:imm10:imm11` rule would give a different target, so the
    // wide-branch decoders must not claim them.
    assert_eq!(decode_bl(&img, at), None);
    assert_eq!(decode_b_wide(&img, at), None);
}

#[test]
fn decode_b_cond_rejects_non_branches_and_truncated_reads() {
    // A 16-bit instruction that is not in the 0xDxxx space and not a 32-bit
    // prefix: `movs r0, #1`.
    assert_eq!(decode_b_cond(&0x2001u16.to_le_bytes(), 0), None);
    // A 32-bit prefix whose hw2 is a BL (0xD000 class), not a T3 conditional.
    let bl = encode_bl(0, 0x100).unwrap();
    assert_eq!(decode_b_cond(&bl, 0), None);
    // …and one whose hw2 is a B.W (0x9000 class).
    let bw = encode_b_wide(0, 0x100).unwrap();
    assert_eq!(decode_b_cond(&bw, 0), None);
    // T3 shape but cond == 0b1110 / 0b1111 (the "related encodings" space:
    // MSR/MRS, hints, UDF.W, BL) — not a branch.
    for bits in [0b1110u16, 0b1111] {
        let hw1 = 0xF000u16 | (bits << 6);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&hw1.to_le_bytes());
        bytes.extend_from_slice(&0x8000u16.to_le_bytes());
        assert_eq!(decode_b_cond(&bytes, 0), None, "cond {bits:#06b}");
    }
    // Truncated: one halfword of a 32-bit prefix, and an empty image.
    assert_eq!(decode_b_cond(&0xF000u16.to_le_bytes(), 0), None);
    assert_eq!(decode_b_cond(&[], 0), None);
    assert_eq!(decode_b_cond(&[0x0E], 0), None);
}

#[test]
fn encode_b_cond_picks_the_narrowest_encoding_and_roundtrips() {
    // Boundaries from A7.7.12: T1 spans -256..=254, T3 -1048576..=1048574.
    let site = 0x10_0000usize;
    let pc = site as u32 + 4;
    let cases: &[(u32, usize)] = &[
        (pc, 2),                   // zero displacement
        (pc + 254, 2),             // widest forward T1
        (pc.wrapping_sub(256), 2), // widest backward T1
        (pc + 256, 4),             // one halfword past T1 → T3
        (pc.wrapping_sub(258), 4),
        (pc + 1_048_574, 4),             // widest forward T3
        (pc.wrapping_sub(1_048_576), 4), // widest backward T3
    ];
    let mut img = vec![0u8; 0x40_0000];
    for &(target, len) in cases {
        for bits in 0u8..=0b1101 {
            let cond = Cond::from_bits(bits).unwrap();
            let bytes = encode_b_cond(site, cond, target)
                .unwrap_or_else(|| panic!("in range: target {target:#x} cond {cond}"));
            assert_eq!(bytes.len(), len, "width for target {target:#x}");
            img[site..site + bytes.len()].copy_from_slice(&bytes);
            let got = decode_b_cond(&img, site).expect("decodes back");
            assert_eq!(got.cond, cond);
            assert_eq!(got.target, target, "roundtrip target {target:#x}");
            assert_eq!(got.len, len);
        }
    }
    // Just outside T3 in both directions.
    assert_eq!(encode_b_cond(site, Cond::Eq, pc + 1_048_576), None);
    assert_eq!(
        encode_b_cond(site, Cond::Eq, pc.wrapping_sub(1_048_578)),
        None
    );
    // Odd displacement: Thumb instructions are halfword aligned.
    assert_eq!(encode_b_cond(site, Cond::Eq, pc + 1), None);
    assert_eq!(encode_b_cond(site, Cond::Eq, pc + 0x1001), None);
    // `AL` has no conditional-branch encoding at either width.
    assert_eq!(encode_b_cond(site, Cond::Al, pc), None);
    assert_eq!(encode_b_cond(site, Cond::Al, pc + 0x1000), None);
}

#[test]
fn encode_b_cond_matches_the_hand_computed_t1_and_t3_vectors() {
    assert_eq!(encode_b_cond(0, Cond::Mi, 0x20), Some(vec![0x0E, 0xD4]));
    assert_eq!(
        encode_b_cond(0x1000, Cond::Mi, 0x1_1004),
        Some(vec![0x10, 0xF1, 0x00, 0x80])
    );
    // Backward, past T1's -256 floor: site 0x2000, target 0x1E04 → off =
    // -0x200, imm = -256 = 0xFFF00 over 20 bits, so S=J2=J1=1, imm6 = 0x3F,
    // imm11 = 0x700 → hw1 = 0xF6FF, hw2 = 0x8000|0x2000|0x800|0x700 = 0xAF00.
    assert_eq!(
        encode_b_cond(0x2000, Cond::Lt, 0x1E04),
        Some(vec![0xFF, 0xF6, 0x00, 0xAF])
    );
    // One halfword nearer and T1 reaches, so the narrow form is chosen instead.
    assert_eq!(
        encode_b_cond(0x2000, Cond::Lt, 0x1F04),
        Some(vec![0x80, 0xDB])
    );
}

#[test]
fn branch_kind_dispatches_and_displays() {
    assert_eq!(BranchKind::Bl.to_string(), "bl");
    assert_eq!(BranchKind::BWide.to_string(), "b.w");

    let site = 0x1000usize;
    let target = 0x2000u32;
    let mut img = vec![0u8; 0x4000];
    for kind in [BranchKind::Bl, BranchKind::BWide] {
        let bytes = kind.encode(site, target).expect("in range");
        img[site..site + 4].copy_from_slice(&bytes);
        assert_eq!(kind.decode(&img, site), Some(target));
    }
    // Each kind rejects the other's bytes: they differ only in hw2 bit 14.
    let bl = BranchKind::Bl.encode(site, target).unwrap();
    img[site..site + 4].copy_from_slice(&bl);
    assert_eq!(BranchKind::BWide.decode(&img, site), None);
    // Out of range is refused, not truncated.
    assert_eq!(BranchKind::Bl.encode(0, 0x0200_0000), None);
    assert_eq!(BranchKind::BWide.encode(0, 0x0200_0000), None);
}

#[test]
fn install_branch_writes_and_verifies_both_kinds() {
    let mut img = vec![0u8; 0x4000];
    for (site, kind) in [(0x100usize, BranchKind::Bl), (0x200, BranchKind::BWide)] {
        // Thumb bit set on the way in: masked off before encoding, so this is
        // the same request as the even address.
        install_branch(&mut img, site, kind, 0x1001).expect("in range");
        assert_eq!(kind.decode(&img, site), Some(0x1000));
        assert!(verify_branch(&img, site, kind, 0x1000).is_ok());
        assert!(verify_branch(&img, site, kind, 0x1001).is_ok()); // bit 0 ignored
                                                                  // Re-installing the same detour is idempotent.
        install_branch(&mut img, site, kind, 0x1000).expect("still in range");
        assert!(verify_branch(&img, site, kind, 0x1000).is_ok());
    }
}

#[test]
fn verify_branch_reports_a_wrong_target_a_wrong_kind_and_no_branch_at_all() {
    let mut img = vec![0u8; 0x4000];
    let site = 0x100usize;
    install_branch(&mut img, site, BranchKind::Bl, 0x1000).expect("in range");

    // Right kind, wrong target: `found` names what is actually there.
    let err = verify_branch(&img, site, BranchKind::Bl, 0x2000).unwrap_err();
    assert_eq!(
        err,
        InstallMismatch {
            site,
            kind: BranchKind::Bl,
            expected: 0x2000,
            found: Some(0x1000),
        }
    );
    assert_eq!(
        err.to_string(),
        "bl at 0x100: expected target 0x00002000, found 0x00001000"
    );
    // `expected` is stored masked, so the Thumb-bit form gives the same error.
    assert_eq!(
        verify_branch(&img, site, BranchKind::Bl, 0x2001).unwrap_err(),
        err
    );

    // Wrong kind at a real branch, and bytes that are no branch at all: both
    // are `found: None`.
    let err = verify_branch(&img, site, BranchKind::BWide, 0x1000).unwrap_err();
    assert_eq!(err.found, None);
    assert_eq!(
        err.to_string(),
        "b.w at 0x100: expected target 0x00001000, but no b.w decodes there"
    );
    let err = verify_branch(&img, 0x800, BranchKind::Bl, 0x1000).unwrap_err();
    assert_eq!(err.found, None);
    // `Error` is implemented, so this composes with any error framework.
    let dynamic: &dyn std::error::Error = &err;
    assert!(dynamic.to_string().contains("no bl decodes there"));
    assert!(dynamic.source().is_none());
}

#[test]
fn install_branch_writes_nothing_when_it_cannot_encode() {
    // Out of range for BL (> 16 MiB): nothing is written and the error carries
    // `found: None`.
    let mut img = vec![0u8; 0x100];
    let before = img.clone();
    let err = install_branch(&mut img, 0x10, BranchKind::Bl, 0x0200_0000).unwrap_err();
    assert_eq!(err.found, None);
    assert_eq!(err.expected, 0x0200_0000);
    assert_eq!(img, before, "a failed install must not touch the image");

    // Site too close to the end of the image for four bytes of branch.
    let mut small = vec![0u8; 6];
    let err = install_branch(&mut small, 4, BranchKind::BWide, 0x0).unwrap_err();
    assert_eq!(err.found, None);
    assert_eq!(err.site, 4);
    assert_eq!(small, vec![0u8; 6]);
    // Exactly four bytes of room is enough — the bound is `site + 4 <= len`.
    let mut exact = vec![0u8; 8];
    install_branch(&mut exact, 4, BranchKind::BWide, 0x8).expect("fits exactly");
    assert_eq!(decode_b_wide(&exact, 4), Some(0x8));
}

#[test]
fn crate_result_alias_defaults_to_asm_error() {
    fn build() -> Result<Vec<u8>> {
        let mut a = Asm::new();
        a.mov_reg(0, 8); // high register: only MOV (register) T1 can do this
        a.finish()
    }
    // `finish` pads the code to the pool's 4-byte alignment, hence the tail.
    assert_eq!(build().unwrap(), vec![0x40, 0x46, 0x00, 0x00]);

    // The second parameter is still free.
    fn check(img: &[u8]) -> Result<(), InstallMismatch> {
        verify_branch(img, 0, BranchKind::Bl, 0x10)
    }
    assert!(check(&[0u8; 8]).is_err());
}

#[test]
fn mov_reg_reaches_the_high_registers_and_preserves_the_flag_setting_alias() {
    let mut a = Asm::new();
    a.mov_reg(0, 8); // mov r0, r8  — rm's bit 3 rides in the 4-bit Rm field
    a.mov_reg(9, 1); // mov r9, r1  — rd's bit 3 is the D bit
    a.mov_reg(15, 14); // mov pc, lr — a branch, but architecturally a MOV
    a.movs_reg(1, 2); // movs r1, r2
    a.lsls_imm(1, 2, 0); // the A5-2 footnote alias of the line above
    let code = a.finish().expect("no fixups");
    let hw = |i: usize| u16::from_le_bytes([code[i * 2], code[i * 2 + 1]]);
    assert_eq!(hw(0), 0x4600 | (8 << 3)); // 0x4640
    assert_eq!(hw(1), 0x4600 | (1 << 7) | (1 << 3) | 1); // 0x4689
    assert_eq!(hw(2), 0x4600 | (1 << 7) | (14 << 3) | 7); // 0x46F7
    assert_eq!(hw(3), (2 << 3) | 1); // 0x0011
    assert_eq!(hw(3), hw(4), "lsls #0 IS movs (A5-2 footnote a)");
    // The old 0.1.0 lowering (`adds rd, rm, #0`, 0x1C00 class) is gone.
    assert_eq!(hw(0) & 0xFE00, 0x4600);
    assert_ne!(hw(0) & 0xFE00, 0x1C00);
}

#[test]
fn cond_bits_roundtrip_suffixes_and_inversions() {
    // `Cond` is part of this crate's public surface (re-exported for
    // `decode_b_cond`/`encode_b_cond`), so exercise the whole table.
    let all = [
        (0b0000u8, Cond::Eq, "eq", Cond::Ne),
        (0b0001, Cond::Ne, "ne", Cond::Eq),
        (0b0010, Cond::Hs, "hs", Cond::Lo),
        (0b0011, Cond::Lo, "lo", Cond::Hs),
        (0b0100, Cond::Mi, "mi", Cond::Pl),
        (0b0101, Cond::Pl, "pl", Cond::Mi),
        (0b0110, Cond::Vs, "vs", Cond::Vc),
        (0b0111, Cond::Vc, "vc", Cond::Vs),
        (0b1000, Cond::Hi, "hi", Cond::Ls),
        (0b1001, Cond::Ls, "ls", Cond::Hi),
        (0b1010, Cond::Ge, "ge", Cond::Lt),
        (0b1011, Cond::Lt, "lt", Cond::Ge),
        (0b1100, Cond::Gt, "gt", Cond::Le),
        (0b1101, Cond::Le, "le", Cond::Gt),
        (0b1110, Cond::Al, "", Cond::Al),
    ];
    for &(bits, cond, suffix, inverted) in &all {
        assert_eq!(Cond::from_bits(bits), Some(cond), "from_bits {bits:#06b}");
        assert_eq!(cond.bits(), bits);
        assert_eq!(cond.suffix(), suffix);
        assert_eq!(cond.to_string(), suffix);
        assert_eq!(cond.invert(), inverted, "invert {suffix}");
        assert_eq!(cond.invert().invert(), cond);
    }
    // `from_bits` masks to four bits, so the high bits of a byte are ignored.
    assert_eq!(Cond::from_bits(0xF0), Some(Cond::Eq));
    // 0b1111 is not a condition at all (SVC in the 16-bit space, reserved in
    // the 32-bit one), so there is no fifteenth variant to invent.
    assert_eq!(Cond::from_bits(0b1111), None);
    assert_eq!(Cond::from_bits(0xFF), None);
}

/// The `try_read_*` family exists so a scan can walk to the end of an image
/// without the caller hand-rolling the bound. An offset near `usize::MAX`
/// used to overflow the `at + n` *before* `get` saw it: a panic in debug, and
/// in release a wrapped range that can land back in bounds and hand back the
/// wrong bytes. The value is not hypothetical — a handler pointer read out of
/// erased flash is `0xFFFF_FFFF`, and masked to even that is `0xFFFF_FFFE`,
/// which is precisely the offset that overflows on a 32-bit target.
#[test]
fn try_reads_refuse_an_offset_that_would_overflow_rather_than_panicking() {
    let img = [0xAAu8; 8];
    for at in [usize::MAX, usize::MAX - 1, usize::MAX - 3] {
        assert_eq!(try_read_u8(&img, at), None, "u8 at {at:#x}");
        assert_eq!(try_read_u16(&img, at), None, "u16 at {at:#x}");
        assert_eq!(try_read_u32(&img, at), None, "u32 at {at:#x}");
    }
    // The in-bounds answers are unchanged.
    assert_eq!(try_read_u16(&img, 6), Some(0xAAAA));
    assert_eq!(try_read_u32(&img, 4), Some(0xAAAA_AAAA));
    assert_eq!(try_read_u32(&img, 5), None);
}

/// `len` is the caller's number, not the image's, so the free-space scan has to
/// survive one large enough to overflow the end-of-window calculation. The
/// honest answer is "no run that big exists", not a panic and not a wrapped
/// range that appears to fit.
#[test]
fn free_space_refuses_a_length_that_would_overflow_the_window() {
    let img = [0xFFu8; 8];
    assert_eq!(find_free_space(&img, usize::MAX, 1, 1), None);
    assert_eq!(find_free_space(&img, usize::MAX, 1, 0), None);
    assert_eq!(find_free_space(&img, usize::MAX - 1, 4, 4), None);
    // The ordinary answers are unchanged.
    assert_eq!(find_free_space(&img, 8, 1, 0), Some(0));
    assert_eq!(find_free_space(&img, 4, 4, 1), Some(4));
}

/// `decode_bl` and `decode_b_wide` take an offset a caller may have derived from
/// image content — a pointer read out of erased flash is `0xFFFF_FFFF` — so the
/// end-of-read calculation must not wrap. Answering `None` is right; panicking
/// in debug, or in release reading four bytes from a wrapped offset that happens
/// to land back in bounds, is not.
#[test]
fn branch_decoders_refuse_an_offset_that_would_overflow() {
    let img = [0u8; 8];
    for at in [usize::MAX, usize::MAX - 3] {
        assert_eq!(decode_bl(&img, at), None, "decode_bl at {at:#x}");
        assert_eq!(decode_b_wide(&img, at), None, "decode_b_wide at {at:#x}");
    }
    // A real `bl` at a sane offset still decodes, so the guard has not eaten it.
    let mut img = vec![0u8; 8];
    img[0..4].copy_from_slice(&encode_bl(0, 0x40).unwrap());
    assert_eq!(decode_bl(&img, 0), Some(0x40));
}

// ---------------------------------------------------------------------------
// Asm operand validation.
//
// Every emitter ORs its arguments into a fixed encoding. Before this was
// checked, an out-of-range operand did not fail — it overflowed its field and
// silently assembled to a *different instruction*. `push(0x4000)` produced
// `0xF400`, which is not a push at all but the first halfword of a 32-bit
// instruction, so the two following bytes got swallowed as its second halfword
// and every subsequent instruction decoded from the wrong offset.
//
// The contract is: bad operands are reported by `finish()`, never encoded.
// ---------------------------------------------------------------------------

/// Assemble one instruction with a deliberately bad operand and return the
/// error `finish` gives back.
fn rejected(build: impl FnOnce(&mut Asm)) -> String {
    let mut a = Asm::new();
    build(&mut a);
    match a.finish() {
        Ok(bytes) => panic!("expected rejection, assembled {bytes:02x?}"),
        Err(e) => e.to_string(),
    }
}

/// Assemble and require success, returning just the instruction stream.
/// `finish` pads to 4 bytes for the literal pool, so a lone halfword comes
/// back with two zero bytes after it; the tests below are about the encoding.
fn accepted(build: impl FnOnce(&mut Asm)) -> Vec<u8> {
    let mut a = Asm::new();
    build(&mut a);
    a.finish().expect("expected this to assemble")
}

/// `accepted`, narrowed to the single halfword the emitter produced.
fn accepted_hw(build: impl FnOnce(&mut Asm)) -> [u8; 2] {
    let b = accepted(build);
    [b[0], b[1]]
}

#[test]
fn push_with_a_reglist_that_overflows_its_field_is_rejected_not_encoded() {
    // The regression case. 0xB400 | 0x4000 == 0xF400: hw1[15:11] == 0b11110,
    // which is a 32-bit prefix, so this desynchronises the whole stream.
    let e = rejected(|a| a.push(0x4000));
    assert!(e.contains("push"), "{e}");
    assert!(e.contains("outside R0-R7"), "{e}");

    // And the legitimate forms still work, at the values the doc now cites.
    assert_eq!(accepted_hw(|a| a.push(0x0100)), 0xB500u16.to_le_bytes());
    assert_eq!(accepted_hw(|a| a.push(0x0103)), 0xB503u16.to_le_bytes());
    assert_eq!(accepted_hw(|a| a.pop(0x0100)), 0xBD00u16.to_le_bytes());
    assert_eq!(accepted_hw(|a| a.pop(0x0103)), 0xBD03u16.to_le_bytes());
}

#[test]
fn push_and_pop_accept_the_widest_list_the_encoding_can_hold() {
    // 0x1FF is every bit the 16-bit encoding has: `push {r0-r7, lr}` /
    // `pop {r0-r7, pc}`, which is the frame save and return of any handler that
    // uses all the low registers — the most common prologue there is. The
    // bound is inclusive; rejecting the maximum itself would make that
    // prologue unassemblable, so a stub could not be built at all.
    assert_eq!(accepted_hw(|a| a.push(0x01FF)), 0xB5FFu16.to_le_bytes());
    assert_eq!(accepted_hw(|a| a.pop(0x01FF)), 0xBDFFu16.to_le_bytes());
    // One bit past the field is still refused.
    assert!(rejected(|a| a.push(0x0200)).contains("outside R0-R7"));
    assert!(rejected(|a| a.pop(0x0200)).contains("outside R0-R7"));
}

#[test]
fn an_empty_push_or_pop_list_is_unpredictable_and_refused() {
    assert!(rejected(|a| a.push(0)).contains("empty"));
    assert!(rejected(|a| a.pop(0)).contains("empty"));
}

#[test]
fn every_low_register_operand_rejects_a_high_register() {
    // One case per emitter per low-register field. r8 is the first value that
    // does not fit a 3-bit field.
    /// Emitter name paired with a call that gives one of its low-register
    /// fields a high register.
    type Case = (&'static str, fn(&mut Asm));
    let cases: Vec<Case> = vec![
        ("ldr_lit", |a| a.ldr_lit(8, 0xDEAD)),
        ("ldrb_imm", |a| a.ldrb_imm(8, 0, 0)),
        ("ldrb_imm", |a| a.ldrb_imm(0, 8, 0)),
        ("ldr_imm", |a| a.ldr_imm(8, 0, 0)),
        ("ldr_imm", |a| a.ldr_imm(0, 8, 0)),
        ("strh_imm", |a| a.strh_imm(8, 0, 0)),
        ("strh_imm", |a| a.strh_imm(0, 8, 0)),
        ("str_imm", |a| a.str_imm(8, 0, 0)),
        ("str_imm", |a| a.str_imm(0, 8, 0)),
        ("bics", |a| a.bics(8, 0)),
        ("bics", |a| a.bics(0, 8)),
        ("orrs", |a| a.orrs(8, 0)),
        ("orrs", |a| a.orrs(0, 8)),
        ("strb_imm", |a| a.strb_imm(8, 0, 0)),
        ("strb_imm", |a| a.strb_imm(0, 8, 0)),
        ("cmp_imm", |a| a.cmp_imm(8, 0)),
        ("cmp_reg", |a| a.cmp_reg(8, 0)),
        ("cmp_reg", |a| a.cmp_reg(0, 8)),
        ("movs_imm", |a| a.movs_imm(8, 0)),
        ("ldrb_reg", |a| a.ldrb_reg(8, 0, 0)),
        ("ldrb_reg", |a| a.ldrb_reg(0, 8, 0)),
        ("ldrb_reg", |a| a.ldrb_reg(0, 0, 8)),
        ("adds_imm", |a| a.adds_imm(8, 0)),
        ("subs_imm", |a| a.subs_imm(8, 0)),
        ("lsls_imm", |a| a.lsls_imm(8, 0, 0)),
        ("lsls_imm", |a| a.lsls_imm(0, 8, 0)),
        ("lsrs_imm", |a| a.lsrs_imm(8, 0, 1)),
        ("lsrs_imm", |a| a.lsrs_imm(0, 8, 1)),
        ("adds_reg", |a| a.adds_reg(8, 0, 0)),
        ("adds_reg", |a| a.adds_reg(0, 8, 0)),
        ("adds_reg", |a| a.adds_reg(0, 0, 8)),
        ("movs_reg", |a| a.movs_reg(8, 0)),
        ("movs_reg", |a| a.movs_reg(0, 8)),
        ("adr", |a| a.adr(8, 0)),
    ];
    for (name, build) in cases {
        let e = rejected(build);
        assert!(
            e.starts_with(name) && e.contains("low register"),
            "{name}: unhelpful or missing rejection: {e}"
        );
    }
}

// `Asm::imm`'s second guard, `step > 1 && v % step != 0`, cannot be tested at
// `step == 1`: admitting 1 into the branch changes nothing, because `v % 1` is
// 0 for every `v`. The only step values any emitter passes are 1, 2 and 4, and
// 0 is refused by the `step > 1` test either way, so no call can reach a
// modulo by zero. There is nothing here to cover beyond the steps below.
#[test]
fn immediate_fields_reject_oversized_and_unaligned_values() {
    // (emitter, just-past-the-maximum, misaligned-but-in-range)
    assert!(rejected(|a| a.ldrb_imm(0, 1, 32)).contains("exceeds maximum 31"));
    assert!(rejected(|a| a.strb_imm(0, 1, 32)).contains("exceeds maximum 31"));
    assert!(rejected(|a| a.lsls_imm(0, 1, 32)).contains("exceeds maximum 31"));
    assert!(rejected(|a| a.lsrs_imm(0, 1, 32)).contains("exceeds maximum 31"));

    assert!(rejected(|a| a.ldr_imm(0, 1, 128)).contains("exceeds maximum 124"));
    assert!(rejected(|a| a.ldr_imm(0, 1, 2)).contains("multiple of 4"));
    assert!(rejected(|a| a.str_imm(0, 1, 128)).contains("exceeds maximum 124"));
    assert!(rejected(|a| a.str_imm(0, 1, 2)).contains("multiple of 4"));

    assert!(rejected(|a| a.strh_imm(0, 1, 64)).contains("exceeds maximum 62"));
    assert!(rejected(|a| a.strh_imm(0, 1, 1)).contains("multiple of 2"));

    // The maxima themselves are accepted.
    accepted(|a| a.ldrb_imm(0, 1, 31));
    accepted(|a| a.ldr_imm(0, 1, 124));
    accepted(|a| a.str_imm(0, 1, 124));
    accepted(|a| a.strh_imm(0, 1, 62));
    accepted(|a| a.lsls_imm(0, 1, 31));
    // lsrs #0 is legal and means #32 (DecodeImmShift), so it is not rejected.
    accepted(|a| a.lsrs_imm(0, 1, 0));
}

#[test]
fn full_width_register_operands_reject_only_values_above_r15() {
    for r in 0..=15u16 {
        accepted(|a| a.bx(r));
        accepted(|a| a.mov_reg(r, 0));
        accepted(|a| a.mov_reg(0, r));
        if r != 15 {
            accepted(|a| a.blx(r));
        }
    }
    assert!(rejected(|a| a.bx(16)).contains("R0-R15"));
    assert!(rejected(|a| a.blx(16)).contains("R0-R15"));
    assert!(rejected(|a| a.mov_reg(16, 0)).contains("R0-R15"));
    assert!(rejected(|a| a.mov_reg(0, 16)).contains("R0-R15"));
    // blx pc is encodable but UNPREDICTABLE, so it is refused by name.
    assert!(rejected(|a| a.blx(15)).contains("UNPREDICTABLE"));
}

#[test]
fn binding_a_label_that_was_never_reserved_is_an_error_not_a_panic() {
    let e = rejected(|a| {
        a.bind(7);
        a.movs_imm(0, 1);
    });
    assert!(e.contains("never reserved"), "{e}");
}

#[test]
fn the_first_bad_operand_is_the_one_reported() {
    // A later failure must not displace the one the caller has to fix.
    let e = rejected(|a| {
        a.movs_imm(0, 1);
        a.push(0x4000);
        a.bx(16);
    });
    assert!(e.starts_with("push"), "{e}");
}

#[test]
fn a_rejected_operand_never_reaches_the_output() {
    // The bytes are unobservable through the public API once finish() errors,
    // which is the point: there is no path that yields the corrupt encoding.
    let mut a = Asm::new();
    a.movs_imm(0, 1);
    a.ldrb_imm(0, 0, 99); // bad
    assert!(a.finish().is_err());
}

#[test]
fn raw16_stays_raw() {
    // The documented escape hatch: raw16 is the one emitter that promises
    // nothing, so it must keep accepting any halfword including 0xF400.
    assert_eq!(accepted_hw(|a| a.raw16(0xF400)), 0xF400u16.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Asm emitters, checked against the decoder rather than against themselves.
//
// Every emitter is a single OR of shifted fields, and a test that recomputes
// that same expression cannot see a mistake in it — that is precisely how a
// `Rd << 12` where the manual says `<< 8` survived fourteen tests at 100%
// coverage elsewhere in this crate. Mutation testing put a number on the gap:
// 80 surviving mutants in `Asm`, including `<<` flipped to `>>` in `ldr_lit`,
// `cmp_imm` and `adr` — which drops the register field entirely and silently
// assembles against `r0`.
//
// So the oracle here is the *decoder*, which is corroborated byte-for-byte
// against LLVM by the conformance suite and shares no code with the emitters.
// Assemble, decode, and require the instruction that comes back to be the one
// the call asked for. Operands are chosen so no two fields hold the same
// value: a test using `r1, r1` cannot tell two swapped register fields apart.
// ---------------------------------------------------------------------------

/// Assemble one instruction and disassemble the result.
fn round_trip(build: impl FnOnce(&mut Asm)) -> String {
    let mut a = Asm::new();
    build(&mut a);
    let bytes = a.finish().expect("should assemble");
    crate::isa::decode_at_with(&bytes, 0, 0, false)
        .expect("emitted bytes should decode")
        .to_string()
}

#[test]
fn every_emitter_assembles_to_the_instruction_its_name_promises() {
    type Case = (fn(&mut Asm), &'static str);
    let cases: Vec<Case> = vec![
        (|a| a.ldrb_imm(1, 2, 5), "ldrb r1, [r2, #5]"),
        (|a| a.ldr_imm(1, 2, 8), "ldr r1, [r2, #8]"),
        (|a| a.strh_imm(1, 2, 6), "strh r1, [r2, #6]"),
        (|a| a.str_imm(1, 2, 8), "str r1, [r2, #8]"),
        (|a| a.bics(1, 2), "bics r1, r2"),
        (|a| a.orrs(1, 2), "orrs r1, r2"),
        (|a| a.strb_imm(1, 2, 5), "strb r1, [r2, #5]"),
        (|a| a.cmp_imm(1, 7), "cmp r1, #7"),
        (|a| a.cmp_reg(1, 2), "cmp r1, r2"),
        (|a| a.movs_imm(1, 7), "movs r1, #7"),
        (|a| a.push(0x105), "push {r0, r2, lr}"),
        (|a| a.pop(0x105), "pop {r0, r2, pc}"),
        (|a| a.blx(3), "blx r3"),
        (|a| a.bx(3), "bx r3"),
        (|a| a.ldrb_reg(1, 2, 3), "ldrb r1, [r2, r3]"),
        (|a| a.adds_imm(1, 7), "adds r1, #7"),
        (|a| a.subs_imm(1, 7), "subs r1, #7"),
        (|a| a.lsls_imm(1, 2, 3), "lsls r1, r2, #3"),
        (|a| a.lsrs_imm(1, 2, 3), "lsrs r1, r2, #3"),
        (|a| a.adds_reg(1, 2, 3), "adds r1, r2, r3"),
        (|a| a.mov_reg(9, 3), "mov r9, r3"),
        (|a| a.movs_reg(1, 2), "movs r1, r2"),
    ];
    for (build, want) in cases {
        assert_eq!(round_trip(build), want);
    }
}

#[test]
fn the_register_field_of_every_emitter_that_has_one_is_actually_read() {
    // Sweeping the register across its whole range is what distinguishes a
    // real shift from a dropped one: `rt >> 8` and `rt << 8` agree only at
    // `rt == 0`, so a single-register test would pass either way.
    for r in 0..8u16 {
        assert_eq!(
            round_trip(|a| a.ldr_lit(r, 0xDEAD_BEEF)),
            format!("ldr r{r}, [pc, #0], 0x4")
        );
        assert_eq!(round_trip(|a| a.cmp_imm(r, 7)), format!("cmp r{r}, #7"));
        assert_eq!(round_trip(|a| a.movs_imm(r, 7)), format!("movs r{r}, #7"));
        assert_eq!(round_trip(|a| a.adds_imm(r, 7)), format!("adds r{r}, #7"));
        assert_eq!(round_trip(|a| a.subs_imm(r, 7)), format!("subs r{r}, #7"));
        assert_eq!(round_trip(|a| a.bx(r)), format!("bx r{r}"));
        assert_eq!(
            round_trip(|a| a.movs_reg(r, 7 - r)),
            format!("movs r{r}, r{}", 7 - r)
        );
    }
    // r13/r14/r15 print as `sp`/`lr`/`pc`, which is what UAL calls them.
    for r in 0..16u16 {
        let name = match r {
            13 => "sp".to_string(),
            14 => "lr".to_string(),
            15 => "pc".to_string(),
            n => format!("r{n}"),
        };
        assert_eq!(round_trip(|a| a.mov_reg(r, 3)), format!("mov {name}, r3"));
    }
}

#[test]
fn the_literal_pool_and_data_blobs_land_where_the_instruction_points() {
    // `ldr_lit` is patched at `finish`, so the displacement is computed from
    // the final layout rather than emitted up front. The pool word itself is
    // checked, not just the instruction: a correct `ldr` pointing at the wrong
    // word is the failure mode that matters.
    let mut a = Asm::new();
    a.ldr_lit(3, 0xDEAD_BEEF);
    let bytes = a.finish().unwrap();
    assert_eq!(bytes, vec![0x00, 0x4B, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE]);
    assert_eq!(
        crate::isa::decode_at_with(&bytes, 0, 0, false)
            .unwrap()
            .to_string(),
        "ldr r3, [pc, #0], 0x4"
    );

    // Two references to the same value share one pool word, in first-reference
    // order, and both `ldr`s resolve to it.
    let mut a = Asm::new();
    a.ldr_lit(0, 0x1111_2222);
    a.ldr_lit(1, 0x1111_2222);
    let bytes = a.finish().unwrap();
    assert_eq!(&bytes[4..], &[0x22, 0x22, 0x11, 0x11], "one word, not two");

    let mut a = Asm::new();
    let blob = a.data_blob(vec![1, 2, 3, 4]);
    a.adr(5, blob);
    let bytes = a.finish().unwrap();
    assert_eq!(bytes, vec![0x00, 0xA5, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]);
    assert_eq!(
        crate::isa::decode_at_with(&bytes, 0, 0, false)
            .unwrap()
            .to_string(),
        "adr r5, 0x4"
    );
}

#[test]
fn a_bound_label_resolves_to_the_offset_it_was_bound_at() {
    let mut a = Asm::new();
    let l = a.label();
    a.beq(l);
    a.movs_imm(0, 1);
    a.bind(l);
    a.bx(14);
    let bytes = a.finish().unwrap();
    assert_eq!(bytes, vec![0x00, 0xD0, 0x01, 0x20, 0x70, 0x47, 0x00, 0x00]);
    assert_eq!(
        crate::isa::decode_at_with(&bytes, 0, 0, false)
            .unwrap()
            .to_string(),
        "beq 0x4"
    );
    assert_eq!(
        crate::isa::decode_at_with(&bytes, 4, 4, false)
            .unwrap()
            .to_string(),
        "bx lr"
    );
}

// ---------------------------------------------------------------------------
// 0.11.0: the consumer-requested search and classification surface.
// ---------------------------------------------------------------------------

#[test]
fn masked_search_matches_dont_care_bits_and_only_on_halfword_boundaries() {
    // `bl` is `1111 0Sii iiii iiii` + `11J1 Jiii iiii iiii`: the top five bits
    // of each halfword identify it and the rest is displacement, which is why
    // a byte search cannot find "any bl".
    let any_bl = [(0xF000u16, 0xF800u16), (0xD000u16, 0xD000u16)];

    // movs r0,#1 | bl +0 | movs r1,#2
    let image = [0x01, 0x20, 0xFF, 0xF7, 0xFE, 0xFF, 0x02, 0x21];
    assert_eq!(find(&image, Needle::Masked(&any_bl), 0), Some(2));
    // Searching past it finds nothing more.
    assert_eq!(find(&image, Needle::Masked(&any_bl), 4), None);

    // A pattern with no don't-care bits behaves like an exact halfword search.
    let exact = [(0x2001u16, 0xFFFFu16)];
    assert_eq!(find(&image, Needle::Masked(&exact), 0), Some(0));
    assert_eq!(find(&image, Needle::Masked(&[(0x2002, 0xFFFF)]), 0), None);

    // Odd offsets are never reported, even when the bytes there do match.
    // The halfwords at even offsets are 0x2001, 0xF7FF, 0xFFFE, 0x2102; read
    // from offset 3 the bytes spell 0xFEF7, which is not an instruction — it
    // is the tail of the `bl` glued to the head of its second halfword. A
    // byte-granular scan would report it and a caller would patch nonsense.
    let straddle = [(0xFEF7u16, 0xFFFFu16)];
    assert_eq!(
        image[3] as u16 | ((image[4] as u16) << 8),
        0xFEF7,
        "the straddling value really is present at offset 3"
    );
    assert_eq!(find(&image, Needle::Masked(&straddle), 0), None);

    // An odd `start` is rounded up rather than scanning from it.
    assert_eq!(find(&image, Needle::Masked(&any_bl), 1), Some(2));
    assert_eq!(find(&image, Needle::Masked(&any_bl), 3), None);
}

#[test]
fn an_empty_masked_pattern_matches_nothing_rather_than_everything() {
    let image = [0x01, 0x20, 0x70, 0x47];
    assert_eq!(find(&image, Needle::Masked(&[]), 0), None);
    // And a pattern longer than the image is not a match either.
    let long = [(0u16, 0u16); 8];
    assert_eq!(find(&image, Needle::Masked(&long), 0), None);
}

#[test]
fn find_one_refuses_to_choose_between_ambiguous_matches() {
    // Two identical instructions: a signature that cannot tell them apart has
    // not identified anything, and picking the first is how the wrong site
    // gets patched.
    let image = [0x01, 0x20, 0x70, 0x47, 0x01, 0x20, 0x70, 0x47];
    assert_eq!(
        find_one(&image, Needle::Bytes(&[0x01, 0x20])),
        Err(FindError::Ambiguous { count: 2, first: 0 })
    );
    // Unique: answered.
    assert_eq!(
        find_one(&image, Needle::Bytes(&[0x20, 0x70, 0x47, 0x01])),
        Ok(1)
    );
    // Absent: said so, distinctly from ambiguous.
    assert_eq!(
        find_one(&image, Needle::Bytes(&[0xDE, 0xAD])),
        Err(FindError::NotFound)
    );

    // Counting is non-overlapping: `AA AA AA` holds two `AA AA`, not three.
    let overlap = [0xAAu8, 0xAA, 0xAA, 0xAA];
    assert_eq!(
        find_one(&overlap, Needle::Bytes(&[0xAA, 0xAA])),
        Err(FindError::Ambiguous { count: 2, first: 0 })
    );

    // Every needle kind reaches the same machinery.
    assert_eq!(
        find_one(&image, Needle::Word(0x4770_2001)),
        Err(FindError::Ambiguous { count: 2, first: 0 })
    );
    assert_eq!(
        find_one(&image, Needle::Masked(&[(0x2001, 0xFFFF)])),
        Err(FindError::Ambiguous { count: 2, first: 0 })
    );
    let free = [0xFFu8; 8];
    assert_eq!(
        find_one(&free, Needle::FreeRun { len: 4, align: 4 }),
        Err(FindError::Ambiguous { count: 2, first: 0 })
    );
}

#[test]
fn find_error_says_which_failure_it_was() {
    assert_eq!(FindError::NotFound.to_string(), "no match");
    assert_eq!(
        FindError::Ambiguous {
            count: 3,
            first: 0x120
        }
        .to_string(),
        "3 matches, first at 0x120"
    );
    // It is a std::error::Error, so `?` works in a consumer's error type.
    fn as_err(e: FindError) -> Box<dyn std::error::Error> {
        Box::new(e)
    }
    assert!(as_err(FindError::NotFound).to_string().contains("no match"));
}

/// One region, as a slice. Written this way rather than `&[a..b]` because a
/// one-element array of `Range` is ambiguous enough that clippy rejects the
/// literal: it cannot tell it from `vec![a; b]`.
fn region(r: core::ops::Range<usize>) -> [core::ops::Range<usize>; 1] {
    [r]
}

/// 4 live | 8 free | 4 live | 16 free
fn two_holes() -> Vec<u8> {
    let mut v = vec![0x00; 4];
    v.extend(std::iter::repeat(0xFF).take(8));
    v.extend(std::iter::repeat(0x00).take(4));
    v.extend(std::iter::repeat(0xFF).take(16));
    v
}

#[test]
fn free_space_search_honours_the_regions_it_was_given() {
    let image = two_holes();
    let all = region(0..image.len());

    // First fit takes the near hole; largest fit keeps to the far one.
    assert_eq!(find_free_space_in(&image, 4, 4, &all, Fit::First), Some(4));
    assert_eq!(
        find_free_space_in(&image, 4, 4, &all, Fit::Largest),
        Some(16)
    );

    // A region that excludes the big hole cannot return it under either policy.
    assert_eq!(
        find_free_space_in(&image, 4, 4, &region(0..12), Fit::Largest),
        Some(4)
    );
    assert_eq!(
        find_free_space_in(&image, 4, 4, &region(0..12), Fit::First),
        Some(4)
    );

    // A region that excludes both holes finds nothing.
    assert_eq!(
        find_free_space_in(&image, 4, 4, &region(0..4), Fit::First),
        None
    );
    // No regions at all is not "the whole image".
    assert_eq!(find_free_space_in(&image, 4, 4, &[], Fit::First), None);
    assert_eq!(find_free_space_in(&image, 4, 4, &[], Fit::Largest), None);

    // Ranges may be given out of order and are considered on their merits.
    assert_eq!(
        find_free_space_in(&image, 4, 4, &[16..32, 0..12], Fit::Largest),
        Some(16)
    );

    // Ranges past the end are clipped rather than panicking.
    assert_eq!(
        find_free_space_in(&image, 4, 4, &region(0..usize::MAX), Fit::First),
        Some(4)
    );
    assert_eq!(
        find_free_space_in(&image, 4, 4, &region(100..200), Fit::First),
        None
    );

    // Nothing fits: the biggest hole is 16 bytes.
    assert_eq!(find_free_space_in(&image, 32, 4, &all, Fit::Largest), None);
    assert_eq!(find_free_space_in(&image, 32, 4, &all, Fit::First), None);
}

#[test]
fn free_space_alignment_is_applied_inside_the_run_not_to_its_start() {
    // A free run starting at an unaligned offset still offers aligned space,
    // and the amount it offers is measured from the aligned point — rounding
    // the start up without re-measuring is the bug `align` exists to avoid.
    let mut image = vec![0x00; 3];
    image.extend(std::iter::repeat(0xFF).take(9)); // free 3..12
    let all = region(0..image.len());
    // The run is 3..12; the first 4-aligned offset in it is 4, leaving 8 bytes.
    assert_eq!(find_free_space_in(&image, 8, 4, &all, Fit::First), Some(4));
    // Nine bytes will not fit even though the run is nine long, because the
    // usable part starts at 4.
    assert_eq!(find_free_space_in(&image, 9, 4, &all, Fit::First), None);
    // align 1 uses the whole run.
    assert_eq!(find_free_space_in(&image, 9, 1, &all, Fit::First), Some(3));
}

#[test]
#[should_panic(expected = "alignment must be at least 1 byte")]
fn free_space_in_rejects_a_zero_alignment() {
    let image = two_holes();
    let _ = find_free_space_in(&image, 4, 0, &region(0..image.len()), Fit::First);
}

#[test]
fn classify_branch_reports_the_width_that_decides_whether_a_patch_fits() {
    // `b.n` — 2 bytes, and not a kind `install_branch` can write. Overwriting
    // it with a 4-byte branch consumes the next instruction, which is exactly
    // what a caller needs to know before doing it.
    let narrow = [0xFE, 0xE7];
    assert_eq!(
        classify_branch(&narrow, 0),
        BranchAt::Direct {
            kind: None,
            width: 2,
            target: 0
        }
    );

    // `bl` — 4 bytes and installable.
    let bl = [0xFF, 0xF7, 0xFE, 0xFF];
    assert!(matches!(
        classify_branch(&bl, 0),
        BranchAt::Direct {
            kind: Some(BranchKind::Bl),
            width: 4,
            ..
        }
    ));

    // `b.w` — 4 bytes, the jump form.
    let bw = encode_b_wide(0, 0x100).expect("b.w +0x100");
    assert!(matches!(
        classify_branch(&bw, 0),
        BranchAt::Direct {
            kind: Some(BranchKind::BWide),
            width: 4,
            target: 0x100
        }
    ));

    // `bx lr` — indirect, 2 bytes: no target to compare against.
    assert_eq!(
        classify_branch(&[0x70, 0x47], 0),
        BranchAt::Indirect { width: 2 }
    );

    // Not a branch, and not decodable at all.
    assert_eq!(classify_branch(&[0x01, 0x20], 0), BranchAt::NotABranch);
    assert_eq!(classify_branch(&[0x00], 0), BranchAt::NotABranch);
    assert_eq!(classify_branch(&[], 0), BranchAt::NotABranch);

    // `cbz r0, +6` is direct but not installable.
    assert!(matches!(
        classify_branch(&[0x08, 0xB1], 0),
        BranchAt::Direct {
            kind: None,
            width: 2,
            ..
        }
    ));
}

#[test]
fn classify_branch_does_not_mistake_a_literal_pool_address_for_a_destination() {
    // `ldr.w pc, [pc, #0]` — a veneer. Its `Target` operand is the address of
    // the pool word, not where control goes, so this is Indirect.
    let v = crate::analysis::veneer(0, 0x1234).expect("veneer at 0");
    assert_eq!(classify_branch(&v, 0), BranchAt::Indirect { width: 4 });
}

#[test]
fn classify_branch_agrees_with_verify_branch_wherever_both_have_an_opinion() {
    // The two answer different questions; where they overlap they must not
    // disagree, or one of them is lying to a caller about the same bytes.
    for target in [0x100u32, 0x1000, 0x10_0000] {
        for kind in [BranchKind::Bl, BranchKind::BWide] {
            let bytes = kind.encode(0, target).expect("encodable");
            assert!(verify_branch(&bytes, 0, kind, target).is_ok());
            match classify_branch(&bytes, 0) {
                BranchAt::Direct {
                    kind: k,
                    width,
                    target: t,
                } => {
                    assert_eq!(k, Some(kind));
                    assert_eq!(width, 4);
                    assert_eq!(t, target);
                }
                other => panic!("{kind:?} to {target:#x} classified as {other:?}"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 0.11.1: scoped search, order-independent placement, the allocator, and the
// pre-flight install check.
// ---------------------------------------------------------------------------

/// Two equal-sized holes: 4..12 and 16..24.
fn two_equal_holes() -> Vec<u8> {
    let mut v = vec![0x00; 4];
    v.extend(std::iter::repeat(0xFF).take(8));
    v.extend(std::iter::repeat(0x00).take(4));
    v.extend(std::iter::repeat(0xFF).take(8));
    v
}

#[test]
fn free_space_placement_does_not_depend_on_the_order_the_regions_were_listed() {
    // The bug this test exists for shipped in 0.11.0 and a full green gate did
    // not see it, because nothing passed the same regions twice in different
    // orders. Two callers with identical intent got different stub addresses.
    let image = two_equal_holes();
    let a = 0..12;
    let b = 16..24;
    for fit in [Fit::First, Fit::Largest] {
        let forwards = find_free_space_in(&image, 4, 4, &[a.clone(), b.clone()], fit);
        let backwards = find_free_space_in(&image, 4, 4, &[b.clone(), a.clone()], fit);
        assert_eq!(forwards, backwards, "{fit:?} depends on region order");
        // And "first" means lowest address, which is what the name promises.
        assert_eq!(
            forwards,
            Some(4),
            "{fit:?} should resolve to the lower hole"
        );
    }
}

#[test]
fn largest_fit_still_prefers_the_bigger_hole_and_breaks_ties_downward() {
    // 4..12 is 8 bytes; 16..32 is 16. Largest must take the second whichever
    // order it hears about them, and First must take the first.
    let image = two_holes();
    let small = 0..12;
    let big = 16..32;
    for order in [[small.clone(), big.clone()], [big.clone(), small.clone()]] {
        assert_eq!(
            find_free_space_in(&image, 4, 4, &order, Fit::Largest),
            Some(16)
        );
        assert_eq!(
            find_free_space_in(&image, 4, 4, &order, Fit::First),
            Some(4)
        );
    }
}

#[test]
fn scoping_a_search_is_what_makes_an_ambiguous_signature_unique() {
    // movs r0,#1 | bx lr | movs r0,#1 | bx lr
    let image = [0x01, 0x20, 0x70, 0x47, 0x01, 0x20, 0x70, 0x47];
    let movs = Needle::Bytes(&[0x01, 0x20]);

    assert_eq!(
        find_one(&image, movs),
        Err(FindError::Ambiguous { count: 2, first: 0 })
    );
    assert_eq!(find_one_in(&image, movs, 0..4), Ok(0));
    assert_eq!(find_one_in(&image, movs, 4..8), Ok(4));
    assert_eq!(find_one_in(&image, movs, 2..4), Err(FindError::NotFound));

    // A match must lie *entirely* inside the window: one starting at 4 does
    // not fit in a window ending at 5.
    assert_eq!(find_in(&image, movs, 4..5), None);
    assert_eq!(find_in(&image, movs, 4..6), Some(4));

    // An empty or inverted window finds nothing rather than panicking.
    // Built rather than written as a literal: clippy rejects `6..2` on sight,
    // which is fair for real code and unhelpful when the reversal is the case
    // under test.
    let inverted = core::ops::Range { start: 6, end: 2 };
    assert_eq!(find_in(&image, movs, 4..4), None);
    assert_eq!(find_in(&image, movs, inverted), None);
    // A window past the end is clipped.
    assert_eq!(find_in(&image, movs, 4..usize::MAX), Some(4));
    assert_eq!(find_in(&image, movs, 100..200), None);
}

#[test]
fn a_window_does_not_move_what_counts_as_an_instruction_boundary() {
    // The reason `find_in` takes image coordinates rather than leaving callers
    // to slice: alignment is measured from the image origin. Starting a window
    // at an odd offset must not make odd offsets into instruction boundaries.
    let image = [0x01, 0x20, 0xFF, 0xF7, 0xFE, 0xFF, 0x02, 0x21];
    let straddling = Needle::Masked(&[(0xFEF7, 0xFFFF)]); // only at odd offset 3
    assert_eq!(find_in(&image, straddling, 0..8), None);
    assert_eq!(
        find_in(&image, straddling, 3..8),
        None,
        "an odd window start is not an origin"
    );

    // And a FreeRun's alignment is likewise the image's, not the window's.
    let mut free = vec![0x00, 0x00];
    free.extend(std::iter::repeat(0xFF).take(8)); // free 2..10
                                                  // 4-aligned placement inside a window starting at 2 is 4, never 2.
    assert_eq!(
        find_in(&free, Needle::FreeRun { len: 4, align: 4 }, 2..10),
        Some(4)
    );
}

#[test]
fn the_allocator_packs_and_never_hands_back_the_same_offset_twice() {
    let mut image = vec![0u8; 16];
    image.extend(std::iter::repeat(0xFF).take(64)); // free 16..80

    let mut space = FreeSpace::new(&image, &region(0..image.len()), 4, Straddle::Clip);
    assert_eq!(space.remaining(), 64);
    let a = space.alloc(12).unwrap();
    let b = space.alloc(8).unwrap();
    let c = space.alloc(4).unwrap();
    assert_eq!((a, b, c), (16, 28, 36));
    // Every allocation is 4-aligned and none overlaps its predecessor.
    for (at, len) in [(a, 12), (b, 8)] {
        assert_eq!(at % 4, 0);
        assert!(at + len <= b.max(c));
    }
    assert_eq!(space.remaining(), 80 - 40);

    // Nothing was written to the image; packing comes from the cursor, which
    // is the whole difference from repeating a search.
    assert!(image[16..80].iter().all(|&b| b == 0xFF));

    // `remaining` accounts for runs already stepped past, not just the
    // current one.
    let image2 = two_holes();
    let mut many = FreeSpace::new(&image2, &[0..12, 16..32], 4, Straddle::Clip);
    assert_eq!(many.remaining(), 8 + 16);
    assert_eq!(many.alloc(8), Some(4)); // consumes the whole first run
    assert_eq!(many.remaining(), 16);
    assert_eq!(many.alloc(8), Some(16)); // steps into the second
    assert_eq!(many.remaining(), 8);

    // An absurd request is refused rather than overflowing the offset.
    assert_eq!(many.alloc(usize::MAX), None);
    assert_eq!(many.remaining(), 8, "a refused allocation consumes nothing");

    // Exhaustion is reported, not wrapped around.
    let mut small = FreeSpace::new(&image, &region(0..image.len()), 4, Straddle::Clip);
    assert_eq!(small.alloc(64), Some(16));
    assert_eq!(small.alloc(1), None);
    assert_eq!(small.remaining(), 0);
}

#[test]
fn the_allocator_steps_across_runs_and_ignores_region_order() {
    let image = two_holes(); // free 4..12 and 16..32
    let holes = [0..12, 16..32];
    let reversed = [16..32, 0..12];

    let seq = |regions: &[core::ops::Range<usize>]| {
        let mut sp = FreeSpace::new(&image, regions, 4, Straddle::Clip);
        (0..4).map(|_| sp.alloc(8)).collect::<Vec<_>>()
    };
    // 4..12 gives one 8-byte block; 16..32 gives two.
    assert_eq!(seq(&holes), vec![Some(4), Some(16), Some(24), None]);
    assert_eq!(seq(&holes), seq(&reversed), "region order must not matter");

    // Overlapping regions describe the same bytes once, not twice.
    let overlapping = [0..20, 8..32];
    assert_eq!(seq(&overlapping), vec![Some(4), Some(16), Some(24), None]);
}

#[test]
fn straddle_reject_drops_a_run_that_continues_past_the_region() {
    // Free 4..28. A region of 4..16 clips it; the erased bytes carry on.
    let mut image = vec![0x00; 4];
    image.extend(std::iter::repeat(0xFF).take(24));
    image.extend(std::iter::repeat(0x00).take(4));

    let clip = FreeSpace::new(&image, &region(4..16), 4, Straddle::Clip);
    assert_eq!(
        clip.runs(),
        region(4..16),
        "clipping offers the covered part"
    );

    let reject = FreeSpace::new(&image, &region(4..16), 4, Straddle::Reject);
    assert!(
        reject.runs().is_empty(),
        "the run leaves the region, so it is not offered"
    );

    // A region that contains the whole run is fine under both.
    for straddle in [Straddle::Clip, Straddle::Reject] {
        let whole = FreeSpace::new(&image, &region(0..32), 4, straddle);
        assert_eq!(whole.runs(), region(4..28), "{straddle:?}");
    }

    // Straddling off the *front* is caught too.
    let front = FreeSpace::new(&image, &region(8..32), 4, Straddle::Reject);
    assert!(front.runs().is_empty(), "the run starts before the region");
    assert_eq!(
        FreeSpace::new(&image, &region(8..32), 4, Straddle::Clip).runs(),
        region(8..28)
    );
}

#[test]
fn free_space_exposes_what_it_was_built_from() {
    let image = two_holes();
    let sp = FreeSpace::new(&image, &region(0..image.len()), 4, Straddle::Clip);
    assert_eq!(sp.image(), &image[..]);
    assert_eq!(sp.runs(), [4..12, 16..32]);
    // An empty region list allocates nothing rather than the whole image.
    let mut none = FreeSpace::new(&image, &[], 4, Straddle::Clip);
    assert!(none.runs().is_empty());
    assert_eq!(none.alloc(1), None);
    assert_eq!(none.remaining(), 0);
    // Inverted ranges are dropped, not panicked on.
    let backwards = core::ops::Range { start: 12, end: 4 };
    let inverted = FreeSpace::new(&image, &[backwards], 4, Straddle::Clip);
    assert!(inverted.runs().is_empty());
}

#[test]
#[should_panic(expected = "alignment must be at least 1 byte")]
fn the_allocator_rejects_a_zero_alignment() {
    let image = two_holes();
    let _ = FreeSpace::new(&image, &region(0..image.len()), 0, Straddle::Clip);
}

#[test]
fn can_install_refuses_a_site_where_four_bytes_would_cut_an_instruction() {
    // Two 16-bit instructions: exactly four bytes, nothing cut.
    assert!(can_install(&[0x01, 0x20, 0x02, 0x21], 0, BranchKind::Bl).is_ok());
    // One 32-bit instruction: also exactly four.
    assert!(can_install(&[0xFF, 0xF7, 0xFE, 0xFF], 0, BranchKind::BWide).is_ok());

    // 16-bit then 32-bit: six bytes, so a four-byte branch leaves half a `bl`
    // behind. This is the case a `width` check alone does not catch, because
    // the *first* instruction's width is a perfectly innocent 2.
    let split = [0x01, 0x20, 0xFF, 0xF7, 0xFE, 0xFF];
    assert_eq!(
        can_install(&split, 0, BranchKind::Bl),
        Err(InstallHazard::SplitsInstruction {
            at: 2,
            displaced: 6
        })
    );
    // classify_branch alone would have said nothing alarming here.
    assert_eq!(classify_branch(&split, 0), BranchAt::NotABranch);

    // Past the end.
    assert_eq!(
        can_install(&[0x01, 0x20], 0, BranchKind::Bl),
        Err(InstallHazard::OutOfBounds {
            site: 0,
            image_len: 2
        })
    );
    assert!(matches!(
        can_install(&[0x01, 0x20, 0x02, 0x21], usize::MAX, BranchKind::Bl),
        Err(InstallHazard::OutOfBounds { .. })
    ));

    // Undecodable bytes are a refusal, not an assumption. `0x4500` is `CMP`
    // (register) T2 with both registers low, which A7.7.28 calls
    // UNPREDICTABLE and this crate therefore does not decode — found by sweep
    // rather than guessed, because the obvious candidate `0xDE00` is `UDF` and
    // decodes perfectly well.
    let bad = [0x00, 0x45, 0x00, 0x45];
    assert!(
        isa::decode_at(&bad, 0).is_none(),
        "the premise of this test is that these bytes do not decode"
    );
    assert_eq!(
        can_install(&bad, 0, BranchKind::Bl),
        Err(InstallHazard::NotAnInstruction { site: 0 })
    );

    // And undecodable bytes *after* a decodable first instruction are caught
    // at the offset they are actually at, not reported against the site.
    let late = [0x01, 0x20, 0x00, 0x45];
    assert_eq!(
        can_install(&late, 0, BranchKind::Bl),
        Err(InstallHazard::NotAnInstruction { site: 2 })
    );
}

#[test]
fn install_hazard_says_what_went_wrong() {
    assert!(InstallHazard::OutOfBounds {
        site: 0x10,
        image_len: 0x12
    }
    .to_string()
    .contains("runs past the end"));
    assert!(InstallHazard::NotAnInstruction { site: 0x10 }
        .to_string()
        .contains("nothing decodes"));
    assert!(InstallHazard::SplitsInstruction {
        at: 2,
        displaced: 6
    }
    .to_string()
    .contains("in half"));
    fn as_err(e: InstallHazard) -> Box<dyn std::error::Error> {
        Box::new(e)
    }
    assert!(!as_err(InstallHazard::NotAnInstruction { site: 0 })
        .to_string()
        .is_empty());
}

#[test]
fn can_install_agrees_with_what_detour_would_displace() {
    // `can_install` is the question `detour`'s planner already answers
    // internally; where both have an opinion they must not differ, or one of
    // them is telling a caller something the other contradicts.
    let mut image = vec![0u8; 0x2000];
    for b in image[0x1000..].iter_mut() {
        *b = 0xFF;
    }
    // movs r0,#1 · bl +0  — displaces 6, so a bare branch would cut it.
    image[0x100..0x106].copy_from_slice(&[0x01, 0x20, 0xFF, 0xF7, 0xFE, 0xFF]);
    assert!(matches!(
        can_install(&image, 0x100, BranchKind::Bl),
        Err(InstallHazard::SplitsInstruction { displaced: 6, .. })
    ));
    let d = crate::detour::tramp(&mut image, 0x100, 0x80).unwrap();
    assert_eq!(
        d.displaced, 6,
        "detour relocates exactly what can_install refused to cut"
    );
}

// ---------------------------------------------------------------------------
// The encoding digest.
//
// A consumer with a byte-exact golden test or a signed image needs to know
// when emitted bytes change. Finding out because a KAT failed — which is how
// 0.10.0's `mov_reg` fix reached one — is finding out too late and in the
// wrong place.
//
// So the emitted bytes of the whole 16-bit encoding space are hashed into one
// number, pinned here, and published in the changelog. A consumer compares two
// releases' digests instead of building their own corpus, and this test fails
// the moment any encoding moves, for any instruction, including ones nobody
// thought to write a test for.
//
// A failure here is NOT automatically a bug. It means: decide whether the
// change is intended, and if it is, update the constant and add the entry to
// `### Emitted bytes changed` in CHANGELOG.md. The point is that the decision
// is forced, not that the bytes are frozen.
//
// See docs/ENCODING-STABILITY.md.
// ---------------------------------------------------------------------------

/// FNV-1a, 64-bit. Written out rather than pulled in: the crate has no
/// dependencies and is to keep none, and a digest only has to be stable and
/// well-mixed, not cryptographic.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Every 16-bit halfword that decodes, re-encoded, hashed in order.
///
/// Both directions are covered: the halfword goes in, and what `isa::encode`
/// produces from the decoded instruction comes out. A change to either the
/// decoder's reading or an encoder's writing moves the digest.
fn encoding_digest() -> (u64, usize) {
    let mut buf: Vec<u8> = Vec::new();
    let mut decoded = 0usize;
    for hw in 0x0000u32..=0xFFFF {
        let hw = hw as u16;
        if isa::insn_len(hw) != 2 {
            continue;
        }
        let insn = match isa::decode_halfwords(hw, 0, 0, false) {
            Some(i) => i,
            None => continue,
        };
        decoded += 1;
        buf.extend_from_slice(&hw.to_le_bytes());
        match isa::encode(&insn) {
            Some((a, b)) => {
                buf.push(1);
                buf.extend_from_slice(&a.to_le_bytes());
                buf.extend_from_slice(&b.to_le_bytes());
            }
            None => buf.push(0),
        }
    }
    (fnv1a(&buf), decoded)
}

#[test]
fn the_emitted_encoding_corpus_has_not_moved() {
    // Update deliberately, and say so in CHANGELOG.md under
    // `### Emitted bytes changed`. Never update to make a red build green.
    const DIGEST: u64 = 0x0e06_fda2_5d6b_89e8;
    const DECODED: usize = 58_233;

    let (digest, decoded) = encoding_digest();
    assert_eq!(
        (digest, decoded),
        (DIGEST, DECODED),
        "\nEmitted bytes changed.\n\
         \x20 decoded halfwords: {decoded} (pinned {DECODED})\n\
         \x20 digest:            {digest:#018x} (pinned {DIGEST:#018x})\n\n\
         If that was intended, update both constants and add an entry to\n\
         `### Emitted bytes changed` in CHANGELOG.md naming what moved.\n\
         Consumers with golden tests or signed images read that section.\n"
    );
}

#[test]
fn a_masked_pattern_compares_each_halfword_at_its_own_offset() {
    // Mutation found this: `i * 2` became `i / 2`, which compares every pair
    // against the *first* halfword, and the existing tests still passed —
    // because their second pair happened to also match the first halfword.
    // A pattern whose halfwords are genuinely different is what tells them
    // apart.
    let image = [0x01, 0x20, 0x70, 0x47]; // movs r0,#1 · bx lr
    let in_order = [(0x2001u16, 0xFFFFu16), (0x4770u16, 0xFFFFu16)];
    let reversed = [(0x4770u16, 0xFFFFu16), (0x2001u16, 0xFFFFu16)];
    assert_eq!(find(&image, Needle::Masked(&in_order), 0), Some(0));
    assert_eq!(
        find(&image, Needle::Masked(&reversed), 0),
        None,
        "the order of the halfwords in the pattern has to matter"
    );
}

#[test]
fn a_masked_pattern_reaches_the_last_halfword_and_no_further() {
    // Mutation found this too: `pat.len() * 2` became `pat.len() + 2`, which
    // agrees for the two-halfword patterns every other test uses. A
    // one-halfword pattern matching the final instruction is what separates
    // them — with `+`, the bound is three bytes and the last halfword becomes
    // unreachable.
    let image = [0x01, 0x20, 0x70, 0x47];
    let bx_lr = [(0x4770u16, 0xFFFFu16)];
    assert_eq!(find(&image, Needle::Masked(&bx_lr), 0), Some(2));

    // And a three-halfword pattern must not read past the end: with `+` the
    // bound would be five bytes, so this would be attempted against a
    // four-byte image.
    let three = [
        (0x2001u16, 0xFFFFu16),
        (0x4770u16, 0xFFFFu16),
        (0x0000u16, 0x0000u16),
    ];
    assert_eq!(
        find(&image, Needle::Masked(&three), 0),
        None,
        "six bytes of pattern cannot match in a four-byte image"
    );
    // Give it the sixth byte and it matches, which pins the bound at 2*len.
    let longer = [0x01, 0x20, 0x70, 0x47, 0xAA, 0xBB];
    assert_eq!(find(&longer, Needle::Masked(&three), 0), Some(0));
}

// ---------------------------------------------------------------------------
// `Asm::finish`'s range checks.
//
// Mutation found these unexercised: the `ldr` literal displacement bound, the
// `adr` bound, and the arithmetic computing both. They matter more than most
// guards in this crate because they run at *layout* time — the point where the
// assembler decides what bytes come out — and the failure is silent: an
// out-of-range displacement that is not refused becomes a truncated one, so
// the emitted `ldr` reads from the wrong pool word and the code runs against a
// constant nobody chose.
// ---------------------------------------------------------------------------

/// An `Asm` holding one `ldr_lit` followed by `pad` filler halfwords, so the
/// pool sits a controlled distance away.
fn ldr_at_distance(pad: usize) -> Result<Vec<u8>, AsmError> {
    let mut a = Asm::new();
    a.ldr_lit(0, 0xDEAD_BEEF);
    for _ in 0..pad {
        a.raw16(0x46C0); // nop (mov r8, r8)
    }
    a.finish()
}

#[test]
fn the_ldr_literal_displacement_is_bounded_exactly_at_the_field() {
    // `LDR (literal)` T1 holds `imm8:'00'`, so the furthest reachable word is
    // `Align(pc,4) + 1020`. One word further has to be an error, not a
    // truncated displacement pointing at the wrong constant.
    let ok = ldr_at_distance(511).expect("1020 bytes away is the last reachable word");
    // The `ldr` encodes the maximum displacement, and the pool word is there.
    assert_eq!(
        u16::from_le_bytes([ok[0], ok[1]]),
        0x48FF,
        "imm8 should be 0xff"
    );
    assert_eq!(&ok[1024..1028], &0xDEAD_BEEFu32.to_le_bytes());

    let err = ldr_at_distance(512).expect_err("one word further cannot be encoded");
    assert!(
        err.to_string().contains("ldr literal out of range"),
        "{err}"
    );
    assert!(
        err.to_string().contains("256"),
        "the message should name the imm8: {err}"
    );
}

#[test]
fn the_adr_displacement_is_bounded_too() {
    // `ADR` T1 is the same `imm8:'00'` field measured from `Align(pc,4)`, and
    // a blob placed past it must be refused rather than wrapped.
    let build = |pad: usize| -> Result<Vec<u8>, AsmError> {
        let mut a = Asm::new();
        let blob = a.data_blob(vec![0xAA; 4]);
        a.adr(0, blob);
        for _ in 0..pad {
            a.raw16(0x46C0);
        }
        a.finish()
    };
    // Reachable: the blob lands within 1020 bytes of `Align(pc,4)`.
    let ok = build(500).expect("a near blob is reachable");
    assert_eq!(ok[1] & 0xF8, 0xA0, "should still be an adr");

    let err = build(520).expect_err("a blob past the field cannot be addressed");
    assert!(err.to_string().contains("adr target out of range"), "{err}");

    // And the displacement it encodes is pinned, not merely bounded. The
    // subtraction and the division are separate mutations and a layout where
    // `base == target` agrees with both of them by accident, so this uses one
    // where it does not: `adr r3, blob` at 0 with five filler halfwords puts
    // the blob at 12, `Align(pc,4)` at 4, and `(12 - 4) / 4 == 2`.
    let mut a = Asm::new();
    let blob = a.data_blob(vec![0x11, 0x22, 0x33, 0x44]);
    a.adr(3, blob);
    for _ in 0..5 {
        a.raw16(0x46C0);
    }
    let bytes = a.finish().unwrap();
    assert_eq!(
        &bytes[12..16],
        &[0x11, 0x22, 0x33, 0x44],
        "blob lands at 12"
    );
    assert_eq!(
        u16::from_le_bytes([bytes[0], bytes[1]]),
        0xA302,
        "adr r3, #8 — rd in bits 10:8, (target - Align(pc,4)) / 4 in the imm8"
    );
}

#[test]
fn a_literal_pool_word_is_shared_and_the_displacement_follows_the_layout() {
    // Two references to one value share a word, so the *second* `ldr` has a
    // shorter displacement than the first — which is the arithmetic
    // (`(off - pc) / 4`) that mutation flagged. Pinning both encodings pins
    // the subtraction and the division together.
    let mut a = Asm::new();
    a.ldr_lit(0, 0x1111_2222);
    a.raw16(0x46C0);
    a.ldr_lit(1, 0x1111_2222);
    let bytes = a.finish().unwrap();

    let first = u16::from_le_bytes([bytes[0], bytes[1]]);
    let second = u16::from_le_bytes([bytes[4], bytes[5]]);
    // Code is 6 bytes, padded to 8; the single pool word sits at 8.
    assert_eq!(&bytes[8..12], &0x1111_2222u32.to_le_bytes());
    // `LDR (literal)` T1 is `0x4800 | rt<<8 | imm8`; spelling both halves the
    // same way keeps the rt/imm8 split visible instead of pre-folding a zero.
    let ldr_lit = |rt: u16, imm8: u16| 0x4800 | (rt << 8) | imm8;
    // First `ldr` at 0: Align(0+4,4) = 4, (8-4)/4 = 1.
    assert_eq!(first, ldr_lit(0, 1), "first ldr: rt=r0, imm8=1");
    // Second at 4: Align(4+4,4) = 8, (8-8)/4 = 0.
    assert_eq!(second, ldr_lit(1, 0), "second ldr: rt=r1, imm8=0");
}

#[test]
fn the_masked_needle_step_is_two_bytes_per_halfword() {
    // `needle_len` feeds `find_one`'s non-overlapping advance. Mutation
    // changed `pat.len() * 2` to `+ 2` and `/ 2`, both of which agree with the
    // truth at the two-halfword patterns every other test uses. A
    // one-halfword and a three-halfword pattern are what separate them.
    // Six identical halfwords. The image has to be this long for the counts
    // to separate: with three halfwords a wrong step still lands on the same
    // answer by accident, which is how the mutant survived in the first place.
    let image = [0xAAu8, 0xBB].repeat(6);
    assert_eq!(image.len(), 12);

    // One halfword: step 2, so all six occurrences are found. With `+ 2` the
    // step would be 3, which rounds up to the next even offset and skips
    // every other one — three occurrences, not six.
    assert_eq!(
        find_one(&image, Needle::Masked(&[(0xBBAA, 0xFFFF)])),
        Err(FindError::Ambiguous { count: 6, first: 0 })
    );

    // Three halfwords: step 6, so two non-overlapping occurrences at 0 and 6.
    // With `/ 2` the step would be 1, and the scan would count every even
    // offset that still has six bytes after it — four, not two.
    let three = [(0xBBAAu16, 0xFFFFu16); 3];
    assert_eq!(
        find_one(&image, Needle::Masked(&three)),
        Err(FindError::Ambiguous { count: 2, first: 0 })
    );
}
