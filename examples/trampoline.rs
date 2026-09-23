//! Mirrors the example in README.md verbatim; CI runs this on every push so
//! the README's example can't silently drift from a working API.

use thumb_asm::{decode_bl, encode_bl, find_free_space, insert, Asm};

fn main() {
    let mut image = vec![0xFFu8; 0x10000]; // stand-in for a firmware dump

    let call_site = 0x2000;
    image[call_site..call_site + 4].copy_from_slice(&encode_bl(call_site, 0x100).unwrap());
    let original_target = decode_bl(&image, call_site).unwrap();

    let mut asm = Asm::new();
    asm.movs_imm(0, 0x01);
    asm.ldr_lit(1, original_target | 1); // Thumb bit set
    asm.bx(1);
    let code = asm
        .finish()
        .expect("small, self-contained, always in range");

    let free = find_free_space(&image, code.len(), 4, 0).expect("room for the trampoline");
    let target_addr = insert(&mut image, free, &code);
    image[call_site..call_site + 4].copy_from_slice(&encode_bl(call_site, target_addr).unwrap());

    assert_eq!(decode_bl(&image, call_site).unwrap() & !1, target_addr);
    println!("ok");
}
