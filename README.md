# thumb-asm

[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/MattJackson)

[![CI](https://github.com/MattJackson/thumb-asm/actions/workflows/dev.yml/badge.svg?branch=dev)](https://github.com/MattJackson/thumb-asm/actions/workflows/dev.yml)
[![crates.io](https://img.shields.io/crates/v/thumb-asm.svg)](https://crates.io/crates/thumb-asm)
[![docs.rs](https://img.shields.io/docsrs/thumb-asm)](https://docs.rs/thumb-asm)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![MSRV 1.58](https://img.shields.io/badge/MSRV-1.58-blue.svg)](#minimum-supported-rust-version)
[![dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](https://github.com/MattJackson/thumb-asm/blob/main/Cargo.toml)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-brightgreen.svg)](#design-and-what-this-is-not)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14762/badge)](https://www.bestpractices.dev/projects/14762)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/MattJackson/thumb-asm/badge)](https://scorecard.dev/viewer/?uri=github.com/MattJackson/thumb-asm)
[![REUSE status](https://api.reuse.software/badge/github.com/MattJackson/thumb-asm)](https://api.reuse.software/info/github.com/MattJackson/thumb-asm)

<!-- The Scorecard and REUSE badges above will read "unknown" until the first
     scheduled scorecard.yml run and the first time api.reuse.software scans a
     pushed branch. Both go green on their own after the push; neither needs an
     account. The two static badges are claims this file has to keep true:
     `dependencies: 0` is the empty `[dependencies]` table in Cargo.toml, and
     `unsafe: forbidden` is `#![forbid(unsafe_code)]` in src/lib.rs. If either
     ever stops being true, the badge is the thing to delete first. -->

<!-- Codecov. The upload is already wired into qa.yml's coverage job and fires
     as soon as the CODECOV_TOKEN secret exists (docs/SETUP.md, step 2) — no
     workflow edit needed. Kept commented out until then, because a badge that
     renders "unknown" for weeks is worse than no badge. Uncomment on the first
     green upload:
[![codecov](https://codecov.io/gh/MattJackson/thumb-asm/graph/badge.svg)](https://codecov.io/gh/MattJackson/thumb-asm)
-->

<!-- Deferred on purpose: a Thumb-ISA-coverage badge ("N encodings", "N% of the
     encoding space"). spec/THUMB-ISA.md tracks the real figure, but the total
     is still moving as the ISA build-out lands, and no job independently
     verifies the count — so any number in a badge would be an unverified claim
     rendered as a measurement. It goes in when a CI job computes it. -->

An **ARM Thumb decoder, instruction builder and detour installer** for Rust.

It operates on a flat `&[u8]` image — a firmware dump, a flash region, a blob
carved out of something larger — at the byte-offset level, where file offset
and load address are the same number. It decodes and re-encodes Thumb and
Thumb-2, assembles position-independent code, finds the places worth patching,
and installs a trampoline over live code: decode what a four-byte hook branch
would displace, move those instructions into a stub with their pc-relative
operands rewritten, branch back. It knows nothing about ELF, relocations, or
any particular device: which byte pattern to look for, where a table lives and
what a hook should do are all the caller's.

Pure safe Rust: `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`, no
dependencies beyond `std`, and no Cargo features to choose between.

```toml
[dependencies]
thumb-asm = "0.10"
```

## Status

**Pre-1.0, and 0.10.0 is a large release.** 0.1.0 was a 676-line assembler and
patch-site finder with 26 instruction encodings. 0.10.0 is roughly twenty
thousand lines: a decoder and encoder for essentially the whole Thumb and
Thumb-2 instruction set, an instruction relocator built on it, and a
trampoline installer built on that.

**The API is not frozen, and a minor bump may break it.** Three things that
shipped in 0.1.0 break here: `find_free_space` takes a required `align`
parameter, `Needle::FreeRun` became a struct variant, and `Asm::mov_reg` no
longer writes the condition flags, because it no longer lowers to
`adds rd, rm, #0`. The first two are compile errors; the third is a behaviour
change and is the one to read about before upgrading — it is in
[Design](#design-and-what-this-is-not) and, with the rest,
in [`CHANGELOG.md`](CHANGELOG.md).

**What is covered, and what is not.**
[`spec/THUMB-ISA.md`](https://github.com/MattJackson/thumb-asm/blob/main/spec/THUMB-ISA.md)
is the coverage map: it walks the 16-bit and 32-bit encoding spaces section by
section against Arm's own architecture reference manuals (DDI 0403E.e and DDI
0406C), one file of `src/isa/` per numbered sub-table, and states coverage in
counts rather than adjectives — see [ISA coverage](#isa-coverage) below for the
figures and how they are counted. The honest summary: the 16-bit space is
covered bar 1,157 halfwords that are named one at a time, the 32-bit space is
covered broadly but unevenly, and §5 and §6 of that document list the places
where the manual, or this crate, is not what a reader would assume. In
particular `Insn` has no channel for "this encoding is UNPREDICTABLE", so
*decoded* must not be read as *architecturally well-formed*; that is
deliberate, because a firmware image full of such encodings is exactly what a
reverse-engineer is looking for.

That is enough to disassemble a firmware image, follow its control flow, and
install a detour over live code. It is not a simulator, and nothing here
executes anything.

## What it does

The headline verb is `detour::tramp`. Everything else in the table is either
what it is built on or what you need around it.

```rust
let d = tramp(&mut image, site, hook)?;
```

That one call decodes the instructions a four-byte hook branch would displace,
relocates them into a stub with their pc-relative operands rewritten, branches
back to the instruction after the displaced region, and installs the hook — or
refuses, atomically and with a specific reason, when it cannot be done safely.
It is the difference between a library that reads Thumb and a library that
patches it, and it cannot be written without the decoder.

| Capability | Entry points | Notes |
| ---------- | ------------ | ----- |
| **Install a detour** | `detour::tramp`, `detour::detour`, `DetourOptions`, `Convention`, `Detour`, `DetourError` | Decode, relocate, branch back, install. Refuses rather than guesses: a site that is not an instruction boundary, a displaced instruction that is inside an `IT` block, a literal load whose pool would no longer be in reach, a stub that cannot be reached from the site. On any error the image is byte-for-byte unchanged |
| Decode and disassemble | `isa::Decoder`, `isa::decode_at`, `isa::decode_at_with`, `isa::decode_halfwords`, `isa::disassemble`, `isa::insn_len` | `Decoder` is an `Iterator<Item = Insn>` that walks a stream from a known start and tracks `ITSTATE`, so the instructions governed by an `IT` come back with their condition filled in rather than reported as unconditional |
| The decoded form | `Insn`, `Operand`, `Operands`, `Mem`, `AddrMode`, `Reg`, `FpReg`, `Shift`, `Width` | One shared vocabulary across all nineteen encoding-group modules. `Insn` carries its mnemonic, encoding name (`"T1"`, `"T3"`, …), address, width, condition and operands, and answers `is_branch`, `is_call`, `writes_pc` and `branch_target`. Decoding allocates nothing |
| Re-encode | `isa::encode`, `isa::encode_bytes` | The inverse of the decoder, and the crate's compliance proof. Dispatch is *verified*: every candidate is decoded again and compared before it is returned, so a group that accepts a neighbour's instruction wastes work instead of emitting the wrong encoding |
| Relocate one instruction | `relocate::relocate`, `relocate_with`, `relocate_bytes`, `Widen`, `RelocateError` | Move an instruction to a new address and have it still mean the same thing. Never redoes pc arithmetic — an `Operand::Target` is a resolved absolute address, so relocation holds the target still and asks whether the new displacement fits. `Align(PC, 4)` does not move linearly, which is the trap this exists to avoid |
| Analyse an image | `analysis::xrefs`, `function_start`, `literal_value`, `nop_fill`, `reachable`, `veneer` | `xrefs` is instruction-accurate and covers all four ways an image names an address — call, branch, literal-pool word, `adr`. `reachable` walks control flow from an entry point; `veneer` builds an 8-byte `ldr pc` stub for a target no branch encoding reaches |
| Search | `find`, `find_one`, `find_free_space`, `find_free_space_in`, `Needle`, `Fit` | One primitive over a `Needle::{Bytes, Word, FreeRun, Masked}`; every named finder is an overload of it. `Masked` takes `(value, mask)` halfword pairs, so "any `BL`" is `(0xF000, 0xF800)` — a thing `Bytes` cannot express, because the bytes differ at every call site — and matches halfword-aligned, since a byte-granular scan reports hits straddling two real instructions. `find_one` refuses to choose between ambiguous matches: a signature that matches three places has not identified a function, and patching the first is how a tool reports success and bricks a device. `find_free_space_in` restricts placement to regions the caller says are writable, because slicing the image instead moves the alignment origin |
| Read | `read_u8`, `read_u16`, `read_u32` and `try_read_u8`, `try_read_u16`, `try_read_u32` | Little-endian. The plain forms index the slice and so panic past the end of the image, for an offset a search already proved in bounds; the `try_` forms return `Option`, for a scan that walks to the end |
| Write and place | `write`, `insert` | `insert` copies a code blob into free space and returns the address it now lives at (offset == address on this flat mapping) |
| Assemble | `Asm` | Position-independent 16-bit Thumb: labels, a deduplicated 4-byte-aligned literal pool, data blobs appended after it, the conditional branch in all fourteen conditions (`b_cond`, plus `beq`/`bne`/… wrappers), and `raw16` for any halfword it cannot yet spell |
| Branch codec | `encode_bl`/`decode_bl`, `encode_b_wide`/`decode_b_wide`, `encode_b_cond`/`decode_b_cond`, `BranchKind`, `CondBranch` | `BL` T1, `B.W` T4 and the conditional branch, in both directions. A 32-bit Thumb instruction is two little-endian halfwords rather than a little-endian `u32`, and the `S:I1:I2` packing the wide branches share is handled for you |
| Install a branch | `install_branch`, `verify_branch`, `classify_branch`, `BranchAt`, `InstallMismatch` | The whole detour-installation pattern — encode, write, decode back to confirm — in one call, so a patch that did not land is an error and not a surprise later. `verify_branch` checks an assertion you supply; `classify_branch` asks what is actually there, and reports the **width**, which is what decides whether the patch fits: writing a 4-byte branch over a 16-bit `b` overwrites the instruction after it |
| Find call sites | `find_bl_sites`, `prologue_is_push_lr` | Every `BL` in the image that targets a given address, plus a cheap corroborating check for a function prologue. A blind even-offset scan, so it can land mid-instruction; `analysis::xrefs` supersedes it and answers the larger question soundly |
| Condition codes | `Cond` | The fourteen conditions plus `AL`, carrying the architectural bit values — `Cond::bits` and `Cond::from_bits` *are* the encoding — with `invert` and the UAL suffixes. `0b1111` is rejected rather than treated as a fifteenth condition, because the architecture does not define one |
| Dispatch tables | `CommandTable::{find, replace, walk}`, `CommandRecord` | Fixed-stride opcode → handler record arrays, for firmware that dispatches through a table instead of hardcoded call sites. The type holds only the geometry — base, stride, field offsets, terminator flag — and the caller supplies the numbers |
| Errors | `AsmError`, `InstallMismatch`, `thumb_asm::Result` | `Result<T, E = AsmError>` is the crate's alias. `Asm::finish` is fallible: an out-of-range branch, `ldr` literal or `adr`, or a label referenced and never bound, is an error rather than a mis-encoded instruction |

There are no feature flags. The crate is one dependency-free library and all
of the above is always compiled in.

## ISA coverage

Stated in counts, with the counting method, because a percentage on its own is
not checkable.

Thumb's length rule partitions every bit pattern a Thumb stream can present
into exactly two sets, and both are small enough to enumerate: **59,392** single
halfwords (`0x0000..=0xE7FF`) and **402,653,184** halfword pairs (the 6,144
values of `hw1` that begin a 32-bit instruction, times 65,536). The figures in
[`spec/THUMB-ISA.md`](https://github.com/MattJackson/thumb-asm/blob/main/spec/THUMB-ISA.md)
§4 are an exhaustive enumeration of all **402,712,576** of them — not a
sample — handed to the decoder at an address deliberately 2 mod 4, so that
every `Align(PC, 4)` form is exercised at the alignment where getting it wrong
shows.

- **16-bit: 58,233 of 59,392 halfwords decode — 98.05%.** The 1,159 exceptions
  are named one at a time in §1.3, §1.5 and §1.6 rather than left as a
  remainder. ThumbEE's re-assigned map is counted separately: 3,840 of its
  4,096 halfwords.
- **32-bit: over half of the 402,653,184 pairs decode**, per the
  module-by-module table in §4.2, whose rows partition the whole space so the
  total is a sum rather than an estimate.

**The 32-bit ratio is not a grade, and should not be read as one.** Most of
that space is UNDEFINED *by construction*: Table A5-9 leaves whole `op2` rows
unallocated, `t32_dp_reg` requires `hw2[15:12] == 0b1111` before any decoding
happens at all — a fifteen-sixteenths rejection that no table row states — and
most sub-tables allocate a minority of their opcode cells. **A decoder that
scored higher there would be wrong.** The useful claim is not the ratio but the
attribution: every pattern that does not decode falls under one of three stated
rules, and each module's tests enumerate its own holes and assert their total
as a literal, so a change in what decodes surfaces as a failing census rather
than as a silently different number. The 16-bit ratio *is* meaningful, because
that space is almost fully allocated.

## Examples

### Composing the primitives

Find free space, assemble a trampoline that tail-calls back into the original
code, and repoint a call site at it:

```rust
use thumb_asm::{decode_bl, encode_bl, find_free_space, insert, Asm};

let mut image = vec![0xFFu8; 0x10000]; // stand-in for a firmware dump

// Somewhere in `image`, a real BL instruction would already exist. For this
// example we fabricate one, calling an original handler at 0x100.
let call_site = 0x2000;
image[call_site..call_site + 4].copy_from_slice(&encode_bl(call_site, 0x100).unwrap());
let original_target = decode_bl(&image, call_site).unwrap();

// Assemble a tiny trampoline: load r0, then tail-call back to the original.
let mut asm = Asm::new();
asm.movs_imm(0, 0x01);
asm.ldr_lit(1, original_target | 1); // Thumb bit set
asm.bx(1);
let code = asm
    .finish()
    .expect("small, self-contained, always in range");

// Place it in free space and redirect the call site at it.
let free = find_free_space(&image, code.len(), 4, 0).expect("room for the trampoline");
let target_addr = insert(&mut image, free, &code);
image[call_site..call_site + 4].copy_from_slice(&encode_bl(call_site, target_addr).unwrap());

assert_eq!(decode_bl(&image, call_site).unwrap() & !1, target_addr);
```

That is not a sketch. Every line of code above is the body of
[`examples/trampoline.rs`](examples/trampoline.rs) — the example file adds only
a `fn main` wrapper and drops three of the explanatory comments — and
`cargo run --example trampoline` is a step in the CI gate on every push and
every pull request. If this example stops compiling, or stops asserting, the
build goes red.

### The same thing in one call

That example composes the primitives by hand, and it can, because it patches a
call site whose target it already knows. Patching *live code* — putting a hook
over an arbitrary address, where four bytes may straddle two instructions and
either of them may be pc-relative — is what `detour::tramp` is for:

```rust
use thumb_asm::detour::tramp;
use thumb_asm::{decode_bl, isa};

// A flat image: code at 0x100, erased flash from 0x200 on.
let mut image = vec![0u8; 0x400];
for b in image[0x200..].iter_mut() {
    *b = 0xff;
}
// movs r0, #1 · movs r1, #2
image[0x100..0x104].copy_from_slice(&[0x01, 0x20, 0x02, 0x21]);

let d = tramp(&mut image, 0x100, 0x80).unwrap();
assert_eq!(d.displaced, 4); // two 16-bit instructions, neither cut in half
assert_eq!(d.stub, 0x200); // the first 4-aligned free space
assert_eq!(decode_bl(&image, 0x100), Some(0x200)); // the site now calls it

// And the stub: call the hook, re-run what was displaced, branch back.
assert_eq!(
    isa::disassemble(&image, d.stub as usize, d.stub, 4),
    [
        "00000200: bl 0x80",
        "00000204: movs r0, #1",
        "00000206: movs r1, #2",
        "00000208: b.w 0x104",
    ]
);
```

This one is verbatim the module-level doctest on
[`thumb_asm::detour`](https://docs.rs/thumb-asm/latest/thumb_asm/detour/), so
`cargo test --doc` runs it — on every push and pull request in the fast gate,
and on all six cells of the `qa` OS and MSRV matrix.

`tramp` is `detour` with the defaults: a `BL` at the site, and a stub that
calls the hook and then continues. `DetourOptions` covers the two choices that
actually change the shape of the patch — `BranchKind::BWide` at a tail-call
site, where `lr` must survive, and `Convention::HookDecides`, which jumps to
the hook with `lr` untouched and `r12` pointing at the relocated code, so the
hook can run the original, skip it, or return on the caller's behalf. Give it
`scan_from`, a known instruction boundary at or before the site, and it also
*checks* — rather than assumes — that the site is an instruction boundary and
is not inside an `IT` block. Neither can be inferred from the site alone,
because a Thumb stream cannot be decoded backwards.

[`examples/`](https://github.com/MattJackson/thumb-asm/tree/main/examples) has
longer worked versions of both, and the rustdoc for the main entry points
carries runnable examples of its own, which `cargo test --doc` runs.

## Design, and what this is not

**Flat image, byte offsets, no loader.** The only address model is
`offset == address`. If your image is mapped somewhere else, do the arithmetic
before you call in. There is no ELF reader, no section table, no relocation
processing, and no symbol table.

**It decodes; it does not execute.** Every encoding claim here is a claim about
bit patterns, checked against the architecture manual and against LLVM — never
against a core running the instruction. Nothing in this crate simulates
anything, and it says nothing about whether a patched image behaves.

**Decoded is not the same as well-formed.** An encoding the architecture calls
UNPREDICTABLE — `pop.w {lr, pc}`, `cmp pc, r0`, `stm.w r0!, {r0, r1}` — is
decoded, because it is fully describable as an `Insn` and re-encodes to the
bytes it came from, and because a firmware image containing one is exactly what
a reverse-engineer is hunting for. `Insn` has no flag saying so. What *is*
refused is an encoding that cannot be represented faithfully: an unallocated
pattern, or one whose should-be-zero bit holds the wrong value, where decoding
would discard information and re-encode to a different pattern.

**Scan at a stride and you will land mid-instruction.** A Thumb stream has no
self-synchronising structure: `hw1[15:11]` is the only length rule, so a walk
that starts at the wrong halfword stays wrong until it happens to fall back
into phase. `find_bl_sites` is a blind even-offset scan and needs corroborating
(that is what `prologue_is_push_lr` is for); `isa::Decoder` and
`analysis::xrefs` walk from a known start instead and remove the need.

**Alignment is a parameter, not a caveat.** `Asm::finish` lays out its literal
pool assuming the code will be placed at a 4-byte-aligned address, because
`LDR (literal)` computes its base from `Align(PC, 4)`. So `find_free_space`
requires the alignment you need — `find_free_space(&image, len, 4, 0)` for
anything you are about to assemble, `1` for raw data — and the scan honours it
while searching rather than rounding up a run it already found, which would move
the start without moving the end. Through 0.1.0 this was documented rather than
enforced, and the one known consumer worked around it by over-asking for
`len + 16` bytes.

**Encoding hazards are named, not hidden.** Each of these is in the rustdoc for
the item it affects, with the manual section it comes from:

- `mov_reg` emits `MOV (register)` T1 (`0x4600`): it leaves the flags alone and
  reaches R8–R15, which is what a register move should do. Through 0.1.0 it
  emitted `adds rd, rm, #0` instead and wrote N, Z, C and V, so a move between
  a `cmp` and its `b<cond>` was silently miscompiled. The flag-setting move now
  has to be asked for by name, as `movs_reg`.
- `movs_reg` and `lsls_imm(rd, rm, 0)` are the same instruction — `MOV
  (register)` T2 — because that is how the architecture defines it.
- `b_cond(Cond::Al, label)` emits the *unconditional* `b`, not a condition
  field of `0b1110`: in the 16-bit branch space `0b1110` is the permanently
  undefined `UDF` and `0b1111` is `SVC`.
- `B<cond>.W` T3 does **not** pack its immediate the way `B.W` T4 does. T3 is
  `S:J2:J1:imm6:imm11` with no I1/I2 inversion and the J bits in the opposite
  order; T4, `BL` T1 and `BLX` T2 are `S:I1:I2:imm10:imm11`. The two encodings
  differ only in `hw2[12]`, and reusing T4's arithmetic for T3 produces a
  target that is plausible, wrong, and roughly 12 MB away.
- A displaced literal load is refused, not silently re-pointed. Its pool does
  not move, and ±1020 (or ±4095) bytes essentially never reaches free space
  from a stub. Widening buys nothing here, which is why `relocate` widens only
  direct branches.

**No I/O and no global state.** The crate takes a slice and gives you bytes
back. Reading the firmware, writing it, checksumming it and getting it onto a
device are all outside the library.

## How it is checked

Stated because a badge only shows you a colour.

### The encodings

Two different questions, asked separately, because only one of them can be
answered from inside this repository.

**Does the decoder agree with the encoder?** Every group module implements an
`encode` beside its `decode` and sweeps the round trip over its own slice of
the encoding space, **with the count pinned as a literal in the test** — 16,384
patterns for A5.2.1, 10,224 at four different addresses for A5.2.6, and so on —
so a change in what decodes surfaces as a failing census rather than as a
silently larger or smaller sweep. Those are the sweeps CI runs on every push.
`spec/THUMB-ISA.md` §4.5 records the same round trip run across the *whole*
space at once through the public `isa::encode`, which is what catches a group
that silently accepts a neighbour's instruction; it is an audit rather than a
per-push gate, because 402 million re-encodes is not a two-minute job. Every
16-bit pattern that decodes re-encodes to the halfword it came from, exactly.

Note the addresses these sweeps decode at. The whole-space enumeration uses one
that is 2 mod 4, deliberately, and several of the module sweeps repeat
themselves at two or four different addresses — so that every `Align(PC, 4)`
form is exercised at the alignment where getting it wrong shows, rather than
only at the one where it happens to cancel.

**Does the decoder agree with the architecture?** The round trip cannot answer
that, and this is the point worth being clear about: it proves the two
directions agree with *each other*. A systematic misreading of the manual — a
field read one bit too wide, a `U` bit inverted, an immediate shifted by the
wrong amount — round-trips perfectly and is still wrong, in both directions, in
exactly the same way.

That is not hypothetical, and asking LLVM is what found it. The harness's
findings against this crate are recorded as findings rather than explained
away: a zero-offset pc-relative load whose printed text does not say which of
two encodings it came from, an empty register list printed as `push {}`, a
floating-point immediate printed as `#5` where only a floating-point literal
will do. In each case the decode is right and the *text* is not something an
assembler can read back — and no byte round trip can see any of them, because
it never looks at the text.

What closes that gap is an implementation nobody here wrote.
[`tests/conformance.rs`](https://github.com/MattJackson/thumb-asm/blob/main/tests/conformance.rs)
asks LLVM:

```text
bytes  →  our decoder  →  our UAL text  →  LLVM assembler  →  bytes′
assert bytes′ == bytes
```

If LLVM reads our text back as the same bytes, then whatever we printed, LLVM
understood it as the instruction the bytes encode. It is a byte-level claim —
no normaliser, no judgement about what counts as a disagreement, which is
precisely where a real bug would otherwise hide.

- **The 16-bit space is swept exhaustively: all 59,392 halfwords**, and **98%
  of that space round-trips through LLVM byte-for-byte** — over 99.9% of the
  patterns this crate claims to decode. A further 1.59% are patterns neither
  implementation calls an instruction, which is agreement of a kind and is
  reported in its own row rather than counted as corroboration, because two
  implementations agreeing that something is *not* an instruction is much
  weaker evidence than two agreeing what one is.
- **The 32-bit space is sampled**, since 2³² is not enumerable: 669,696
  structured probes (every one of the 6,144 first halfwords crossed with 109
  second-halfword field-boundary vectors) and 200,000 pseudorandom ones from a
  printed seed, reported separately so a gap is visible rather than averaged
  away.
- **Every divergence is enumerated.** LLVM is not the specification — it is
  lenient where the architecture says UNPREDICTABLE, implements profiles
  selectively, and has syntax preferences of its own — so the 21 known
  divergence classes live in an allow-list, each entry naming the architectural
  clause that justifies it and carrying a budget, set from the measured count,
  on how many probes it may absorb.
  Anything not on the list fails the test. Entries that are defects in *this*
  crate are listed as findings rather than excuses.
- [`docs/CONFORMANCE.md`](https://github.com/MattJackson/thumb-asm/blob/main/docs/CONFORMANCE.md)
  has the full outcome tables, the divergence list with citations, and a
  "what is **not** corroborated" section that should be read alongside the
  numbers above.

### The gates

All four workflows pin every third-party action to a full commit SHA rather
than a tag or a branch, and none of them uses `continue-on-error` anywhere.

- **Fast gate — every push to `dev`, and every pull request**
  ([`dev.yml`](https://github.com/MattJackson/thumb-asm/blob/main/.github/workflows/dev.yml)):
  `cargo fmt --all --check`; clippy over `--all-targets --all-features` with
  `-D warnings`; `cargo test --all-targets`; `cargo test --doc`; and
  `cargo run --example trampoline`, which is the first example above.
- **Full gate — every push to `qa`**
  ([`qa.yml`](https://github.com/MattJackson/thumb-asm/blob/main/.github/workflows/qa.yml)),
  eight jobs behind one required `qa gate` check that goes red on a skipped or
  cancelled upstream job rather than green:
  - build, test, doctests and the trampoline example across **six
    configurations** — Linux, macOS and Windows against both current stable and
    the MSRV, which the workflow reads out of `Cargo.toml`'s `rust-version`
    rather than hardcoding, so CI cannot test a floor the crate no longer
    promises;
  - a **hard 100% line/region/function coverage gate**
    (`cargo llvm-cov --fail-under-lines 100 --fail-under-regions 100
    --fail-under-functions 100`), enforced in-workflow and not dependent on any
    third-party service. That number says every line *ran*, not that any line
    was *checked* — which is why it is not the headline claim here, and why the
    suite is audited separately by mutation testing (below);
  - **rustdoc with `-D warnings -D rustdoc::broken_intra_doc_links`**, so a
    dead doc link is a build failure rather than a line in a log;
  - **the LLVM conformance sweep** above, with `--nocapture` so a green run
    that silently skipped cannot be mistaken for one that checked something;
  - **mutation testing**, periodically rather than in CI: `cargo-mutants`
    rewrites the source in small mechanical ways and reruns the suite, so a
    surviving mutant is a change to behaviour no test noticed. The latest run
    is 7,475 mutants, **89.0% caught** — or **96.9%** once the 588 survivors
    that are provably equivalent (`|` swapped for `^` across disjoint
    bit-fields) are set aside. It is not decoration: it is what produced the
    `Asm` operand validation and the tests pinning `writes_pc` and
    `first_operand_is_source`. See
    [`docs/CONFORMANCE.md`](https://github.com/MattJackson/thumb-asm/blob/main/docs/CONFORMANCE.md#mutation-testing-what-the-coverage-number-does-not-say);
  - **`cargo semver-checks` against the crate already published on crates.io**,
    guarded only by whether a published baseline exists yet — so a breaking
    change under too small a version bump goes red;
  - `cargo package --list` with `cargo publish --dry-run`, plus an assertion
    that Arm's `spec/` dump has not crept into the `.crate`.
- **Release** ([`release.yml`](https://github.com/MattJackson/thumb-asm/blob/main/.github/workflows/release.yml)):
  manually dispatched, dry-run by default, and it **calls `qa.yml` itself**
  rather than trusting that it ran, so "what qa proved" and "what release
  verified" cannot drift apart. It publishes from `main` only, refuses to
  proceed unless the version, tag and release state are consistent, fails if
  `CHANGELOG.md` has no section for the version being released, and mints a
  short-lived crates.io token through Trusted Publishing rather than holding a
  long-lived one.
- **What these gates do not do:** clippy runs on latest stable only, never on
  the MSRV toolchain — its lints track current idiom, not the floor. The 32-bit
  conformance sweep is a sample, so a bug that needs two specific non-boundary
  immediates to show itself can hide from it. And nothing here executes Thumb
  code: every encoding is checked against the bit pattern the architecture
  manual specifies and against what LLVM makes of it, not against a core
  running it.

## Minimum supported Rust version

**Rust 1.58**, and it is a measurement rather than a guess. The 2021 edition
sets a floor of 1.56 on its own; the only thing in this crate's source that
needs anything newer is captured identifiers in format strings
(`format!("unbound label {label}")`), stabilised in 1.58.0 and used where
`Asm::finish` builds its error messages and throughout the tests. Nothing else
here — range `contains`, `u32::from_le_bytes`, `std::mem::take`, `BTreeSet` —
needs anything past 1.35.

The `qa` gate builds, tests and runs the doctests on the declared floor on
Linux, macOS and Windows, alongside current stable, and takes the toolchain
from `Cargo.toml`'s `rust-version` rather than from a number written into the
workflow — so CI cannot end up testing a floor the crate no longer promises, or
promising one it never tests. Clippy deliberately runs only on latest stable —
its lints track current idiom, not the floor this crate promises — and
`clippy.toml` pins `msrv = "1.58"` so the MSRV-aware lints never suggest an API
the floor cannot use.

The floor is treated as part of the public API: raising it gets a version bump
and a changelog entry, not a silent commit.

## Provenance

This code began as the `thumb.rs` module of a firmware patching toolchain,
where it backed Thumb/Thumb-2 trampoline injection across several ARM-based
drive controllers, and was extracted into a standalone crate because the
find/read/modify/insert model in it is not specific to that toolchain or to any
device. It now has several unrelated consumers, and the library is maintained
for the general case: anything platform-specific belongs in the caller.

One artefact of that history is kept on purpose rather than scrubbed:
`CommandTable`'s docs spell out the concrete dispatch-table layout the type was
first validated against — record shape, stride, field offsets, terminator flag,
and what the scanner routine that reads it actually does. It is there because a
worked example makes seven numeric fields comprehensible in a way that prose
does not, and it is labelled as an example rather than a default. A table with
12-byte records and the handler first is the same type with different numbers.

[`spec/THUMB-ISA.md`](https://github.com/MattJackson/thumb-asm/blob/main/spec/THUMB-ISA.md)
maps every encoding this crate emits or decodes to its section in Arm's
architecture reference manuals. Those manuals are in `spec/` in the repository
so each claim is checkable against its source; they are Arm's copyright and
around 35 MB, so `spec/` is excluded from the published `.crate` and the links
above point at GitHub.

## Contributing

Issues and pull requests are welcome at
[github.com/MattJackson/thumb-asm](https://github.com/MattJackson/thumb-asm).
Changes flow `dev` → `qa` → `main`: the fast gate has to be green on `dev`, and
the full gate — the OS and MSRV matrix, the 100% coverage gate, the rustdoc
link check, the LLVM conformance sweep, the semver check and the packaging dry
run — has to be green on `qa` before anything reaches `main` or crates.io.
A new encoding should arrive with its `spec/THUMB-ISA.md` row updated, the
manual section number it came from, and its round-trip count pinned as a
literal, because that document is the reason any encoding claim here can be
checked. A new conformance divergence has to name the architectural clause that
justifies it; if you cannot write the citation, you have found a bug rather
than a divergence.

[`CONTRIBUTING.md`](CONTRIBUTING.md) has the detail: what each gate runs, how a
release is cut, the coding standards and the testing policy, and the
[DCO](https://developercertificate.org/) sign-off contributions are made under.
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) and
[`GOVERNANCE.md`](GOVERNANCE.md) cover conduct, who decides what, and what
happens to the project if the maintainer steps away;
[`ROADMAP.md`](ROADMAP.md) says where it is going.
[`docs/SETUP.md`](docs/SETUP.md) collects the one-time setup that has to be done
by a human on someone else's website — crates.io Trusted Publishing, Codecov
activation, the OpenSSF Best Practices submission — in the order to do it.

## Security

[`SECURITY.md`](SECURITY.md) is the reporting process: report privately through
[GitHub's private vulnerability reporting](https://github.com/MattJackson/thumb-asm/security/advisories/new)
rather than as a public issue, expect acknowledgement within 14 days, and
reporters are credited unless they ask not to be. It also says what is in scope
and what is not — notably that `read_u8`/`read_u16`/`read_u32` are documented to
index the slice and panic past the end, which is why `try_read_*` exists for
untrusted input.

[`docs/ASSURANCE_CASE.md`](docs/ASSURANCE_CASE.md) is the argument that this
crate is adequately secure for what it does, with the evidence for each claim
and — just as importantly — the limits of that argument stated plainly. The
realistic harm here is not a memory-safety exploit in a `forbid(unsafe_code)`
crate with no dependencies and no I/O; it is a wrong instruction written into
firmware.

Releases are signed. Every release carries a SLSA build-provenance attestation
and a keyless cosign signature over the exact `.crate` published to crates.io,
both attached as release assets:

```sh
gh attestation verify thumb-asm-0.10.1.crate --repo MattJackson/thumb-asm
```

## Changelog

Notable changes are recorded in [`CHANGELOG.md`](CHANGELOG.md), which follows
[Keep a Changelog](https://keepachangelog.com) and
[Semantic Versioning](https://semver.org).

## License

MIT. See [LICENSE](LICENSE), which is also published as
[`LICENSES/MIT.txt`](https://github.com/MattJackson/thumb-asm/blob/main/LICENSES/MIT.txt)
in the layout [REUSE](https://reuse.software) expects.

Every file in the repository has copyright and licence information attached,
inline or through
[`REUSE.toml`](https://github.com/MattJackson/thumb-asm/blob/main/REUSE.toml) —
that is what the REUSE badge above checks. One carve-out is worth stating in
prose rather than leaving to a scanner: the Arm architecture reference manuals
in `spec/`, and the text dumps taken from them, are **Arm Limited's copyright,
not this project's**. They are declared as `LicenseRef-Arm-Documentation`
([what that means](https://github.com/MattJackson/thumb-asm/blob/main/LICENSES/LicenseRef-Arm-Documentation.txt)),
are kept in the repository only so that the crate's encoding claims can be
checked against the documents they came from, and are excluded from the
published `.crate`. The MIT licence covers thumb-asm's own source, tests,
examples, documentation and CI configuration. It does not cover Arm's
documents, and is not offered for them.
