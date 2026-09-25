# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.14.1] - 2026-09-25

Mutation-coverage patch. No API changes, no behaviour changes. Adds tests
that close the remaining tractable gaps in the pre-0.14.0 code, and
introduces a durable convention for documenting mutants that are provably
equivalent-by-construction so future sweeps can stop chasing them.

### Test coverage

- `Flags::contains` — added three per-flag `other=set, self=empty` cases
  (one each for N, Z, C), which pin the `!other.x || self.x` clauses that
  the existing `NZC.contains(ALL)` case only exercised for V. Kills three
  `delete !` mutants in `src/flags.rs:121`.
- `encode_stm_ldm` T1 (`stmia`/`ldmia` narrow encoder in `src/isa/t16_branch.rs`)
  — added a hand-built-`Insn` case with `Rn` in `r8..=r15` for both
  mnemonics. The `r.is_low()` guard on the base register was previously
  only exercised by the exhaustive-halfword round-trip loop, whose inputs
  never see a non-low base; a mutant that replaced the guard with `true`
  would silently flip `stmia` (base `0xC000`) to `ldmia` (base `0xC800`)
  through `rn << 8` overflow. The new test asserts `encode` returns `None`
  for every non-low base for both mnemonics.

### Documentation

Introduces a `// mutant-equivalent:` line-marker convention for mutants
that are provably equivalent-by-construction — the mutation produces the
same observable behaviour as the original across every input the function
can receive, so no test can distinguish them. Comments are one line,
positioned on or immediately above the mutated line, and state the
equivalence argument in one sentence.

Sites documented in this release:

- `src/isa/mod.rs:317`, `:331` — the two 32-bit dispatch arms whose
  mutation is subsumed by the `_ =>` catch-all's `t32_coproc::decode(...)
  .or_else(t32_simd::decode)`, or by that catch-all's `None`. The existing
  block comments already argued the equivalence; the `mutant-equivalent`
  markers make them greppable.
- `src/lib.rs:904` — `Asm::imm`'s `step > 1` fast-path: with `step == 1`,
  `v % 1` is identically `0`, so the second conjunct is unreachable under
  either `> 1` or `>= 1`.
- `src/analysis.rs:687` — `reachable_with`'s `image[at + 1]` for
  `it_state_from` reads only the low byte's cond/mask nibbles; the high
  byte the second index would name (the IT opcode's `0xBF`) is never
  looked at, so `at + 1` → `at * 1` is observably identical.
- `src/isa/t32_coproc.rs:1464..1472` — the pre-existing block comment on
  the four hand-written `r.num() < 16` guards has grown a
  `mutant-equivalent (nine mutants — ...)` header so the grep sweep
  recognises the whole family in one place. `Reg::num` is `self.0 & 0xF`,
  so the predicate is unconditionally true and every weakening of it
  yields an identical program.

### Not addressed

The 597 `replace | with ^` misses on encoders that OR together
mask-disjoint bit-fields remain provably equivalent-by-construction, as
`cargo-mutants`' own runbook (skill §7b) calls out. The `hw = a | b | c`
family is left as-is: annotating each one line-by-line would be six
hundred lines of noise. A future release may add a per-encoder-file
header once the semantics of "these fields are disjoint" is stated once
in `isa::insn` and pointed to from the emitters.

## [0.14.0] - 2026-09-24

The encoder learns to say "not on this chip". `isa::Target` — decoder-only
through 0.13 — now runs through the assembler and the install/verify/analysis
surfaces, so a caller who knows their image's profile gets refusal at the
emitter that would produce an instruction the target does not define, and a
detour that would misread a CMSE Security Gateway as a spurious pc-relative
`LDRD` gets the honest answer.

The mechanism is a per-emitter legality table (see
`src/isa/legality.rs`), not decode-back: `spec/THUMB-ISA.md` §988–991 makes
the decoder a union by design, so "does it decode under V7A?" is not the
question. "Does this mnemonic + encoding form appear on V7A?" is, and that is
what the table answers.

The 0.14.0 table is deliberately minimal: only `sdiv` and `udiv` (Thumb-2
T1) are restricted, on Armv7-A and on the strict `V7AR` intersection.
Every other current Asm emitter is baseline T1 that is defined across
Armv6-M / V7-M / V7-A / V7-R / V7E-M / V8-M identically, so the gate is a
no-op for the pre-existing emitter surface today. The follow-on rows —
`sg`/`bxns`/`blxns` under V8M, `enterx`/`leavex` under ThumbEE, `blx label`
T2, DSP, and the operand-discriminated `mrs`/`msr`/`cps`/`dsb`/`dmb`
mnemonics — land in 0.14.x / 0.15.0 alongside their emitters.

### Emitted bytes changed

Nothing changes for an existing caller under `Target::Union` — the crate's
default. Bytes for `sdiv`/`udiv` are unchanged (they weren't emittable
before 0.14). The 16-bit digest across the baseline emitter corpus is
unchanged.

### Added

- **`Asm::with_target(isa::Target)`** and **`Asm::target()`** — construct
  a chip-specific assembler that refuses at the emit site any instruction
  the target does not define. Under `Target::Union` the behaviour is
  byte-for-byte identical to `Asm::new()`.

- **Every `Asm` emitter is now fluent**: `-> &mut Self`, so
  `Asm::with_target(V8M).sdiv(0, 1, 2).finish().unwrap()` reads as a
  single expression. `label()`, `data_blob()`, `pos()`, `target()` and
  `finish()` do not chain (they return values other than the builder).

- **`Asm::finish(&mut self)`** replaces the by-value `finish(self)`.
  Every path (`Ok` or `Err`) leaves `self` a fresh empty assembler with
  the same target — the reuse contract Fable's audit named. Two `finish()`
  calls in a row: the second returns `Ok(vec![])`. A label from the
  previous buffer used after `finish` is refused as
  `AsmError::Layout { .. }` by the next `finish`, never silently bound to
  an offset in the new buffer.

- **`Asm::sdiv(rd, rn, rm)`** and **`Asm::udiv(rd, rn, rm)`** — the
  demonstration restricted emitters. Both emit the Thumb-2 T1 wide
  encoding (ARM ARM A8.8.165 / A8.8.267); both refuse SP (r13) and PC
  (r15) in any argument as `AsmError::Operand`. Under
  `Target::V7A`/`V7AR` they refuse as `AsmError::Unsupported`; under
  `V7R`/`V7M`/`V7EM`/`V8M`/`Union` they emit.

- **`Asm::raw16_unchecked(hw)`** — the explicit "these bytes, no gate"
  escape hatch. `raw16(hw)` under a non-Union target now decodes `hw` under
  `self.target`, refuses a wide-instruction prefix (points at `raw32`),
  and consults the legality table on the recovered mnemonic; use the
  `_unchecked` form to bypass every check.

- **`Asm::raw32(hw1, hw2)`** — first-class emitter for wide (Thumb-2)
  patterns. Same non-Union rule as `raw16` — decode under `self.target`,
  legality-check the recovered mnemonic — the load-bearing correctness for
  hand-encoding CMSE (`SG`) sequences on V8M.

- **`isa::Target::V7A`**, **`isa::Target::V7R`**, **`isa::Target::V7EM`**
  — the sub-profile split V7AR needed. `Target` is `#[non_exhaustive]` so
  the additions are additive. `V7AR` is retained as the **strict
  intersection** — legal iff legal on both V7A and V7R — which makes it
  strictly stricter than V7R alone (the answer for images of unknown
  sub-profile). V7M/V7A/V7R/V7EM are legality-discriminated only; the
  decoder treats them identically to `Union`. V8M and ThumbEE remain
  decoder-discriminated.

- **`can_install_with(target, ...)`**, **`classify_branch_with(target,
  ...)`**, **`analysis::xrefs_with(target, ...)`**,
  **`analysis::reachable_with(target, ...)`**,
  **`analysis::function_start_with(target, ...)`**,
  **`analysis::literal_value_with(target, ...)`** — target-aware overloads
  of every install / analysis surface that previously hardcoded
  `Target::Union`. The old signatures are retained and delegate to Union.

- **`DetourOptions::target: isa::Target`** and
  **`DetourOptions::with_target(...)`** — threads the caller's profile
  through the detour path (displaced-instruction sweep, flag-liveness
  analysis, stub verifier). Consequence: on an Armv8-M image a Security
  Gateway (`SG`) at the hook site is now decoded as `sg`, not as a
  phantom pc-relative `LDRD` whose "literal target" the detour follows
  into whatever bytes sit at that offset.

### Changed (breaking, pre-1.0)

- **`AsmError` becomes an enum** with three variants:
  `Operand { at, msg }`, `Unsupported { at, mnemonic, target }`,
  `Layout { at, msg }`. `reason()` accordingly returns `"operand"`,
  `"unsupported"` or `"layout"`. `message()` is removed — use
  `format!("{err}")` or the `Display` impl. Every variant carries `at`,
  the byte position in the code buffer the error refers to. `AsmError::at()`
  exposes it.

- **`Asm::finish` takes `&mut self`** rather than `self`. Callers doing
  `asm.finish()?` on a `mut` binding are unaffected; a caller passing
  `Asm` by value into a function that then called `.finish()` will need
  to pass `&mut Asm` instead.

- **Every `Asm` emitter returns `&mut Self`** rather than `()`. Callers
  who wrote closures like `|a| a.push(0)` in a `FnOnce(&mut Asm)` context
  will need to add a discard: `|a| { a.push(0); }`.

## [0.13.0] - 2026-09-23

Know what the registers and flags are doing. The crate stops refusing
instructions it can prove are safe to rewrite.

### Emitted bytes changed

Nothing changes for an existing caller. The one rewrite this release adds is
off by default: `DetourOptions::rewrite_compare_branches` is `false`, so a
displaced `CBZ`/`CBNZ` that cannot reach its target is still refused exactly
as in 0.12.0. Turn it on and a `CBZ` at a site where every condition flag is
dead becomes `CMP` + `B<cond>.W` — different bytes, deliberately, and only
where they mean the same thing.

The 16-bit digest is unchanged: `0x0e06fda25d6b89e8`.

### Added

- **`flags`** — which condition flags an instruction reads and writes, and
  which are live at a point in an image.

  This is per-flag rather than a bool, and that is the whole point.
  `Insn::sets_flags` says *that* flags are written; the mnemonic says *which*.
  Logical and shift operations with `S` — `ANDS`, `ORRS`, `EORS`, `BICS`,
  `MVNS`, `LSLS`, `LSRS`, `ASRS` — write N, Z and C and leave **V untouched**,
  with DDI 0403E.e A7.7.9 and its siblings saying `// APSR.V unchanged`
  outright. Arithmetic and the comparisons write all four. A model that reads
  `sets_flags` as "all four die here" therefore reports V dead after an
  `ANDS`, which would licence a rewrite that destroys a V the next branch
  tests.

  Reads are asymmetric in the same way: `ADC`, `SBC`, `RSC` and `RRX` consume
  the carry flag with `cond: None`, so a rule built on `insn.cond.is_some()`
  misses every one of them.

  `live_after` follows **both** the fall-through and the taken path. That is
  not a refinement — the motivating caller is rewriting a `CBZ`, which is
  itself a conditional branch, so half of what happens after it is at its
  target. Anything it cannot follow (an unresolvable target, a target outside
  the image, undecodable bytes, the walk budget running out) resolves to every
  flag live. The approximation is one-directional by design: a flag reported
  live may be dead, but a flag reported dead is dead on every path it saw.

- **`relocate::widen_compare_branch`** — rewrites `cbz rn, t` as `cmp rn, #0`
  + `beq.w t`. `relocate` refuses these outright, because the offset is
  unsigned and forward-only (0 to 126 bytes, no backward form), so a stub in
  free space essentially never reaches.

  It takes the liveness as an argument rather than computing it, because it
  receives an `Insn` and liveness is a property of the image around it. It
  refuses unless every flag is dead.

- **`RelocateError::FlagsLive`** — names *which* flags are live, not just that
  some are. Worth reading rather than treating as a yes/no: "only V" is the
  common answer, because a nearby `ANDS` kills three of the four and looks as
  though it killed all of them.

- **`DetourOptions::rewrite_compare_branches`** — opt in, and it does not make
  the rewrite unconditional. Liveness is computed from the image at each
  displaced instruction's original address, and a site where any flag survives
  is still refused.

### Hardened

- **A ten-lens audit of the new liveness code and the modules around it**,
  looped to convergence over six rounds. It confirmed 27 defects, all fixed
  here. The four high-severity ones were all in this release's own `flags`
  code and all erred toward reporting a flag *dead* — the direction that turns
  a refusal into a silent clobber: `live_after` following a literal load's
  `Target` into the pool and decoding data as code; `live_from` walking with
  the stateless decoder and so missing an `IT` block's flag reads and its
  `setflags = !InITBlock()` suppression; `reads` missing `RRX` used as a shift
  operand; and `writes` claiming `MSR APSR_g` touches the condition flags when
  it writes only the GE bits.

- **An integer-overflow class, fixed in six places.** Arithmetic on a
  caller-supplied `u32`/`usize` address done before the bounds check meant to
  reject an extreme value — a panic in debug, a wrapped and wrong result in
  release — in `CommandTable::find`, `widen_compare_branch`, `build_stub`,
  `disassemble`, `function_start` and `reachable`. A crate that must never
  crash on caller input now refuses these rather than overflowing.

- **Every ARMv8-M / VFP citation in `docs/CONFORMANCE.md` corrected** (twelve
  section numbers that named the wrong instruction), and the document is now
  pinned to `tests/support/divergences.rs` by a test, so the two cannot drift
  again. `Asm::finish` also stopped indexing its label table with an
  unvalidated caller id, and several stale comment fragments were removed.

### Deferred

- **The `UNPREDICTABLE` channel on `Insn`**, again. It needs
  `#[non_exhaustive]` on `Insn`, which removes literal construction from a
  struct whose hand-construction is a documented use case, so it needs a
  builder designed first — and then every group module has to classify its own
  encodings, which is a pass over nineteen files rather than an afternoon.
  Shipping half of it would mean a second breaking release to finish it.

## [0.12.0] - 2026-09-23

Say what you are patching. The crate stops inferring the instruction set from
the instruction and starts being told.

### Emitted bytes changed

Nothing moves for existing callers. [`Target::Union`] is the default and
reproduces 0.11.1 exactly, including where an Armv8-M encoding collides with
an Armv7 one: under the union `SG` still decodes as the `LDRD` Armv7 reads
there. The pinned 16-bit digest is unchanged — 58,233 decoded halfwords,
`0x0e06fda25d6b89e8`.

Bytes *do* change if you opt in to `Target::V8M`, which is the point of
opting in.

### Fixed

- **Armv8-M images were decoded wrongly, silently.** Not refused — answered,
  confidently and incorrectly:

  | halfwords | was | is, under `Target::V8M` |
  |---|---|---|
  | `0xE97F 0xE97F` | `ldrd lr, r9, [pc, #-508]!, 0xe08` | `sg` |
  | `0xE841 0xF000` | `strex r0, pc, [r1]` | `tt r0, r1` |
  | `0x4774` | `None`, and `Decoder` stops | `bxns lr` |

  `SG` is the mandatory first instruction of every secure-gateway veneer, so
  every TrustZone-M image contains one; read as `LDRD` it carries a resolved
  pc-relative target and `analysis::literal_value` will read a pool word that
  is not there. `BXNS` ends every secure entry function, so `reachable`
  reported a function with a truncated body and no exit.

### Breaking changes

- **`decode_at_with`, `decode_halfwords` and `Decoder::thumbee` take a
  `Target`** instead of a `thumbee: bool`. `Decoder::thumbee(true)` becomes
  `Decoder::target(Target::ThumbEE)`; `false` becomes `Target::Union`.
  `decode_at` and `Decoder::new` are unchanged.

- **`Operand`, `XrefKind`, `Widen`, `Reach`, `Xref`, `DetourError` and
  `InstallMismatch` are now `#[non_exhaustive]`**, so a `match` over them
  needs a wildcard arm. This is the same budget 0.11.0 spent on `Needle` and
  friends, finishing the job it started — every one of these has to grow as
  the ISA and the refusal vocabulary do.

  `Width` and `Cond` are deliberately **not** marked. Thumb has two
  instruction lengths and a four-bit condition field, so those sets are closed
  by the architecture; marking them would cost callers exhaustive matching for
  a flexibility that can never be used.

  `Insn` is not marked either, and that is a deferral rather than a decision:
  it is a struct with public fields, so `#[non_exhaustive]` would remove
  literal construction — which is a documented use case here. It needs a
  builder first, and that is 0.13.0's.

### Added

- **`isa::Target`** — `Union`, `V7M`, `V7AR`, `V8M`, `ThumbEE`. Most of the
  crate still decodes the union deliberately: for most of the map the profiles
  disagree only about which patterns are UNDEFINED, and a union decoder is
  more useful on an image of unknown provenance. `Target` is for where that
  stops being a coherent answer, because the patterns *collide*.

- **The Armv8-M Security Extension** — `SG`, `BXNS`, `BLXNS`, `TT`, `TTT`,
  `TTA`, `TTAT`, decoded and encoded under `Target::V8M`. Implemented as a
  profile-owned slice in the shape `thumbee` established, consulted before
  dispatch, so none of the nineteen group modules changed. It has to run
  *before* them rather than as a fallback: these are reassignments of
  allocated patterns, so once an Armv7 group has answered, the wrong answer
  has been chosen.

  `CLRM` is **not** included despite usually being listed with CMSE. LLVM
  rejects it for `armv8-m.main` with "instruction requires: armv8.1m.main", so
  it belongs with the Armv8.1-M work.

- **`RelocateError::SecureGateway`** — moving an `SG` is refused. It is the
  only refusal here that is not about range, alignment or encodability: `SG`
  re-encodes perfectly at any address and is still wrong to move, because the
  Security Attribution Unit identifies a gateway by the address the
  instruction sits at. Moved, it stops being a gateway and the address it
  vacated stops being guarded — so a detour over one would silently close the
  entry point it was patching.

- **`detour::detour_in`** — place the stub only in regions the caller declares
  writable. The built-in search knows about runs of `0xff`, which is a guess
  about what is *erased* and says nothing about what is *safe to write*: a run
  inside a checksummed block, or one the bootloader rewrites, looks identical
  to a spare one. `FreeSpace` and `find_free_space_in` shipped in 0.11.1 and
  `detour` reached neither.

  It is a function rather than a `DetourOptions` field because the option
  struct would need a lifetime parameter to hold a borrowed slice, and because
  the regions describe the call rather than a default. It is not equivalent to
  allocating and passing `stub_at`: that is one attempt with no retry, and
  whether a stub is usable is not knowable until the patch is laid out.

- **`reason()` on every error type.** `RelocateError` was the only one with
  both `#[non_exhaustive]` and a machine-readable reason; `FindError` and
  `InstallHazard` had the first, `DetourError` the second, `AsmError` and
  `InstallMismatch` neither. All six now have both. `AsmError` also gains
  `message()`.

### Testing

- **Mutation score holds at 91.1%** across 7,738 mutants (up from 7,624), so
  the new code is covered in the same proportion as the old rather than
  diluting it. 593 of the 666 survivors are the `|` to `^` family over
  disjoint bit-fields and 4 are `r.num() < 16`, both equivalent by
  construction.

  The run found one real gap in this release's own code: nothing distinguished
  `hook & !1` from `hook`, `hook | !1` or `hook ^ !1` in `detour_in`, because
  every test passed an already-even hook. A Thumb function pointer
  conventionally has bit 0 set — that is how the architecture marks a Thumb
  entry point — so a caller reading one out of a vector table passes an odd
  address, and the masking is on the path every such call takes.

### Documentation

- **Which "regions" this crate means: the caller's, always.** Raised by a
  consumer against `Straddle`, whose `Reject` rationale cites erase
  granularity and so reads as though the crate consults an erase-block map. It
  does not and cannot — it is handed a `&[u8]` with no device geometry. A
  region is whatever you meant it to be, and erase granularity is a reason you
  might *choose* `Reject`, not something that can be detected here. Stated on
  `Straddle` and applied to every region-taking API.

- **Labelling a `FindError`** is shown rather than supported. A `context(&str)`
  was requested; a `&'static str` would not take a label built at run time and
  a `String` would make a currently-`Copy` error allocate on a path that is
  often in a loop. `count` and `first` are public, so the wrapper it would
  replace is one `match` arm, now the documented example.

## [0.11.1] - 2026-09-23

### Emitted bytes changed

**`VLD4` (single 4-element structure to all lanes) with `:128` alignment now
encodes, and the UNDEFINED spelling of it no longer decodes.** The guard on
`size == 0b11` was inverted. A8.6.320 says `if size == '11' && a == '0' then
UNDEFINED`, and its `<align>` list gives 128 as "available only if `<size>` is
32, encoded as `a = 1, size = 0b11`" — so the `a` bit that asks for 16-byte
alignment is *required* there. The code required it to be clear. The two
consequences were opposite and both wrong: `vld4.32 {d0[],d1[],d2[],d3[]},
[r0:128]` — the only legal 128-bit-aligned form — was refused by `encode`,
while the UNDEFINED `a == 0` pattern was decoded as though it were that form.
Anything that round-tripped agreed with itself, which is why no sweep saw it.

The 16-bit digest is unchanged — 58,233 decoded halfwords,
`0x0e06fda25d6b89e8` — because this is a 32-bit encoding and the digest does
not cover that space. Do not read "digest unchanged" as "no bytes moved": if
you emit or decode that VLD4 form, bytes moved.

**But placement did.** The `find_free_space_in` fix below changes the address
returned for callers who pass more than one region, so an image built through
it can differ byte-for-byte from one built with 0.11.0 even though every
instruction in it encodes identically. If you pin a whole image or a digest
over one, expect a diff and check it is only the stub addresses moving.

That is not an instruction-encoding change and the digest cannot see it, which
is worth being explicit about rather than letting "digest unchanged" be read as
"your image is unchanged".

This section is now a fixed heading that appears in every release, empty or
not, so a consumer with a byte-exact golden test can grep for it rather than
read for it. See `docs/ENCODING-STABILITY.md`, which exists because 0.10.0's
`mov_reg` fix moved 21 bytes in a consumer's image and they discovered it when
their known-answer test failed rather than from the release notes. The fix was
correct; announcing it only in prose was not.

### Fixed

- **`find_free_space_in` returned a different address depending on the order
  the regions were passed.** `Fit::First` returned whichever region was listed
  first rather than the lowest address, despite the name, and `Fit::Largest`
  broke ties the same way. Two callers with identical intent got different stub
  addresses, which for anyone producing byte-reproducible images is
  nondeterminism with nothing to show for it. Both policies now resolve to an
  address: `First` is the lowest offset, `Largest` breaks ties on the lowest
  offset. Reported by a consumer; it shipped in 0.11.0 through a green gate,
  because nothing tested the same regions in two orders.

- **`isa::encode` could return bytes for a different encoding than the one
  asked for.** `faithful`, the check every candidate encoding is put through,
  compared mnemonic, width, operands, flags and condition — but never
  `encoding`. So an `Insn` naming `CMP (register)` T1 was answered with
  `0x4548`, which is T2: the same mnemonic and the same two registers, a
  different instruction format, and the only encoding of the two that can
  reach `r9` at all. Anything round-tripping through `decode` was unaffected,
  because the `Insn` it produced already named the encoding the bits held; the
  exposure was to callers who build an `Insn` by hand and name an encoding.
  `faithful` now compares `encoding` as well.

- **Every ARMv7-A/R manual citation pointed at a revision the repository does
  not ship.** `spec/` carries `ARM DDI 0406B_errata_2011_Q2`, whose own title
  page says so, while sixty citations labelled it `DDI 0406C` — and revision C
  renumbers the instruction sections, so nine of them named `A8.8.x` sections
  that do not exist in the shipped text. The labels are now `0406B` and the
  numbers are revision B's, resolved by instruction name rather than by
  arithmetic, since the renumbering is not an offset: `A8.8.127` is PLD/PLDW
  in C, whereas `A8.6.127` is QASX in B. The file is renamed to
  `spec/ARMv7-AR_DDI0406B.pdf` to match. Checking this also found four
  citations that were simply wrong — `Table A6-30` and `A2.11.2` do not exist
  in revision B, `A8.6.184` is `SSAT16` rather than `STC/STC2`, and the `reg`
  field of `VMRS` is documented in `B6.1.14`, not in the `VMSR` section — plus
  a miscount of the reserved `VMRS` encodings, which is ten and not nine.

### Added

- **`find_in` and `find_one_in`** — search confined to a window. Scoping is not
  ergonomics, it is how an otherwise-ambiguous signature becomes usable: a
  pattern matching three places across an image may match once inside the
  region you care about, and `find_one` without a bound was usable only where
  the pattern was globally unique — the case that never needed checking. The
  range is in **image coordinates** and matches must lie entirely inside it;
  taking a window rather than letting callers slice is what keeps
  `Needle::Masked`'s halfword boundaries and `Needle::FreeRun`'s alignment
  measured from the image origin.

- **`FreeSpace` and `Straddle`** — an allocator over erased space. Placing
  several stubs is a different question from placing one, and repeating a
  search does not answer it: nothing has been written yet, so every call
  returns the same offset. This tracks what it has handed out, so allocations
  pack contiguously without writing first. Regions are normalised to a sorted,
  merged set, so the sequence of offsets depends on the region *set* and not
  the order they were listed. `Straddle::Reject` refuses a free run that
  continues past the regions it was found in — for callers whose erase
  granularity is coarser than their integrity regions, where clipping does not
  help because the hazard is the write, not the placement.

- **`can_install` and `InstallHazard`** — a pre-flight check for a patch site.
  `classify_branch` reports width; this answers the question width was being
  consulted for, so the caller is not left doing the reasoning that goes wrong.
  The hazard is more general than "the site holds a 16-bit branch": any 2-byte
  instruction followed by a 4-byte one spans six, and a 4-byte branch leaves
  two bytes to be executed as whatever they encode.

- **`docs/ENCODING-STABILITY.md`** and a pinned encoding digest in the test
  suite, so a change to emitted bytes fails the build before it reaches a
  consumer's known-answer test.

### Testing

- **A mutation-testing campaign over the whole crate**, on the principle that
  a surviving mutant in a library that reflashes devices is a potential brick
  rather than a missing unit test. The score moves from 89.0% to **91.1%** of
  7,624 mutants, and from 96.9% to **99.1%** once the provably-equivalent
  families are set aside — roughly 64 real survivors remain, down from 206.
  It also found the `VLD4` bug above, which is the point: a round trip cannot
  see a decoder and an encoder that are wrong in the same direction. Mutants that survived were triaged one at a
  time into "the tests do not notice this" and "no test could notice this,
  because the change is unobservable at the public boundary" — the second
  class is recorded in comments beside the code, with the argument, so the
  next person does not re-derive it. Where a guard turned out to be genuinely
  unobservable it was left alone rather than given a test asserting an
  implementation detail.

### Documentation

- The half-open range convention is stated on every range-taking function.
  `a..=b` is deliberately not accepted: a `&[Range]` whose elements were built
  under two conventions cannot be told apart by reading it, so refusing the
  inclusive form makes a porting error a compile error rather than an
  off-by-one.

## [0.11.0] - 2026-09-23

Four additions requested by a consumer patching firmware with this crate, each
a case where the crate was close but an assumption blocked them. Two of the
four cannot be made without breaking changes, which is what makes this 0.11.0
rather than 0.10.2 — `cargo-semver-checks` runs in the `qa` gate and would have
refused a patch bump.

### Breaking changes

- **`Needle`, `BranchKind`, `Convention` and `DetourOptions` are now
  `#[non_exhaustive]`.** This is the last time an addition to any of them costs
  a version. A downstream `match` on one of the enums now needs a `_` arm, and
  `DetourOptions` must be built through `DetourOptions::new()` and the `with_*`
  chain rather than a struct literal — which is what the examples already did.

- **`DetourOptions` gained a `style` field.** Defaults to
  `DetourStyle::ResumeAfter`, which is the existing behaviour, so a caller
  using the builder is unaffected.

### Added

- **`Needle::Masked(&[(u16, u16)])` — instruction search with don't-care
  bits.** A signature is `(value, mask)` halfword pairs: "any `BL`" is
  `(0xF000, 0xF800)`, the five bits that identify the encoding fixed and the
  eleven displacement bits ignored. `Needle::Bytes` cannot express that at all,
  because the bytes differ at every call site, so every consumer was
  hand-rolling the scan. Matches are **halfword-aligned**: Thumb instructions
  are 2-aligned, and a byte-granular scan reports hits straddling two real
  instructions that look plausible and are not instructions. An empty pattern
  matches nothing rather than everything.

- **`find_one` — search that refuses to guess.** `find` returns the first
  match, which is right when scanning and wrong when *identifying*: a signature
  matching three places has not found the function, it has said the signature
  is too weak, and patching the first one is how a tool reports success and
  bricks a device. `Err(FindError::Ambiguous { count, first })` carries both
  numbers so a caller can say what happened without repeating the search.

- **`find_free_space_in` and `Fit`** — free space restricted to regions the
  caller says are writable, with a first-fit or largest-fit policy.
  `find_free_space` scans the whole image, which assumes every erased byte is
  fair game; in a real image it is not — a region may be integrity-covered,
  vendor-reserved, or outside the erase block being rewritten. Only the caller
  knows. **Slicing the image and searching that is not a workaround**: slicing
  at an unaligned offset moves the alignment origin, so a result that is
  4-aligned within the slice is not 4-aligned within the image — the same
  failure the `align` parameter exists to prevent, reintroduced one layer up.
  `Fit::Largest` exists because first-fit takes the first hole big enough and
  leaves the large one fragmented.

- **`classify_branch` and `BranchAt` — ask what is at a site before
  overwriting it.** `verify_branch` checks an assertion: you say which kind and
  target you expect and it agrees or disagrees. It cannot catch the
  expectation itself being wrong, which is the interesting failure. The field
  that matters most is **width**: a 16-bit `b` at the site comes back as
  `Direct { kind: None, width: 2 }`, and `install_branch` only writes 4-byte
  branches, so patching over it consumes the two bytes of whatever follows.
  Checking `width` first turns a field-reported brick into a refusal.

- **`DetourStyle::DiscardAndJumpTo(u32)`** — the tail-call detour shape:
  replace the site's instructions and branch to a computed address rather than
  relocating them and resuming. The variant is named for what it does because
  the displaced instructions **do not run**; an arm called `JumpTo` reads like
  a destination choice and hides that. This is the only operation in the crate
  that discards instructions, and the crate cannot check that you meant it.

## [0.10.1] - 2026-09-23

No code changes: the library is byte-identical in behaviour to 0.10.0. This
release exists so that the project's governance, security and assurance
documentation is published alongside the crate rather than only in the
repository, and so that there is a release carrying signatures.

### Added

- **`SECURITY.md`** — how to report a vulnerability (privately, through GitHub
  private vulnerability reporting or by email), what response to expect, and
  how reporters are credited. It also states scope: the realistic reports are a
  panic reachable from untrusted input through an API not documented as
  panicking, a mis-encoded or mis-decoded instruction, or an unbounded loop or
  allocation driven by input. Explicitly out of scope: `read_u8`/`read_u16`/
  `read_u32` panicking past the end of the image, which they are documented to
  do — `try_read_*` returning `Option` is the form for untrusted input.

- **`docs/ASSURANCE_CASE.md`** — the argument that the crate is adequately
  secure for what it does, with the evidence for each claim and the limits of
  the argument stated rather than left implied. The realistic harm here is not
  a memory-safety exploit in a `forbid(unsafe_code)` crate with no dependencies
  and no I/O; it is a wrong instruction written into firmware.

- **`GOVERNANCE.md`, `CODE_OF_CONDUCT.md`, `ROADMAP.md`** — who decides what,
  what happens to the project if the maintainer becomes unavailable, the
  Contributor Covenant, and where the project is going. `GOVERNANCE.md` is
  honest that this is a single-maintainer project rather than describing a
  committee that does not exist.

- **`CONTRIBUTING.md` gained coding standards, a testing policy and a DCO
  section.** The standards were already enforced by CI; they were not written
  down anywhere a contributor would find them. The testing policy states
  red-before-green as a requirement and says why a test that cannot fail is
  worse than no test — both failure modes happened in this project and are in
  the 0.10.0 entry below.

- **Signed releases.** Every release now carries a SLSA build-provenance
  attestation and a keyless cosign signature over the exact `.crate` published
  to crates.io, attached as release assets and verified inside the workflow
  that produces them. crates.io holds the bytes but publishes no signature over
  them; consumers of this crate write its output into firmware, so "are these
  the bytes the maintainer built?" is a question with a device on the end of
  it. Verify with `gh attestation verify thumb-asm-0.10.1.crate --repo
  MattJackson/thumb-asm`, or `cosign verify-blob --bundle` against the bundle
  asset.

- A **`yank` dispatch input** on the release workflow. Trusted Publishing mints
  a token scoped to publishing, and crates.io refuses it for a yank, so that
  path takes a separately scoped token and says so rather than failing with an
  authentication error that looks like a misconfiguration.

### Fixed

- **`CODE_OF_CONDUCT.md` is declared CC BY 4.0, not MIT.** It is the
  Contributor Covenant reproduced verbatim — someone else's text, under its own
  licence. Labelling it MIT with this project's copyright would have been the
  same mistake `LICENSES/LicenseRef-Arm-Documentation.txt` exists to avoid for
  the Arm manuals.

## [0.10.0] - 2026-09-22

0.1.0 was a 676-line position-independent assembler and patch-site finder with
26 instruction encodings. 0.10.0 is roughly twenty thousand lines: a decoder
and encoder for essentially the whole Thumb and Thumb-2 instruction set, an
instruction relocator built on it, and a trampoline installer built on that.
The crate went from *emitting* Thumb to *reading* it, which is what makes
patching over live code possible rather than only over a known prologue.

Three things that shipped in 0.1.0 break. They are listed first, because they
are the only reason this is not a drop-in upgrade.

### Breaking changes

- **`DetourError::Install` has been removed.** The variant named a failure whose
  precondition set is empty: `detour`'s planning phase already proves the site is
  in bounds, that the hook branch encodes, and — via `StubOverlapsSite` — that
  writing the stub cannot touch the site's four bytes. What remained was
  `install_branch`'s read-back, and a write to a `&mut [u8]` followed by a read
  cannot disagree under Rust's memory model. The commit is now two infallible
  stores and the read-back survives as a `debug_assert_eq!` post-condition, which
  makes the code match what the module's Atomicity section already claimed.

- **`find_free_space` takes a required `align` parameter.** The signature is now
  `find_free_space(image, len, align, start)`. Alignment has to be accounted for
  *during* the scan, not by rounding up a run that was already found: rounding
  the start up moves the start without moving the end, so a run that was exactly
  long enough stops being long enough and the caller gets an offset whose tail
  overlaps live bytes. Pass `4` for anything destined for `Asm::finish`, whose
  literal-pool offsets are computed against `Align(PC, 4)`; pass `1` for raw
  data, which is the pre-0.10 behaviour. Panics if `align` is 0.
- **`Needle::FreeRun` is a struct variant.** `Needle::FreeRun(len)` is now
  `Needle::FreeRun { len, align }`, for the same reason. Any `match` over
  `Needle` has to be updated.
- **`Asm::mov_reg` no longer writes the condition flags.** See *Fixed* below for
  what it used to emit and why that was wrong. Callers that wanted the old
  flag-setting behaviour must switch to the new `Asm::movs_reg`; callers that
  wanted a register move need no change and were previously getting a silently
  different instruction.

One further shape change affects nobody on crates.io but does affect anyone
tracking `dev`: **`isa::Mem` stores its offset as an unsigned magnitude plus a
separate `add: bool`** — the architecture's `U` bit — rather than as a signed
`i32`, and gained an `align: u16` field for Advanced SIMD's `[rn:64]`
qualifier. `AddrMode` gained a fourth variant, `PostIncrement`, for the
`[rn]!` form of the element and structure transfers. `Mem::displacement()`
returns the signed byte count for consumers that only want the effective
address.

### Added

#### `isa` — the decoder, the encoder and the instruction vocabulary

- **`isa::Decoder`** — an `Iterator<Item = Insn>` that walks a Thumb stream from
  a known start and **tracks `ITSTATE`**. The 1–4 instructions after an `IT`
  carry no condition in their own encoding, so a decoder that ignores `IT`
  reports them as unconditional — silently, and in the one place where being
  wrong changes control flow. Instructions decoded inside an IT block come back
  with `Insn::cond` already filled in. `Decoder::at` decodes from an offset that
  is not the address; `.thumbee(true)` selects ThumbEE state; `pos`, `it_state`
  and `skip` are there to resynchronise past an undefined encoding.
- **`isa::decode_at`, `decode_at_with`, `decode_halfwords`** — decode one
  instruction, from an image or straight from a halfword pair.
  **`isa::insn_len`** is the whole of Thumb's length rule: `hw1[15:11]` decides
  and nothing else is consulted (ARM DDI 0403E.e A5.1).
- **`isa::encode` / `isa::encode_bytes`** — the inverse. Dispatch is *verified*,
  not trusted: a mnemonic does not identify an encoding group — `add` lives in
  five of them — so `encode` offers the instruction to each group in turn and
  **decodes every candidate again, comparing it against the instruction asked
  for, before returning it**. A mismatch is discarded and the next group gets a
  turn. With a bare fallback chain the whole thing would only be as correct as
  its least strict member, and a group accepting a neighbour's instruction would
  emit the wrong encoding while every module's own tests stayed green.
- **`isa::disassemble`** — `count` instructions from an offset as UAL text.
- **`isa::insn`** — the shared vocabulary every group module speaks: `Insn`
  (`mnemonic`, `encoding`, `addr`, `width`, `cond`, `sets_flags`,
  `explicit_width`, `operands`) with `is_branch`, `is_call`, `writes_pc`,
  `branch_target` and `len`; `Operand`, `Operands` (a fixed inline array,
  `MAX_OPERANDS == 6`, so decoding allocates nothing), `Mem`, `AddrMode`, `Reg`,
  `FpReg`, `Shift`, `ShiftKind`, `ShiftAmount` and `Width`. `Insn`, `Operand`,
  `Reg` and `Width` are re-exported at the crate root.
- **Nineteen group modules**, one per numbered sub-table of Arm's architecture
  reference manual, so a review is one section of `spec/THUMB-ISA.md` beside one
  table of Arm's beside one file of the crate's: the six 16-bit groups of A5.2,
  the twelve 32-bit groups of A5.3 (including the coprocessor, floating-point
  and Advanced SIMD space), and ThumbEE's re-assigned 16-bit map from
  DDI 0406 A9.2.1.
- **Coverage, counted rather than asserted.** Thumb's length rule partitions
  every bit pattern a Thumb stream can present into 59,392 single halfwords and
  402,653,184 `(hw1, hw2)` pairs, and both are small enough to enumerate, so
  `spec/THUMB-ISA.md` §4 states coverage as an exhaustive count of all
  402,712,576 of them rather than as an adjective. **58,233 of the 59,392
  16-bit halfwords decode — 98.05%** — with the 1,159 exceptions named one at a
  time rather than left as a remainder, and 3,840 of ThumbEE's 4,096
  re-assigned halfwords. Over half of the wide space decodes; §4.2 has the
  module-by-module table, whose rows partition the whole space so the total is
  a sum rather than an estimate, together with the distinct-mnemonic and
  `(mnemonic, encoding)` counts. §4.3 explains why the wide-space ratio is not
  a coverage grade: most of the 32-bit space is UNDEFINED by construction —
  Table A5-9 leaves whole `op2` rows unallocated, `t32_dp_reg` rejects fifteen
  sixteenths of its space before decoding anything — and a decoder scoring
  higher there would be wrong.
- **One refusal policy, stated once** (§4.4): `decode` returns `None` only for
  an encoding the table does not allocate, for a should-be-zero or should-be-one
  bit holding the wrong value — `Insn` has nowhere to put it, so decoding would
  discard information and re-encode to a *different* pattern — and for an
  UNPREDICTABLE encoding with no representable UAL. The converse is applied just
  as uniformly: an UNPREDICTABLE *choice of operands* is decoded, because
  `pop.w {lr, pc}` is exactly the malformed code a reverse-engineer is hunting
  for and refusing it would hide it.

#### `relocate` — moving one instruction to a new address

- **`relocate(insn, to)`**, **`relocate_with(insn, to, widen)`** and
  **`relocate_bytes`** — re-site a decoded instruction so it still means the
  same thing somewhere else. Thumb has three ways for behaviour to depend on an
  instruction's own address: a direct branch's displacement, a pc-relative
  literal access based on `Align(PC, 4)`, and the handful of instructions that
  read `pc` as a value. The decoder has already done the hard half, because an
  `Operand::Target` is the *resolved absolute address*, so relocation never
  redoes pc arithmetic — it holds the target still and asks whether the new
  displacement fits.
- The case worth knowing: **`Align(PC, 4)` does not move linearly.** Moving an
  instruction two bytes changes a literal displacement by either zero or four,
  never by two, so the tempting `new = old - (to - from)` is wrong at every
  second halfword and wrong in a way that still assembles.
- **`Widen::{Never, IfNeeded}`** — whether a narrow direct branch may be
  re-encoded wide when the narrow displacement no longer reaches. `relocate`
  never widens, because widening changes the instruction's length and a caller
  laying out a fixed buffer has to be told; the widening form is asked for by
  name. Only direct branches widen: a narrow `ADR` or `LDR (literal)` is refused
  rather than widened, because ±4095 is the same "cannot reach a pool from free
  space" class as ±1020.
- **`RelocateError`** — eight variants, each naming the instruction and both
  addresses, with a stable `reason()` string, plus `mnemonic()`, `from()`,
  `to()` and `is_address_dependent()`, which is what tells a caller whether
  retrying at a different address could possibly help.

#### `detour` — the headline verb

- **`tramp(image, site, hook)`** and **`detour(image, site, hook, opts)`** —
  decode the instructions a four-byte hook branch would displace, relocate them
  into a stub, branch back, and install the hook. This is the thing that cannot
  be written without a decoder, because patching four bytes over an arbitrary
  address is four ways wrong and every one of them is silent: it cuts an
  instruction in half; it moves an instruction out from under its `IT`, so a
  conditional instruction runs unconditionally in the stub; it relocates a
  pc-relative instruction as a byte copy; and it half-applies.
- **Refusals are specific and atomic.** `DetourError` has fifteen variants, each
  with a stable `reason()` — `"splits-it-block"`, `"site-not-aligned"`,
  `"site-in-it-block"`, `"no-free-space"`, `"site-unreachable"`,
  `"hook-unreachable"`, `"resume-unreachable"`, `"relocate"` (wrapping the
  `RelocateError` that says which instruction could not be moved), and the rest.
  On **any** error the image is byte-for-byte unchanged: every fallible step —
  decoding, the IT checks, relocating each displaced instruction, encoding all
  three branches, the free-space search, every bounds check — happens in a
  planning phase that takes `&[u8]`, and only then are the two writes issued.
  The stub is written first on purpose, so that even an impossible failure of
  the final verification leaves an unreferenced blob in free space and an
  untouched site rather than a live branch into free space.
- **`Detour`** reports `site`, `displaced` (always a whole number of
  instructions, so 4 or 6, never 5), `stub`, `stub_len`, `kind`, and `resume()`.
- **`DetourOptions`** — `kind` (`BranchKind::Bl` by default; `BWide` preserves
  `lr`, which is what a tail-call site needs), `convention`, `search_start`,
  `stub_at` for a consumer with its own allocator, and `scan_from`, a known
  instruction boundary at or before the site. Without `scan_from` the IT state
  entering the site is *assumed* inactive and the site is *assumed* to be an
  instruction boundary, neither of which can be checked from the site alone,
  because a Thumb stream cannot be decoded backwards; with it, both are checked.
- **`Convention::CallThenContinue`** calls the hook and then runs the original;
  **`Convention::HookDecides`** jumps to the hook with `lr` untouched and `r12`
  pointing at the relocated code, so the hook can run the original, return
  without running it, or do something else — which is the convention for a gate
  whose answer is "deny".

#### `analysis` — the derived questions

- **`xrefs(image, target)`** — every reference to an address, instruction-
  accurate, over all four ways a Thumb image names one: a direct call
  (`XrefKind::Call`), a direct branch including `cbz`/`cbnz`
  (`XrefKind::Branch`), a 4-byte data word (`XrefKind::LiteralPool`), and an
  address materialised from `pc` by `adr` (`XrefKind::PcRelativeAddress`). Each
  `Xref` carries the mnemonic that produced it, because the distinction inside a
  kind is often the one that matters. This supersedes `find_bl_sites`, which
  answers a strictly smaller question and answers it unsoundly.
- **`function_start`** — a documented heuristic, with its failure modes written
  down rather than implied.
- **`literal_value`** — what an `ldr` literal actually loads, resolving
  `Align(PC, 4)` through the decoder instead of by hand.
- **`nop_fill`** — blank code with `NOP` T1, because `0x0000` is `movs r0, r0`
  and writes the flags.
- **`reachable`** / **`Reach`** — a control-flow walk from an entry point,
  reporting what was reached, what could not be followed, an over-approximate
  `end`, and whether the walk itself ran out of road, as four separate facts.
- **`veneer`** — an 8-byte `ldr.w pc, [pc]` plus literal, for a target too far
  for any branch encoding.

#### Image, branch and error surface at the crate root

- **`read_u16`** — the little-endian halfword read that was missing beside
  `read_u32`/`read_u8`. A halfword is the unit a Thumb image is made of, and
  consumers were open-coding `u16::from_le_bytes([image[at], image[at + 1]])` at
  every signature-scan site.
- **`try_read_u8`, `try_read_u16`, `try_read_u32`** — `Option`-returning
  siblings of the panicking reads, for scans that walk to the end of an image.
- **`decode_b_cond` / `CondBranch` / `encode_b_cond`** — a generic
  conditional-branch codec covering **both** encodings: `B<cond>` T1 (16-bit,
  `1101 cond imm8`, A5.2.6) and `B<cond>.W` T3 (32-bit, `S:J2:J1:imm6:imm11`,
  A5.3.4). `decode_b_cond` returns the condition, the absolute target and the
  instruction width, so a caller can step over either form; `encode_b_cond`
  picks the narrowest encoding that reaches. T3 is **not** packed like `B.W` T4:
  it has no I1/I2 inversion and the J bits are in the opposite order, and the
  two encodings differ only in `hw2[12]`.
- **Conditional-branch emitters on `Asm` for all fourteen conditions** — `bmi`,
  `bpl`, `bvs`, `bvc`, `bls`, `bge`, `blt`, `bgt`, `ble` join the existing
  `beq`/`bne`/`bhs`/`bhi`/`blo`, all one-liners over the new generic
  `Asm::b_cond(cond, label)`.
- **`Asm::movs_reg(rd, rm)`** — `MOV (register)` T2, the flag-setting register
  move, low registers only. For callers who want the behaviour `mov_reg` used to
  have, by its right name.
- **`verify_branch`, `install_branch`, `BranchKind` and `InstallMismatch`** —
  framework-agnostic detour installation and verification. `install_branch`
  encodes, writes, then decodes the image back to prove the bytes mean what was
  intended; `verify_branch` is that last step alone. Bit 0 is masked off both
  sides before comparing, so either form of an address may be passed.
  `BranchKind::encode` / `decode` dispatch over the existing `encode_bl`/
  `encode_b_wide` and `decode_bl`/`decode_b_wide` pairs.
- **`Cond`** — the shared condition-code type (`bits`, `from_bits`, `invert`,
  `suffix`, `Display`), carrying the architectural bit values, with `0b1111`
  rejected rather than treated as a fifteenth condition.
- **`thumb_asm::Result<T, E = AsmError>`** at the crate root, so downstream code
  can write `-> thumb_asm::Result<Vec<u8>>`.

#### Checked against an implementation nobody here wrote

- **`tests/conformance.rs`**, a differential harness against LLVM, documented in
  `docs/CONFORMANCE.md`. The round-trip sweeps prove the decoder and the encoder
  agree with *each other*, which a systematic misreading of the manual satisfies
  perfectly while still being wrong in both directions. This asks a second
  implementation instead: bytes → our decoder → our UAL text → LLVM's assembler
  → bytes, asserting the bytes come back identical. **All 59,392 halfwords of
  the 16-bit space are swept, and 98% of that space round-trips through LLVM
  byte-for-byte** — over 99.9% of the patterns this crate claims to decode. The
  32-bit space is covered by 669,696 structured probes and 200,000 pseudorandom
  ones from a printed seed, reported separately so a gap is visible rather than
  averaged away. Every divergence is enumerated in a **21-entry allow-list**
  (`tests/support/divergences.rs`), each entry carrying the architectural clause
  that justifies it and a budget, set from the measured count, on how many
  probes it may absorb; anything not
  on the list fails the test. The harness skips and passes with no LLVM
  installed, so a contributor without it still gets a green `cargo test`.

### Changed

- **The test suite is now audited by mutation testing.** 100% line, region and
  function coverage says every line ran, not that any line was checked — and
  three real defects in this crate had already lived under it. `cargo-mutants`
  generates 7,475 mutants; 89.0% are caught, or 96.9% once the 588 survivors
  that are provably equivalent (`|` swapped for `^` across disjoint bit-fields,
  which cannot change the value) are set aside. The remaining 206 are recorded
  in `docs/CONFORMANCE.md` rather than glossed over. Three groups of fixes in
  this release came directly out of that run: operand validation on the `Asm`
  emitters, the tests pinning every clause of `Insn::writes_pc` and
  `first_operand_is_source`, and a test for `prologue_len`.

- **The conformance harness was assembling its probes as Arm, not Thumb.** The
  dialect prologues wrote `.thumb` above `.arch`, and `.arch` resets the
  assembler to Arm state, so every probe was assembled as a 32-bit Arm
  instruction. LLVM 23 happens not to reset and LLVM 18 does, so this passed on
  a developer machine and failed the first time CI ran the sweeps: the byte
  round-trip fell from 98% to 0.36%. The disassembly comparison went on
  agreeing throughout, because it reads the original probe bytes rather than the
  assembled ones — which is exactly why the two directions are counted
  separately. A second version-dependency went with it: the harness required
  the `.balign` padding after each probe to be zero, and `.balign 16, 0x00` in
  an executable Thumb section is honoured literally by LLVM 23 and filled with
  `nop` by LLVM 18. The sentinel's position is already the length check, so the
  padding requirement is gone.

- **The conformance harness now tests the printer the crate actually ships.**
  `render` built its own UAL text rather than calling `Insn::Display`, so what
  the sweeps corroborated was a second printer that existed only in the test
  suite — and a rule in the real one, forcing `LDR (literal)` T1 to print
  `[pc, #0]` instead of the ambiguous `[pc]`, was absent from the copy. The
  divergence stayed on the allow-list as a known defect while the fix for it
  sat in the shipped code, untested. `render` now delegates and performs only
  the one documented substitution (an absolute `Target` becomes LLVM's
  pc-relative immediate); the eight affected probes round-trip byte-for-byte
  and the allow-list entry is gone rather than kept as an excuse.

- **A width suffix the assembler will not parse is now a test failure.** When
  LLVM refuses our text the sweep falls back to comparing its *disassembly*,
  and that comparison strips `.w`/`.n` before matching — so an invalid suffix
  was refused by the assembler and then forgiven by a comparison that could not
  see it, landing in the bucket labelled "agreed". `mul.w` sat there across
  282,000 probes. A separate check now offers every distinct suffixed form to
  LLVM on its own and requires some dialect to accept it.

- **The 32-bit probe vectors cover every `Rd` and sub-opcode nibble.** The
  hand-picked second-halfword vectors never put `r3`, `r6` or `r9` in `Rd`, and
  reached several instructions only through a pattern naming `pc` in every
  field — and `<op> pc, pc` is UNPREDICTABLE, which LLVM will not assemble, so
  those instructions were corroborated only through the weaker disassembly
  path. The structured sweep is now 669,696 probes rather than 282,624.

- **Every allow-list budget is set from its measured count.** They were round
  numbers with up to fourteen times the slack of what they admitted, which
  cannot detect a class growing. Each is now the observed count plus a small
  margin.

- **Fourteen allow-list citations pointed at the wrong section.** They had
  drifted against the DDI 0403E text in `spec/`: `A7.7.24` was cited for both
  `CPS` and `BIC` and is in fact `CLZ`; all six numbers in the saturate/bitfield
  entry named different instructions; three Advanced SIMD entries cited the
  Armv7-M manual, which does not contain Advanced SIMD at all. Corrected against
  the manuals in `spec/`, and the header comment now names DDI 0406B, which is
  the A/R revision actually in the tree.

- **`Asm::mov_reg` now emits `MOV (register)` T1 and no longer touches the
  flags** — see *Breaking changes* above and *Fixed* below. It now emits
  `0x4600 | (d << 7) | (rm << 3) | (rd & 7)` with `d = (rd >> 3) & 1`
  (A5.2.3 / A7.7.77), which preserves the flags and additionally reaches
  R8–R15, making it the only 16-bit way to move `r8`–`r12`, `sp` or `lr`.
- `Asm`'s `beq`/`bne`/`bhs`/`bhi`/`blo` delegate to `Asm::b_cond`; the encodings
  are unchanged. `b_cond(Cond::Al, label)` deliberately emits the
  *unconditional* `b` rather than a condition field of `0b1110`, because in the
  16-bit branch space `0b1110` is the permanently undefined `UDF` and `0b1111`
  is `SVC`.
- `find_bl_sites` is superseded by `analysis::xrefs` and its documentation says
  so. It is still present and still supported; it answers a strictly smaller
  question — direct `BL` only — by scanning every even offset, so it can land
  mid-instruction and report a halfword pair that merely looks like a `BL`.
- Crate-level documentation rewritten to be consumer-neutral: it described one
  specific firmware tool's private platform engines, which no longer reflects
  how the crate is used. Same four-verb (find / read / modify-insert / create)
  framing, no private names.
- `CommandTable`'s documentation reframed: the MT1959 record layout is kept
  because it is a genuinely useful worked example of what the geometry fields
  mean, but it is now presented as one example rather than as the definition,
  and the dangling `crate::engine::Engine` doc link is gone.
- `Asm::lsls_imm` documents the A5-2 footnote alias: `lsls_imm(rd, rm, 0)` is
  not a zero-bit shift, it *is* `MOV (register)` T2 and disassembles as
  `movs rd, rm` — the same halfword `movs_reg` emits.
- `AsmError`'s documentation explains that because it is
  `std::error::Error + Send + Sync + 'static`, `anyhow` already accepts it
  through its own blanket `From` impl, so a bare `?` in a function returning
  `anyhow::Result` works with no `.map_err`. It also explains why an `anyhow`
  feature flag is impossible rather than merely unimplemented: such an impl
  would overlap `anyhow`'s blanket impl and be rejected for coherence.

### Fixed

- **Every `Asm` emitter accepted operands no encoding field could hold.** Each
  one ORs its arguments into a fixed halfword, and none checked them first, so
  an out-of-range value did not fail — it overflowed its field and assembled to
  a *different instruction*. `push(0x4000)` produced `0xF400`, which is not a
  push but the first halfword of a 32-bit instruction, so the two bytes after it
  were swallowed as its second halfword and everything downstream decoded from
  the wrong offset. The documentation invited exactly that call: `push`'s example
  gave `push {lr}` as `0x4000` when the register-list bit for `lr` is `0x0100`.
  Operands are now validated at emit and the first bad one is reported by
  [`Asm::finish`], which is the same channel an out-of-range branch already used
  — there is no path that yields the corrupt encoding. `Asm::bind` on a label
  that was never reserved indexed out of bounds and panicked; it is an error now.

- **`MUL` T2 printed a `.w` that is not valid UAL.** A7.7.84 gives the 32-bit
  encoding the syntax line `MUL<c> <Rd>,<Rn>,<Rm>` and offers no width
  qualifier; LLVM rejects `mul.w` outright. The two encodings are told apart by
  their operands instead — T1 is `<Rdm>,<Rn>,<Rdm>` and sets flags outside an IT
  block. Text this crate emitted for `FB0n Fxxx` could not be re-assembled by
  any assembler.

- **`ROR (immediate)` was labelled encoding T2.** A7.7.116 lists one encoding.
  `LSL`, `LSR` and `ASR` are T2 in this group because each spends a T1 on its
  16-bit form, and `ROR` has no 16-bit immediate form to spend one on — which is
  why `RRX`, in the same table, was already correctly T1.

- **`analysis::reachable` ignored `IT` blocks, contrary to its documentation.**
  It decoded every instruction with IT state off, so an instruction made
  conditional only by an enclosing block — `bxeq lr`, which has no condition
  field of its own — was read as an unconditional branch and the walk ended
  there. A function returning under `IT` was reported as stopping at the
  conditional return, with `complete: true` and no indication anything had been
  missed. Deciding where a patch may go on that answer would put it on top of
  live code. `ITSTATE` now travels with each pending offset.

- **`try_read_u16` and `try_read_u32` panicked on an offset near `usize::MAX`.**
  Both computed `at + 2` / `at + 4` *before* handing the range to `get`, so the
  addition overflowed: a panic in a debug build, from the one family of functions
  whose entire purpose is to be the non-panicking read — and in a release build a
  wrapped range that can land back in bounds and silently return the wrong bytes,
  which is worse. The offsets these take come from scans over attacker-supplied
  firmware, and the triggering value is not hypothetical: a handler pointer read
  out of erased flash is `0xFFFF_FFFF`, which masked to even is `0xFFFF_FFFE` —
  exactly the offset that overflows on a 32-bit target. Both now use
  `checked_add`.

- **`Asm::mov_reg` emitted `adds rd, rm, #0` and clobbered the flags.** Through
  0.1.0 it emitted `0x1C00 | rm << 3 | rd`, which is not `MOV` at all: it is
  `ADD (immediate)` T1 with `imm3 == 0`, and it writes N, Z, C and V. **Any
  sequence that moved a register between a `cmp` and its `b<cond>` was silently
  miscompiled**, because the move destroyed the comparison's flags before the
  branch read them. The flag-setting move now has to be asked for by name, as
  `Asm::movs_reg`.
- **`find_bl_sites` missed a `BL` occupying the final four bytes of an image.**
  The scan bound was `0..image.len().saturating_sub(4)`, which is *exclusive* of
  `len - 4` — a legal site, and exactly where a trailing thunk or an
  end-of-region dispatch table puts one. Now `saturating_sub(3)`, so the last
  offset examined is `len - 4`. The regression test was verified red against the
  old bound.
- **`Mem` folded the architectural `U` bit into a sign, so `#0` and `#-0`
  collapsed.** Seventeen places in DDI 0403E.e say in as many words that
  "different instructions are generated for #0 and #-0", and A7.7.51 lists
  `LDRD<c> <Rt>,<Rt2>,[PC,#-0]` as an encoding in its own right. In an `i32`,
  `-0 == 0`, so a sign-corrected offset destroyed `U` on decode and had to
  invent it on re-encode — **breaking exact re-encoding on 874 encodings across
  the dual, load, store and coprocessor groups.** `offset` is now an unsigned
  magnitude and `add` is the `U` bit itself, so every bit pattern of the pair
  denotes a distinct, legal addressing form.
- **Advanced SIMD data processing was implemented but unreachable.** The whole
  `VADD`/`VAND`/`VMUL`/`VSHL` grid lives in `t32_simd`, but both halves of its
  space set `op2[6]`, which Table A5-9 gives to the coprocessor arm — so all
  33,554,432 of those patterns decoded to `None` no matter how completely they
  were implemented. The dispatcher now falls through from `t32_coproc` to
  `t32_simd` on both coprocessor arms, which is what makes NEON reachable at
  all.
- **A `t32_dp_reg` encoder wrote `Rd` to the wrong nibble.** Its second halfword
  was built as `0xF000 | rd << 12 | op2 << 4 | rm`, putting `Rd` in `hw2[15:12]`
  — the field the group's own first rule requires to be `1111` — where `decode`
  correctly reads it from `hw2[11:8]`. `Rd` was therefore discarded, and only
  instructions whose destination was `r0` re-encoded: **18,768 of 300,288,
  exactly one sixteenth**. The module's own sweep could not catch it, because
  its test helper repeated the same formula and the two agreed; the
  cross-module round trip through the public `isa::encode` is what found it.
- **`ItState::advance` advanced only the mask, so the else-arm of every `ITE`
  came back with the un-inverted condition.** `ITAdvance()` (A7.3.2) shifts
  `ITSTATE<4:0>`, and `ITSTATE<4>` is the **low bit of the condition**, not the
  top of the mask — so the shift crosses the cond/mask boundary and each step
  pulls `mask<3>` into `cond<0>`. That bit is the `T`/`E` selector, and it is
  what makes the else-arms of an `ITE`/`ITTE`/… block run on the *inverted*
  condition. Advancing only the mask looks right and *is* right for an all-`T`
  block, and hands back a silently wrong answer about control flow for every
  `E` arm. `ItState::advance` is now the pseudocode line for line.

### Removed

Nothing. Every item that shipped in 0.1.0 is still present under the same name;
the three breaking changes above are signature and behaviour changes, not
removals.

## [0.1.0] - 2026-09-22

### Added

- Initial extraction from `freemkv-firmware`'s internal `thumb.rs` toolkit into
  a standalone crate: `find`/`read_u32`/`read_u8`/`write`/`insert` byte-image
  primitives, `CommandTable` for SCSI-style opcode dispatch tables, `Asm` (a
  small position-independent Thumb assembler with a literal pool and data
  blobs), and `encode_bl`/`decode_bl`/`encode_b_wide`/`decode_b_wide`/
  `find_bl_sites` for Thumb/Thumb-2 branch encoding.
- 100% line/region/function test coverage (`cargo llvm-cov`).

[Unreleased]: https://github.com/MattJackson/thumb-asm/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/MattJackson/thumb-asm/compare/v0.1.0...v0.10.0
[0.1.0]: https://github.com/MattJackson/thumb-asm/releases/tag/v0.1.0
