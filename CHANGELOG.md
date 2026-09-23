# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
