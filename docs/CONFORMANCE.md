<!--
SPDX-FileCopyrightText: 2026 Matthew Jackson <dev4@getbusbar.com>
SPDX-License-Identifier: MIT
-->

# Conformance against LLVM

Every encoding group in this crate is covered by an internal decode/re-encode
round trip. That is a strong property and it is not the property anyone
actually wants. It proves the decoder and the encoder agree with **each
other**. A systematic misreading of the architecture reference manual — a field
read one bit too wide, a `U` bit inverted, an immediate shifted by the wrong
amount — round-trips perfectly and is still wrong, in both directions, in
exactly the same way.

What closes that gap is corroboration by an implementation nobody here wrote.
`tests/conformance.rs` is that corroboration: it asks LLVM, the most widely
deployed independent implementation of the Thumb encodings, whether this
crate's disassembly means what the bytes mean.

## The loop

```text
    bytes  →  our decoder  →  our UAL text  →  LLVM assembler  →  bytes′
    assert bytes′ == bytes
```

If LLVM reads our text back as the same bytes, then whatever we printed, LLVM
understood it as the instruction the bytes encode. That is the whole claim, and
it is a byte-level claim — no judgement, no normalisation, no interpretation.

### Why not compare disassembly text

The obvious design is to disassemble each pattern with both implementations and
`assert_eq!` the two strings. It was tried and rejected, and the reason matters
enough to record, because "just compare the text" is what everyone suggests
first.

The two disassemblers disagree constantly about things that have nothing to do
with correctness:

| | this crate | LLVM |
|---|---|---|
| branch destination | resolved address, `b 0x20` | pc-relative offset, `b 0x1c` |
| immediates | `#31` below ten in decimal, `#0x1f` above | `#0x1f` throughout |
| `adr` | resolved address | offset from `Align(PC,4)` |
| register lists | runs collapsed, `{r4-r11, pc}` | enumerated, `{r4, r5, …, pc}` |
| M-profile special registers | `APSR`, `PRIMASK` | `apsr`, `primask` |
| VFP immediates | `#5` | `#5.000000e+00` |
| `.w` suffix | on the mnemonic per UAL | absent on some mnemonics LLVM has no `.w` spelling for (`MUL`) |

Making a text comparison pass means writing a normaliser for every row of that
table. The normaliser is then the thing that decides what counts as a
disagreement — and a normaliser is precisely where a real bug goes to hide,
because the honest response to a failing case is indistinguishable from
"add another normalisation rule". The assemble-back loop deletes the whole
problem: formatting cancels out, and what survives is the only question worth
asking.

### The one piece of arithmetic the harness does

LLVM spells a branch or `adr` destination as an **offset from `PC`** where this
crate prints a **resolved address**. Every probe is decoded at address 0, and
in Thumb `PC` reads as the instruction's address plus four (ARM DDI 0403E.e
A5.1.2), so an `Operand::Target(t)` is handed to LLVM as `#(t - 4)`. That
constant `4` is the only architectural arithmetic in the harness; everything
else is bytes in and bytes out.

The alternative — writing `b . + t` and letting LLVM do the arithmetic — does
not work: LLVM relaxes a symbolic narrow branch to its wide form, or rejects
it outright ("branch target out of range"), so the encoding under test never
gets assembled.

### The fallback, and its limits

A large slice of the encoding space cannot round-trip through **any**
assembler, and not because anything is wrong. The architecture marks an
encoding UNPREDICTABLE — `STRD pc, sp, [r0]`, `LDM r0!, {r0}`, `ADD.W pc, r0,
r0` — LLVM's *disassembler* reads it happily, and LLVM's *assembler* then
refuses to write it back. Roughly 4% of the 32-bit probes are in that
position.

Where the byte loop cannot close, the harness asks a second, weaker question:
does LLVM's decoder read these bytes as the same mnemonic, on the same
registers, with the same immediate values? That comparison ignores everything
in the table above (width suffix, immediate radix, register-list spelling,
`sp`/`r13`) and keeps only meaning. If it holds, the probe is reported as
`agreed (LLVM's decoder, not re-assemblable)` — corroborated, one notch weaker,
because it confirms the *meaning* without confirming that every bit of the
encoding was accounted for.

This is the only place text is compared, it is never the primary check, and it
is reported in its own column so the weaker result is never silently counted as
the strong one.

### The reverse direction

Where an `llvm-objdump` is present the harness also asks LLVM's decoder about
every pattern this crate **rejects**, which is the one thing the forward loop
cannot see: a byte pattern LLVM understands and we do not. It stops at a
census. This crate has no assembler that parses text — `Asm` is a programmatic
builder and `isa::encode` takes an `Insn`, not a string — so LLVM's
disassembly cannot be fed back through our own assembler. If a text front end
is ever added, that loop becomes worth building; the census is the useful part
in the meantime.

The reverse census is asked only of the **Armv7** dialects. Asking an Armv8
decoder what it knows that this crate does not answers "the Armv8
instructions", which is true, uninteresting, and would bury the Armv7 gaps
that are the point.

## Running it

```sh
cargo test --test conformance -- --nocapture
```

`--nocapture` matters: the toolchain banner, the outcome tables and the skip
message are all printed, and libtest swallows stdout without it.

It is **not** gated behind `#[ignore]` or an environment variable. The whole
thing takes about twenty seconds, which is cheap enough to run by default, and a
conformance test nobody runs is worthless.

With no LLVM on the machine the test **skips and passes**, printing what it
looked for and where. A contributor who has not installed LLVM still gets a
green `cargo test`.

Useful environment variables:

| variable | effect |
|---|---|
| `THUMB_ASM_LLVM_BIN` | a directory to search first for `llvm-mc`, `clang`, `llvm-objdump` |
| `THUMB_ASM_CONFORMANCE_REPORT` | path to append a tab-separated row per unexplained divergence; also lifts the cap on how many are kept. This is how the table below was built |
| `THUMB_ASM_KEEP_SCRATCH` | keep the generated `.s`/`.o` files for inspection (they are otherwise deleted as soon as they have been read — a full sweep would otherwise leave hundreds of megabytes behind) |
| `THUMB_ASM_SKIP_LLVM` | force the skip path on a machine that *does* have LLVM, so the path contributors without LLVM will hit can be checked by someone who is not one of them |

### Toolchain discovery

`llvm-mc` is preferred; `clang` driving its integrated assembler is the
fallback and in practice the common case. Both are looked for under bare and
version-suffixed names (`-11` … `-21`, covering the Debian/Ubuntu/Fedora
packaging convention of shipping no unsuffixed symlink), on `$PATH` and in
`$THUMB_ASM_LLVM_BIN`, `/opt/homebrew/opt/llvm/bin`,
`/usr/local/opt/llvm/bin`, the Xcode command line tools and `/usr/bin`. A
candidate is only accepted after it has actually assembled `movs r0, #1` and
produced `01 20`, so an LLVM built without the ARM backend is skipped rather
than mistaken for a working one.

### Verified against

| tool | version | platform |
|---|---|---|
| `clang` (integrated assembler) | Apple clang 21.0.0 (`clang-2100.1.1.101`) | macOS 15 / arm64 |
| `llvm-objdump` | Apple LLVM 21.0.0 | macOS 15 / arm64 |

The `llvm-mc` path is implemented but **has not been exercised** — no `llvm-mc`
exists anywhere on the machine this was developed on. Its flags
(`--assemble --filetype=obj --triple=… -o`) are long-standing and its
diagnostic format is the same `file:line:col: error:` one `clang` uses, which
is all the harness parses, but treat the first CI run that finds an `llvm-mc`
as the real verification of that branch.

### Dialects

No single ARM variant covers the space this crate decodes: the M-profile
special registers do not exist for an A-profile assembler, Advanced SIMD does
not exist for an M-profile one, and `VSEL`/`VMAXNM`/`d16`–`d31` exist only from
Armv8. A probe counts as corroborated if **any** dialect round-trips it, which
is the right rule — the question is whether some real ARM implementation agrees
that these bytes mean this.

| dialect | directives | reverse census |
|---|---|---|
| Armv7-A | `.arch armv7-a`, `+idiv +sec +virt +mp`, `.fpu neon-vfpv4` | yes |
| Armv7E-M | `.arch armv7e-m`, `.fpu fpv5-d16` | yes |
| Armv8-A | `.arch armv8-a`, `+idiv +sec +virt +mp +crc`, `.fpu neon-fp-armv8` | no |

## Coverage: what is actually corroborated

Numbers from the run of 2026-09-23 against `llvm-mc` 23.1.1, over 929 088
probes in total.

**The LLVM version is part of the result, not a footnote.** These counts move
with it: LLVM is lenient about different UNPREDICTABLE clauses in different
releases, spells some aliases differently, and gains instructions over time.
CI runs the same sweeps against whatever LLVM the runner image carries — 18.1.3
at the time of writing — precisely so the claim is tested against more than one
implementation of the reference. A divergence that appears only on one version
is still a divergence and still needs an entry.

That is not hypothetical. The first time CI ran these sweeps, the byte
round-trip collapsed from 98% to 0.36% on LLVM 18 while passing on LLVM 23:
the dialect prologues wrote `.thumb` above `.arch`, and `.arch` resets the
assembler to Arm state on the older release, so every probe was being
assembled as a 32-bit Arm instruction. The disassembly comparison went on
agreeing throughout, because it reads the original probe bytes rather than the
assembled ones — which is exactly why the two directions are reported
separately below rather than merged into one number.

### 16-bit: exhaustive

All 59 392 halfwords whose top five bits make them 16-bit instructions
(ARM DDI 0403E.e A5.1) — that is every one of the 65 536 halfword values
except the 6 144 that are the *first* halfword of a 32-bit instruction, and
those are swept in the 32-bit pass with `hw2 == 0x0000` among others.

| outcome | count | share |
|---|---:|---:|
| agreed (bytes round-trip) | 58 225 | 98.04 % |
| both reject | 944 | 1.59 % |
| LLVM decodes, we reject | 215 | 0.36 % |
| byte mismatch | 8 | 0.01 % |

**98 % of the 16-bit encoding space is corroborated byte-for-byte by an
independent implementation.** The remaining 1.6 % is `both reject` — patterns
neither implementation calls an instruction, which is agreement of a kind but
not evidence of anything. The 223 divergences are all in the table below.

### 32-bit: structured plus pseudorandom

2³² is not enumerable. The space is covered three ways and reported
separately so a gap is visible rather than averaged away.

**Structured** — all 6 144 first halfwords in the 32-bit space (`hw1[15:11]` of
`0b11101`, `0b11110` or `0b11111`, with all eleven low bits free, so every
`hw1[15:4]` opcode pattern appears sixteen times with sixteen different `Rn`)
crossed with 109 second-halfword vectors: all-clear, all-set, `0x8000`,
`0x7FFF`, each of the sixteen bits alone, each of the sixteen bits alone
clear, a handful of asymmetric patterns, and — added after a gap was found —
every value of the `Rd` nibble `hw2[11:8]` and of the sub-opcode nibble
`hw2[7:4]` with ordinary registers around them. The hand-picked vectors alone
never put `r3`, `r6` or `r9` in `Rd`, and reached several instructions only
through a pattern naming `pc` in every field; since `<op> pc, pc` is
UNPREDICTABLE and LLVM refuses to assemble it, those instructions were being
compared only through the weaker disassembly path. 669 696 probes.

| outcome | count | share |
|---|---:|---:|
| agreed (bytes round-trip) | 393 231 | 58.72 % |
| agreed (LLVM's decoder, not re-assemblable) | 29 360 | 4.38 % |
| both reject | 204 981 | 30.61 % |
| LLVM decodes, we reject | 37 094 | 5.54 % |
| we decode, LLVM has no encoding | 5 024 | 0.75 % |
| byte mismatch | 5 | 0.00 % |
| we decode, LLVM rejects our text | 1 | 0.00 % |

**Pseudorandom** — 200 000 probes from a xorshift32 seeded `0x9E3779B9`, `hw1`
uniform over the 6 144 first halfwords and `hw2` from the generator's high
bits. No `rand` dependency: the crate has none and is to keep none, and a
three-line generator plus a printed seed reproduces any failure exactly.

| outcome | count | share |
|---|---:|---:|
| agreed (bytes round-trip) | 108 232 | 54.12 % |
| agreed (LLVM's decoder, not re-assemblable) | 5 246 | 2.62 % |
| both reject | 77 269 | 38.63 % |
| LLVM decodes, we reject | 7 468 | 3.73 % |
| we decode, LLVM has no encoding | 1 785 | 0.89 % |

### The honest statement

Of the instructions this crate **claims to decode**:

* in the 16-bit space, **99.99 %** are corroborated byte-for-byte — 58 225 of
  the 58 233 patterns this crate decodes. The eight that are not are the
  `ldr rN, [pc]` printer defect listed below;
* in the 32-bit structured sample, of the 427 621 probes this crate decodes,
  **91.9 %** (393 231) are corroborated byte-for-byte and a further **6.9 %**
  (29 360) at the weaker mnemonic-and-operands level. The remaining **1.2 %**
  (5 030) are the encodings LLVM will neither write nor read — overwhelmingly
  saturate and bitfield instructions whose destination is `pc` — and they are
  not corroborated at all, in either direction.

What is **not** corroborated, and should not be read as if it were:

* The 31 % of 32-bit probes both implementations reject. Two implementations
  agreeing that something is not an instruction is much weaker evidence than
  two implementations agreeing what an instruction is — they could be wrong
  together, and for the Advanced SIMD space in particular "neither decodes it"
  may mean "this crate has a gap and the harness's Armv7 dialect happens to
  share it".
* Anything outside the sampled 32-bit space. The structured sweep guarantees
  every `hw1` and a systematic set of `hw2` field boundaries; it does not
  guarantee every *combination* of fields. A bug that needs two specific
  non-boundary immediates to show itself can hide from this.
* Behaviour. Nothing here executes anything. This is an encoding-level
  agreement test and says nothing about whether the crate's `is_branch`,
  `writes_pc` or IT-state tracking are right.
* The 16-bit sweep's `both reject` bucket includes the whole permanently-
  undefined `UDF` space, which inflates it harmlessly.

## Mutation testing: what the coverage number does not say

This crate's test suite covers 100% of lines, regions and functions. That
number says every line ran. It does not say any line was *checked*, and the
difference is not academic: three separate real defects in this crate lived
under 100% coverage, and one of them — a data-processing encoder writing `Rd`
at bit 12 where the manual says bit 8, so fifteen sixteenths of its group
encoded wrongly — survived fourteen tests, because the test helper that built
the expected halfword used the same formula as the encoder it was checking.

Mutation testing measures the thing coverage cannot. It changes the source in
small, mechanical ways — an operator flipped, a comparison loosened, a return
value replaced by a constant — rebuilds, and reruns the suite. A mutant that
is *caught* is a change some test noticed. A mutant that *survives* is a change
to this crate's behaviour that the entire suite ran straight past.

### Result

`cargo-mutants` generates 7,624 mutants across the crate. The run is sharded
across two large spot machines and takes about 20 minutes of wall time. It
runs the library tests only (`-- --lib`): the LLVM differential suite costs
47 seconds per invocation and is a separate gate that runs once per push, and
running it once per mutant turns a 20-minute job into a 7-hour one. That
exclusion costs nothing measurable — a run with LLVM present and one with it
excluded returned identical per-shard counts.

| outcome | count |
|---|---:|
| caught | 6,669 |
| **missed** | **656** |
| timeout | 53 |
| unviable (did not compile) | 246 |

That is a mutation score of **91.1%**, counting a timeout as detected: a
mutation that makes a search loop spin forever is a difference the suite
notices, even though it notices it by hanging rather than by failing. The 53
are all in `lib.rs`'s search and allocator loops, which is where an off-by-one
in a loop bound has exactly that effect.

### Not every survivor is a gap

588 of the survivors are a single mechanical family: `|` replaced by `^`
in an expression ORing **disjoint** bit-fields into a fixed opcode. With no
overlap the two operators compute the same value, so the mutated program is
identical to the original and no test can distinguish them. That the fields
really are disjoint is not an assumption — the 669,696-probe round-trip sweep
proves `encode` reproduces the bytes each instruction was decoded from, which
could not hold if any field collided. A second family is a value written and
then unconditionally overwritten by a later fix-up pass; mutating a
placeholder that is always patched is unobservable by construction.

A third family is `r.num() < 16`, which is unconditionally true because
`Reg::num` is `self.0 & 0xF`; 4 survivors are that guard.

Setting those aside leaves roughly **64** survivors — a score of **99.1%** —
and those are real, in the sense that each is a change to behaviour nothing
asserts. They are concentrated in `encode` guard clauses (the `if
insn.encoding != … { return None }` checks that refuse operand shapes a group
cannot hold), which the sweeps do not exercise because the sweeps only ever
feed `encode` instructions that decoded successfully.

### What was fixed because of it

The run is not decoration; it changed the code. Surviving mutants directly
produced:

* operand validation on every `Asm` emitter, and the round-trip tests behind
  it — mutation flipped `<<` to `>>` in three emitters, dropping the register
  field entirely so the instruction assembled against `r0`, and nothing
  failed;
* tests pinning every clause of `first_operand_is_source` and of
  `Insn::writes_pc`'s source-first guard. Each is a chain of `||`s, and
  replacing any one with `&&` makes the whole chain unsatisfiable — no
  mnemonic starts with two different prefixes at once — so the guard silently
  disabled itself and `str pc, [r0]` began reporting as a pc *write*, which
  would corrupt any control-flow graph built on it;
* a test for `prologue_len`, whose entire body could be replaced with `0` or
  `1` unnoticed. It is the offset at which displaced instructions are copied
  into a trampoline, so a wrong value writes them over the prologue itself.

### Reproducing it

The run is not part of CI — it costs about an hour of CPU and CI should stay
fast. It is a periodic audit, not a gate:

```sh
cargo mutants -j 4 -- --lib          # the whole crate, slowly
cargo mutants -F 'Asm::' -- --lib    # one area
```

A survivor is not automatically a bug to fix. It is a question: *what would
break if this line were wrong, and would anyone find out?* Sometimes the
honest answer is "nothing, it is equivalent". The value is in having asked.

## The divergence table

LLVM is not the specification. It is deliberately lenient where the
architecture says UNPREDICTABLE, it implements profiles selectively, and its
assembler has syntax preferences of its own. Every divergence is listed here
and in `tests/support/divergences.rs`, with the clause it turns on. **Anything
not on the list fails the test.**

Several entries are keyed on a *region* of the encoding space rather than on a
single bit pattern, because the clause being enforced is a property of the
region's encodings and not of one mnemonic. That is a real weakness — a broad
entry could absorb a genuine regression — so every entry also carries a
**budget**: the most probes it may account for in one sweep, set from the
measured population with headroom for a different LLVM version having slightly
different opinions. A class that grows past its budget fails the test and names
itself. The budgets are the reason the region-level entries are tolerable; if
you tighten an entry's mask, tighten its budget too.

### Known and justified — this crate is stricter than LLVM

These are cases where the architecture declares an encoding UNPREDICTABLE and
this crate refuses it while LLVM's decoder accepts it. The crate's position is
the defensible one for a tool that disassembles firmware: naming an encoding
the manual refuses to define means inventing a meaning for it.

| id | region | citation | divergence |
|---|---|---|---|
| `t16-cmp-reg-t2-both-low` | `0x4500`–`0x453F` | A7.7.28 CMP (register) T2 | `N:Rm` and `Rn` both low, which T1 already covers, so T2 declares it UNPREDICTABLE. LLVM decodes it. |
| `t16-bx-should-be-zero-bits` | `0x4700`–`0x477F` | A7.7.20 BX T1, bits[2:0] are `(0)(0)(0)` | A should-be-zero bit is set. LLVM ignores them. |
| `t16-reserved-hint` | `0xBF50`–`0xBFF0` | A5.2.5 Table A5-7 | A reserved hint. Executes as `NOP` but has no mnemonic; LLVM prints `hint #n`. **Arguably LLVM is more useful here** — see below. |
| `t16-it-unpredictable-firstcond` | `0xBFE0`–`0xBFFF` | A7.7.38 IT | `firstcond == 0b1111`, or `AL` governing more than one instruction. |
| `t16-cps-no-flags` | `0xB660`, `0xB670` | A7.7.29 CPS T1 | `CPSIE`/`CPSID` naming no mask. LLVM prints `cpsie none`. |
| `t32-ldm-stm-unpredictable-register-list` | `0xE800`–`0xE9FF` | A7.7.41, A7.7.99, A7.7.101, A7.7.159 | list contains SP, or PC and LR together, or fewer than two registers. |
| `t32-dp-shifted-register-unpredictable` | `0xEA00`–`0xEBFF` | A5.3.11 and the per-instruction clauses | PC or SP in a register field that forbids it, or `hw2[15]`'s `(0)` bit set. |
| `t32-vfp-load-store-multiple-overrun` | `0xEC00`–`0xEDFF` | A7.7.258 VSTM, A7.7.235 VLDM | register list runs off the end of the bank, or the pre-UAL `FSTMIAX`/`FLDMIAX` odd-length form. |
| `t32-vmsr-vmrs-reserved-system-register` | `0xEE00`–`0xEFFF` | A7.7.247 VMSR, A7.7.246 VMRS, DDI 0406B A8.6.326 VMOV (imm) | a VFP system register the architecture does not define as writable (`FPSID` is read-only), or an Advanced SIMD `cmode`/`op` pair with no meaning. |
| `t32-modified-immediate-unpredictable-constant` | `0xF000`–`0xF1FF`, `0xF400`–`0xF5FF` | A5.3.2 `ThumbExpandImm` | a replication pattern is selected but the byte is zero, which the expansion pseudocode calls UNPREDICTABLE. LLVM evaluates it to `#0`. |
| `t32-plain-immediate-unpredictable` | `0xF200`–`0xF3FF`, `0xF600`–`0xF7FF` | A7.7.14 BFI, B5.2.3 MSR, A7.7.82 MRS | `msbit < lsbit`; `MSR` with `mask == '00'`; `MRS`/`MSR` with a should-be-one field wrong. |
| `t32-branch-misc-smc-hvc` | `0xF7E0`–`0xF7FF` | DDI 0406B B6.1.9 SMC; HVC is Virtualization Extensions, DDI 0406C only | `SMC`/`HVC` with should-be-zero bits set, and `HVC` itself (Virtualization Extensions, not decoded here). |
| `t32-load-store-single-rt-is-pc` | `0xF800`–`0xF9FF` | A7.7.163 STRB, A7.7.46 LDRB, A7.7.59 LDRSB, A7.7.63 LDRSH and the `…T` forms | transfer register is PC or SP, which no such encoding permits. |
| `t32-dp-register-pc-operand` | `0xFA00`–`0xFBFF` | A7.7.181 SXTAH, A7.7.220 UXTAH, A7.7.127 SDIV, … (A5.3.12) | an extend, reverse, shift or divide naming PC or SP. |
| `t32-ldc-stc-vfp-coprocessor-space` | `0xFC00`–`0xFDFF` | DDI 0406B A8.6.51 LDC/LDC2 | `LDC2`/`STC2` naming coprocessor 10 or 11, which the architecture reserves for the Advanced SIMD and floating-point space. |
| `t32-simd-table-lookup-list-overrun` | `0xFF00`–`0xFFFF` | DDI 0406B A8.6.406 VTBL/VTBX | the list of table registers runs past `d31`. LLVM decodes it and prints names off the end of its own register table (`{d30, d31, fpinst2, mvfr0}`), which is a fair illustration of why this crate refuses the encoding. |

### Known and justified — the bits carry more than any text can

| id | citation | divergence |
|---|---|---|
| `t32-adr-minus-zero`, `t32-adr-minus-zero-rejected` | A7.7.7 ADR T2/T3 | `ADR` with a zero offset: the subtracting T2 and the adding T3 encodings name the same address and no text can say which it came from. |
| `t32-saturate-bitfield-destination-is-pc` | A7.7.152 SSAT, A7.7.213 USAT, A7.7.14 BFI, … | destination is PC or SP. This crate decodes it; LLVM neither reads nor writes it, so there is no second opinion at all. This is the weakest bucket in the table: it is not corroboration, it is an absence of one. |

### Defects this harness found, and their fixes

All three were printer defects — the decode was right, the *text* was not
something an assembler could read back, which matters because `isa::disassemble`
output is what a user pastes into an assembler when writing a patch. All three
are fixed; the rows are kept because the harness's value is best judged by what
it caught, not by the fact that it is currently green.

| id | encodings | what was wrong | how it was fixed |
|---|---|---|---|
| `t16-ldr-literal-zero-offset-is-ambiguous` *(resolved — no longer diverges)* | `0x4800`, `0x4900`, … `0x4F00` (8) | `Mem`'s `Display` dropped a zero offset, so `LDR (literal)` T1 with `imm8 == 0` printed `ldr r0, [pc]` — text that does not say which encoding it came from, and which LLVM reads back as the 32-bit T2 form. | `Insn::Display` forces the `#0`, gated on three conditions together: the instruction is narrow, it has a pc-based `Mem`, and it carries a resolved `Operand::Target`. The obvious alternative was measured and rejected: `ldr.n r0, [pc]` assembles to `f8df 0000`, the *wide* form, under `armv7-a`, `armv7e-m` and `armv8-a` — LLVM ignores the `.n` here, so only the displacement selects the narrow encoding. A first attempt keyed on `base == PC` alone and over-fired on ~40 `strex`/`stc`/`ldrd`/`strd` probes with `Rn == pc`. |
| `t16-empty-register-list`, `t32-empty-register-list` | `0xB400`, `0xBC00`, `0xE880`–`0xE89F`, `0xE910`–`0xE92F`, … (130) | a `PUSH`/`POP`/`STM`/`LDM` with an empty register list decoded and printed `push {}` — syntax no assembler parses — while this crate rejected comparable UNPREDICTABLE encodings elsewhere (`BX` with should-be-zero bits set, `CMP` T2 with two low registers). An inconsistency as well as unassemblable output. | `BitCount(registers) < 1` refused for the narrow T1 forms and `< 2` for the wide T2 forms, in `decode` *and* `encode`. The two thresholds genuinely differ, because a narrow single-register `push` has no shorter spelling to be outranked by. Four allow-list entries became dead as a result and were deleted. |
| `t32-vfp-immediate-printed-as-an-integer`, `t32-simd-immediate-printed-as-an-integer` | `0xEE00`–`0xEFFF`, `0xFE00`–`0xFFFF` with an integral expanded immediate (14 seen) | `Operand::FpImm(5.0)` printed `#5`; LLVM's assembler accepts only a floating-point literal there, and rejects `vmov.f32 s1, #2` outright. | integral values print with a forced decimal point (`#5.0`, `#-19.0`, `#-0.0`); non-integral values are unchanged. |

### A judgement call worth revisiting

`t16-reserved-hint` — the eleven reserved values in the 16-bit hint space
(`0xBF50`, `0xBF60`, … `0xBFF0`). The architecture defines them: they are
reserved hints and they execute as `NOP` (A5.2.5, Table A5-7). This crate
returns `None` for them, so a disassembly of firmware that contains one shows
`.short 0xbf50` instead of an instruction, and the instruction-length walk is
unaffected but the listing is less useful. LLVM prints `hint #5`. Decoding
them as `hint #n` — or as `nop` with the raw `opA` retained — would be
strictly more informative and would not weaken any invariant. This is not a
correctness bug; it is a deliberate choice that is worth re-taking.

## CI

This belongs in `.github/workflows/qa.yml`, not `dev.yml`. It needs an LLVM
install (about 40 s on a GitHub `ubuntu-latest` runner, which already has
`clang` and `llvm` in its image) and about 20 s of runtime, and `dev.yml` is
deliberately a two-minute inner loop.

The job, ready to paste:

```yaml
  conformance:
    name: conformance against LLVM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Install LLVM
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends llvm clang
          llvm-mc --version || true
          clang --version
      - name: Sweep the encoding space against LLVM
        run: cargo test --test conformance -- --nocapture --test-threads=1
```

Notes for whoever adds it:

* `--nocapture` is not optional. Without it the outcome tables and the
  toolchain banner are swallowed and a green run says nothing about *what* it
  was checked against.
* `--test-threads=1` is not required for correctness — each test gets its own
  scratch directory — but it keeps the four tests' output from interleaving,
  which matters for a log a human reads.
* `llvm-mc` comes from the `llvm` package on Debian/Ubuntu (as
  `/usr/lib/llvm-*/bin/llvm-mc`, and usually also as `llvm-mc-NN`); `clang`
  alone is enough, and `llvm-objdump` from the same package enables the reverse
  census. The harness finds all three by itself; the `|| true` is there so a
  missing `llvm-mc` does not fail the step.
* Expected wall time: under a minute including the apt install. If it starts
  taking materially longer, `RANDOM_SAMPLES` in `tests/conformance.rs` is the
  dial.
* The harness skips cleanly with a printed message when no LLVM is found, so
  this job cannot go quietly green by accident — but it *can* go green having
  skipped, which is why the banner needs to be in the log.

## Extending the harness

* A new dialect is four lines in `DIALECTS`. Set `reverse: false` unless the
  dialect's profile is one this crate claims to implement.
* A new divergence is one entry in `tests/support/divergences.rs` — and the
  entry has to name the clause that justifies it. If you cannot write the
  citation, you have found a bug, not a divergence.
* Mirror any change to that file into the tables above. They are meant to be
  readable by someone who is not going to read the test.
