<!--
SPDX-FileCopyrightText: 2026 Matthew Jackson <dev4@getbusbar.com>
SPDX-License-Identifier: MIT
-->

# Assurance case

An assurance case is a structured argument, supported by evidence, that the
software is adequately secure for what it does. This is a short and honest one
for `thumb-asm`. It is not a proof, and it does not claim the crate is correct;
it sets out what is claimed, why, and on what evidence, so that a reader can
check the argument rather than take the badge's word for it.

Read it with [`SECURITY.md`](../SECURITY.md), which defines the scope, and
[`CONFORMANCE.md`](CONFORMANCE.md), which is where most of the evidence
actually lives.

## What the software is, for the purpose of this argument

A zero-dependency, pure safe Rust library that decodes, disassembles,
assembles, relocates and patches ARM Thumb and Thumb-2 instructions in a
caller-owned `&[u8]`. No cryptography, no I/O, no network, no global state, no
Cargo features, no code generation, no `unsafe`. Nothing in it executes
anything.

That negative surface matters, because it removes most of the categories a
security argument usually has to cover. There is no transport to protect, no
key to leak, no session to fixate, and no dependency tree to be compromised.

## Claim

> **`thumb-asm` will not silently produce a wrong instruction.** For any input
> it accepts, it either produces the bytes the architecture defines, or it
> refuses with a specific error — and it never crashes or hangs in a way that
> the caller was not told to expect.

The claim is about **correctness as safety**, and that framing is deliberate.
The realistic harm from this crate is not a memory-safety exploit: safe Rust
with `#![forbid(unsafe_code)]` removes that class structurally. The realistic
harm is that a consumer takes this crate's output, writes it into firmware, and
flashes it. A mis-encoded instruction does not raise an error anywhere. It
bricks a device, or worse, changes what the device does. **A wrong answer here
is the security failure**, and it is a failure this crate cannot detect after
the fact, because nothing downstream of it will notice either.

## Threats considered

| # | Threat | Why it is the one to worry about |
|---|---|---|
| T1 | **A systematic misreading of the architecture manual** — a field read one bit too wide, a `U` bit inverted, an immediate shifted by the wrong amount | The encoder and decoder agree with *each other* perfectly and are both wrong. Round-trip testing cannot see it. This is the top threat. |
| T2 | **An out-of-range operand encoded as a different instruction** rather than rejected | The caller asked for something impossible and got something plausible. |
| T3 | **A relocated instruction whose meaning changes with its address** | `Align(PC, 4)` does not move linearly; a literal load moved into a stub no longer reaches its pool. |
| T4 | **A partially installed patch** — a detour that fails halfway and leaves the image modified | Half a trampoline over live code is worse than no trampoline. |
| T5 | **Panic or non-termination on hostile input** | A firmware image is untrusted data; a disassembler that aborts on a crafted byte pattern is a denial of service for the analysis around it. |
| T6 | **Memory-safety defects** — out-of-bounds read, overflow, use-after-free | The classic class, and the one this crate is structurally unable to have. |
| T7 | **Supply-chain compromise** | A dependency, a build script, a mutable action tag. |

## Sub-claims and evidence

### 1. Memory safety is eliminated by construction, not by scanning for it (T6)

*Argument.* The crate is `#![forbid(unsafe_code)]` at the root — `forbid`, not
`deny`, so no module can opt back in. Every slice access is bounds-checked by
the language. There is no C, no assembly, no build script and no code
generation anywhere in the repository.

*Evidence.* `src/lib.rs`; `cargo clippy --all-targets --all-features -D
warnings` on every push; the `unsafe: forbidden` badge in `README.md`, which
the project treats as a claim it has to keep true. Integer overflow in the
shifting and masking that *is* the encoding work is caught as well: `cargo
test` runs the debug profile, where arithmetic overflow panics, across every
CI cell.

### 2. There is no supply chain to compromise (T7)

*Argument.* `[dependencies]` is empty. Not "few dependencies" — none. There is
consequently no transitive package that an advisory can apply to, no lockfile
to pin (none is committed, which is why no cargo invocation passes `--locked`),
and no third-party code in the build closure beyond rustc and Cargo themselves.

*Evidence.* `Cargo.toml`; the `dependencies: 0` badge; `cargo
package`/`publish --dry-run` in the qa gate. On the CI side, every third-party
GitHub Action is pinned to a full commit SHA with the readable ref in a
trailing comment, because a tag is not an identity — its owner can repoint it —
and Dependabot moves those pins weekly onto `dev`. Releases publish via
crates.io Trusted Publishing, so no long-lived registry token exists to be
stolen.

### 3. The encoder is the decoder's inverse, and the round trip is swept, not sampled (T1, partially)

*Argument.* Every one of the nineteen encoding-group modules implements an
`encode` beside its `decode`, and sweeps the round trip across its own slice of
the encoding space — **with the probe count pinned as a literal in the test**,
so a change in what decodes surfaces as a failing census rather than as a
silently larger or smaller sweep. `isa::encode`'s dispatch is *verified*: every
candidate encoding is decoded again and compared before it is returned, so a
group that accepts a neighbour's instruction wastes work instead of emitting
the wrong bytes.

*Evidence.* The per-module sweeps under `src/isa/`, run on every push;
`spec/THUMB-ISA.md` §4, which runs the same round trip across all 402,712,576
bit patterns a Thumb stream can present, at an address deliberately 2 mod 4 so
that every `Align(PC, 4)` form is exercised at the alignment where getting it
wrong shows.

*Limit, stated because it is the whole point of the next sub-claim.* This
proves the encoder and decoder agree with **each other**. T1 round-trips
perfectly. Internal consistency is necessary and it is not sufficient.

### 4. An independent implementation corroborates the encodings (T1)

*Argument.* What closes the gap in §3 is corroboration by an implementation
nobody here wrote. `tests/conformance.rs` decodes bytes, prints UAL, hands that
text to LLVM's assembler, and compares the bytes LLVM produces with the bytes
it started from. If LLVM reads our text back as the same bytes, LLVM understood
it as the instruction the bytes encode. That is a byte-level claim — no
normalisation, no judgement, no interpretation, and specifically not a text
comparison, because a text normaliser is exactly where a real bug goes to hide.

*Evidence.* **929,088 probes**: all 59,392 halfwords of the 16-bit space
exhaustively, 669,696 structured 32-bit probes (every one of the 6,144 first
halfwords crossed with 109 second-halfword field-boundary vectors), and 200,000
pseudorandom probes from a printed seed. 98.04% of the 16-bit space
round-trips byte-for-byte; of the patterns this crate *claims* to decode,
99.99% in the 16-bit space and 91.9% in the 32-bit structured sample are
corroborated byte-for-byte, with a further 6.9% at the weaker
mnemonic-and-operands level. Every divergence is in a **21-entry allow-list**,
each entry citing the Arm manual clause that justifies it, each carrying a
probe budget so a broad entry cannot quietly absorb a regression. **Anything
not on the list fails the test.** The sweep is a job in the qa gate, not an
occasional manual run.

*This has caught real defects.* Three printer defects, all found by this
harness: `ldr r0, [pc]` printed without its `#0` and therefore re-assembling as
the wrong (wide) encoding; `push {}` printed for an empty register list, which
no assembler parses; and VFP immediates printed as integers, which LLVM rejects
outright. All three are fixed, and the rows are kept in
[`CONFORMANCE.md`](CONFORMANCE.md) because a harness is best judged by what it
caught rather than by being currently green.

### 5. 100% coverage is enforced, and mutation testing says what that number is worth (T1, T2)

*Argument.* Coverage is a floor in CI, not a report that can drift: `cargo
llvm-cov --fail-under-lines 100 --fail-under-regions 100 --fail-under-functions
100` in the qa gate, so an unexercised error path fails the build and names
itself. But 100% coverage says every line *ran*, not that any line was
*checked*, and that difference is not academic here — a data-processing encoder
that wrote `Rd` at bit 12 where the manual says bit 8 survived fourteen tests,
because the test helper built its expected halfword with the same formula as
the encoder it was checking.

*Evidence.* The coverage job in `qa.yml`; 601 library tests, 9 conformance
tests and 36 doctests. Against that, periodic `cargo-mutants` runs: **7,820
mutants, 91.1% caught, 99.2% once the provably-equivalent families are set
aside** (594 survivors are `|` replaced by `^` across disjoint bit-fields,
which computes the same value — and that the fields really are disjoint is not
an assumption, it is what the 669,696-probe round-trip sweep proves; 4 more
are `r.num() < 16`, which `Reg::num` makes unconditionally true). The
remaining survivors are real and are named as such in
[`CONFORMANCE.md`](CONFORMANCE.md) and on [`../ROADMAP.md`](../ROADMAP.md),
rather than rounded away. The run is not decoration: it produced operand
validation on every `Asm` emitter, tests pinning `first_operand_is_source` and
`Insn::writes_pc`, and a test for `prologue_len`, whose entire body could be
replaced by a constant unnoticed — and which is the offset displaced
instructions are copied to, so a wrong value writes them over the trampoline's
own prologue.

### 6. An impossible request is an error, not a different instruction (T2)

*Argument.* Fallibility is in the types, at the point where the mistake is
made. `Asm::finish` is fallible: an out-of-range branch, `ldr` literal or
`adr`, or a label referenced and never bound, is an `AsmError` rather than a
mis-encoded instruction. Every `Asm` emitter validates its operands.
`install_branch` decodes back what it just wrote and returns `InstallMismatch`
if it does not match, so a patch that did not land is an error at the call site
rather than a surprise on the bench. `Cond::from_bits` rejects `0b1111` instead
of inventing a fifteenth condition, because the architecture does not define
one.

*Evidence.* `AsmError`, `InstallMismatch` and the `Result<T, E = AsmError>`
alias in the public API; the emitter validation tests added as a direct result
of the mutation run (mutation flipped `<<` to `>>` in three emitters, dropping
the register field so everything assembled against `r0`, and nothing failed —
that is now caught); the 100% region-coverage floor, which forces the error
paths to be exercised rather than merely present.

### 7. Relocation refuses anything whose meaning depends on its address (T3)

*Argument.* `relocate` never redoes pc arithmetic. An `Operand::Target` is a
resolved absolute address, so relocation holds the target still and asks only
whether the new displacement fits — which is the opposite of recomputing an
offset and hoping. Where the answer is "this cannot move and still mean the
same thing", it refuses: a displaced literal load is refused rather than
silently re-pointed, because its pool does not move and ±1020 (or ±4095) bytes
essentially never reaches free space from a stub. Widening is applied only to
direct branches, where it actually buys something.

*Evidence.* `RelocateError` and its variants; the rustdoc on `relocate`, which
names `Align(PC, 4)`'s non-linearity as the specific trap the function exists
to avoid; the documented hazard list in `README.md` under "Encoding hazards are
named, not hidden" — including that `B<cond>.W` T3 packs its immediate
differently from `B.W` T4, and that reusing T4's arithmetic for T3 yields a
target that is plausible, wrong, and about 12 MB away.

### 8. A detour is planned completely before a byte is written (T4)

*Argument.* `detour::tramp` decodes what the hook branch would displace,
relocates it, lays out the stub and checks reachability **first**. If any step
cannot be done safely it refuses, with a specific reason — the site is not an
instruction boundary, a displaced instruction is inside an `IT` block, a
literal load's pool would no longer be in reach, the stub cannot be reached
from the site — and **on any error the image is byte-for-byte unchanged**.
There is no partially installed state to recover from.

*Evidence.* `DetourError`'s variants; the atomicity guarantee stated in
`README.md` and in the `detour` module rustdoc; the module-level doctest, which
is the README's example verbatim and which `cargo test --doc` runs on every
push and on all six cells of the qa OS × MSRV matrix; `examples/trampoline.rs`,
which CI executes so the documented composition cannot drift from the API.

### 9. Panicking and non-panicking input handling are distinguished in the type system (T5)

*Argument.* The API is split on purpose. `read_u8`/`read_u16`/`read_u32` index
the slice and are documented to panic past the end of the image — they are for
an offset a search has already proved in bounds.
`try_read_u8`/`try_read_u16`/`try_read_u32` return `Option` and are for walking
untrusted data to its end. The distinction is in the signature, not in a
comment, and `SECURITY.md` says which side of it a report has to land on.
Decoding itself allocates nothing, and `isa::Decoder` walks from a known start
rather than guessing phase.

*Evidence.* The two families in the public API and their rustdoc; the scope
section of [`SECURITY.md`](../SECURITY.md); the decoder's no-allocation
property, stated in `README.md`.

### 10. Every claim is traceable to its source (T1)

*Argument.* Nothing rests on anything hidden. Every encoding claim in `src/`
cites the Arm architecture reference manual section it came from, and `spec/`
holds the manuals (DDI 0403E.e and DDI 0406B among them) so a reader can check
rather than trust. `spec/THUMB-ISA.md` walks the encoding space section by
section and states coverage in counts with the counting method, because a
percentage on its own is not checkable. Where this crate is deliberately
stricter than LLVM, the allow-list entry names the clause; a divergence that
cannot cite one is a bug, not a divergence.

*Evidence.* `spec/`, `spec/THUMB-ISA.md`, `tests/support/divergences.rs`, and
the per-item rustdoc. The repository is public and MIT licensed, so all of it
is reviewable by anyone who cares to.

## Residual risks, stated plainly

- **No fuzzing.** There is no fuzzer. The suite is thorough but it exercises
  chosen inputs; it does not vary them. The decode path reads
  attacker-influenced firmware bytes, which is where a fuzzer would earn its
  keep. The OpenSSF `dynamic_analysis` criterion is answered **Unmet** for this
  reason rather than argued around, and closing it is on
  [`../ROADMAP.md`](../ROADMAP.md).
- **No formal verification.** No part of this crate is proved correct against a
  formal model of the architecture. The argument above is evidence and
  corroboration, not proof, and it cannot become proof by adding more probes.
- **The conformance numbers depend on the LLVM release.** They move with it:
  LLVM is lenient about different UNPREDICTABLE clauses in different versions,
  spells some aliases differently, and gains instructions over time. This is not
  hypothetical — the first CI run of these sweeps saw the byte round-trip
  collapse from 98% to 0.36% on LLVM 18 while passing on LLVM 23, because
  `.arch` resets the assembler to Arm state on the older release. The figures
  quoted here are from a specific run against a specific `llvm-mc`; CI
  deliberately runs against a different version so the claim is tested against
  more than one reading of the reference.
- **Agreement on rejection is weak evidence.** Around 31% of 32-bit probes are
  rejected by both implementations. Two implementations agreeing that something
  is *not* an instruction is far weaker than agreeing what an instruction *is* —
  they can be wrong together, and for the Advanced SIMD space "neither decodes
  it" may mean this crate has a gap that the harness's Armv7 dialect happens to
  share.
- **Some encodings have no second opinion at all.** Saturate and bitfield
  instructions whose destination is `pc` are decoded here and neither read nor
  written by LLVM. That bucket is not corroboration; it is the absence of one,
  and `CONFORMANCE.md` labels it as the weakest row in the table.
- **Nothing here says anything about behaviour.** This is an encoding-level
  argument. It does not claim that `is_branch`, `writes_pc` or the `IT`-state
  tracking are right, and it does not claim a patched image works.
- **Sampling, not exhaustion, in the 32-bit space.** The structured sweep
  guarantees every first halfword and a systematic set of second-halfword field
  boundaries. It does not guarantee every *combination* of fields, and a bug
  needing two specific non-boundary immediates can hide from it.
- **Single maintainer, bus factor 1.** One person reviews, releases, and holds
  the crates.io ownership. No change reaching users has been reviewed by a
  second pair of eyes. See [`../GOVERNANCE.md`](../GOVERNANCE.md).

## Conclusion

Within the scope in [`SECURITY.md`](../SECURITY.md), `thumb-asm` is adequately
secure for its purpose: the memory-safety class is structurally absent, the
supply chain is empty, the correctness claim that actually matters is
corroborated by an independent implementation across 929,088 probes with every
divergence justified against the architecture manual, the tests are enforced at
100% coverage and audited by mutation testing rather than trusted, and every
operation that cannot be performed faithfully refuses instead of guessing.

The gaps are named above rather than omitted. This document is revisited
whenever the threat model or the evidence changes — a fuzzer landing, a 1.0, a
second maintainer, or a conformance run whose numbers move.
