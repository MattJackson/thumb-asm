<!--
SPDX-FileCopyrightText: 2026 Matthew Jackson <dev4@getbusbar.com>
SPDX-License-Identifier: MIT
-->

# Roadmap

Direction of travel, not a commitment, and certainly not a schedule. Nothing
below has a date, and an item can be dropped if it stops being worth doing.
This is a single-maintainer project ([`GOVERNANCE.md`](GOVERNANCE.md)) and the
standing priority is correctness over feature count; anything here is subject to
that.

What the crate deliberately does *not* try to do is in `README.md` under
"Design, and what this is not", and it is not a roadmap item — an ELF reader, a
simulator, or a loader are not coming. What is currently covered, and what is
not, is counted section by section in
[`spec/THUMB-ISA.md`](spec/THUMB-ISA.md). Per-release honesty lives in
[`CHANGELOG.md`](CHANGELOG.md).

## Near term

- **Close the remaining real mutation survivors.** `cargo-mutants` generates
  7,475 mutants; 89.0% are caught, and 96.9% once the provably-equivalent
  families are set aside. The **206** that remain are real — each is a change to
  behaviour that nothing asserts. They are concentrated in `encode` guard
  clauses, the `if insn.encoding != … { return None }` checks that refuse
  operand shapes a group cannot hold, and the round-trip sweeps miss them by
  construction because a sweep only ever hands `encode` an instruction that
  already decoded. Killing them means tests that feed `encode` deliberately
  wrong-shaped input. See `docs/CONFORMANCE.md`, "Mutation testing".

- **Fuzz the decoder.** There is no fuzzer today. That is why the OpenSSF
  `dynamic_analysis` criterion is answered **Unmet** rather than argued around:
  the test suite is thorough but it exercises chosen inputs, and fuzzing is
  about varying them. The decode side reads attacker-influenced firmware bytes,
  which is textbook fuzzing territory. The shape is a `cargo-fuzz` target over
  the decoders plus a decode/encode round-trip property, run nightly rather than
  in the inner loop. This is new test infrastructure, which is why it has not
  been bolted on as a hygiene change.

- **Review the ThumbEE and coprocessor spaces.** Both are covered, and both are
  the least even parts of the map: ThumbEE's re-assigned 16-bit space sits at
  3,840 of 4,096 halfwords, with three differences that deliberately produce no
  code and are documented as a cost; the coprocessor, floating-point and
  Advanced SIMD arm of A5.3.18 is the one place where decoding is a chain rather
  than a match. Both deserve a pass that either closes the gaps or writes down
  why each one stays open, the way the 16-bit exceptions are already named one
  at a time.

- **Consider a `no_std` build.** The crate needs `std` for very little — it
  works on a caller-supplied slice, does no I/O, and holds no global state — and
  its natural users are embedded. The open questions are what the allocating
  APIs (`Asm`, `disassemble`, the analysis walks) should become, and whether the
  answer is `alloc` plus a feature flag or a genuinely allocation-free subset.
  Today there are no Cargo features at all, and adding the first one is a
  decision, not a tweak.

- **1.0, once the API has had real consumer exposure.** The API is not frozen
  and a minor bump may still break it; 0.10.0 broke three things from 0.1.0. A
  1.0 is a promise about stability, and the only thing that earns that promise
  is a stretch of the API being used to patch real images without needing to
  change shape. Until then the 0.x contract stands and `cargo semver-checks`
  keeps it honest.

## Further out

- **A second maintainer.** The bus factor is 1, and the crates.io ownership and
  repository admin are held by one person
  ([`GOVERNANCE.md`](GOVERNANCE.md#access-and-continuity)). A second independent
  owner who can review and release is the single change that would most improve
  the project's resilience, and it would also unlock the review practices a solo
  project simply cannot meet.

- **A text front end.** `Asm` is a programmatic builder and `isa::encode` takes
  an `Insn`; nothing here parses assembly text. That closes off one half of the
  conformance loop — LLVM's disassembly of a pattern this crate rejects cannot
  currently be fed back through our own assembler, so the reverse direction
  stops at a census (`docs/CONFORMANCE.md`). A parser would make that loop worth
  building.

- **A security-oriented static analyser in the gate.** Clippy with `-D warnings`
  is a genuine static analysis and it runs on every push, but it is a
  defect-and-idiom linter rather than a vulnerability scanner, which is why the
  OpenSSF `static_analysis_common_vulnerabilities` criterion is answered Unmet.
  A CodeQL job with `language: rust` in the qa gate would settle it.

## How to influence this list

Open an issue saying what a change would buy someone patching a real image —
which encoding, which device, what the current behaviour forced you to work
around. Concrete reports from real firmware move items up this list faster than
anything else: the required `align` parameter on `find_free_space` exists
because the one known consumer was working around its absence by over-asking
for `len + 16` bytes.
