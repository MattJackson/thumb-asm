# OpenSSF Best Practices — passing-level answers for thumb-asm

> **Submitted.** The questionnaire was filed against project
> [14762](https://www.bestpractices.dev/projects/14762) on 2026-09-23 and the
> project is at **passing, 100%**. Three answers moved since this draft was
> written: `vulnerability_report_process` and `vulnerability_report_private`
> are Met (GitHub private vulnerability reporting is enabled, so the published
> process and the private channel are the same URL), and `version_tags` is Met
> now that v0.10.0 is tagged. The two remaining Unmets are both SUGGESTED and
> are recorded honestly rather than argued around:
> `static_analysis_common_vulnerabilities` and `dynamic_analysis`. This file
> stays as the reasoning behind each answer, so a re-submission or a
> silver-level attempt starts from evidence rather than from scratch.

A pre-filled draft of the [OpenSSF Best Practices](https://www.bestpractices.dev)
**passing**-level questionnaire, answered against what this repository actually
does. The point of this file is that it can be submitted without being
re-checked, so nothing below is aspirational: where the project does not meet a
criterion it says **Unmet** and says what would close it.

- Criteria text and IDs come from the badge project's own
  [`criteria/criteria.yml`](https://github.com/coreinfrastructure/best-practices-badge/blob/main/criteria/criteria.yml)
  and `config/locales/en.yml`, level `0` (passing) — 67 criteria, fetched
  2026-09-22, in the order the form presents them.
- Register with: **Matthew Jackson, matthew@pq.io**. Signup is a GitHub OAuth
  click-through at <https://www.bestpractices.dev>; there is no API for it.
- Project URL to enter: `https://github.com/MattJackson/thumb-asm`
  Repository URL: `https://github.com/MattJackson/thumb-asm`

## How the levels are scored, so the Unmets below don't cause alarm

- **MUST** — has to be Met or N/A. Anything else blocks the badge.
- **SHOULD** — has to be Met or N/A, *or* Unmet with a justification written in
  the box. An explained Unmet still passes.
- **SUGGESTED** — only has to be *answered*. A plain Unmet passes.

## Read this before submitting

1. **One MUST is currently Unmet: `vulnerability_report_process`.** There is no
   published process for reporting a vulnerability. This is the only thing that
   blocks the badge, it is a five-minute fix, and it is deliberately left for
   the maintainer because it involves promising something (a contact route, and
   implicitly a response time) that only he can promise. See the entry below for
   two ways to close it, including a ready-to-commit file.
2. **Submit after the branch is on `main`.** Every URL below points at
   `blob/main/...`. `CONTRIBUTING.md`, `REUSE.toml`, `LICENSES/`, `docs/` and
   `.github/dependabot.yml` exist on the working branch but have not reached
   `main` yet, so those links 404 until the usual dev → qa → main promotion.
   Submitting before then answers "Met" against a 404.
3. **Two answers are self-assessments about a person, not the repo**
   (`know_secure_design`, `know_common_errors`). They are pre-filled with the
   evidence in the code that supports them, but they are claims about the
   maintainer's knowledge and he should read them and agree before submitting.
4. Uncertain answers are marked **[JUDGEMENT]** with the reasoning, so they can
   be re-decided rather than re-derived. There are three.

---

## Basics

### Basic project website content

**`description_good` (MUST) — Met.**
The README opens with "An **ARM Thumb instruction builder, decoder and patch-site
finder** for Rust" followed by a paragraph in plain terms about operating on a
flat `&[u8]` firmware image. Minimal jargon beyond the domain's own.
<https://github.com/MattJackson/thumb-asm#thumb-asm>

**`interact` (MUST) — Met.**
The README covers obtaining it (the `[dependencies]` snippet, crates.io and
docs.rs badges), giving feedback and contributing (the "Contributing" section
links the issue tracker and describes the branch flow).
<https://github.com/MattJackson/thumb-asm#contributing>

**`contribution` (MUST, URL required) — Met.**
`CONTRIBUTING.md` states the process explicitly: work lands on `dev`, pull
requests run the fast gate whatever they target, `dev` → `qa` → `main` by
fast-forward only, and a release needs a version bump plus a CHANGELOG section.
<https://github.com/MattJackson/thumb-asm/blob/main/CONTRIBUTING.md>

**`contribution_requirements` (SHOULD, URL required) — Met.**
`CONTRIBUTING.md`'s "Source conventions" section is the requirements list:
`#![forbid(unsafe_code)]` and `#![deny(missing_docs)]` are non-negotiable, the
crate stays dependency-free, every encoding claim cites its Arm manual section,
and new public API arrives with tests. Formatting and lint requirements are
machine-enforced (`cargo fmt --all --check`, `cargo clippy -- -D warnings`).
<https://github.com/MattJackson/thumb-asm/blob/main/CONTRIBUTING.md#source-conventions>

### FLOSS license

**`floss_license` (MUST) — Met.** MIT.
<https://github.com/MattJackson/thumb-asm/blob/main/LICENSE>

**`floss_license_osi` (SUGGESTED) — Met.**
MIT is OSI-approved (<https://opensource.org/license/mit>) and is declared as
`license = "MIT"` in `Cargo.toml`, so crates.io and every downstream tool see
the same SPDX identifier.

**`license_location` (MUST, URL required) — Met.**
Both conventions the criterion names are satisfied: a top-level `LICENSE` file,
and a `LICENSES/` directory in REUSE layout holding the SPDX-identified text.
<https://github.com/MattJackson/thumb-asm/blob/main/LICENSE> and
<https://github.com/MattJackson/thumb-asm/blob/main/LICENSES/MIT.txt>

Worth mentioning in the box: the repository is REUSE 3.3 compliant
(`reuse lint` passes), so every file has machine-readable copyright and licence
information, and the Arm architecture reference manuals under `spec/` are
declared as `LicenseRef-Arm-Documentation` — Arm's copyright, redistributed for
reference only, excluded from the published crate — rather than being swept up
as MIT. <https://github.com/MattJackson/thumb-asm/blob/main/REUSE.toml>

### Documentation

**`documentation_basics` (MUST) — Met.**
README covers installation (the `[dependencies]` snippet), a complete worked
example (find free space, assemble a trampoline, install a branch, verify it),
what the crate does and does not do, and the MSRV. Using it "securely" is
addressed structurally rather than as a section: the crate is
`#![forbid(unsafe_code)]`, has no I/O and no dependencies, and the README's
"Design, and what this is not" documents the one hazard that matters — the
plain `read_u*` accessors index the slice and so panic past the end of the
image, and the `try_read_u*` forms returning `Option` are the ones to use when
walking untrusted input.
<https://github.com/MattJackson/thumb-asm#example>

**`documentation_interface` (MUST) — Met.**
Full rustdoc for the public API at <https://docs.rs/thumb-asm>, enforced rather
than hoped for: `#![deny(missing_docs)]` makes an undocumented public item a
compile error, and the `docs` job in `qa.yml` builds rustdoc with
`-D warnings -D rustdoc::broken_intra_doc_links`, so a dead doc link fails the
gate. The README additionally carries a capability → entry-point table.

### Other

**`sites_https` (MUST) — Met.**
`https://github.com/MattJackson/thumb-asm` (project site and repository),
`https://crates.io/crates/thumb-asm` (download), `https://docs.rs/thumb-asm`
(documentation). All HTTPS; there is no separate project website.

**`discussion` (MUST) — Met.**
GitHub issues and pull request discussions: searchable, per-URL addressable,
open to new participants, no proprietary client needed.
<https://github.com/MattJackson/thumb-asm/issues>

**`english` (SHOULD) — Met.**
All documentation, code comments and commit messages are in English, and bug
reports in English are accepted.

**`maintained` (MUST) — Met.**
Actively developed: the crate is mid-build-out toward full Thumb ISA coverage,
with CHANGELOG entries through 0.10.0, three staged CI gates, and weekly
Dependabot action-pin bumps.
<https://github.com/MattJackson/thumb-asm/commits/main>

---

## Change Control

### Public version-controlled source repository

**`repo_public` (MUST) — Met.**
Public git repository at <https://github.com/MattJackson/thumb-asm> (verified
public, not archived).

**`repo_track` (MUST) — Met.**
git records author, committer and timestamp for every change.

**`repo_interim` (MUST) — Met.**
`dev` carries ordinary interim work commits, not only releases; `qa` and `main`
are fast-forwarded from it. Everything between releases is publicly visible on
`dev`. <https://github.com/MattJackson/thumb-asm/commits/dev>

**`repo_distributed` (SUGGESTED) — Met.** git.

### Unique version numbering

**`version_unique` (MUST) — Met.**
Each release has a unique semantic version, declared once in `Cargo.toml`'s
`[package].version` and read from there by CI rather than duplicated — the
`manifest` job in `qa.yml` extracts it with `cargo metadata` and `release.yml`
publishes exactly the version that gate verified.
<https://crates.io/crates/thumb-asm/versions>

**`version_semver` (SUGGESTED) — Met.**
Semantic Versioning, and enforced, not merely intended: `cargo semver-checks`
runs in the qa gate against the greatest version already on crates.io and fails
when a change needs a bigger bump than `Cargo.toml` took (for 0.x, a breaking
change requires the minor). The README states the 0.x contract and the CHANGELOG
follows Keep a Changelog.

**`version_tags` (SUGGESTED) — Unmet.**
No tags exist in the repository yet. The machinery is in place and not
aspirational — `release.yml` pushes an annotated `vX.Y.Z` tag and opens a
matching GitHub Release as part of every publish — but the currently published
version (0.1.0) predates that workflow, so there is nothing tagged to point at.
*Closes itself:* the next release through `release.yml` creates the first tag.
This is SUGGESTED, so an Unmet here does not block the badge.

### Release notes

**`release_notes` (MUST, URL required) — Met.**
`CHANGELOG.md`, following Keep a Changelog: a human-written summary per version,
not a `git log` dump. It is mandatory rather than customary — `release.yml`
extracts the release body from the section for the version being released and
*fails the release* if that section is missing or empty.
<https://github.com/MattJackson/thumb-asm/blob/main/CHANGELOG.md>

**`release_notes_vulns` (MUST) — N/A.**
There have been no publicly known vulnerabilities in this crate, so no release
notes identify one. The criterion's own guidance says to choose N/A in that case.

---

## Reporting

### Bug-reporting process

**`report_process` (MUST, URL required) — Met.**
GitHub issues, enabled and linked from the README's Contributing section.
<https://github.com/MattJackson/thumb-asm/issues>

**`report_tracker` (SHOULD) — Met.** GitHub issues.

**`report_responses` (MUST) — Met.**
No bug reports have been submitted (0 issues have ever been opened), so there
are none unacknowledged. Say exactly that in the box — a vacuous Met with the
reason stated is the accurate answer, and reviewers accept it for a young
project.

**`enhancement_responses` (SHOULD) — Met.**
Same situation: no external enhancement requests have been filed. The project is
actively adding functionality, so the "no longer making enhancements → Unmet"
case in the criterion's guidance does not apply; see the CHANGELOG through
0.10.0.

**`report_archive` (MUST, URL required) — Met.**
The GitHub issue tracker is itself the public, searchable archive of reports and
responses. <https://github.com/MattJackson/thumb-asm/issues?q=is%3Aissue>

### Vulnerability report process

**`vulnerability_report_process` (MUST, URL required) — UNMET. This is the one
blocker.**

There is no published vulnerability-reporting process. `CONTRIBUTING.md` and the
README describe ordinary bug reporting but neither says what to do about a
security issue, and there is no `SECURITY.md` (confirmed: GitHub's community
profile for the repo reports no security policy).

Either of these closes it, and they can be combined:

- **Option A — GitHub private vulnerability reporting (no file, ~1 minute).**
  Settings → Code security → "Private vulnerability reporting" → Enable. GitHub
  then publishes a "Report a vulnerability" button on the Security tab, which is
  a published process *and* a private channel. Answer Met with the URL
  `https://github.com/MattJackson/thumb-asm/security/advisories/new`, and answer
  `vulnerability_report_private` Met with the same URL.
- **Option B — commit a `SECURITY.md`.** Put it at `.github/SECURITY.md` (GitHub
  surfaces it on the Security tab and when a new issue is opened). A sufficient
  draft, which still needs the maintainer to choose the contact address and be
  willing to stand behind the 14-day figure that `vulnerability_report_response`
  measures:

  > # Security policy
  >
  > ## Reporting a vulnerability
  >
  > Report privately, not as a public issue: use
  > [GitHub's private vulnerability reporting](https://github.com/MattJackson/thumb-asm/security/advisories/new),
  > or email <matthew@pq.io>.
  >
  > Expect an acknowledgement within 14 days. If a report is confirmed, the fix
  > is released as a new version on crates.io, the CHANGELOG entry names the
  > issue, and a GitHub Security Advisory is published.
  >
  > ## Scope
  >
  > `thumb-asm` is a `#![forbid(unsafe_code)]` library with no dependencies and
  > no I/O. It parses and emits Thumb instruction encodings from a caller-owned
  > `&[u8]`. The realistic reports are therefore: a panic reachable from
  > untrusted input via an API not documented as panicking, a mis-encoded or
  > mis-decoded instruction (a wrong patch in firmware is a safety problem for
  > whoever installs it), or an unbounded loop or allocation driven by input.
  >
  > Out of scope: panics from the `read_u8`/`read_u16`/`read_u32` accessors past
  > the end of the image, which are documented to index the slice — the
  > `try_read_*` forms returning `Option` exist for untrusted input. Also out of
  > scope: anything about the Arm reference manuals in `spec/`, which are Arm's
  > documents and not part of the published crate.
  >
  > ## Supported versions
  >
  > Pre-1.0: fixes land on the latest minor only. There are no long-term support
  > branches.

**`vulnerability_report_private` (MUST) — depends on the answer above.**
- Option A, or Option B with the email: **Met**, URL as above.
- If the maintainer decides reports should always be public: **N/A**, which the
  criterion explicitly permits ("If vulnerability reports are always public
  [...] choose N/A"), and `vulnerability_report_process` must then still be
  answered Met by saying so in writing somewhere public.

**`vulnerability_report_response` (MUST) — N/A.**
No vulnerability has been reported in the last 6 months (none ever). The
criterion says to choose N/A in that case.

---

## Quality

### Working build system

**`build` (MUST) — Met.**
`cargo build`. Standard Cargo project, no build script, no code generation, no
vendored artefacts — `cargo build` from a clean checkout reproduces the library
from source.

**`build_common_tools` (SUGGESTED) — Met.** Cargo, the Rust ecosystem's standard.

**`build_floss_tools` (SHOULD) — Met.**
rustc and Cargo are FLOSS (MIT OR Apache-2.0), and the crate has zero
dependencies, so the entire build closure is FLOSS. CI additionally uses only
FLOSS tooling (`cargo-llvm-cov`, `cargo-semver-checks`).

### Automated test suite

**`test` (MUST) — Met.**
A Rust test suite in-tree (`src/thumb_tests.rs` and per-module `#[cfg(test)]`
tests), plus doctests on the public API and a runnable `examples/trampoline.rs`
that CI executes so the README's example cannot drift from the API. Released as
FLOSS under the same MIT licence as the crate. How to run it is documented in
`CONTRIBUTING.md` and visible in the workflows.
<https://github.com/MattJackson/thumb-asm/blob/main/CONTRIBUTING.md#branches-are-the-pipeline>

**`test_invocation` (SHOULD) — Met.**
`cargo test` — the standard invocation for the language. CI runs
`cargo test --all-targets` and `cargo test --doc` (the latter separately,
because `--all-targets` silently excludes doctests).

**`test_most` (SUGGESTED) — Met, and this is one of the project's stronger
answers.** The qa gate enforces a hard **100%** floor on lines, regions *and*
functions via `cargo llvm-cov --fail-under-lines 100 --fail-under-regions 100
--fail-under-functions 100`. It is not a reported number that can drift; the job
goes red below it and names the regressed lines. The crate being a pure function
of its inputs with no I/O and no dependencies is what makes that bar
maintainable rather than aspirational.
<https://github.com/MattJackson/thumb-asm/blob/main/.github/workflows/qa.yml>

**`test_continuous_integration` (SUGGESTED) — Met.**
Three staged GitHub Actions gates. `dev.yml` on every push and every pull
request (fmt, clippy `-D warnings`, tests, doctests, the example). `qa.yml` on
`qa` adds a 3-OS × {stable, MSRV} matrix, the coverage floor, rustdoc link
checking, `cargo package`/`publish --dry-run`, and `cargo semver-checks`.
`release.yml` re-invokes `qa.yml` on the exact commit it is about to publish, so
"what qa proved" and "what release verified" cannot diverge.

### New functionality testing

**`test_policy` (MUST) — Met.**
Written policy, in `CONTRIBUTING.md`: "New public API arrives with tests — the
100% coverage floor in `qa` will say so otherwise." It is also mechanically
enforced, which is stronger than a policy: adding an instruction encoder without
a test for it drops coverage below 100% and fails the gate.
<https://github.com/MattJackson/thumb-asm/blob/main/CONTRIBUTING.md#source-conventions>

**`tests_are_added` (MUST) — Met.**
The evidence is that the coverage gate has stayed green across the ISA
build-out, which is impossible without tests arriving alongside each new
encoder. Per-version, the CHANGELOG's feature entries (the conditional-branch
surface in 0.2 — `Cond`, all fourteen conditions, the branch codec — and the
subsequent `src/isa/` expansion) each landed with their tests.
<https://github.com/MattJackson/thumb-asm/blob/main/CHANGELOG.md>

**`tests_documented_added` (SUGGESTED) — Met.**
Documented in `CONTRIBUTING.md`, which is the instructions for change proposals,
in the same sentence as the coverage floor that enforces it.

### Warning flags

**`warnings` (MUST) — Met.**
Several layers, all failing the build rather than printing:
`cargo clippy --all-targets --all-features -- -D warnings` (Clippy is a separate
linter, not just compiler warnings); `#![forbid(unsafe_code)]` and
`#![deny(missing_docs)]` in `src/lib.rs`; `cargo fmt --all --check`;
`RUSTDOCFLAGS: -D warnings -D rustdoc::broken_intra_doc_links
-D rustdoc::private_intra_doc_links` for the docs job. `clippy.toml` pins
`msrv = "1.58"` so MSRV-aware lints stay correct.

**`warnings_fixed` (MUST) — Met.**
`-D warnings` promotes every warning to an error, so a warning cannot be
accepted: the gate is red until it is fixed. There are no suppressed warnings
and no `continue-on-error` anywhere in the workflows.

**`warnings_strict` (SUGGESTED) — Met.**
`-D warnings` on `--all-targets --all-features` is the maximum practical
strictness, applied on every push rather than at release time.

---

## Security

### Secure development knowledge

> Both criteria in this group are self-assessments about a person. The evidence
> below is real and drawn from the code, but the maintainer should read and
> agree before answering Met.

**`know_secure_design` (MUST) — Met** *(maintainer to confirm)*.
Design choices in the crate that map onto the Saltzer–Schroeder principles the
criterion lists:
- *Economy of mechanism* — one library, zero dependencies, no feature flags, no
  I/O, no `unsafe`. Search is a single primitive over `Needle` with every named
  finder as an overload of it, rather than a family of near-duplicates.
- *Fail-safe defaults* — `Asm::finish` is fallible: an out-of-range branch,
  literal or `adr`, or a label referenced and never bound, is an `AsmError`
  rather than a silently mis-encoded instruction. `install_branch` decodes back
  what it wrote and returns `InstallMismatch` if it does not match, so a patch
  that did not land is an error rather than a later surprise. `Cond::from_bits`
  rejects `0b1111` instead of inventing a fifteenth condition.
- *Least privilege* — applied to the toolchain rather than to a runtime: every
  workflow declares `permissions:` explicitly and minimally, `release.yml`
  starts from `permissions: {}`, publishing uses a short-lived OIDC token
  (crates.io Trusted Publishing) so no long-lived registry credential exists in
  the repository at all, and the new `scorecard.yml` checks out with
  `persist-credentials: false`.
- *Open design* — no security rests on anything hidden: the repository is
  public, every encoding claim cites the Arm manual section it came from, and
  `spec/` holds those manuals so a reader can check rather than trust.

**`know_common_errors` (MUST) — Met** *(maintainer to confirm)*.
The relevant error classes for a byte-slice instruction codec, and how each is
countered here:
- *Memory-safety errors* (buffer overflow, out-of-bounds read, use-after-free) —
  eliminated by construction: safe Rust with `#![forbid(unsafe_code)]`, so slice
  accesses are bounds-checked by the language. The class cannot be present, as
  opposed to being scanned for.
- *Denial of service via panic on untrusted input* — the API is deliberately
  split: `read_u8`/`read_u16`/`read_u32` index the slice and are documented to
  panic past the end of the image (for offsets a search already proved in
  bounds), and `try_read_u8`/`try_read_u16`/`try_read_u32` return `Option` for
  scanning to the end of untrusted data. The panicking/non-panicking distinction
  is in the type, not in a comment.
- *Integer overflow and truncation* in offset and immediate arithmetic — the
  characteristic bug of an encoder. Countered by range checks that produce
  `AsmError` rather than wrapping, by `cargo test` running the debug profile
  with overflow checks on, and by the 100% region-coverage floor forcing the
  error paths to be exercised.
- *Incorrect encoding/decoding* — the class with real-world consequences, since
  a wrong patch bricks firmware. Countered by round-trip tests
  (`encode_*`/`decode_*` in both directions), by `install_branch` verifying what
  it wrote, and by citing the Arm manual section for every encoding so the
  claim is reviewable.
- *Supply-chain compromise* — no dependencies to be compromised; every GitHub
  Action pinned to a full commit SHA (a tag can be repointed by its owner) with
  Dependabot moving the pins weekly; secret scanning and push protection enabled
  on the repository.

### Use basic good cryptographic practices

**All nine criteria — N/A.** thumb-asm performs no cryptography and contains no
security mechanism of its own. It is a `no-I/O`, zero-dependency library that
assembles, encodes and decodes ARM Thumb instructions in a caller-supplied byte
slice: there are no keys, nonces, hashes, passwords, sessions, random numbers or
protocols anywhere in it. Answer N/A with that sentence for each of
`crypto_published`, `crypto_call`, `crypto_floss`, `crypto_keylength`,
`crypto_working`, `crypto_weaknesses`, `crypto_pfs`,
`crypto_password_storage`, `crypto_random`.

### Secured delivery against MITM attacks

**`delivery_mitm` (MUST) — Met.**
Everything is delivered over HTTPS/TLS: source from
`https://github.com/MattJackson/thumb-asm`, releases from
`https://crates.io/crates/thumb-asm` (crates.io is HTTPS-only and HSTS). Cargo
verifies a checksum for every downloaded crate against the registry index.
Stronger than the minimum: releases are published via crates.io Trusted
Publishing, so the artefact is uploaded by an OIDC-attested GitHub Actions run
on `main` rather than by a long-lived token that could be stolen and reused.

**`delivery_unsigned` (MUST) — Met.**
Nothing in the build or CI retrieves a hash or an artefact over plain HTTP.
Every `curl` in the workflows uses `https://`, action installs go through
`taiki-e/install-action` (which verifies its downloads), and every action is
pinned to an immutable commit SHA rather than to a mutable tag.

### Publicly known vulnerabilities fixed

**`vulnerabilities_fixed_60_days` (MUST) — Met.**
No vulnerability in thumb-asm is publicly known, so none is unpatched. There is
also no dependency surface: the crate has zero dependencies, so no advisory
against a transitive package can apply to it.
<https://rustsec.org/packages/thumb-asm.html>

**`vulnerabilities_critical_fixed` (SHOULD) — Met.**
None has been reported. The mechanism to act quickly exists and is exercised:
`release.yml` is a single push to `main`, so a fix can be released as soon as
the gate is green.

### Other security issues

**`no_leaked_credentials` (MUST) — Met.**
No credential is committed. The release path holds no registry token at all
(OIDC Trusted Publishing, minting a ~30-minute token per run); the only
repository secret is the forthcoming `CODECOV_TOKEN`, which is an upload token,
not an access credential. GitHub secret scanning **and push protection** are
both enabled, so a credential cannot be pushed in the first place.

---

## Analysis

### Static code analysis

**`static_analysis` (MUST) — Met. [JUDGEMENT]**
`cargo clippy --all-targets --all-features -- -D warnings` runs on every push
and every pull request, and again in the qa gate. Clippy is a genuine static
analysis tool, separate from rustc's own warnings — ~750 lints across
`correctness`, `suspicious`, `complexity`, `perf` and `style` groups, with
`correctness` covering real defect classes (lossy casts, incorrect bit
manipulation, comparison and arithmetic mistakes) that matter a great deal in an
instruction encoder. `cargo semver-checks` is a second static analysis, over the
public API, run against the version already published.
*Why this is flagged:* the criterion excludes "compiler warnings and safe
language modes", and Clippy ships with the Rust toolchain, so a strict reviewer
could argue it is the compiler. The Rust ecosystem's settled reading is that
Clippy counts — it is a separate binary doing separate, deeper analysis — and
this is how comparable Rust projects answer. If a reviewer pushes back, adding
`github/codeql-action` with `language: rust` to the qa gate settles it outright.

**`static_analysis_common_vulnerabilities` (SUGGESTED) — Unmet.**
Honest answer: Clippy is a defect-and-idiom linter, not a vulnerability-focused
scanner, and nothing here is specifically aimed at a vulnerability catalogue.
Two things reduce what such a tool would have to find — `#![forbid(unsafe_code)]`
removes the memory-safety class structurally rather than by scanning for it, and
zero dependencies mean `cargo audit`/`cargo deny` would have nothing to check —
but neither is the same as running a security-oriented analyser.
*Closes it:* a CodeQL job (`language: rust`) in the qa gate. SUGGESTED, so Unmet
does not block the badge.

**`static_analysis_fixed` (MUST) — Met.**
No medium-or-higher severity exploitable vulnerability has been found by static
analysis. Clippy findings cannot accumulate at all: `-D warnings` means the gate
is red until each one is fixed, so there is no backlog in which something could
sit.

**`static_analysis_often` (SUGGESTED) — Met.**
Every commit. Clippy runs in `dev.yml` on every push and pull request, and again
in `qa.yml`; `scorecard.yml` additionally re-analyses the repository's
supply-chain posture weekly.

### Dynamic code analysis

**`dynamic_analysis` (SUGGESTED) — Unmet, and worth the maintainer's attention.**
No fuzzer or other input-varying dynamic analysis runs. The test suite is
thorough (100% line/region/function coverage, enforced) but it exercises chosen
inputs; it does not vary them, which is what the criterion asks for.
*Why it matters more here than the SUGGESTED label implies:* the decode side of
this crate (`decode_bl`, `decode_b_wide`, `decode_b_cond`, `find_bl_sites`,
`CommandTable::walk`) reads attacker-influenced firmware bytes, which is
textbook fuzzing territory.
*Closes it:* a `cargo-fuzz` target over the decoders plus round-trip
encode/decode properties, run in the qa gate or nightly. Left out of this pass
deliberately — it is new test infrastructure, not a repository-hygiene change.

**`dynamic_analysis_unsafe` (SUGGESTED) — N/A.**
The project produces no code in a memory-unsafe language. It is 100% safe Rust
with `#![forbid(unsafe_code)]` at the crate root and no C, C++ or assembly
anywhere. The criterion explicitly permits N/A in this case.

**`dynamic_analysis_enable_assertions` (SUGGESTED) — Met. [JUDGEMENT]**
`cargo test` builds and runs in the `test` profile, where `debug_assertions` and
**arithmetic overflow checks** are on by default. For a crate whose work is
shifting and masking bit-fields into instruction encodings, a panic on overflow
during testing is precisely the fault detection this criterion is asking for,
and it is active on every CI cell — three operating systems × {stable, MSRV
1.58} — not just locally.
*Why this is flagged:* it is arguably the language's default rather than a
"configuration [...] which enables many assertions" chosen by the project. The
answer is defensible and the mechanism is real, but a reviewer could read the
criterion more narrowly.

**`dynamic_analysis_fixed` (MUST) — N/A.**
Per the criterion's own guidance: no dynamic code analysis is being run, so no
vulnerabilities have been found by it. (This must be revisited if the fuzzing
above is added.)

---

## Summary

All 67 passing-level criteria are answered above:

| answer | count | |
| --- | --- | --- |
| Met | 49 | |
| N/A | 13 | 9 crypto, plus `release_notes_vulns`, `vulnerability_report_response`, `dynamic_analysis_unsafe`, `dynamic_analysis_fixed` |
| Unmet | 4 | one MUST, three SUGGESTED |
| conditional | 1 | `vulnerability_report_private` — Met or N/A depending on the choice below |
| **total** | **67** | |

The four Unmet: `vulnerability_report_process` (**MUST — the only blocker**),
`version_tags` (SUGGESTED, closes itself on the next release),
`static_analysis_common_vulnerabilities` (SUGGESTED), `dynamic_analysis`
(SUGGESTED).

The three SUGGESTED Unmets do not affect the passing badge — SUGGESTED criteria
only have to be answered. Publishing a vulnerability-reporting process does.
