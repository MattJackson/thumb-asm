<!--
SPDX-FileCopyrightText: 2026 Matthew Jackson <dev4@getbusbar.com>
SPDX-License-Identifier: MIT
-->

# Security policy

`thumb-asm` decodes, assembles, relocates and patches ARM Thumb instructions in
a caller-owned `&[u8]`. It performs no cryptography, opens no sockets, reads no
files, and holds no global state — so the usual shape of a library security
report does not fit it.

What *does* fit is this: the crate's consumers take its output and write it into
firmware. An instruction this crate encodes wrongly does not raise an error
somewhere downstream. It gets flashed, and the device it was flashed onto stops
working, or works differently. **For this crate, correctness is the security
property**, and a mis-encoded or mis-decoded instruction is treated as a
security defect rather than as a bug of ordinary severity. Reports are welcome
and are taken seriously.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use either channel:

- **GitHub private vulnerability reporting** —
  <https://github.com/MattJackson/thumb-asm/security/advisories/new>
  (equivalently: the Security tab, "Report a vulnerability"). This creates a
  private advisory only the maintainer can see, and it is the preferred route
  because the fix, the advisory and the credit all happen in one place.
- **Email** — <matthew@pq.io>. Plain email is fine; there is no PGP key to
  chase.

Please include, as far as you can:

- the crate version or commit,
- the exact bytes, or the exact `Insn`, that triggers it — this is an encoding
  library, so a hex halfword pair is worth a page of description,
- what you expected and what you got, with the Arm architecture reference manual
  section you believe is being violated (DDI 0403E.e and DDI 0406B are the two
  this crate works from; `spec/` holds both),
- for a panic, the offset and the API that was called.

A failing test is the most useful thing you can send. `tests/conformance.rs` and
the per-module sweeps under `src/isa/` show the shape.

## What to expect

- **Acknowledgement within 14 days.** If you do not hear back in that time,
  assume the message went astray rather than that it was ignored, and try the
  other channel.
- An assessment of whether the report is confirmed, and of what a consumer
  would have to be doing for it to bite them.
- Updates while a fix is developed.
- Credit, as described below.

## Credit for reporters

**Reporters are credited by name.** Specifically: in the GitHub Security
Advisory for the issue, and in the `CHANGELOG.md` entry for the version that
fixes it, alongside a description of the defect. If you would rather not be
named, say so and you will not be — the credit is yours to decline, and
declining it changes nothing else about how the report is handled.

If you would like to be credited under a handle, a company name, or an
alternative address rather than the one you reported from, say which.

## Response process

What happens after a report arrives:

1. **Triage.** The report is confirmed or not, within the timeframe above.
   Confirmation means a reproduction: for an encoding defect, the bytes and the
   manual clause; for a panic, a test that panics.
2. **Fix, red first.** A security fix starts with a test that fails before the
   change and passes after it, as every behavioural change in this repository
   does (see [`CONTRIBUTING.md`](CONTRIBUTING.md)). A fix with no test that
   failed beforehand is not a fix.
3. **Gate.** The fix goes through the ordinary pipeline — `dev`, then `qa`,
   whose gate includes the 100% line/region/function coverage floor and the
   differential conformance sweep against LLVM. A security fix does not get to
   skip the gate; the gate is most of the reason to believe the fix is right.
4. **Release.** The fix ships as a **new version on crates.io**, published from
   `main` via Trusted Publishing. Fixes are released, not held: pre-1.0, there
   is no backport branch to wait on.
5. **Advisory.** A **GitHub Security Advisory** is published on the repository,
   with a CVE requested where one is warranted, and with the reporter credited
   unless they asked otherwise. RustSec picks up advisories from there.
6. **Changelog.** The `CHANGELOG.md` section for the fixing version **names the
   issue** and links the advisory. The release workflow refuses to release a
   version with no changelog section, so this step cannot be skipped by
   accident.
7. **Yank if warranted.** An affected version may be yanked from crates.io. A
   yank hides a version from new resolution and never deletes it, so builds that
   already pinned it keep working.

Coordinated disclosure is preferred, and a date is agreed with the reporter. You
will not be asked to wait indefinitely; if a fix is taking too long, that is a
thing to be explained, not a thing for the reporter to absorb.

## Scope

### In scope

- **A panic reachable from untrusted input** through an API that is not
  documented as panicking. A firmware image is untrusted data, and a
  disassembler that aborts on a hostile byte pattern is a denial of service for
  whatever is analysing it.
- **A mis-encoded or mis-decoded instruction.** An encoder that produces the
  wrong bytes, a decoder that reports an instruction as something it is not, a
  relocation that changes the meaning of the instruction it moved, or a detour
  that installs a stub which does not do what the displaced code did. A wrong
  patch written into firmware is a safety problem for whoever installs it, and
  this crate has no way to find out about it afterwards.
- **An unbounded loop or an unbounded allocation driven by input** — a decoder
  walk, a control-flow traversal, or an assembly that does not terminate or that
  grows without limit on a crafted image.
- Anything that makes the refusals real rather than nominal: a detour that
  leaves the image modified after returning an error, an out-of-range operand
  that produces a different instruction instead of an `AsmError`, a
  `Cond::from_bits` that accepts a fifteenth condition.

### Out of scope

- **Panics from `read_u8`, `read_u16` and `read_u32` past the end of the
  image.** These accessors index the slice and are documented to do so; they
  exist for an offset a search has already proved in bounds. The
  `try_read_u8`/`try_read_u16`/`try_read_u32` forms return `Option` and are the
  ones to use on untrusted input. The distinction is in the type and in the
  rustdoc, not in a footnote. A panic from a *different* API, or from a `try_`
  form, is in scope.
- **Anything about the Arm architecture reference manuals under `spec/`.** Those
  are Arm Limited's documents, kept in-tree so every encoding claim in `src/`
  can be checked against its source. They are not this project's work, they are
  not relicensable by this project, and `Cargo.toml`'s `exclude` keeps them out
  of the published `.crate` — a fact the `package` job in `qa.yml` asserts
  rather than assumes. A misreading of a manual clause *by this crate* is very
  much in scope; that is an encoding defect, and it is the most valuable kind of
  report this project can receive.
- **Behaviour of a patched device.** Nothing here executes anything. The crate
  makes claims about bit patterns, not about what a core does with them, and it
  says nothing about whether a patched image is a good idea.
- Encodings the architecture itself calls UNPREDICTABLE, which this crate
  decodes deliberately: `Insn` has no channel for "this is not architecturally
  well-formed", and `README.md` says so. *Decoded* does not mean *well-formed*.
  A divergence from the architecture on a *defined* encoding is in scope.

## Supported versions

The crate is pre-1.0. **Fixes land on the latest minor only** — there are no
long-term support branches and nothing is backported. The current line is 0.10.x;
a fix ships as the next release of that line, or as the next minor if the fix is
breaking (for 0.x, `cargo semver-checks` requires the minor for a breaking
change, and it runs in the gate).

## Our own practice

Stated because a policy that only describes what happens after a report is half
a policy.

- `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`, enforced at the crate
  root rather than by review.
- **Zero dependencies.** There is no transitive supply chain to compromise and
  no advisory against a third-party package that can apply here.
- Every behavioural change is developed red first.
- CI enforces a hard **100% line, region and function** coverage floor, so an
  unexercised error path fails the build.
- A **differential conformance harness** checks this crate's disassembly against
  LLVM by re-assembling it and comparing bytes, over 929,088 probes. Every known
  divergence is in a 21-entry allow-list, and each entry cites the Arm manual
  clause that justifies it. Anything not on the list fails the test. See
  [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md).
- **Mutation testing** is run periodically, because 100% coverage says every line
  ran and not that any line was checked. `docs/CONFORMANCE.md` records the
  score, the survivors, and the three real defects the run produced fixes for.
- The reasoned argument for why all of that adds up to "adequately secure",
  including what it does *not* cover, is
  [`docs/ASSURANCE_CASE.md`](docs/ASSURANCE_CASE.md).

None of that makes the crate correct. It makes the claims checkable, which is
the most any project can honestly offer.
