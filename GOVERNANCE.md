<!--
SPDX-FileCopyrightText: 2026 Matthew Jackson <dev4@getbusbar.com>
SPDX-License-Identifier: MIT
-->

# Governance

How `thumb-asm` is governed: who decides what, how a change gets in, who holds
the keys, and what happens to the project if that person stops answering. It is
short, and it is honest about the project's size rather than describing a
structure that does not exist.

## Model

`thumb-asm` uses a **benevolent-maintainer** model, which is the accurate name
for "one person decides". There is one maintainer. There is no steering
committee, no working group, no foundation, and no vote to appeal to.

Discussion happens in the open, on the GitHub issue tracker and on pull
requests. The maintainer makes the final call, guided by the priorities the
repository already states: correctness first, and a refusal in preference to a
guess. `README.md`'s "Design, and what this is not" is the standing statement of
what the crate will and will not try to be, and a proposal that contradicts it
needs to argue with it rather than around it.

If a second active maintainer ever appears, this document gets rewritten to say
how the two of them share the decision — expected: lazy consensus on pull
requests, either able to merge after review, disagreements resolved by not
merging until they agree. Writing that down now would be describing a committee
of one.

## Roles and responsibilities

- **Maintainer** — Matthew Jackson ([@MattJackson](https://github.com/MattJackson)),
  <matthew@pq.io>. Reviews and merges, advances `dev` → `qa` → `main`, cuts
  releases, triages issues, receives and handles security reports
  ([`SECURITY.md`](SECURITY.md)), and is the enforcement contact for
  [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Holds every credential listed
  under [Access and continuity](#access-and-continuity). There is no
  `CODEOWNERS` file because there is no second owner for it to name.
- **Contributors** — anyone who opens an issue or a pull request. What a
  contribution has to satisfy is in [`CONTRIBUTING.md`](CONTRIBUTING.md): the
  branch flow, the Developer Certificate of Origin sign-off, the coding
  standards, and the testing policy. None of it is a matter of the maintainer's
  mood — CI enforces the whole list, on every push and every pull request.
- **Users** — anyone depending on the published crate. A user's leverage here is
  an issue that says what a patch of real firmware needed and could not get. The
  crate exists because of that kind of report and it is the fastest route onto
  [`ROADMAP.md`](ROADMAP.md).

## How decisions are made

1. **Non-trivial changes start as an issue.** Say what the change buys someone
   patching a real image. An encoding claim has to name the Arm manual section
   it comes from; "LLVM does it this way" is corroboration, not a citation, and
   `docs/CONFORMANCE.md` explains why the difference matters.
2. **Changes arrive as pull requests against `dev`.** Every pull request runs
   the fast gate (`cargo fmt --all --check`, `cargo clippy --all-targets
   --all-features -D warnings`, `cargo test --all-targets`, `cargo test --doc`,
   `cargo run --example trampoline`). A red gate is not a discussion.
3. **`qa` is the thorough gate**, and green `qa` is the release signal: three
   operating systems, the MSRV floor read from `Cargo.toml` at run time, the
   rustdoc link check, the 100% line/region/function coverage floor, the
   `cargo package`/`publish --dry-run` checks, `cargo semver-checks`, and the
   differential conformance sweep against LLVM.
4. **`main` publishes.** Fast-forwarding `main` from a green `qa` re-runs the
   entire gate on that exact commit and publishes to crates.io. The mechanics
   are in [`CONTRIBUTING.md`](CONTRIBUTING.md#cutting-a-release).
5. **Security-relevant changes additionally follow [`SECURITY.md`](SECURITY.md)**,
   which means a private advisory and a fix released before the details are
   public.

The maintainer merges. The gate decides whether that is even possible.

## Access and continuity

### Who holds what

- **GitHub repository admin** — the maintainer, alone, on
  <https://github.com/MattJackson/thumb-asm>. That includes branch settings,
  Actions secrets, secret scanning and push protection, and the private
  vulnerability reporting channel.
- **crates.io ownership** — the maintainer is the sole owner of the
  [`thumb-asm`](https://crates.io/crates/thumb-asm) crate name. This is the real
  key to the project, more so than the repository: a fork of the source is a
  click, and the crate name is not.
- **Publishing credentials** — there are none to hold. Releases authenticate
  with crates.io **Trusted Publishing** (OIDC), so no long-lived registry token
  exists in the repository or on anyone's machine; the token is minted per run
  and expires. The thing that grants publishing rights is therefore the crates.io
  *ownership* record plus admin on the repository, not a secret that could be
  copied, leaked, or handed over.
- **Nothing is held off the record.** No credential is committed. There is no
  signing key, no release binary to sign, and no infrastructure: the project is a
  source crate, a set of workflows, and the Arm manuals under `spec/`, which are
  Arm's documents and are excluded from the published `.crate`.

### Bus factor

**One.** Stated rather than implied. Every role above is the same person, and if
that person is unreachable then no new version of `thumb-asm` can be published
to crates.io under this name, no advisory can be issued on this repository, and
no pull request can be merged.

### What happens if the maintainer becomes unavailable

There is no standing succession arrangement today. This is the honest answer,
and the succession plan is correspondingly plain:

- **Everything needed to continue is already public.** The source, the tests,
  the conformance harness, the coverage and release workflows, the coverage map
  in `spec/THUMB-ISA.md` and the reasoning in `docs/` are all in the repository.
  The crate has zero dependencies and no committed lockfile because it needs
  none, so there is no private build environment to reconstruct. A capable
  successor needs the repository and a Rust toolchain, and nothing else.
- **The licence permits it.** `thumb-asm` is MIT. Anyone may fork it, continue
  it, and publish the result under a different crate name without asking.
- **Published versions do not depend on anyone remaining reachable.** A crates.io
  release is immutable: versions already on crates.io keep resolving and keep
  building for existing dependants whatever happens to the maintainer.
- **What a fork cannot inherit is the name.** `thumb-asm` on crates.io stays
  where it is. crates.io has a policy for abandoned crates, and that route — or a
  new name — is what a successor would have to use.
- **The one action that would change this** is adding a second crates.io owner
  and a second repository admin who can review and release. That is an explicit
  goal rather than a completed one; it is on [`ROADMAP.md`](ROADMAP.md), and it
  cannot be closed by writing a document.

## Changing this document

Like any other change: a pull request, gated by CI, merged by the maintainer.
If the governance described here stops being true — a second maintainer, a
second crates.io owner, a change in how releases are authorised — this file is
the first thing to update, not the last.
