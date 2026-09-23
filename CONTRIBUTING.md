# Contributing to thumb-asm

## Branches are the pipeline

Three long-lived branches, in one direction only:

```
dev  ──fast-forward──▶  qa  ──fast-forward──▶  main
 │                       │                      │
 fast gate          full gate              publish to crates.io
```

- **`dev`** — where work lands. Every push runs `.github/workflows/dev.yml`:
  `cargo fmt --all --check`, `cargo clippy --all-targets --all-features -D
  warnings`, `cargo test --all-targets`, `cargo test --doc`, and `cargo run
  --example trampoline`, on latest stable Linux only. It is deliberately a
  couple of minutes: it is the inner loop.
- **`qa`** — advanced by fast-forwarding from a `dev` commit that already
  passed. `.github/workflows/qa.yml` is the thorough gate, and green `qa` is
  the release signal. It runs everything `dev` runs plus:
  - the full test set on ubuntu, macOS and Windows,
  - the same set on the MSRV floor from `Cargo.toml`'s `rust-version` (read at
    run time, never hardcoded) — clippy is *not* run there, only stable,
  - `cargo doc` with `-D warnings -D rustdoc::broken_intra_doc_links`,
  - `cargo llvm-cov` with a hard 100% line/region/function floor,
  - `cargo package --list` + `cargo publish --dry-run`, including an assertion
    that Arm's ~35 MB `spec/` dump is still excluded from the `.crate`,
  - `cargo semver-checks` against the version already on crates.io.
- **`main`** — advanced by fast-forwarding from a green `qa`.
  `.github/workflows/release.yml` publishes.

Pull requests run the fast gate too, whatever branch they target.

## Cutting a release

1. On `dev`: bump `[package].version` in `Cargo.toml` and add the matching
   `## [X.Y.Z] - YYYY-MM-DD` section to `CHANGELOG.md`. Both are mandatory —
   the release workflow refuses to release a version with no changelog section,
   and `cargo semver-checks` refuses a breaking change the bump does not cover
   (for `0.x` a breaking change needs the *minor*: `0.1.x` → `0.2.0`).
2. Fast-forward `qa` and wait for `qa full gate` to go green.
3. Fast-forward `main`. That is the whole release: `release.yml` re-runs the
   entire qa gate on that commit, publishes to crates.io via Trusted
   Publishing, pushes the `vX.Y.Z` tag, and opens a GitHub Release whose body
   is that version's `CHANGELOG.md` section.

Pushing docs or CI changes to `main` without a version bump is a clean no-op:
every step is guarded by whether it has already happened, so nothing is
double-published and nothing fails. Re-running the workflow after a partial
failure is likewise safe.

`release.yml` can also be dispatched manually with `dry_run: true`, which runs
the full gate and every pre-flight check but publishes, tags and releases
nothing.

### One-time crates.io setup

Publishing authenticates with crates.io **Trusted Publishing** (OIDC), so there
is no long-lived token in this repository. The crates.io half of that has to be
configured once by a crate owner; the exact values are in the header comment of
`.github/workflows/release.yml`.

## Conventions worth knowing before you touch `.github/`

- Every third-party action is pinned to a **full commit SHA** with the readable
  ref in a trailing comment. A tag is not an identity — its owner can repoint
  it. Dependabot (`.github/dependabot.yml`) bumps the pins weekly onto `dev`.
- **No `continue-on-error`.** A check that is allowed to fail is not a check.
- `permissions:` is declared explicitly and minimally in every workflow, and
  per-job where a job needs more than the rest.
- There is no committed `Cargo.lock` (zero-dependency library), which is why no
  cargo invocation passes `--locked`: on a fresh checkout there is no lockfile
  and cargo refuses.
- Comments explain *why*, not what the YAML does.

## Source conventions

`#![forbid(unsafe_code)]` and `#![deny(missing_docs)]` are not negotiable, the
crate stays dependency-free, and every encoding claim cites its Arm manual
section (see `spec/`). New public API arrives with tests — the 100% coverage
floor in `qa` will say so otherwise.

## Coding standards

The standards are short, they are stated here rather than absorbed by reading
the code, and none of them is a matter of taste on the day — every one is
machine-checked, on every push and every pull request, and a violation is a red
build rather than a review comment.

| Standard | Enforced by |
| --- | --- |
| One formatting, no debate | `cargo fmt --all --check` (`rustfmt.toml` holds the settings) |
| No warnings, no lint escapes | `cargo clippy --all-targets --all-features -- -D warnings`, with `clippy.toml` pinning `msrv = "1.58"` so the MSRV-aware lints stay correct |
| No `unsafe`, anywhere, ever | `#![forbid(unsafe_code)]` in `src/lib.rs` — `forbid`, so no module can opt back in |
| Every public item documented | `#![deny(missing_docs)]`, plus `cargo doc` with `-D warnings -D rustdoc::broken_intra_doc_links` in the `qa` gate |
| Zero dependencies | the empty `[dependencies]` table in `Cargo.toml`, and the `dependencies: 0` badge that has to stay true |
| Every encoding claim cites its Arm manual section | review — this is the one that cannot be automated, and it is the most important one |

That last row is the standard the rest exist to protect. An encoding is not
"what LLVM does" and it is not "what made the test pass": it is a clause in
`spec/`, named in the comment or the rustdoc beside the code that implements it.
If you cannot write the citation, you have not finished reading — and if you are
adding a conformance divergence, the entry in `tests/support/divergences.rs`
has to name the clause too. A divergence with no citation is a bug, not a
divergence.

Beyond the table: comments explain *why*, not what the code does; a refusal is
preferred to a guess, so an operand that cannot be encoded faithfully returns an
error rather than something plausible; and nothing is allowed to fail quietly —
there is no `continue-on-error` in any workflow, because a check that is allowed
to fail is not a check.

## Testing policy

These are requirements, not aspirations.

- **New functionality arrives with its tests, in the same change.** Not "in a
  follow-up". An encoder with no test for it is not a contribution to a crate
  whose entire value is being right about bit patterns.
- **A bug fix starts with a failing test.** Red before green: write the test
  that reproduces the defect, watch it fail against the unfixed code, then fix
  it and watch it pass. A test written after the fix proves only that the code
  does what it does. A fix with no test that failed beforehand is not a fix, it
  is a hope — and for a crate whose output gets flashed onto devices, hope is
  not a review standard. Say in the pull request what was red.
- **CI enforces 100% line, region and function coverage.** `cargo llvm-cov
  --fail-under-lines 100 --fail-under-regions 100 --fail-under-functions 100`
  in the `qa` gate. That is a floor, not a report: an untested branch —
  including an error path you added and never exercised — fails the build and
  names the lines. It is a maintainable bar precisely because the crate is a
  pure function of its inputs, with no I/O and no dependencies.
- **Pin the sweep counts.** A round-trip sweep over an encoding group asserts
  its probe count as a literal, so a change in what decodes surfaces as a
  failing census rather than as a silently different number. If your change
  moves a count, move the literal and say why.
- **A test that cannot fail is worse than no test.** Coverage says every line
  ran, not that any line was checked, and the difference is not academic here:
  `docs/CONFORMANCE.md` records an encoder writing `Rd` at the wrong bit that
  survived fourteen tests, because the test helper built its expected halfword
  with the same formula as the encoder it was checking. Assert against the Arm
  manual, not against the implementation.

## Developer Certificate of Origin

Contributions are accepted under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/). There
is no contributor licence agreement to sign and no copyright to assign: the DCO
is a statement that you wrote the change, or otherwise have the right to submit
it under this project's MIT licence.

Certify it by signing off each commit:

```sh
git commit -s
```

which appends a line naming you:

```text
Signed-off-by: Your Name <your.email@example.com>
```

Use a real name and a reachable address — the sign-off is a statement of
provenance, so it has to identify someone. If you forget,
`git commit --amend -s` fixes the last commit and `git rebase --signoff` fixes
a branch.
