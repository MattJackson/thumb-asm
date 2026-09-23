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
