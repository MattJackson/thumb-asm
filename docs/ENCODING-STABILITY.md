<!--
SPDX-FileCopyrightText: 2026 Matthew Jackson <dev4@getbusbar.com>
SPDX-License-Identifier: MIT
-->

# Encoding stability

What this crate promises, and does not promise, about the bytes it emits.

It exists because of a real failure. `Asm::mov_reg` was fixed in 0.10.0: it had
been emitting `adds rd, rm, #0`, which is not `MOV` and which writes N, Z, C
and V — so any register move between a `cmp` and its `b<cond>` was silently
miscompiled. The fix was right. But a consumer pinning a byte-exact image and
two AES-CMAC digests found out that 21 bytes had moved **because their
known-answer test failed**, with nothing in the release to tell them to look.

That is the failure this document is about. Not that the bytes changed — that
they changed quietly.

## What is not promised

**Emitted bytes are not frozen, and encoding changes are not automatically a
breaking release.**

This is a deliberate choice and it is worth stating why, because the opposite
rule is superficially attractive. If a change to emitted bytes required a
breaking release, then a *known-wrong encoding must keep shipping* until the
project is willing to cut one. For a crate whose entire job is emitting correct
instructions, that inverts the priority: it would mean answering a report of
"this encodes the wrong instruction" with "yes, and it will keep doing that for
a while."

So a wrong encoding is a bug, and bugs get fixed in patch releases.

## What is promised

**No change to emitted bytes is ever silent.** Discoverability is the
guarantee, not immutability. Three mechanisms, in increasing order of how
little they depend on anyone reading carefully:

### 1. A fixed heading in the changelog

Any release that changes what any constructor emits carries a section headed
exactly:

```
### Emitted bytes changed
```

It names the constructor, says what it emitted before and emits now, and says
why. The heading is fixed so it can be grepped or watched by a tool, rather
than depending on a reader noticing a line in a long entry.

### 2. A published encoding digest

Every release publishes a digest over the emitted bytes of the whole 16-bit
encoding space — each halfword that decodes, together with what `isa::encode`
produces from it. Two releases with the same digest emit identical bytes for
every 16-bit instruction; different digests mean something moved.

A consumer can compare two numbers instead of building and maintaining their
own corpus, and it covers instructions nobody thought to write a test for.

| version | decoded halfwords | digest |
| --- | ---: | --- |
| 0.11.1 | 58,233 | `0x0e06fda25d6b89e8` |
| 0.14.0 | 58,233 | `0x0e06fda25d6b89e8` |

The digest is over the emitted bytes under [`Target::Union`], which is the
default and reproduces the crate's historical behaviour byte for byte. Under
a non-`Union` target the encoder consults a per-profile legality table
(`src/isa/legality.rs`), and bytes an existing emitter refuses on the target
are not written — that is the whole point of the target gate. Per-target
byte digests may land in a future release; for 0.14.0 the promise is:
`Target::Union` output is unchanged, and any non-`Union` output that
succeeds is byte-identical to what `Union` produces for the same emitter
call.

The digest is pinned in the test suite, so a change fails the build here before
it reaches anyone. A failure is not automatically a defect — it is a prompt to
decide whether the change was intended, and to write the changelog entry if it
was. It must never be updated to turn a red build green.

### 3. A deprecation cycle, where one is possible

If an existing constructor is to emit different bytes, the new behaviour
arrives under a new name and the old name gets `#[deprecated]` for one release,
so callers find out at compile time rather than at flash time.

The exception is a genuinely dangerous encoding, where continuing to emit it
for another release is worse than the churn. `mov_reg` was that case: it was
corrupting flags. Fixing it in place was defensible; shipping it without the
changelog entry was not, and that omission is what produced this document.

## What a consumer should do

- Pin a version, as you would anyway.
- Watch for `### Emitted bytes changed` when upgrading, or diff the digest
  above between the version you are on and the one you are moving to.
- Keep your own golden test regardless. It checks something narrower and more
  valuable than this does: that the bytes *you* emit for *your* image have not
  changed. This document only removes the surprise.
