# The complete Thumb instruction set, and what `thumb-asm` covers

Grounded in ARM DDI 0403E.e (Armv7-M) chapters A5 and A7 and ARM DDI 0406
(ARMv7-A/R) chapters A6, A8 and A9, both in `spec/` — see `spec/README.md` for
what each dump is and how it was made. Section numbers below are
clickable-by-grep into `spec/ARMv7-M.txt` (`A5.*`, `A7.*`) and
`spec/ARMv7-AR.txt` (`A6.*`, `A8.*`, `A9.*`).

This is a map of what the crate **does**. `src/isa/` has one module per numbered
sub-table of the architecture reference manual, and the sections below follow the
same numbering, so a review is one section of this file beside one table of Arm's
beside one file of the crate's. Coverage is stated in counts rather than
adjectives; §4 gives the counting method and the totals, and §5 and §6 give the
places where the manual, or this crate, is not what a reader would assume.

Legend, per row: **✅** every encoding the row allocates decodes and re-encodes ·
**🔶** partial, with the omission named in the row itself · **❌** not
implemented.

---

## 0. The two halves, and how to tell them apart

A Thumb instruction stream is a sequence of halfwords. Decode halfword `hw1`:

| `hw1[15:11]` | Width | Meaning |
|---|---|---|
| `11101`, `11110`, `11111` | 32-bit | Thumb-2 wide; `hw2` follows (ARMv6T2+) |
| anything else | 16-bit | classic Thumb-1 |

This is the *only* length rule — there is no other prefix, and nothing else in
the instruction is consulted (A5.1). It is `isa::insn_len`, and it is why
`find_bl_sites`-style "scan every even offset" searches can land mid-instruction
and must be corroborated (which is what `prologue_is_push_lr` is for, and what
`isa::Decoder` removes the need for).

Word-invariant order: `hw1` is at the lower address. A 32-bit Thumb instruction
is **not** a little-endian `u32` — it is two little-endian `u16`s. `decode_bl` /
`encode_bl` in `src/lib.rs` get this right, `isa::encode_bytes` is the one place
the rule lives for decoded instructions, and anything new must too.

---

## 1. 16-bit encoding space (A5.2 / A6.2)

Top-level split on `hw1[15:10]` (Table A5-1 / Table A6-1). Thumb's length rule
keeps `0xE800` and above out of this space entirely, so the 16-bit map is exactly
the 59,392 halfwords `0x0000..=0xE7FF`.

| `[15:10]` | Class | § | Module | Halfwords | Decoded |
|---|---|---|---|---|---|
| `00xxxx` | Shift (imm), add, sub, move, compare | A5.2.1 | `t16_shift` | 16,384 | 16,384 |
| `010000` | Data processing (reg-reg, low regs) | A5.2.2 | `t16_dataproc` | 1,024 | 1,024 |
| `010001` | Special data / branch-exchange (high regs) | A5.2.3 | `t16_special` | 1,024 | 736 |
| `010010`–`101011` | Load/store single item, `LDR (literal)`, `ADR`, `ADD (SP plus imm)` | A5.2.4 | `t16_loadstore` | 26,624 | 26,624 |
| `1011xx` | Miscellaneous 16-bit | A5.2.5 | `t16_misc` | 4,096 | 3,241 |
| `1100xx`–`11100x` | `STM`/`LDM`, `B<cond>`/`SVC`/`UDF`, `B` T2 | A5.2.6 | `t16_branch` | 10,240 | 10,224 |

Every non-decoding halfword in the three short rows is accounted for by name in
the owning module's tests; the policy that produces them is §4's.

### 1.1 Shift/add/sub/mov/cmp — `00 opcode[4:0]` (A5.2.1, Table A5-2) ✅

| opcode | Instruction | Encoding | Cov |
|---|---|---|---|
| `000xx` | `LSL (immediate)` T1 | `0000 0 imm5 Rm Rd` | ✅ |
| `001xx` | `LSR (immediate)` T1 | `0000 1 imm5 Rm Rd` | ✅ |
| `010xx` | `ASR (immediate)` T1 | `0001 0 imm5 Rm Rd` | ✅ |
| `01100` | `ADD (register)` T1 | `0001 100 Rm Rn Rd` | ✅ |
| `01101` | `SUB (register)` T1 | `0001 101 Rm Rn Rd` | ✅ |
| `01110` | `ADD (immediate)` T1 | `0001 110 imm3 Rn Rd` | ✅ |
| `01111` | `SUB (immediate)` T1 | `0001 111 imm3 Rn Rd` | ✅ |
| `100xx` | `MOV (immediate)` T1 | `0010 0 Rd imm8` | ✅ |
| `101xx` | `CMP (immediate)` T1 | `0010 1 Rn imm8` | ✅ |
| `110xx` | `ADD (immediate)` T2 | `0011 0 Rdn imm8` | ✅ |
| `111xx` | `SUB (immediate)` T2 | `0011 1 Rdn imm8` | ✅ |

The space is *fully allocated*: all 16,384 halfwords in `0x0000..=0x3FFF` are
instructions, so the exhaustive round-trip in `t16_shift` is a total check of the
group rather than a sample of it.

Two traps, both of which produce a decoder that looks right and disassembles
wrongly:

- **Footnote a of Table A5-2.** `LSL (immediate)` T1 with `imm5 == 0` is not a
  shift by zero, it **is** `MOV (register)` T2 — A7.7.68 says so as pseudocode
  (`if imm5 == '00000' then SEE MOV (register)`). The two differ in observable
  behaviour: `LSLS` writes `APSR.C` from the shifted-out bit, `MOVS` leaves `C`
  alone. `Asm::lsls_imm(rd, rm, 0)` and `Asm::movs_reg(rd, rm)` emit the same
  halfword, and both document it.
- **`DecodeImmShift` (A7.4.2).** For `LSR` and `ASR` a zero `imm5` means a shift
  of **32**, not 0 — those forms have a syntax range of 1–32 while `LSL` gets
  0–31. A decoder that prints `#0` there is wrong by a factor of 2^32.

Every instruction here has `setflags = !InITBlock()`, so `Insn::sets_flags` is
`true` throughout — except `CMP`, which has no `S` bit and no `S` suffix in UAL;
`Display` would render a set flag as the non-existent mnemonic `cmps`.
`isa::Decoder` clears `sets_flags` on narrow instructions it finds inside an IT
block, which is why UAL spells the conditional form `lsleq` and not `lslseq`.

### 1.2 Data processing — `010000 opcode[3:0] Rm Rdn` (A5.2.2, Table A5-3) ✅

`0000 AND` · `0001 EOR` · `0010 LSL (register)` · `0011 LSR (register)` ·
`0100 ASR (register)` · `0101 ADC` · `0110 SBC` · `0111 ROR (register)` ·
`1000 TST` · `1001 RSB #0` · `1010 CMP` · `1011 CMN` · `1100 ORR` · `1101 MUL` ·
`1110 BIC` · `1111 MVN`.

Base `0x4000 | opcode << 6 | Rm << 3 | Rdn`, all low registers, all flag-setting,
all two-operand destructive except `TST`/`CMP`/`CMN`. All sixteen are allocated
and all 1,024 halfwords decode; nothing here is UNDEFINED or UNPREDICTABLE.

Three rows do not follow the shared shape:

- `TST`/`CMP`/`CMN` exist *to* write the flags, so UAL gives them no `S` suffix
  (A7.7.189, A7.7.28, A7.7.26). They carry `sets_flags: false`, because that
  field means "prints an `S`".
- `RSB (immediate)` T1 (A7.7.119) — pre-UAL `NEG` — has no immediate field at
  all (`imm32 = Zeros(32)`), and its syntax line is `RSBS <Rd>,<Rn>,#0`, so the
  `#0` is emitted as a real third operand.
- `MUL` T1 (A7.7.84) names its destination twice: `MULS <Rdm>,<Rn>,<Rdm>`.

The four shift-by-register forms are two plain registers, not a shifted-register
operand: the shift *is* the operation (`LSLS <Rdn>,<Rm>`, A7.7.69), not a
modifier on some other operation's operand.

### 1.3 Special data + branch/exchange — `010001 opcode[3:0]` (A5.2.3, Table A5-4) 🔶

| opcode | Instruction | Encoding | Cov |
|---|---|---|---|
| `00xx` | `ADD (register)` T2 — high regs, no flags | `0100 0100 DN Rm Rdn` | ✅ |
| `00xx` with `Rm == 1101` | `ADD (SP plus register)` T1 | `0100 0100 DM 1101 Rdm` | ✅ |
| `00xx` with `DN:Rdn == 1101` | `ADD (SP plus register)` T2 | `0100 0100 1 Rm 101` | ✅ |
| `0100` | UNPREDICTABLE (`CMP` T1 already encodes it) | — | ❌ by policy |
| `0101`, `011x` | `CMP (register)` T2 — at least one high reg | `0100 0101 N Rm Rn` | ✅ |
| `10xx` | `MOV (register)` T1 — high regs, no flags | `0100 0110 D Rm Rd` | ✅ |
| `110x` | `BX Rm` | `0100 0111 0 Rm (0)(0)(0)` | ✅ |
| `111x` | `BLX (register)` Rm | `0100 0111 1 Rm (0)(0)(0)` | ✅ |

The `D`/`N` bit is the register's bit 3, so the destination is the 4-bit
`opcode[1]:field[2:0]` — this is the only 16-bit path to `r8`–`r15`. Hence
`add r10, r3` is `0x449A` and `mov r8, r3` is `0x4698`. `opcode[0]` is `Rm[3]`,
which is why Table A5-4 spends three of its sixteen rows on `CMP`.

288 of the 1,024 halfwords do not decode, and both reasons are §4's policy:
`0x4500..=0x453F` is `CMP (register)` T2 with both operands low, which
A7.7.28's own `if n < 8 && m < 8 then UNPREDICTABLE` forbids because A5.2.2
already encodes it (64 halfwords); and 224 `BX`/`BLX` patterns whose `(0)(0)(0)`
field is not zero. LLVM is lenient about the latter and prints `bx r0` for
`0x4701`; this crate is not, deliberately.

`mov pc, rm` *is* a branch (A7.7.77), and `Insn::writes_pc` reports it as one.

### 1.4 Load/store single data item (A5.2.4, Table A5-5) ✅

Register-offset forms, `opA = 0101`, base `0x5000 | opB << 9 | Rm << 6 | Rn << 3 | Rt`:

| opB | `000` | `001` | `010` | `011` | `100` | `101` | `110` | `111` |
|---|---|---|---|---|---|---|---|---|
| insn | `STR` | `STRH` | `STRB` | `LDRSB` | `LDR` | `LDRH` | `LDRB` | `LDRSH` |
| base | `0x5000` | `0x5200` | `0x5400` | `0x5600` | `0x5800` | `0x5A00` | `0x5C00` | `0x5E00` |

Immediate-offset forms. Each scales its immediate by the access size, so the
encoded field is always five bits and the *byte* range differs per row;
`Mem::offset` holds the multiplied-out byte value, so no consumer has to know
which row of Table A5-5 an address came from.

| opA | Instruction | Base | imm field | byte range | Cov |
|---|---|---|---|---|---|
| `0110 0xx` | `STR (immediate)` T1 | `0x6000` | `imm5 = off/4` | 0–124 | ✅ |
| `0110 1xx` | `LDR (immediate)` T1 | `0x6800` | `imm5 = off/4` | 0–124 | ✅ |
| `0111 0xx` | `STRB (immediate)` T1 | `0x7000` | `imm5 = off` | 0–31 | ✅ |
| `0111 1xx` | `LDRB (immediate)` T1 | `0x7800` | `imm5 = off` | 0–31 | ✅ |
| `1000 0xx` | `STRH (immediate)` T1 | `0x8000` | `imm5 = off/2` | 0–62 | ✅ |
| `1000 1xx` | `LDRH (immediate)` T1 | `0x8800` | `imm5 = off/2` | 0–62 | ✅ |
| `1001 0xx` | `STR (immediate)` T2 — SP-relative | `0x9000` | `imm8 = off/4` | 0–1020 | ✅ |
| `1001 1xx` | `LDR (immediate)` T2 — SP-relative | `0x9800` | `imm8 = off/4` | 0–1020 | ✅ |

Three single-encoding rows of Table A5-1 share this module because they share its
one concern, forming an address: `LDR (literal)` T1 (`01001x`, A7.7.44), `ADR` T1
(`10100x`, A7.7.7) and `ADD (SP plus immediate)` T1 (`10101x`, A7.7.5).

**`Align(PC, 4)`.** Thumb's pc reads as the instruction's address plus four, and
the two pc-relative forms additionally force that word-aligned (A4.2.2). The
steps do not commute: at a 4-aligned address the `AND` changes nothing, so a
decoder that omits it still looks right, and at a 2-mod-4 address — half of all
real instructions — every resolved literal comes out two bytes too high. The
group's sweep therefore runs at both alignments, and the resolved address is
handed out as an `Operand::Target` so no consumer redoes the arithmetic.

There is no hole in this table: all 26,624 halfwords decode. No `P`/`W`/`U` bit
exists in 16 bits, so every addressing mode here is plain offset with a
non-negative displacement, and there is no 16-bit signed-immediate load —
`LDRSB`/`LDRSH` appear only in the register-offset row.

### 1.5 Miscellaneous 16-bit — `1011 opcode[6:0]` (A5.2.5 / A6.2.5) 🔶

This module implements the **union** of Table A5-6 and Table A6-6, because the
crate reads images for both profiles. The union differs from the M-profile table
in exactly one row: `SETEND` exists only on A/R.

| opcode | Instruction | Encoding | Cov |
|---|---|---|---|
| `00000xx` | `ADD (SP plus immediate)` T2 | `1011 0000 0 imm7` | ✅ |
| `00001xx` | `SUB (SP minus immediate)` T1 | `1011 0000 1 imm7` | ✅ |
| `0001xxx`, `0011xxx` | `CBZ` (v6T2+) | `1011 0 0 i 1 imm5 Rn` | ✅ |
| `001000x` | `SXTH` | `1011 0010 00 Rm Rd` | ✅ |
| `001001x` | `SXTB` | `1011 0010 01 Rm Rd` | ✅ |
| `001010x` | `UXTH` | `1011 0010 10 Rm Rd` | ✅ |
| `001011x` | `UXTB` | `1011 0010 11 Rm Rd` | ✅ |
| `010xxxx` | `PUSH` | `1011 010 M reglist` | 🔶 `push {}` refused |
| `0110010` | `SETEND` (**A/R only**) | `1011 0110 010 (1) E (0)(0)(0)` | 🔶 `0xB650`/`0xB658` only |
| `0110011` | `CPSIE`/`CPSID` | `1011 0110 011 im (0) A I F` | 🔶 14 of 32 |
| `1001xxx`, `1011xxx` | `CBNZ` (v6T2+) | `1011 1 0 i 1 imm5 Rn` | ✅ |
| `101000x` | `REV` | `1011 1010 00 Rm Rd` | ✅ |
| `101001x` | `REV16` | `1011 1010 01 Rm Rd` | ✅ |
| `101010x` | UNDEFINED (there is no 16-bit `RBIT`) | — | — |
| `101011x` | `REVSH` | `1011 1010 11 Rm Rd` | ✅ |
| `110xxxx` | `POP` | `1011 110 P reglist` | 🔶 `pop {}` refused |
| `1110xxx` | `BKPT #imm8` | `1011 1110 imm8` | ✅ |
| `1111xxx` | `IT` and hints (Table A5-7) | `1011 1111 opA opB` | 🔶 219 of 256 |

`IT` and hints: `opB != 0000` → `IT{x{y{z}}} <firstcond>`; `opB == 0000` →
`NOP` (`0xBF00`), `YIELD` (`0xBF10`), `WFE` (`0xBF20`), `WFI` (`0xBF30`),
`SEV` (`0xBF40`). The `T`/`E` letters are part of `Insn::mnemonic` (`itt`, `ite`,
`ittte`, …) because nothing else in `Insn` can carry the mask — which is why
`Decoder` tests `mnemonic.starts_with("it")` rather than `== "it"`.

855 halfwords do not decode, every one of them enumerated in the module's
`undefined_holes_are_accounted_for` test, whose expectation is spelled
`768 + 30 + 18 + 2 + 37`: 768 across 24 unallocated opcodes, 30 non-canonical
`SETEND`s, 18 `CPS` encodings whose `(0)` bit is set or whose `A:I:F` is `000`
(A7.7's `<iflags>` is "a sequence of one or more"), the 2 empty register lists
below, and 37 `IT`s that name `firstcond == 0b1111` or use an `E` arm with `AL`
— both UNPREDICTABLE per A7.7.38, and neither spellable in UAL. Unallocated
hints (`opA > 0b0100`) are refused too: A5.2.5 says they "execute as NOPs, but
software must not use them", so decoding them *as* `nop` would discard `opA`.

`push {}` / `pop {}` (`0xB400` / `0xBC00`) are **refused**. A7.7.101's encoding
T1 says `if BitCount(registers) < 1 then UNPREDICTABLE`, A7.7.99's says the same
for `POP` — note `< 1`, not the `< 2` those pages give their *wide* encodings two
lines later (§2.4) — and the deciding argument is §4.4's
third case rather than the UNPREDICTABLE label: `{}` is not UAL — no assembler
parses an empty register list — so `Display` emitted text that could not be read
back, which is exactly the property the round trip exists to guarantee. The
check is `list == 0` in `decode` *and* in `encode`, so the two directions cannot
drift. Single-register lists are kept here: `push {r0}` is legal UAL and has no
shorter spelling to be outranked by, which is why the narrow threshold is `< 1`
and the wide one (§2.4) is `< 2`. `docs/CONFORMANCE.md` records this as one of
the three defects the LLVM differential found (`t16-empty-register-list`).

`CBZ`/`CBNZ` are **forward-only** — the offset is zero-extended, not sign-extended
— range 0–126 bytes, low registers only. A frequent trap when hand-relocating.

### 1.6 `STM`/`LDM`, conditional branch, `SVC`, `UDF`, `B` T2 (A5.2.6) 🔶

`1101 cond imm8` is not simply "the conditional branches". The `B` pseudocode on
A7-205 opens by diverting two of the sixteen conditions:

```text
if cond == '1110' then SEE UDF;
if cond == '1111' then SEE SVC;
```

So `0xDExx` is the *permanently* undefined `UDF #<imm8>` — DDI 0406 adds that the
space "will not be allocated in future", which is what makes it usable as a
deliberate trap — and `0xDFxx` is `SVC #<imm8>`. Treating all of
`0xD000..=0xDFFF` as `B<cond>` mis-decodes 512 halfwords, and does so in the worst
way: it invents control flow where the hardware takes an exception.

| `[15:10]` | Instruction | Cov |
|---|---|---|
| `11000x` | `STM`/`STMIA`/`STMEA` T1 | 🔶 empty register list refused |
| `11001x` | `LDM`/`LDMIA`/`LDMFD` T1 | 🔶 empty register list refused |
| `1101xx`, `cond[3:1] != 111` | `B<cond>` T1, −256…+254 | ✅ |
| `1101xx`, `cond == 1110` | `UDF #imm8` (`0xDExx`) | ✅ |
| `1101xx`, `cond == 1111` | `SVC #imm8` (`0xDFxx`) | ✅ |
| `11100x` | `B` T2, −2048…+2046 | ✅ |

Conditions: `0 EQ · 1 NE · 2 CS/HS · 3 CC/LO · 4 MI · 5 PL · 6 VS · 7 VC ·
8 HI · 9 LS · A GE · B LT · C GT · D LE`.

16 of the 10,240 halfwords are refused: `STM`/`LDM` with `register_list == 0`,
one per base register for each, UNPREDICTABLE per A7.7.159/A7.7.40 and — the
operative reason — unspellable in UAL (§1.5, §4.4). A *one*-register list is
kept: `stmia r0!, {r0}` is `0xC001` and decodes, because the narrow threshold is
`BitCount < 1`. The wide forms of §2.4 use `BitCount < 2`, and the asymmetry is
deliberate: a wide single-register transfer is outranked by a narrow spelling of
the same instruction, and a narrow one is not.

**The ranges are asymmetric** — −256 to +254 and −2048 to +2046, not ±254 and
±2046. See §5.

### 1.7 ThumbEE — the re-assigned 16-bit space (DDI 0406 A9.2.1, Table A9-2) ✅

ThumbEE is not a superset, it is a *re-assignment*: `0xC000..=0xCFFF` is a 16-bit
`STM`/`LDM` in Thumb state and something else entirely in ThumbEE state, and
nothing in the halfword says which — only the processor's `CPSR.{J,T}` does. A
caller that knows a region executes in ThumbEE state says so
(`Decoder::thumbee(true)`), and `thumbee::decode` gets first refusal on every
narrow halfword; it returns `None` everywhere outside its range, which
`tests::non_interference` proves over all 65,536 values.

| `hw1[11:8]` | Halfwords | Instruction | Encoding |
|---|---|---|---|
| `0000` | `0xC000..=0xC0FF` | `HBP #<imm3>, #<handler>` | `11000000 imm3 handler` |
| `0001` | `0xC100..=0xC1FF` | UNDEFINED | — |
| `001x` | `0xC200..=0xC3FF` | `HB`/`HBL #<handler>` | `1100001L handler` |
| `01xx` | `0xC400..=0xC7FF` | `HBLP #<imm5>, #<handler>` | `110001 imm5 handler` |
| `100x` | `0xC800..=0xC9FF` | `LDR <Rt>, [<Rn>, #-<imm>]` — array | `1100100 imm3 Rn Rt` |
| `1010` | `0xCA00..=0xCAFF` | `CHKA <Rn>, <Rm>` | `11001010 N Rm Rn` |
| `1011` | `0xCB00..=0xCBFF` | `LDR <Rt>, [r10, #<imm>]` — literal pool | `11001011 imm5 Rt` |
| `110x` | `0xCC00..=0xCDFF` | `LDR <Rt>, [r9, #<imm>]` — frame | `1100110 imm6 Rt` |
| `111x` | `0xCE00..=0xCFFF` | `STR <Rt>, [r9, #<imm>]` — frame | `1100111 imm6 Rt` |

3,840 of the 4,096 decode; the 256 refused are exactly Table A9-2's UNDEFINED row.
The frame/array labelling above is *not* Table A9-2's — see §5.

Three ThumbEE differences deliberately produce no code, because the encodings
involved are unchanged and stealing them from a sibling would express a
difference that is not in the bits: the implicit null check on every load and
store (A9.1.2 — `Insn` has no "may trap" channel); the scaled register-offset
forms of A9.1.3, which A9.4 reprints under "Encoding T1" rather than a new `E<n>`
(so in ThumbEE state those five encodings print without the `lsl` the syntax line
shows — an honest cost, stated); and `BLX (immediate)`, UNDEFINED in ThumbEE but
32-bit, so it never reaches this module. `ENTERX`/`LEAVEX` are 32-bit, live in
`t32_branch_misc`, and are available in both states.

The handler branches have no computable target: `HB`/`HBL`/`HBP`/`HBLP` branch to
`TEEHBR + handler:'00000'`, reachable only through
`MRC p14, 6, <Rt>, c1, c0, 0`. `branch_target()` correctly answers `None` while
`is_branch()` answers `true`.

---

## 2. 32-bit encoding space (A5.3 / A6.3) — Thumb-2, ARMv6T2+

Top-level on `hw1[12:11] = op1` (after the `111` prefix), `hw1[10:4] = op2` and
`hw2[15] = op` (Table A5-9 / Table A6-9). The 32-bit map is every pair
`(hw1, hw2)` with `hw1` in `0xE800..=0xFFFF` — 6,144 × 65,536 = 402,653,184 bit
patterns, which is small enough to enumerate exhaustively, and §4 does.

| op1 | op2 | op | Class | § | Module |
|---|---|---|---|---|---|
| `01` | `00xx0xx` | — | Load/store multiple, `PUSH.W`/`POP.W`, `SRS`/`RFE` (A/R) | A5.3.5 | `t32_ldm_stm` |
| `01` | `00xx1xx` | — | Load/store dual, exclusive, table branch | A5.3.6 | `t32_dual_excl` |
| `01` | `01xxxxx` | — | Data processing (shifted register) | A5.3.11 | `t32_dp_shiftreg` |
| `01` | `1xxxxxx` | — | Coprocessor, floating-point, Advanced SIMD | A5.3.18 | `t32_coproc` → `t32_simd` |
| `10` | `x0xxxxx` | `0` | Data processing (modified immediate) | A5.3.1–2 | `t32_dp_modimm` |
| `10` | `x1xxxxx` | `0` | Data processing (plain binary immediate) | A5.3.3 | `t32_dp_plainimm` |
| `10` | any | `1` | Branches and miscellaneous control | A5.3.4 | `t32_branch_misc` |
| `11` | `000xxx0` | — | Store single data item | A5.3.10 | `t32_store` |
| `11` | `001xxx0` | — | Advanced SIMD element/structure load/store (A/R) | DDI 0406 A7.7 | `t32_simd` |
| `11` | `00xx001` | — | Load byte, memory hints | A5.3.9 | `t32_load` |
| `11` | `00xx011` | — | Load halfword, memory hints | A5.3.8 | `t32_load` |
| `11` | `00xx101` | — | Load word | A5.3.7 | `t32_load` |
| `11` | `00xx111` | — | UNDEFINED | — | — |
| `11` | `010xxxx` | — | Data processing (register), parallel add/sub, misc | A5.3.12–15 | `t32_dp_reg` |
| `11` | `0110xxx` | — | Multiply, MAC, absolute difference | A5.3.16 | `t32_multiply` |
| `11` | `0111xxx` | — | Long multiply, long MAC, divide | A5.3.17 | `t32_multiply` |
| `11` | `1xxxxxx` | — | Coprocessor, floating-point, Advanced SIMD | A5.3.18 | `t32_coproc` → `t32_simd` |

**The two `1xxxxxx` rows are a chain, not a single module.** Table A5-9 has no
column for Advanced SIMD *data processing*: that space is `hw1` of `0xEFxx` and
`0xFFxx`, whose `op2[6]` is set, so it arrives on the coprocessor arm along with
`LDC`/`CDP`/`MCR` and VFP. `t32_coproc::decode` returns `None` for every `hw1`
with bits[9:8] of `0b11` — exactly that space and nothing else — and the arm
chains onward to `t32_simd::decode`. The split is therefore decidable from `hw1`
alone, which is what lets §4.2 report the two as separate rows rather than as one
undifferentiated 134,217,728-pattern block. Without the chain every Advanced SIMD
data-processing encoding decodes as `None` however completely `t32_simd`
implements it, which is what happened until
`isa::tests::advanced_simd_is_reachable_through_the_dispatcher` was written to
pin it.

### 2.1 Branches and miscellaneous control (A5.3.4, Table A5-13) ✅

`hw1 = 11110 op(7) …`, `hw2 = 1 op1(3) …`, and `op1` = `hw2[14:12]` makes the
first cut:

| `hw2[14:12]` | `hw2` base | Instruction | Range | Cov |
|---|---|---|---|---|
| `0x0` | `0x8000` | `B<cond>.W` T3, or (`op == 0111xxx`) the control block | ±1 MB | ✅ |
| `0x1` | `0x9000` | `B.W` T4 | ±16 MB | ✅ |
| `1x0` | `0xC000` | `BLX (immediate)` T2 — A/R only, target 4-aligned | ±16 MB | ✅ |
| `1x1` | `0xD000` | `BL` T1 | ±16 MB | ✅ |

**T3 and T4 do not pack their immediates the same way.** This is the trap in the
group, and it is the most commonly mis-implemented thing in Thumb-2, because the
two encodings differ only in `hw2[12]` and yet resolve the same bits to different
addresses:

- `B.W` T4, `BL` T1 and `BLX` T2 use `S:I1:I2:imm10:imm11` with
  `I1 = NOT(J1 EOR S)` and `I2 = NOT(J2 EOR S)` — a ten-bit high field and two
  *inverted* J bits, giving −16777216…+16777214 (A7.7.12 T4, A7.7.18 T1,
  A8.6.23 T2).
- `B<cond>.W` T3 uses `S:J2:J1:imm6:imm11` — a **six**-bit high field, the J bits
  in the **opposite order**, and **no inversion at all**, giving
  −1048576…+1048574 (A7.7.12 T3, `imm32 = SignExtend(S:J2:J1:imm6:imm11:'0', 32)`
  on page A7-205).

Reusing the T4 arithmetic for T3 yields a target that is plausible, wrong, and
roughly 12 MB away. `crate::decode_bl` and `crate::decode_b_cond` implement both
rules, and this module is cross-checked against them.

The control block (`op == 0111xxx`, reached only with `hw2[14:12] == 000`) is
`MSR` (`0111000`/`0111001`), hints and 32-bit `CPS` (`0111010`), the barriers and
`CLREX` (`0111011`), `BXJ` (`0111100`), `SUBS PC, LR` (`0111101`) and `MRS`
(`0111110`/`0111111`). `op == 1111111` is `SMC` with `hw2[14:12] == 000` and the
permanently UNDEFINED `UDF.W` space otherwise.

Two profiles in one table, decoded as a union:

- M only: `UDF.W`, `CSDB`, `SSBB`, `PSSBB`, and the `SYSm`-numbered special
  registers (`PRIMASK`, `BASEPRI`, `CONTROL`, …) named by `MSR`/`MRS`.
- A/R only: `BLX (immediate)` T2 (there is no ARM state on M), `BXJ`,
  `SUBS PC, LR, #imm`, `SMC`, the 32-bit `CPS`, the `CPSR_<fields>` /
  `SPSR_<fields>` forms of `MSR`/`MRS`, and `ENTERX`/`LEAVEX`.

Where one encoding has two names, the one legal in both profiles wins: `MSR` with
`SYSm == 0` and `mask == 0b1000` prints as `APSR_nzcvq`, which DDI 0406 B6.1.7
states *is* `CPSR_f`. `SUBS PC, LR, #0` is the same encoding the Virtualization
Extensions call `ERET` and pre-UAL assembly wrote as `MOVS PC, LR`; the canonical
`SUBS<c><q> PC, LR, #<const>` is what prints, since it is correct on every A/R
processor.

> **ARMv5 compatibility note.** On ARMv4T/ARMv5T there is no J1/J2: `BL` is a
> pair of 16-bit instructions, `hw1 = 11110 offhi(11)` then
> `hw2 = 11111 offlo(11)`, for a 22-bit halfword offset and a range of ±4 MB.
> Within that range the two encodings are **bit-identical in both directions**:
> sign extension makes `I1 = I2 = S`, so `J1 = J2 = 1` always, which is exactly
> the `11111` prefix the v5 form requires, and `S:imm10` is exactly v5's `offhi`.
> The v7 encoding diverges from v5 only outside ±4 MB, where the v5 form does not
> exist at all. (The corresponding v5 `BLX (immediate)` suffix is `11101 offlo`,
> with the low bit architecturally zero.)

### 2.2 Data processing (modified immediate) — A5.3.1, Table A5-10 🔶

`hw1 = 11110 i 0 op(4) S Rn`, `hw2 = 0 imm3 Rd imm8`. The Armv7-M table lists a
five-bit `op` whose trailing `x` *is* the `S` bit; the A/R table gives `S` its own
column. This module decodes on the A/R spelling, because every predicate on the
instruction pages is written in terms of a standalone `S`.

Ten of the sixteen `op` values are allocated: `0000 AND` · `0001 BIC` ·
`0010 ORR` · `0011 ORN` · `0100 EOR` · `1000 ADD` · `1010 ADC` · `1011 SBC` ·
`1101 SUB` · `1110 RSB`. The other six (`0101`, `0110`, `0111`, `1001`, `1100`,
`1111`) are UNDEFINED and decode to `None`.

Aliasing is the character of the group: `Rd == 1111 && S == 1` discards the
result so `AND`/`EOR`/`ADD`/`SUB` become `TST`/`TEQ`/`CMN`/`CMP`; `Rn == 1111`
removes the first operand so `ORR`/`ORN` become `MOV`/`MVN`; and `Rn == 1101`
redirects `ADD`/`SUB` to `ADD (SP plus immediate)` T3 and
`SUB (SP minus immediate)` T2, which is visible only in `Insn::encoding`.

**`ThumbExpandImm` (A5.3.2, Table A5-11)** — the twelve bits `i:imm3:imm8` are
not a binary number. The top five, `i:imm3:a` where `a` is `imm8[7]`, select a
pattern:

| `i:imm3:a` | constant | count |
|---|---|---|
| `0000x` | `0x000000XY` | 256 |
| `0001x` | `0x00XY00XY`, `XY != 0` | 255 |
| `0010x` | `0xXY00XY00`, `XY != 0` | 255 |
| `0011x` | `0xXYXYXYXY`, `XY != 0` | 255 |
| `>= 01000` | `(0x80 \| imm8[6:0]) << (32 - i:imm3:a)` | 3,072 |

The expansion is famously non-injective in general, but on the encodings this
module decodes it is a **bijection**, and `encode_modified_imm` is its exact
inverse rather than a heuristic search — 4,093 of the 4,096 `imm12` values, the
three exceptions being `0x100`/`0x200`/`0x300`, which `ThumbExpandImm_C` itself
calls UNPREDICTABLE and which would otherwise collide with `0x000` on zero.
Refusing those three is what forces the canonical choice rather than merely
preferring it.

`Insn::explicit_width` is set for exactly the five encodings whose A7 syntax line
carries a literal `.W` — `MOV` T2, `ADD` T3, `SUB` T3, `CMP` T2 and `RSB` T2 —
which is the rule "a narrow encoding of this mnemonic *with an immediate operand*
exists". The rest of the group has no narrow immediate counterpart, so
`mvn r0, #1` is already unambiguous and printing `mvn.w` would add a suffix the
manual does not.

Not all constants are representable; an assembler must fall back to `MOVW`/`MOVT`
(§2.3) or a literal pool. `Asm::ldr_lit` is still the only way `Asm` materialises
an arbitrary `u32`.

### 2.3 Data processing (plain binary immediate) — A5.3.3, Table A5-12 ✅

`hw1 = 11110 i 1 op(5) Rn`, `hw2 = 0 imm3 Rd imm8` — the same bit positions as
A5.3.1, with `hw1[9]` the only thing that tells the two tables apart. Here the
immediate is a **plain binary number**: `ADDW r0, r1, #0x101` encodes, while the
modified-immediate `ADD.W r0, r1, #0x101` cannot.

| `op` | `Rn` | Instruction | Page | Cov |
|---|---|---|---|---|
| `00000` | not `1111` | `ADD (immediate)` T4 — `ADDW`, 12-bit | A7.7.3 | ✅ |
| `00000` | `1111` | `ADR` T3, add form | A7.7.7 | ✅ |
| `00100` | — | `MOV (immediate)` T3 — `MOVW`, 16-bit | A7.7.76 | ✅ |
| `01010` | not `1111` | `SUB (immediate)` T4 — `SUBW`, 12-bit | A7.7.174 | ✅ |
| `01010` | `1111` | `ADR` T2, subtract form | A7.7.7 | ✅ |
| `01100` | — | `MOVT`, 16-bit into the top half | A7.7.79 | ✅ |
| `10000`, `10010` | — | `SSAT` | A7.7.152 | ✅ |
| `10010`, `hw2[14:12,7:6] == 0` | — | `SSAT16` (v7E-M) | A7.7.153 | ✅ |
| `10100` | — | `SBFX` | A7.7.126 | ✅ |
| `10110` | not `1111` | `BFI` | A7.7.14 | 🔶 `msb < lsb` refused |
| `10110` | `1111` | `BFC` | A7.7.13 | 🔶 `msb < lsb` refused |
| `11000`, `11010` | — | `USAT` | A7.7.213 | ✅ |
| `11010`, `hw2[14:12,7:6] == 0` | — | `USAT16` (v7E-M) | A7.7.214 | ✅ |
| `11100` | — | `UBFX` | A7.7.193 | ✅ |

Every other `op` is UNDEFINED — in particular every *odd* one, since bit 0 of
`op` is zero in all eleven allocated rows.

`MOVW` + `MOVT` is the pool-free way to load an arbitrary `u32`, which is the
natural upgrade path for `Asm` when a literal pool will not fit.

Nothing here has an `S` bit: `ADDW`/`SUBW` exist precisely *because* they are the
non-flag-setting wide add and subtract, `SSAT`/`USAT` write `APSR.Q` (not the
`S`-suffix flags), and the bitfield instructions write no status at all.

**The deliberate off-by-ones**, each spelled out in the instruction's own
pseudocode — and the first two are one opcode bit apart, which makes them the
single easiest thing in this table to get wrong:

- `SSAT`: `saturate_to = UInt(sat_imm) + 1`, syntax range 1–32.
- `USAT`: `saturate_to = UInt(sat_imm)`, syntax range **0–31** — no `+1`.
- `SBFX`/`UBFX`: the field is `widthm1`, and `<width> = widthm1 + 1`, range 1–32.
- `BFI`/`BFC`: the encoding holds `lsb` and `msb`, UAL writes `lsb` and `width`,
  with `msbit = <lsb> + <width> - 1`. `msb < lsb` would make `<width>` zero or
  negative, which the pseudocode calls UNPREDICTABLE, so it is refused.

### 2.4 Load/store multiple (A5.3.5, Table A5-16) 🔶

```text
hw1 = 1110 100 op(2) 0 W L Rn
hw2 = register_list(16)
```

Six operations out of two bits, because `W:Rn` is consulted as well as `op:L`:

| `op` | `L` | `W:Rn` | Instruction | Encoding |
|---|---|---|---|---|
| `01` | 0 | — | `STM` / `STMIA` / `STMEA` | T2 |
| `01` | 1 | not `11101` | `LDM` / `LDMIA` / `LDMFD` | T2 |
| `01` | 1 | `11101` | `POP` | T2 |
| `10` | 0 | not `11101` | `STMDB` / `STMFD` | T1 |
| `10` | 0 | `11101` | `PUSH` | T2 |
| `10` | 1 | — | `LDMDB` / `LDMEA` | T1 |
| `00` | 0 | — | `SRS` (A/R only) | T1 |
| `00` | 1 | — | `RFE` (A/R only) | T1 |
| `11` | 0 | — | `SRS` (A/R only) | T2 |
| `11` | 1 | — | `RFE` (A/R only) | T2 |

**`W:Rn == 11101` is what makes a `push`.** Writeback to `sp` is not *like* a
push, it **is** one: A7.7.159 carries `if W == '1' && Rn == '1101' then SEE PUSH`
and A7.7.41 carries `if W == '1' && Rn == '1101' then SEE POP (Thumb)`. `e92d
4010` is `push.w {r4, lr}`, not `stmdb sp!, {r4, lr}`. Decoding it the long way
leaves every 32-bit prologue in an image legible but un-reassemblable. Note which
rows this does *not* touch: `LDMDB sp!` is not a `pop` (wrong direction),
`STM sp!` is not a `push`, and without the `!` neither is anything but itself.

The register list is a real sixteen-bit mask here — `pc` (bit 15) and `lr`
(bit 14) are ordinary members of it, not a separate `M`/`P` bit as in the 16-bit
forms. Two bits are constrained by the diagrams rather than by prose, and both
are refused outright: **bit 13 is `(0)` in all six encodings** (`sp` cannot be in
any list) and **bit 15 is `(0)` in the three stores** (`pc` cannot be stored by a
Store Multiple).

**`BitCount(registers) < 2` is refused here, where the narrow forms refuse only
`< 1`** (§1.5, §1.6). **The asymmetry is Arm's, not this crate's**, and it is on
the same page in each case: A7.7.41 writes `if BitCount(registers) < 1 then
UNPREDICTABLE` under `LDM` encoding T1 and `if n == 15 || BitCount(registers) < 2
|| (P == '1' && M == '1') then UNPREDICTABLE` three lines later under T2, and
A7.7.99 (`POP`), A7.7.101 (`PUSH`) and A7.7.159 (`STM`) each do the same. The
reason is not merely the label: a
one-register wide list has a narrow spelling of the same instruction, so the text
a wide decode would print reads back as the *narrow* halfword and the round trip
is no longer an identity. `e890 0001` — `ldm.w r0, {r0}` — is `None`; `e890 0003`
is `ldm.w r0, {r0, r1}` and decodes. The check is `list.count_ones() >= 2` in one
helper, called from `decode` and from both arms of `encode`. It removes 1,984
patterns from this group's count against an enumeration taken before the rule
existed.

Writeback prints as part of the base operand — `Operand::Text("sp!")` rather than
`Operand::Reg(sp)` plus something — because `Insn` has no writeback flag and
`Display` joins operands with `", "`, so a trailing `Operand::Text("!")` would
print `stmdb sp, !, {…}`. A consumer matching on `Operand::Reg` to find the base
must handle the `Text` case too.

`STM`, `LDM`, `PUSH` and `POP` have 16-bit encodings, so their wide forms carry
`.w`; `STMDB`, `LDMDB`, `SRS` and `RFE` have no narrow counterpart and Arm's
syntax lines carry no `.W`, so neither do we.

One limit worth stating: `RFE` loads the pc, but `Insn::writes_pc` recognises
pc-writing loads by mnemonic (`ldm`, `ldmdb`, `pop`) or by a pc destination
operand, and `RFE` is neither — so `rfeia r0!` reports `is_branch() == false`.

### 2.5 Load/store dual, exclusive, table branch (A5.3.6, Table A5-17) 🔶

Every encoding shares one first halfword, `hw1 = 1110 100 P U 1 W L Rn`, and
Table A5-17's `op1`/`op2` are those four bits regrouped — `op1 = P:U`,
`op2 = W:L`. Reading them as `P`, `U`, `W`, `L` is what makes the table's shape
obvious: `P`/`W` are the dual transfers' addressing mode (`10` offset, `11`
pre-indexed, `01` post-indexed), and the fourth combination `P == 0 && W == 0`
names no addressing mode at all — which is precisely the hole the architecture
fills with the exclusives and the table branches.

| `hw2` | Instruction | Page | From |
|---|---|---|---|
| `Rt Rd imm8` | `STREX` | A7.7.167 / A8.6.202 | Armv6T2 |
| `Rt (1)(1)(1)(1) imm8` | `LDREX` | A7.7.52 / A8.6.69 | Armv6T2 |
| `Rt Rt2 imm8` | `STRD` | A7.7.166 / A8.6.200 | Armv6T2 |
| `Rt Rt2 imm8` | `LDRD` (`Rn == 1111` → `LDRD (literal)`) | A7.7.50 / A8.6.66 | Armv6T2 |
| `Rt (1)(1)(1)(1) 0100 Rd` | `STREXB` | A7.7.168 | Armv7 |
| `Rt (1)(1)(1)(1) 0101 Rd` | `STREXH` | A7.7.169 | Armv7 |
| `Rt Rt2 0111 Rd` | `STREXD` | A8.6.204 | Armv7 A/R only |
| `(1)(1)(1)(1) (0)(0)(0)(0) 0000 Rm` | `TBB` | A7.7.185 | Armv6T2 |
| `(1)(1)(1)(1) (0)(0)(0)(0) 0001 Rm` | `TBH` | A7.7.185 | Armv6T2 |
| `Rt (1)(1)(1)(1) 0100 (1)(1)(1)(1)` | `LDREXB` | A7.7.53 | Armv7 |
| `Rt (1)(1)(1)(1) 0101 (1)(1)(1)(1)` | `LDREXH` | A7.7.54 | Armv7 |
| `Rt Rt2 0111 (1)(1)(1)(1)` | `LDREXD` | A8.6.71 | Armv7 A/R only |

**Operand order is the thing to get wrong.** The load and store exclusives are
not mirror images: `LDREX<c><q> <Rt>, [<Rn> {,#<imm>}]` against
`STREX<c><q> <Rd>, <Rt>, [<Rn> {,#<imm>}]`. The store carries an extra *first*
operand, `<Rd>`, which receives the success status — a destination on a store.
The asymmetry runs through the sized forms and through the A/R doubleword pair
(`STREXD` takes four operands). Transposing them produces text that assembles and
stores the wrong register, so the tests assert the operand *count* as well as the
order.

Only `STREX`/`LDREX` take an immediate (`imm8:'00'`, 0–1020); the sized and
doubleword exclusives have none, and the bits an offset would occupy hold `op3`
and a register instead.

`TBB [<Rn>, <Rm>]` and `TBH [<Rn>, <Rm>, LSL #1]` branch, but nowhere in
particular: the target comes from memory this crate has not been given, so
`branch_target()` is `None` while `is_branch()` is `true` — the honest answer,
"control leaves here and I cannot tell you where". `TBH`'s `LSL #1` is not an
optional shift a disassembler may drop; it is real (`R[n] + LSL(R[m],1)`, because
the table holds halfwords) and part of the syntax line.

### 2.6 Load/store single data item (A5.3.7–A5.3.10, Tables A5-18–A5-21) 🔶

Three load tables and one store table, one shape:

```text
loads   hw1: 1 1 1 1 1 0 0 S L size(3) Rn(4)      hw2: Rt(4) op2(6) …
stores  hw1: 1 1 1 1 1 0 0 0 op1(3) 0  Rn(4)      hw2: Rt(4) op2(6) …
```

`size` is `001`/`011`/`101` for byte/halfword/word (`111` is UNDEFINED), `S`
selects the signed load, and `L` means three different things depending on the
row — the literal form's `U` bit when `Rn == 1111`, otherwise the selector
between the 12-bit unsigned immediate form and the `op2`-dispatched forms. `S`
with `size == 101` is UNDEFINED: there is no signed word load, because a word
needs no widening. Getting `S` inverted swaps `LDRB` with `LDRSB`, which decodes
to something plausible and wrong.

**`P`/`U`/`W`, and the row that is not an addressing mode:**

| `P` | `U` | `W` | `op2` | Result |
|---|---|---|---|---|
| 1 | 0 | 0 | `1100xx` | offset, negative — `[rn, #-imm8]` |
| 1 | 1 | 0 | `1110xx` | the **unprivileged** `LDR*T`/`STR*T` forms |
| 1 | `U` | 1 | `1xx1xx` | pre-indexed — `[rn, #±imm8]!` |
| 0 | `U` | 1 | `1xx1xx` | post-indexed — `[rn], #±imm8` |
| 0 | `U` | 0 | `10x0xx` | UNDEFINED |

Note the last two rows against a common misreading: `P == 0 && W == 0` is *not*
the unprivileged form, it is UNDEFINED. See §5.

**Offsets here are unscaled.** Every immediate in the wide space is a plain byte
offset (`ZeroExtend(imm12, 32)` or `ZeroExtend(imm8, 32)`), which is the
*opposite* of the 16-bit space, where each is scaled by the access size. So
`strh.w r0, [r1, #4]` puts a literal `4` in the field where the narrow
`strh r0, [r1, #4]` puts a `2`. Assuming symmetry silently halves or quarters
every halfword and word offset in a disassembly.

`Rn == 1111` in a *load* is the literal form, whatever `op2` says (`op2` is then
part of `imm12`), and its base is `Align(PC,4)` — same non-commuting pair of
steps as §1.4, same both-alignment sweep. `Rn == 1111` in a *store* is UNDEFINED
in every row; there is no "store to a literal".

`Rt == 1111` in the byte and halfword *load* spaces does not name a destination
register — it selects a hint, and Tables A5-19/A5-20 split those encodings three
ways, which this module answers three different ways:

1. **A real hint** — `PLD` (immediate, literal, register) and `PLI`
   (immediate/literal, register). Decoded as themselves, no `Rt` operand.
   Table A6-19 additionally allocates three `PLDW` rows under the ARMv7
   Multiprocessing Extensions; the halfword space *is* the `W` bit of
   `PLD, PLDW`, so those decode too, with the caveat that an M-profile core
   executes them as a NOP.
2. **"Unallocated memory hint, treat as NOP"** — allocated by no profile, no
   syntax to print, nothing to re-assemble: `None`, so a caller stepping over
   four bytes sees exactly the NOP-shaped hole the architecture describes.
3. **UNPREDICTABLE** — the writeback and unprivileged rows, plus the halfword
   literal rows: `None`, because naming an instruction there would assert a
   behaviour no conforming core owes the caller.

The word space has no such rule (Table A5-18 has no `Rt` column), so
`ldr.w pc, [r0]` is a real, branching load and decodes as one.

`Rt == 1111` in a *store* is refused — the one operand-level rejection
`t32_store` makes — because `Insn::writes_pc` ends with "operand 0 is `pc`",
which is right for a load and exactly wrong for a store. Decoding `str pc, [r0]`
would make `is_branch()` report a branch that is not one, in the crate whose
reason for existing is to stop a firmware scan from inventing branches.

**`push` hiding in the store table, and the one place the two sides disagree.**
`STR (immediate)` T4 carries a redirect that is easy to miss:
`if Rn == '1101' && P == '1' && U == '0' && W == '1' && imm8 == '00000100' then
SEE PUSH` (A7.7.161). `str rt, [sp, #-4]!` **is** `PUSH` encoding T3, the
one-register push, and `t32_store` decodes `f84d 4d04` as `push.w {r4}` —
`Insn::encoding` of `"T3"` is what tells it from the multi-register `PUSH` T2 of
§2.4. `LDR (immediate)` T4 carries the exact mirror-image redirect,
`if Rn == '1101' && P == '0' && U == '1' && W == '1' && imm8 == '00000100' then
SEE POP` (A7.7.43), but `t32_load` **deliberately does not take it**:
`f85d 4b04` decodes as `ldr r4, [sp], #4`, on the grounds that Table A5-18
allocates that encoding to `LDR (immediate)` and `POP`'s own encoding
(A7.7.99 T3) belongs to another group, so claiming it here would make the round
trip ambiguous. The same argument applies verbatim to `PUSH`, and the two
modules resolve it opposite ways. Both choices round-trip; they are simply not
the same choice, and a consumer scanning for stack traffic must look for
`push` *and* for a post-indexed `ldr` from `sp` by four.

`explicit_width` follows Arm's own syntax lines: set for the encodings spelled
`LDR<c>.W`/`STR<c>.W` — the 12-bit immediate forms, the register forms, and
`LDR (literal)` T2 — and clear for the forms with no narrow twin (the 8-bit
`P`/`U`/`W` forms, the unprivileged forms, the non-`LDR` literals and the hints),
because nothing 16-bit subtracts, writes back, or drops privilege.

### 2.7 Data processing (shifted register) — A5.3.11, Tables A5-22/A5-23 🔶

```text
hw1 = 1110 101 op(4) S Rn(4)
hw2 = (0) imm3(3) Rd(4) imm2(2) type(2) Rm(4)
```

Every instruction here is "`Rn` combined with `Rm` shifted by `type` by
`imm3:imm2`, into `Rd`, optionally setting the flags". The five bits of
`imm3:imm2` and the two of `type` are a single `Shift`, and this group is what
`Operand::RegShifted` exists for.

Eleven of the sixteen `op` values are allocated: `0000 AND/TST` · `0001 BIC` ·
`0010 ORR/MOV` · `0011 ORN/MVN` · `0100 EOR/TEQ` · `0110 PKHBT/PKHTB` ·
`1000 ADD/CMN` · `1010 ADC` · `1011 SBC` · `1101 SUB/CMP` · `1110 RSB`. The other
five are UNDEFINED.

Three things are not the shared shape:

- **`Rd == 1111` is a test instruction, not a destination**, for `op` of `0000`,
  `0100`, `1000` and `1101` — but only with `S == 1`. `Rd == 1111` with `S == 0`
  is UNPREDICTABLE in Table A5-22 and names no instruction at all, so those 8,192
  encodings decode to `None` rather than inventing an `and pc, …` no assembler
  would accept back.
- **`Rn == 1111` is "no first operand"**, so `ORR` becomes `MOV` and `ORN`
  becomes `MVN` — the same two aliasing rules as §2.2, applied to the other half
  of the data-processing space.
- **Table A5-23 is the interesting part.** When `op == 0010 && Rn == 1111` the
  shift *is* the operation, and `type` plus `imm3:imm2` select one of six:

| `type` | `imm3:imm2` | Instruction | Encoding |
|---|---|---|---|
| `00` | `00000` | `MOV (register)` | T3 |
| `00` | not `00000` | `LSL (immediate)` | T2 |
| `01` | — | `LSR (immediate)` | T2 |
| `10` | — | `ASR (immediate)` | T2 |
| `11` | `00000` | `RRX` | T1 |
| `11` | not `00000` | `ROR (immediate)` | T1 |

The two boundaries are the whole of A5.3.11's difficulty. A left shift by zero is
a no-op, so `type == 00` with a zero amount is spent on `MOV` (A7.7.68); a rotate
by zero is equally a no-op, so `type == 11` with a zero amount is spent on `RRX`
(A7.7.116). `LSR` and `ASR` have no such hole, because for them a zero field
already means 32.

UAL writes `and.w r0, r1, r2`, never `and.w r0, r1, r2, lsl #0` — every syntax
line spells the shift `{,<shift>}` — so a zero `LSL` yields a plain register
operand in both directions, and an explicit `lsl #0` is *rejected* on encode
because it is not a form this decoder ever produces.

`PKHBT`/`PKHTB` (the `0110` row, Armv7E-M) read `type` as `tb:T` rather than as a
shift type: `T == 1` and `S == 1` are both UNDEFINED, and `tb` picks between
`PKHBT` (`LSL`) and `PKHTB` (`ASR`). Because the pseudocode is
`DecodeImmShift(tb:'0', imm3:imm2)`, the *amount* still decodes by the ordinary
rule — which is why `PKHTB` with a zero field prints `, asr #32` and never omits
its shift, while `PKHBT` with a zero field omits it. Arm explicitly forbids the
`PKHTB …, asr #0` spelling for disassembly.

`hw2[15]` is drawn `(0)` in every diagram in this group; a `1` there decodes to
`None`.

### 2.8 Data processing (register), parallel add/sub, miscellaneous — A5.3.12–15 🔶

```text
hw1 = 1111 1010 op1(4) Rn(4)
hw2 = 1111      Rd(4)  op2(4) Rm(4)
```

**The first check is not a table lookup.** Stated under the A5.3.12 bit diagram
and repeated under each of A5.3.13–15: *if, in the second halfword, bits[15:12]
!= 0b1111, the instruction is UNDEFINED*. That is fifteen sixteenths of the
group's encoding space rejected before any `op1`/`op2` decoding happens, and it
is the one rule a table-driven decoder is most likely to skip, because it lives
in the prose rather than in a table row. It is also most of why §4's row for
this group reads 1.79%.

| Sub-table | Contents |
|---|---|
| A5-24 `op1[3] == 0` | `LSL`/`LSR`/`ASR`/`ROR (register)` T2 — the only rows here with an `S` bit — and the six extend pairs `SXTAH`/`SXTH`, `UXTAH`/`UXTH`, `SXTAB16`/`SXTB16`, `UXTAB16`/`UXTB16`, `SXTAB`/`SXTB`, `UXTAB`/`UXTB` |
| A5-25 `op2[3:2] == 00` | signed parallel: `SADD8/16`, `SASX`, `SSUB8/16`, `SSAX`, and the `Q`- and `SH`-prefixed saturating and halving variants |
| A5-26 `op2[3:2] == 01` | unsigned parallel: `UADD8/16`, `UASX`, `USUB8/16`, `USAX`, and the `UQ`- and `UH`-prefixed variants |
| A5-27 `op2[3:2] == 10` | `QADD`, `QDADD`, `QSUB`, `QDSUB`; `REV`, `REV16`, `RBIT`, `REVSH`; `SEL`; `CLZ` |
| `op2[3:2] == 11` | unallocated |

Six of A5-24's rows are pairs distinguished only by `Rn`: `op1 == 0b0000` with
`op2 == 0b1xxx` is `SXTAH` unless `Rn == 0b1111`, in which case there is nothing
to add to and the instruction is the plain `SXTH`. A7.7.181 says so from the
other direction (`if Rn == '1111' then SEE SXTH;`), so the aliasing is
architectural, not a disassembler convention. Reading it backwards yields an
instruction that is plausible, assembles, and is wrong.

Two ways a bit pattern can be in a table and still not be an instruction, both
refused: bit 6 of the extends' `hw2` is a `(0)`; and `REV`, `REV16`, `RBIT`,
`REVSH` and `CLZ` encode their single source register *twice*, in `hw1`'s `Rn`
and `hw2`'s `Rm`, with `if !Consistent(Rm) then UNPREDICTABLE` on every page.

Most of this group is DSP-extension territory — the whole of A5-25 and A5-26, the
extend-and-add forms, `SXTB16`/`UXTB16`, `SEL` and the four saturating `Q`
operations are v7E-M. Only the shifts, the plain byte and halfword extends,
`REV`/`REV16`/`RBIT`/`REVSH` and `CLZ` are baseline. A consumer analysing what it
believed to be a Cortex-M3 image and finding a `QADD16` has learned something
important about the image.

### 2.9 Multiply, MAC, long multiply, divide — A5.3.16/A5.3.17, Tables A5-28/A5-29 🔶

```text
A5.3.16   hw1 = 1111 1011 0 op1(3) Rn(4)   hw2 = Ra(4)   Rd(4)   0 0 op2(2) Rm(4)
A5.3.17   hw1 = 1111 1011 1 op1(3) Rn(4)   hw2 = RdLo(4) RdHi(4) op2(4)     Rm(4)
```

Both share the top byte `0xFB`, and `hw1[7]` is the only bit that tells them
apart. Seventeen of A5-28's 32 `(op1, op2)` cells are allocated; fifteen of
A5-29's 128 are.

**`Ra == 0b1111` is an alias, not a register.** Almost every row of Table A5-28 is
a multiply-accumulate, and almost every one spends the `Ra` encoding `0b1111` on
naming the *non*-accumulating operation instead of on `r15`: `MLA` becomes `MUL`,
`SMLABB` becomes `SMULBB`, `USADA8` becomes `USAD8`. Each A7.7 page states it as
a decode-time redirection, so the two forms are different instructions — the
accumulating form takes four register operands and the plain form three. Exactly
two rows have no alias, and there `Ra == 0b1111` really does mean `r15`
(UNPREDICTABLE, but decodable): `MLS` and `SMMLS`/`SMMLSR`, both of which
Table A5-28 writes with `-` in the `Ra` column. The `op1 = 111` row is the one the
tables get wrong — see §5.

**Suffixes come from the encoding, not from an operand**, which is why this module
is a table of `&'static str`:

- `<x><y>` on `SMLAxy`/`SMULxy`/`SMLALxy`: `op2` supplies `N:M`, `N` selecting
  which halfword of `Rn` and `M` which of `Rm`, `0` bottom and `1` top. So
  `op2 = 0b01` is `BT` and `0b10` is `TB`. Transposing those two is silent — both
  mnemonics exist and both assemble.
- `X` on `SMLAD`/`SMUAD`/`SMLSD`/`SMUSD`/`SMLALD`/`SMLSLD`: `op2[0]` is `M`,
  "swap the halfwords of the second operand before multiplying".
- `R` on `SMMLA`/`SMMUL`/`SMMLS`: `op2[0]` is `R`, "round rather than truncate".

Architecture variants, which a consumer can read a core's feature set off:
`MUL`, `MLA`, `MLS`, `SMULL`, `UMULL`, `SMLAL`, `UMLAL` are ARMv6T2-and-above
baseline; everything else in Table A5-28 plus `SMLALBB`…`SMLALTT`, `SMLALD`,
`SMLSLD` and `UMAAL` is v7E-M on the M profile (baseline ARMv6T2 on A/R), so an
`SMLALD` in the stream means a Cortex-M4/M7-class core and not an M3; and
`SDIV`/`UDIV` are mandatory from ARMv7-M and present on ARMv7-R but **UNDEFINED
on ARMv7-A**, so finding one rules an A-profile core out. The two divides also
carry a should-be-one `RdLo` field of `1111`, and an encoding that violates it
does not decode.

`MUL` is the one operation here that also has a 16-bit encoding (T1,
`MULS <Rdm>,<Rn>,<Rdm>`, §1.2), so its wide form is encoding **T2** and is the
only member of either table that needs `explicit_width`.

### 2.10 Coprocessor, floating-point and Advanced SIMD — A5.3.18, Table A5-30 🔶

`hw1[15:13] == 0b111` with `hw1[11:10] == 0b11`, that is `hw1` in
`0xEC00..=0xEFFF` and `0xFC00..=0xFFFF`. The dispatcher reaches `t32_coproc` from
two arms of Table A5-9, because `hw1[12]` is not part of the group selector here:
it is the bit that turns `LDC` into `LDC2` and `CDP` into `CDP2`, and — once the
coprocessor number says floating-point — VFPv4 into the four FPv5 additions
`VSEL`, `VMAXNM`/`VMINNM`, `VRINT{A,N,P,M}` and `VCVT{A,N,P,M}`.

**Two instruction sets share one encoding space.** Every encoding here is
architecturally a coprocessor access, and `coproc` = `hw2[11:8]` decides how to
read the rest. For `coproc` other than 10 and 11 the operand fields are *opaque*
— A7.7.22 says of `CDP` that "only instruction bits<31:24>, bits<11:8>, and
bit<4> are architecturally defined. The remaining fields are recommendations" —
so `LDC`/`STC`/`CDP`/`MCR`/`MRC`/`MCRR`/`MRRC` and their `2` and `L` variants
decode to coprocessor numbers, coprocessor registers and raw immediates, and
nothing is claimed about what they mean. `coproc == 10` and `coproc == 11` are
not coprocessor accesses at all in any implementation that matters: they are the
floating-point instruction set, with `coproc[0]` as the precision.

**The register-numbering rule is the thing to get right.** An extension register
number is five bits assembled from a 4-bit field and a separate 1-bit field, and
**the two are concatenated in opposite orders for the two precisions**:

| operand | single precision | double precision |
|---|---|---|
| destination | `Vd:D`, bits[15:12,22] | `D:Vd`, bits[22,15:12] |
| first source | `Vn:N`, bits[19:16,7] | `N:Vn`, bits[7,19:16] |
| second source | `Vm:M`, bits[3:0,5] | `M:Vm`, bits[5,3:0] |

Get the order backwards and `s1` decodes as `s16`. Every one of the 32 register
numbers is reachable either way, so nothing about the bits looks wrong; the only
defence is a test that pins both directions.

The floating-point coverage is the scalar VFP instruction set: the three-register
data-processing operations (`VADD`, `VSUB`, `VMUL`, `VNMUL`, `VDIV`, `VMLA`,
`VMLS`, `VNMLA`, `VNMLS`, `VFMA`, `VFMS`, `VFNMA`, `VFNMS`, and FPv5's `VMAXNM`,
`VMINNM`), the two-register ones (`VMOV`, `VABS`, `VNEG`, `VSQRT`, the `VRINT`
family), `VCMP`/`VCMPE`, the whole `VCVT` matrix (half, integer, fixed-point,
double↔single, and FPv5's directed roundings), `VSEL`, the transfers `VMOV`
(register↔extension, and the `.32` scalar forms), `VMRS`/`VMSR`, and the memory
forms `VLDR`/`VSTR`/`VLDM`/`VSTM`/`VPUSH`/`VPOP`. `VFPExpandImm` (A6.4.1) is
transcribed from the pseudocode, and its inverse is an exact search over the 256
representable values rather than a nearest-match — an assembler that silently
encoded `#0.3` as `#0.3125` would be worse than one that refused.

**Advanced SIMD** splits in two — two chapters of DDI 0406, two regions of `hw1`,
two routes through the dispatcher, one module:

- *Element and structure load/store* (`hw1[15:8] == 0b1111_1001`, DDI 0406 A7.7,
  Tables A7-20/A7-21) — `VLD1`–`VLD4` and `VST1`–`VST4`, in all three shapes:
  multiple-element, single-element-to-one-lane, and to-all-lanes. Implemented in
  `t32_simd` and routed there directly by the dispatcher (`op1 == 0b11`,
  `op2 == 0b001xxx0`). ✅
- *Data processing* (`hw1[15:8] == 0b111u_1111`, DDI 0406 A7.4) — the `VADD.I32`
  / `VAND` / `VMUL` / `VSHL` / … grid, dispatched by Table A7-8 into Table A7-9
  (three registers of the same length), A7-10 (different lengths), A7-11 (two
  registers and a scalar), A7-12 (two registers and a shift), A7-13 (two
  registers, miscellaneous) and A7-14/A7-15 (one register and a modified
  immediate), plus `VEXT`, `VTBL`/`VTBX` and `VDUP (scalar)`. Also `t32_simd`,
  reached through the coprocessor arm's chain (§2 above). `0xEF02 0842` is
  `vadd.i8 q0, q1, q1`. ✅

**A quadword operand must name an even doubleword.** `Qn` *is* the pair
`D(2n):D(2n+1)`, so every `Q` form in A7.4 carries
`if Q == '1' && Vd<0> == '1' then UNDEFINED` (A8.6.271 and forty pages like it),
and the same for `Vn` and `Vm` where the form has them. `t32_simd::vec` is the
one place that test lives, which is why it is applied uniformly rather than in
the forty places the manual writes it: `0xEF02 0A42` is `None` where
`0xEF02 0842` is `vadd.i8 q0, q1, q1`. A sweep that only ever offers even
register numbers never exercises the rule; firmware is not so considerate, and
the module's sweeps put an odd number in each of the three operand positions in
turn.

Two consequences of the shared vocabulary, both visible in printed output. A
floating-point register *range* is encoded as a first register and a count, not a
bitmask, so `Operand::RegList` cannot hold one and `VLDM`/`VSTM`/`VPUSH`/`VPOP`
lists longer than one register are `Operand::Text`; so are `<Rn>!` writeback,
`LDC`'s braced `<option>`, and Advanced SIMD's `[<Rn>:<align>]!`. And `VSEL`'s
condition is part of the operation rather than a suffix the IT machinery
supplies, so it is spelled into the mnemonic (`vselgt.f32`) — printing it the
other way would give `vsel.f32gt`.

---

## 3. Profile deltas worth remembering

| | ARMv5T (ARM7/9) | ARMv6-M (M0) | ARMv7-M (M3/M4) | ARMv7-A/R |
|---|---|---|---|---|
| 16-bit Thumb-1 | ✅ | ✅ | ✅ | ✅ |
| `BL` J-bit encoding | ❌ (halfword pair) | ✅ | ✅ | ✅ |
| `CBZ`/`CBNZ`, `IT` | ❌ | ❌ ("ARMv6-M does not support the IT instruction") | ✅ | ✅ |
| 32-bit Thumb-2 general | ❌ | only `BL`, `DSB`, `DMB`, `ISB`, `MSR`, `MRS` | ✅ | ✅ |
| `SETEND` / `CPS`, 16-bit | ❌ (both are v6+) | `CPS` only | `CPS` only | both |
| DSP / saturating (`Q*`, `SMLA*`, parallel add/sub) | ARMv5TE, ARM state only | ❌ | v7E-M (M4) | ✅ baseline from v6T2 |
| Hardware divide (`SDIV`/`UDIV`) | ❌ | ❌ | ✅ mandatory | R ✅, **UNDEFINED on A** |
| `SRS`/`RFE`, `BXJ`, `SMC`, `SUBS PC, LR` | ❌ | ❌ | ❌ | ✅ |
| Coprocessor (`MCR`/`MRC`/`LDC`/`STC`) | ARM state only | ❌ | ✅ | ✅ |
| Floating point (VFP) | optional, ARM state | ❌ | ✅ FPv4/FPv5 (M4F/M7) | ✅ |
| ThumbEE, Advanced SIMD | ❌ | ❌ | ❌ | ✅ (ThumbEE required on A, optional on R) |
| `BLX (immediate)` | ✅ (v5T) | ❌ | ❌ (no ARM state) | ✅ |
| Condition via `IT` | n/a | n/a | ✅ | ✅ |

For reverse engineering: if an image contains `CBZ` or `IT`, it is v6T2 or later;
if it contains `SETEND`, `SRS`, `BXJ` or an Advanced SIMD instruction it is A/R,
not M; an `SDIV` rules out ARMv7-A; an `SMLALD` means Cortex-M4/M7-class rather
than M3. The decoder in this crate implements the **union** of the profiles
throughout, because a decoder that knows only one of them mis-reads the other,
and the halfwords carry nothing that distinguishes them. A consumer that must
reject an instruction its target does not have has to do so itself, by mnemonic.

---

## 4. Coverage, counted

### 4.1 The counting method

Thumb's length rule (§0) partitions every bit pattern a Thumb stream can present
into exactly two sets, and both are small enough to enumerate:

- **59,392** single halfwords, `0x0000..=0xE7FF`.
- **402,653,184** halfword pairs, `(hw1, hw2)` with `hw1` in `0xE800..=0xFFFF`
  — 6,144 × 65,536. (It is not 2^32: only 6,144 of the 65,536 `hw1` values begin
  a 32-bit instruction.)

**402,712,576** patterns in total. The figures below are an exhaustive
enumeration of all of them, not a sample: every pattern was handed to
`isa::decode_halfwords` at an address of `0x1002` — deliberately 2 mod 4, so that
every `Align(PC,4)` form is exercised at the alignment where getting it wrong
shows — and every pattern that decoded was handed back to `isa::encode` and the
result compared with the pattern it came from. Each group's row below is the
slice of that space the dispatcher in `src/isa/mod.rs` routes to it, so the rows
partition the whole and the totals are a sum, not an estimate. ThumbEE is counted
separately, because it *re-assigns* 4,096 of the narrow halfwords rather than
adding to them (§1.7), and is enumerated with the flag set.

Attribution is by the dispatcher's own bit tests, transcribed. The one arm that
is not a plain match is the coprocessor chain (§2), and it is still decidable
from `hw1` alone: `t32_coproc::decode` answers `None` for exactly
`hw1[9:8] == 0b11`, and `t32_simd::decode` answers `None` for every `hw1` outside
`0xF9xx`/`0xEFxx`/`0xFFxx`, so the chain's two members own disjoint halves of the
arm and are reported as separate rows. The `t32_simd` row is therefore split in
two — element/structure (A7.7), which the dispatcher routes directly, and data
processing (A7.4), which arrives through the chain — because they are different
sub-tables of Arm's manual reached by different paths, and merging them would
hide the path.

Mnemonic counts are over the same enumeration: the distinct `Insn::mnemonic`
values seen, and the distinct `(mnemonic, encoding)` pairs. The *base* count
collapses the three things `Insn` spells into the mnemonic for want of another
field (§6): everything from the first `.` is dropped (`vadd.i8` → `vadd`), an
`IT` mask becomes `it` (`ittee` → `it`), and `VSEL`'s condition is dropped
(`vselgt` → `vsel`). Nothing else is merged, so `ldmia` and `ldmdb` remain two
names, as they are two rows of A7.7.

### 4.2 The numbers

| Module | § | Patterns | Decoded | Share |
|---|---|---|---|---|
| `t16_shift` | A5.2.1 | 16,384 | 16,384 | 100% |
| `t16_dataproc` | A5.2.2 | 1,024 | 1,024 | 100% |
| `t16_special` | A5.2.3 | 1,024 | 736 | 71.88% |
| `t16_loadstore` | A5.2.4 | 26,624 | 26,624 | 100% |
| `t16_misc` | A5.2.5 | 4,096 | 3,241 | 79.13% |
| `t16_branch` | A5.2.6 | 10,240 | 10,224 | 99.84% |
| **16-bit total** | **A5.2** | **59,392** | **58,233** | **98.05%** |
| `thumbee` (re-assigned) | A9.2.1 | 4,096 | 3,840 | 93.75% |
| `t32_dp_modimm` | A5.3.1–2 | 33,554,432 | 20,956,160 | 62.45% |
| `t32_dp_plainimm` | A5.3.3 | 33,554,432 | 11,026,432 | 32.86% |
| `t32_branch_misc` | A5.3.4 | 67,108,864 | 56,690,519 | 84.48% |
| `t32_ldm_stm` | A5.3.5 | 16,777,216 | 3,143,936 | 18.74% |
| `t32_dual_excl` | A5.3.6 | 16,777,216 | 13,775,872 | 82.11% |
| `t32_load` | A5.3.7–9 | 12,582,912 | 7,331,136 | 58.26% |
| `t32_store` | A5.3.10 | 8,388,608 | 3,844,800 | 45.83% |
| `t32_dp_shiftreg` | A5.3.11 | 33,554,432 | 10,616,832 | 31.64% |
| `t32_dp_reg` | A5.3.12–15 | 16,777,216 | 300,288 | 1.79% |
| `t32_multiply` | A5.3.16–17 | 16,777,216 | 1,974,272 | 11.77% |
| `t32_coproc` | A5.3.18 + VFP | 100,663,296 | 86,922,507 | 86.35% |
| `t32_simd`, element/structure | DDI 0406 A7.7 | 8,388,608 | 3,864,064 | 46.06% |
| `t32_simd`, data processing | DDI 0406 A7.4 | 33,554,432 | 11,817,024 | 35.22% |
| (UNDEFINED by Table A5-9) | — | 4,194,304 | 0 | 0% |
| **32-bit total** | **A5.3** | **402,653,184** | **232,263,842** | **57.68%** |
| **Whole encoding space** | | **402,712,576** | **232,322,075** | **57.69%** |

The `t32_coproc` and `t32_simd` data-processing rows together are the 134,217,728
patterns the two `op2[6] == 1` arms of Table A5-9 carry; §2 explains why they are
one arm and two modules, and §4.1 why the split is exact rather than approximate.

Those 232,322,075 patterns are **817 distinct `Insn::mnemonic` values** across
**911 distinct `(mnemonic, encoding)` pairs**. The mnemonic count is inflated by
the suffixes `Insn` has no other channel for (§6) — the `T`/`E` letters of an
`IT` mask, the data type of a floating-point or Advanced SIMD operation, and
`VSEL`'s condition — and collapsing those by §4.1's rule gives **385 base
instruction names**, which is the number to compare against the alphabetical
lists in A7.7 and A8.8. Advanced SIMD is most of the growth over the figures a
reader may remember from an earlier revision of this file: 146 of the 385 base
names begin with `v`, and 564 of the 817 spelled mnemonics do.

### 4.3 What the denominator does and does not mean

57.69% of the pattern space is not a coverage grade, because most of the 32-bit
space is UNDEFINED *by construction*. Table A5-9 leaves whole `op2` rows
unallocated; `t32_dp_reg` requires `hw2[15:12] == 0b1111` before any decoding
happens at all — a fifteen-sixteenths rejection stated in prose rather than in a
table row (§2.8), which is why its row reads 1.79%; `t32_ldm_stm` refuses every
register list containing `sp`, every *stored* list containing `pc` and every list
of fewer than two registers, and its `SRS`/`RFE` rows — half its first halfwords
— pin `hw2` to one or a handful of values; and most sub-tables allocate a
minority of their opcode cells. A decoder that scored higher here would be
*wrong*.

The useful claim is not the ratio but the **attribution**: every pattern that
does not decode falls under one of the three rules in §4.4, and each module's
tests enumerate its own holes and assert their total as a literal, so a change in
what decodes surfaces as a failing census rather than as a silently larger or
smaller round trip. `t16_misc` lists all 855 of its refusals by construction, as
`768 + 30 + 18 + 2 + 37`; `t32_dp_reg`'s test attributes all 2,176 non-decoding
combinations of its sweep to nine named reasons whose sum is checked against the
total; `t32_coproc`'s accounts for all 516,096 points of its sweep as
285,238 decoded, 85,706 unallocated, one quarter handed to Advanced SIMD and one
thirty-second UNDEFINED.

The 16-bit ratio *is* meaningful, because that space is almost fully allocated:
98.05%, with the 1,159 exceptions named one at a time in §1.3, §1.5 and §1.6.

**No family is absent.** An earlier revision of this section recorded Advanced
SIMD *data processing* — DDI 0406 A7.4, the `VADD.I32` / `VAND` / `VMUL` /
`VSHL` / … grid at `hw1[15:8] == 0b111u_1111` — as implemented inside `t32_simd`
but unreachable through `decode_halfwords`, and claimed that all 33,554,432 of
its patterns decoded to `None`. That was true and is no longer: both coprocessor
arms chain to `t32_simd` when `t32_coproc` declines (§2), 11,817,024 of those
patterns decode, and `isa::tests::advanced_simd_is_reachable_through_the_dispatcher`
pins the chain with a count rather than a spot check. The note is kept rather
than deleted because the failure mode it describes is the interesting one: a
group module can be complete, exhaustively tested against its own tables, and
still contribute nothing to the public decoder, and no test *inside* that module
can see it.

### 4.4 When a module refuses — one policy, stated once

Rather than repeating it in nineteen modules, here it is once. `decode` returns
`None` in exactly three cases:

1. **UNDEFINED.** The table does not allocate the encoding. `None` here means
   "no such instruction", which is the truth. Note that UNDEFINED and
   UNPREDICTABLE are different architectural categories: an UNPREDICTABLE
   encoding *is* allocated, its behaviour merely is not guaranteed, so
   conflating the two would make the decoder claim that, say,
   `and pc, r0, #1` is not an encoding at all. It is one.
2. **A should-be-zero or should-be-one bit holds the wrong value.** A bit an Arm
   encoding diagram draws `(0)` or `(1)` carries no information, and an encoding
   whose value differs there is UNPREDICTABLE (DDI 0403E.e D6.1; DDI 0406 A6.1.1,
   and Appendix I.1 for the diagram convention itself). `Insn` has nowhere to put
   the offending bit, so decoding it would silently discard information and
   re-encode to a *different* pattern. Refusing is what makes `decode` and
   `encode` exact inverses — the crate's whole compliance argument — and that is
   worth more than claiming a handful of encodings whose behaviour the
   architecture declines to define. (LLVM is lenient here and prints `bx r0` for
   `0x4701`; this is a deliberate divergence, not an oversight.)
3. **UNPREDICTABLE with no representable UAL.** An unallocated hint, which has no
   mnemonic at all and whose `opA` would be lost if it were called `nop`; a
   `BFI` whose `<width>` operand would be zero or negative; a `ThumbExpandImm`
   whose *value* the architecture leaves unspecified, so there is no honest
   `Operand::Imm` to emit and reporting `0` would invent a number; an `IT` that
   names `AL` with an `E` arm, which no `IT{x{y{z}}} <firstcond>` spells; an
   empty register list, which no assembler parses as `{}` (§1.5); a *wide*
   register list of one register, whose UAL text reads back as the narrow
   encoding and so does not round-trip (§2.4); a store to `pc`, which
   `Insn::writes_pc` would report as a branch in the one crate whose reason for
   existing is to stop a firmware scan from inventing branches.

And the converse, applied just as uniformly: **an UNPREDICTABLE choice of
operands is decoded.** `and.w r0, sp, r2`, `ldrd r0, r0, [r1]`,
`pop.w {lr, pc}`, `stm.w r0!, {r0, r1}`, `cmp pc, r0`, `bx pc`, `ldr r0, [r0, #-0]`,
`mov pc, sp` — the architecture declines to define what they do, but the encoding
is fully described by an `Insn`, it re-encodes to the bytes it came from, and a
disassembler reading a firmware image is more useful reporting the halfwords that
are there than refusing to. Suppressing them would hide exactly the malformed
code a reverse-engineer is hunting for.

So the line is: *representable, and merely undefined in behaviour* → decode.
*Not representable* → refuse. One rule, which explains cases 2 and 3 both, and
which is why the round trip below is an identity almost everywhere.

### 4.5 The round-trip evidence

Every group module implements an `encode` beside its `decode`, and a round trip
over the whole encoding space is the compliance proof this crate rests on: if an
instruction decodes but does not re-encode to the bytes it came from, one of the
two directions disagrees with the architecture, and the test says so without
anyone hand-writing a vector for it.

Dispatch is *verified*, not trusted. A mnemonic does not identify an encoding
group — `add` lives in five of them — so `isa::encode` has to offer the
instruction to each group in turn, and with a bare `or_else` chain the whole
thing would be only as correct as its least strict member: one group accepting a
neighbour's instruction would silently emit the wrong encoding, and the
neighbour's own tests would still pass, because the collision only shows up
through the shared entry point. So every candidate is decoded again and compared
before it is returned, and a mismatch is discarded so the next group gets a turn.
A greedy group can waste work but cannot produce a wrong answer.

Over the whole space, through the public `isa::encode`:

| | Decoded | Re-encode to themselves | Re-encode to an SBZ twin | Do not re-encode |
|---|---|---|---|---|
| 16-bit | 58,233 | 58,233 | 0 | 0 |
| ThumbEE (re-assigned) | 3,840 | 3,840 | 0 | 0 |
| 32-bit | 232,263,842 | 227,131,554 | 5,132,288 | 0 |

**Nothing fails to re-encode.** All 232,322,075 patterns of §4.2 — plus ThumbEE's
3,840, which re-assign narrow halfwords already counted there — produce an `Insn`
that `isa::encode` turns back into halfwords, and all but 5,132,288 of them are
the halfwords they came from.

Those 5,132,288 are one documented normalisation and nothing else, all of them
in `t32_dp_plainimm`, where the saturate and bitfield rows draw `hw1[10]`,
`hw2[5]` (and, for the `16` forms, `hw2[4]`) as `(0)`: `decode` ignores those
bits because the instruction they denote is still unambiguous, and `encode`
always emits zero, so `encode(decode(x))` is `x` for every canonical encoding and
`x` with those bits cleared otherwise. The census sees exactly seven distinct
difference masks — `hw2` bit 4, bit 5, both; and each of those again with
`hw1` bit 10 — in the counts 8,192 / 1,699,840 / 8,192 / 1,699,840 / 8,192 /
1,699,840 / 8,192.

Two classes that appeared in this table in earlier revisions are gone, and both
are worth naming because their absence is the evidence that the fix landed:

- **The `#-0` twins.** `Mem` carried a signed `i32` offset, in which `-0 == 0`,
  so every `U == 0` encoding with a zero immediate re-encoded to its `U == 1`
  spelling — 28,284 patterns as last measured, with a further 4,992 in the
  `LDC`/`STC` and `VLDR`/`VSTR` rows refused outright rather than
  canonicalised. `Mem` now holds an unsigned magnitude and the `U` bit itself
  (§5.1), so `#0` and `#-0` are distinct values, all 118,208 `#-0` encodings in
  the 32-bit space decode, and every one of them re-encodes to itself.
- **`t32_dp_reg`'s 281,520 failures.** `assemble` placed `Rd` in `hw2[15:12]`,
  the field the group's own first rule requires to be `1111`, where `decode`
  reads it from `hw2[11:8]`; only destinations of `r0` survived the trip. Also
  §5.1. All 300,288 now re-encode exactly.

Two fields are deliberately excluded from the comparison: `addr`, which is
context the bytes do not carry, and `cond`, which can have come from an enclosing
`IT` block rather than from the instruction's own encoding. A conditional
*narrow* instruction is additionally allowed to disagree about flag-setting, and
must be: the 16-bit data-processing encodings specify `setflags = !InITBlock()`,
so `lsleq r0, r1, #2` and `lsls r0, r1, #2` are the *same halfword*, and
requiring them to match would make every conditional narrow instruction
unencodable.

Beyond the sweep, each module asserts its own exhaustive or systematic round trip
with the count pinned as a literal, so the totals above can be checked piecewise.
Those literals are the source of truth: where this document and a module disagree
about a number, the module is right and this file is stale.

| § | Module | Pinned count |
|---|---|---|
| A5.2.1 | `t16_shift` | 16,384 — the whole of `0x0000..=0x3FFF`, no holes |
| A5.2.2 | `t16_dataproc` | 1,024 |
| A5.2.3 | `t16_special` | 736 decoded, 288 refused as 64 + 224 |
| A5.2.4 | `t16_loadstore` | 26,624, at two alignments |
| A5.2.5 | `t16_misc` | 3,241 decoded, 855 refused as 768 + 30 + 18 + 2 + 37 |
| A5.2.6 | `t16_branch` | 10,224 decoded, 16 refused, at four addresses |
| A9.2.1 | `thumbee` | 3,840 decoded, 256 refused, at four addresses; plus 3,840 again through the public `isa::encode` |
| A5.3.1 | `t32_dp_modimm` | 1,309,760 — ten allocated `op` × two `S` × sixteen register pairs × all 4,093 decodable immediates |
| A5.3.5 | `t32_ldm_stm` | 1,292 of 5,632, as 1,216 list forms + 64 `RFE` + 12 `SRS` |
| A5.3.6 | `t32_dual_excl` | 219,264 decoded and 42,880 refused, at two alignments; 1,536 of them `#-0` |
| A5.3.7–9 | `t32_load` | 18,032 decoded and 7,408 refused, at two alignments; 328 `#-0` |
| A5.3.10 | `t32_store` | 31,950 decoded and 29,490 refused; 450 `#-0` |
| A5.3.11 | `t32_dp_shiftreg` | 663,552 of 1,048,576, with the 385,024 refusals attributed per `op` |
| A5.3.12–15 | `t32_dp_reg` | 896 of 3,072, with the 2,176 refusals attributed to nine named reasons |
| A5.3.16 | `t32_multiply` | 918 allocated, 810 UNDEFINED, of 1,728 |
| A5.3.17 | `t32_multiply` | 756 allocated, 6,156 UNDEFINED, of 6,912 |
| A5.3.18 | `t32_coproc` | 285,238 decoded and 85,706 unallocated, of 516,096 |
| A7.7 | `t32_simd` | 3,584 multiple-element + 4,820 single-lane and all-lanes |
| A7.4 | `t32_simd` | 1,485 (A7-9) + 414 (A7-10) + 127 (A7-11) + 20,096 (A7-12) + 828 (A7-13) + 2,508 (A7-14) + 104 `VEXT` + 34 `VTBL`/`VTBX` + 154 `VDUP` + 10 `VMOV (register)` |

---

## 5. Corrections — against the crate, against assumption, against the manual

Everything in this section was found by reading code against the manual text in
`spec/`, and every claim here is checkable by grepping the dumps at the cited
section.

### 5.1 Bugs this audit found in the crate

All are fixed in 0.10.0. The first three shipped in 0.1.0; the rest were
introduced with the encoding groups themselves and never shipped, and are
recorded because the thing that found each of them is the interesting part.

**Shipped in 0.1.0.**

- **`Asm::mov_reg` set the flags.** It emitted `0x1C00 | Rm << 3 | Rd`, which is
  not `MOV` at all: it is `ADD (immediate)` T1 with `imm3 == 0`, i.e.
  `ADDS Rd, Rm, #0`, and N/Z/C/V were written. `MOV (register)` T1
  (`0x4600 | D:Rm << 3 | Rd`, A5.2.3 / A7.7.77) leaves the flags alone and
  reaches the high registers as well. Any trampoline moving a register *between*
  a `CMP` and its `B<cond>` was miscompiled. `mov_reg` now emits T1, and
  `movs_reg` was added for the flag-setting T2 form.
- **`find_bl_sites` missed a `BL` in the last four bytes.** The scan was
  `(0..image.len().saturating_sub(4)).step_by(2)`, exclusive of `len - 4` — the
  final legal site, and exactly where a trailing thunk or an end-of-region
  dispatch table puts one. Now `saturating_sub(3)`, with a regression test
  verified red against the old bound.
- **`lsls_imm(rd, rm, 0)` silently means `movs rd, rm`** (Table A5-2 footnote a,
  A7.7.68). Harmless aliasing, now documented on both emitters.

**Found after 0.1.0, by the sweeps and the LLVM differential.**

- **`t32_dp_reg::assemble` wrote `Rd` to the wrong field.** It built its second
  halfword as `0xF000 | rd << 12 | op2 << 4 | rm`, putting `Rd` in `hw2[15:12]`
  — the field A5.3.12's first rule requires to be `1111` (§2.8) — where `decode`
  correctly reads it from `hw2[11:8]`. The destination was therefore discarded
  and only instructions targeting `r0` re-encoded: 18,768 of 300,288, exactly one
  sixteenth. **The module's own exhaustive sweep could not see it**, because its
  `hw()` test helper repeated the same formula, so the two directions agreed with
  each other and disagreed with the architecture — the precise failure a
  round-trip test is blind to by construction. Only the cross-module sweep
  through the public `isa::encode` (§4.5) caught it, and
  `every_register_field_survives_a_round_trip` now pins the field with a message
  that names it.
- **`Mem::offset` was an `i32`, and `-0 == 0`.** The architecture distinguishes
  `#0` from `#-0` — seventeen places in DDI 0403E.e say so in as many words, and
  A7.7.51 lists `LDRD<c> <Rt>,<Rt2>,[PC,#-0]` as a named special case — but a
  signed offset destroys `U` on decode and has to invent it on re-encode. The
  cost was 28,284 patterns re-encoding to their `U == 1` twin and a further 4,992
  in the `LDC`/`STC` and `VLDR`/`VSTR` rows refused outright to avoid the
  collapse. `Mem` now carries an unsigned magnitude plus `add: bool` — the `U`
  bit itself — with `Mem::displacement()` for the consumer that wants the signed
  value. All 118,208 `#-0` encodings in the 32-bit space now decode and
  re-encode to themselves (24,576 dual, 86,016 `LDC`/`STC`, 3,543 load, 2,048
  `VLDR`/`VSTR`, 2,025 store).
- **`read_hw`, `try_read_u16` and `try_read_u32` overflowed `usize` before the
  bounds check.** All three read `image.get(at..at + n)`, and the addition
  happens before `get` sees it: an `at` within `n` of `usize::MAX` panics in a
  debug build and, in release, wraps to a range that can land back *in bounds*
  and return the wrong bytes. Not hypothetical — the offsets come from scans over
  firmware, a handler pointer read out of erased flash is `0xFFFF_FFFF`, and
  masked even that is `0xFFFF_FFFE`, which is exactly the value that overflows on
  a 32-bit target. `Decoder::skip` saturates, so `usize::MAX` is reachable input
  through the public API. All three now use `checked_add`, and
  `a_truncated_instruction_at_the_end_of_an_image_is_not_decoded` passes
  `usize::MAX` through every entry point.
- **`encode_vldr_vstr` did not bound its operand count.** Only the literal form
  of `VLDR` carries a resolved `Operand::Target`, and no form in that row has a
  fourth operand, but the encoder matched on `operands.get(2)` and said nothing
  about operand 3 — so a literal `VLDR` with a trailing operand re-encoded to the
  halfwords of the three-operand form, dropping the extra silently and claiming
  an exact round trip. The arity is now checked explicitly, as every sibling
  encoder in the group checks it.
- **`t32_simd::encode` assembled an empty mnemonic into UNDEFINED bytes.** The
  module's mnemonic tables are `const` arrays of fully spelled names indexed by
  the raw `size`/`cmode` field, with an **empty string** where Arm's table leaves
  the encoding UNDEFINED. Every encoder searches its table by mnemonic, and a
  plain `position(|&s| s == insn.mnemonic)` matches an empty cell when handed an
  `Insn` whose mnemonic is `""` — returning the encoding of a hole, bytes the
  module's own `decode` refuses to read back. Each search now skips empty cells
  explicitly (`!s.is_empty() && s == insn.mnemonic`), in all six tables.

### 5.2 Corrections against plausible-looking assumptions

Each of these contradicts something a competent implementer would guess, and
each is the kind of mistake that produces code which looks right and is wrong.

- **The 16-bit branch ranges are asymmetric.** A7-206 gives
  "even numbers in the range -256 to 254 for encoding T1, -2048 to 2046 for
  encoding T2, -1048576 to 1048574 for encoding T3, and -16777216 to 16777214
  for encoding T4" — *not* ±254 and ±2046. Two's complement is asymmetric and so
  is the range; a decoder built to the symmetric one rejects a legal `0xD080`.
- **`B` T2 *is* permitted in an IT block**, as the last instruction. A7.7.12's
  encoding-specific pseudocode for T2 and T4 reads
  `if InITBlock() && !LastInITBlock() then UNPREDICTABLE`, and the syntax section
  spells it "Outside or last in IT block". It is `B<cond>` T1 — and `B<cond>.W`
  T3 — that are flatly forbidden (`if InITBlock() then UNPREDICTABLE`,
  "Not permitted in IT block"), because their condition is already in their own
  encoding. A7-206 draws the consequence: "encodings T1 and T2 are never both
  available to the assembler, nor are encodings T3 and T4".
- **`ITAdvance()` shifts `ITSTATE<4:0>`, not the mask alone.** The pseudocode
  (A7.3.2) is

  ```text
  if ITSTATE<2:0> == '000' then ITSTATE.IT = '00000000';
  else                         ITSTATE.IT<4:0> = LSL(ITSTATE.IT<4:0>, 1);
  ```

  Note what that shift spans: `ITSTATE<4>` is the **low bit of the condition**,
  not the top of the mask, so the shift crosses the cond/mask boundary and each
  step pulls `mask<3>` into `cond<0>`. That bit is the `T`/`E` selector — it is
  what makes the else-arms of an `ITE`/`ITTE`/… block run on the *inverted*
  condition. Advancing only the mask looks right, *is* right for an all-`T`
  block, and hands back the un-inverted condition for every `E` arm: a silent and
  consequential wrong answer about control flow. `ItState::advance` is the
  pseudocode line for line.
- **`B<cond>.W` T3 does not pack its immediate like `B.W` T4.** T3 is
  `S:J2:J1:imm6:imm11` with **no I1/I2 inversion** and the J bits in the opposite
  order; T4, `BL` T1 and `BLX` T2 are `S:I1:I2:imm10:imm11` with
  `I1 = NOT(J1 EOR S)`, `I2 = NOT(J2 EOR S)`. The two encodings differ only in
  `hw2[12]`. This is the most commonly mis-implemented thing in Thumb-2, and
  reusing the T4 arithmetic for T3 produces a target that is plausible, wrong,
  and roughly 12 MB away. See §2.1.
- **The unprivileged load/store forms are `P == 1 && U == 1 && W == 0`**, not
  `P == 0 && W == 0`. Every affected page carries both halves of the statement:
  `if P == '1' && U == '1' && W == '0' then SEE LDRT;` and, two lines later,
  `if P == '0' && W == '0' then UNDEFINED;` (A7.7.43, and identically for
  `LDRB`/`LDRH`/`LDRSB`/`LDRSH`/`STR`/`STRB`/`STRH`; DDI 0406 A8.6.x agrees).
  Reading `P == 0 && W == 0` as "unprivileged" — which is what the *ARM*
  instruction set's post-indexed encoding would suggest — decodes an UNDEFINED
  pattern as an instruction. It is also why `LDRT` can only ever add.
- **`PUSH` and `POP` hide in two different tables.** In the load/store *multiple*
  forms, `W:Rn == 11101` is what makes one: A7.7.159 carries
  `if W == '1' && Rn == '1101' then SEE PUSH` and A7.7.41 carries
  `if W == '1' && Rn == '1101' then SEE POP (Thumb)`. In the load/store *single*
  forms, `str rt, [sp, #-4]!` **is** `PUSH` encoding T3 — A7.7.161's
  `if Rn == '1101' && P == '1' && U == '0' && W == '1' && imm8 == '00000100'
  then SEE PUSH` — and `ldr rt, [sp], #4` is `POP` T3 by A7.7.43's mirror image
  (`P == '0' && U == '1' && W == '1'`, same `imm8`). Decoding the multiple forms
  the long way leaves every 32-bit prologue and epilogue in an image legible but
  un-reassemblable, so both are taken; of the single forms only the `PUSH` side
  is, for the reason given in §2.6.
- **`USAT`'s `sat_imm` has no `+1` while `SSAT`'s does.** A7.7.152:
  `saturate_to = UInt(sat_imm)+1`, syntax range 1–32. A7.7.213:
  `saturate_to = UInt(sat_imm)`, syntax range 0–31. Same field, same position,
  one opcode bit apart — `op` is `100x0` for `SSAT` and `110x0` for `USAT`, so
  `op[3]` alone separates them — and `SSAT16`/`USAT16` repeat the asymmetry.
- **The v7 `BL` encoding is bit-identical to the ARMv4T/v5T one throughout the
  older form's whole range** — a correction to an earlier revision of this
  document, which claimed they diverge for backward branches. On v4T/v5T there is
  no J1/J2: `BL` is a pair of 16-bit instructions, `hw1 = 11110 offhi(11)` and
  `hw2 = 11111 offlo(11)`, giving a 22-bit halfword offset and ±4 MB. Within
  ±4 MB, sign extension of `S:I1:I2:imm10:imm11` forces `I1 = I2 = S`, so
  `J1 = NOT(I1) XOR S` and `J2` are **both 1 regardless of sign** — which is
  exactly the `11111` prefix v5 requires — and `S:imm10` is exactly v5's
  `offhi`. The encodings therefore agree everywhere v5 has an encoding at all,
  and diverge only outside ±4 MB, where the v5 form does not exist. A worked
  case: a `BL` at `0x1000` targeting `0x0FF0` is `f7ff fff6` under both rules.

### 5.3 Two apparent errata in the shipped manuals

An erratum claim against Arm's own manual should be made only where the evidence
is unambiguous, and in both cases below the evidence is the same and is the
strongest kind available: the **encoding diagram plus the operation pseudocode**,
which are self-consistent and contradict the summary table. Both are stated
against the text as it extracts in the dumps in `spec/`, so both are checkable
without the PDFs.

**1. Table A5-28 / Table A6-27, the `Ra` column of the `op1 = 111` row
(`USAD8`/`USADA8`).** Every other row of both tables spends `Ra == 1111` on the
*non*-accumulating operation: `not 1111 → MLA`, `1111 → MUL`;
`not 1111 → SMLABB`, `1111 → SMULBB`; and so on. The `op1 = 111` row reverses
it, in both editions:

| Source | `Ra` | Instruction |
|---|---|---|
| DDI 0403E.e Table A5-28 | `1111` | `USADA8` |
| | `not 1111` | `USAD8` |
| DDI 0406 Table A6-27 | `not 1111` | `USAD8` |
| | `1111` | `USADA8` |

The two editions agree with each other (they differ only in which sub-row is
printed first) and both disagree with the encoding diagrams, which are not
ambiguous at all:

```text
USAD8  T1   1 1 1 1 0 1 1 0 1 1 1  Rn  | 1 1 1 1  Rd  0 0 0 0  Rm
USADA8 T1   1 1 1 1 0 1 1 0 1 1 1  Rn  |  Ra      Rd  0 0 0 0  Rm
```

`USAD8` has a literal `1111` where `Ra` sits (A7.7.211), and `USADA8` carries a
real `Ra` field plus `if Ra == '1111' then SEE USAD8;` (A7.7.212). So this row
obeys exactly the same rule as every other: **`Ra == 0b1111` is `USAD8`**, and
`Ra != 0b1111` is `USADA8`. That is what `t32_multiply` implements. The caveat
worth stating: the evidence *against* the tables is a text extraction of a
two-line wrapped table cell, and the evidence *for* the crate's reading is a bit
diagram and a `SEE` directive; the latter is much harder to misread, which is why
the claim is made at all.

**2. DDI 0406's Table A9-2 transposes the ThumbEE frame and array load rows.**
The table's prose column reads:

| `Opcode` | Table A9-2 says | The diagrams say |
|---|---|---|
| `100x` | "Load Register from a frame" | `1100100 imm3 Rn Rt` — **array**, `n = UInt(Rn)`, negative offset |
| `1011` | "Load Register from a literal pool" | `11001011 imm5 Rt` — literal pool, `n = 10` ✔ |
| `110x` | "Load Register (array operations)" | `1100110 imm6 Rt` — **frame**, `n = 9`, positive offset |

A9.5.5's three encodings and their pseudocode are self-consistent and say the
opposite of the table for two of the three rows: E1 is `1100110 imm6 Rt` with
`n = 9` and the prose "R9 as base register … for loading from a frame"; E3 is
`1100100 imm3 Rn Rt` with `n = UInt(Rn)`, `add = FALSE` and "R0-R7 as base
register, with a negative offset … for array operations". The `1011` literal-pool
row and the `111x` store row are both correct. `thumbee` implements the diagrams;
later revisions of the manual correct the table. Anyone checking that file
against that one table will see the transposition, which is why it is recorded
here rather than left to be rediscovered as a bug.

---

## 6. What `Insn` cannot say

These are the honest caveats a consumer should know before building on the
decoded form. None of them is a decoding error; each is a place where the shared
vocabulary in `src/isa/insn.rs` is narrower than the architecture, and where the
cost has been paid deliberately rather than hidden.

- **`Insn` has no channel for "this encoding is UNPREDICTABLE".** A consumer that
  decodes `pop.w {lr, pc}` or `stm.w r0!, {r0, r1}` gets a perfectly ordinary
  `Insn` and no signal that the architecture declines to define what it does.
  This is a deliberate consequence of §4.4's policy — such encodings are decoded
  precisely because they are representable, and a firmware image full of them is
  exactly what a reverse-engineer is looking for — but it means "decoded" must
  not be read as "architecturally well-formed". Adding the flag is a
  backwards-compatible change to `insn.rs`; nothing in the group modules would
  have to move.
- **Immediates print in a mixed hex/decimal dialect, and the two halves of it
  disagree with each other.** `Operand::Imm`'s `Display` prints 0–9 in decimal
  and everything else — including every negative value — in hexadecimal, so
  `add sp, #0x14` and `bkpt #0xab` come out where a listing would more usually
  show `#20` and `#171`. `Mem`'s `Display`, meanwhile, prints its offset in
  plain decimal throughout, so the *same* number is spelled two ways depending
  on whether it sits inside the brackets: `ldrbt r0, [r0, #4]` and
  `add sp, #0x50` are both 0.10.0 output, and the `4` and the `0x50` are the same
  kind of thing. Still true as of 0.10.0, checked against the code rather than
  assumed: `Operand::Imm`'s arm is `< 10` decimal and otherwise `{:#x}`, with
  negatives as `#-0x…`, while `Mem::write`'s is `write!(f, ", #{}", self.offset)`.
  It is unambiguous, it round-trips through this crate, and `docs/CONFORMANCE.md`
  lists it among the formatting differences from LLVM that the assemble-back loop
  makes irrelevant — but it is not what `objdump` or Arm's own syntax examples
  print. Anything parsing the printed form should not rely on the current
  spelling.
- **Some of the mnemonic is doing work no other field can.** `Insn::mnemonic` is
  a `&'static str` and the crate does not allocate, so three things that are
  architecturally *operands or fields* are spelled into the name instead: the
  `T`/`E` letters of an `IT` mask (`itt`, `ite`, `ittte`, …), the data type of a
  floating-point or Advanced SIMD operation (`vadd.f64`, `vld1.32`), and `VSEL`'s
  condition (`vselgt.f32`, because `Display` appends a condition *after* the
  mnemonic and would otherwise print `vsel.f32gt`). That is why there are
  817 distinct mnemonic strings for 385 base instruction names (§4.1 gives the
  collapsing rule), and why `Decoder` tests `mnemonic.starts_with("it")` rather
  than `== "it"`. Advanced SIMD is most of the gap: 564 of the 817 spellings
  begin with `v`, against 146 of the 385 base names.
- **A pc-relative load prints its resolved address as an extra operand.** Still
  true as of 0.10.0: `Insn`'s `Display` joins every operand with `", "`, and the
  only special case it makes for a literal is to force the narrow
  `LDR (literal)` T1's `#0` to print. Every literal form carries an
  `Operand::Target` beside the syntactic `[pc, #±imm]` — deliberately, so that no
  consumer has to redo Thumb's `Align(PC,4)` arithmetic and so `encode` can
  cross-check the two against each other — so `isa::disassemble` of `0x4800` at
  `0x1000` is `ldr r0, [pc, #0], 0x1004`, which no assembler accepts. The same
  applies to `ldr.w` (`ldr.w r0, [pc, #4], 0x1008`), `ldrd`, `vldr` and `ldc`
  literals. `ADR` is the exception: it has a target and no memory operand, so it
  prints clean UAL (`adr r0, 0x1004`). Anything feeding `isa::disassemble`'s
  output back to an assembler must drop the trailing address on a bracketed
  pc-relative form. `docs/CONFORMANCE.md`'s harness does exactly that: its
  `render` skips an `Operand::Target` whenever the instruction also carries a
  `Mem`, which is why the LLVM differential is green on the literal loads and is
  not evidence that this caveat has gone away.
- **Some operands are text, because no structured variant fits.** A base register
  with writeback (`sp!` in `stmdb sp!, {…}`), a floating-point register *range*
  (`{s0-s7}` — encoded as a first register and a count, which `Operand::RegList`'s
  sixteen-bit mask cannot hold), `LDC`'s braced `<option>`, and Advanced SIMD's
  alignment-qualified address (`[r0:64]!` — `Mem` has `base`, `index`, `offset`,
  `mode` and nowhere to put `:64`) are all `Operand::Text`. The printed UAL is
  exactly Arm's and they round-trip; but a consumer matching on `Operand::Reg` to
  find a base register must handle the `Text` case too, or it will silently miss
  every writeback form.
- **`Insn::writes_pc` is a heuristic with two known blind spots.** It reads
  "operand 0 is `pc`" for most mnemonics, having first special-cased the families
  where operand 0 is a *source* (stores, `push`, the comparisons) and the ones
  that carry `pc` in a register list. Two things escape it: `RFE` loads the pc but
  is neither a recognised load-multiple mnemonic nor has a `pc` destination
  operand, so `rfeia r0!` reports `is_branch() == false`; and `t32_store` has to
  refuse `Rt == 1111` outright (§2.6) because the heuristic would otherwise report
  `str pc, [r0]` as a branch.
- **ThumbEE's scaled register-offset loads print without their shift.** In
  ThumbEE state `LDR`/`STR (register)` T1 shift `Rm` left by 2 and
  `LDRH`/`LDRSH`/`STRH` by 1 (A9.1.3, Table A9-1), but A9.4 reprints the halfword
  under "Encoding T1" rather than a new `E<n>` — the difference is in the
  *operation*, not the encoding — so those five forms stay with
  `t16_loadstore` and print `ldr rt, [rn, rm]` where the ThumbEE syntax line
  shows `ldr rt, [rn, rm, lsl #2]`. Claiming `0x5000..=0x5FFF` wholesale to fix a
  printing detail would re-introduce exactly the over-claim `thumbee`'s dispatch
  contract exists to avoid. Likewise ThumbEE's implicit null check on every load,
  store, `PUSH`, `POP`, `TBB` and `TBH` (A9.1.2) changes not one bit of any
  encoding and has nowhere to be recorded.
