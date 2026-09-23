// The divergence allow-list. `include!`d into `tests/conformance.rs`, which
// defines `Divergence` and `Outcome`; it lives in its own file because it is
// as much a document as it is test data, and `docs/CONFORMANCE.md` mirrors it
// entry for entry.
//
// Adding an entry means claiming that LLVM and this crate disagree for a
// reason the architecture justifies. The cost of that claim is the `citation`
// field: name the clause. Every entry also carries a `budget` — the most
// probes it may account for in a single sweep — so an entry cannot quietly
// widen to swallow a regression: if the class grows past its budget the test
// fails and says which entry grew.
//
// The two profile manuals cited throughout:
//   A5.*, A7.*  — ARM DDI 0403E.e, Armv7-M Architecture Reference Manual
//   A6.*, A8.*, B*.*  — ARM DDI 0406B, Armv7-A/R Architecture Reference Manual
//                       (the revision in spec/; it numbers instruction pages
//                       A8.6.x and predates the Virtualization Extensions)

/// Match nothing in `hw2` — the entry is keyed on `hw1` and the outcome alone.
const ANY_HW2: (u16, u16) = (0x0000, 0x0000);

const DIVERGENCES: &[Divergence] = &[
    // -----------------------------------------------------------------------
    // 16-bit space
    // -----------------------------------------------------------------------
    Divergence {
        id: "t16-cmp-reg-t2-both-low",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFFC0,
        hw1: 0x4500,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: Some("cmp"),
        budget: 96,
        citation: "A7.7.28 CMP (register), encoding T2",
        why: "N:Rm and Rn both name a low register, which the encoding declares \
              UNPREDICTABLE because encoding T1 already covers it; LLVM's decoder \
              accepts it anyway.",
    },
    Divergence {
        id: "t16-bx-should-be-zero-bits",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFF80,
        hw1: 0x4700,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: Some("bx"),
        budget: 168,
        citation: "A7.7.20 BX, encoding T1 — bits[2:0] are (0)(0)(0)",
        why: "One or more of BX's three should-be-zero bits is set; this crate \
              refuses the encoding rather than inventing a meaning for the bits, \
              and LLVM's decoder ignores them.",
    },
    Divergence {
        id: "t16-reserved-hint",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFF0F,
        hw1: 0xBF00,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: Some("hint"),
        budget: 24,
        citation: "A5.2.5 Table A5-7 (If-Then and hint instructions), and A7.7.88 \
                   NOP — hint space, opA 0b0101-0b1111",
        why: "A reserved hint. The architecture says it executes as a NOP but gives \
              it no mnemonic, so this crate declines to name it; LLVM prints \
              `hint #n`. Arguably LLVM is more useful here — see CONFORMANCE.md.",
    },
    Divergence {
        id: "t16-it-unpredictable-firstcond",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFFE0,
        hw1: 0xBFE0,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: Some("it"),
        budget: 48,
        citation: "A7.7.38 IT — `if firstcond == '1111' || (firstcond == '1110' && \
                   BitCount(mask) != 1) then UNPREDICTABLE`",
        why: "An IT whose first condition is 0b1111, or is AL while governing more \
              than the one instruction AL may govern. LLVM decodes both.",
    },
    Divergence {
        id: "t16-cps-no-flags",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFFEF,
        hw1: 0xB660,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: Some("cps"),
        budget: 8,
        citation: "A7.7.29 CPS, encoding T1, and B5.2.1 CPS — \
                   `if (I == '0' && F == '0') then UNPREDICTABLE`",
        why: "A CPSIE/CPSID that names no interrupt mask to change. LLVM prints it as \
              `cpsie none`.",
    },
    // `t16-ldr-literal-zero-offset-is-ambiguous` was here: `LDR (literal)` T1
    // printed `ldr r0, [pc]`, dropping the zero offset, and LLVM read that text
    // back as the 32-bit T2 form. `Insn::Display` was fixed to force the `#0`,
    // but the entry had to stay because the harness's `render` built its own
    // text and so never exercised the fix. `render` now delegates to
    // `Insn::Display`, the eight probes round-trip byte-for-byte, and the entry
    // is gone rather than kept as an excuse for a defect that no longer exists.
    // -----------------------------------------------------------------------
    // 32-bit space: this crate enforces UNPREDICTABLE clauses, LLVM's decoder
    // does not. One entry per encoding-space region of Table A5-9, because the
    // clause being enforced is a property of the region's encodings, not of
    // one mnemonic.
    // -----------------------------------------------------------------------
    Divergence {
        id: "t32-ldm-stm-unpredictable-register-list",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFE00,
        hw1: 0xE800,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: None,
        // Raised from 1800 to 3400 in 0.10.0 when the `BitCount(registers) < 2`
        // rejection landed. Before that, a wide `LDM`/`STM` with an empty or
        // single-register list decoded and printed `ldm.w r0, {}` — text no
        // assembler will read back, and inconsistent with this crate rejecting
        // comparable UNPREDICTABLE encodings elsewhere (`BX` with should-be-zero
        // bits set, `CMP` T2 with two low registers). Rejecting them is correct
        // and moves 1272 probes from "agreed" into this class, which is the
        // budget doing its job: the class grew for a named reason rather than
        // silently.
        budget: 6450,
        citation: "A7.7.41 LDM/LDMIA encoding T2, A7.7.159 STM encoding T2, \
                   A7.7.99 POP encoding T2, A7.7.101 PUSH encoding T2 — \
                   `if registers<13> == '1' then UNPREDICTABLE`, and \
                   `if BitCount(registers) < 2 then UNPREDICTABLE`",
        why: "The register list names SP, or names PC and LR together, or holds \
              fewer than two registers. LLVM's decoder prints the list regardless.",
    },
    Divergence {
        id: "t32-dp-shifted-register-unpredictable",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFE00,
        hw1: 0xEA00,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: None,
        budget: 21500,
        citation: "A5.3.11 Data-processing (shifted register), and the per-instruction \
                   clauses A7.7.9 AND, A7.7.4 ADD (register), A7.7.16 BIC (register) … — \
                   `if d == 13 || d == 15 || n == 15 || m == 13 || m == 15 then \
                   UNPREDICTABLE`, plus the `(0)` bit at hw2[15]",
        why: "A register field names PC or SP where the encoding forbids it, or the \
              should-be-zero bit at hw2[15] is set. LLVM's decoder prints `add.w pc, \
              r0, r0` happily; this crate refuses to.",
    },
    Divergence {
        id: "t32-vfp-load-store-multiple-overrun",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFE00,
        hw1: 0xEC00,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: None,
        budget: 1020,
        citation: "A7.7.258 VSTM and A7.7.235 VLDM — `if regs == 0 || regs > 16 || \
                   (VFPSmallRegisterBank() && d+regs > 16) then UNPREDICTABLE`",
        why: "A VFP load/store-multiple whose register list runs off the end of the \
              register bank, or the pre-UAL `FSTMIAX`/`FLDMIAX` odd-length form. LLVM \
              decodes both and prints a list that overruns.",
    },
    Divergence {
        id: "t32-vmsr-vmrs-reserved-system-register",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFE00,
        hw1: 0xEE00,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: None,
        budget: 36,
        citation: "A7.7.247 VMSR and A7.7.246 VMRS — only FPSCR is an architected \
                   destination; and DDI 0406B A8.6.326 VMOV (immediate) with \
                   A7.4.6 Table A7-15 for the Advanced SIMD \
                   modified-immediate `cmode`/`op` combinations",
        why: "A VFP system-register transfer naming a register the architecture does \
              not define as writable (`FPSID` is read-only), or an Advanced SIMD \
              modified immediate whose cmode/op pair has no defined meaning. LLVM \
              names them anyway.",
    },
    Divergence {
        id: "t32-modified-immediate-unpredictable-constant",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFA00,
        hw1: 0xF000,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: None,
        budget: 680,
        citation: "A5.3.2 Modified immediate constants in Thumb instructions — in the \
                   `imm12<11:10> == '00'` rows, `if imm8 == '00000000' then \
                   UNPREDICTABLE`",
        why: "A `ThumbExpandImm` whose replication pattern is selected but whose \
              byte is zero, which the expansion pseudocode calls UNPREDICTABLE. LLVM \
              evaluates it to `#0`.",
    },
    Divergence {
        id: "t32-plain-immediate-unpredictable",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFA00,
        hw1: 0xF200,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: None,
        budget: 380,
        citation: "A7.7.14 BFI — `if msbit < lsbit then UNPREDICTABLE`; B5.2.3 MSR — \
                   `if mask == '00' then UNPREDICTABLE`; A7.7.82 MRS — hw1[3:0] is \
                   SBO `1111`",
        why: "A bitfield insert whose most significant bit is below its least \
              significant bit, an MSR that writes no field, or an MRS/MSR with a \
              should-be-one field wrong. LLVM decodes all three.",
    },
    Divergence {
        id: "t32-branch-misc-smc-hvc",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFFE0,
        hw1: 0xF7E0,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: None,
        budget: 96,
        citation: "DDI 0406B B6.1.9 / A8.6.165 SMC (previously SMI), encoding T1 — \
                   hw2 is twelve (0) bits; A6.3.4 Branch and miscellaneous control, \
                   Table A6-13 (op 000, op1 1111111). HVC is Virtualization \
                   Extensions and is not in the DDI 0406B text under spec/, so \
                   that half rests on DDI 0406C.d B1.6 and is uncorroborated here",
        why: "`SMC`/`HVC` with should-be-zero bits set in hw2, and `HVC` itself, which \
              belongs to the Virtualization Extensions this crate does not decode. \
              LLVM decodes them under `.arch_extension sec`/`virt`.",
    },
    Divergence {
        id: "t32-load-store-single-rt-is-pc",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFE00,
        hw1: 0xF800,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: None,
        budget: 7000,
        citation: "A7.7.163 STRB (immediate) — `if t IN {13,15} then \
                   UNPREDICTABLE`; A7.7.46 LDRB, A7.7.59 LDRSB (immediate), \
                   A7.7.63 LDRSH and the \
                   unprivileged `…T` forms carry the same clause",
        why: "A byte, halfword or unprivileged transfer whose transfer register is PC \
              or SP, which no such encoding permits. LLVM's decoder prints \
              `strb pc, [r0]`.",
    },
    Divergence {
        id: "t32-dp-register-pc-operand",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFE00,
        hw1: 0xFA00,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: None,
        budget: 2100,
        citation: "A7.7.181 SXTAH, A7.7.220 UXTAH, A7.7.127 SDIV, A7.7.195 UDIV and \
                   the rest of A5.3.12 Data-processing (register) — \
                   `if d == 13 || d == 15 || n == 13 || n == 15 || m == 13 || m == 15 \
                   then UNPREDICTABLE`",
        why: "An extend, reverse, shift or divide naming PC or SP. LLVM decodes it.",
    },
    Divergence {
        id: "t32-ldc-stc-vfp-coprocessor-space",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFE00,
        hw1: 0xFC00,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: None,
        budget: 340,
        citation: "DDI 0406B A8.6.51 LDC/LDC2 (immediate) and A8.6.184 STC/STC2 — \
                   `if coproc == '101x' then SEE \
                   Advanced SIMD and Floating-point`",
        why: "An `LDC2`/`STC2` naming coprocessor 10 or 11, which the architecture \
              reserves for the Advanced SIMD and floating-point instruction space \
              rather than for generic coprocessor transfers. LLVM prints \
              `stc2l p10, …`.",
    },
    Divergence {
        id: "t32-adr-minus-zero",
        outcome: Outcome::ByteMismatch,
        hw1_mask: 0xFFFF,
        hw1: 0xF2AF,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: Some("adr"),
        llvm_prefix: None,
        budget: 8,
        citation: "A7.7.7 ADR, encodings T2 (subtract) and T3 (add)",
        why: "`ADR` with a zero offset: the subtracting T2 and the adding T3 encodings \
              name the same address, and no text can say which of the two it came \
              from, so re-assembly picks the other one.",
    },
    Divergence {
        id: "t32-adr-minus-zero-rejected",
        outcome: Outcome::LlvmRejectsOurText,
        hw1_mask: 0xFFFF,
        hw1: 0xF2AF,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: Some("adr"),
        llvm_prefix: None,
        budget: 4,
        citation: "A7.7.7 ADR, encodings T2 and T3",
        why: "As `t32-adr-minus-zero`, in the cases where LLVM's assembler declines \
              the `adr.w rd, #0` spelling outright rather than choosing an encoding.",
    },
    Divergence {
        id: "t32-vfp-immediate-printed-as-an-integer",
        outcome: Outcome::LlvmRejectsOurText,
        hw1_mask: 0xFE00,
        hw1: 0xEE00,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: None,
        budget: 48,
        citation: "A7.7.239 VMOV (immediate) — VFPExpandImm, and A6.4.1 Operation of \
                   modified immediate constants in floating-point instructions, its \
                   decimal-literal syntax",
        why: "A VFP immediate whose value happens to be integral (`5.0`, `-20.0`) is \
              printed `#5`, and LLVM's assembler will only read a floating-point \
              literal there. A printer nit, not a decode error; see CONFORMANCE.md.",
    },
    Divergence {
        id: "t32-saturate-bitfield-destination-is-pc",
        outcome: Outcome::LlvmSilent,
        hw1_mask: 0xFA00,
        hw1: 0xF200,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: None,
        budget: 5330,
        citation: "A7.7.152 SSAT, A7.7.213 USAT, A7.7.153 SSAT16, A7.7.214 USAT16, \
                   A7.7.14 BFI, A7.7.13 BFC — `if d IN {13,15} || n IN {13,15} then \
                   UNPREDICTABLE`",
        why: "A saturate or bitfield instruction whose destination is PC or SP. This \
              crate decodes it; LLVM neither writes it nor reads it, so there is no \
              second opinion to compare against.",
    },
    Divergence {
        id: "t32-simd-table-lookup-list-overrun",
        outcome: Outcome::WeRejectLlvmDecodes,
        hw1_mask: 0xFF00,
        hw1: 0xFF00,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: Some("vtb"),
        budget: 14,
        citation: "DDI 0406B A8.6.406 VTBL/VTBX — `if n+length > 32 then \
                   UNPREDICTABLE`",
        why: "A table lookup whose list of table registers runs past `d31`. LLVM \
              decodes it and prints names off the end of its own register table \
              (`{d30, d31, fpinst2, mvfr0}`), which is a fair illustration of why this \
              crate refuses the encoding.",
    },
    Divergence {
        id: "t32-simd-immediate-printed-as-an-integer",
        outcome: Outcome::LlvmRejectsOurText,
        hw1_mask: 0xFE00,
        hw1: 0xFE00,
        hw2_mask: ANY_HW2.0,
        hw2: ANY_HW2.1,
        mnemonic: None,
        llvm_prefix: None,
        budget: 200,
        citation: "DDI 0406B A8.6.326 VMOV (immediate), encoding T1 — AdvSIMDExpandImm \
                   with cmode 0b1111, and A7.4.6 Table A7-15 (op 0, cmode 0b1111 \
                   selects F32)",
        why: "An Advanced SIMD floating-point immediate whose value is integral is \
              printed `#-19` rather than `#-19.0`, and LLVM's assembler will only read a \
              floating-point literal there. The same printer nit as \
              `t32-vfp-immediate-printed-as-an-integer`, in the SIMD half of the space.",
    },
];
