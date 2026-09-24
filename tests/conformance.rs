//! Conformance against an implementation nobody here wrote.
//!
//! Every encoding group in this crate is already covered by a decode/encode
//! round trip. That proves self-consistency and nothing else: a systematic
//! misreading of the architecture reference manual round-trips perfectly and
//! is still wrong. This file supplies the missing half — corroboration by
//! LLVM, which is the most widely deployed independent implementation of the
//! Thumb encodings there is.
//!
//! # The loop, and why it is this loop
//!
//! ```text
//!     bytes  ->  our decoder  ->  our UAL text  ->  LLVM assembler  ->  bytes'
//!     assert bytes' == bytes
//! ```
//!
//! The obvious alternative — disassemble with both and `assert_eq!` the two
//! strings — does not work and is not worth making work. LLVM prints branch
//! and `adr` operands as pc-relative *offsets* where this crate prints
//! resolved *addresses*; LLVM writes `#0x1f`, this crate writes `#0x1f` in
//! some places and `#31` in others; `.w` placement, register-list spelling and
//! shift spelling all differ. Every one of those is a formatting disagreement
//! with no bearing on whether the bytes were understood. Comparing text means
//! drowning the signal in dialect noise and then suppressing the noise with
//! normalisation rules that quietly become the place bugs hide.
//!
//! Closing the loop through LLVM's *assembler* deletes the entire problem.
//! Formatting cancels: whatever we print, if LLVM reads it back as the same
//! instruction, the bytes come out identical. What is left is exactly the
//! question worth asking — **does our disassembly mean what the bytes mean,
//! according to an implementation that shares no code and no author with
//! this one?** A byte-level disagreement is a real defect in one of the two.
//!
//! One translation is unavoidable and is made explicitly here rather than
//! hidden: LLVM spells a branch or `adr` destination as an offset from `PC`,
//! so an [`Operand::Target`] is rendered as `#(target - 4)`. Every probe is
//! decoded at address 0, and in Thumb `PC` reads as the instruction's address
//! plus four (ARM DDI 0403E.e A5.1.2, "Use of 0b1111 as a register
//! specifier"), so the bias is the constant 4. That is the only piece of
//! architectural arithmetic this harness performs; everything else is bytes.
//!
//! # The reverse direction
//!
//! Where an `llvm-objdump` is available the harness also asks LLVM's
//! *decoder* about every probe this crate rejects. That fills in the one
//! category the forward loop cannot see: a byte pattern LLVM understands and
//! we do not. It stops at a census — this crate has no assembler that parses
//! text, so LLVM's disassembly cannot be fed back in — and the census is the
//! useful part anyway.
//!
//! # Running it
//!
//! ```text
//! cargo test --test conformance -- --nocapture
//! ```
//!
//! `--nocapture` matters: the summary tables, the toolchain banner and the
//! skip message are all printed, and libtest swallows stdout without it.
//! With no LLVM on the machine the test **skips and passes** — a contributor
//! who has not installed LLVM must still get a green `cargo test`.
//!
//! See `docs/CONFORMANCE.md` for the divergence table in readable form and an
//! honest account of what fraction of the encoding space this corroborates.

mod support;

use std::collections::BTreeMap;
use std::fmt::Write as _;

use support::{
    assemble, find_assembler, find_objdump, raw_disassemble, Asm, Assembled, Objdump, Scratch,
};
use thumb_asm::isa::{decode_halfwords, insn_len, Insn, Operand, Target};
use thumb_asm::Cond;

// ---------------------------------------------------------------------------
// Dialects
// ---------------------------------------------------------------------------

/// One `(.arch, .fpu)` configuration to ask LLVM about.
///
/// No single ARM variant covers the encoding space this crate decodes: the
/// M-profile special registers (`PRIMASK`, `BASEPRI`) do not exist for an
/// A-profile assembler, and Advanced SIMD does not exist for an M-profile
/// one. A probe is counted as corroborated if **any** dialect round-trips it,
/// which is the right rule — the question is whether some real ARM
/// implementation agrees that these bytes mean this, not whether one
/// arbitrarily chosen profile does.
struct Dialect {
    name: &'static str,
    /// Directives injected at the top of every generated `.s` file.
    prologue: &'static str,
    /// The matching `--triple`/`--mcpu` for `llvm-objdump`.
    triple: &'static str,
    cpu: &'static str,
    /// Whether to ask this dialect's *decoder* about patterns we reject.
    ///
    /// The forward direction wants every dialect: an instruction this crate
    /// decodes should round-trip through whichever profile actually defines
    /// it. The reverse census wants only the profiles this crate claims to
    /// implement — Armv7-A/R and Armv7-M. Asking an Armv8 decoder "what byte
    /// patterns do you know that thumb-asm rejects?" answers "the Armv8
    /// ones", which is true, uninteresting, and would bury the Armv7 gaps
    /// that are the point of the exercise.
    reverse: bool,
}

const DIALECTS: &[Dialect] = &[
    Dialect {
        name: "armv7-a +idiv +sec +virt, neon-vfpv4",
        prologue: concat!(
            "\t.syntax unified\n",
            "\t.arch armv7-a\n",
            "\t.arch_extension idiv\n",
            "\t.arch_extension sec\n",
            "\t.arch_extension virt\n",
            "\t.arch_extension mp\n",
            "\t.fpu neon-vfpv4\n",
            "\t.text\n",
            // `.thumb` comes last, after every `.arch`/`.fpu` directive.
            // `.arch` resets the assembler to Arm state, so a `.thumb`
            // written above it is undone and the whole file assembles as
            // 32-bit Arm instructions. LLVM 23 happens not to do this and
            // LLVM 18 does, which is why it survived local runs and only
            // appeared in CI: the byte round-trip fell from 98% to 0.36%,
            // with the disassembler still agreeing because it was reading
            // the original probe bytes rather than the assembled ones.
            "\t.thumb\n",
        ),
        triple: "thumbv7a-none-eabi",
        cpu: "cortex-a15",
        reverse: true,
    },
    Dialect {
        name: "armv7e-m, fpv5-d16",
        prologue: concat!(
            "\t.syntax unified\n",
            "\t.arch armv7e-m\n",
            "\t.fpu fpv5-d16\n",
            "\t.text\n",
            // `.thumb` comes last, after every `.arch`/`.fpu` directive.
            // `.arch` resets the assembler to Arm state, so a `.thumb`
            // written above it is undone and the whole file assembles as
            // 32-bit Arm instructions. LLVM 23 happens not to do this and
            // LLVM 18 does, which is why it survived local runs and only
            // appeared in CI: the byte round-trip fell from 98% to 0.36%,
            // with the disassembler still agreeing because it was reading
            // the original probe bytes rather than the assembled ones.
            "\t.thumb\n",
        ),
        triple: "thumbv7em-none-eabi",
        cpu: "cortex-m7",
        reverse: true,
    },
    Dialect {
        // Armv8-A is not redundant with Armv7-A: `VSEL`, `VMAXNM`/`VMINNM`
        // and the `VRINT` family exist only from v8, and only an FPU with
        // thirty-two double registers can name `d16`-`d31`.
        name: "armv8-a +idiv +sec +virt +mp +crc, neon-fp-armv8",
        prologue: concat!(
            "\t.syntax unified\n",
            "\t.arch armv8-a\n",
            "\t.arch_extension idiv\n",
            "\t.arch_extension sec\n",
            "\t.arch_extension virt\n",
            "\t.arch_extension mp\n",
            "\t.arch_extension crc\n",
            "\t.fpu neon-fp-armv8\n",
            "\t.text\n",
            // `.thumb` comes last, after every `.arch`/`.fpu` directive.
            // `.arch` resets the assembler to Arm state, so a `.thumb`
            // written above it is undone and the whole file assembles as
            // 32-bit Arm instructions. LLVM 23 happens not to do this and
            // LLVM 18 does, which is why it survived local runs and only
            // appeared in CI: the byte round-trip fell from 98% to 0.36%,
            // with the disassembler still agreeing because it was reading
            // the original probe bytes rather than the assembled ones.
            "\t.thumb\n",
        ),
        triple: "thumbv8a-none-eabi",
        cpu: "cortex-a53",
        reverse: false,
    },
];

/// Bytes reserved per probe in the generated object.
///
/// Sixteen, not four, for two reasons. A probe may assemble to more bytes
/// than it decoded from — that is one of the failures being looked for — and
/// a fixed stride keeps every later probe's offset correct when it happens.
/// And an `IT` instruction has to be followed by the conditional instructions
/// it governs or LLVM refuses the *next* probe, so an `IT` slot holds up to
/// five instructions.
const SLOT: usize = 16;

/// Written immediately after each probe. Its position reveals the length LLVM
/// gave the instruction, which is checked as strictly as the bytes: a probe
/// that decodes to two bytes and re-assembles to four has not round-tripped
/// even if the first two bytes match.
const SENTINEL: u8 = 0xAA;

/// Probes per assembler invocation. Batching is what makes this finish in
/// seconds: one `clang` process assembles sixteen thousand instructions in
/// about a tenth of a second, and sixteen thousand processes would take
/// twenty minutes.
const CHUNK: usize = 16384;

// ---------------------------------------------------------------------------
// Rendering our decode as something LLVM will read
// ---------------------------------------------------------------------------

/// Thumb's `PC` bias: `PC` reads as the instruction's address plus four
/// (ARM DDI 0403E.e A5.1.2). Every probe is decoded at address 0, so a
/// resolved target `T` is `T - 4` bytes from `PC`, which is the number LLVM's
/// assembler wants for a branch or `adr`.
const PC_BIAS: u32 = 4;

/// What we hand the assembler for one probe.
#[derive(Clone)]
struct Body {
    /// Assembly source lines, without the leading tab.
    lines: Vec<String>,
    /// How many bytes the instruction must occupy, when that is checkable.
    /// `None` for an `IT`, whose slot also holds the block it governs.
    expect_len: Option<usize>,
}

/// Render a decoded instruction as UAL text LLVM can assemble.
///
/// This is `Insn`'s own `Display` with exactly one substitution: an
/// [`Operand::Target`] becomes LLVM's pc-relative immediate. Nothing else is
/// normalised, adjusted or worked around — if LLVM will not read what this
/// crate prints, that is a finding, not something for the harness to paper
/// over.
fn render(insn: &Insn) -> Body {
    // Start from the printer the crate actually ships. Building the text here
    // instead would mean the sweeps corroborate a second printer that exists
    // only in the test suite, and any defect in `Insn::Display` — the one
    // every consumer sees — would be invisible to the whole harness. That is
    // not hypothetical: `Display` carries a rule forcing `LDR (literal)` T1 to
    // print `[pc, #0]` rather than the ambiguous `[pc]`, and while this
    // function had its own copy of the formatting the rule was absent here and
    // the divergence stayed on the allow-list.
    let shipped = insn.to_string();

    // The one substitution. `Operand::Target` is the resolved *absolute*
    // address, which is this crate's output and not assembler input: LLVM
    // wants a pc-relative immediate. Where the instruction also has a `Mem`,
    // the target is the address of a literal-pool word rather than a
    // destination and is not part of the syntax at all, so it is dropped.
    let target = insn
        .operands
        .as_slice()
        .position(|o| matches!(o, Operand::Target(_)));
    let text = match target {
        None => shipped,
        Some(i) => {
            assert_eq!(
                i,
                insn.operands.len() - 1,
                "`{shipped}` puts its Target at operand {i} of {}; this \
                 substitution rewrites the last operand and assumes it is that \
                 one",
                insn.operands.len()
            );
            let t = match insn.operands.as_slice().nth(i) {
                Some(Operand::Target(t)) => t,
                _ => unreachable!("position() just matched Target"),
            };
            // Cut the last operand off the shipped text. With more than one
            // operand the separator is the final `", "` — which is after any
            // `", "` inside a `Mem`'s brackets, because the target prints last.
            let cut = if insn.operands.len() > 1 {
                shipped.rfind(", ").map(|n| (n, n + 2))
            } else {
                shipped.find(' ').map(|n| (n, n + 1))
            };
            let (head_end, _) = cut.unwrap_or((shipped.len(), shipped.len()));
            let head = &shipped[..head_end];
            let has_mem = insn
                .operands
                .as_slice()
                .any(|o| matches!(o, Operand::Mem(_)));
            if has_mem {
                head.to_string()
            } else if insn.operands.len() > 1 {
                format!("{head}, #{}", t.wrapping_sub(PC_BIAS) as i32)
            } else {
                format!("{head} #{}", t.wrapping_sub(PC_BIAS) as i32)
            }
        }
    };

    match it_block(insn) {
        Some(conds) => {
            let mut lines = vec![text];
            for c in conds {
                // `AL` has an empty UAL suffix, and LLVM's assembler reads a
                // bare `nop` inside an IT block as unpredicated and rejects
                // it. The explicit `nopal` spelling is what it wants.
                let suffix = if c == Cond::Al { "al" } else { c.suffix() };
                lines.push(format!("nop{suffix}"));
            }
            Body {
                lines,
                expect_len: None,
            }
        }
        None => Body {
            lines: vec![text],
            expect_len: Some(insn.len()),
        },
    }
}

/// A condition from its UAL suffix. `al` is spelled out, which
/// `Cond::suffix()` never produces (it renders `AL` as the empty string).
fn cond_from_suffix(s: &str) -> Option<Cond> {
    if s == "al" {
        return Some(Cond::Al);
    }
    (0..14)
        .filter_map(Cond::from_bits)
        .find(|c| c.suffix() == s)
}

/// The conditions of the instructions an `IT` governs, if this is one.
///
/// LLVM's assembler enforces the architecture's rule that the instructions
/// inside an `IT` block carry the matching condition (ARM DDI 0403E.e
/// A7.7.38), and it enforces it against the *next* instruction in the file.
/// Emitting an `IT` on its own therefore poisons the following probe, so each
/// `IT` is followed here by the exact conditional `NOP`s its mask calls for.
///
/// The mnemonic spells the block out: `it` governs one instruction, `itte`
/// three, of which the third takes the inverted condition.
fn it_block(insn: &Insn) -> Option<Vec<Cond>> {
    let m = insn.mnemonic;
    if !m.starts_with("it") || m.len() < 2 || !m[1..].bytes().all(|b| b == b't' || b == b'e') {
        return None;
    }
    // `IT`'s `<firstcond>` is an operand, not a mnemonic suffix (A7.7.38),
    // and this crate spells the always-condition out as the literal `al`
    // because Table A7-1's "AL may be omitted" footnote explicitly excepts
    // `IT`. So the condition can arrive three ways.
    let base = insn.cond.or_else(|| {
        insn.operands.as_slice().find_map(|o| match o {
            Operand::Cond(c) => Some(c),
            Operand::Text(t) => cond_from_suffix(t),
            _ => None,
        })
    })?;
    let mut conds = vec![base];
    for c in m.bytes().skip(2) {
        conds.push(if c == b'e' { base.invert() } else { base });
    }
    Some(conds)
}

// ---------------------------------------------------------------------------
// The fallback: does LLVM's *decoder* read these bytes the way we do?
// ---------------------------------------------------------------------------

/// Compare our disassembly with LLVM's, structurally rather than literally.
///
/// This is the one place text is compared, and it is used **only where the
/// byte loop cannot close** — never as the primary check. It exists because
/// a large, entirely expected slice of the encoding space cannot round-trip
/// through any assembler: the architecture marks an encoding UNPREDICTABLE
/// (`STRD pc, sp, [r0]`, `LDM r0!, {r0}`), LLVM's disassembler will happily
/// read it, and LLVM's assembler then refuses to write it back. Reporting
/// those as unexplained would bury the real findings under fourteen thousand
/// non-events.
///
/// The comparison deliberately ignores everything that is dialect and keeps
/// everything that is meaning: the mnemonic with any width suffix removed,
/// the register operands in order (with our collapsed `r0-r3` runs expanded
/// to match LLVM's enumerated lists), and the immediates in order *by value*,
/// so `#1020` and `#0x3fc` are the same number. If those all agree, the two
/// implementations read the same instruction out of the same bytes. If any
/// of them disagrees the case stays a divergence and has to be explained.
fn same_instruction(ours: &str, theirs: &str) -> bool {
    let theirs = strip_annotations(theirs);
    mnemonic_of(ours) == mnemonic_of(&theirs)
        && registers_of(ours) == registers_of(&theirs)
        && immediates_of(ours) == immediates_of(&theirs)
        && shape_of(ours) == shape_of(&theirs)
}

/// The parts of an operand list that are neither a register nor an immediate:
/// the shift keyword, and the punctuation that spells the addressing mode.
///
/// Without this, the comparison sees `lsl` and `asr` as the same instruction on
/// the same registers with the same immediate — they differ only in a word it
/// was not reading — and likewise `[r0, r1]`, `[r0, r1]!` and `[r0], r1`, which
/// are an offset load, a pre-indexed load with writeback, and a post-indexed
/// one. All three write different things to different places. This is the
/// weaker of the two corroboration paths, taken when LLVM's assembler will not
/// read our text back, so it is the only check those encodings get.
fn shape_of(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut first = true;
    // Registers *inside* a `{…}` list are not recorded. This crate prints a run
    // of them as a range (`{r0-r12, lr, pc}`) and LLVM writes each one out, so
    // counting markers there would compare spellings rather than structure —
    // and a register list has no addressing mode to get wrong. Which registers
    // the list holds is `registers_of`'s job, and it expands ranges.
    let mut in_list = 0i32;
    let flush = |w: &mut String, out: &mut Vec<String>, first: &mut bool, in_list: i32| {
        if *first {
            // The leading token is the mnemonic, compared separately.
            *first = false;
        } else if matches!(w.as_str(), "lsl" | "lsr" | "asr" | "ror" | "rrx") {
            out.push(w.clone());
        } else if in_list == 0 && register_name(w).is_some() {
            // Which register it is, `registers_of` already says; what matters
            // here is only where it sits relative to the brackets.
            out.push("r".to_string());
        }
        w.clear();
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            word.push(c.to_ascii_lowercase());
            continue;
        }
        flush(&mut word, &mut out, &mut first, in_list);
        match c {
            '{' => in_list += 1,
            '}' => in_list -= 1,
            _ => {}
        }
        // `#` is here for its *position*: `[r1, #4]` and `[r1], #4` hold the
        // same register and the same immediate and are an offset load and a
        // post-indexed one. `,` alone adds nothing the ordering does not.
        if matches!(c, '[' | ']' | '{' | '}' | '!' | '^' | '#') {
            out.push(c.to_string());
        }
    }
    flush(&mut word, &mut out, &mut first, in_list);
    out
}

/// Drop `llvm-objdump`'s trailing `<symbol+off>` and `@ comment` decorations.
fn strip_annotations(text: &str) -> String {
    let mut out = text;
    if let Some(i) = out.find('@') {
        out = &out[..i];
    }
    if let Some(i) = out.find('<') {
        out = &out[..i];
    }
    out.trim().to_string()
}

/// The mnemonic, without the `.w`/`.n` width suffix — which is exactly the
/// thing the two spell differently and exactly the thing the byte comparison
/// already settled wherever it could.
fn mnemonic_of(text: &str) -> String {
    let head = text.split_whitespace().next().unwrap_or("");
    let head = head.strip_suffix(".w").unwrap_or(head);
    head.strip_suffix(".n").unwrap_or(head).to_lowercase()
}

/// The register operands in syntactic order.
///
/// A range in a register list (`{r4-r11}`, which this crate prints and LLVM
/// does not) is expanded, so the two spellings of the same list compare
/// equal.
fn registers_of(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
        if raw.is_empty() {
            continue;
        }
        match raw.split_once('-') {
            Some((lo, hi)) => match (reg_number(lo), reg_number(hi)) {
                (Some((k, a)), Some((k2, b))) if k == k2 && a <= b => {
                    for n in a..=b {
                        out.push(format!("{k}{n}"));
                    }
                }
                _ => {
                    if let Some(r) = register_name(raw) {
                        out.push(r);
                    }
                }
            },
            None => {
                if let Some(r) = register_name(raw) {
                    out.push(r);
                }
            }
        }
    }
    out
}

/// A register token in canonical form: `sp`/`lr`/`pc` become `r13`/`r14`/`r15`
/// so the two spellings of the same register compare equal.
fn register_name(token: &str) -> Option<String> {
    match token {
        "sp" => return Some("r13".to_string()),
        "lr" => return Some("r14".to_string()),
        "pc" => return Some("r15".to_string()),
        _ => {}
    }
    reg_number(token).map(|(k, n)| format!("{k}{n}"))
}

/// Split a register token into its bank letter and number, for the banks
/// where a range is meaningful.
fn reg_number(token: &str) -> Option<(char, u8)> {
    let mut chars = token.chars();
    let bank = chars.next()?;
    if !matches!(bank, 'r' | 's' | 'd' | 'q') {
        return None;
    }
    let rest: String = chars.collect();
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    rest.parse::<u8>().ok().map(|n| (bank, n))
}

/// Every `#`-introduced immediate, by value, so `#1020` and `#0x3fc` match
/// and `#-4` and `#-0x4` match.
fn immediates_of(text: &str) -> Vec<i64> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'#' {
            i += 1;
            continue;
        }
        i += 1;
        let negative = i < bytes.len() && bytes[i] == b'-';
        if negative {
            i += 1;
        }
        let start = i;
        let radix = if bytes[i..].starts_with(b"0x") || bytes[i..].starts_with(b"0X") {
            i += 2;
            16
        } else {
            10
        };
        let digits_start = i;
        while i < bytes.len() && (bytes[i] as char).is_digit(radix) {
            i += 1;
        }
        if i == digits_start {
            continue;
        }
        // A floating-point immediate (`#1.5`) is compared as text, since the
        // two print it very differently and it is not an integer field.
        if i < bytes.len() && bytes[i] == b'.' {
            let _ = start;
            out.push(i64::MIN); // marker: unequal to any parsed integer
            continue;
        }
        if let Ok(v) = i64::from_str_radix(&text[digits_start..i], radix) {
            out.push(if negative { -v } else { v });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Outcome {
    /// We decode it, and LLVM re-assembles our text to the identical bytes.
    /// The strong result: byte-for-byte corroboration.
    Agreed,
    /// The byte loop could not close — LLVM's assembler would not take our
    /// text back, or took it back as different bytes — but LLVM's *decoder*
    /// reads the same bytes as the same mnemonic, on the same registers, with
    /// the same immediates. Corroboration, one notch weaker: it confirms the
    /// meaning without confirming that every bit was accounted for. Almost
    /// all of it is the architecture's own doing — LLVM's assembler refuses
    /// to emit instructions the manual calls UNPREDICTABLE, so an encoding
    /// that names `pc` where `pc` is forbidden can be read but not written.
    AgreedViaDisassembly,
    /// Neither implementation claims it is an instruction.
    BothReject,
    /// We decode it; LLVM will not assemble what we printed.
    LlvmRejectsOurText,
    /// LLVM decodes it; we return `None`.
    WeRejectLlvmDecodes,
    /// We decode it, LLVM assembles our text — to different bytes.
    ByteMismatch,
    /// We decode it, LLVM rejects both directions. Interesting but weak:
    /// LLVM has no opinion to disagree with.
    LlvmSilent,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Outcome::Agreed => "agreed (bytes round-trip)",
            Outcome::AgreedViaDisassembly => "agreed (LLVM's decoder, not re-assemblable)",
            Outcome::BothReject => "both reject",
            Outcome::LlvmRejectsOurText => "we decode, LLVM rejects our text",
            Outcome::WeRejectLlvmDecodes => "LLVM decodes, we reject",
            Outcome::ByteMismatch => "byte mismatch",
            Outcome::LlvmSilent => "we decode, LLVM has no encoding",
        }
    }

    /// Whether this outcome needs an entry in [`DIVERGENCES`] to be allowed.
    fn is_divergence(self) -> bool {
        !matches!(
            self,
            Outcome::Agreed | Outcome::AgreedViaDisassembly | Outcome::BothReject
        )
    }
}

/// One probe and everything learned about it.
struct Finding {
    hw1: u16,
    hw2: u16,
    outcome: Outcome,
    /// What we printed, if we decoded it.
    ours: Option<String>,
    /// The mnemonic we decoded, for divergence matching.
    mnemonic: Option<&'static str>,
    /// LLVM's complaint, or its disassembly, whichever applies.
    llvm: String,
}

// ---------------------------------------------------------------------------
// The divergence allow-list
// ---------------------------------------------------------------------------

/// A knowingly-accepted disagreement with LLVM.
///
/// LLVM is not the specification. It is deliberately lenient in places the
/// architecture calls UNPREDICTABLE, it implements profiles and extensions
/// selectively, and its assembler has syntax preferences of its own. Every
/// such case is listed here with the clause it turns on, and **anything not
/// listed fails the test**. That is what keeps the list honest: it cannot
/// quietly grow to cover a real bug, because adding an entry means writing
/// down the citation that justifies it.
struct Divergence {
    id: &'static str,
    outcome: Outcome,
    hw1_mask: u16,
    hw1: u16,
    hw2_mask: u16,
    hw2: u16,
    /// Optional extra filter on the mnemonic we decoded.
    mnemonic: Option<&'static str>,
    /// The most probes this entry may account for in a single sweep.
    ///
    /// The allow-list's weakness is that an entry keyed on an encoding-space
    /// region is broad, and a broad entry could absorb a genuine regression
    /// without anyone noticing. The budget closes that: each class is also
    /// asserted to be no *larger* than it was when it was written down, with
    /// headroom for a different LLVM version having slightly different
    /// opinions. A class that grows has to be looked at.
    budget: usize,
    /// Optional filter on what LLVM said — the start of its disassembly, or
    /// of its assembler's complaint. Keeps an entry from quietly widening:
    /// "LLVM decodes `0x4500`-ish as *`cmp`*" is a much narrower claim than
    /// "something happens in that range".
    llvm_prefix: Option<&'static str>,
    citation: &'static str,
    why: &'static str,
}

impl Divergence {
    fn matches(&self, f: &Finding) -> bool {
        self.outcome == f.outcome
            && f.hw1 & self.hw1_mask == self.hw1
            && f.hw2 & self.hw2_mask == self.hw2
            && match self.mnemonic {
                Some(m) => f.mnemonic == Some(m),
                None => true,
            }
            && match self.llvm_prefix {
                Some(p) => f.llvm.starts_with(p),
                None => true,
            }
    }
}

include!("support/divergences.rs");

// ---------------------------------------------------------------------------
// Driving the assembler
// ---------------------------------------------------------------------------

/// What one slot came back as.
enum Slot {
    /// The probe was not offered (we do not decode it).
    Absent,
    /// LLVM assembled it; here are the slot's sixteen bytes.
    Bytes(Vec<u8>),
    /// LLVM refused the text, with this message.
    Refused(String),
}

/// Assemble one chunk of bodies, retrying without the lines LLVM refuses.
///
/// The retry is what makes a batch of sixteen thousand probes survive the
/// several thousand of them LLVM will not accept. `llvm-mc` and `clang` both
/// report every rejected line in a single run, so one retry normally
/// converges; the loop is bounded anyway, because a harness that can hang is
/// worse than one that reports a partial answer.
fn assemble_chunk(
    asm: &Asm,
    scratch: &std::path::Path,
    dialect: &Dialect,
    tag: &str,
    bodies: &[Option<Body>],
) -> Result<Vec<Slot>, String> {
    let mut refused: BTreeMap<usize, String> = BTreeMap::new();
    for round in 0..6 {
        let mut src = String::with_capacity(bodies.len() * 48);
        src.push_str(dialect.prologue);
        // Slot index for each source line, so a diagnostic's line number can
        // be turned back into the probe that provoked it.
        let mut owner: Vec<Option<usize>> = vec![None; src.lines().count() + 1];
        for (i, body) in bodies.iter().enumerate() {
            let _ = writeln!(src, "\t.balign {SLOT}, 0x00");
            owner.push(None);
            if !refused.contains_key(&i) {
                if let Some(b) = body {
                    for line in &b.lines {
                        let _ = writeln!(src, "\t{line}");
                        owner.push(Some(i));
                    }
                }
            }
            let _ = writeln!(src, "\t.byte {SENTINEL:#04x}");
            owner.push(None);
        }
        let _ = writeln!(src, "\t.balign {SLOT}, 0x00");

        match assemble(asm, scratch, &format!("{tag}-{round}"), &src)? {
            Assembled::Object { text, object } => {
                support::discard(&object);
                let mut slots = Vec::with_capacity(bodies.len());
                for (i, body) in bodies.iter().enumerate() {
                    slots.push(if let Some(msg) = refused.get(&i) {
                        Slot::Refused(msg.clone())
                    } else if body.is_none() {
                        Slot::Absent
                    } else {
                        let start = i * SLOT;
                        match text.get(start..start + SLOT) {
                            Some(b) => Slot::Bytes(b.to_vec()),
                            None => {
                                return Err(format!(
                                    ".text is {} bytes, short of slot {i} at {start}",
                                    text.len()
                                ))
                            }
                        }
                    });
                }
                return Ok(slots);
            }
            Assembled::Errors(errors) => {
                let mut progressed = false;
                for (line, msg) in errors {
                    match owner.get(line).copied().flatten() {
                        Some(slot) => {
                            if refused.insert(slot, msg).is_none() {
                                progressed = true;
                            }
                        }
                        None => {
                            return Err(format!(
                                "assembler error on line {line}, which belongs to no probe: {msg}"
                            ))
                        }
                    }
                }
                if !progressed {
                    return Err("assembler errors did not converge".to_string());
                }
            }
        }
    }
    Err("assembler errors did not converge in six rounds".to_string())
}

/// Check one returned slot against the bytes the probe came from.
fn slot_agrees(slot: &[u8], want: &[u8], expect_len: Option<usize>) -> bool {
    match expect_len {
        Some(len) => {
            // The sentinel is the length check: if the assembler had emitted
            // more or fewer bytes than `len`, it would not be sitting exactly
            // there. What comes *after* it is `.balign` padding, which is the
            // assembler's business and not ours — requiring it to be zero
            // looked harmless and made the harness depend on the LLVM
            // release. `.balign 16, 0x00` in an executable Thumb section is
            // honoured literally by LLVM 23 and filled with `nop` (`bf00`) by
            // LLVM 18, so every probe failed on the older one while passing
            // on the newer.
            slot.len() >= SLOT && &slot[..len] == want && slot[len] == SENTINEL
        }
        // An `IT` slot also holds the block it governs, so only the `IT`
        // itself can be compared.
        None => slot.len() >= 2 && &slot[..2] == want,
    }
}

fn slot_hex(slot: &[u8]) -> String {
    let end = slot.iter().position(|&b| b == SENTINEL).unwrap_or(4).min(8);
    let mut s = String::new();
    for b in &slot[..end.max(2)] {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Driving the disassembler (the reverse direction)
// ---------------------------------------------------------------------------

/// Ask LLVM's decoder about a list of probes.
///
/// Each probe gets a slot of `4 * len` bytes: the probe itself, then `NOP`
/// halfwords. The padding is not cosmetic, and packing the probes tightly
/// instead is a trap this harness fell into once. When LLVM's disassembler
/// cannot decode a pattern it prints `<unknown>` and advances **two** bytes,
/// not four — it has no length to work from — so a tightly packed stream
/// slides out of phase at the first undecodable 32-bit pattern and every
/// probe after it is read at the wrong offset. The failure is silent and it
/// biases the result in the flattering direction: misaligned probes decode as
/// nothing, and "LLVM decodes this and we do not" collapses into "neither of
/// us decodes it".
///
/// `NOP` padding makes every slot boundary self-resynchronising. From the
/// start of a slot the disassembler consumes either four bytes (the probe
/// decoded) or two (it did not); in the second case it lands on the probe's
/// second halfword, which is itself either two or four bytes; every byte
/// after that is a two-byte `NOP`. The slot is a multiple of two in every
/// path and exactly `4 * len` bytes long, so the next slot always starts on a
/// printed instruction.
fn llvm_disassembly(
    asm: &Asm,
    dump: &Objdump,
    scratch: &std::path::Path,
    dialect: &Dialect,
    tag: &str,
    probes: &[(u16, u16)],
    len: usize,
) -> Result<Vec<Option<String>>, String> {
    let slot = 4 * len;
    let mut src = String::with_capacity(probes.len() * 40);
    src.push_str(dialect.prologue);
    for &(hw1, hw2) in probes {
        let _ = writeln!(src, "\t.short {hw1:#06x}");
        if len == 4 {
            let _ = writeln!(src, "\t.short {hw2:#06x}");
        }
        for _ in 0..(slot - len) / 2 {
            src.push_str("\t.short 0xbf00\n"); // NOP, the resynchroniser
        }
    }
    let (bytes, obj) = match assemble(asm, scratch, tag, &src)? {
        Assembled::Object { text, object } => (text, object),
        Assembled::Errors(e) => {
            return Err(format!(
                "`.short` directives were rejected, which cannot happen: {e:?}"
            ))
        }
    };
    if bytes.len() != probes.len() * slot {
        return Err(format!(
            "expected {} bytes of data, got {}",
            probes.len() * slot,
            bytes.len()
        ));
    }
    let lines = raw_disassemble(dump, &obj, dialect.triple, dialect.cpu)
        .ok_or_else(|| "llvm-objdump produced nothing".to_string());
    support::discard(&obj);
    let lines = lines?;

    let mut out = vec![None; probes.len()];
    for (addr, text) in lines {
        let addr = addr as usize;
        if addr % slot != 0 || addr / slot >= probes.len() {
            continue;
        }
        if text.starts_with("<unknown>") {
            continue;
        }
        out[addr / slot] = Some(text);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

struct Report {
    tally: BTreeMap<Outcome, usize>,
    unexplained: Vec<Finding>,
    explained: BTreeMap<&'static str, usize>,
    probes: usize,
    keep: usize,
}

impl Report {
    fn new() -> Report {
        Report {
            tally: BTreeMap::new(),
            unexplained: Vec::new(),
            explained: BTreeMap::new(),
            probes: 0,
            // Triage mode: `THUMB_ASM_CONFORMANCE_REPORT=<path>` keeps every
            // divergence and writes the lot to a file, which is how the
            // allow-list below was built in the first place. The default caps
            // the list, because a harness that answers a broken decoder with
            // a gigabyte of panic message helps nobody.
            keep: if std::env::var_os("THUMB_ASM_CONFORMANCE_REPORT").is_some() {
                usize::MAX
            } else {
                400
            },
        }
    }

    fn record(&mut self, f: Finding) {
        self.probes += 1;
        *self.tally.entry(f.outcome).or_insert(0) += 1;
        if !f.outcome.is_divergence() {
            return;
        }
        match DIVERGENCES.iter().find(|d| d.matches(&f)) {
            Some(d) => *self.explained.entry(d.id).or_insert(0) += 1,
            None => {
                if self.unexplained.len() < self.keep {
                    self.unexplained.push(f);
                }
            }
        }
    }

    fn print(&self, title: &str) {
        println!("\n  {title}");
        println!("    probes: {}", self.probes);
        for (outcome, n) in &self.tally {
            let pct = 100.0 * *n as f64 / self.probes.max(1) as f64;
            println!("      {:<34} {n:>9}  {pct:>6.2}%", outcome.label());
        }
        if !self.explained.is_empty() {
            println!("    divergences, all on the allow-list:");
            for (id, n) in &self.explained {
                println!("      {id:<44} {n:>9}");
            }
        }
    }

    fn assert_clean(&self, title: &str) {
        if let Some(path) = std::env::var_os("THUMB_ASM_CONFORMANCE_REPORT") {
            let mut out = String::new();
            for f in &self.unexplained {
                let _ = writeln!(
                    out,
                    "{title}\t{:04x}\t{:04x}\t{}\t{}\t{}",
                    f.hw1,
                    f.hw2,
                    f.outcome.label(),
                    f.ours.as_deref().unwrap_or(""),
                    f.llvm
                );
            }
            use std::io::Write as _;
            if let Ok(mut fh) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                let _ = fh.write_all(out.as_bytes());
            }
        }
        let mut over: Vec<String> = Vec::new();
        for (id, n) in &self.explained {
            if let Some(d) = DIVERGENCES.iter().find(|d| &d.id == id) {
                if *n > d.budget {
                    over.push(format!(
                        "  `{id}` matched {n} probes, over its budget of {}. Either the \n\
                         class really did grow — look at what joined it — or the budget \n\
                         needs raising with a note saying why.",
                        d.budget
                    ));
                }
            }
        }
        if !over.is_empty() {
            panic!(
                "\nallow-list budgets exceeded in {title}:\n{}",
                over.join("\n")
            );
        }
        if self.unexplained.is_empty() {
            return;
        }
        let mut msg = format!(
            "\n{} unexplained divergence(s) from LLVM in {title}.\n\
             Each is either a defect in this crate or a case that belongs on the\n\
             allow-list in tests/support/divergences.rs with a spec citation.\n\n",
            self.unexplained.len()
        );
        for f in self.unexplained.iter().take(40) {
            let _ = writeln!(
                msg,
                "  {:04x} {:04x}  {:<34}\n      ours: {}\n      llvm: {}",
                f.hw1,
                f.hw2,
                f.outcome.label(),
                f.ours.as_deref().unwrap_or("<not decoded>"),
                f.llvm
            );
        }
        if self.unexplained.len() > 40 {
            let _ = writeln!(msg, "  ... and {} more", self.unexplained.len() - 40);
        }
        panic!("{msg}");
    }
}

/// Run one sweep end to end.
fn sweep(
    asm: &Asm,
    dump: Option<&Objdump>,
    scratch: &std::path::Path,
    tag: &str,
    probes: &[(u16, u16)],
    len: usize,
) -> Result<Report, String> {
    let mut report = Report::new();

    for (chunk_no, chunk) in probes.chunks(CHUNK).enumerate() {
        // Our side, once.
        let decoded: Vec<Option<Insn>> = chunk
            .iter()
            .map(|&(hw1, hw2)| decode_halfwords(hw1, hw2, 0, Target::Union))
            .collect();
        let bodies: Vec<Option<Body>> = decoded
            .iter()
            .map(|d| d.as_ref().map(render))
            .collect::<Vec<_>>();

        // Forward direction, dialect by dialect. A probe that round-trips in
        // the first dialect is never offered to the second; a probe that does
        // not keeps whichever verdict is most informative, and a byte
        // mismatch is more informative than a refusal — the assembler that
        // *had* an opinion is the one worth reporting.
        let mut settled: Vec<Option<(Outcome, String)>> = vec![None; chunk.len()];
        for (di, dialect) in DIALECTS.iter().enumerate() {
            let pending: Vec<Option<Body>> = bodies
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    if matches!(settled[i], Some((Outcome::Agreed, _))) {
                        None
                    } else {
                        b.clone()
                    }
                })
                .collect();
            if pending.iter().all(|b| b.is_none()) {
                break;
            }
            let slots = assemble_chunk(
                asm,
                scratch,
                dialect,
                &format!("{tag}-{chunk_no}-d{di}"),
                &pending,
            )?;
            for (i, slot) in slots.iter().enumerate() {
                let insn = match &decoded[i] {
                    Some(insn) => insn,
                    None => continue,
                };
                let verdict = match slot {
                    Slot::Absent => continue,
                    Slot::Refused(msg) => (
                        Outcome::LlvmRejectsOurText,
                        format!("{} — {msg}", dialect.name),
                    ),
                    Slot::Bytes(b) => {
                        let want = want_bytes(chunk[i].0, chunk[i].1, insn.len());
                        if slot_agrees(b, &want, bodies[i].as_ref().and_then(|b| b.expect_len)) {
                            (Outcome::Agreed, String::new())
                        } else {
                            (
                                Outcome::ByteMismatch,
                                format!("{} assembled it to {}", dialect.name, slot_hex(b)),
                            )
                        }
                    }
                };
                let keep = match &settled[i] {
                    None => true,
                    Some((Outcome::Agreed, _)) => false,
                    Some((existing, _)) => {
                        verdict.0 == Outcome::Agreed || *existing != Outcome::ByteMismatch
                    }
                };
                if keep {
                    settled[i] = Some(verdict);
                }
            }
        }

        // Reverse direction: only the probes we reject need LLVM's opinion,
        // plus the ones LLVM's assembler refused (to say whether its decoder
        // knows them either).
        let mut llvm_text: Vec<Option<String>> = vec![None; chunk.len()];
        if let Some(dump) = dump {
            let want: Vec<usize> = (0..chunk.len())
                .filter(|&i| {
                    decoded[i].is_none()
                        || matches!(
                            settled[i],
                            Some((Outcome::LlvmRejectsOurText, _))
                                | Some((Outcome::ByteMismatch, _))
                        )
                })
                .collect();
            for (di, dialect) in DIALECTS.iter().enumerate().filter(|(_, d)| d.reverse) {
                let still: Vec<usize> = want
                    .iter()
                    .copied()
                    .filter(|&i| llvm_text[i].is_none())
                    .collect();
                if still.is_empty() {
                    break;
                }
                let subset: Vec<(u16, u16)> = still.iter().map(|&i| chunk[i]).collect();
                let texts = llvm_disassembly(
                    asm,
                    dump,
                    scratch,
                    dialect,
                    &format!("{tag}-{chunk_no}-r{di}"),
                    &subset,
                    len,
                )?;
                for (k, t) in texts.into_iter().enumerate() {
                    if t.is_some() {
                        llvm_text[still[k]] = t;
                    }
                }
            }
        }

        for (i, &(hw1, hw2)) in chunk.iter().enumerate() {
            let ours = bodies[i].as_ref().map(|b| b.lines[0].clone());
            let mnemonic = decoded[i].as_ref().map(|d| d.mnemonic);
            let (outcome, llvm) = match (&settled[i], decoded[i].is_some()) {
                (Some((Outcome::Agreed, _)), _) => (Outcome::Agreed, String::new()),
                // The byte loop did not close. Before calling that a
                // divergence, ask whether LLVM's decoder reads the same
                // instruction out of the same bytes.
                (
                    Some((failed @ (Outcome::LlvmRejectsOurText | Outcome::ByteMismatch), msg)),
                    _,
                ) => {
                    let mine = ours.as_deref().unwrap_or("");
                    match &llvm_text[i] {
                        Some(t) if same_instruction(mine, t) => {
                            (Outcome::AgreedViaDisassembly, t.clone())
                        }
                        Some(t) => (*failed, format!("LLVM reads these bytes as `{t}`; {msg}")),
                        None => (Outcome::LlvmSilent, msg.clone()),
                    }
                }
                (Some((o, msg)), _) => (*o, msg.clone()),
                (None, true) => (
                    Outcome::LlvmRejectsOurText,
                    "no dialect produced a verdict".to_string(),
                ),
                (None, false) => match &llvm_text[i] {
                    Some(t) => (Outcome::WeRejectLlvmDecodes, t.clone()),
                    None => (Outcome::BothReject, String::new()),
                },
            };
            report.record(Finding {
                hw1,
                hw2,
                outcome,
                ours,
                mnemonic,
                llvm,
            });
        }
    }
    Ok(report)
}

fn want_bytes(hw1: u16, hw2: u16, len: usize) -> Vec<u8> {
    let mut v = hw1.to_le_bytes().to_vec();
    if len == 4 {
        v.extend_from_slice(&hw2.to_le_bytes());
    }
    v
}

// ---------------------------------------------------------------------------
// Probe generation
// ---------------------------------------------------------------------------

/// Every 16-bit halfword. No sampling: the space is 65536 wide and the whole
/// of it fits in four assembler invocations.
fn probes_16() -> Vec<(u16, u16)> {
    (0..=u16::MAX)
        .filter(|&hw1| insn_len(hw1) == 2)
        .map(|hw1| (hw1, 0))
        .collect()
}

/// `hw2` values that between them exercise every field boundary the 32-bit
/// encodings have: all-clear, all-set, each bit alone, each bit alone clear,
/// the `op`/`S`/`i` bit at 15, and a handful of asymmetric patterns that catch
/// a field read one bit wide or one bit off.
fn hw2_vectors() -> Vec<u16> {
    let mut v = vec![
        0x0000, 0xFFFF, 0x8000, 0x7FFF, 0x0F00, 0x1234, 0x0A10, 0x0B04, 0x0C04, 0x8F00, 0x5A5A,
        0xA5A5, 0x0001, 0x000F, 0x00F0, 0x0FFF, 0xF000,
    ];
    for b in 0..16 {
        v.push(1 << b);
        v.push(!(1u16 << b));
    }
    // Every `Rd` nibble, with tame values around it.
    //
    // `Rd` is `hw2[11:8]` across most of the 32-bit space, and the hand-picked
    // vectors above happen to miss three of its sixteen values entirely: no
    // probe ever asked what `r3`, `r6` or `r9` as a destination decodes to.
    // Worse, the values they *do* reach are dominated by `0xF`, so for several
    // instructions the only probe in the whole sweep named `pc` twice — and
    // `<op> pc, pc` is UNPREDICTABLE, which LLVM refuses to assemble, so those
    // instructions were only ever compared through the weaker disassembly
    // path. These fill the nibble in with an `Rm`/`Rn` that is an ordinary
    // register, so the forms get tested as an assembler would meet them.
    for rd in 0..16u16 {
        v.push(0xF000 | (rd << 8) | 0x02); // `Ra`/`Rn` absent (the `1111` marker)
        v.push((rd << 8) | 0x23); // accumulate and shift shapes
        v.push(0xF080 | (rd << 8) | 0x03); // rotated extend shapes
    }
    // And every value of `hw2[7:4]`, the sub-opcode nibble, with tame
    // registers. It selects between instructions that share a first halfword
    // — `REV`/`REV16`/`RBIT`/`REVSH` are `1000`/`1001`/`1010`/`1011` of one
    // another (A7.7.107-110) — so leaving it thin means whole instructions
    // are reached only through whichever hand-picked vector happened to land
    // on them, which for `REVSH` was `0xFFBF`: `pc` in every field.
    for op in 0..16u16 {
        v.push(0xF000 | (op << 4) | 0x03);
    }
    v.sort_unstable();
    v.dedup();
    v
}

/// A `(hw1, hw2)` pair to offer both implementations.
type Probe = (u16, u16);

/// The 32-bit sweep.
///
/// 2^32 is not enumerable, so the space is covered three ways and the three
/// are reported separately so a gap is visible rather than averaged away:
///
/// * **structured** — every one of the 6144 first halfwords in the 32-bit
///   space (`hw1[15:11]` of `0b11101`, `0b11110` or `0b11111`, all 11 low
///   bits free, so every `hw1[15:4]` opcode pattern appears sixteen times
///   with sixteen different `Rn`) crossed with [`hw2_vectors`];
/// * **pseudorandom** — a fixed-seed xorshift sample, reproducible from the
///   seed printed in the summary and needing no `rand` dependency;
/// * **boundary** — every `hw1` with `hw2` walking one bit at a time, which
///   is already folded into the structured set above.
fn probes_32(seed: u32, random: usize) -> (Vec<Probe>, Vec<Probe>) {
    let vectors = hw2_vectors();
    let mut structured = Vec::with_capacity(6144 * vectors.len());
    for hw1 in 0xE800u32..=0xFFFF {
        for &hw2 in &vectors {
            structured.push((hw1 as u16, hw2));
        }
    }

    let mut rng = Xorshift32(seed);
    let mut sampled = Vec::with_capacity(random);
    for _ in 0..random {
        let hw1 = 0xE800u32 + rng.next() % 0x1800;
        let hw2 = (rng.next() >> 8) as u16;
        sampled.push((hw1 as u16, hw2));
    }
    (structured, sampled)
}

/// Marsaglia's xorshift32. Three lines, no dependency, and the seed in the
/// summary is enough to replay any failure exactly.
struct Xorshift32(u32);

impl Xorshift32 {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0
    }
}

const SEED: u32 = 0x9E37_79B9;
const RANDOM_SAMPLES: usize = 200_000;

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Locate a toolchain, or explain why the test is a no-op.
fn toolchain(scratch: &Scratch) -> Option<(Asm, Option<Objdump>)> {
    let asm = match find_assembler(&scratch.dir) {
        Some(a) => a,
        None => {
            println!(
                "\n  SKIPPED: conformance against LLVM needs an LLVM toolchain and this\n\
                 \x20 machine has none that can assemble Thumb.\n\
                 \x20 Looked for llvm-mc and clang (including -11..-21 suffixes) on $PATH,\n\
                 \x20 in $THUMB_ASM_LLVM_BIN, /opt/homebrew/opt/llvm/bin,\n\
                 \x20 /usr/local/opt/llvm/bin and the Xcode command line tools.\n\
                 \x20 Install LLVM (brew install llvm, apt install llvm, dnf install llvm)\n\
                 \x20 or set THUMB_ASM_LLVM_BIN to a directory containing one.\n\
                 \x20 The rest of the suite is unaffected; nothing here has failed.\n"
            );
            // A skip is invisible: libtest swallows stdout without
            // `--nocapture`, so on a machine with no LLVM these tests report
            // `ok` and `cargo test`'s summary is identical to a run that
            // corroborated every probe. That is fine for a contributor and
            // unacceptable for CI, which would otherwise publish a release
            // claiming differential conformance it never checked.
            //
            // So the choice is the caller's: set `THUMB_ASM_REQUIRE_LLVM` and
            // a missing toolchain is a hard failure instead of a quiet pass.
            // CI sets it; nobody else has to.
            if std::env::var_os("THUMB_ASM_REQUIRE_LLVM").is_some() {
                panic!(
                    "THUMB_ASM_REQUIRE_LLVM is set but no LLVM assembler was found. \
                     Refusing to report a pass for conformance checks that did not run."
                );
            }
            return None;
        }
    };
    let dump = find_objdump(&asm, &scratch.dir);
    println!("\n  conformance harness");
    println!("    assembler:    {} ({})", asm.path.display(), asm.version);
    match &dump {
        Some(d) => println!("    disassembler: {} ({})", d.path.display(), d.version),
        None => println!(
            "    disassembler: none found — the reverse direction (which byte \
             patterns LLVM decodes that we reject) is not covered this run"
        ),
    }
    for d in DIALECTS {
        println!("    dialect:      {}", d.name);
    }
    Some((asm, dump))
}

#[test]
fn every_16_bit_halfword_means_to_llvm_what_it_means_to_us() {
    let scratch = Scratch::new("t16").expect("scratch directory");
    let (asm, dump) = match toolchain(&scratch) {
        Some(t) => t,
        None => return,
    };
    let probes = probes_16();
    let started = std::time::Instant::now();
    let report = sweep(&asm, dump.as_ref(), &scratch.dir, "t16", &probes, 2)
        .unwrap_or_else(|e| panic!("16-bit sweep could not run: {e}"));
    report.print(&format!(
        "16-bit sweep: all {} halfwords whose top five bits make them 16-bit \
         instructions ({:.1}s)",
        probes.len(),
        started.elapsed().as_secs_f64()
    ));
    report.assert_clean("the 16-bit sweep");
}

#[test]
fn the_structured_32_bit_sample_means_to_llvm_what_it_means_to_us() {
    let scratch = Scratch::new("t32").expect("scratch directory");
    let (asm, dump) = match toolchain(&scratch) {
        Some(t) => t,
        None => return,
    };
    let (structured, sampled) = probes_32(SEED, RANDOM_SAMPLES);

    let started = std::time::Instant::now();
    let a = sweep(&asm, dump.as_ref(), &scratch.dir, "t32s", &structured, 4)
        .unwrap_or_else(|e| panic!("structured 32-bit sweep could not run: {e}"));
    a.print(&format!(
        "32-bit structured sweep: all 6144 first halfwords x {} second-halfword \
         vectors = {} probes ({:.1}s)",
        hw2_vectors().len(),
        structured.len(),
        started.elapsed().as_secs_f64()
    ));

    let started = std::time::Instant::now();
    let b = sweep(&asm, dump.as_ref(), &scratch.dir, "t32r", &sampled, 4)
        .unwrap_or_else(|e| panic!("random 32-bit sweep could not run: {e}"));
    b.print(&format!(
        "32-bit pseudorandom sweep: {} probes, xorshift32 seed {:#010x} ({:.1}s)",
        sampled.len(),
        SEED,
        started.elapsed().as_secs_f64()
    ));

    a.assert_clean("the structured 32-bit sweep");
    b.assert_clean("the pseudorandom 32-bit sweep");
}

/// The allow-list is documentation as much as it is test data, so it is held
/// to the standard documentation is held to: every entry cites the clause it
/// rests on and says why in one line.
#[test]
fn every_allow_list_entry_carries_a_citation() {
    for d in DIVERGENCES {
        assert!(!d.id.is_empty(), "a divergence entry has no id");
        assert!(
            !d.citation.is_empty(),
            "divergence `{}` has no spec citation",
            d.id
        );
        assert!(
            d.why.len() > 20,
            "divergence `{}` needs a real explanation, not `{}`",
            d.id,
            d.why
        );
        assert!(
            d.outcome.is_divergence(),
            "divergence `{}` allows `{}`, which is not a divergence",
            d.id,
            d.outcome.label()
        );
        assert!(d.budget > 0, "divergence `{}` has a zero budget", d.id);
    }
    let mut ids: Vec<&str> = DIVERGENCES.iter().map(|d| d.id).collect();
    ids.sort_unstable();
    let before = ids.len();
    ids.dedup();
    assert_eq!(before, ids.len(), "duplicate divergence id");
}

/// A handful of hand-checked vectors, so a catastrophic failure of the
/// harness itself (wrong slot stride, wrong endianness, silently empty probe
/// list) cannot pass as a clean run.
#[test]
fn the_harness_agrees_with_itself_on_known_bytes() {
    let scratch = Scratch::new("self").expect("scratch directory");
    let (asm, _) = match toolchain(&scratch) {
        Some(t) => t,
        None => return,
    };
    // Instructions whose encodings are not in dispute, one per major shape.
    let probes: Vec<(u16, u16)> = vec![
        (0x2001, 0x0000), // movs r0, #1            A7.7.76 T1
        (0x4770, 0x0000), // bx lr                  A7.7.20 T1
        (0xB580, 0x0000), // push {r7, lr}          A7.7.101 T1
        (0x1888, 0x0000), // adds r0, r1, r2        A7.7.4 T1
    ];
    let report = sweep(&asm, None, &scratch.dir, "self", &probes, 2).expect("self-check sweep");
    report.assert_clean("the harness self-check");
    assert_eq!(
        report.tally.get(&Outcome::Agreed).copied().unwrap_or(0),
        probes.len(),
        "the harness disagrees with LLVM about instructions whose encodings are textbook; \
         the harness itself is broken, not the crate"
    );

    let wide: Vec<(u16, u16)> = vec![
        (0xF000, 0xF800), // bl  +0                 A7.7.18 T1
        (0xE92D, 0x4800), // push.w {r11, lr}       A7.7.101 T2
        (0xF3BF, 0x8F5F), // dmb sy                 A7.7.33 T1
    ];
    let report = sweep(&asm, None, &scratch.dir, "selfw", &wide, 4).expect("self-check sweep");
    report.assert_clean("the harness self-check");
    assert_eq!(
        report.tally.get(&Outcome::Agreed).copied().unwrap_or(0),
        wide.len(),
        "the harness disagrees with LLVM about 32-bit instructions whose encodings are \
         textbook; the harness itself is broken, not the crate"
    );
}

/// Every width suffix this crate prints must be one LLVM will actually parse.
///
/// The three sweeps above cannot see this class of bug, and it is worth being
/// precise about why, because the gap is in the comparison rather than in the
/// coverage. When LLVM refuses our text, a probe is not immediately a
/// divergence: the sweep falls back to comparing LLVM's *disassembly* of the
/// same bytes against our text, and if the two agree it records
/// [`Outcome::AgreedViaDisassembly`], which needs no allow-list entry. That
/// comparison runs through [`same_instruction`], and [`mnemonic_of`]
/// deliberately strips `.w`/`.n` before comparing — width is spelled
/// differently by the two implementations often enough that comparing it
/// directly would bury the sweep in noise.
///
/// Those two reasonable decisions compose into an unreasonable one. An
/// instruction we print with a suffix that is not valid UAL is refused by the
/// assembler, then forgiven by a comparison that cannot see the suffix, and
/// lands in the bucket labelled "agreed". `mul.w` sat there for the whole
/// 32-bit sweep: A7.7.84 gives `MUL` T2 the syntax line
/// `MUL<c> <Rd>,<Rn>,<Rm>` with no width qualifier, LLVM rejects `mul.w`
/// outright, and 282,000 probes reported no disagreement.
///
/// So this asks the one question the sweeps cannot: for each distinct suffixed
/// form we can produce, offer LLVM the text on its own and require that some
/// dialect accepts it. It is small — one representative per distinct
/// `(mnemonic, s, width)` — because the question is about the *spelling*, and
/// one instance settles a spelling.
#[test]
fn every_width_suffix_we_print_is_one_llvm_will_parse() {
    let scratch = Scratch::new("suffix").expect("scratch directory");
    let (asm, _) = match toolchain(&scratch) {
        Some(t) => t,
        None => return,
    };

    // One representative per distinct suffixed form, over the same probe
    // space the sweeps use.
    let (structured, sampled) = probes_32(SEED, RANDOM_SAMPLES);
    let mut reps: BTreeMap<String, (Body, String, u16, u16)> = BTreeMap::new();
    for &(hw1, hw2) in probes_16().iter().chain(&structured).chain(&sampled) {
        let insn = match decode_halfwords(hw1, hw2, 0, Target::Union) {
            Some(i) => i,
            None => continue,
        };
        if !insn.explicit_width {
            continue;
        }
        let body = render(&insn);
        // An IT block's body is several lines and is not about width.
        if body.lines.len() != 1 {
            continue;
        }
        let text = body.lines[0].clone();
        let key = mnemonic_with_suffix(&text);
        // Prefer a representative that names neither `pc` nor `sp`. LLVM
        // refuses to assemble forms the manual calls UNPREDICTABLE, and
        // `<op> pc, pc` is refused for that reason and not for its suffix —
        // taking the first probe that happened to decode would test the
        // wrong thing and fail for the wrong reason.
        let tame = !mentions_pc_or_sp(&text);
        match reps.get(&key) {
            Some((_, prev, _, _)) if tame && mentions_pc_or_sp(prev) => {
                reps.insert(key, (body, text, hw1, hw2));
            }
            Some(_) => {}
            None => {
                reps.insert(key, (body, text, hw1, hw2));
            }
        }
    }
    assert!(
        reps.len() > 40,
        "only {} suffixed forms found — the probe set or the width flag has \
         changed and this test is no longer asking anything",
        reps.len()
    );

    // Offer each to every dialect; accepted by any one is enough, since a
    // suffix can be legal only on a profile that defines the instruction.
    let keys: Vec<&String> = reps.keys().collect();
    let bodies: Vec<Option<Body>> = keys.iter().map(|k| Some(reps[*k].0.clone())).collect();
    let mut accepted = vec![false; keys.len()];
    let mut why: Vec<String> = vec![String::new(); keys.len()];
    for (di, dialect) in DIALECTS.iter().enumerate() {
        let slots = assemble_chunk(&asm, &scratch.dir, dialect, &format!("sfx{di}"), &bodies)
            .unwrap_or_else(|e| panic!("suffix probe could not be assembled: {e}"));
        for (i, slot) in slots.iter().enumerate() {
            match slot {
                Slot::Bytes(_) => accepted[i] = true,
                Slot::Refused(msg) => {
                    if why[i].is_empty() {
                        why[i] = msg.clone();
                    }
                }
                Slot::Absent => {}
            }
        }
    }

    let mut bad = String::new();
    for (i, k) in keys.iter().enumerate() {
        if !accepted[i] {
            let (_, text, hw1, hw2) = &reps[*k];
            let _ = writeln!(
                bad,
                "    {hw1:04x} {hw2:04x}  we print `{text}`  LLVM: {}",
                why[i].trim()
            );
        }
    }
    println!(
        "\n  width-suffix check: {} distinct suffixed forms, {} rejected\n",
        keys.len(),
        bad.lines().count()
    );
    assert!(
        bad.is_empty(),
        "these forms carry a width suffix no LLVM dialect will parse, which \
         means the suffix is not valid UAL and the sweeps cannot see it:\n{bad}"
    );
}

/// Whether a rendered line names `pc` or `sp` as an operand.
fn mentions_pc_or_sp(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|t| t.eq_ignore_ascii_case("pc") || t.eq_ignore_ascii_case("sp"))
}

/// The leading token of a rendered line — mnemonic, flag-setting `s`,
/// condition and width suffix together. Unlike [`mnemonic_of`] this keeps the
/// width, because the width is the thing under test.
fn mnemonic_with_suffix(text: &str) -> String {
    text.split_whitespace().next().unwrap_or("").to_lowercase()
}

/// [`render`] must be [`Insn::Display`] plus one substitution, and this is
/// what holds it to that.
///
/// The harness feeds LLVM whatever `render` produces. If `render` builds the
/// text itself rather than delegating, then what gets corroborated is a
/// second printer that only exists in the test suite, and every defect in the
/// printer the crate actually ships is invisible — including, when this was
/// written, the `LDR (literal)` T1 rule that makes `0x4800` print
/// `ldr r0, [pc, #0]` instead of the ambiguous `ldr r0, [pc]`.
#[test]
fn render_is_display_apart_from_the_pc_relative_substitution() {
    let (structured, sampled) = probes_32(SEED, RANDOM_SAMPLES);
    let mut checked = 0usize;
    let mut diffs: Vec<String> = Vec::new();
    for &(hw1, hw2) in probes_16().iter().chain(&structured).chain(&sampled) {
        let insn = match decode_halfwords(hw1, hw2, 0, Target::Union) {
            Some(i) => i,
            None => continue,
        };
        // The substitution only applies to instructions carrying a `Target`;
        // everything else must match the shipped printer exactly.
        if insn
            .operands
            .as_slice()
            .any(|o| matches!(o, Operand::Target(_)))
        {
            continue;
        }
        if it_block(&insn).is_some() {
            continue; // rendered as several lines, not comparable
        }
        checked += 1;
        let ours = render(&insn).lines.join("");
        let shipped = insn.to_string();
        if ours != shipped && diffs.len() < 20 {
            diffs.push(format!(
                "    {hw1:04x} {hw2:04x}  render {ours:?}  Display {shipped:?}"
            ));
        }
    }
    assert!(checked > 100_000, "only {checked} comparable instructions");
    assert!(
        diffs.is_empty(),
        "`render` and `Insn::Display` disagree on {} of {checked} instructions, \
         so the conformance sweeps are corroborating a printer this crate does \
         not ship:\n{}",
        diffs.len(),
        diffs.join("\n")
    );
    println!("\n  render/Display agreement: {checked} instructions, 0 divergences\n");
}

/// `same_instruction` must not call two different instructions the same.
///
/// It is the weaker of the two corroboration paths — used when LLVM's
/// assembler will not take our text back — so anything it cannot see is
/// unchecked for those encodings. It compares mnemonic, registers and
/// immediates; before `shape_of` was added, that made `lsl` and `asr`
/// indistinguishable, and made an offset, a pre-indexed and a post-indexed
/// load all the same instruction.
#[test]
fn same_instruction_distinguishes_shift_kind_and_addressing_mode() {
    // Sanity: it still accepts genuinely equal text, and the spellings it is
    // meant to forgive.
    assert!(same_instruction("lsl r0, r1, #2", "lsl r0, r1, #2"));
    assert!(same_instruction("lsl.w r0, r1, #2", "lsl r0, r1, #2"));
    assert!(same_instruction("mov r0, #16", "mov r0, #0x10"));
    assert!(same_instruction("ldr r0, [r1]", "ldr r0, [r1] <sym+0x4>"));

    // The four shift kinds are four different instructions.
    for (a, b) in [
        ("lsl r0, r1, #2", "asr r0, r1, #2"),
        ("lsl r0, r1, #2", "lsr r0, r1, #2"),
        ("asr r0, r1, #2", "ror r0, r1, #2"),
        ("mov r0, r1, lsl #2", "mov r0, r1"),
    ] {
        assert!(!same_instruction(a, b), "`{a}` is not `{b}`");
    }

    // Offset, pre-indexed and post-indexed are three different instructions
    // with identical registers and immediates.
    for (a, b) in [
        ("ldr r0, [r1, #4]", "ldr r0, [r1, #4]!"),
        ("ldr r0, [r1, #4]", "ldr r0, [r1], #4"),
        ("ldr r0, [r1, #4]!", "ldr r0, [r1], #4"),
        ("ldm r0, {r1, r2}", "ldm r0!, {r1, r2}"),
        ("ldm r0, {r1, r2}", "ldm r0, {r1, r2}^"),
    ] {
        assert!(!same_instruction(a, b), "`{a}` is not `{b}`");
    }
}

/// Every Armv8-M Security Extension encoding this crate decodes, assembled by
/// LLVM and compared byte for byte.
///
/// This is the ratchet for `Target::V8M`. The unit tests in `isa::cmse` check
/// against LLVM's answers *recorded as constants*; this checks against LLVM
/// itself, over the whole group rather than ten samples, so a change to either
/// implementation shows up here rather than in a stale table.
///
/// The group is small enough to enumerate exhaustively — 16 `BXNS`, 16
/// `BLXNS`, 16x16x4 `TT` forms and the single `SG` — so there is no sampling
/// argument to make and no seed to record.
///
/// It assembles with `.arch armv8-m.main`, which overrides the harness's
/// `thumbv7a` triple: the directive wins, which is the same reason every
/// dialect in `DIALECTS` puts `.thumb` *after* its `.arch`.
#[test]
fn every_security_extension_encoding_means_to_llvm_what_it_means_to_us() {
    let scratch = Scratch::new("cmse").expect("scratch directory");
    let (asm, _) = match toolchain(&scratch) {
        Some(t) => t,
        None => return,
    };

    // Enumerate the whole group, decode under `Target::V8M`, and keep the
    // ones that decode. What this crate refuses is not this test's subject —
    // the reverse census covers that — so a `None` is skipped rather than
    // failed.
    let mut cases: Vec<((u16, u16), String)> = Vec::new();
    for rm in 0u16..16 {
        for &base in &[0x4704u16, 0x4784] {
            let hw1 = base | (rm << 3);
            if let Some(i) = decode_halfwords(hw1, 0, 0, Target::V8M) {
                cases.push(((hw1, 0), i.to_string()));
            }
        }
    }
    if let Some(i) = decode_halfwords(0xE97F, 0xE97F, 0, Target::V8M) {
        cases.push(((0xE97F, 0xE97F), i.to_string()));
    }
    for rn in 0u16..16 {
        for rt in 0u16..16 {
            for az in 0u16..4 {
                let hw1 = 0xE840 | rn;
                let hw2 = 0xF000 | (rt << 8) | (az << 6);
                if let Some(i) = decode_halfwords(hw1, hw2, 0, Target::V8M) {
                    cases.push(((hw1, hw2), i.to_string()));
                }
            }
        }
    }
    assert_eq!(
        cases.len(),
        // 15 BXNS (pc refused) + 13 BLXNS (sp, lr, pc refused) + 1 SG
        // + TT: 15 usable Rn x 14 usable Rt x 4 forms.
        15 + 13 + 1 + 15 * 14 * 4,
        "the enumeration changed shape; a count pinned as a literal is what \
         makes that visible rather than silent"
    );

    // One source file, one assembler invocation. Each instruction is followed
    // by a sentinel `.short` so a form that assembles to the wrong *length*
    // is caught as well as one that assembles to the wrong bytes.
    let mut src = String::with_capacity(cases.len() * 32);
    src.push_str("\t.syntax unified\n\t.arch armv8-m.main\n\t.text\n\t.thumb\n");
    for (_, text) in &cases {
        let _ = writeln!(src, "\t{text}");
        let _ = writeln!(src, "\t.short 0xbf00");
    }

    let bytes = match assemble(&asm, &scratch.dir, "cmse", &src).expect("assembling") {
        Assembled::Object { text, object } => {
            support::discard(&object);
            text
        }
        Assembled::Errors(e) => panic!(
            "LLVM rejected text this crate printed for Armv8-M: {:?}",
            &e[..e.len().min(6)]
        ),
    };

    let mut pos = 0usize;
    for ((hw1, hw2), text) in &cases {
        let wide = *hw2 != 0 || *hw1 == 0xE97F;
        let n = if wide { 4 } else { 2 };
        let got: Vec<u8> = bytes[pos..pos + n].to_vec();
        let want: Vec<u8> = if wide {
            vec![
                (*hw1 & 0xFF) as u8,
                (*hw1 >> 8) as u8,
                (*hw2 & 0xFF) as u8,
                (*hw2 >> 8) as u8,
            ]
        } else {
            vec![(*hw1 & 0xFF) as u8, (*hw1 >> 8) as u8]
        };
        assert_eq!(
            got, want,
            "`{text}` (from {hw1:#06x} {hw2:#06x}) assembled to different bytes"
        );
        // The sentinel proves LLVM gave the instruction the length we did.
        assert_eq!(
            &bytes[pos + n..pos + n + 2],
            &[0x00, 0xBF],
            "`{text}` assembled to a different length than {n} bytes"
        );
        pos += n + 2;
    }
    assert_eq!(pos, bytes.len(), "trailing bytes in the assembled output");
}

/// Every Arm section number `docs/CONFORMANCE.md` cites for a divergence is
/// one that `tests/support/divergences.rs` cites for the same divergence.
///
/// The two are independent prose about the same facts, which is exactly the
/// shape that drifts: the allow-list is what the harness actually enforces,
/// and the document is what a reader checks. An audit found **ten** rows where
/// they disagreed — `A7.7.24 CPS` where the real section is `A7.7.29`,
/// `A7.7.242 VTBL/VTBX` where VTBL is not in the M-profile manual at all — and
/// every one of them had been sitting there being read as authoritative.
///
/// This compares the *set of section tokens* per divergence id rather than the
/// prose, because the two are deliberately worded differently: the allow-list
/// entry carries the architectural clause, the table carries a summary. What
/// must not differ is which section a reader is sent to.
#[test]
fn the_conformance_document_cites_what_the_allow_list_cites() {
    let doc = include_str!("../docs/CONFORMANCE.md");
    let list = include_str!("support/divergences.rs");

    // `A7.7.29`, `A8.6.406`, `A5.2.5`, `B5.2.1` — the shapes used for a
    // numbered section in either manual.
    fn sections(text: &str) -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        let bytes: Vec<char> = text.chars().collect();
        let mut i = 0;
        while i < bytes.len() {
            if (bytes[i] == 'A' || bytes[i] == 'B') && i + 1 < bytes.len() {
                let start = i;
                let mut j = i + 1;
                while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == '.') {
                    j += 1;
                }
                let tok: String = bytes[start..j].iter().collect();
                // At least two dotted components, e.g. `A7.7.29` or `A5.2.5`.
                if tok.matches('.').count() >= 2 && !tok.ends_with('.') {
                    out.insert(tok);
                }
                i = j;
            } else {
                i += 1;
            }
        }
        out
    }

    let mut missing: Vec<(String, String)> = Vec::new();
    for id_line in list
        .lines()
        .filter(|l| l.trim_start().starts_with("id: \""))
    {
        let id = id_line
            .trim()
            .trim_start_matches("id: \"")
            .trim_end_matches("\",");
        // The document row for this id, if the document names it at all.
        let row = match doc.lines().find(|l| l.contains(&format!("`{id}`"))) {
            Some(r) => r,
            None => continue,
        };
        // The allow-list entry's citation block: from this id to the next.
        let from = list.find(&format!("id: \"{id}\"")).unwrap_or(0);
        let rest = &list[from..];
        let to = rest[1..]
            .find("id: \"")
            .map(|k| k + 1)
            .unwrap_or(rest.len());
        let entry = &rest[..to];

        for cited in sections(row) {
            if !sections(entry).contains(&cited) {
                missing.push((id.to_string(), cited));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "docs/CONFORMANCE.md cites sections the allow-list does not, so one of \
         the two is wrong about the manual: {missing:?}"
    );
}
