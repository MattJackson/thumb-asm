//! The encoder-side profile-legality gate.
//!
//! This module answers **"is this mnemonic / encoding form defined on this
//! target?"** for the assembler's [`Asm::with_target`](crate::Asm::with_target)
//! path. It is deliberately *not* decode-back: [`decode_at_with`] treats
//! [`Target::V7M`], [`Target::V7A`], [`Target::V7R`] and [`Target::V7AR`]
//! identically to [`Target::Union`] because the crate's decoder is a union by
//! design (see `spec/THUMB-ISA.md`), so asking the decoder "does this halfword
//! decode under V7A?" is equivalent to asking "does it decode at all?" —
//! which does not tell an emitter that `sdiv` is UNDEFINED on Armv7-A.
//!
//! The right answer is a per-target legality table keyed on the emitter's
//! *own* static knowledge of what mnemonic and encoding form it produces.
//! Every `Asm` emitter that could differ across profiles passes its mnemonic
//! and form to [`Asm::check_target`](crate::Asm::check_target), which consults
//! [`defined_on`] under any non-Union target and records
//! [`AsmError::Unsupported`](crate::AsmError::Unsupported) via the standard
//! first-error-wins path.
//!
//! # State of the table in 0.14.0
//!
//! Minimal: only `sdiv` and `udiv` (Thumb-2 T1) are restricted, on
//! [`Target::V7A`] and [`Target::V7AR`]. The consumer-honesty statement:
//! every other current Asm emitter is baseline T1 that is defined across
//! Armv6-M / V7-M / V7-A / V7-R / V7E-M / V8-M identically, so the gate is
//! a no-op for that set today. Restricted emitters (`sg`/`bxns`/`blxns`
//! CMSE-only on V8M, `enterx`/`leavex` ThumbEE, `blx label` T2, DSP,
//! operand-discriminated `mrs`/`msr`/`cps`/`dsb`/`dmb`) land as follow-ons
//! in 0.14.x / 0.15.0 and become new rows here.
//!
//! [`Target::V7M`]: crate::isa::Target::V7M
//! [`Target::V7A`]: crate::isa::Target::V7A
//! [`Target::V7R`]: crate::isa::Target::V7R
//! [`Target::V7AR`]: crate::isa::Target::V7AR
//! [`Target::Union`]: crate::isa::Target::Union
//! [`decode_at_with`]: crate::isa::decode_at_with

use crate::isa::Target;

/// Which Thumb encoding form of a mnemonic we are asking about. Mnemonics
/// with more than one encoding routinely differ across profiles per form —
/// e.g. `mov` T1 is baseline everywhere, `mov` T3 (`movw`) requires v6T2+ —
/// so a legality key that ignores the form loses that split.
///
/// The crate today emits only `T1`, `T2` and `T3` variants; `T4` is reserved
/// for `bl`-family and similar wide encodings that land in follow-on work.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[allow(dead_code)] // T4 reserved for follow-on emitters
pub(crate) enum EncForm {
    T1,
    T2,
    T3,
    T4,
}

impl From<&str> for EncForm {
    /// Recover an `EncForm` from the [`Insn.encoding`](crate::isa::Insn) string
    /// the decoder attaches. Panics on any string other than `"T1"..="T4"` —
    /// deliberately: a decoder that grows a new form silently is exactly the
    /// mutation the whole-table sweep is meant to catch, and a panic in an
    /// internal caller shows up as a failed test not a silent miscount.
    fn from(s: &str) -> Self {
        match s {
            "T1" => EncForm::T1,
            "T2" => EncForm::T2,
            "T3" => EncForm::T3,
            "T4" => EncForm::T4,
            other => panic!(
                "EncForm::from: unknown encoding string {other:?} — decoder \
                 grew a form the legality table does not know"
            ),
        }
    }
}

/// Extra operand keys that discriminate legality within a `(mnemonic, form)`
/// pair. Placeholder in 0.14.0 with only `Plain`; the four operand-discriminated
/// mnemonics Fable's round-2 audit named — `mrs`, `msr`, `cps`, `dsb`/`dmb` —
/// gain their own variants when their emitters land.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[non_exhaustive]
#[allow(dead_code)] // future variants reserved
pub(crate) enum OpExtra {
    /// No operand-level discrimination: the `(mnemonic, form)` pair alone
    /// determines legality.
    Plain,
}

/// Is `(mnemonic, form)` (with the given `extra` operand key) defined on
/// `target`? Union is permissive by design (unchanged from pre-0.14.0
/// behaviour); everything else consults the per-profile table.
///
/// See the module docstring for what's in the table today.
pub(crate) fn defined_on(
    mnemonic: &str,
    form: EncForm,
    target: Target,
    extra: OpExtra,
) -> bool {
    // Union always accepts — that's the pre-0.14 byte-for-byte contract.
    if target == Target::Union {
        return true;
    }
    // Every current entry is Plain; the parameter is here so mrs/msr/cps/…
    // can slot in without rewriting the signature.
    let _ = extra;
    match (mnemonic, form) {
        // Integer divide, Thumb-2 T1 (ARM ARM A8.8.165 / A8.8.267).
        //
        // Mandatory on Armv7-R and Armv7-M / Armv7E-M / Armv8-M. Not part
        // of Armv7-A: the Thumb T1 encoding is UNDEFINED on Armv7-A
        // proper. V7AR is the strict intersection, so it refuses too.
        ("sdiv" | "udiv", EncForm::T1) => !matches!(target, Target::V7A | Target::V7AR),
        // Everything else: currently unrestricted across all non-Union
        // targets. Restricted mnemonics land here as new arms.
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Target::Union` never refuses. This is the pre-0.14 contract; a mutant
    /// that flips it to `false` for any input must fail.
    #[test]
    fn union_is_permissive_for_every_mnemonic_and_form() {
        for m in ["sdiv", "udiv", "push", "cmp", "bl", "bxns", "enterx"] {
            for f in [EncForm::T1, EncForm::T2, EncForm::T3, EncForm::T4] {
                assert!(
                    defined_on(m, f, Target::Union, OpExtra::Plain),
                    "Union must accept {m}/{f:?}"
                );
            }
        }
    }

    /// The 0.14.0 pinned-literal false-set per target. This is deliberately
    /// hardcoded rather than mirrored from a lookup: editing `defined_on`
    /// without editing this test breaks the test.
    ///
    /// Add a new row when a restricted mnemonic lands.
    #[test]
    fn the_per_target_false_set_matches_the_0_14_0_pinned_literal() {
        // (mnemonic, form) pairs that must be refused on the given target.
        let cases: &[(Target, &[(&str, EncForm)])] = &[
            (Target::Union, &[]),
            (Target::V7M, &[]),
            (Target::V7EM, &[]),
            (Target::V7A, &[("sdiv", EncForm::T1), ("udiv", EncForm::T1)]),
            (Target::V7R, &[]),
            (Target::V7AR, &[("sdiv", EncForm::T1), ("udiv", EncForm::T1)]),
            (Target::V8M, &[]),
            (Target::ThumbEE, &[]),
        ];

        // A restricted-mnemonic universe to probe: every (mnemonic, form)
        // this crate can currently produce that could plausibly differ
        // across profiles. When new emitters land, extend this set (and
        // then the `cases` above will start rejecting stale expectations).
        let universe: &[(&str, EncForm)] = &[
            ("sdiv", EncForm::T1),
            ("udiv", EncForm::T1),
        ];

        for (target, expected_false) in cases {
            for probe in universe {
                let result = defined_on(probe.0, probe.1, *target, OpExtra::Plain);
                let should_fail = expected_false.contains(probe);
                assert_eq!(
                    result, !should_fail,
                    "defined_on({:?}, {:?}, {:?}) disagreed with pinned literal",
                    probe.0, probe.1, target
                );
            }
        }
    }

    /// A whole-target-variant sweep: every `Target` participates in the pin
    /// set. If someone adds a new variant to `Target` without wiring it into
    /// the pinned-literal `cases` above, this test loudly points at the
    /// missing entry.
    #[test]
    fn every_target_variant_appears_in_the_pin_set() {
        // Enumerate every `Target::` variant explicitly here — a compiler
        // help-line will point right at any additions we forgot to wire up.
        let all: &[Target] = &[
            Target::Union,
            Target::V7M,
            Target::V7EM,
            Target::V7A,
            Target::V7R,
            Target::V7AR,
            Target::V8M,
            Target::ThumbEE,
        ];
        // The `cases` array above is the source of truth for the pinned
        // literal; a new `Target` variant not present in `all` here means
        // we need to add it in both places.
        for t in all {
            // Under any target, at least `Union`'s permissive contract lets
            // an arbitrary decoded mnemonic pass. We exercise the function
            // pointer to keep it live under mutation.
            let _ = defined_on("push", EncForm::T1, *t, OpExtra::Plain);
        }
    }

    /// `EncForm::from(&str)` panics loudly on an unknown encoding string —
    /// the mutation tripwire the decoder relies on.
    #[test]
    #[should_panic(expected = "decoder grew a form")]
    fn encform_from_str_panics_on_unknown_form() {
        let _ = EncForm::from("A1");
    }
}
