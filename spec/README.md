# Local ARM specs (reference only — not shipped in the crate)

Primary sources for every encoding claim in `src/lib.rs` and in `THUMB-ISA.md`.
Each PDF has a sibling `.txt` (pypdf text dump, one `===== PDFPAGE n =====`
marker per page) so the encodings are greppable:

```sh
grep -n "A5.2.5" spec/ARMv7-M.txt          # jump to an encoding section
awk '/PDFPAGE 134 /,/PDFPAGE 136 /' spec/ARMv7-M.txt
```

| File | Doc | Pages | Why it's here |
|---|---|---|---|
| `ARMv7-M_DDI0403E.pdf` | Armv7-M ARM, DDI 0403E.e (ID021621) | 858 | Cleanest full Thumb-only spec. Ch. **A5** = encoding space, **A7.7** = alphabetical instruction detail. The reference for anything Cortex-M. |
| `ARMv7-AR_DDI0406C.pdf` | ARMv7-A/R ARM, DDI 0406 (B-errata build) | 2158 | The *superset* Thumb: adds SETEND/CPS/RFE/SRS/SMC/BXJ, ThumbEE (ch. A9), coprocessor + Advanced SIMD/VFP in Thumb encodings. Ch. **A6** = Thumb encoding, **A8.6** = instruction detail (ARM + Thumb side by side). |
| `ARMv6-M_DDI0419.pdf` | ARMv6-M ARM, DDI 0419C | 436 | The minimal Thumb subset (Cortex-M0). Useful to check "is this encoding legal on the smallest core". |
| `ARMv5_DDI0100I.pdf` | ARM ARM, DDI 0100I (ARMv5TE) | ~1100 | Original Thumb-1 definition + the ARMv5 `BL`/`BLX` halfword-pair semantics, which is what most pre-Cortex firmware (ARM7TDMI / ARM9) actually is. |

Download provenance: pjrc.com mirror (v7-M), cs.utexas.edu mirror (v7-A/R),
users.ece.utexas.edu mirror (v6-M), fdi.ucm.es mirror (v5). All are
Arm-published PDFs redistributed by universities; the canonical homes are
`developer.arm.com/documentation/{ddi0403,ddi0406,ddi0419,ddi0100}`.
