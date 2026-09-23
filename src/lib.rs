//! Generic, platform-neutral toolkit for reading, patching and generating
//! ARM-Thumb code inside a flat binary image.
//!
//! Whatever the image is — a drive firmware dump, a boot ROM, a stripped
//! `.bin` carved out of an update package — the work reduces to four verbs:
//!
//! * **find**  — locate something (a byte pattern, a word, a run of free space,
//!   a call site). ONE primitive, [`find`], expressed over a [`Needle`]; every
//!   named finder ([`find_free_space`], …) is a thin overload of it. Because
//!   [`find`] takes a `start` and returns the match offset, finds compose by
//!   nesting: `find(y, find(x, find(a, 0)))`.
//! * **read**  — read a value at a found location: [`read_u32`], [`read_u16`],
//!   [`read_u8`] for offsets already known to be in bounds, and the
//!   `Option`-returning [`try_read_u32`], [`try_read_u16`], [`try_read_u8`] for
//!   scans that walk to the end of the image. Instruction-level reads are
//!   [`decode_bl`], [`decode_b_wide`] and [`decode_b_cond`].
//! * **modify / insert** — [`write()`] bytes at an offset (repoint a record,
//!   patch a field) or [`insert`] a code blob into free space, returning its
//!   address. [`install_branch`] does the whole detour-installation pattern —
//!   encode, write, decode back to confirm — in one call.
//! * **create** — [`Asm`], a small position-independent Thumb assembler with a
//!   literal pool and data blobs, plus the standalone encoders [`encode_bl`],
//!   [`encode_b_wide`] and [`encode_b_cond`].
//!
//! The crate deliberately knows nothing about any particular firmware, vendor
//! or tool. The *knowledge* — which needle to look for, where it lives, what to
//! assemble in its place — belongs to the caller; this crate supplies only the
//! verbs, so supporting a new platform never means new toolkit logic.
//!
//! Every encoding claim in this file cites its section in Arm's architecture
//! reference manuals (`A5.*`/`A7.*` = ARM DDI 0403E.e, Armv7-M; `A6.*` =
//! ARM DDI 0406C, Armv7-A/R).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod analysis;
mod cond;
pub mod detour;
pub mod isa;
pub mod relocate;

pub use cond::Cond;
pub use isa::{Insn, Operand, Reg, Width};

/// The crate's `Result`, defaulted to [`AsmError`] so downstream code can write
/// `-> thumb_asm::Result<Vec<u8>>` and mean "or an assembler error".
///
/// The second parameter is still free, so the fallible image operations that
/// report a different failure keep their own error type without a second alias:
/// [`verify_branch`] returns `Result<(), InstallMismatch>`.
///
/// ```
/// fn build() -> thumb_asm::Result<Vec<u8>> {
///     let mut a = thumb_asm::Asm::new();
///     a.movs_imm(0, 1);
///     a.bx(0);
///     a.finish()
/// }
/// assert_eq!(build().unwrap(), vec![0x01, 0x20, 0x00, 0x47]);
/// ```
pub type Result<T, E = AsmError> = core::result::Result<T, E>;

/// A thing [`find`] can search for. Add a variant here to teach every caller a
/// new kind of search without touching caller code.
#[derive(Debug, Clone, Copy)]
pub enum Needle<'a> {
    /// An exact byte pattern.
    Bytes(&'a [u8]),
    /// A little-endian 32-bit word (e.g. an absolute address embedded as a
    /// Thumb literal, or a handler pointer).
    Word(u32),
    /// A run of at least `len` erased-flash bytes (`0xFF`) — i.e. free space —
    /// whose *start offset* is a multiple of `align`.
    ///
    /// The alignment belongs in the needle rather than in a round-up afterwards.
    /// [`Asm::finish`] documents that its output assumes a 4-byte-aligned load
    /// address, because its literal-pool offsets are computed against
    /// `Align(PC, 4)` relative to the buffer start — and rounding a found run's
    /// start up moves the start without extending the end, so a run that was
    /// exactly long enough stops being long enough and the caller gets an offset
    /// whose tail overlaps live bytes. Accounting for alignment *during* the scan
    /// is the only form of the question with a correct answer. `align: 1` is the
    /// pre-0.10 behaviour.
    FreeRun {
        /// How many free bytes are needed.
        len: usize,
        /// Required alignment of the run's start offset, in bytes. Must be >= 1.
        align: usize,
    },
}

/// The one search primitive. Find `needle` at or after byte offset `start`;
/// return the offset of the match, or `None`. Every named finder below is a
/// thin overload of this call.
pub fn find(image: &[u8], needle: Needle, start: usize) -> Option<usize> {
    match needle {
        Needle::Bytes(pat) => find_bytes(image, pat, start),
        Needle::Word(w) => find_bytes(image, &w.to_le_bytes(), start),
        Needle::FreeRun { len, align } => find_free_run(image, len, align, start),
    }
}

/// Overload: the first run of `>= len` free (`0xFF`) bytes at or after `start`
/// whose start offset is a multiple of `align`.
/// `find_free_space(image, len, align, start) ==
/// find(image, Needle::FreeRun { len, align }, start)`.
///
/// `align` is required rather than defaulted because there is no safe default.
/// Anything destined for [`Asm::finish`] needs 4, and an unaligned placement is
/// not diagnosed anywhere — the assembled code simply runs against the wrong
/// constants, because its pool offsets were computed for an aligned base. Pass
/// `1` to mean "raw data, alignment is irrelevant to me".
///
/// # Panics
///
/// Panics if `align` is 0.
pub fn find_free_space(image: &[u8], len: usize, align: usize, start: usize) -> Option<usize> {
    find(image, Needle::FreeRun { len, align }, start)
}

/// Read the little-endian u32 at `at` (e.g. a record's handler pointer).
pub fn read_u32(image: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([image[at], image[at + 1], image[at + 2], image[at + 3]])
}

/// Read the byte at `at`.
pub fn read_u8(image: &[u8], at: usize) -> u8 {
    image[at]
}

/// Read the little-endian u16 at `at`.
///
/// Present because a halfword is the unit a Thumb image is actually made of:
/// signature scans and instruction classification both want one, and without
/// this they open-code `u16::from_le_bytes([image[at], image[at + 1]])` at every
/// site. Panics on a short slice, exactly like [`read_u32`] and [`read_u8`];
/// use [`try_read_u16`] when the offset comes from a scan rather than from a
/// bounds-checked structure.
///
/// ```
/// let img = [0x34u8, 0x12];
/// assert_eq!(thumb_asm::read_u16(&img, 0), 0x1234);
/// ```
pub fn read_u16(image: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([image[at], image[at + 1]])
}

/// [`read_u8`] without the panic: `None` when `at` is past the end.
///
/// The three `try_read_*` functions exist for the scan-to-the-end case, where
/// the last legal offset is `len - size` and getting that bound wrong silently
/// drops the final match — which was a real bug in this crate's own
/// [`find_bl_sites`] before 0.2.0. Reaching for a checked read instead of
/// hand-rolling the bound is the fix that generalises.
///
/// ```
/// let img = [0xAAu8];
/// assert_eq!(thumb_asm::try_read_u8(&img, 0), Some(0xAA));
/// assert_eq!(thumb_asm::try_read_u8(&img, 1), None);
/// ```
pub fn try_read_u8(image: &[u8], at: usize) -> Option<u8> {
    image.get(at).copied()
}

/// [`read_u16`] without the panic: `None` unless all 2 bytes are in bounds.
///
/// ```
/// let img = [0x34u8, 0x12];
/// assert_eq!(thumb_asm::try_read_u16(&img, 0), Some(0x1234));
/// assert_eq!(thumb_asm::try_read_u16(&img, 1), None); // would run past the end
/// ```
pub fn try_read_u16(image: &[u8], at: usize) -> Option<u16> {
    // `checked_add`, not `at + 2`: the addition happens *before* `get` sees
    // it, so a near-`usize::MAX` offset overflows — a panic in debug, and in
    // release a wrapped range that can land back in bounds and silently return
    // the wrong bytes. The offsets here come from scans over attacker-supplied
    // firmware: a handler pointer read out of erased flash is `0xFFFF_FFFF`,
    // which masked to even is `0xFFFF_FFFE`, and on a 32-bit target that is
    // exactly the value that overflows. Not panicking is this function's whole
    // reason to exist.
    let b = image.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// [`read_u32`] without the panic: `None` unless all 4 bytes are in bounds.
///
/// ```
/// let img = [0x78u8, 0x56, 0x34, 0x12];
/// assert_eq!(thumb_asm::try_read_u32(&img, 0), Some(0x1234_5678));
/// assert_eq!(thumb_asm::try_read_u32(&img, 1), None);
/// ```
pub fn try_read_u32(image: &[u8], at: usize) -> Option<u32> {
    // `checked_add`, not `at + 4`: the addition happens *before* `get` sees
    // it, so a near-`usize::MAX` offset overflows — a panic in debug, and in
    // release a wrapped range that can land back in bounds and silently return
    // the wrong bytes. The offsets here come from scans over attacker-supplied
    // firmware: a handler pointer read out of erased flash is `0xFFFF_FFFF`,
    // which masked to even is `0xFFFF_FFFE`, and on a 32-bit target that is
    // exactly the value that overflows. Not panicking is this function's whole
    // reason to exist.
    let b = image.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Modify: overwrite `image[at..at+bytes.len()]` with `bytes`.
pub fn write(image: &mut [u8], at: usize, bytes: &[u8]) {
    image[at..at + bytes.len()].copy_from_slice(bytes);
}

/// Insert: copy `code` into free space at `free_off`, returning the image
/// address it now lives at (offset == load address on this flat mapping).
pub fn insert(image: &mut [u8], free_off: usize, code: &[u8]) -> u32 {
    write(image, free_off, code);
    free_off as u32
}

/// An opcode-dispatch table: an array of fixed-size records that firmware scans
/// by key until it finds a handler pointer to call. The shape recurs across
/// unrelated devices (SCSI/ATA command tables, vendor-command tables, ioctl and
/// AT-command jump tables), so this type stores only the *geometry* — where the
/// records start, how wide they are, and which byte of a record holds the
/// opcode, the flags and the handler pointer. The caller supplies those
/// numbers; [`CommandTable::find`], [`CommandTable::walk`] and
/// [`CommandTable::replace`] are generic over them.
///
/// **One worked example**, given because it makes the fields concrete rather
/// than because the crate assumes it: an MT1959 optical-drive scanner does
/// `ldrb [rec + opcode_off]` to match, then `ldr [rec + handler_off]; blx` to
/// dispatch, over records laid out `[opcode(1) | flags(1) | resv(2) |
/// handler(4 LE)]`. That table is described by `stride: 8`, `opcode_off: 0`,
/// `flags_off: 1`, `handler_off: 4`, and `term_flag: 0x03` for the record that
/// ends the scan. A different firmware with, say, 12-byte records and the
/// handler first is the same type with different numbers.
#[derive(Debug, Clone, Copy)]
pub struct CommandTable {
    /// File offset of the first record.
    pub base: usize,
    /// Bytes per record.
    pub stride: usize,
    /// Byte offset of the opcode within a record.
    pub opcode_off: usize,
    /// Byte offset of the flags byte within a record.
    pub flags_off: usize,
    /// Byte offset of the 4-byte LE handler pointer within a record.
    pub handler_off: usize,
    /// Flags value that marks the terminator record (scan stops here).
    pub term_flag: u8,
    /// Max records to scan before giving up (guards a corrupt/missing terminator).
    pub max_records: usize,
}

/// One resolved dispatch record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandRecord {
    /// File offset of the record.
    pub off: usize,
    /// The opcode it dispatches.
    pub opcode: u8,
    /// The record's flags byte.
    pub flags: u8,
    /// The handler pointer (Thumb bit as-stored; 0 = null / no handler).
    pub handler: u32,
}

impl CommandTable {
    /// `find(opcode)` — the record dispatching `opcode`, or `None` if absent
    /// (scan stops at the terminator, exactly like the drive's scanner).
    pub fn find(&self, image: &[u8], opcode: u8) -> Option<CommandRecord> {
        let mut off = self.base;
        for _ in 0..self.max_records {
            if off + self.stride > image.len() {
                return None;
            }
            let flags = image[off + self.flags_off];
            if flags == self.term_flag {
                return None; // reached terminator without a match
            }
            if image[off + self.opcode_off] == opcode {
                return Some(CommandRecord {
                    off,
                    opcode,
                    flags,
                    handler: read_u32(image, off + self.handler_off),
                });
            }
            off += self.stride;
        }
        None
    }

    /// `replace(record, newHandler)` — overwrite a record's handler pointer (and,
    /// if `flags` is `Some`, its flags byte). This is the hijack: point an
    /// existing opcode's dispatch at injected code. Prefer a record whose
    /// current handler is null (nothing runs today); repointing a live handler
    /// is allowed but the caller should warn.
    /// # Panics
    ///
    /// Panics if either field lies outside `image`. Both are checked *before*
    /// either is written, so a record too close to the end of a truncated image
    /// leaves the table untouched rather than half-repointed: the flags byte and
    /// the handler pointer are one logical edit, and a table whose flags say
    /// "live handler" while the pointer still says "null" is worse than one that
    /// was never touched. This mirrors the atomicity `detour` guarantees.
    pub fn replace(&self, image: &mut [u8], rec: &CommandRecord, handler: u32, flags: Option<u8>) {
        let flags_at = flags.map(|_| {
            rec.off
                .checked_add(self.flags_off)
                .expect("flags offset overflows")
        });
        let handler_at = rec
            .off
            .checked_add(self.handler_off)
            .expect("handler offset overflows");
        let handler_end = handler_at.checked_add(4).expect("handler field overflows");
        // `len` bound before the assertion rather than passed as a format
        // argument: an argument is only evaluated when the assertion fails, so
        // it is a branch no passing run can take.
        let len = image.len();
        assert!(
            handler_end <= len && flags_at.map_or(true, |a| a < len),
            "CommandTable::replace: record at {:#x} does not fit in a {len}-byte image",
            rec.off
        );
        if let (Some(f), Some(at)) = (flags, flags_at) {
            image[at] = f;
        }
        write(image, handler_at, &handler.to_le_bytes());
    }
}

impl CommandTable {
    /// Walk the table exactly as the firmware's own scanner does — following
    /// chain records (`flags == chain_flag`) to successor segments and stopping
    /// at the first terminator (`flags == term_flag`) — collecting every
    /// dispatch record. A chain record is one whose `flags` equal `chain_flag`
    /// and whose `handler` field is not a handler at all but the file offset of
    /// the next segment; that is how a table too big for one contiguous run is
    /// spelled (the MT1959 example above uses `chain_flag == 4`). Pass a
    /// `chain_flag` that no real record uses if the table has no segments.
    ///
    /// A `BTreeSet` of visited bases guards against a chain that loops back on
    /// itself, so a corrupt image costs a wasted scan rather than a hang.
    ///
    /// Returns the records in scan order. This is the grounded basis for
    /// [`CommandTable::find`]-style lookups when a table spans chained segments.
    pub fn walk(&self, image: &[u8], chain_flag: u8) -> Vec<CommandRecord> {
        let mut out = Vec::new();
        let mut base = self.base;
        let mut seen = std::collections::BTreeSet::new();
        // One budget for the whole walk, not one per segment. `max_records` is
        // documented as the number of records to scan before giving up, and a
        // cap applied separately to the outer chain and to each segment would
        // make the real bound its *square*: a crafted image that never presents
        // the terminator and chains through `max_records` distinct segments, each
        // holding `max_records` records, yields that many pushes. At a caller's
        // entirely reasonable `max_records` of 100_000 that is 10^10 records.
        let mut budget = self.max_records;
        for _ in 0..self.max_records {
            if !seen.insert(base) {
                break; // chain loop guard
            }
            let mut off = base;
            loop {
                if budget == 0 {
                    return out;
                }
                budget -= 1;
                // `checked_add`: `off` comes from a handler word read out of the
                // image, so it is attacker-controlled up to `u32::MAX`, and on a
                // 32-bit target `off + stride` can wrap back into bounds.
                match off.checked_add(self.stride) {
                    Some(end) if end <= image.len() => {}
                    _ => return out,
                }
                let flags = image[off + self.flags_off];
                if flags == self.term_flag {
                    return out;
                }
                let handler = read_u32(image, off + self.handler_off);
                if flags == chain_flag {
                    base = handler as usize; // next segment base
                    break;
                }
                out.push(CommandRecord {
                    off,
                    opcode: image[off + self.opcode_off],
                    flags,
                    handler,
                });
                off += self.stride;
            }
            // Reaching here means the inner loop hit a chain record and set the
            // next `base`; every other way out of it returns. The old
            // `advanced` flag existed because that loop could also fall through
            // by exhausting a per-segment counter — which the shared budget now
            // handles by returning, so the flag could no longer ever be false.
        }
        out
    }
}

/// Whether the Thumb code at file offset `off` begins with a `push {..., lr}`
/// (`0xB5xx`, A5.2.5) within the first `window` halfwords — a cheap "this is a
/// real function entry" cross-check. Used to reject a coincidental byte match
/// when resolving a handler pointer: a scan over every even offset can land
/// mid-instruction, and a plausible-looking hit that is not preceded by a
/// prologue usually is one of those.
pub fn prologue_is_push_lr(image: &[u8], off: usize, window: usize) -> bool {
    (0..window).any(|k| {
        let p = off + k * 2;
        p + 2 <= image.len() && (u16::from_le_bytes([image[p], image[p + 1]]) & 0xFF00) == 0xB500
    })
}

/// Error returned by [`Asm::finish`] when an encoded branch, `ldr` literal, or
/// `adr` falls outside what its Thumb encoding can represent, or when a label
/// was referenced but never bound.
///
/// # Using this with `anyhow`
///
/// `AsmError` is `Send + Sync + 'static` and implements [`std::error::Error`],
/// which is exactly the bound on `anyhow`'s own blanket
/// `impl<E: Error + Send + Sync + 'static> From<E> for anyhow::Error`. A bare
/// `?` on an `Asm::finish()` inside a function returning `anyhow::Result<_>`
/// therefore already compiles — no `.map_err(anyhow::Error::from)`, no wrapper
/// type, nothing to opt into.
///
/// That is also why this crate has no `anyhow` feature and cannot grow one: a
/// hand-written `impl From<AsmError> for anyhow::Error` would overlap `anyhow`'s
/// blanket impl and be rejected for coherence. The feature is not withheld, it
/// is unrepresentable — and unnecessary. The same holds for
/// [`InstallMismatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsmError(String);

impl core::fmt::Display for AsmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AsmError {}

/// A tiny position-independent Thumb assembler with a trailing 4-byte-aligned
/// literal pool — the "create" verb. It is *dumb*: it emits exactly the
/// instructions asked for and lays out `ldr rt, [pc, #imm]` literals in
/// first-reference order. An engine composes it; the toolkit never decides what
/// to assemble.
///
/// Placement invariant: the returned bytes assume a 4-byte-aligned load address
/// (so `Align(PC, 4)` for the pool matches the buffer-relative layout). Callers
/// must place the code at a 4-aligned offset.
#[derive(Default)]
pub struct Asm {
    code: Vec<u8>,
    ldrs: Vec<(usize, u32, u16)>,    // (insn byte pos, value, rt)
    fixups: Vec<(usize, u16, bool)>, // (insn pos, label, is_unconditional) branch
    adrs: Vec<(usize, u16)>,         // (insn pos, blob label) for `adr rd, blob`
    blobs: Vec<(u16, Vec<u8>)>,      // (label, data) appended after the pool
    labels: Vec<Option<usize>>,      // label id -> byte pos
    err: Option<AsmError>,           // first invalid operand; surfaced by finish()
}

impl Asm {
    /// A fresh, empty assembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current byte position (also a branch target).
    pub fn pos(&self) -> usize {
        self.code.len()
    }

    /// Record the first invalid operand. Later ones are dropped: the first is
    /// the one the caller has to fix, and a cascade of consequences obscures it.
    fn fail(&mut self, msg: String) {
        if self.err.is_none() {
            self.err = Some(AsmError(msg));
        }
    }

    /// `r` must be R0–R7. Most 16-bit Thumb encodings carry 3-bit register
    /// fields; a wider value silently overflows into the opcode and assembles
    /// to a different instruction.
    fn lo(&mut self, what: &str, field: &str, r: u16) {
        if r > 7 {
            self.fail(format!(
                "{what}: {field} must be a low register R0-R7, got r{r}"
            ));
        }
    }

    /// `r` must name some register, R0–R15.
    fn reg(&mut self, what: &str, field: &str, r: u16) {
        if r > 15 {
            self.fail(format!("{what}: {field} must be R0-R15, got r{r}"));
        }
    }

    /// `v` must be in `0..=max` and a multiple of `step` — the immediate is
    /// stored scaled, so an unaligned value loses its low bits and an oversized
    /// one runs into the neighbouring field.
    fn imm(&mut self, what: &str, v: u16, max: u16, step: u16) {
        if v > max {
            self.fail(format!("{what}: immediate {v} exceeds maximum {max}"));
        } else if step > 1 && v % step != 0 {
            self.fail(format!("{what}: immediate {v} is not a multiple of {step}"));
        }
    }

    /// A 16-bit `push`/`pop` register list: R0–R7 plus the one extra bit, and
    /// never empty (an empty list is UNPREDICTABLE, A7.7.99).
    fn reglist(&mut self, what: &str, extra: &str, list: u16) {
        if list == 0 {
            self.fail(format!("{what}: register list is empty"));
        } else if list > 0x1FF {
            self.fail(format!(
                "{what}: register list {list:#06x} has bits outside R0-R7 and {extra} (bit 8)"
            ));
        }
    }

    /// Reserve a label id; bind it later with [`Asm::bind`].
    pub fn label(&mut self) -> u16 {
        self.labels.push(None);
        (self.labels.len() - 1) as u16
    }

    /// Bind `label` to the current position.
    pub fn bind(&mut self, label: u16) {
        match self.labels.get_mut(label as usize) {
            Some(slot) => *slot = Some(self.code.len()),
            None => self.fail(format!("bind: label {label} was never reserved")),
        }
    }

    /// Emit a raw 16-bit Thumb instruction (little-endian).
    pub fn raw16(&mut self, insn: u16) {
        self.code.extend_from_slice(&insn.to_le_bytes());
    }

    /// `ldr rt, [pc, #imm]` loading `value` from the pool (dedup, first-ref order).
    pub fn ldr_lit(&mut self, rt: u16, value: u32) {
        self.lo("ldr_lit", "rt", rt);
        let pos = self.code.len();
        self.raw16(0x4800 | (rt << 8)); // patched in finish()
        self.ldrs.push((pos, value, rt));
    }

    /// `ldrb rt, [rn, #imm5]` (byte load, offset 0..31).
    pub fn ldrb_imm(&mut self, rt: u16, rn: u16, imm5: u16) {
        self.lo("ldrb_imm", "rt", rt);
        self.lo("ldrb_imm", "rn", rn);
        self.imm("ldrb_imm", imm5, 31, 1);
        self.raw16(0x7800 | (imm5 << 6) | (rn << 3) | rt);
    }

    /// `ldr rt, [rn, #imm]` (word load; `imm` must be a multiple of 4, 0..124).
    pub fn ldr_imm(&mut self, rt: u16, rn: u16, imm: u16) {
        self.lo("ldr_imm", "rt", rt);
        self.lo("ldr_imm", "rn", rn);
        self.imm("ldr_imm", imm, 124, 4);
        self.raw16(0x6800 | ((imm >> 2) << 6) | (rn << 3) | rt);
    }

    /// `strh rt, [rn, #imm]` (halfword store; `imm` must be even, 0..62).
    pub fn strh_imm(&mut self, rt: u16, rn: u16, imm: u16) {
        self.lo("strh_imm", "rt", rt);
        self.lo("strh_imm", "rn", rn);
        self.imm("strh_imm", imm, 62, 2);
        self.raw16(0x8000 | ((imm >> 1) << 6) | (rn << 3) | rt);
    }

    /// `str rt, [rn, #imm]` (word store; `imm` must be a multiple of 4, 0..124).
    pub fn str_imm(&mut self, rt: u16, rn: u16, imm: u16) {
        self.lo("str_imm", "rt", rt);
        self.lo("str_imm", "rn", rn);
        self.imm("str_imm", imm, 124, 4);
        self.raw16(0x6000 | ((imm >> 2) << 6) | (rn << 3) | rt);
    }

    /// `bics rd, rm` (bit-clear: `rd &= ~rm`).
    pub fn bics(&mut self, rd: u16, rm: u16) {
        self.lo("bics", "rd", rd);
        self.lo("bics", "rm", rm);
        self.raw16(0x4380 | (rm << 3) | rd);
    }

    /// `orrs rd, rm` (`rd |= rm`).
    pub fn orrs(&mut self, rd: u16, rm: u16) {
        self.lo("orrs", "rd", rd);
        self.lo("orrs", "rm", rm);
        self.raw16(0x4300 | (rm << 3) | rd);
    }

    /// `strb rt, [rn, #imm5]` (byte store, offset 0..31).
    pub fn strb_imm(&mut self, rt: u16, rn: u16, imm5: u16) {
        self.lo("strb_imm", "rt", rt);
        self.lo("strb_imm", "rn", rn);
        self.imm("strb_imm", imm5, 31, 1);
        self.raw16(0x7000 | (imm5 << 6) | (rn << 3) | rt);
    }

    /// `cmp rn, #imm8`.
    pub fn cmp_imm(&mut self, rn: u16, imm8: u8) {
        self.lo("cmp_imm", "rn", rn);
        self.raw16(0x2800 | (rn << 8) | imm8 as u16);
    }

    /// `cmp rn, rm` (low registers, data-processing form).
    pub fn cmp_reg(&mut self, rn: u16, rm: u16) {
        self.lo("cmp_reg", "rn", rn);
        self.lo("cmp_reg", "rm", rm);
        self.raw16(0x4280 | (rm << 3) | rn);
    }

    /// `movs rt, #imm8`.
    pub fn movs_imm(&mut self, rt: u16, imm8: u8) {
        self.lo("movs_imm", "rt", rt);
        self.raw16(0x2000 | (rt << 8) | imm8 as u16);
    }

    /// `push {reglist}` (bit 8 = lr). e.g. `push {lr}` = `0x0100`,
    /// `push {r0, r1, lr}` = `0x0103`. Must be non-empty and within R0-R7 + lr;
    /// anything else is an [`AsmError`] from [`Asm::finish`].
    pub fn push(&mut self, reglist: u16) {
        self.reglist("push", "lr", reglist);
        self.raw16(0xB400 | reglist);
    }

    /// `pop {reglist}` (bit 8 = pc). e.g. `pop {pc}` = `0x0100`,
    /// `pop {r0, r1, pc}` = `0x0103`. Must be non-empty and within R0-R7 + pc;
    /// anything else is an [`AsmError`] from [`Asm::finish`].
    pub fn pop(&mut self, reglist: u16) {
        self.reglist("pop", "pc", reglist);
        self.raw16(0xBC00 | reglist);
    }

    /// `blx rm`.
    pub fn blx(&mut self, rm: u16) {
        self.reg("blx", "rm", rm);
        if rm == 15 {
            self.fail("blx: rm must not be pc (UNPREDICTABLE, A7.7.20)".to_string());
        }
        self.raw16(0x4780 | (rm << 3));
    }

    /// `bx rm`.
    pub fn bx(&mut self, rm: u16) {
        self.reg("bx", "rm", rm);
        self.raw16(0x4700 | (rm << 3));
    }

    /// `b<cond> label` — the generic conditional branch (`B` T1, `1101 cond
    /// imm8`, A5.2.6), patched to a relative offset at [`Asm::finish`]. Range
    /// ±254 bytes from the branch; out of range is an [`AsmError`], never a
    /// truncated offset.
    ///
    /// [`Cond::Al`] is deliberately *not* encoded as `0b1110` here — in this
    /// encoding space `0b1110` is the permanently-undefined `UDF` and `0b1111`
    /// is `SVC`. `b_cond(Cond::Al, l)` emits the unconditional [`Asm::b`]
    /// instead, which is both what "branch always" means and what an assembler
    /// does with `bal`. As a bonus it gets the wider ±2046-byte range.
    ///
    /// The fourteen named wrappers ([`Asm::beq`], [`Asm::bne`], …) are one-line
    /// calls to this; use whichever reads better at the call site.
    pub fn b_cond(&mut self, cond: Cond, label: u16) {
        match cond {
            Cond::Al => self.b(label),
            c => {
                let pos = self.code.len();
                self.raw16(0xD000 | ((c.bits() as u16) << 8));
                self.fixups.push((pos, label, false));
            }
        }
    }

    /// `beq label` — equal, `Z == 1`.
    pub fn beq(&mut self, label: u16) {
        self.b_cond(Cond::Eq, label);
    }

    /// `bne label` — not equal, `Z == 0`.
    pub fn bne(&mut self, label: u16) {
        self.b_cond(Cond::Ne, label);
    }

    /// `bhs label` / `bcs` — unsigned ≥, `C == 1`.
    pub fn bhs(&mut self, label: u16) {
        self.b_cond(Cond::Hs, label);
    }

    /// `blo label` / `bcc` — unsigned <, `C == 0`.
    pub fn blo(&mut self, label: u16) {
        self.b_cond(Cond::Lo, label);
    }

    /// `bmi label` — negative, `N == 1`.
    pub fn bmi(&mut self, label: u16) {
        self.b_cond(Cond::Mi, label);
    }

    /// `bpl label` — positive or zero, `N == 0`.
    pub fn bpl(&mut self, label: u16) {
        self.b_cond(Cond::Pl, label);
    }

    /// `bvs label` — overflow set, `V == 1`.
    pub fn bvs(&mut self, label: u16) {
        self.b_cond(Cond::Vs, label);
    }

    /// `bvc label` — overflow clear, `V == 0`.
    pub fn bvc(&mut self, label: u16) {
        self.b_cond(Cond::Vc, label);
    }

    /// `bhi label` — unsigned >, `C == 1 && Z == 0`.
    pub fn bhi(&mut self, label: u16) {
        self.b_cond(Cond::Hi, label);
    }

    /// `bls label` — unsigned ≤, `C == 0 || Z == 1`.
    pub fn bls(&mut self, label: u16) {
        self.b_cond(Cond::Ls, label);
    }

    /// `bge label` — signed ≥, `N == V`.
    pub fn bge(&mut self, label: u16) {
        self.b_cond(Cond::Ge, label);
    }

    /// `blt label` — signed <, `N != V`.
    pub fn blt(&mut self, label: u16) {
        self.b_cond(Cond::Lt, label);
    }

    /// `bgt label` — signed >, `Z == 0 && N == V`.
    pub fn bgt(&mut self, label: u16) {
        self.b_cond(Cond::Gt, label);
    }

    /// `ble label` — signed ≤, `Z == 1 || N != V`.
    pub fn ble(&mut self, label: u16) {
        self.b_cond(Cond::Le, label);
    }

    /// `b label` (unconditional, 11-bit offset; `B` T2, A7.7.12). Range
    /// ±2046 bytes.
    pub fn b(&mut self, label: u16) {
        let pos = self.code.len();
        self.raw16(0xE000);
        self.fixups.push((pos, label, true));
    }

    /// `ldrb rt, [rn, rm]` (register-offset byte load).
    pub fn ldrb_reg(&mut self, rt: u16, rn: u16, rm: u16) {
        self.lo("ldrb_reg", "rt", rt);
        self.lo("ldrb_reg", "rn", rn);
        self.lo("ldrb_reg", "rm", rm);
        self.raw16(0x5C00 | (rm << 6) | (rn << 3) | rt);
    }

    /// `adds rt, #imm8`.
    pub fn adds_imm(&mut self, rt: u16, imm8: u8) {
        self.lo("adds_imm", "rt", rt);
        self.raw16(0x3000 | (rt << 8) | imm8 as u16);
    }

    /// `subs rt, #imm8`.
    pub fn subs_imm(&mut self, rt: u16, imm8: u8) {
        self.lo("subs_imm", "rt", rt);
        self.raw16(0x3800 | (rt << 8) | imm8 as u16);
    }

    /// `lsls rd, rm, #imm5` — `LSL (immediate)` T1, `0000 0 imm5 Rm Rd`
    /// (A5.2.1).
    ///
    /// Note the alias in the A5-2 footnote: `imm5 == 0` is *not* a zero-bit
    /// shift, it **is** `MOV (register)` T2 — `lsls_imm(rd, rm, 0)` assembles to
    /// the same halfword as [`Asm::movs_reg`]`(rd, rm)` and disassembles as
    /// `movs rd, rm`. Both set N/Z. Callers who mean the move should write the
    /// move.
    pub fn lsls_imm(&mut self, rd: u16, rm: u16, imm5: u16) {
        self.lo("lsls_imm", "rd", rd);
        self.lo("lsls_imm", "rm", rm);
        self.imm("lsls_imm", imm5, 31, 1);
        self.raw16((imm5 << 6) | (rm << 3) | rd);
    }

    /// `lsrs rd, rm, #imm5` (logical shift right). `imm5` is 0..=31, where
    /// `0` is not a zero-bit shift but encodes a shift of **32** (A7.7.71
    /// `DecodeImmShift`), leaving `rd` zeroed and C set from `rm`'s bit 31.
    pub fn lsrs_imm(&mut self, rd: u16, rm: u16, imm5: u16) {
        self.lo("lsrs_imm", "rd", rd);
        self.lo("lsrs_imm", "rm", rm);
        self.imm("lsrs_imm", imm5, 31, 1);
        self.raw16(0x0800 | (imm5 << 6) | (rm << 3) | rd);
    }

    /// `adds rd, rn, rm` (register).
    pub fn adds_reg(&mut self, rd: u16, rn: u16, rm: u16) {
        self.lo("adds_reg", "rd", rd);
        self.lo("adds_reg", "rn", rn);
        self.lo("adds_reg", "rm", rm);
        self.raw16(0x1800 | (rm << 6) | (rn << 3) | rd);
    }

    /// `mov rd, rm` — `MOV (register)` T1, `0100 0110 D Rm(4) Rd(3)`
    /// (A5.2.3 / A7.7.77), encoded `0x4600 | (d << 7) | (rm << 3) | (rd & 7)`
    /// where `d = (rd >> 3) & 1`.
    ///
    /// # Behaviour change in 0.2.0
    ///
    /// Through 0.1.0 this emitted `0x1C00 | rm << 3 | rd`, which is not `MOV` at
    /// all: it is `ADD (immediate)` T1 with `imm3 == 0` — i.e. `adds rd, rm, #0`
    /// — and **it writes N, Z, C and V**. Any sequence that moved a register
    /// between a `cmp` and its `b<cond>` was silently miscompiled, because the
    /// move destroyed the comparison's flags. T1 `MOV (register)` leaves the
    /// flags untouched, which is what a register move is expected to do.
    ///
    /// The new encoding also reaches the high registers: `rd` may be 0–15 (the
    /// `D` bit is `rd`'s bit 3), and `rm` is a full 4-bit field, so this is the
    /// only 16-bit way to move R8–R12, SP or LR. `mov pc, rm` (`rd == 15`) is a
    /// branch; the architecture permits it, and this helper will encode it, but
    /// prefer [`Asm::bx`] where a branch is what is meant.
    ///
    /// For the old flag-setting behaviour, ask for it by name: [`Asm::movs_reg`].
    pub fn mov_reg(&mut self, rd: u16, rm: u16) {
        self.reg("mov_reg", "rd", rd);
        self.reg("mov_reg", "rm", rm);
        self.raw16(0x4600 | ((rd & 8) << 4) | ((rm & 0xF) << 3) | (rd & 7));
    }

    /// `movs rd, rm` — `MOV (register)` T2, `0000 0000 00 Rm Rd` (A5.2.1 /
    /// A7.7.77), encoded `0x0000 | rm << 3 | rd`. Low registers only (R0–R7).
    ///
    /// Sets N and Z from the moved value and leaves C and V alone, per T2's
    /// `setflags = TRUE` pseudocode. This is the form 0.1.0's `mov_reg` was
    /// *reaching* for — a flag-setting register move — though it got there by a
    /// different instruction (`adds rd, rm, #0`, which also writes C and V).
    /// T2 is not permitted inside an IT block.
    ///
    /// Identical in encoding to `lsls rd, rm, #0`; see [`Asm::lsls_imm`].
    pub fn movs_reg(&mut self, rd: u16, rm: u16) {
        self.lo("movs_reg", "rd", rd);
        self.lo("movs_reg", "rm", rm);
        self.raw16((rm << 3) | rd);
    }

    /// `adr rd, blob` — position-independent load of a data blob's address
    /// (`add rd, pc, #imm`). The blob is declared with [`Asm::data_blob`].
    pub fn adr(&mut self, rd: u16, blob_label: u16) {
        self.lo("adr", "rd", rd);
        let pos = self.code.len();
        self.raw16(0xA000 | (rd << 8));
        self.adrs.push((pos, blob_label));
    }

    /// Declare a read-only data blob appended after the code+pool; returns a
    /// label usable with [`Asm::adr`]. Blobs are laid out 4-byte aligned.
    pub fn data_blob(&mut self, bytes: Vec<u8>) -> u16 {
        let label = self.label();
        self.blobs.push((label, bytes));
        label
    }

    /// Lay out the pool (4-aligned) then data blobs, and back-patch every branch,
    /// `ldr` literal, and `adr`.
    pub fn finish(mut self) -> Result<Vec<u8>, AsmError> {
        // 0. any operand rejected during emit. Reported before layout so the
        //    caller sees the cause, not a downstream symptom of the bad bytes.
        if let Some(e) = self.err.take() {
            return Err(e);
        }
        // 1. code-position branches (targets already bound during emit).
        for (pos, label, uncond) in core::mem::take(&mut self.fixups) {
            let target = self.labels[label as usize]
                .ok_or_else(|| AsmError(format!("unbound label {label}")))?;
            let off = (target as i32 - (pos as i32 + 4)) / 2;
            let enc = if uncond {
                if !(-1024..=1023).contains(&off) {
                    return Err(AsmError(format!("branch out of range ({off} halfwords)")));
                }
                0xE000u16 | (off as u16 & 0x07FF)
            } else {
                if !(-128..=127).contains(&off) {
                    return Err(AsmError(format!(
                        "conditional branch out of range ({off} halfwords)"
                    )));
                }
                let base = u16::from_le_bytes([self.code[pos], self.code[pos + 1]]) & 0xFF00;
                base | (off as i8 as u8 as u16)
            };
            self.code[pos..pos + 2].copy_from_slice(&enc.to_le_bytes());
        }
        // 2. literal pool (4-aligned), patch ldr.
        while self.code.len() % 4 != 0 {
            self.code.push(0x00);
        }
        let mut placed: Vec<(u32, u32)> = Vec::new();
        for (pos, value, rt) in core::mem::take(&mut self.ldrs) {
            // Linear scan is deliberate. The pool is laid out in first-reference
            // order, which this `Vec` is what preserves, and a realistic stub holds
            // a handful of distinct literals — the `Asm` type is documented as a
            // deliberately dumb assembler for trampolines, not a code generator.
            // It is O(n^2) in the number of *distinct* literals and would want an
            // index beside the `Vec` if that ever reached the thousands.
            let off = match placed.iter().find(|(v, _)| *v == value) {
                Some(&(_, o)) => o,
                None => {
                    let o = self.code.len() as u32;
                    self.code.extend_from_slice(&value.to_le_bytes());
                    placed.push((value, o));
                    o
                }
            };
            let pc = (pos as u32 + 4) & !3;
            let imm8 = (off - pc) / 4;
            if imm8 > 0xFF {
                return Err(AsmError(format!(
                    "ldr literal out of range (imm8 = {imm8})"
                )));
            }
            let enc = 0x4800u16 | (rt << 8) | imm8 as u16;
            self.code[pos..pos + 2].copy_from_slice(&enc.to_le_bytes());
        }
        // 3. data blobs (each 4-aligned); bind their labels.
        for (label, bytes) in core::mem::take(&mut self.blobs) {
            while self.code.len() % 4 != 0 {
                self.code.push(0x00);
            }
            self.labels[label as usize] = Some(self.code.len());
            self.code.extend_from_slice(&bytes);
        }
        // 4. adr fixups (blob labels now bound).
        for (pos, label) in core::mem::take(&mut self.adrs) {
            let target = self.labels[label as usize]
                .ok_or_else(|| AsmError(format!("unbound blob label {label}")))?;
            let base = (pos as u32 + 4) & !3;
            let imm = target as u32;
            if imm < base || (imm - base) % 4 != 0 || (imm - base) / 4 > 0xFF {
                return Err(AsmError(format!(
                    "adr target out of range (pos=0x{pos:x} target=0x{target:x})"
                )));
            }
            let enc = 0xA000u16
                | ((u16::from_le_bytes([self.code[pos], self.code[pos + 1]]) >> 8 & 7) << 8)
                | ((imm - base) / 4) as u16;
            self.code[pos..pos + 2].copy_from_slice(&enc.to_le_bytes());
        }
        Ok(self.code)
    }
}

/// Decode a Thumb `BL` at file offset `off` → its absolute target VA (Thumb bit
/// cleared). `None` if the 4 bytes at `off` are not a `BL`.
pub fn decode_bl(image: &[u8], off: usize) -> Option<u32> {
    let b = image.get(off..off.checked_add(4)?)?;
    let hw1 = u16::from_le_bytes([b[0], b[1]]);
    let hw2 = u16::from_le_bytes([b[2], b[3]]);
    if (hw1 & 0xF800) != 0xF000 || (hw2 & 0xD000) != 0xD000 {
        return None;
    }
    let s = ((hw1 >> 10) & 1) as u32;
    let imm10 = (hw1 & 0x3FF) as u32;
    let j1 = ((hw2 >> 13) & 1) as u32;
    let j2 = ((hw2 >> 11) & 1) as u32;
    let imm11 = (hw2 & 0x7FF) as u32;
    let i1 = (!(j1 ^ s)) & 1;
    let i2 = (!(j2 ^ s)) & 1;
    let mut imm = (imm11 | (imm10 << 11) | (i2 << 21) | (i1 << 22) | (s << 23)) << 1;
    if imm & (1 << 24) != 0 {
        imm |= !0u32 << 25;
    }
    Some((off as u32).wrapping_add(4).wrapping_add(imm))
}

/// Encode a Thumb `BL` at file offset `site` that calls absolute target `target`
/// (Thumb bit is implicit; pass the even entry address). Returns the 4 bytes, or
/// `None` if `target` is out of `BL` range (±16 MiB).
pub fn encode_bl(site: usize, target: u32) -> Option<[u8; 4]> {
    let pc = (site as u32).wrapping_add(4);
    let off = (target.wrapping_sub(pc)) as i32;
    if !(-(1 << 24)..(1 << 24)).contains(&off) || off & 1 != 0 {
        return None;
    }
    let imm = (off >> 1) as u32 & 0x00ff_ffff;
    let s = (imm >> 23) & 1;
    let i1 = (imm >> 22) & 1;
    let i2 = (imm >> 21) & 1;
    let imm10 = (imm >> 11) & 0x3ff;
    let imm11 = imm & 0x7ff;
    let j1 = (!(i1 ^ s)) & 1;
    let j2 = (!(i2 ^ s)) & 1;
    let hw1 = 0xF000 | (s << 10) as u16 | imm10 as u16;
    let hw2 = 0xD000 | (j1 << 13) as u16 | (j2 << 11) as u16 | imm11 as u16;
    let mut out = [0u8; 4];
    out[0..2].copy_from_slice(&hw1.to_le_bytes());
    out[2..4].copy_from_slice(&hw2.to_le_bytes());
    Some(out)
}

/// Encode a Thumb-2 **wide unconditional branch** (`B.W`, T4 encoding) at file
/// offset `site` that jumps to absolute target `target` (Thumb bit implicit;
/// pass the even entry address). Same 4-byte width and same imm packing as
/// [`encode_bl`] — the only difference is `hw2`'s base (`0x9000` for `B.W`
/// instead of `0xD000` for `BL`, i.e. bit 14 cleared). Same ±16 MiB range.
///
/// Use this over `encode_bl` when the site being patched sits at a **tail-call
/// idiom** (OEM `b <shared_leaf>` returned to the OUTER function's caller via
/// the shared leaf's `bx lr`). A `bl` install would clobber the outer function's
/// `lr` with `site+4`, so the shared leaf's `bx lr` would land inside the outer
/// function instead of at its caller — running code the OEM never reaches on
/// that path. `B.W` preserves `lr` unchanged, so the tail-call semantics are
/// exact.
pub fn encode_b_wide(site: usize, target: u32) -> Option<[u8; 4]> {
    let pc = (site as u32).wrapping_add(4);
    let off = (target.wrapping_sub(pc)) as i32;
    if !(-(1 << 24)..(1 << 24)).contains(&off) || off & 1 != 0 {
        return None;
    }
    let imm = (off >> 1) as u32 & 0x00ff_ffff;
    let s = (imm >> 23) & 1;
    let i1 = (imm >> 22) & 1;
    let i2 = (imm >> 21) & 1;
    let imm10 = (imm >> 11) & 0x3ff;
    let imm11 = imm & 0x7ff;
    let j1 = (!(i1 ^ s)) & 1;
    let j2 = (!(i2 ^ s)) & 1;
    let hw1 = 0xF000 | (s << 10) as u16 | imm10 as u16;
    let hw2 = 0x9000 | (j1 << 13) as u16 | (j2 << 11) as u16 | imm11 as u16;
    let mut out = [0u8; 4];
    out[0..2].copy_from_slice(&hw1.to_le_bytes());
    out[2..4].copy_from_slice(&hw2.to_le_bytes());
    Some(out)
}

/// Decode a Thumb-2 `B.W` (T4) at `off` and return its absolute target (Thumb
/// bit cleared), or `None` if the two halfwords there are not a `B.W`. Mirror
/// of [`decode_bl`] but discriminates on the `hw2` bit-12=1 && bit-14=0 pattern
/// (`B.W`) vs bit-12=1 && bit-14=1 (`BL`).
pub fn decode_b_wide(image: &[u8], at: usize) -> Option<u32> {
    // `checked_add`, not `at + 4`: `at` is routinely a scan offset derived from
    // image content, and on a 32-bit target the sum can wrap back into bounds
    // and read the wrong four bytes. Same rule as `try_read_u32`.
    if at.checked_add(4).map_or(true, |end| end > image.len()) {
        return None;
    }
    let hw1 = u16::from_le_bytes([image[at], image[at + 1]]);
    let hw2 = u16::from_le_bytes([image[at + 2], image[at + 3]]);
    // `hw1 = 11110 S imm10` and `hw2 = 10 J1 0 J2 imm11` (B.W T4).
    if (hw1 & 0xF800) != 0xF000 || (hw2 & 0xD000) != 0x9000 {
        return None;
    }
    let s = ((hw1 >> 10) & 1) as u32;
    let imm10 = (hw1 & 0x3FF) as u32;
    let j1 = ((hw2 >> 13) & 1) as u32;
    let j2 = ((hw2 >> 11) & 1) as u32;
    let imm11 = (hw2 & 0x7FF) as u32;
    let i1 = (!(j1 ^ s)) & 1;
    let i2 = (!(j2 ^ s)) & 1;
    let mut imm = (imm11 | (imm10 << 11) | (i2 << 21) | (i1 << 22) | (s << 23)) << 1;
    if imm & (1 << 24) != 0 {
        imm |= !0u32 << 25;
    }
    Some((at as u32).wrapping_add(4).wrapping_add(imm))
}

/// Every file offset holding a Thumb `BL` whose target is `target` (Thumb bit
/// ignored). These are the direct call sites that reach a handler — the thing to
/// redirect when a firmware dispatches by hardcoded call rather than a table.
///
/// The scan is every even offset with room for four bytes, so the last site
/// considered is `len - 4`. (Through 0.1.0 the bound was
/// `len.saturating_sub(4)` used *exclusively*, which stopped one site short and
/// missed a `BL` occupying the final four bytes of an image — the case where a
/// dispatch table or trailing thunk sits right at the end.)
///
/// Being a blind even-offset scan, it can in principle match four bytes that
/// are really the tail of some other instruction; corroborate a hit with
/// [`prologue_is_push_lr`] on its target when that matters.
pub fn find_bl_sites(image: &[u8], target: u32) -> Vec<usize> {
    let want = target & !1;
    (0..image.len().saturating_sub(3))
        .step_by(2)
        .filter(|&off| decode_bl(image, off).map(|t| t & !1) == Some(want))
        .collect()
}

/// A decoded conditional branch: which condition, where it goes, and how wide
/// the instruction was.
///
/// Produced by [`decode_b_cond`], which resolves both the 16-bit T1 and the
/// 32-bit T3 encodings into this one shape so a caller can step over the
/// instruction (`at + len`) without caring which it found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CondBranch {
    /// The branch condition.
    pub cond: Cond,
    /// Absolute target offset in the image (`at + 4 + imm32`), Thumb bit not
    /// set — this is a file offset in the same flat space as `at`.
    pub target: u32,
    /// Instruction width in bytes: 2 for T1, 4 for T3.
    pub len: usize,
}

/// Decode the conditional branch at `at`, in either encoding, or `None` if the
/// bytes there are not one.
///
/// # T1 — 16-bit, `1101 cond imm8` (A5.2.6, A7.7.12)
///
/// `target = at + 4 + SignExtend(imm8:'0')`, so ±254 bytes.
///
/// **`0b1101xxxx` is not all branches.** Per Table A5-8, `cond == 0b1110` is
/// the permanently UNDEFINED `UDF` (A7.7.194) and `cond == 0b1111` is `SVC`
/// (A7.7.175) — a supervisor call, which transfers control somewhere entirely
/// unrelated to any `imm8`-relative target. Neither is a branch, so this
/// function returns `None` for `0xDE**` and `0xDF**`. Code that treats
/// `0xD0xx..=0xDFxx` as the conditional-branch range is wrong for exactly those
/// two sixteenths of it, and will read an `SVC #n` as a branch to `at + 4 + 2n`.
/// The correct range is `0xD0xx..=0xDDxx`.
///
/// # T3 — 32-bit, `hw1 = 11110 S cond imm6`, `hw2 = 10 J1 0 J2 imm11` (A5.3.4)
///
/// Matched by `(hw1 & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0x8000`, with
/// `target = at + 4 + SignExtend(S:J2:J1:imm6:imm11:'0')` — ±1 MB.
///
/// Mind the packing: T3 is **not** the `BL`/`B.W` scheme. Those pack
/// `S:I1:I2:imm10:imm11` with `I1 = NOT(J1 EOR S)` and `I2 = NOT(J2 EOR S)`;
/// T3 packs `S:J2:J1:imm6:imm11` — J2 and J1 in the opposite order, used
/// directly with no inversion, over a 6-bit rather than 10-bit high field.
/// Reusing [`decode_bl`]'s arithmetic here produces a plausible, wrong target.
/// (Verified against ARM DDI 0403E.e A7.7.12 and DDI 0406C A8.8.18.)
///
/// `cond<3:1> == 0b111` in T3 is "see Related encodings" — `MSR`/`MRS`, hints,
/// `UDF.W`, `BL` — so, as in T1, both `0b1110` and `0b1111` decode as `None`.
///
/// ```
/// use thumb_asm::{decode_b_cond, Cond};
///
/// // `bmi` T1 at offset 0, reaching 0x20: 0xD40E.
/// let b = decode_b_cond(&[0x0E, 0xD4], 0).unwrap();
/// assert_eq!((b.cond, b.target, b.len), (Cond::Mi, 0x20, 2));
///
/// // `UDF` and `SVC` share the space but are not branches.
/// assert!(decode_b_cond(&[0x00, 0xDE], 0).is_none());
/// assert!(decode_b_cond(&[0x00, 0xDF], 0).is_none());
/// ```
pub fn decode_b_cond(image: &[u8], at: usize) -> Option<CondBranch> {
    let hw1 = try_read_u16(image, at)?;

    // T1: 1101 cond imm8.
    if (hw1 & 0xF000) == 0xD000 {
        // 0xDE** is UDF and 0xDF** is SVC: `Cond::from_bits` rejects 0b1111
        // outright, and 0b1110 comes back as `Al`, which this space cannot
        // encode. Both are "not a branch".
        let cond = match Cond::from_bits(((hw1 >> 8) & 0xF) as u8) {
            Some(c) if c != Cond::Al => c,
            _ => return None,
        };
        let imm = ((hw1 & 0xFF) as u8 as i8 as i32) * 2;
        return Some(CondBranch {
            cond,
            target: (at as u32).wrapping_add(4).wrapping_add(imm as u32),
            len: 2,
        });
    }

    // T3: hw1 = 11110 S cond imm6, hw2 = 10 J1 0 J2 imm11.
    let hw2 = try_read_u16(image, at + 2)?;
    if (hw1 & 0xF800) != 0xF000 || (hw2 & 0xD000) != 0x8000 {
        return None;
    }
    // `cond<3:1> == 0b111` is "see Related encodings" — MSR/MRS, hints, UDF.W,
    // BL — so again neither 0b1110 (`Al`) nor 0b1111 is a branch here.
    let cond = match Cond::from_bits(((hw1 >> 6) & 0xF) as u8) {
        Some(c) if c != Cond::Al => c,
        _ => return None,
    };
    let s = ((hw1 >> 10) & 1) as u32;
    let imm6 = (hw1 & 0x3F) as u32;
    let j1 = ((hw2 >> 13) & 1) as u32;
    let j2 = ((hw2 >> 11) & 1) as u32;
    let imm11 = (hw2 & 0x7FF) as u32;
    let mut imm = (imm11 | (imm6 << 11) | (j1 << 17) | (j2 << 18) | (s << 19)) << 1;
    if imm & (1 << 20) != 0 {
        imm |= !0u32 << 21;
    }
    Some(CondBranch {
        cond,
        target: (at as u32).wrapping_add(4).wrapping_add(imm),
        len: 4,
    })
}

/// Encode a conditional branch at file offset `site` to absolute `target`,
/// choosing the narrowest encoding that reaches: 2 bytes (T1, ±254) if it fits,
/// else 4 bytes (T3, ±1 MB), else `None`.
///
/// `None` also for an odd displacement (Thumb instructions are halfword
/// aligned) and for [`Cond::Al`], which **has no conditional-branch encoding**:
/// `0b1110` is `UDF` in T1 and a different instruction class in T3 (see
/// [`decode_b_cond`]). Emit [`encode_b_wide`] — or a 16-bit `B` T2 — for an
/// unconditional branch.
///
/// Round-trips with [`decode_b_cond`] for every value it accepts.
///
/// ```
/// use thumb_asm::{encode_b_cond, Cond};
///
/// assert_eq!(encode_b_cond(0, Cond::Mi, 0x20), Some(vec![0x0E, 0xD4]));
/// // Too far for T1, so T3: `bmi.w` +0x10000.
/// assert_eq!(
///     encode_b_cond(0x1000, Cond::Mi, 0x1_1004),
///     Some(vec![0x10, 0xF1, 0x00, 0x80])
/// );
/// assert_eq!(encode_b_cond(0, Cond::Al, 0x20), None); // no such encoding
/// ```
pub fn encode_b_cond(site: usize, cond: Cond, target: u32) -> Option<Vec<u8>> {
    if cond == Cond::Al {
        return None;
    }
    let bits = cond.bits() as u16;
    let pc = (site as u32).wrapping_add(4);
    let off = target.wrapping_sub(pc) as i32;
    if off & 1 != 0 {
        return None;
    }
    // T1: 1101 cond imm8, offsets -256..=254 (A7.7.12).
    if (-256..=254).contains(&off) {
        let hw = 0xD000u16 | (bits << 8) | ((off >> 1) as i8 as u8 as u16);
        return Some(hw.to_le_bytes().to_vec());
    }
    // T3: S:J2:J1:imm6:imm11, offsets -1048576..=1048574 (A7.7.12).
    if !(-1_048_576..=1_048_574).contains(&off) {
        return None;
    }
    let imm = (off >> 1) as u32 & 0xF_FFFF;
    let s = (imm >> 19) & 1;
    let j2 = (imm >> 18) & 1;
    let j1 = (imm >> 17) & 1;
    let imm6 = (imm >> 11) & 0x3F;
    let imm11 = imm & 0x7FF;
    let hw1 = 0xF000u16 | (s as u16) << 10 | (bits << 6) | imm6 as u16;
    let hw2 = 0x8000u16 | (j1 as u16) << 13 | (j2 as u16) << 11 | imm11 as u16;
    let mut out = Vec::with_capacity(4);
    out.extend_from_slice(&hw1.to_le_bytes());
    out.extend_from_slice(&hw2.to_le_bytes());
    Some(out)
}

/// Which 4-byte branch a detour site is patched with.
///
/// Both members are 32-bit and ±16 MB, and differ only in whether `lr` is
/// written; see [`encode_b_wide`] for when that distinction decides a patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchKind {
    /// `BL` (T1) — a call: sets `lr` to `site + 4`, so the callee returns here.
    Bl,
    /// `B.W` (T4) — a jump: leaves `lr` untouched, so the callee returns to
    /// whatever called *this* function. The right choice at a tail call.
    BWide,
}

impl BranchKind {
    /// Encode a branch of this kind at `site` to `target`, or `None` if the
    /// displacement is out of range or odd. Thin dispatch over [`encode_bl`]
    /// and [`encode_b_wide`].
    pub fn encode(self, site: usize, target: u32) -> Option<[u8; 4]> {
        match self {
            BranchKind::Bl => encode_bl(site, target),
            BranchKind::BWide => encode_b_wide(site, target),
        }
    }

    /// Decode a branch of this kind at `at` to its absolute target, or `None`
    /// if the four bytes there are not one. Thin dispatch over [`decode_bl`]
    /// and [`decode_b_wide`].
    pub fn decode(self, image: &[u8], at: usize) -> Option<u32> {
        match self {
            BranchKind::Bl => decode_bl(image, at),
            BranchKind::BWide => decode_b_wide(image, at),
        }
    }
}

impl core::fmt::Display for BranchKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            BranchKind::Bl => "bl",
            BranchKind::BWide => "b.w",
        })
    }
}

/// The four bytes at a detour site do not branch where they were meant to.
///
/// Returned by [`verify_branch`] and [`install_branch`]. `expected` and `found`
/// are both stored with bit 0 cleared, so a caller can print or compare them
/// without re-deriving the Thumb-bit convention (see [`verify_branch`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallMismatch {
    /// File offset that was checked.
    pub site: usize,
    /// The branch kind that was expected there.
    pub kind: BranchKind,
    /// The intended target, Thumb bit masked off.
    pub expected: u32,
    /// What actually decodes there, Thumb bit masked off — or `None` if the
    /// bytes are not a branch of that kind at all (which is also what
    /// [`install_branch`] reports when `expected` was out of range and so
    /// nothing was written).
    pub found: Option<u32>,
}

impl core::fmt::Display for InstallMismatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self {
            site,
            kind,
            expected,
            found,
        } = self;
        match found {
            Some(got) => write!(
                f,
                "{kind} at 0x{site:x}: expected target 0x{expected:08x}, found 0x{got:08x}"
            ),
            None => write!(
                f,
                "{kind} at 0x{site:x}: expected target 0x{expected:08x}, \
                 but no {kind} decodes there"
            ),
        }
    }
}

impl std::error::Error for InstallMismatch {}

/// Confirm that the four bytes at `site` are a `kind` branch to `expected`.
///
/// This is the check every consumer of this crate ends up writing by hand after
/// patching a detour site: encode, write, then *decode the image back* and
/// prove the bytes now mean what was intended. Decoding back is what catches a
/// truncated displacement, a half-written patch, or a site that was never four
/// bytes of branch to begin with — none of which the encoder can see.
///
/// # The Thumb bit
///
/// Branch targets in a Thumb image are routinely carried with bit 0 set, since
/// that is the form `bx`/`blx` and a function pointer need. The *encoded*
/// displacement has no room for it: `BL` and `B.W` targets are halfword
/// aligned, so bit 0 is always zero on the way out of a decoder. This function
/// therefore masks bit 0 off **both** sides before comparing, and `expected`
/// may be passed in either form. If a caller needs to distinguish `0x1234` from
/// `0x1235` it is not asking about a branch target.
pub fn verify_branch(
    image: &[u8],
    site: usize,
    kind: BranchKind,
    expected: u32,
) -> Result<(), InstallMismatch> {
    let expected = expected & !1;
    let found = kind.decode(image, site).map(|t| t & !1);
    if found == Some(expected) {
        Ok(())
    } else {
        Err(InstallMismatch {
            site,
            kind,
            expected,
            found,
        })
    }
}

/// Encode a `kind` branch from `site` to `target`, write it into `image`, and
/// verify by decoding it back — the whole install-a-detour pattern in one call.
///
/// Fails, writing nothing, when the displacement is out of range for `kind`,
/// when it is odd, or when `site` has fewer than four bytes after it; the
/// returned [`InstallMismatch`] has `found: None` in each case. Bit 0 of
/// `target` is masked off, so a Thumb-bit-carrying address may be passed
/// directly — see [`verify_branch`].
///
/// The trailing verification is not paranoia about this crate's own encoder: it
/// is what makes the operation *self-checking at the byte level*, so a caller
/// that later re-runs it over an already-patched image, or over an image some
/// other tool touched, gets a definite answer rather than a silent overwrite.
///
/// ```
/// use thumb_asm::{decode_bl, install_branch, verify_branch, BranchKind};
///
/// let mut image = vec![0u8; 0x100];
/// install_branch(&mut image, 0x10, BranchKind::Bl, 0x81).unwrap(); // Thumb bit ok
/// assert_eq!(decode_bl(&image, 0x10), Some(0x80));
/// assert!(verify_branch(&image, 0x10, BranchKind::Bl, 0x80).is_ok());
///
/// // Wrong kind at the same site: a `bl` is not a `b.w`.
/// let err = verify_branch(&image, 0x10, BranchKind::BWide, 0x80).unwrap_err();
/// assert_eq!(err.found, None);
/// ```
pub fn install_branch(
    image: &mut [u8],
    site: usize,
    kind: BranchKind,
    target: u32,
) -> Result<(), InstallMismatch> {
    let target = target & !1;
    let fail = || InstallMismatch {
        site,
        kind,
        expected: target,
        found: None,
    };
    if site.checked_add(4).map_or(true, |end| end > image.len()) {
        return Err(fail());
    }
    let bytes = kind.encode(site, target).ok_or_else(fail)?;
    write(image, site, &bytes);
    verify_branch(image, site, kind, target)
}

// --- internal matchers (the actual scans behind `find`) ---

fn find_bytes(image: &[u8], pat: &[u8], start: usize) -> Option<usize> {
    if pat.is_empty() || start >= image.len() {
        return None;
    }
    image[start..]
        .windows(pat.len())
        .position(|w| w == pat)
        .map(|p| p + start)
}

fn find_free_run(image: &[u8], len: usize, align: usize, start: usize) -> Option<usize> {
    assert!(align != 0, "alignment must be at least 1 byte");
    let mut p = round_up(start.min(image.len()), align);
    loop {
        // `checked_add`, because `len` is the caller's and may be enormous;
        // a saturated `p` fails this test too, which is why `round_up` can
        // saturate rather than report.
        if p.checked_add(len).map_or(true, |end| end > image.len()) {
            return None;
        }
        // Test the whole window at an aligned start, rather than finding a run
        // and aligning after the fact: aligning afterwards moves the start
        // without moving the end, so it can reject a run that had the room.
        match image[p..p + len].iter().position(|&b| b != 0xFF) {
            None => return Some(p),
            // The byte at `p + k` is live, so no window starting at or before it
            // can work; resume at the first aligned offset past it.
            Some(k) => p = round_up(p + k + 1, align),
        }
    }
}

/// `v` rounded up to the next multiple of `align`, saturating.
///
/// Saturation rather than an `Option` because the overflow it would report
/// cannot happen here and the caller does not need it to: `v` is always bounded
/// by the image length, and for `v < align` the result is exactly `align`,
/// while `v >= align` would need an `align` near `usize::MAX` *and* an image of
/// comparable size. Were it ever to saturate anyway, the `p + len > image.len()`
/// test at the only call site rejects the result, so the failure mode is
/// "no free space found" rather than a wrong offset.
fn round_up(v: usize, align: usize) -> usize {
    match v % align {
        0 => v,
        r => v.saturating_add(align - r),
    }
}

#[cfg(test)]
#[path = "thumb_tests.rs"]
mod tests;
