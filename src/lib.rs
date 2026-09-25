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
//! ARM DDI 0406B, Armv7-A/R).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod analysis;
mod cond;
pub mod detour;
pub mod flags;
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
///
/// `#[non_exhaustive]`: a `match` on this in a downstream crate must carry a
/// `_` arm, so a future search kind is an addition rather than a breaking
/// change. That was not true before 0.11.0, and adding [`Needle::Masked`] is
/// what cost the minor bump.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
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
    /// An instruction pattern with don't-care bits: a slice of
    /// `(value, mask)` halfword pairs, matching where
    /// `halfword & mask == value & mask` for every pair in order.
    ///
    /// This is how a signature is actually written. "Any `BL`" is
    /// `(0xF000, 0xF800)` — the five bits that identify the encoding fixed and
    /// the eleven displacement bits ignored — and searching for it with
    /// [`Needle::Bytes`] is not possible at all, because the bytes differ at
    /// every call site.
    ///
    /// **Matches are halfword-aligned.** Thumb instructions are 2-aligned, so
    /// a match at an odd offset is not an instruction; scanning every byte
    /// offset would report plausible-looking hits straddling two real
    /// instructions. The scan starts at the first even offset at or after
    /// `start`.
    ///
    /// An empty pattern matches nothing rather than matching everywhere: a
    /// needle that is satisfied by any position is a mistake in the caller,
    /// and returning the start offset would hide it.
    ///
    /// ```
    /// use thumb_asm::{find, Needle};
    ///
    /// // `bl` to somewhere, preceded by `movs r0, #1`.
    /// let image = [0x01, 0x20, 0xFF, 0xF7, 0xFE, 0xFF];
    /// let any_bl = [(0xF000u16, 0xF800u16), (0xD000, 0xD000)];
    /// assert_eq!(find(&image, Needle::Masked(&any_bl), 0), Some(2));
    /// ```
    Masked(&'a [(u16, u16)]),
}

/// The one search primitive. Find `needle` at or after byte offset `start`;
/// return the offset of the match, or `None`. Every named finder below is a
/// thin overload of this call.
pub fn find(image: &[u8], needle: Needle, start: usize) -> Option<usize> {
    match needle {
        Needle::Bytes(pat) => find_bytes(image, pat, start),
        Needle::Word(w) => find_bytes(image, &w.to_le_bytes(), start),
        Needle::FreeRun { len, align } => find_free_run(image, len, align, start),
        Needle::Masked(pat) => find_masked(image, pat, start),
    }
}

/// [`find`], confined to a window of the image.
///
/// Scoping a search is not a convenience, it is how an otherwise-ambiguous
/// signature becomes usable. A pattern that matches three places in a whole
/// image may match exactly once inside the region you care about, and without
/// a bound [`find_one`] can only be used where the pattern happens to be
/// unique across everything — which is the case that never needed it.
///
/// The match must lie **entirely** within `range`: a signature half outside
/// the window is not in the window.
///
/// `range` is half-open (`0x90000..0xb0000` excludes `0xb0000`) and is in
/// **image coordinates**. That matters, and is why this exists rather than
/// leaving callers to slice: alignment is measured from the image origin, so
/// [`Needle::Masked`]'s halfword boundaries and [`Needle::FreeRun`]'s `align`
/// mean the same thing inside a window as outside one. Slicing the image at an
/// odd or unaligned offset and searching the slice silently moves that origin.
///
/// ```
/// use thumb_asm::{find, find_in, Needle};
///
/// // The same two bytes twice; the window is what tells them apart.
/// let image = [0x01, 0x20, 0x70, 0x47, 0x01, 0x20];
/// assert_eq!(find(&image, Needle::Bytes(&[0x01, 0x20]), 0), Some(0));
/// assert_eq!(find_in(&image, Needle::Bytes(&[0x01, 0x20]), 2..6), Some(4));
///
/// // Entirely within: a match starting at 4 does not fit in `0..5`.
/// assert_eq!(find_in(&image, Needle::Bytes(&[0x01, 0x20]), 4..5), None);
/// ```
pub fn find_in(image: &[u8], needle: Needle, range: core::ops::Range<usize>) -> Option<usize> {
    let (lo, hi) = (range.start, range.end.min(image.len()));
    if lo >= hi {
        return None;
    }
    match needle {
        Needle::Bytes(pat) => find_bytes_in(image, pat, lo, hi),
        Needle::Word(w) => find_bytes_in(image, &w.to_le_bytes(), lo, hi),
        Needle::FreeRun { len, align } => find_free_run_in(image, len, align, lo, hi),
        Needle::Masked(pat) => find_masked_in(image, pat, lo, hi),
    }
}

/// How many bytes one occurrence of `needle` spans, for advancing past a match.
fn needle_len(needle: Needle) -> usize {
    match needle {
        Needle::Bytes(pat) => pat.len(),
        Needle::Word(_) => 4,
        Needle::FreeRun { len, .. } => len,
        Needle::Masked(pat) => pat.len() * 2,
    }
}

/// Why [`find_one`] did not return an offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FindError {
    /// Nothing matched.
    NotFound,
    /// More than one thing matched.
    Ambiguous {
        /// How many non-overlapping occurrences were found.
        count: usize,
        /// The offset of the first, for diagnostics — so a message can say
        /// *where* the search became ambiguous rather than only that it did.
        first: usize,
    },
}

impl FindError {
    /// A stable, machine-readable reason: `"not-found"` or `"ambiguous"`.
    ///
    /// Every error type in this crate carries one, so a caller can branch on
    /// the cause without matching variants it would have to update when a new
    /// one appears (these enums are `#[non_exhaustive]` precisely so that new
    /// ones can appear).
    ///
    /// # Labelling a failure
    ///
    /// There is deliberately no `context` or `label` on this type. A
    /// `&'static str` would not take a label built at run time, and a `String`
    /// would make the error allocate on a path that is often in a loop. Both
    /// fields a caller needs to write its own message are public, so the
    /// wrapper this replaces is one line:
    ///
    /// ```
    /// use thumb_asm::{find_one, FindError, Needle};
    ///
    /// let image = [0u8; 8];
    /// let what = "cmac table";
    /// let msg = match find_one(&image, Needle::Word(0xdead_beef)) {
    ///     Ok(at) => format!("{what} at {at:#x}"),
    ///     Err(e @ FindError::Ambiguous { count, .. }) => {
    ///         format!("{what} signature matched {count} times ({e})")
    ///     }
    ///     Err(e) => format!("{what}: {e}"),
    /// };
    /// assert_eq!(msg, "cmac table: no match");
    /// ```
    pub fn reason(&self) -> &'static str {
        match self {
            FindError::NotFound => "not-found",
            FindError::Ambiguous { .. } => "ambiguous",
        }
    }
}

impl core::fmt::Display for FindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FindError::NotFound => f.write_str("no match"),
            FindError::Ambiguous { count, first } => {
                write!(f, "{count} matches, first at {first:#x}")
            }
        }
    }
}

impl std::error::Error for FindError {}

/// Find `needle` and require that it occurs exactly once.
///
/// [`find`] returns the first match, which is the right answer when you are
/// scanning. It is the wrong answer when you are *identifying* something: a
/// signature that matches three places in a firmware image has not found the
/// function you meant, it has told you the signature is too weak. Taking the
/// first one and patching it is how a device gets bricked by a tool that
/// reported success.
///
/// So this refuses to choose. `Err(FindError::Ambiguous { count, first })`
/// carries both the count and the first offset, so a caller can say what
/// happened without repeating the search.
///
/// Occurrences are counted **non-overlapping**: after a match the scan resumes
/// one needle-length later. For [`Needle::FreeRun`] that makes the count the
/// number of disjoint free windows, which is rarely a useful question — use
/// [`find_free_space_in`] to place something instead.
///
/// ```
/// use thumb_asm::{find_one, FindError, Needle};
///
/// let image = [0x01, 0x20, 0x01, 0x20];
/// assert_eq!(
///     find_one(&image, Needle::Bytes(&[0x01, 0x20])),
///     Err(FindError::Ambiguous { count: 2, first: 0 })
/// );
/// assert_eq!(find_one(&image, Needle::Bytes(&[0x70, 0x47])), Err(FindError::NotFound));
/// assert_eq!(find_one(&image, Needle::Word(0x2001_2001)), Ok(0));
/// ```
pub fn find_one(image: &[u8], needle: Needle) -> Result<usize, FindError> {
    find_one_in(image, needle, 0..image.len())
}

/// [`find_one`], confined to a window of the image.
///
/// This is the pairing that makes either function useful on real firmware.
/// Uniqueness is a property of a signature *and a region*, not of a signature
/// alone: scoping to the range you already know the function lives in is what
/// turns a pattern that matches three times across the image into one that
/// matches once where it matters. Requiring global uniqueness would restrict
/// this to signatures strong enough not to need checking.
///
/// `range` is half-open and in image coordinates, with the same reasoning as
/// [`find_in`]; matches must lie entirely inside it.
///
/// ```
/// use thumb_asm::{find_one, find_one_in, FindError, Needle};
///
/// let image = [0x01, 0x20, 0x70, 0x47, 0x01, 0x20];
/// let movs = Needle::Bytes(&[0x01, 0x20]);
///
/// // Ambiguous across the whole image...
/// assert_eq!(find_one(&image, movs), Err(FindError::Ambiguous { count: 2, first: 0 }));
/// // ...and unique inside the window you meant.
/// assert_eq!(find_one_in(&image, movs, 2..6), Ok(4));
/// ```
pub fn find_one_in(
    image: &[u8],
    needle: Needle,
    range: core::ops::Range<usize>,
) -> Result<usize, FindError> {
    let step = needle_len(needle).max(1);
    let hi = range.end.min(image.len());
    let first = match find_in(image, needle, range.start..hi) {
        Some(p) => p,
        None => return Err(FindError::NotFound),
    };
    let mut count = 1;
    let mut at = first;
    while let Some(next) = at
        .checked_add(step)
        .and_then(|from| find_in(image, needle, from..hi))
    {
        count += 1;
        at = next;
    }
    if count == 1 {
        Ok(first)
    } else {
        Err(FindError::Ambiguous { count, first })
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
            // `checked_add`, not `off + self.stride`: `base` and `stride` are
            // the caller's, so their sum can overflow. In debug that panics;
            // in release it wraps to a small number that passes the `>` test,
            // and the indexing below then reads from an offset the check was
            // supposed to have refused. `walk` below has always used
            // `checked_add` — this is the same guard, which `find` was
            // missing.
            let end = off.checked_add(self.stride)?;
            if end > image.len() {
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
#[non_exhaustive]
pub enum AsmError {
    /// An operand the requested encoding cannot hold: a low-register field
    /// with a high register in it, an immediate outside the encoding's
    /// range, a `blx` with `pc` as its argument, and so on. Reported at
    /// [`Asm::finish`] with the byte position of the emitter that failed.
    Operand {
        /// Byte position in the code buffer where the emitter tried to write.
        at: usize,
        /// Human-readable diagnostic naming the operand and the limit.
        msg: String,
    },
    /// The encoding an emitter produces is not defined on the assembler's
    /// [`isa::Target`]. Introduced in 0.14.0 alongside `Asm::with_target`;
    /// the only in-crate emitter that raises it today is `sdiv`/`udiv`
    /// under [`Target::V7A`](isa::Target::V7A) or
    /// [`Target::V7AR`](isa::Target::V7AR), plus `raw16` and `raw32` over
    /// bytes their target's decoder does not accept.
    Unsupported {
        /// Byte position in the code buffer where the refused emit happened.
        at: usize,
        /// Static mnemonic the emitter identifies as, e.g. `"sdiv"`.
        mnemonic: &'static str,
        /// The target the assembler was built for.
        target: isa::Target,
    },
    /// A layout-time failure: an unbound or never-reserved label, a branch
    /// whose displacement is out of range for its encoding, a literal-pool
    /// entry too far away for `ldr pc-relative`'s 8-bit immediate, or an
    /// `adr` whose blob sits before it. These are the diagnostics
    /// [`Asm::finish`] can only report after every emitter has run — the
    /// mistake is not a bad operand, it is a missing (or geometrically
    /// impossible) call the caller has to add or move.
    Layout {
        /// Byte position of the emitter whose fix-up could not be resolved
        /// (for branches / `adr` / `ldr` literals). Zero for
        /// never-reserved-label diagnostics that have no code position.
        at: usize,
        /// Human-readable diagnostic naming what went wrong.
        msg: String,
    },
}

impl AsmError {
    /// A stable, machine-readable reason: `"operand"`, `"unsupported"`, or
    /// `"layout"`. Consumers branch on this to distinguish "the operand is
    /// wrong" (fixable at the emitter's arguments) from "the encoding is not
    /// legal on this target" (fixable by changing the target or the
    /// emitter) from "the layout does not close" (fixable at the caller's
    /// label / branch / pool geometry).
    pub fn reason(&self) -> &'static str {
        match self {
            AsmError::Operand { .. } => "operand",
            AsmError::Unsupported { .. } => "unsupported",
            AsmError::Layout { .. } => "layout",
        }
    }

    /// Byte position in the code buffer this error refers to. Zero for
    /// never-reserved-label diagnostics that have no code position.
    pub fn at(&self) -> usize {
        match self {
            AsmError::Operand { at, .. }
            | AsmError::Unsupported { at, .. }
            | AsmError::Layout { at, .. } => *at,
        }
    }
}

impl core::fmt::Display for AsmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AsmError::Operand { msg, .. } => f.write_str(msg),
            AsmError::Unsupported {
                mnemonic, target, ..
            } => write!(
                f,
                "{mnemonic}: not defined on {target:?} (encoder-side legality \
                 gate refused it)"
            ),
            AsmError::Layout { msg, .. } => f.write_str(msg),
        }
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
    target: isa::Target,             // profile this buffer is being built for
}

impl Asm {
    /// A fresh, empty assembler targeting [`isa::Target::Union`] — the historical
    /// default, which accepts every profile's encodings.
    ///
    /// For a chip-specific buffer where the encoder must refuse instructions the
    /// target does not define, use [`Asm::with_target`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Build for a specific ISA target. Emitters whose encoding is not defined on
    /// `target` fail at the call site — the resulting `Err` surfaces from
    /// [`Asm::finish`] with the exact mnemonic and byte position of the refused
    /// emitter, and the buffer up to that point is discarded on the next
    /// [`Asm::finish`] because the assembler resets itself.
    ///
    /// The default [`Asm::new`] is `with_target(Target::Union)`, which is the
    /// crate's historical byte-for-byte behaviour.
    ///
    /// ```
    /// use thumb_asm::{Asm, isa::Target};
    /// // A V8M buffer emitting a Security Gateway pattern via raw32 — accepted.
    /// let mut a = Asm::with_target(Target::V8M);
    /// a.raw32(0xE97F, 0xE97F);
    /// assert!(a.finish().is_ok());
    /// ```
    pub fn with_target(target: isa::Target) -> Self {
        Self {
            target,
            ..Self::default()
        }
    }

    /// The [`isa::Target`] this buffer is being built for.
    pub fn target(&self) -> isa::Target {
        self.target
    }

    /// Current byte position (also a branch target).
    pub fn pos(&self) -> usize {
        self.code.len()
    }

    /// Record the first invalid operand. Later ones are dropped: the first is
    /// the one the caller has to fix, and a cascade of consequences obscures it.
    fn fail(&mut self, msg: String) {
        if self.err.is_none() {
            self.err = Some(AsmError::Operand {
                at: self.code.len(),
                msg,
            });
        }
    }

    /// Record the first target-legality failure. Same first-wins semantics as
    /// [`Asm::fail`] — one class of error, one report.
    fn fail_target(&mut self, mnemonic: &'static str) {
        if self.err.is_none() {
            self.err = Some(AsmError::Unsupported {
                at: self.code.len(),
                mnemonic,
                target: self.target,
            });
        }
    }

    /// Consult the per-profile legality table for `(mnemonic, form)` and
    /// record an [`AsmError::Unsupported`] on this assembler if the target
    /// does not accept it. Under [`Target::Union`](isa::Target::Union) this
    /// is a no-op (Union is permissive by design); every other target routes
    /// through [`isa::legality::defined_on`].
    ///
    /// Call **after** every operand check (`lo`/`reg`/`imm`/…) and after
    /// cond validation, so an operand or condition error still surfaces as
    /// the primary cause rather than being masked by a downstream
    /// "not defined on target" that the caller cannot act on.
    fn check_target(
        &mut self,
        mnemonic: &'static str,
        form: isa::legality::EncForm,
        extra: isa::legality::OpExtra,
    ) {
        if self.target == isa::Target::Union {
            return;
        }
        if !isa::legality::defined_on(mnemonic, form, self.target, extra) {
            self.fail_target(mnemonic);
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
    pub fn bind(&mut self, label: u16) -> &mut Self {
        match self.labels.get_mut(label as usize) {
            Some(slot) => *slot = Some(self.code.len()),
            None => self.fail(format!("bind: label {label} was never reserved")),
        }
        self
    }

    /// The internal 16-bit writer. Every emitter appends here; this is the one
    /// choke point that consumes the operand-formed halfword and stops it being
    /// second-guessed downstream. Public [`Asm::raw16`] delegates to this after
    /// running the target-legality gate for non-`Union` targets.
    fn emit16(&mut self, insn: u16) {
        self.code.extend_from_slice(&insn.to_le_bytes());
    }

    /// The internal 32-bit writer for wide (Thumb-2) encodings — halfword-order
    /// `hw1` then `hw2`, each little-endian, matching [`encode_bl`]'s byte layout.
    fn emit32(&mut self, hw1: u16, hw2: u16) {
        self.code.extend_from_slice(&hw1.to_le_bytes());
        self.code.extend_from_slice(&hw2.to_le_bytes());
    }

    /// Emit a raw 16-bit Thumb instruction (little-endian).
    ///
    /// # Under [`Target::Union`](isa::Target::Union)
    ///
    /// Byte-for-byte unchanged from pre-0.14: any halfword goes in the
    /// buffer. This is the historical contract callers depended on.
    ///
    /// # Under any non-`Union` target
    ///
    /// The rule is *bytes as this chip reads them*. The decoder itself is
    /// authoritative for what a target's CPU makes of the halfword — Armv8-M
    /// CMSE and ThumbEE state both reassign patterns Armv7 uses for
    /// something else — so `raw16` runs [`isa::decode_at_with`] under
    /// `self.target` on the two-byte slice and, if the decoder returns
    /// `Some(insn)`, consults [`isa::legality::defined_on`] with the
    /// recovered `(mnemonic, encoding form)` pair.
    ///
    /// - `insn_len(insn) == 4` (a wide-instruction prefix) is refused
    ///   distinctly, pointing at [`Asm::raw32`] or
    ///   [`Asm::raw16_unchecked`]. This is the isolated
    ///   `raw16(0xF400)`-style case: the second halfword is missing, so
    ///   the target decoder cannot recover the mnemonic.
    /// - `decode_at_with` returns `None` (the halfword is UNDEFINED on
    ///   this target) → `AsmError::Unsupported { mnemonic: "raw16", .. }`.
    /// - `defined_on` returns `false` for the recovered mnemonic → same.
    /// - Otherwise the halfword is written.
    ///
    /// Use [`Asm::raw16_unchecked`] to bypass every check.
    pub fn raw16(&mut self, insn: u16) -> &mut Self {
        if self.target == isa::Target::Union {
            self.emit16(insn);
            return self;
        }
        if isa::insn_len(insn) == 4 {
            if self.err.is_none() {
                self.err = Some(AsmError::Unsupported {
                    at: self.code.len(),
                    mnemonic: "raw16",
                    target: self.target,
                });
            }
            // Emit the byte anyway to keep pos() consistent for later
            // fixups; finish() will still refuse to hand back bytes.
            self.emit16(insn);
            return self;
        }
        let bytes = insn.to_le_bytes();
        match isa::decode_at_with(&bytes, 0, 0, self.target) {
            Some(decoded) => {
                let form = isa::legality::EncForm::from(decoded.encoding);
                if isa::legality::defined_on(
                    decoded.mnemonic,
                    form,
                    self.target,
                    isa::legality::OpExtra::Plain,
                ) {
                    self.emit16(insn);
                } else {
                    // Report under the decoded mnemonic so the caller sees
                    // what the chip actually reads these bytes as — the
                    // "raw" contract in the docstring.
                    self.fail_target(decoded.mnemonic);
                    self.emit16(insn);
                }
            }
            None => {
                self.fail_target("raw16");
                self.emit16(insn);
            }
        }
        self
    }

    /// Emit two halfwords of a wide Thumb-2 instruction (`hw1` then `hw2`,
    /// little-endian each).
    ///
    /// Same rule as [`Asm::raw16`] under non-Union: decode under
    /// `self.target`, then look the recovered mnemonic up in the legality
    /// table. Under [`Target::Union`](isa::Target::Union) the bytes are
    /// written unchanged.
    ///
    /// # Example: SG on V8M
    ///
    /// ```
    /// use thumb_asm::{Asm, isa::Target};
    /// // Security Gateway T1 (ARM ARM CMSE) — halfwords 0xE97F 0xE97F.
    /// // Accepted under V8M because the V8M decoder recovers `sg`, which
    /// // the legality table accepts; refused under V7A because that
    /// // decoder recovers `ldrd`, which the legality table does accept
    /// // there — this is the "bytes as this chip reads them" contract.
    /// let mut a = Asm::with_target(Target::V8M);
    /// a.raw32(0xE97F, 0xE97F);
    /// assert!(a.finish().is_ok());
    /// ```
    pub fn raw32(&mut self, hw1: u16, hw2: u16) -> &mut Self {
        if self.target == isa::Target::Union {
            self.emit32(hw1, hw2);
            return self;
        }
        // `to_le_bytes` on each halfword rather than hand-masking with `& 0xFF`
        // and `>> 8`: the manual form generated four provably-equivalent mutants
        // (`&`→`|`, `>>`→`<<`) whose effect on the decoded mnemonic is only
        // observable through operand-discriminated legality, which the table
        // does not yet consult (OpExtra::Plain everywhere in 0.14.0). This
        // spelling has no mutant surface for those bit ops.
        let hw1_le = hw1.to_le_bytes();
        let hw2_le = hw2.to_le_bytes();
        let bytes = [hw1_le[0], hw1_le[1], hw2_le[0], hw2_le[1]];
        match isa::decode_at_with(&bytes, 0, 0, self.target) {
            Some(decoded) => {
                let form = isa::legality::EncForm::from(decoded.encoding);
                if isa::legality::defined_on(
                    decoded.mnemonic,
                    form,
                    self.target,
                    isa::legality::OpExtra::Plain,
                ) {
                    self.emit32(hw1, hw2);
                } else {
                    self.fail_target(decoded.mnemonic);
                    self.emit32(hw1, hw2);
                }
            }
            None => {
                self.fail_target("raw32");
                self.emit32(hw1, hw2);
            }
        }
        self
    }

    /// Emit any 16-bit halfword, bypassing every legality check. The explicit
    /// escape hatch for hand-encoded CMSE / ThumbEE / new-Cortex-M patterns that
    /// this crate has no emitter for yet — the caller has taken responsibility
    /// for the bytes.
    pub fn raw16_unchecked(&mut self, insn: u16) -> &mut Self {
        self.emit16(insn);
        self
    }

    /// `ldr rt, [pc, #imm]` loading `value` from the pool (dedup, first-ref order).
    pub fn ldr_lit(&mut self, rt: u16, value: u32) -> &mut Self {
        self.lo("ldr_lit", "rt", rt);
        let pos = self.code.len();
        self.emit16(0x4800 | (rt << 8)); // patched in finish()
        self.ldrs.push((pos, value, rt));
        self
    }

    /// `ldrb rt, [rn, #imm5]` (byte load, offset 0..31).
    pub fn ldrb_imm(&mut self, rt: u16, rn: u16, imm5: u16) -> &mut Self {
        self.lo("ldrb_imm", "rt", rt);
        self.lo("ldrb_imm", "rn", rn);
        self.imm("ldrb_imm", imm5, 31, 1);
        self.emit16(0x7800 | (imm5 << 6) | (rn << 3) | rt);
        self
    }

    /// `ldr rt, [rn, #imm]` (word load; `imm` must be a multiple of 4, 0..124).
    pub fn ldr_imm(&mut self, rt: u16, rn: u16, imm: u16) -> &mut Self {
        self.lo("ldr_imm", "rt", rt);
        self.lo("ldr_imm", "rn", rn);
        self.imm("ldr_imm", imm, 124, 4);
        self.emit16(0x6800 | ((imm >> 2) << 6) | (rn << 3) | rt);
        self
    }

    /// `strh rt, [rn, #imm]` (halfword store; `imm` must be even, 0..62).
    pub fn strh_imm(&mut self, rt: u16, rn: u16, imm: u16) -> &mut Self {
        self.lo("strh_imm", "rt", rt);
        self.lo("strh_imm", "rn", rn);
        self.imm("strh_imm", imm, 62, 2);
        self.emit16(0x8000 | ((imm >> 1) << 6) | (rn << 3) | rt);
        self
    }

    /// `str rt, [rn, #imm]` (word store; `imm` must be a multiple of 4, 0..124).
    pub fn str_imm(&mut self, rt: u16, rn: u16, imm: u16) -> &mut Self {
        self.lo("str_imm", "rt", rt);
        self.lo("str_imm", "rn", rn);
        self.imm("str_imm", imm, 124, 4);
        self.emit16(0x6000 | ((imm >> 2) << 6) | (rn << 3) | rt);
        self
    }

    /// `bics rd, rm` (bit-clear: `rd &= ~rm`).
    pub fn bics(&mut self, rd: u16, rm: u16) -> &mut Self {
        self.lo("bics", "rd", rd);
        self.lo("bics", "rm", rm);
        self.emit16(0x4380 | (rm << 3) | rd);
        self
    }

    /// `orrs rd, rm` (`rd |= rm`).
    pub fn orrs(&mut self, rd: u16, rm: u16) -> &mut Self {
        self.lo("orrs", "rd", rd);
        self.lo("orrs", "rm", rm);
        self.emit16(0x4300 | (rm << 3) | rd);
        self
    }

    /// `strb rt, [rn, #imm5]` (byte store, offset 0..31).
    pub fn strb_imm(&mut self, rt: u16, rn: u16, imm5: u16) -> &mut Self {
        self.lo("strb_imm", "rt", rt);
        self.lo("strb_imm", "rn", rn);
        self.imm("strb_imm", imm5, 31, 1);
        self.emit16(0x7000 | (imm5 << 6) | (rn << 3) | rt);
        self
    }

    /// `cmp rn, #imm8`.
    pub fn cmp_imm(&mut self, rn: u16, imm8: u8) -> &mut Self {
        self.lo("cmp_imm", "rn", rn);
        self.emit16(0x2800 | (rn << 8) | imm8 as u16);
        self
    }

    /// `cmp rn, rm` (low registers, data-processing form).
    pub fn cmp_reg(&mut self, rn: u16, rm: u16) -> &mut Self {
        self.lo("cmp_reg", "rn", rn);
        self.lo("cmp_reg", "rm", rm);
        self.emit16(0x4280 | (rm << 3) | rn);
        self
    }

    /// `movs rt, #imm8`.
    pub fn movs_imm(&mut self, rt: u16, imm8: u8) -> &mut Self {
        self.lo("movs_imm", "rt", rt);
        self.emit16(0x2000 | (rt << 8) | imm8 as u16);
        self
    }

    /// `push {reglist}` (bit 8 = lr). e.g. `push {lr}` = `0x0100`,
    /// `push {r0, r1, lr}` = `0x0103`. Must be non-empty and within R0-R7 + lr;
    /// anything else is an [`AsmError`] from [`Asm::finish`].
    pub fn push(&mut self, reglist: u16) -> &mut Self {
        self.reglist("push", "lr", reglist);
        self.emit16(0xB400 | reglist);
        self
    }

    /// `pop {reglist}` (bit 8 = pc). e.g. `pop {pc}` = `0x0100`,
    /// `pop {r0, r1, pc}` = `0x0103`. Must be non-empty and within R0-R7 + pc;
    /// anything else is an [`AsmError`] from [`Asm::finish`].
    pub fn pop(&mut self, reglist: u16) -> &mut Self {
        self.reglist("pop", "pc", reglist);
        self.emit16(0xBC00 | reglist);
        self
    }

    /// `blx rm`.
    pub fn blx(&mut self, rm: u16) -> &mut Self {
        self.reg("blx", "rm", rm);
        if rm == 15 {
            self.fail("blx: rm must not be pc (UNPREDICTABLE, A7.7.20)".to_string());
        }
        self.emit16(0x4780 | (rm << 3));
        self
    }

    /// `bx rm`.
    pub fn bx(&mut self, rm: u16) -> &mut Self {
        self.reg("bx", "rm", rm);
        self.emit16(0x4700 | (rm << 3));
        self
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
    pub fn b_cond(&mut self, cond: Cond, label: u16) -> &mut Self {
        match cond {
            Cond::Al => self.b(label),
            c => {
                let pos = self.code.len();
                self.emit16(0xD000 | ((c.bits() as u16) << 8));
                self.fixups.push((pos, label, false));
                self
            }
        }
    }

    /// `beq label` — equal, `Z == 1`.
    pub fn beq(&mut self, label: u16) -> &mut Self {
        self.b_cond(Cond::Eq, label)
    }

    /// `bne label` — not equal, `Z == 0`.
    pub fn bne(&mut self, label: u16) -> &mut Self {
        self.b_cond(Cond::Ne, label)
    }

    /// `bhs label` / `bcs` — unsigned ≥, `C == 1`.
    pub fn bhs(&mut self, label: u16) -> &mut Self {
        self.b_cond(Cond::Hs, label)
    }

    /// `blo label` / `bcc` — unsigned <, `C == 0`.
    pub fn blo(&mut self, label: u16) -> &mut Self {
        self.b_cond(Cond::Lo, label)
    }

    /// `bmi label` — negative, `N == 1`.
    pub fn bmi(&mut self, label: u16) -> &mut Self {
        self.b_cond(Cond::Mi, label)
    }

    /// `bpl label` — positive or zero, `N == 0`.
    pub fn bpl(&mut self, label: u16) -> &mut Self {
        self.b_cond(Cond::Pl, label)
    }

    /// `bvs label` — overflow set, `V == 1`.
    pub fn bvs(&mut self, label: u16) -> &mut Self {
        self.b_cond(Cond::Vs, label)
    }

    /// `bvc label` — overflow clear, `V == 0`.
    pub fn bvc(&mut self, label: u16) -> &mut Self {
        self.b_cond(Cond::Vc, label)
    }

    /// `bhi label` — unsigned >, `C == 1 && Z == 0`.
    pub fn bhi(&mut self, label: u16) -> &mut Self {
        self.b_cond(Cond::Hi, label)
    }

    /// `bls label` — unsigned ≤, `C == 0 || Z == 1`.
    pub fn bls(&mut self, label: u16) -> &mut Self {
        self.b_cond(Cond::Ls, label)
    }

    /// `bge label` — signed ≥, `N == V`.
    pub fn bge(&mut self, label: u16) -> &mut Self {
        self.b_cond(Cond::Ge, label)
    }

    /// `blt label` — signed <, `N != V`.
    pub fn blt(&mut self, label: u16) -> &mut Self {
        self.b_cond(Cond::Lt, label)
    }

    /// `bgt label` — signed >, `Z == 0 && N == V`.
    pub fn bgt(&mut self, label: u16) -> &mut Self {
        self.b_cond(Cond::Gt, label)
    }

    /// `ble label` — signed ≤, `Z == 1 || N != V`.
    pub fn ble(&mut self, label: u16) -> &mut Self {
        self.b_cond(Cond::Le, label)
    }

    /// `b label` (unconditional, 11-bit offset; `B` T2, A7.7.12). Range
    /// ±2046 bytes.
    pub fn b(&mut self, label: u16) -> &mut Self {
        let pos = self.code.len();
        self.emit16(0xE000);
        self.fixups.push((pos, label, true));
        self
    }

    /// `ldrb rt, [rn, rm]` (register-offset byte load).
    pub fn ldrb_reg(&mut self, rt: u16, rn: u16, rm: u16) -> &mut Self {
        self.lo("ldrb_reg", "rt", rt);
        self.lo("ldrb_reg", "rn", rn);
        self.lo("ldrb_reg", "rm", rm);
        self.emit16(0x5C00 | (rm << 6) | (rn << 3) | rt);
        self
    }

    /// `adds rt, #imm8`.
    pub fn adds_imm(&mut self, rt: u16, imm8: u8) -> &mut Self {
        self.lo("adds_imm", "rt", rt);
        self.emit16(0x3000 | (rt << 8) | imm8 as u16);
        self
    }

    /// `subs rt, #imm8`.
    pub fn subs_imm(&mut self, rt: u16, imm8: u8) -> &mut Self {
        self.lo("subs_imm", "rt", rt);
        self.emit16(0x3800 | (rt << 8) | imm8 as u16);
        self
    }

    /// `lsls rd, rm, #imm5` — `LSL (immediate)` T1, `0000 0 imm5 Rm Rd`
    /// (A5.2.1).
    ///
    /// Note the alias in the A5-2 footnote: `imm5 == 0` is *not* a zero-bit
    /// shift, it **is** `MOV (register)` T2 — `lsls_imm(rd, rm, 0)` assembles to
    /// the same halfword as [`Asm::movs_reg`]`(rd, rm)` and disassembles as
    /// `movs rd, rm`. Both set N/Z. Callers who mean the move should write the
    /// move.
    pub fn lsls_imm(&mut self, rd: u16, rm: u16, imm5: u16) -> &mut Self {
        self.lo("lsls_imm", "rd", rd);
        self.lo("lsls_imm", "rm", rm);
        self.imm("lsls_imm", imm5, 31, 1);
        self.emit16((imm5 << 6) | (rm << 3) | rd);
        self
    }

    /// `lsrs rd, rm, #imm5` (logical shift right). `imm5` is 0..=31, where
    /// `0` is not a zero-bit shift but encodes a shift of **32** (A7.7.71
    /// `DecodeImmShift`), leaving `rd` zeroed and C set from `rm`'s bit 31.
    pub fn lsrs_imm(&mut self, rd: u16, rm: u16, imm5: u16) -> &mut Self {
        self.lo("lsrs_imm", "rd", rd);
        self.lo("lsrs_imm", "rm", rm);
        self.imm("lsrs_imm", imm5, 31, 1);
        self.emit16(0x0800 | (imm5 << 6) | (rm << 3) | rd);
        self
    }

    /// `adds rd, rn, rm` (register).
    pub fn adds_reg(&mut self, rd: u16, rn: u16, rm: u16) -> &mut Self {
        self.lo("adds_reg", "rd", rd);
        self.lo("adds_reg", "rn", rn);
        self.lo("adds_reg", "rm", rm);
        self.emit16(0x1800 | (rm << 6) | (rn << 3) | rd);
        self
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
    pub fn mov_reg(&mut self, rd: u16, rm: u16) -> &mut Self {
        self.reg("mov_reg", "rd", rd);
        self.reg("mov_reg", "rm", rm);
        self.emit16(0x4600 | ((rd & 8) << 4) | ((rm & 0xF) << 3) | (rd & 7));
        self
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
    pub fn movs_reg(&mut self, rd: u16, rm: u16) -> &mut Self {
        self.lo("movs_reg", "rd", rd);
        self.lo("movs_reg", "rm", rm);
        self.emit16((rm << 3) | rd);
        self
    }

    /// `sdiv rd, rn, rm` — signed integer divide, `SDIV` T1
    /// (ARM ARM A8.8.165). Wide (32-bit) Thumb-2 encoding.
    ///
    /// # Target legality
    ///
    /// `SDIV` is UNDEFINED on Armv7-A but mandatory on Armv7-R and every
    /// Armv7-M / Armv7E-M / Armv8-M profile. Under
    /// [`Target::V7A`](isa::Target::V7A) or
    /// [`Target::V7AR`](isa::Target::V7AR) (the strict intersection),
    /// [`Asm::finish`] returns `AsmError::Unsupported { mnemonic: "sdiv", .. }`.
    /// Under [`Target::Union`](isa::Target::Union) — the default — it emits
    /// unconditionally, matching the crate's pre-0.14 behaviour.
    ///
    /// # Operands
    ///
    /// `Rd`, `Rn`, `Rm` are 4-bit register fields. `PC` (r15) is
    /// UNPREDICTABLE and `SP` (r13) is refused for the same reason as
    /// [`Asm::blx`]'s guard on r15 — a decoder can accept them, but the
    /// hardware behaviour is unspecified. This helper reports either as
    /// [`AsmError::Operand`].
    pub fn sdiv(&mut self, rd: u16, rn: u16, rm: u16) -> &mut Self {
        self.divmod_wide("sdiv", 0xFB90, rd, rn, rm);
        self
    }

    /// `udiv rd, rn, rm` — unsigned integer divide, `UDIV` T1
    /// (ARM ARM A8.8.267). Same encoding shape and same target legality
    /// story as [`Asm::sdiv`].
    pub fn udiv(&mut self, rd: u16, rn: u16, rm: u16) -> &mut Self {
        self.divmod_wide("udiv", 0xFBB0, rd, rn, rm);
        self
    }

    /// Shared body of `sdiv`/`udiv` — same operand-validation, same target
    /// check, same 4-byte encoding shape, only the base of `hw1` changes
    /// (`0xFB90` for signed, `0xFBB0` for unsigned; both keep the `0xF0F0 |
    /// (Rd << 8) | Rm` layout for `hw2`).
    fn divmod_wide(&mut self, mnemonic: &'static str, hw1_base: u16, rd: u16, rn: u16, rm: u16) {
        self.reg(mnemonic, "rd", rd);
        self.reg(mnemonic, "rn", rn);
        self.reg(mnemonic, "rm", rm);
        for (field, r) in [("rd", rd), ("rn", rn), ("rm", rm)] {
            if r == 13 || r == 15 {
                self.fail(format!(
                    "{mnemonic}: {field} = r{r} is UNPREDICTABLE (SP/PC), refuse rather than emit"
                ));
            }
        }
        self.check_target(
            mnemonic,
            isa::legality::EncForm::T1,
            isa::legality::OpExtra::Plain,
        );
        let hw1 = hw1_base | (rn & 0xF);
        let hw2 = 0xF0F0 | ((rd & 0xF) << 8) | (rm & 0xF);
        self.emit32(hw1, hw2);
    }

    /// `adr rd, blob` — position-independent load of a data blob's address
    /// (`add rd, pc, #imm`). The blob is declared with [`Asm::data_blob`].
    pub fn adr(&mut self, rd: u16, blob_label: u16) -> &mut Self {
        self.lo("adr", "rd", rd);
        let pos = self.code.len();
        self.emit16(0xA000 | (rd << 8));
        self.adrs.push((pos, blob_label));
        self
    }

    /// Declare a read-only data blob appended after the code+pool; returns a
    /// label usable with [`Asm::adr`]. Blobs are laid out 4-byte aligned.
    pub fn data_blob(&mut self, bytes: Vec<u8>) -> u16 {
        let label = self.label();
        self.blobs.push((label, bytes));
        label
    }

    /// Lay out the pool (4-aligned) then data blobs, and back-patch every branch,
    /// `ldr` literal, and `adr`. Returns the assembled bytes.
    ///
    /// # Reuse
    ///
    /// `finish` takes `&mut self` and, on every path (`Ok` or `Err`), leaves
    /// `self` as a **fresh, empty assembler with the same target** — the
    /// half-consumed intermediate state (fixups, literal pool, labels, code
    /// buffer) is taken out of `self` before any layout work runs, so a caller
    /// can call `finish` twice in a row (the second returns `Ok(vec![])`), and
    /// a stale label from the previous buffer used after `finish` decodes as
    /// "never reserved" — never as a silent branch into the previous buffer's
    /// address space. See the reuse tests in `src/lib.rs::asm_reuse_tests`.
    pub fn finish(&mut self) -> Result<Vec<u8>, AsmError> {
        // Reading `self.target` while `self` is also `&mut`-borrowed as the
        // first argument of `mem::replace` trips E0503; the two-phase borrow
        // rules cover method-call autoref, not an explicit `&mut` in argument
        // position. Copy the field out first, then let `mem::replace` take
        // exclusive ownership.
        let target = self.target;
        let mut this = core::mem::replace(self, Asm::with_target(target));

        // 0. any operand rejected during emit. Reported before layout so the
        //    caller sees the cause, not a downstream symptom of the bad bytes.
        if let Some(e) = this.err.take() {
            return Err(e);
        }
        // 1. code-position branches (targets already bound during emit).
        for (pos, label, uncond) in core::mem::take(&mut this.fixups) {
            // `get`, not `this.labels[..]`. The id is the caller's: `bind`
            // validates it through `get_mut` and reports "never reserved" as
            // an error, but the emitters that push fixups — `b`, `b_cond`,
            // `adr` — do not, so an id that was never handed out by `label()`
            // arrives here unchecked. Indexing raw turns a would-be
            // `AsmError` into a panic, which contradicts this type's whole
            // contract that a bad operand is an error.
            //
            // The two failures are distinguished because they are different
            // mistakes: an id nobody reserved is a bug at the call site, and
            // a reserved id never bound is a missing `bind`.
            let target = match this.labels.get(label as usize) {
                Some(Some(t)) => *t,
                Some(None) => {
                    return Err(AsmError::Layout {
                        at: pos,
                        msg: format!("unbound label {label}"),
                    })
                }
                None => {
                    return Err(AsmError::Layout {
                        at: pos,
                        msg: format!("label {label} was never reserved by `label()`"),
                    })
                }
            };
            let off = (target as i32 - (pos as i32 + 4)) / 2;
            let enc = if uncond {
                if !(-1024..=1023).contains(&off) {
                    return Err(AsmError::Layout {
                        at: pos,
                        msg: format!("branch out of range ({off} halfwords)"),
                    });
                }
                0xE000u16 | (off as u16 & 0x07FF)
            } else {
                if !(-128..=127).contains(&off) {
                    return Err(AsmError::Layout {
                        at: pos,
                        msg: format!("conditional branch out of range ({off} halfwords)"),
                    });
                }
                let base = u16::from_le_bytes([this.code[pos], this.code[pos + 1]]) & 0xFF00;
                base | (off as i8 as u8 as u16)
            };
            this.code[pos..pos + 2].copy_from_slice(&enc.to_le_bytes());
        }
        // 2. literal pool (4-aligned), patch ldr.
        while this.code.len() % 4 != 0 {
            this.code.push(0x00);
        }
        let mut placed: Vec<(u32, u32)> = Vec::new();
        for (pos, value, rt) in core::mem::take(&mut this.ldrs) {
            // Linear scan is deliberate. The pool is laid out in first-reference
            // order, which this `Vec` is what preserves, and a realistic stub holds
            // a handful of distinct literals — the `Asm` type is documented as a
            // deliberately dumb assembler for trampolines, not a code generator.
            // It is O(n^2) in the number of *distinct* literals and would want an
            // index beside the `Vec` if that ever reached the thousands.
            let off = match placed.iter().find(|(v, _)| *v == value) {
                Some(&(_, o)) => o,
                None => {
                    let o = this.code.len() as u32;
                    this.code.extend_from_slice(&value.to_le_bytes());
                    placed.push((value, o));
                    o
                }
            };
            let pc = (pos as u32 + 4) & !3;
            let imm8 = (off - pc) / 4;
            if imm8 > 0xFF {
                return Err(AsmError::Layout {
                    at: pos,
                    msg: format!("ldr literal out of range (imm8 = {imm8})"),
                });
            }
            let enc = 0x4800u16 | (rt << 8) | imm8 as u16;
            this.code[pos..pos + 2].copy_from_slice(&enc.to_le_bytes());
        }
        // 3. data blobs (each 4-aligned); bind their labels.
        for (label, bytes) in core::mem::take(&mut this.blobs) {
            while this.code.len() % 4 != 0 {
                this.code.push(0x00);
            }
            // Indexed directly, unlike the fixup loops above, and safely so:
            // `this.blobs` has exactly one producer, `data_blob`, which calls
            // `label()` itself and returns that id. So a blob's label is
            // always one this `Asm` reserved. The *reader* below is different
            // — `adr` takes the id from the caller — and is guarded.
            this.labels[label as usize] = Some(this.code.len());
            this.code.extend_from_slice(&bytes);
        }
        // 4. adr fixups (blob labels now bound).
        for (pos, label) in core::mem::take(&mut this.adrs) {
            let target = match this.labels.get(label as usize) {
                Some(Some(t)) => *t,
                Some(None) => {
                    return Err(AsmError::Layout {
                        at: pos,
                        msg: format!("unbound blob label {label}"),
                    })
                }
                None => {
                    return Err(AsmError::Layout {
                        at: pos,
                        msg: format!("blob label {label} was never reserved by `label()`"),
                    })
                }
            };
            let base = (pos as u32 + 4) & !3;
            let imm = target as u32;
            if imm < base || (imm - base) % 4 != 0 || (imm - base) / 4 > 0xFF {
                return Err(AsmError::Layout {
                    at: pos,
                    msg: format!("adr target out of range (pos=0x{pos:x} target=0x{target:x})"),
                });
            }
            let enc = 0xA000u16
                | ((u16::from_le_bytes([this.code[pos], this.code[pos + 1]]) >> 8 & 7) << 8)
                | ((imm - base) / 4) as u16;
            this.code[pos..pos + 2].copy_from_slice(&enc.to_le_bytes());
        }
        Ok(this.code)
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
/// (Verified against ARM DDI 0403E.e A7.7.12 and DDI 0406B A8.6.16.)
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
#[non_exhaustive]
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
#[non_exhaustive]
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

impl InstallMismatch {
    /// A stable, machine-readable reason: `"not-a-branch"` when nothing of the
    /// expected kind decodes at the site, `"wrong-target"` when one does but
    /// points elsewhere.
    ///
    /// The distinction matters and is otherwise only recoverable by inspecting
    /// [`found`](Self::found): a `None` there means the write did not happen
    /// or was overwritten, while a `Some` means it happened and landed wrong.
    pub fn reason(&self) -> &'static str {
        match self.found {
            None => "not-a-branch",
            Some(_) => "wrong-target",
        }
    }
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

/// What is already at a patch site. Returned by [`classify_branch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BranchAt {
    /// Nothing decoded there, or what decoded is not a branch.
    NotABranch,
    /// A branch whose destination is fixed in the encoding.
    Direct {
        /// Which installable kind this is, or `None` for a direct branch that
        /// [`install_branch`] cannot write — a 16-bit `b`, a `cbz`, a `blx`
        /// to an Arm-state label. `None` is the interesting answer: it means
        /// the site holds a branch you cannot replace in place without
        /// thinking about width.
        kind: Option<BranchKind>,
        /// How many bytes it occupies: 2 or 4. **This is the field that
        /// matters.** Writing a 4-byte branch over a 2-byte one does not just
        /// change the branch, it overwrites the instruction after it.
        width: u8,
        /// Where it goes, with the Thumb bit already cleared.
        target: u32,
    },
    /// A branch whose destination is computed — `bx`/`blx` on a register,
    /// `ldr pc, [..]`, `tbb`/`tbh`. There is no target to compare against.
    Indirect {
        /// How many bytes it occupies: 2 or 4.
        width: u8,
    },
}

/// Why [`can_install`] says a site cannot take a branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstallHazard {
    /// The four bytes do not fit: `site + 4` is past the end of the image.
    OutOfBounds {
        /// The site asked about.
        site: usize,
        /// How many bytes the image actually has.
        image_len: usize,
    },
    /// Nothing at `site` decodes as an instruction, so what a branch would
    /// overwrite is unknown. Either the offset is wrong or it is mid-
    /// instruction — both are reasons not to write.
    NotAnInstruction {
        /// The site asked about.
        site: usize,
    },
    /// The four bytes end in the middle of an instruction.
    ///
    /// This is the hazard [`classify_branch`]'s `width` hints at, stated
    /// outright. A 16-bit instruction followed by a 32-bit one spans six
    /// bytes, so a four-byte branch leaves the last two halves of a wide
    /// instruction behind, to be executed as whatever they happen to encode.
    SplitsInstruction {
        /// Where the straddled instruction starts.
        at: usize,
        /// How many bytes whole instructions actually occupy from the site —
        /// always more than 4. Displacing that many is what a detour does;
        /// see [`crate::detour::detour`], which relocates them rather than
        /// leaving them cut.
        displaced: usize,
    },
}

impl InstallHazard {
    /// A stable, machine-readable reason: `"out-of-bounds"`,
    /// `"not-an-instruction"` or `"splits-instruction"`.
    ///
    /// Matches the convention every other error type in this crate follows,
    /// so a caller can log or branch on the cause without matching variants —
    /// which matters here because this enum is `#[non_exhaustive]` and will
    /// grow as more pre-flight hazards become checkable.
    pub fn reason(&self) -> &'static str {
        match self {
            InstallHazard::OutOfBounds { .. } => "out-of-bounds",
            InstallHazard::NotAnInstruction { .. } => "not-an-instruction",
            InstallHazard::SplitsInstruction { .. } => "splits-instruction",
        }
    }
}

impl core::fmt::Display for InstallHazard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InstallHazard::OutOfBounds { site, image_len } => write!(
                f,
                "a 4-byte branch at {site:#x} runs past the end of a {image_len:#x}-byte image"
            ),
            InstallHazard::NotAnInstruction { site } => {
                write!(f, "nothing decodes at {site:#x}")
            }
            InstallHazard::SplitsInstruction { at, displaced } => write!(
                f,
                "a 4-byte branch at this site cuts the instruction at {at:#x} in half; \
                 whole instructions occupy {displaced} bytes"
            ),
        }
    }
}

impl std::error::Error for InstallHazard {}

/// Would installing a 4-byte branch here overwrite whole instructions?
///
/// [`classify_branch`] reports the width of what is at a site; this answers
/// the question that width was being consulted for. Leaving callers to do the
/// arithmetic themselves is leaving them to do the reasoning that goes wrong:
/// every branch this crate installs is four bytes, and four bytes only land
/// cleanly when the instructions at the site add up to exactly four.
///
/// The hazard is more general than "the site holds a 16-bit branch". Any
/// 2-byte instruction followed by a 4-byte one spans six, and cutting it
/// leaves two bytes that will be executed as whatever they encode. That is
/// the case this catches and a `width` check alone does not.
///
/// `kind` is accepted so the signature reads at the call site and so a future
/// narrow branch kind does not change it; both current kinds are four bytes,
/// so it does not currently affect the answer.
///
/// An `Ok` here does **not** mean the patch is a good idea — only that it
/// destroys whole instructions rather than half of one. Use
/// [`crate::detour::detour`] when the displaced instructions still need to
/// run.
///
/// ```
/// use thumb_asm::{can_install, BranchKind, InstallHazard};
///
/// // `movs r0, #1` · `movs r1, #2` — two 16-bit instructions, exactly 4 bytes.
/// assert!(can_install(&[0x01, 0x20, 0x02, 0x21], 0, BranchKind::Bl).is_ok());
///
/// // `movs r0, #1` · `bl +0` — 2 + 4 bytes. A 4-byte branch cuts the `bl`.
/// let image = [0x01, 0x20, 0xFF, 0xF7, 0xFE, 0xFF];
/// assert_eq!(
///     can_install(&image, 0, BranchKind::Bl),
///     Err(InstallHazard::SplitsInstruction { at: 2, displaced: 6 })
/// );
/// ```
pub fn can_install(image: &[u8], site: usize, kind: BranchKind) -> Result<(), InstallHazard> {
    can_install_with(isa::Target::Union, image, site, kind)
}

/// Same as [`can_install`] but for a caller who knows the image's ISA
/// [`isa::Target`]. This is the load-bearing surface for the 0.14.0 detour
/// path: under `Target::Union` an Armv8-M `SG` at the hook site decodes as
/// a plain `LDRD` (the whole reason [`isa::Target`] exists — 0.12.0), so
/// `can_install` silently green-lights overwriting the Security Gateway.
/// A caller who passes `Target::V8M` gets the honest answer, which is
/// still `Ok(())` today because `SG` is a legal instruction on that target,
/// but sets the stage for follow-on hazards
/// (`InstallHazard::SecureGateway`, planned for 0.14.x) to fire from this
/// path.
pub fn can_install_with(
    target: isa::Target,
    image: &[u8],
    site: usize,
    kind: BranchKind,
) -> Result<(), InstallHazard> {
    let _ = kind; // every kind this crate installs is four bytes.
    if site.checked_add(4).map_or(true, |end| end > image.len()) {
        return Err(InstallHazard::OutOfBounds {
            site,
            image_len: image.len(),
        });
    }
    let mut at = site;
    while at < site + 4 {
        let insn = match isa::decode_at_with(image, at, at as u32, target) {
            Some(i) => i,
            None => return Err(InstallHazard::NotAnInstruction { site: at }),
        };
        let next = at + insn.len();
        if next > site + 4 {
            return Err(InstallHazard::SplitsInstruction {
                at,
                displaced: next - site,
            });
        }
        at = next;
    }
    Ok(())
}

/// Ask what branch is already at `at`, before overwriting it.
///
/// [`verify_branch`] checks an *assertion*: you say which kind and target you
/// expect and it agrees or disagrees. That cannot catch the case where the
/// expectation itself is wrong — which is the interesting failure, because a
/// patcher that believes the site holds a `BL` when it holds a `B` will
/// happily install the wrong one and report success.
///
/// This asks the question instead of asserting the answer. The decoder already
/// knows; this only puts it in the same vocabulary [`install_branch`] takes.
///
/// # The width is the dangerous part
///
/// A 16-bit `b` at the site is [`BranchAt::Direct`] with `kind: None` and
/// `width: 2`. [`install_branch`] only writes 4-byte branches, so patching
/// over it silently consumes the two bytes of whatever follows. Checking
/// `width` before installing turns that from a field-reported brick into a
/// refusal:
///
/// ```
/// use thumb_asm::{classify_branch, BranchAt, BranchKind};
///
/// // `b.n +0` — a 16-bit unconditional branch.
/// let image = [0xFE, 0xE7];
/// match classify_branch(&image, 0) {
///     BranchAt::Direct { kind, width, .. } => {
///         assert_eq!(kind, None, "not a kind install_branch can write");
///         assert_eq!(width, 2, "installing a 4-byte branch here eats the next instruction");
///     }
///     other => panic!("expected a direct branch, got {other:?}"),
/// }
///
/// // `bl +0` — 4 bytes, and installable.
/// let image = [0xFF, 0xF7, 0xFE, 0xFF];
/// assert!(matches!(
///     classify_branch(&image, 0),
///     BranchAt::Direct { kind: Some(BranchKind::Bl), width: 4, .. }
/// ));
/// ```
pub fn classify_branch(image: &[u8], at: usize) -> BranchAt {
    classify_branch_with(isa::Target::Union, image, at)
}

/// Same as [`classify_branch`] but for a caller who knows the image's ISA
/// [`isa::Target`]. Under `Target::V8M` this is what lets a hook-site check
/// see a CMSE gateway (`SG`) as `NotABranch` — since `SG` is not a
/// branch — rather than as a fake pc-relative `LDRD` whose displacement
/// then gets followed as a "branch target that carries a literal
/// address". See [`can_install_with`] for the parallel argument on the
/// install side.
pub fn classify_branch_with(target: isa::Target, image: &[u8], at: usize) -> BranchAt {
    let insn = match isa::decode_at_with(image, at, at as u32, target) {
        Some(i) => i,
        None => return BranchAt::NotABranch,
    };
    if !insn.is_branch() {
        return BranchAt::NotABranch;
    }
    let width = insn.len() as u8;
    // A `Target` alongside a `Mem` is the address of a literal-pool word, not
    // a destination — the same overload `analysis::reachable` documents, and
    // the shape of `ldr pc, [pc, #imm]`, which is emphatically indirect.
    let has_mem = insn
        .operands
        .as_slice()
        .any(|o| matches!(o, isa::Operand::Mem(_)));
    match insn.branch_target() {
        Some(target) if !has_mem => {
            let kind = match (insn.mnemonic, insn.len()) {
                ("bl", 4) => Some(BranchKind::Bl),
                ("b", 4) => Some(BranchKind::BWide),
                _ => None,
            };
            BranchAt::Direct {
                kind,
                width,
                target: target & !1,
            }
        }
        _ => BranchAt::Indirect { width },
    }
}

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
    find_bytes_in(image, pat, start, image.len())
}

/// `find_bytes`, bounded above: the match must lie entirely within
/// `[start, end)`.
fn find_bytes_in(image: &[u8], pat: &[u8], start: usize, end: usize) -> Option<usize> {
    let end = end.min(image.len());
    if pat.is_empty() || start >= end || pat.len() > end - start {
        return None;
    }
    image[start..end]
        .windows(pat.len())
        .position(|w| w == pat)
        .map(|p| p + start)
}

fn find_free_run(image: &[u8], len: usize, align: usize, start: usize) -> Option<usize> {
    find_free_run_in(image, len, align, start, image.len())
}

/// `find_free_run`, bounded above. Alignment is still measured from the image
/// origin, not from `start` — that is the whole reason this takes a window
/// rather than the caller slicing and searching the slice.
fn find_free_run_in(
    image: &[u8],
    len: usize,
    align: usize,
    start: usize,
    end: usize,
) -> Option<usize> {
    assert!(align != 0, "alignment must be at least 1 byte");
    let end = end.min(image.len());
    let mut p = round_up(start.min(end), align);
    loop {
        // `checked_add`, because `len` is the caller's and may be enormous;
        // a saturated `p` fails this test too, which is why `round_up` can
        // saturate rather than report.
        if p.checked_add(len).map_or(true, |stop| stop > end) {
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

/// Halfword-aligned masked search. See [`Needle::Masked`].
fn find_masked(image: &[u8], pat: &[(u16, u16)], start: usize) -> Option<usize> {
    find_masked_in(image, pat, start, image.len())
}

/// `find_masked`, bounded above. Halfword alignment is measured from the image
/// origin: a window starting at an odd offset does not shift what counts as an
/// instruction boundary.
fn find_masked_in(image: &[u8], pat: &[(u16, u16)], start: usize, end: usize) -> Option<usize> {
    // An empty pattern is satisfied by every position; reporting `start` would
    // be technically true and useless. See the variant's documentation.
    if pat.is_empty() {
        return None;
    }
    // `* 2`, not `checked_mul`: `pat` is a real slice of 4-byte elements, so
    // its length is at most `usize::MAX / 4` and the product cannot overflow.
    // A `checked_mul` here would add an arm no input can reach.
    let need = pat.len() * 2;
    let end = end.min(image.len());
    let mut p = round_up(start.min(end), 2);
    while p.checked_add(need).map_or(false, |stop| stop <= end) {
        let hit = pat.iter().enumerate().all(|(i, &(value, mask))| {
            let at = p + i * 2;
            u16::from_le_bytes([image[at], image[at + 1]]) & mask == value & mask
        });
        if hit {
            return Some(p);
        }
        p += 2;
    }
    None
}

/// Which free run to choose when more than one will do. See
/// [`find_free_space_in`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Fit {
    /// The lowest usable offset in the image, and what [`find_free_space`]
    /// does.
    ///
    /// "Lowest" means lowest *address*, not first encountered: the order the
    /// regions are passed in does not change the answer.
    First,
    /// The usable offset inside the longest free run. Prefer this when placing
    /// several stubs: first-fit takes the first hole big enough and leaves the
    /// large one fragmented, whereas this keeps the big hole for the things
    /// that need it.
    ///
    /// Ties are broken on the lowest address, so this too is independent of
    /// the order the regions are passed in.
    Largest,
}

/// Free space, restricted to regions the caller says are writable.
///
/// [`find_free_space`] scans the whole image, which assumes every erased byte
/// is fair game. In a real firmware image it is not: a region may be covered
/// by an integrity check, reserved by the vendor, or outside the erase block
/// the caller intends to rewrite. Only the caller knows which, and there is no
/// safe way to express it from outside — **slicing the image and searching
/// that is wrong**, because slicing at an unaligned offset moves the alignment
/// origin, so a result that looks 4-aligned within the slice is not 4-aligned
/// within the image. That is the same failure the `align` parameter exists to
/// prevent, reintroduced one layer up.
///
/// `within` is in *image* coordinates, and each range is **half-open**:
/// `0x90000..0xb0000` includes `0x90000` and excludes `0xb0000`, as every
/// `Range` in Rust does. `a..=b` is deliberately not accepted, so porting from
/// an inclusive convention is a compile error rather than an off-by-one.
///
/// Ranges are clipped to the image, need not be disjoint, and **may be given
/// in any order without changing the answer** — both [`Fit`] policies resolve
/// to an address, not to whichever region was looked at first. Two callers
/// with the same intent get the same offset, which anyone producing
/// byte-reproducible images depends on. An empty slice finds nothing.
///
/// A free run that extends past a region's end is **clipped** to the region,
/// not rejected: the offset returned is always one where `len` bytes fit
/// entirely inside a region you named. If you need the stronger rule — refuse
/// a run that straddles a boundary at all, because your erase granularity is
/// coarser than your regions — use [`FreeSpace`] with [`Straddle::Reject`].
///
/// # Panics
///
/// Panics if `align` is 0, as [`find_free_space`] does.
///
/// ```
/// use thumb_asm::{find_free_space_in, Fit};
///
/// //          0..4 live        4..12 free       12..16 live    16..32 free
/// let mut image = vec![0x00; 4];
/// image.extend(std::iter::repeat(0xFF).take(8));
/// image.extend(std::iter::repeat(0x00).take(4));
/// image.extend(std::iter::repeat(0xFF).take(16));
///
/// // First fit takes the 8-byte hole; largest fit keeps to the 16-byte one.
/// assert_eq!(find_free_space_in(&image, 4, 4, &[0..image.len()], Fit::First), Some(4));
/// assert_eq!(find_free_space_in(&image, 4, 4, &[0..image.len()], Fit::Largest), Some(16));
///
/// // Restricted to the first region, the big hole is not a candidate at all.
/// assert_eq!(find_free_space_in(&image, 4, 4, &[0..12], Fit::Largest), Some(4));
/// ```
pub fn find_free_space_in(
    image: &[u8],
    len: usize,
    align: usize,
    within: &[core::ops::Range<usize>],
    fit: Fit,
) -> Option<usize> {
    assert!(align != 0, "alignment must be at least 1 byte");
    // `best` is compared, never short-circuited, so the result is a function
    // of the regions rather than of the order they arrived in. Returning early
    // on the first hit — which this did until 0.11.1 — makes `Fit::First`
    // report whichever region was listed first, so the same two regions in the
    // other order produce a different address and a byte-reproducible build
    // stops being reproducible with nothing to show for it.
    let mut best: Option<(usize, usize)> = None; // (usable bytes, offset)
    for region in within {
        let lo = region.start.min(image.len());
        let hi = region.end.min(image.len());
        let mut p = lo;
        while p < hi {
            // Skip live bytes, then measure the free run that follows.
            if image[p] != 0xFF {
                p += 1;
                continue;
            }
            let run_start = p;
            while p < hi && image[p] == 0xFF {
                p += 1;
            }
            // Alignment is applied inside the run, not to the run's start, so
            // a run whose start is unaligned still counts the bytes it can
            // actually offer.
            let at = round_up(run_start, align);
            if at.checked_add(len).map_or(false, |end| end <= p) {
                let usable = p - at;
                let better = match (fit, best) {
                    (_, None) => true,
                    // Lowest address wins outright.
                    (Fit::First, Some((_, b_at))) => at < b_at,
                    // Largest run wins; equal runs fall back to the lowest
                    // address so the answer is still total rather than
                    // dependent on which was seen first.
                    (Fit::Largest, Some((b_len, b_at))) => {
                        usable > b_len || (usable == b_len && at < b_at)
                    }
                };
                if better {
                    best = Some((usable, at));
                }
            }
        }
    }
    best.map(|(_, at)| at)
}

/// What to do with a free run that crosses out of the regions it was found in.
///
/// The two are different safety decisions, not two spellings of one, so this
/// is explicit rather than defaulted in a way that suits one caller.
///
/// # Which regions
///
/// **The ones you passed, and nothing else.** This is worth stating outright
/// because the wording below invites the other reading:
/// [`Reject`](Straddle::Reject)'s rationale mentions erase granularity, which
/// sounds as though the crate consults an erase-block map. It does not, and
/// cannot — it is handed a `&[u8]` with no device geometry, no flash
/// controller, and no idea what a page is on your part.
///
/// So a "region" is whatever *you* meant it to be: an integrity-covered span,
/// a CMAC-protected table, an erase block, a linker-script section. The two
/// variants differ only in whether a run may be offered when it extends past
/// one of them.
///
/// Erase granularity is a reason you might *choose* `Reject`, not something
/// this crate detects. If a page on your part is coarser than the regions you
/// are passing, that is a fact about the part which has to be reflected in the
/// regions themselves; nothing here can discover it.
///
/// Every "region" in this crate works this way — [`find_free_space_in`],
/// [`FreeSpace`], and [`detour_in`](crate::detour::detour_in) all take the
/// caller's declaration and never infer one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Straddle {
    /// Truncate the run to the region. The offset handed back always has its
    /// `len` bytes inside a region you named, so the *placement* is safe even
    /// though the erased run it came from was not entirely covered.
    Clip,
    /// Do not offer a run that extends past the region at all.
    ///
    /// Use this when writing near a boundary is unsafe even if the bytes
    /// written are inside it — most often because erase granularity is coarser
    /// than the regions, so programming a page that straddles the boundary
    /// disturbs bytes outside it. Clipping cannot protect against that,
    /// because the hazard is the write, not the placement.
    Reject,
}

/// An allocator over the erased space in an image.
///
/// [`find_free_space_in`] answers "where could this go?" once. Placing several
/// stubs needs a different question — "where does the *next* one go?" — and
/// repeating the search does not answer it: nothing has been written yet, so
/// every call returns the same offset. Writing each stub before searching for
/// the next works, but only by accident of the bytes changing, and it forces
/// the whole layout to be interleaved with the writing.
///
/// This tracks what it has handed out, so allocations pack contiguously and
/// none is ever returned twice:
///
/// ```
/// use thumb_asm::{FreeSpace, Straddle};
///
/// let mut image = vec![0u8; 16];
/// image.extend(std::iter::repeat(0xFF).take(64));   // free: 16..80
///
/// let mut space = FreeSpace::new(&image, &[0..image.len()], 4, Straddle::Clip);
/// assert_eq!(space.alloc(12), Some(16));
/// assert_eq!(space.alloc(8),  Some(28));   // packed, nothing written yet
/// assert_eq!(space.alloc(4),  Some(36));
/// ```
///
/// Regions are half-open, may be given in any order and may overlap: they are
/// normalised to a sorted, merged set first, so the sequence of offsets is a
/// function of the region *set* and not of the order they were listed in.
/// Anyone producing byte-reproducible images depends on that.
#[derive(Debug, Clone)]
pub struct FreeSpace<'a> {
    image: &'a [u8],
    /// Usable runs, ascending and disjoint.
    runs: Vec<core::ops::Range<usize>>,
    align: usize,
    /// Index into `runs` of the run being handed out of.
    at: usize,
    /// Next unallocated offset within `runs[at]`.
    cursor: usize,
}

impl<'a> FreeSpace<'a> {
    /// Collect the erased runs inside `within` that may be allocated from.
    ///
    /// # Panics
    ///
    /// Panics if `align` is 0, as [`find_free_space`] does.
    pub fn new(
        image: &'a [u8],
        within: &[core::ops::Range<usize>],
        align: usize,
        straddle: Straddle,
    ) -> Self {
        assert!(align != 0, "alignment must be at least 1 byte");

        // Normalise the regions first — sorted, clipped, and merged where they
        // touch — so everything below is a function of the set rather than of
        // the argument order.
        let mut regions: Vec<core::ops::Range<usize>> = within
            .iter()
            .map(|r| r.start.min(image.len())..r.end.min(image.len()))
            .filter(|r| r.start < r.end)
            .collect();
        regions.sort_by_key(|r| r.start);
        let mut merged: Vec<core::ops::Range<usize>> = Vec::with_capacity(regions.len());
        for r in regions {
            match merged.last_mut() {
                Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
                _ => merged.push(r),
            }
        }

        let mut runs = Vec::new();
        for region in &merged {
            let mut p = region.start;
            while p < region.end {
                if image[p] != 0xFF {
                    p += 1;
                    continue;
                }
                let start = p;
                while p < region.end && image[p] == 0xFF {
                    p += 1;
                }
                // Does the erased run continue outside the region? Looking at
                // the image rather than the region is the whole point: the run
                // was clipped by the loop bound above, so its extent here says
                // nothing about how far the erased bytes actually go.
                let runs_off_the_front =
                    start > 0 && start == region.start && image[start - 1] == 0xFF;
                let runs_off_the_back = p < image.len() && p == region.end && image[p] == 0xFF;
                if straddle == Straddle::Reject && (runs_off_the_front || runs_off_the_back) {
                    continue;
                }
                runs.push(start..p);
            }
        }
        let cursor = runs.first().map_or(0, |r| r.start);
        FreeSpace {
            image,
            runs,
            align,
            at: 0,
            cursor,
        }
    }

    /// Hand out `len` bytes, aligned, from the lowest place they still fit.
    ///
    /// Returns the offset, or `None` when no run has room left. Successive
    /// calls never overlap, and never revisit a run once one has been
    /// allocated from a later one, so the sequence is monotonically
    /// increasing.
    ///
    /// **A failed allocation changes nothing.** Asking for more than is left
    /// returns `None` and leaves the allocator exactly as it was, so a caller
    /// can ask for something smaller afterwards and still get it.
    pub fn alloc(&mut self, len: usize) -> Option<usize> {
        // Committed only on success. Advancing the cursor while searching
        // would mean a request too large for what is left consumes every
        // remaining run on its way to returning `None` — so one oversized
        // allocation would silently destroy the capacity for all the small
        // ones after it, and `remaining` would report zero with the bytes
        // still there.
        let mut at = self.at;
        let mut cursor = self.cursor;
        while at < self.runs.len() {
            let run = &self.runs[at];
            let start = round_up(cursor.max(run.start), self.align);
            if start.checked_add(len).map_or(false, |end| end <= run.end) {
                self.at = at;
                self.cursor = start + len;
                return Some(start);
            }
            at += 1;
            cursor = self.runs.get(at).map_or(0, |r| r.start);
        }
        None
    }

    /// How many bytes remain unallocated, across every run.
    ///
    /// A budget check, not a promise: alignment and the shape of what is asked
    /// for mean a caller cannot necessarily allocate all of it.
    pub fn remaining(&self) -> usize {
        self.runs
            .iter()
            .enumerate()
            .map(|(i, r)| match i.cmp(&self.at) {
                core::cmp::Ordering::Less => 0,
                core::cmp::Ordering::Equal => r.end.saturating_sub(self.cursor.max(r.start)),
                core::cmp::Ordering::Greater => r.end - r.start,
            })
            .sum()
    }

    /// The runs this allocator will draw from, ascending and disjoint.
    ///
    /// Exposed because the straddle decision is one a caller may want to audit
    /// rather than trust: under [`Straddle::Reject`] the runs that were
    /// dropped simply are not here.
    pub fn runs(&self) -> &[core::ops::Range<usize>] {
        &self.runs
    }

    /// The image this was built over.
    pub fn image(&self) -> &'a [u8] {
        self.image
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

#[cfg(test)]
mod unreserved_label_tests {
    use super::*;

    /// A label id that was never handed out by `label()` is an error, not a
    /// panic — on every path that accepts one.
    ///
    /// `bind` has always validated the id through `get_mut`, and
    /// `thumb_tests::binding_a_label_that_was_never_reserved_is_an_error_not_a_panic`
    /// pins that. The emitters that record a fixup — `b`, `b_cond`, `adr`,
    /// `blob` — did not, and `finish` then indexed `self.labels` raw, so the
    /// same bad id aborted the process instead of returning `AsmError`. The
    /// existing unbound-label tests all call `label()` first, so they
    /// exercised reserved-but-unbound and never never-reserved.
    #[test]
    fn a_label_never_reserved_is_refused_by_every_path_that_takes_one() {
        // A conditional branch to an id nobody reserved.
        let mut a = Asm::new();
        a.b_cond(Cond::Eq, 7);
        let err = a.finish().expect_err("an unreserved label must not panic");
        // Bound before asserting: a format argument is only evaluated when
        // the assertion fails, so inline it is dead on every passing run.
        let msg = err.to_string();
        assert!(msg.contains("never reserved"), "{msg}");

        // An unconditional branch, which takes a different fixup path.
        let mut a = Asm::new();
        a.b(9);
        let err = a.finish().expect_err("an unreserved label must not panic");
        assert!(err.to_string().contains("never reserved"));

        // `adr` to a blob label nobody reserved.
        let mut a = Asm::new();
        a.adr(0, 3);
        let err = a
            .finish()
            .expect_err("an unreserved blob label must not panic");
        assert!(err.to_string().contains("never reserved"));

        // Note there is deliberately no case here for a *blob* recorded
        // against an unreserved label: `data_blob` reserves its own id and is
        // the only producer, so that path cannot be reached from the public
        // API and guarding it would be an unreachable branch.
    }

    /// Reserved-but-never-bound stays distinguishable from never-reserved:
    /// they are different mistakes and deserve different messages.
    #[test]
    fn a_reserved_but_unbound_label_reports_separately() {
        let mut a = Asm::new();
        let l = a.label();
        a.b_cond(Cond::Eq, l);
        let err = a.finish().expect_err("never bound");
        let msg = err.to_string();
        assert!(msg.contains("unbound label"), "{msg}");
        assert!(!msg.contains("never reserved"));
    }
}

#[cfg(test)]
mod command_table_overflow_tests {
    use super::*;

    /// `find`'s bounds check must not overflow on a caller-supplied `base`
    /// and `stride`.
    ///
    /// Both come from the caller describing a table in their own image, so
    /// their sum is not bounded by anything. Computed as `off + stride` this
    /// panics in a debug build and, worse, *wraps* in a release build to a
    /// small number that passes the `> image.len()` test — after which the
    /// indexing below reads from an offset the check was meant to refuse.
    /// `walk` has always used `checked_add`; `find` did not.
    #[test]
    fn a_table_whose_base_plus_stride_overflows_is_refused_not_wrapped() {
        let image = vec![0u8; 100];
        let table = CommandTable {
            base: usize::MAX - 10,
            stride: 20,
            opcode_off: 0,
            flags_off: 1,
            handler_off: 4,
            term_flag: 0xFF,
            max_records: 5,
        };
        assert_eq!(
            table.find(&image, 0x42),
            None,
            "an overflowing base+stride must be refused, not wrapped into range"
        );
        // `walk` is the sibling that already did this correctly; it must
        // agree, so the two cannot drift apart again.
        assert!(
            table.walk(&image, 0x01).is_empty(),
            "walk must refuse the same table"
        );
    }
}

#[cfg(test)]
mod error_reason_tests {
    use super::*;

    /// Every error type in this crate answers `reason()` with a stable token.
    ///
    /// These are part of the public contract: consumers log them, branch on
    /// them, and put them in their own error messages. Pinning them as string
    /// literals here is what makes a rename a failing test rather than a
    /// silent break in somebody else's matching.
    #[test]
    fn every_error_type_reports_a_stable_machine_readable_reason() {
        assert_eq!(FindError::NotFound.reason(), "not-found");
        assert_eq!(
            FindError::Ambiguous {
                count: 3,
                first: 0x10
            }
            .reason(),
            "ambiguous"
        );

        assert_eq!(
            InstallHazard::OutOfBounds {
                site: 0,
                image_len: 2
            }
            .reason(),
            "out-of-bounds"
        );
        assert_eq!(
            InstallHazard::NotAnInstruction { site: 0 }.reason(),
            "not-an-instruction"
        );

        // `found: None` and `found: Some` are genuinely different outcomes —
        // nothing was written, versus something was written and landed wrong.
        let nothing = InstallMismatch {
            site: 0,
            kind: BranchKind::Bl,
            expected: 0x1000,
            found: None,
        };
        assert_eq!(nothing.reason(), "not-a-branch");
        let wrong = InstallMismatch {
            found: Some(0x2000),
            ..nothing
        };
        assert_eq!(wrong.reason(), "wrong-target");
    }

    /// `SplitsInstruction` is reachable only through `can_install`, so it is
    /// built the way a caller would meet it rather than by hand.
    #[test]
    fn the_split_instruction_hazard_reports_its_reason() {
        // A two-byte `nop` followed by a four-byte `bl`: the four bytes a
        // branch needs at offset 0 cover the `nop` and only the first half of
        // the `bl`, which is the hazard — the site itself decodes fine.
        let image = [0x00, 0xBF, 0x00, 0xF0, 0x00, 0xF8, 0x00, 0xBF];
        let hazard =
            can_install(&image, 0, BranchKind::Bl).expect_err("site splits an instruction");
        assert_eq!(hazard.reason(), "splits-instruction");
    }

    /// `AsmError` reports a constant reason and exposes its message.
    #[test]
    fn an_assembler_error_reports_its_reason_and_message() {
        // The immediate is a `u8`, so it cannot overflow by construction —
        // the reachable failure is a register outside the low bank, which
        // `MOVS` (immediate) T1 encodes in three bits.
        let mut asm = Asm::new();
        asm.movs_imm(8, 0);
        let err = asm.finish().expect_err("a high register must fail");
        assert_eq!(err.reason(), "operand");
        // Bound before the assert: a format argument is only evaluated when
        // the assertion fails, so inline it would never be covered.
        let msg = err.to_string();
        assert!(
            msg.contains("movs"),
            "the message should name the instruction, got: {msg}"
        );
        // Structured accessor agrees with the Display form for `Operand`.
        match &err {
            AsmError::Operand { msg: m, .. } => assert_eq!(*m, msg),
            other => panic!("expected AsmError::Operand, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod asm_reuse_tests {
    //! `finish` is `&mut self` (not `self`), so an `Asm` survives it — this
    //! module pins the two invariants of the reuse contract: successive
    //! `finish()`es on the same builder do not carry state between them, and
    //! a label id from a previous buffer used after `finish` decodes as
    //! "never reserved" rather than as a silent branch to the previous
    //! buffer's byte offset.
    use super::*;
    use crate::isa::Target;
    /// A stub the assembler will accept without any pool or fixups, so the
    /// second `finish()` sees an assembler that is genuinely empty and
    /// returns exactly zero bytes rather than a residual pool from the first
    /// buffer.
    #[test]
    fn a_second_finish_on_the_same_assembler_produces_the_empty_buffer() {
        let mut a = Asm::with_target(Target::Union);
        a.push(0x0100); // 2 bytes, no fixups, no pool needed.
        let first = a.finish().expect("push assembles");
        assert_eq!(
            first.len(),
            4,
            "one halfword padded to the 4-byte pool align"
        );
        let second = a.finish().expect("a reset assembler still finishes");
        assert!(
            second.is_empty(),
            "a fresh assembler after finish must produce no bytes, got {second:02x?}"
        );
    }

    /// The reuse hazard round 4 of the audit named: a label reserved on the
    /// old buffer must not silently bind to any offset in the new one. After
    /// `finish`, the labels vector is gone — a stale id is "never reserved",
    /// which is what the next `finish` reports.
    #[test]
    fn a_label_from_a_previous_finish_is_refused_by_the_next_one() {
        let mut a = Asm::new();
        let stale = a.label();
        a.bind(stale);
        let _ = a.finish().expect("empty buffer assembles");
        // `stale` is a `u16` the caller kept, but the reset assembler has an
        // empty labels vector, so referencing it is a use-of-unreserved id.
        a.b(stale);
        let err = a
            .finish()
            .expect_err("stale label must not silently branch into the previous buffer");
        assert!(
            err.to_string().contains("was never reserved"),
            "expected an unreserved-label diagnostic, got: {err}"
        );
    }

    /// `finish` also preserves the target across resets. A caller who set up a
    /// V8M builder and finishes it does not silently lose the V8M gate on the
    /// next round of emits.
    #[test]
    fn a_reset_assembler_keeps_the_original_target() {
        let mut a = Asm::with_target(Target::V8M);
        let _ = a.finish().expect("empty buffer");
        assert_eq!(
            a.target(),
            Target::V8M,
            "target must survive the reset in finish"
        );
    }
}

#[cfg(test)]
mod asm_target_gate_tests {
    //! End-to-end tests for the [`Asm::with_target`] gate: the `sdiv`/`udiv`
    //! demonstration emitters and the `raw16`/`raw32` decode-under-target
    //! recovery path. This module covers the observable behaviour a consumer
    //! would test; the pin-set / whole-target-variant / EncForm mutation
    //! tripwires live in [`crate::isa::legality::tests`].
    use super::*;
    use crate::isa::Target;

    /// `sdiv` under Armv7-A is UNDEFINED (see `Asm::sdiv` docstring). The
    /// gate reports it as [`AsmError::Unsupported`] with the exact mnemonic
    /// and byte position of the emit.
    #[test]
    fn sdiv_is_refused_under_v7a() {
        let mut a = Asm::with_target(Target::V7A);
        a.sdiv(0, 1, 2);
        let err = a.finish().expect_err("sdiv is UNDEFINED on Armv7-A");
        match err {
            AsmError::Unsupported {
                at,
                mnemonic,
                target,
            } => {
                assert_eq!(mnemonic, "sdiv");
                assert_eq!(target, Target::V7A);
                assert_eq!(at, 0, "the refused emit sits at the start of the buffer");
            }
            other => panic!("expected AsmError::Unsupported, got {other:?}"),
        }
    }

    /// V7R accepts `sdiv` — it is mandatory on Armv7-R. The bytes match the
    /// hand-computed encoding from ARM ARM A8.8.165.
    #[test]
    fn sdiv_is_accepted_under_v7r_and_encodes_correctly() {
        let mut a = Asm::with_target(Target::V7R);
        a.sdiv(0, 1, 2);
        let bytes = a.finish().expect("sdiv is mandatory on Armv7-R");
        // hw1 = 0xFB90 | Rn(=1); hw2 = 0xF0F0 | (Rd=0 << 8) | Rm(=2).
        assert_eq!(
            &bytes[..4],
            &[0x91, 0xFB, 0xF2, 0xF0],
            "sdiv r0, r1, r2 encoding"
        );
    }

    /// V7AR is the strict intersection of V7A and V7R — `sdiv` is refused
    /// because V7A refuses it. The point Fable's round-4 audit named:
    /// V7AR is strictly stricter than V7R.
    #[test]
    fn v7ar_is_strictly_stricter_than_v7r() {
        let mut a = Asm::with_target(Target::V7AR);
        a.sdiv(0, 1, 2);
        let err = a
            .finish()
            .expect_err("V7AR must refuse anything V7A refuses");
        assert!(matches!(
            err,
            AsmError::Unsupported {
                mnemonic: "sdiv",
                target: Target::V7AR,
                ..
            }
        ));
    }

    /// `raw16` under a non-Union target with a wide-instruction prefix
    /// halfword (e.g. `0xF400`) is refused distinctly, pointing at
    /// `raw32`/`raw16_unchecked`. Under Union the same call is accepted —
    /// the pre-0.14 byte-for-byte contract.
    #[test]
    fn raw16_refuses_a_wide_prefix_under_non_union() {
        let mut a = Asm::with_target(Target::V7A);
        a.raw16(0xF400);
        let err = a
            .finish()
            .expect_err("wide prefix via raw16 has no second halfword to decode");
        assert!(matches!(
            err,
            AsmError::Unsupported {
                mnemonic: "raw16",
                target: Target::V7A,
                ..
            }
        ));

        // Same call under Union: accepted, byte-for-byte.
        let mut u = Asm::with_target(Target::Union);
        u.raw16(0xF400);
        let bytes = u.finish().expect("Union is permissive");
        assert_eq!(
            &bytes[..2],
            &[0x00, 0xF4],
            "Union writes 0xF400 little-endian"
        );
    }

    /// A ThumbEE-only halfword outside the legal `0xC000..=0xCFFF` reassignment
    /// slice — `0xC100` decodes as UNDEFINED in the ThumbEE table. `raw16`
    /// under `Target::ThumbEE` therefore refuses.
    #[test]
    fn raw16_refuses_thumbee_undefined_pattern() {
        let mut a = Asm::with_target(Target::ThumbEE);
        a.raw16(0xC100);
        let err = a
            .finish()
            .expect_err("0xC1xx is UNDEFINED in ThumbEE (Table A9-2)");
        assert!(matches!(err, AsmError::Unsupported { .. }));
    }

    /// The Security Gateway pattern is `0xE97F 0xE97F`. On `V8M` the decoder
    /// recovers `sg` (accepted), on `V7A` it recovers `ldrd` (also accepted
    /// there — the "bytes as this chip reads them" contract), so both
    /// targets emit. Only the pattern-does-not-decode-on-target case
    /// refuses.
    #[test]
    fn raw32_accepts_the_v8m_sg_pattern() {
        let mut a = Asm::with_target(Target::V8M);
        a.raw32(0xE97F, 0xE97F);
        let bytes = a.finish().expect("V8M decoder recovers this as sg");
        assert_eq!(
            &bytes[..4],
            &[0x7F, 0xE9, 0x7F, 0xE9],
            "SG bytes emitted in little-endian order"
        );
    }

    /// `raw32` with an `sdiv` pattern under `V7A` refuses — the V7A decoder
    /// recovers `sdiv` and the legality table rejects it there.
    #[test]
    fn raw32_refuses_sdiv_pattern_under_v7a() {
        // sdiv r2, r1, r3: hw1 = 0xFB91, hw2 = 0xF2F3.
        let mut a = Asm::with_target(Target::V7A);
        a.raw32(0xFB91, 0xF2F3);
        let err = a.finish().expect_err("sdiv via raw32 is UNDEFINED on V7A");
        assert!(matches!(
            err,
            AsmError::Unsupported {
                mnemonic: "sdiv",
                target: Target::V7A,
                ..
            }
        ));
    }

    /// `raw16_unchecked` is the escape hatch: nothing gated, ever. The
    /// caller has taken responsibility for the bytes.
    #[test]
    fn raw16_unchecked_bypasses_the_gate() {
        let mut a = Asm::with_target(Target::V7A);
        a.raw16_unchecked(0xF400); // wide prefix, gated on raw16.
        let bytes = a
            .finish()
            .expect("raw16_unchecked bypasses every legality check");
        assert_eq!(&bytes[..2], &[0x00, 0xF4]);
    }

    /// The install-side `_with` overload accepts the same bytes as
    /// `can_install` for baseline patterns — the target axis is here for
    /// V8M/ThumbEE cases, not to change the answer for shared encodings.
    #[test]
    fn can_install_with_agrees_with_can_install_on_baseline_bytes() {
        // `nop; nop`: two 2-byte instructions, no split, accepted under any
        // target because `nop` is baseline everywhere.
        let image = [0x00, 0xBF, 0x00, 0xBF];
        for t in [
            Target::Union,
            Target::V7M,
            Target::V7A,
            Target::V7R,
            Target::V7AR,
            Target::V7EM,
            Target::V8M,
        ] {
            assert!(
                can_install_with(t, &image, 0, BranchKind::Bl).is_ok(),
                "can_install_with({t:?}) must accept a baseline site"
            );
        }
    }

    /// `udiv` bytes must match ARM ARM A8.8.267 exactly, and the encoding must
    /// use a non-zero `Rd` so the `Rd << 8` mutant (a survivor in the 0.14.0
    /// baseline sweep) cannot masquerade as identity.
    ///
    /// `udiv r3, r4, r5`: hw1 = 0xFBB0 | Rn(=4) = 0xFBB4; hw2 = 0xF0F0 |
    /// (Rd=3 << 8) | Rm(=5) = 0xF3F5. Bytes: `[0xB4, 0xFB, 0xF5, 0xF3]`.
    #[test]
    fn udiv_encodes_exactly_with_nonzero_rd() {
        let mut a = Asm::new();
        a.udiv(3, 4, 5);
        let bytes = a.finish().expect("udiv is legal under Union");
        assert_eq!(&bytes[..4], &[0xB4, 0xFB, 0xF5, 0xF3], "udiv r3, r4, r5");
    }

    /// `udiv` under `Target::V7R` — the acceptance path proves the target
    /// gate does not accidentally reject udiv on a profile where it is
    /// mandatory.
    #[test]
    fn udiv_is_accepted_under_v7r() {
        let mut a = Asm::with_target(Target::V7R);
        a.udiv(0, 1, 2);
        let bytes = a.finish().expect("udiv is mandatory on Armv7-R (spec:874)");
        assert_eq!(&bytes[..4], &[0xB1, 0xFB, 0xF2, 0xF0]);
    }

    /// `udiv` and `sdiv` share `divmod_wide`; the SP/PC operand check is
    /// `r == 13 || r == 15`. The `||` → `&&` mutant would neuter the check
    /// (no register is BOTH 13 AND 15), so a test using only r=13 kills it.
    #[test]
    fn divmod_wide_refuses_rn_equal_sp() {
        let mut a = Asm::new();
        a.sdiv(0, 13, 2);
        let err = a.finish().expect_err("Rn=SP is UNPREDICTABLE for sdiv");
        assert!(matches!(err, AsmError::Operand { .. }));
    }

    /// The other half of the SP/PC check — r=15 (PC) is separately refused.
    /// Testing both endpoints (13 and 15) rules out any partial `||`/`&&`
    /// mutation.
    #[test]
    fn divmod_wide_refuses_rm_equal_pc() {
        let mut a = Asm::new();
        a.udiv(0, 1, 15);
        let err = a.finish().expect_err("Rm=PC is UNPREDICTABLE for udiv");
        assert!(matches!(err, AsmError::Operand { .. }));
    }

    /// `raw16` under a non-Union target discriminates on `insn_len(insn) == 4`:
    /// wide-prefix halfwords are refused with `mnemonic: "raw16"`, narrow
    /// halfwords go through the decode-under-target legality path. The `==`
    /// → `!=` mutant swaps the two paths, so a narrow accept (this test)
    /// under a non-Union target is what distinguishes them: correct code
    /// emits bytes, mutant code refuses.
    #[test]
    fn raw16_accepts_a_narrow_defined_pattern_under_non_union() {
        // 0xBF00 is `nop` T1 — narrow (`insn_len == 2`), defined on every
        // target the crate knows.
        let mut a = Asm::with_target(Target::V7A);
        a.raw16(0xBF00);
        let bytes = a.finish().expect("nop is baseline everywhere");
        assert_eq!(&bytes[..2], &[0x00, 0xBF]);
    }

    /// `AsmError::at()` must return the actual byte position, not a constant.
    /// The mutants that replace the body with `0` or `1` are killed by a
    /// scenario where `at` is neither: emit a couple of instructions first,
    /// then fail. Uses `sdiv` under V7A (guaranteed Unsupported at pos > 0).
    #[test]
    fn asm_error_at_returns_the_actual_byte_position() {
        let mut a = Asm::with_target(Target::V7A);
        a.raw16_unchecked(0xBF00); // 2 bytes: NOP.
        a.raw16_unchecked(0xBF00); // 2 more: cursor at 4.
        a.sdiv(0, 1, 2); // refused here at position 4.
        let err = a.finish().expect_err("sdiv is UNDEFINED on V7A");
        assert_eq!(
            err.at(),
            4,
            "at() must return the actual position (4), not 0 or 1"
        );
    }
}
