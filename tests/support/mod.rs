//! Support code for the LLVM conformance harness in `tests/conformance.rs`.
//!
//! Nothing in here knows anything about Thumb. It is the plumbing: find an
//! LLVM toolchain, drive it in batches, and read the bytes back out of the
//! object file it produces. Keeping it separate means `conformance.rs` reads
//! as the *argument* being made — bytes in, bytes out, do they match — rather
//! than as a pile of `Command` wrangling.
//!
//! It lives in `tests/support/` rather than `tests/` because Cargo compiles
//! every `.rs` file directly under `tests/` as its own test binary, and this
//! one has no tests in it. A subdirectory is the idiomatic way to share code
//! between integration tests without inventing a dev-dependency — the crate
//! has none and is to keep none.
//!
//! # Why an object file and not `-show-encoding`
//!
//! `llvm-mc --show-encoding` prints `# encoding: [0x01,0x20]` next to each
//! instruction, which looks like the obvious thing to parse. It is not
//! available from `clang`, and `clang` is the LLVM most machines already have.
//! Assembling to an ELF object and reading `.text` works identically under
//! both, needs no third tool, and is parsing a fixed binary layout rather than
//! human-readable output that changes between releases.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Toolchain discovery
// ---------------------------------------------------------------------------

/// Which LLVM front end was found. Both assemble; they differ only in how the
/// target and output file are spelled on the command line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AsmKind {
    /// `llvm-mc`, the MC-layer driver. Preferred: it is the assembler with
    /// nothing else attached, so its behaviour is not perturbed by driver
    /// defaults.
    Mc,
    /// `clang` driving its integrated assembler. The fallback, and in
    /// practice the common case — every Xcode and every distro LLVM has it.
    Clang,
}

/// A located, *verified* assembler. "Verified" means it has already been asked
/// to assemble a known Thumb instruction and produced the known bytes; a tool
/// that exists but was built without the ARM backend never gets this far.
pub struct Asm {
    pub path: PathBuf,
    pub kind: AsmKind,
    pub version: String,
}

/// A located, verified `llvm-objdump`, used only for the reverse direction.
pub struct Objdump {
    pub path: PathBuf,
    pub version: String,
}

/// Directories to look in, in priority order, in addition to `$PATH`.
///
/// `$PATH` is covered by trying the bare name first: `Command::new("llvm-mc")`
/// does a `$PATH` lookup. The explicit directories cover the two common ways
/// an LLVM ends up on a machine without being on `$PATH` — Homebrew keeps its
/// `llvm` keg unlinked, and Apple's Command Line Tools ship `llvm-objdump` and
/// `clang` in a directory that is only partly symlinked into `/usr/bin`.
fn search_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(d) = std::env::var("THUMB_ASM_LLVM_BIN") {
        dirs.push(PathBuf::from(d));
    }
    dirs.push(PathBuf::new()); // empty prefix == bare name == $PATH lookup
    for d in [
        "/opt/homebrew/opt/llvm/bin",
        "/usr/local/opt/llvm/bin",
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/Library/Developer/CommandLineTools/usr/bin",
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin",
        "/usr/lib/llvm/bin",
        "/usr/bin",
    ] {
        dirs.push(PathBuf::from(d));
    }
    dirs
}

/// Versioned suffixes to try, newest first. LLVM packages on Debian, Ubuntu
/// and Fedora all install as `llvm-mc-17`, `clang-16` and so on with no
/// unsuffixed symlink, so a harness that only looks for the bare name finds
/// nothing on exactly the machines most likely to be running CI.
const VERSION_SUFFIXES: &[&str] = &[
    "", "-21", "-20", "-19", "-18", "-17", "-16", "-15", "-14", "-13", "-12", "-11",
];

fn candidates(stem: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in search_dirs() {
        for suffix in VERSION_SUFFIXES {
            let name = format!("{stem}{suffix}");
            out.push(if dir.as_os_str().is_empty() {
                PathBuf::from(name)
            } else {
                dir.join(name)
            });
        }
    }
    out
}

fn version_of(path: &Path) -> Option<String> {
    let out = Command::new(path).arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains("version"))?;
    Some(line.trim().to_string())
}

/// Find an assembler and prove it can assemble Thumb.
///
/// Returns `None` — never an error — when there is no usable LLVM on the
/// machine. That is the whole point of the discovery step: a contributor
/// without LLVM installed must still get a green `cargo test`.
pub fn find_assembler(scratch: &Path) -> Option<Asm> {
    // Set `THUMB_ASM_SKIP_LLVM=1` to exercise the skip path on a machine that
    // does have LLVM. The skip path is the one contributors without LLVM will
    // hit, so it needs to be checkable by someone who is not one of them.
    if std::env::var_os("THUMB_ASM_SKIP_LLVM").is_some() {
        return None;
    }
    let mut tried: Vec<PathBuf> = Vec::new();
    for (stem, kind) in [("llvm-mc", AsmKind::Mc), ("clang", AsmKind::Clang)] {
        for path in candidates(stem) {
            if tried.contains(&path) {
                continue;
            }
            tried.push(path.clone());
            let version = match version_of(&path) {
                Some(v) => v,
                None => continue,
            };
            let asm = Asm {
                path: path.clone(),
                kind,
                version,
            };
            if canary_ok(&asm, scratch) {
                return Some(asm);
            }
        }
    }
    None
}

/// The capability test: assemble one instruction whose encoding is not in
/// dispute and check the bytes. `movs r0, #1` is `0x2001`, little-endian
/// `01 20` (ARM DDI 0403E.e A7.7.76, encoding T1).
fn canary_ok(asm: &Asm, scratch: &Path) -> bool {
    let src = "\t.syntax unified\n\t.thumb\n\t.arch armv7-a\n\t.text\n\tmovs r0, #1\n";
    match assemble(asm, scratch, "canary", src) {
        Ok(Assembled::Object { text, .. }) => text == [0x01, 0x20],
        _ => false,
    }
}

/// Find an `llvm-objdump`. Optional: without one the harness still runs the
/// forward direction (our text -> LLVM -> bytes) and only loses the reverse
/// census of what LLVM's *decoder* accepts.
pub fn find_objdump(asm: &Asm, scratch: &Path) -> Option<Objdump> {
    // The canary object is produced by the assembler that was just found,
    // rather than hand-built here, so it carries the `.ARM.attributes` an ARM
    // object is meant to carry. Hand-building one was the first version of
    // this and it silently cost the harness every Advanced SIMD result.
    let canary = match assemble(
        asm,
        scratch,
        "objdump-canary",
        "\t.syntax unified\n\t.thumb\n\t.arch armv7-a\n\t.text\n\tmovs r0, #1\n",
    ) {
        Ok(Assembled::Object { object, .. }) => object,
        _ => return None,
    };
    let mut tried: Vec<PathBuf> = Vec::new();
    for path in candidates("llvm-objdump") {
        if tried.contains(&path) {
            continue;
        }
        tried.push(path.clone());
        let version = match version_of(&path) {
            Some(v) => v,
            None => continue,
        };
        let dump = Objdump {
            path: path.clone(),
            version,
        };
        // Prove it can read an ELF32 little-endian ARM object and
        // disassemble Thumb, rather than merely existing.
        if let Some(lines) = raw_disassemble(&dump, &canary, "thumbv7a-none-eabi", "cortex-a15") {
            if lines.iter().any(|l| l.1.contains("movs")) {
                return Some(dump);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Running the assembler
// ---------------------------------------------------------------------------

/// The outcome of one assembler invocation.
pub enum Assembled {
    /// The whole file assembled. `text` is the contents of `.text`; `object`
    /// is the object file itself, kept because `llvm-objdump` must be pointed
    /// at a *real* object to disassemble correctly — an ARM object carries a
    /// `.ARM.attributes` section naming the architecture and FPU, and without
    /// it objdump falls back to the bare triple's defaults and silently
    /// declines to decode Advanced SIMD.
    Object { text: Vec<u8>, object: PathBuf },
    /// Some lines were rejected; here are their 1-based line numbers paired
    /// with the assembler's first message for each.
    Errors(Vec<(usize, String)>),
}

/// Assemble `source`, returning either `.text` or the rejected line numbers.
///
/// The error path is not a failure: sweeping the encoding space *means*
/// handing the assembler text it will refuse, and which lines it refuses is
/// one of the two things being measured.
pub fn assemble(asm: &Asm, scratch: &Path, tag: &str, source: &str) -> Result<Assembled, String> {
    let s_path = scratch.join(format!("{tag}.s"));
    let o_path = scratch.join(format!("{tag}.o"));
    fs::write(&s_path, source).map_err(|e| format!("writing {}: {e}", s_path.display()))?;
    discard(&o_path);

    let mut cmd = Command::new(&asm.path);
    match asm.kind {
        AsmKind::Mc => {
            cmd.arg("--assemble")
                .arg("--filetype=obj")
                .arg("--triple=thumbv7a-none-eabi")
                .arg("-o")
                .arg(&o_path)
                .arg(&s_path);
        }
        AsmKind::Clang => {
            cmd.arg("-target")
                .arg("thumbv7a-none-eabi")
                .arg("-c")
                .arg("-o")
                .arg(&o_path)
                .arg(&s_path);
        }
    }
    // Spawn first, delete second, *then* propagate. `?` on the spawn result
    // would return before `discard` ran and leave the `.s` behind — and the
    // path that fails to spawn is exactly the one that repeats for every probe
    // in a sweep, so the leak is unbounded rather than one file.
    let spawned = cmd.output();
    // The source is worth tens of megabytes across a sweep and is of no use
    // once the assembler has read it. Deleting it here rather than at the end
    // keeps the scratch directory's high-water mark at one file, which matters:
    // an exhaustive sweep otherwise leaves half a gigabyte behind.
    discard(&s_path);
    let out = spawned.map_err(|e| format!("running {}: {e}", asm.path.display()))?;
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let errors = parse_errors(&stderr);
    if !errors.is_empty() {
        return Ok(Assembled::Errors(errors));
    }
    if !out.status.success() {
        return Err(format!(
            "{} failed with no parseable diagnostics:\n{stderr}",
            asm.path.display()
        ));
    }
    let obj = fs::read(&o_path).map_err(|e| format!("reading {}: {e}", o_path.display()))?;
    let text = elf32_section(&obj, ".text")
        .ok_or_else(|| "assembled object has no readable .text section".to_string())?;
    Ok(Assembled::Object {
        text: text.to_vec(),
        object: o_path,
    })
}

/// Remove a scratch file, unless the caller asked to keep the scratch
/// directory for inspection.
pub fn discard(path: &Path) {
    if std::env::var_os("THUMB_ASM_KEEP_SCRATCH").is_none() {
        let _ = fs::remove_file(path);
    }
}

/// Pull `file:line:col: error: message` out of an assembler's stderr.
///
/// `llvm-mc` and `clang` both use exactly this format and both report *every*
/// rejected line in one run — there is no error limit on the assembler path —
/// which is what makes a single retry enough to converge.
fn parse_errors(stderr: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for line in stderr.lines() {
        let marker = match line.find(": error: ") {
            Some(i) => i,
            None => continue,
        };
        let (locus, rest) = line.split_at(marker);
        let message = rest[": error: ".len()..].trim().to_string();
        // `locus` is `path:line:col`; the path may itself contain colons on
        // some platforms, so count from the right.
        let mut parts = locus.rsplit(':');
        let _col = parts.next();
        if let Some(n) = parts.next().and_then(|n| n.trim().parse::<usize>().ok()) {
            out.push((n, message));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Disassembly (the reverse direction)
// ---------------------------------------------------------------------------

/// Disassemble an object file, returning `(address, text)` for every line.
pub fn raw_disassemble(
    dump: &Objdump,
    obj: &Path,
    triple: &str,
    cpu: &str,
) -> Option<Vec<(u32, String)>> {
    let out = Command::new(&dump.path)
        .arg("-d")
        .arg(format!("--triple={triple}"))
        .arg(format!("--mcpu={cpu}"))
        .arg("--no-show-raw-insn")
        .arg(obj)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut lines = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let colon = match trimmed.find(':') {
            Some(i) => i,
            None => continue,
        };
        let addr = match u32::from_str_radix(&trimmed[..colon], 16) {
            Ok(a) => a,
            Err(_) => continue,
        };
        // Tabs separate mnemonic from operands in objdump's output; they are
        // flattened so a disassembly can be carried through a tab-separated
        // triage report without shredding it.
        let body = trimmed[colon + 1..].trim().replace('\t', " ");
        if body.is_empty() {
            continue;
        }
        lines.push((addr, body));
    }
    Some(lines)
}

// ---------------------------------------------------------------------------
// ELF32 little-endian: just enough to find one section
// ---------------------------------------------------------------------------

fn u16le(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn u32le(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// The bytes of the named section of a 32-bit little-endian ELF object.
///
/// Hand-rolled rather than shelled out to `llvm-objcopy`, because the layout
/// is fixed by the ELF standard and forty lines here is cheaper than a second
/// tool that has to be discovered, version-checked and skipped around.
pub fn elf32_section<'a>(obj: &'a [u8], want: &str) -> Option<&'a [u8]> {
    if obj.get(..4)? != b"\x7fELF" || obj.get(4)? != &1 || obj.get(5)? != &1 {
        return None; // not ELF32 little-endian
    }
    let shoff = u32le(obj, 0x20)? as usize;
    let shentsize = u16le(obj, 0x2E)? as usize;
    let shnum = u16le(obj, 0x30)? as usize;
    let shstrndx = u16le(obj, 0x32)? as usize;
    if shentsize < 40 || shstrndx >= shnum {
        return None;
    }
    let header = |i: usize| -> Option<(u32, u32, u32, u32)> {
        let base = shoff.checked_add(i.checked_mul(shentsize)?)?;
        Some((
            u32le(obj, base)?,      // sh_name
            u32le(obj, base + 16)?, // sh_offset
            u32le(obj, base + 20)?, // sh_size
            u32le(obj, base + 4)?,  // sh_type
        ))
    };
    let (_, strtab_off, strtab_size, _) = header(shstrndx)?;
    let strtab = obj.get(strtab_off as usize..(strtab_off + strtab_size) as usize)?;
    for i in 0..shnum {
        let (name_off, off, size, sh_type) = header(i)?;
        let name_bytes = strtab.get(name_off as usize..)?;
        let end = name_bytes.iter().position(|&c| c == 0)?;
        if &name_bytes[..end] != want.as_bytes() {
            continue;
        }
        if sh_type == 8 {
            // SHT_NOBITS: occupies no file space.
            return Some(&[]);
        }
        return obj.get(off as usize..(off + size) as usize);
    }
    None
}

// ---------------------------------------------------------------------------
// Scratch directory
// ---------------------------------------------------------------------------

/// A private temporary directory, removed when the guard drops.
pub struct Scratch {
    pub dir: PathBuf,
}

impl Scratch {
    pub fn new(tag: &str) -> std::io::Result<Scratch> {
        // The name carries a nonce and a per-process counter, and the directory
        // is made with `create_dir` rather than `create_dir_all`.
        //
        // Both halves matter on a shared build machine. A name built from the
        // pid and a fixed tag alone is predictable — pids are visible to any
        // local user — and the old `remove_dir_all` then `create_dir_all` pair
        // left a window in which someone could replace the path with a symlink
        // to a directory they control: `create_dir_all` accepts an existing
        // path silently, so every later `fs::write` of a generated `.s`/`.o`
        // would follow it. `create_dir` instead fails with `AlreadyExists`,
        // which turns that race into a test error rather than a write into
        // someone else's tree. The counter also keeps two concurrently-running
        // tests in the same process from sharing a scratch directory, which
        // `cargo test`'s threaded harness makes reachable without any attacker
        // at all.
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "thumb-asm-conformance-{}-{tag}-{nonce:08x}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir)?;
        Ok(Scratch { dir })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if std::env::var_os("THUMB_ASM_KEEP_SCRATCH").is_none() {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}
