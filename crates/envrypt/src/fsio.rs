//! File reads, writes, and encoding detection that match Node's `fs`/`Buffer`
//! behavior byte for byte.
//!
//! Node-decode fidelity:
//! * utf8: lossy decode (WHATWG maximal-subpart U+FFFD substitution, what
//!   `Buffer.toString('utf8')` does); a latin1 file read as utf8 yields
//!   replacement chars, never an error.
//! * utf16le: the BOM stays in the string (the decoded U+FEFF is absorbed by the
//!   line regex's JS `\s` class); an odd trailing byte is dropped (Node floors
//!   the length).
//! * latin1: one char per byte (U+0000..U+00FF).
//! * writes are always utf8, so a utf16le-read file is written back as utf8.

use std::io;
use std::path::Path;

/// A file encoding, matching what Node's `fs` layer detects on read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FileEncoding {
  #[default]
  Utf8,
  Utf16Le,
  Latin1,
}

/// Read the file and sniff its BOM: `FF FE` → utf16le; `EF BB BF` → utf8;
/// anything else → utf8. UTF-16BE and latin1 are never detected, matching Node.
pub fn detect_encoding(path: &Path) -> io::Result<FileEncoding> {
  // Read the whole file, then sniff the first bytes. The whole-file read makes
  // ENOENT/EISDIR surface here first, matching Node.
  let buffer = std::fs::read(path)?;
  Ok(detect_encoding_bytes(&buffer))
}

/// The BOM sniff shared with [`detect_encoding`]. A caller already holding the raw
/// bytes gets the same detection without a filesystem read. The `parse_pipeline`
/// fuzz target drives ingestion from a raw byte buffer, so it uses this and
/// [`decode`] instead of a temp file per iteration.
pub fn detect_encoding_bytes(buffer: &[u8]) -> FileEncoding {
  if buffer.len() >= 2 && buffer[0] == 0xFF && buffer[1] == 0xFE {
    return FileEncoding::Utf16Le;
  }
  if buffer.len() >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF {
    return FileEncoding::Utf8;
  }
  FileEncoding::Utf8
}

/// Read a file and decode it per [`FileEncoding`]; `None` defaults to utf8.
pub fn read_file_x(path: &Path, encoding: Option<FileEncoding>) -> io::Result<String> {
  let bytes = std::fs::read(path)?;
  Ok(decode(&bytes, encoding.unwrap_or_default()))
}

/// Decode bytes the way Node's `Buffer.prototype.toString(encoding)` does. Public
/// so the `parse_pipeline` fuzz target can decode a raw byte buffer with the
/// encoding [`detect_encoding_bytes`] returns, exactly as [`read_file_x`] does
/// after the filesystem read.
pub fn decode(bytes: &[u8], encoding: FileEncoding) -> String {
  match encoding {
    FileEncoding::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
    FileEncoding::Latin1 => bytes.iter().map(|&b| b as char).collect(),
    FileEncoding::Utf16Le => {
      // Node floors the length, dropping an odd trailing byte. Node keeps
      // lone surrogates in the string and re-encodes them to U+FFFD when it
      // writes UTF-8 to stdout; substituting U+FFFD here at decode time
      // yields the same output bytes on every path.
      let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
      String::from_utf16_lossy(&units)
    }
  }
}

/// Write a file as utf8, always. A utf16le-read file is written back as utf8.
pub fn write_file_x(path: &Path, content: &str) -> io::Result<()> {
  std::fs::write(path, content.as_bytes())
}

/// Whether the path is stat-able, like Node's `fs.access(F_OK)`.
pub fn exists(path: &Path) -> bool {
  // Any stat-able path counts; symlinks are resolved.
  std::fs::metadata(path).is_ok()
}

/// The Node/libuv errno name for an io error (`error.code`: `"ENOENT"`,
/// `"EACCES"`, …). Numeric errno values differ per OS, so the libc constants are
/// matched on unix; an unmapped value falls back to `"UNKNOWN"` (libuv's label
/// for unrecognized errors). Feeds the io-error strings that `resolvers::envs`
/// and the exec spawn path render.
#[cfg(unix)]
pub fn errno_name(err: &io::Error) -> &'static str {
  let Some(raw) = err.raw_os_error() else {
    return "UNKNOWN";
  };
  match raw {
    libc::EPERM => "EPERM",
    libc::ENOENT => "ENOENT",
    libc::EINTR => "EINTR",
    libc::EIO => "EIO",
    libc::EBADF => "EBADF",
    libc::EAGAIN => "EAGAIN",
    libc::ENOMEM => "ENOMEM",
    libc::EACCES => "EACCES",
    libc::EBUSY => "EBUSY",
    libc::EEXIST => "EEXIST",
    libc::ENOTDIR => "ENOTDIR",
    libc::EISDIR => "EISDIR",
    libc::EINVAL => "EINVAL",
    libc::ENFILE => "ENFILE",
    libc::EMFILE => "EMFILE",
    libc::EFBIG => "EFBIG",
    libc::ENOSPC => "ENOSPC",
    libc::EROFS => "EROFS",
    libc::EPIPE => "EPIPE",
    libc::ENAMETOOLONG => "ENAMETOOLONG",
    libc::ELOOP => "ELOOP",
    libc::ENOTEMPTY => "ENOTEMPTY",
    libc::ETXTBSY => "ETXTBSY",
    libc::ENXIO => "ENXIO",
    libc::ETIMEDOUT => "ETIMEDOUT",
    _ => "UNKNOWN",
  }
}

/// Windows fallback: map [`io::ErrorKind`] to the libuv-style code. The Windows
/// spawn path emulates ENOENT in code, so only the common cases matter here.
#[cfg(not(unix))]
pub fn errno_name(err: &io::Error) -> &'static str {
  match err.kind() {
    io::ErrorKind::NotFound => "ENOENT",
    io::ErrorKind::PermissionDenied => "EPERM",
    io::ErrorKind::AlreadyExists => "EEXIST",
    io::ErrorKind::TimedOut => "ETIMEDOUT",
    _ => "UNKNOWN",
  }
}

/// libuv's human description for an errno name (`uv_strerror`) — the middle of
/// Node's io error message (`"EACCES: permission denied, open '<path>'"`).
pub fn uv_description(code: &str) -> &'static str {
  match code {
    "EPERM" => "operation not permitted",
    "ENOENT" => "no such file or directory",
    "EINTR" => "interrupted system call",
    "EIO" => "i/o error",
    "EBADF" => "bad file descriptor",
    "EAGAIN" => "resource temporarily unavailable",
    "ENOMEM" => "not enough memory",
    "EACCES" => "permission denied",
    "EBUSY" => "resource busy or locked",
    "EEXIST" => "file already exists",
    "ENOTDIR" => "not a directory",
    "EISDIR" => "illegal operation on a directory",
    "EINVAL" => "invalid argument",
    "ENFILE" => "file table overflow",
    "EMFILE" => "too many open files",
    "EFBIG" => "file too large",
    "ENOSPC" => "no space left on device",
    "EROFS" => "read-only file system",
    "EPIPE" => "broken pipe",
    "ENAMETOOLONG" => "name too long",
    "ELOOP" => "too many symbolic links encountered",
    "ENOTEMPTY" => "directory not empty",
    "ETXTBSY" => "text file is busy",
    "ENXIO" => "no such device or address",
    "ETIMEDOUT" => "connection timed out",
    _ => "unknown error",
  }
}

/// A Node `fs.readFileSync(path)`-style error string (what `catch_and_log` prints
/// for a raw fs throw): `"<CODE>: <desc>, open '<path>'"` for most failures, but
/// `"EISDIR: illegal operation on a directory, read"` for a directory. Node opens
/// the directory fine, then the read fails with `EISDIR` (syscall `read`, no path
/// in the message). `path` is the raw value passed to the reader.
pub fn node_read_file_error(err: &io::Error, path: &str) -> String {
  let code = errno_name(err);
  let desc = uv_description(code);
  if code == "EISDIR" {
    format!("{code}: {desc}, read")
  } else {
    format!("{code}: {desc}, open '{path}'")
  }
}

/// A Node `fs.writeFileSync(path, str)`-style error string (what `catch_and_log`
/// prints for a raw fs write throw): `"<CODE>: <desc>, open '<path>'"`.
/// `writeFile` opens the path (`O_WRONLY|O_CREAT|O_TRUNC`), so every failure
/// surfaces at the `open` syscall with the path, including EISDIR when the path is
/// a directory. (A read's EISDIR surfaces at `read`, with no path.) `path` is the
/// raw value passed to the writer, so a relative `.env.keys` stays relative.
pub fn node_write_file_error(err: &io::Error, path: &str) -> String {
  let code = errno_name(err);
  let desc = uv_description(code);
  format!("{code}: {desc}, open '{path}'")
}

#[cfg(test)]
mod detect_encoding_tests {
  // Fixtures: conformance/fixtures/root/.env{,.utf16le,.latin1}.
  use super::*;

  #[test]
  fn detects_utf8() {
    // tap: tests/lib/helpers/detectEncoding.test.js:6-12
    // tap: tests/lib/helpers/detectEncodingSync.test.js:6-12
    let path = test_support::fixture_path("root/.env");
    assert_eq!(detect_encoding(&path).unwrap(), FileEncoding::Utf8);
  }

  #[test]
  fn detects_utf16le_via_ff_fe_bom() {
    // tap: tests/lib/helpers/detectEncoding.test.js:14-20
    // tap: tests/lib/helpers/detectEncodingSync.test.js:14-20
    let path = test_support::fixture_path("root/.env.utf16le");
    assert_eq!(detect_encoding(&path).unwrap(), FileEncoding::Utf16Le);
  }

  #[test]
  fn latin1_falls_back_to_utf8() {
    // tap: tests/lib/helpers/detectEncoding.test.js:22-28
    // tap: tests/lib/helpers/detectEncodingSync.test.js:22-28
    let path = test_support::fixture_path("root/.env.latin1");
    assert_eq!(detect_encoding(&path).unwrap(), FileEncoding::Utf8);
  }

  #[test]
  fn utf8_bom_detected_as_utf8() {
    // detectEncoding{,Sync}.js: EF BB BF branch returns 'utf8'.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".env");
    std::fs::write(&path, [0xEF, 0xBB, 0xBF, b'A', b'=', b'1']).unwrap();
    assert_eq!(detect_encoding(&path).unwrap(), FileEncoding::Utf8);
  }

  #[test]
  fn short_files_are_utf8() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".env");
    std::fs::write(&path, [0xFF]).unwrap();
    assert_eq!(detect_encoding(&path).unwrap(), FileEncoding::Utf8);
    std::fs::write(&path, b"").unwrap();
    assert_eq!(detect_encoding(&path).unwrap(), FileEncoding::Utf8);
  }

  #[test]
  fn byte_level_detection_and_decode_match_the_file_path_variants() {
    // The parse_pipeline fuzz target uses detect_encoding_bytes+decode instead
    // of a temp file per iteration; both must be byte-identical to the
    // detect_encoding + read_file_x file path they stand in for.
    let dir = tempfile::tempdir().unwrap();
    for bytes in [
      b"HELLO=utf8".to_vec(),
      vec![0xFF, 0xFE, b'H', 0x00, b'I', 0x00], // utf16le BOM
      vec![0xEF, 0xBB, 0xBF, b'A', b'=', b'1'], // utf8 BOM
      vec![b'c', b'a', b'f', 0xE9],             // latin1 byte, no BOM
      vec![0xFF],                               // too short for utf16le
      Vec::new(),                               // empty
    ] {
      let path = dir.path().join("probe");
      std::fs::write(&path, &bytes).unwrap();
      let file_encoding = detect_encoding(&path).unwrap();
      assert_eq!(
        detect_encoding_bytes(&bytes),
        file_encoding,
        "bytes={bytes:?}"
      );
      assert_eq!(
        decode(&bytes, file_encoding),
        read_file_x(&path, Some(file_encoding)).unwrap(),
        "bytes={bytes:?}"
      );
    }
  }

  #[test]
  fn missing_file_errors() {
    let dir = tempfile::tempdir().unwrap();
    assert!(detect_encoding(&dir.path().join("nope")).is_err());
  }

  // -- property tests (proptest) ---------------------------------------------
  //
  // Byte-level encoding detection + Node-parity decode is the raw-bytes ingest
  // boundary the `parse_pipeline` fuzz target drives. These express the total /
  // round-trip contract as shrinking properties over arbitrary bytes.
  mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
      /// `detect_encoding_bytes` and `decode` (all three encodings) are total on
      /// arbitrary byte buffers — never a panic.
      #[test]
      fn detect_and_decode_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let enc = detect_encoding_bytes(&bytes);
        let _ = decode(&bytes, enc);
        let _ = decode(&bytes, FileEncoding::Utf8);
        let _ = decode(&bytes, FileEncoding::Latin1);
        let _ = decode(&bytes, FileEncoding::Utf16Le);
      }

      /// latin1 decode is one char per byte and losslessly round-trips: every
      /// decoded char is U+0000..=U+00FF and re-encoding recovers the bytes.
      #[test]
      fn latin1_is_one_char_per_byte(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let decoded = decode(&bytes, FileEncoding::Latin1);
        prop_assert_eq!(decoded.chars().count(), bytes.len());
        let round: Vec<u8> = decoded.chars().map(|c| c as u8).collect();
        prop_assert_eq!(round, bytes);
      }

      /// utf8 decode matches Node's lossy `Buffer.toString('utf8')` oracle.
      #[test]
      fn utf8_decode_matches_lossy_oracle(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        prop_assert_eq!(
          decode(&bytes, FileEncoding::Utf8),
          String::from_utf8_lossy(&bytes).into_owned()
        );
      }
    }
  }
}

#[cfg(test)]
mod fsx_tests {
  // Real temp files stand in for stubs; the assertions check observable results
  // (content bytes, decode) rather than call arguments.
  use super::*;

  #[test]
  fn read_file_x_defaults_to_utf8() {
    // tap: tests/lib/helpers/fsx.test.js:24-33 (#readFileX default utf8)
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("somefile.txt");
    std::fs::write(&path, "hello").unwrap();
    assert_eq!(read_file_x(&path, None).unwrap(), "hello");
  }

  #[test]
  fn read_file_x_explicit_latin1() {
    // tap: tests/lib/helpers/fsx.test.js:35-44 (#readFileX explicit encoding)
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("somefile.txt");
    std::fs::write(&path, [b'c', b'a', b'f', 0xE9]).unwrap();
    assert_eq!(
      read_file_x(&path, Some(FileEncoding::Latin1)).unwrap(),
      "caf\u{e9}"
    );
  }

  #[test]
  fn read_file_x_utf16le_keeps_the_decoded_bom() {
    // Node's utf16le decode keeps the BOM; the fixture is .env.utf16le
    // (FF FE + "HELLO=\"utf16le\"").
    let path = test_support::fixture_path("root/.env.utf16le");
    assert_eq!(
      read_file_x(&path, Some(FileEncoding::Utf16Le)).unwrap(),
      "\u{FEFF}HELLO=\"utf16le\""
    );
  }

  #[test]
  fn read_file_x_utf16le_drops_odd_trailing_byte() {
    // Node floors the byte length on utf16le decode.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("odd");
    std::fs::write(&path, [0xFF, 0xFE, b'H', 0x00, b'I']).unwrap();
    assert_eq!(
      read_file_x(&path, Some(FileEncoding::Utf16Le)).unwrap(),
      "\u{FEFF}H"
    );
  }

  #[test]
  fn read_file_x_utf8_is_lossy_like_node() {
    // A latin1 byte read as utf8 becomes U+FFFD, never an error.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mixed");
    std::fs::write(&path, [b'H', 0xE9, b'I']).unwrap();
    assert_eq!(
      read_file_x(&path, Some(FileEncoding::Utf8)).unwrap(),
      "H\u{FFFD}I"
    );
  }

  #[test]
  fn write_file_x_always_writes_utf8() {
    // tap: tests/lib/helpers/fsx.test.js:46-60 (#writeFileXSync / #writeFileX —
    // one Rust function covers both twins)
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("somefile.txt");
    write_file_x(&path, "héllo").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), "héllo".as_bytes());
  }

  #[test]
  fn exists_reports_access() {
    // tap: tests/lib/helpers/fsx.test.js:62-70 (#exists)
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("somefile.txt");
    std::fs::write(&path, "x").unwrap();
    assert!(exists(&path));
    assert!(!exists(&dir.path().join("missing.txt")));
  }

  // The Node fs error strings the write path renders. `writeFile` opens the
  // path, so every errno surfaces at `open` with the path, including EISDIR. A
  // read's EISDIR surfaces at `read`, with no path.
  #[cfg(unix)]
  #[test]
  fn node_write_file_error_uses_open_syscall_with_path() {
    let eacces = io::Error::from_raw_os_error(libc::EACCES);
    assert_eq!(
      node_write_file_error(&eacces, ".env.keys"),
      "EACCES: permission denied, open '.env.keys'"
    );
    let eisdir = io::Error::from_raw_os_error(libc::EISDIR);
    assert_eq!(
      node_write_file_error(&eisdir, "/abs/.env"),
      "EISDIR: illegal operation on a directory, open '/abs/.env'"
    );
    // readFile's EISDIR is the divergent `, read` (no path) — regression guard.
    assert_eq!(
      node_read_file_error(&eisdir, "/abs/.env"),
      "EISDIR: illegal operation on a directory, read"
    );
  }
}
