//! Fixture writer with the `encoding` knob. The corpus is utf8 except the 9xx cases,
//! which need more.

use crate::case::Encoding;
use std::io;
use std::path::Path;

/// Write `content` to `path` as `encoding` bytes.
///
/// * [`Encoding::Utf8`] — the string's UTF-8 bytes, verbatim.
/// * [`Encoding::Latin1`] — one byte per scalar; errors on any char above `U+00FF`.
/// * [`Encoding::Utf16Le`] — a `FF FE` BOM followed by UTF-16LE code units.
pub fn write_env_fixture(path: &Path, content: &str, encoding: Encoding) -> io::Result<()> {
  let bytes: Vec<u8> = match encoding {
    Encoding::Utf8 => content.as_bytes().to_vec(),
    Encoding::Latin1 => content
      .chars()
      .map(|c| {
        u8::try_from(u32::from(c)).map_err(|_| {
          io::Error::new(
            io::ErrorKind::InvalidData,
            format!("char {c:?} is not Latin-1-encodable"),
          )
        })
      })
      .collect::<io::Result<Vec<u8>>>()?,
    Encoding::Utf16Le => {
      let mut out = Vec::with_capacity(2 + content.len() * 2);
      out.extend_from_slice(&[0xFF, 0xFE]);
      for unit in content.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
      }
      out
    }
  };
  std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn utf8_writes_verbatim_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join(".env");
    write_env_fixture(&p, "HELLO=world\n", Encoding::Utf8).unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), b"HELLO=world\n");
  }

  #[test]
  fn latin1_writes_one_byte_per_scalar() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join(".env");
    // é = U+00E9 → single byte 0xE9 in Latin-1 (two bytes 0xC3 0xA9 in UTF-8).
    write_env_fixture(&p, "A=caf\u{e9}", Encoding::Latin1).unwrap();
    assert_eq!(
      std::fs::read(&p).unwrap(),
      [b'A', b'=', b'c', b'a', b'f', 0xE9]
    );
  }

  #[test]
  fn latin1_rejects_unencodable_chars() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join(".env");
    let err = write_env_fixture(&p, "A=\u{4e16}", Encoding::Latin1).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
  }

  #[test]
  fn utf16le_writes_ff_fe_bom_then_le_units() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join(".env");
    write_env_fixture(&p, "HELLO=utf16le", Encoding::Utf16Le).unwrap();
    let bytes = std::fs::read(&p).unwrap();
    assert_eq!(&bytes[..2], &[0xFF, 0xFE], "must lead with the FF FE BOM");
    let expected: Vec<u8> = "HELLO=utf16le"
      .encode_utf16()
      .flat_map(|u| u.to_le_bytes())
      .collect();
    assert_eq!(&bytes[2..], &expected[..]);
  }
}
