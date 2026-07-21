//! The one-shot `envrypt-v1` credential channel supplied by Sockeye.
//!
//! Sockeye passes only the descriptor number and protocol name in the process
//! environment. The private key itself is read once from an inherited pipe,
//! held in a zeroizing allocation, and never copied into `std::env`.

use std::io::Read;

use zeroize::Zeroizing;

/// The private-key name carried by the first version of the channel.
pub const CREDENTIAL_NAME: &str = "ENVRYPT_PRIVATE_KEY";
/// The protocol label used as non-secret process metadata.
pub const PROTOCOL: &str = "envrypt-v1";
const DESCRIPTOR: &str = "3";
const HEADER: [u8; 4] = [b'E', b'V', b'1', 1];

/// A private key received from Sockeye. Dropping this value overwrites its
/// allocation with zeroes before that allocation is released.
pub type InheritedPrivateKey = Zeroizing<String>;

/// Reads the optional inherited Sockeye credential.
///
/// Both metadata variables are required together. Malformed metadata and wire
/// data fail closed so an untrusted parent cannot redirect Envrypt to an
/// arbitrary descriptor or downgrade the protocol.
pub fn read_inherited_private_key() -> Result<Option<InheritedPrivateKey>, String> {
  let protocol = std::env::var_os("SOCKEYE_CREDENTIAL_PROTOCOL");
  let descriptor = std::env::var_os("SOCKEYE_CREDENTIAL_FD");
  read_inherited_from_metadata(protocol, descriptor, read_pipe)
}

fn read_inherited_from_metadata(
  protocol: Option<std::ffi::OsString>,
  descriptor: Option<std::ffi::OsString>,
  read: impl FnOnce() -> Result<InheritedPrivateKey, String>,
) -> Result<Option<InheritedPrivateKey>, String> {
  match (protocol, descriptor) {
    (None, None) => Ok(None),
    (Some(protocol), Some(descriptor)) if protocol == PROTOCOL && descriptor == DESCRIPTOR => {
      read().map(Some)
    }
    _ => Err("Sockeye credential refused: envrypt-v1 metadata is invalid.".to_string()),
  }
}

#[cfg(unix)]
fn read_pipe() -> Result<InheritedPrivateKey, String> {
  use std::os::fd::FromRawFd;

  // Sockeye creates this anonymous pipe immediately before exec. Taking
  // ownership closes it on every success and error path.
  // FUZZ: sockeye_decode drives the record parser this descriptor feeds.
  let pipe = unsafe { std::fs::File::from_raw_fd(3) };
  decode(pipe)
}

/// Parses one `envrypt-v1` wire record from `pipe` — the fixed header, the name
/// and value lengths, the credential name, and a 64-hex key — failing closed on
/// any malformed field. Exposed for the `sockeye_decode` fuzz target; not part
/// of the curated public API.
pub fn decode(mut pipe: impl Read) -> Result<InheritedPrivateKey, String> {
  let mut header = [0_u8; 8];
  read_exact(&mut pipe, &mut header)?;
  if header[..4] != HEADER {
    return Err("Sockeye credential refused: envrypt-v1 header is invalid.".to_string());
  }
  let name_length = usize::from(u16::from_be_bytes([header[4], header[5]]));
  let value_length = usize::from(u16::from_be_bytes([header[6], header[7]]));
  if name_length != CREDENTIAL_NAME.len() || value_length != 64 {
    return Err("Sockeye credential refused: envrypt-v1 lengths are invalid.".to_string());
  }

  let mut name = [0_u8; CREDENTIAL_NAME.len()];
  read_exact(&mut pipe, &mut name)?;
  if name != *CREDENTIAL_NAME.as_bytes() {
    return Err("Sockeye credential refused: envrypt-v1 name is invalid.".to_string());
  }

  let mut value = Zeroizing::new(vec![0_u8; value_length]);
  read_exact(&mut pipe, &mut value)?;
  if !value.iter().all(u8::is_ascii_hexdigit) {
    return Err("Sockeye credential refused: envrypt-v1 key is invalid.".to_string());
  }
  let mut extra = [0_u8; 1];
  if pipe
    .read(&mut extra)
    .map_err(|_| "Sockeye credential refused: envrypt-v1 pipe could not be read.".to_string())?
    != 0
  {
    return Err("Sockeye credential refused: envrypt-v1 has trailing data.".to_string());
  }

  let text = String::from_utf8(value.to_vec())
    .map_err(|_| "Sockeye credential refused: envrypt-v1 key is invalid.".to_string())?;
  Ok(Zeroizing::new(text))
}

#[cfg(not(unix))]
fn read_pipe() -> Result<InheritedPrivateKey, String> {
  Err("Sockeye credential refused: envrypt-v1 requires a Unix pipe.".to_string())
}

fn read_exact(pipe: &mut impl Read, buffer: &mut [u8]) -> Result<(), String> {
  pipe
    .read_exact(buffer)
    .map_err(|_| "Sockeye credential refused: envrypt-v1 pipe ended early.".to_string())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::io::Cursor;

  fn record(value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&HEADER);
    bytes.extend_from_slice(&(CREDENTIAL_NAME.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(CREDENTIAL_NAME.as_bytes());
    bytes.extend_from_slice(value);
    bytes
  }

  #[test]
  fn reads_one_valid_record() {
    let value = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert_eq!(
      &*decode(Cursor::new(record(value))).unwrap(),
      std::str::from_utf8(value).unwrap()
    );
  }

  #[test]
  fn rejects_trailing_bytes() {
    let value = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let mut bytes = record(value);
    bytes.push(1);
    assert!(decode(Cursor::new(bytes)).unwrap_err().contains("trailing"));
  }

  #[test]
  fn rejects_non_hex_key() {
    assert!(decode(Cursor::new(record(&[b'x'; 64]))).is_err());
  }

  #[test]
  fn rejects_invalid_header_lengths_and_name() {
    let value = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let mut invalid_header = record(value);
    invalid_header[0] = b'X';
    assert!(decode(Cursor::new(invalid_header))
      .unwrap_err()
      .contains("header"));

    let mut invalid_length = record(value);
    invalid_length[7] = 63;
    assert!(decode(Cursor::new(invalid_length))
      .unwrap_err()
      .contains("lengths"));

    let mut invalid_name = record(value);
    invalid_name[8] = b'X';
    assert!(decode(Cursor::new(invalid_name))
      .unwrap_err()
      .contains("name"));
  }

  #[test]
  fn rejects_early_pipe_end() {
    assert!(decode(Cursor::new(Vec::<u8>::new()))
      .unwrap_err()
      .contains("ended early"));
  }

  #[test]
  fn metadata_only_accepts_the_exact_protocol_and_descriptor() {
    let key = || {
      Ok(Zeroizing::new(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
      ))
    };
    assert!(read_inherited_from_metadata(None, None, key)
      .unwrap()
      .is_none());

    let key = || {
      Ok(Zeroizing::new(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
      ))
    };
    assert_eq!(
      &*read_inherited_from_metadata(Some(PROTOCOL.into()), Some(DESCRIPTOR.into()), key)
        .unwrap()
        .unwrap(),
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );

    let unused = || panic!("invalid metadata must not read a descriptor");
    assert!(read_inherited_from_metadata(Some(PROTOCOL.into()), None, unused).is_err());

    let unavailable = || Err("pipe unavailable".to_string());
    assert!(read_inherited_from_metadata(
      Some(PROTOCOL.into()),
      Some(DESCRIPTOR.into()),
      unavailable,
    )
    .unwrap_err()
    .contains("unavailable"));
  }

  #[cfg(unix)]
  #[test]
  fn reads_the_real_inherited_descriptor_in_a_child_process() {
    use std::os::unix::process::ExitStatusExt;

    let value = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let record = record(value);
    let mut pipe = [-1_i32; 2];
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
    assert_eq!(
      unsafe { libc::write(pipe[1], record.as_ptr().cast(), record.len()) },
      record.len() as isize
    );
    assert_eq!(unsafe { libc::close(pipe[1]) }, 0);

    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
      assert_eq!(unsafe { libc::dup2(pipe[0], 3) }, 3);
      if pipe[0] != 3 {
        assert_eq!(unsafe { libc::close(pipe[0]) }, 0);
      }
      std::env::set_var("SOCKEYE_CREDENTIAL_PROTOCOL", PROTOCOL);
      std::env::set_var("SOCKEYE_CREDENTIAL_FD", DESCRIPTOR);
      let received = read_inherited_private_key();
      let valid = received.as_ref().is_ok_and(|key| {
        key.as_ref().map(|value| value.as_str()) == Some(std::str::from_utf8(value).unwrap())
      });
      std::process::exit(i32::from(!valid));
    }

    assert_eq!(unsafe { libc::close(pipe[0]) }, 0);
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert_eq!(std::process::ExitStatus::from_raw(status).code(), Some(0));
  }
}
