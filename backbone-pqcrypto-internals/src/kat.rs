//! KAT test vector parsing utilities.
//! Conditionally compiled — only available when `std` feature is enabled.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Helper to decode hex strings to byte vectors.
///
/// Odd-length input is left-padded with a zero nibble (e.g., `"abc"` → `0x0a, 0xbc`).
/// This matches the behavior of common KAT file formats where leading zeros
/// may be stripped.
///
/// # Panics
///
/// Panics if the string (after trimming) is empty or contains non-hex characters.
#[must_use]
pub(crate) fn hex_decode(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Vec::new();
    }
    let padded = if hex.len() % 2 != 0 {
        alloc::format!("0{hex}")
    } else {
        hex.to_string()
    };
    (0..padded.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&padded[i..i + 2], 16)
                .expect("hex_decode: input must be valid hex characters")
        })
        .collect()
}

fn decode_rsp_value(value: &str) -> Vec<u8> {
    match value.trim() {
        "null" => return Vec::new(),
        "true" | "false" => return value.as_bytes().to_vec(),
        _ => {}
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        hex_decode(trimmed)
    } else {
        trimmed.as_bytes().to_vec()
    }
}

/// Parses a KAT `.rsp` file into a Vec of HashMaps.
///
/// Handles both ACVP-style and old NIST submission format:
/// - Entries are delimited by `count = N` lines
/// - Hex values are decoded to bytes
/// - Booleans (`true`/`false`) stored as raw ASCII
/// - Non-hex strings (e.g. `hashAlg = SHA-256`) stored as raw ASCII
/// - `null` values are skipped
#[must_use]
pub fn parse_kat_file(path: impl AsRef<Path>) -> Vec<HashMap<String, Vec<u8>>> {
    let content = fs::read_to_string(path.as_ref()).unwrap_or_else(|e| {
        panic!(
            "parse_kat_file: failed to read {}: {}",
            path.as_ref().display(),
            e
        )
    });
    let mut entries = Vec::new();
    let mut current_entry: HashMap<String, Vec<u8>> = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with("count = ") {
            if !current_entry.is_empty() {
                entries.push(core::mem::take(&mut current_entry));
            }
            continue;
        }

        if let Some(eq_pos) = line.find(" = ") {
            let key = line[..eq_pos].trim();
            let value = line[eq_pos + 3..].trim();
            if key == "count" {
                continue;
            }
            let decoded = decode_rsp_value(value);
            if !decoded.is_empty() {
                current_entry.insert(key.to_string(), decoded);
            }
        }
    }

    if !current_entry.is_empty() {
        entries.push(current_entry);
    }

    entries
}

/// Absolute path of the calling crate's committed KAT vector directory
/// (`tests/kats` under the crate's `CARGO_MANIFEST_DIR`).
///
/// Cargo exports `CARGO_MANIFEST_DIR` to the test process, so this resolves
/// to the crate under test (not this utilities crate) and replaces the
/// identical 4-line helper historically copy-pasted into every KAT file.
#[must_use]
pub fn kat_dir() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("kats")
}

/// A test-only RNG that streams a fixed byte buffer.
///
/// Drives the public `*_with_rng` entry points of the algorithm crates with
/// exact KAT vector bytes, so vector-exact tests run through the same code
/// path as production. Once the buffer is exhausted, reads return zeros.
#[derive(Debug)]
pub struct FixedRng {
    bytes: Vec<u8>,
    pos: usize,
}

impl FixedRng {
    /// Create an RNG that yields `bytes` in order, then zeros.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, pos: 0 }
    }
}

impl rand_core::RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = if self.pos < self.bytes.len() {
                let b = self.bytes[self.pos];
                self.pos += 1;
                b
            } else {
                0
            };
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for FixedRng {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use std::fs;

    fn tmp_file(name: &str) -> PathBuf {
        std::env::temp_dir().join(name)
    }

    #[test]
    fn test_hex_decode_basic() {
        assert_eq!(hex_decode("00"), vec![0x00]);
        assert_eq!(hex_decode("ff"), vec![0xff]);
        assert_eq!(hex_decode("deadbeef"), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_hex_decode_with_whitespace() {
        assert_eq!(hex_decode("  ab  "), vec![0xab]);
    }

    #[test]
    fn test_hex_decode_odd_length() {
        assert_eq!(hex_decode("abb"), vec![0x0a, 0xbb]);
    }

    #[test]
    fn test_hex_decode_empty() {
        let result: Vec<u8> = hex_decode("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_kat_file_valid() {
        let content = "\
# KAT test
count = 0
pk = 00112233
sk = aabbccdd

count = 1
pk = deadbeef
sk = 01020304
";
        let path = tmp_file("test_kat_valid.txt");
        fs::write(&path, content).expect("write test file");
        let entries = parse_kat_file(&path);
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].get("pk"), Some(&vec![0x00, 0x11, 0x22, 0x33]));
        assert_eq!(entries[0].get("sk"), Some(&vec![0xaa, 0xbb, 0xcc, 0xdd]));

        assert_eq!(entries[1].get("pk"), Some(&vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(entries[1].get("sk"), Some(&vec![0x01, 0x02, 0x03, 0x04]));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_parse_kat_file_empty() {
        let path = tmp_file("test_kat_empty.txt");
        fs::write(&path, "").expect("write test file");
        let entries = parse_kat_file(&path);
        assert!(entries.is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_parse_kat_file_comments_only() {
        let path = tmp_file("test_kat_comments.txt");
        fs::write(&path, "# just a comment\n# another one\n").expect("write test file");
        let entries = parse_kat_file(&path);
        assert!(entries.is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_parse_kat_file_single_entry() {
        let content = "count = 0\nmsg = cafebabe\n";
        let path = tmp_file("test_kat_single.txt");
        fs::write(&path, content).expect("write test file");
        let entries = parse_kat_file(&path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].get("msg"), Some(&vec![0xca, 0xfe, 0xba, 0xbe]));
        let _ = fs::remove_file(&path);
    }
}
