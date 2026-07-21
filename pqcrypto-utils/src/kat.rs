//! KAT test vector parsing utilities.
//! Conditionally compiled — only available when `std` feature is enabled.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::collections::HashMap;
use std::fs;

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
pub fn hex_decode(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Vec::new();
    }
    // Left-pad odd-length hex with a zero nibble (common in KAT files).
    let padded = if !hex.len().is_multiple_of(2) {
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

/// Parses an ACVP-style KAT file into a Vec of HashMaps.
/// Entries are delimited by 'count = N' lines.
#[must_use]
pub fn parse_kat_file(path: &str) -> Vec<HashMap<String, Vec<u8>>> {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("parse_kat_file: failed to read {}: {}", path, e));
    let mut entries = Vec::new();
    let mut current_entry: HashMap<String, Vec<u8>> = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with("count = ") {
            if !current_entry.is_empty() {
                entries.push(current_entry);
                current_entry = HashMap::new();
            }
            continue;
        }

        if let Some(eq_pos) = line.find(" = ") {
            let key = line[..eq_pos].trim();
            let value = line[eq_pos + 3..].trim();
            if key == "count" {
                continue;
            }
            current_entry.insert(key.to_string(), hex_decode(value));
        }
    }

    if !current_entry.is_empty() {
        entries.push(current_entry);
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use std::fs;

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
        // Odd-length hex is left-padded with a zero nibble
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
        let path = "/tmp/test_kat_valid.txt";
        fs::write(path, content).expect("write test file");
        let entries = parse_kat_file(path);
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].get("pk"), Some(&vec![0x00, 0x11, 0x22, 0x33]));
        assert_eq!(entries[0].get("sk"), Some(&vec![0xaa, 0xbb, 0xcc, 0xdd]));

        assert_eq!(entries[1].get("pk"), Some(&vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(entries[1].get("sk"), Some(&vec![0x01, 0x02, 0x03, 0x04]));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_parse_kat_file_empty() {
        let path = "/tmp/test_kat_empty.txt";
        fs::write(path, "").expect("write test file");
        let entries = parse_kat_file(path);
        assert!(entries.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_parse_kat_file_comments_only() {
        let path = "/tmp/test_kat_comments.txt";
        fs::write(path, "# just a comment\n# another one\n").expect("write test file");
        let entries = parse_kat_file(path);
        assert!(entries.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_parse_kat_file_single_entry() {
        let content = "count = 0\nmsg = cafebabe\n";
        let path = "/tmp/test_kat_single.txt";
        fs::write(path, content).expect("write test file");
        let entries = parse_kat_file(path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].get("msg"), Some(&vec![0xca, 0xfe, 0xba, 0xbe]));
        let _ = fs::remove_file(path);
    }
}
