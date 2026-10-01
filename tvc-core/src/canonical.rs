//! The one canonical byte encoding for every document this crate publishes.
//!
//! A document's identity is the SHA-256 of its canonical bytes, so two parties
//! holding the same document must produce the same bytes or they will disagree
//! about which document they hold. The rules are deliberately few, so that a
//! third party can reproduce them in any language without this crate:
//!
//! - Objects are written with keys in byte order and no whitespace anywhere.
//! - Strings use JSON escaping as `serde_json` writes it: `"` and `\` are
//!   escaped, control characters become `\n`, `\t`, `\uXXXX` and so on, and
//!   every other character is written as raw UTF-8.
//! - Numbers must be integers. A float has more than one plausible decimal
//!   rendering across languages, so a value like a sampling temperature is
//!   written as a string (`"0.7"`) and the document says what it means.
//! - Arrays keep their order. `null`, `true` and `false` are written as-is.
//!
//! The digest is a plain, untagged SHA-256 of those bytes on purpose: anyone
//! can check a published `objects/<digest>.json` file with `sha256sum`.

use bitcoin_hashes::{sha256, HashEngine};
use serde_json::Value;

use crate::error::{Result, TvcError};

/// Encodes a JSON value canonically.
///
/// # Errors
///
/// Returns [`TvcError::InvalidDocument`] if the value contains a non-integer
/// number, which has no canonical encoding under these rules.
pub fn to_canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// SHA-256 of a value's canonical bytes: its content address.
///
/// # Errors
///
/// As [`to_canonical_bytes`].
pub fn canonical_digest(value: &Value) -> Result<[u8; 32]> {
    Ok(sha256_bytes(&to_canonical_bytes(value)?))
}

/// Parses bytes that claim to be a canonical document and confirms they are.
///
/// A document fetched from disk or the network is only trusted as the document
/// named by its digest if re-encoding it gives back exactly the bytes that were
/// hashed. Accepting a non-canonical file would let two different byte strings
/// stand for one document.
///
/// # Errors
///
/// Returns [`TvcError::InvalidDocument`] if the bytes are not JSON or are not in
/// canonical form.
pub fn parse_canonical(bytes: &[u8]) -> Result<Value> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| TvcError::InvalidDocument(format!("not JSON: {error}")))?;
    if to_canonical_bytes(&value)? != bytes {
        return Err(TvcError::InvalidDocument(
            "bytes are valid JSON but not in canonical form".to_owned(),
        ));
    }
    Ok(value)
}

/// Plain SHA-256 of a byte string.
pub fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(bytes);
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            if !(number.is_i64() || number.is_u64()) {
                return Err(TvcError::InvalidDocument(format!(
                    "number {number} is not an integer; write decimals as strings"
                )));
            }
            out.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push(b'[');
            for (position, item) in items.iter().enumerate() {
                if position > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            out.push(b'{');
            for (position, key) in keys.into_iter().enumerate() {
                if position > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write_value(&map[key], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(text: &str, out: &mut Vec<u8>) {
    let encoded = serde_json::to_string(text).expect("a string always serialises");
    out.extend_from_slice(encoded.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canonical(value: Value) -> String {
        String::from_utf8(to_canonical_bytes(&value).unwrap()).unwrap()
    }

    #[test]
    fn keys_are_sorted_and_whitespace_dropped() {
        assert_eq!(
            canonical(json!({"b": 1, "a": [true, null, "x"], "c": {"z": 0, "y": -2}})),
            r#"{"a":[true,null,"x"],"b":1,"c":{"y":-2,"z":0}}"#
        );
    }

    #[test]
    fn key_order_is_byte_order_not_locale_order() {
        assert_eq!(canonical(json!({"a": 1, "B": 2, "_": 3})), r#"{"B":2,"_":3,"a":1}"#);
    }

    #[test]
    fn strings_escape_controls_and_keep_unicode_raw() {
        assert_eq!(
            canonical(json!("quote\" slash\\ nl\n tab\t bell\u{7} é 漢")),
            "\"quote\\\" slash\\\\ nl\\n tab\\t bell\\u0007 é 漢\""
        );
    }

    #[test]
    fn floats_are_refused() {
        assert!(matches!(
            to_canonical_bytes(&json!({"temperature": 0.7})),
            Err(TvcError::InvalidDocument(_))
        ));
    }

    #[test]
    fn insertion_order_does_not_change_the_digest() {
        let left: Value = serde_json::from_str(r#"{"x":1,"y":2}"#).unwrap();
        let right: Value = serde_json::from_str(r#"{"y":2,"x":1}"#).unwrap();
        assert_eq!(canonical_digest(&left).unwrap(), canonical_digest(&right).unwrap());
    }

    #[test]
    fn the_digest_is_plain_sha256_of_the_bytes() {
        // sha256 of the two bytes `{}`, computed independently with
        // `printf '{}' | shasum -a 256`.
        assert_eq!(
            crate::hex::encode(&canonical_digest(&json!({})).unwrap()),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn non_canonical_bytes_are_refused_on_read() {
        assert!(parse_canonical(br#"{"a":1}"#).is_ok());
        assert!(parse_canonical(br#"{ "a": 1 }"#).is_err());
        assert!(parse_canonical(br#"{"b":1,"a":2}"#).is_err());
    }
}
