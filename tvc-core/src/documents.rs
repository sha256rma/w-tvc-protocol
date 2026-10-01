//! The four reference document kinds, and where documents are kept.
//!
//! A reference profile is a small chain of documents, each naming the one
//! before it by digest:
//!
//! ```text
//!   weights-manifest/v1   which files            (public)
//!          ▲
//!   reference-setup/v1    how they were run      (public, self-reported)
//!          ▲
//!   reference-run/v1      prompt and output roots, bands  (roots public, items revealed later)
//!          ▲
//!   profile/v1            one handbook entry version
//! ```
//!
//! [`validate_document`] checks a document's fields and that each reference
//! points at the right kind. Kinds this crate does not define are accepted
//! without field checks, so another project can keep its own documents in the
//! same ledger; such a document may list its references under a top-level
//! `refs` array.
//!
//! A setup record is the operator of the reference describing their own run.
//! Nothing here can check that the engine version or GPU named is the one that
//! ran. What it does fix is the description: it cannot be changed after the
//! fact, and a third party can re-run with exactly the stated configuration.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::canonical::{parse_canonical, sha256_bytes, to_canonical_bytes};
use crate::error::{Result, TvcError};
use crate::hex;
use crate::manifest::{WeightsManifest, KIND_WEIGHTS_MANIFEST};
use crate::signer::validate_kind;

/// Document kind for how reference weights were run.
pub const KIND_REFERENCE_SETUP: &str = "reference-setup/v1";
/// Document kind for one reference run's committed prompts and outputs.
pub const KIND_REFERENCE_RUN: &str = "reference-run/v1";
/// Document kind for one version of a handbook profile.
pub const KIND_PROFILE: &str = "profile/v1";

/// Profile maturity levels, as the SPOT handbook defines them.
pub const MATURITY_LEVELS: [&str; 3] = ["skeleton", "working", "full"];

fn invalid(kind: &str, reason: impl core::fmt::Display) -> TvcError {
    TvcError::InvalidDocument(format!("{kind}: {reason}"))
}

fn text<'a>(kind: &str, document: &'a Value, key: &str) -> Result<&'a str> {
    match document.get(key).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(invalid(kind, format!("{key} must be a non-empty string"))),
    }
}

fn digest(kind: &str, value: Option<&Value>, key: &str) -> Result<[u8; 32]> {
    let raw = value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(kind, format!("{key} must be a 64-character hex digest")))?;
    hex::decode_array::<32>(raw).map_err(|error| invalid(kind, format!("{key}: {error}")))
}

fn integer(kind: &str, document: &Value, key: &str) -> Result<u64> {
    document
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(kind, format!("{key} must be a non-negative integer")))
}

/// A decimal written as a string: optional `-`, digits, optional `.digits`.
fn is_decimal(value: &str) -> bool {
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    let (whole, fraction) = match unsigned.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (unsigned, None),
    };
    let digits = |part: &str| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit());
    digits(whole) && fraction.is_none_or(digits)
}

fn decimal<'a>(kind: &str, value: &'a Value, key: &str) -> Result<&'a str> {
    match value.get(key).and_then(Value::as_str) {
        Some(found) if is_decimal(found) => Ok(found),
        _ => Err(invalid(kind, format!("{key} must be a decimal written as a string, e.g. \"0.7\""))),
    }
}

/// The digests a document refers to, in the order its fields list them.
///
/// This is what the ledger claim's `refs` must equal for the document to be
/// consistent with the claim made about it.
///
/// # Errors
///
/// Returns [`TvcError::InvalidDocument`] if a reference field is missing or malformed.
pub fn refs_of(kind: &str, document: &Value) -> Result<Vec<[u8; 32]>> {
    match kind {
        KIND_WEIGHTS_MANIFEST => Ok(Vec::new()),
        KIND_REFERENCE_SETUP => Ok(vec![digest(kind, document.get("weights"), "weights")?]),
        KIND_REFERENCE_RUN => Ok(vec![digest(kind, document.get("setup"), "setup")?]),
        KIND_PROFILE => {
            let mut refs = vec![digest(kind, document.get("weights"), "weights")?];
            for run in document
                .get("runs")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid(kind, "runs must be an array"))?
            {
                refs.push(digest(kind, Some(run), "runs[]")?);
            }
            Ok(refs)
        }
        _ => match document.get("refs") {
            None => Ok(Vec::new()),
            Some(list) => list
                .as_array()
                .ok_or_else(|| invalid(kind, "refs must be an array"))?
                .iter()
                .map(|entry| digest(kind, Some(entry), "refs[]"))
                .collect(),
        },
    }
}

/// Checks a document's fields and the kinds of the documents it refers to.
///
/// `kind_of` answers "what kind is the document with this digest", usually by
/// looking it up in the ledger. A reference that resolves to nothing, or to
/// the wrong kind, is refused: a reference run must cite a setup, not a
/// manifest.
///
/// # Errors
///
/// Returns [`TvcError::InvalidDocument`] naming the first problem, or
/// [`TvcError::InvalidIdentifier`] for a malformed kind.
pub fn validate_document(
    kind: &str,
    document: &Value,
    kind_of: &dyn Fn(&[u8; 32]) -> Option<String>,
) -> Result<()> {
    validate_kind(kind)?;
    if document.get("kind").and_then(Value::as_str) != Some(kind) {
        return Err(invalid(kind, "the document's own kind field does not match"));
    }
    to_canonical_bytes(document)?;

    let expect = |reference: &[u8; 32], wanted: &str| -> Result<()> {
        match kind_of(reference) {
            Some(found) if found == wanted => Ok(()),
            Some(found) => Err(invalid(
                kind,
                format!("{} is a {found}, expected a {wanted}", hex::encode(reference)),
            )),
            None => Err(invalid(
                kind,
                format!("{} is not a known document", hex::encode(reference)),
            )),
        }
    };

    match kind {
        KIND_WEIGHTS_MANIFEST => {
            WeightsManifest::from_json(document)?;
        }
        KIND_REFERENCE_SETUP => {
            for key in ["engine", "engine_version", "dtype", "hardware"] {
                text(kind, document, key)?;
            }
            integer(kind, document, "context_length")?;
            let decoding = document
                .get("decoding")
                .and_then(Value::as_object)
                .ok_or_else(|| invalid(kind, "decoding must be an object"))?;
            for (key, value) in decoding {
                if !value.as_str().is_some_and(is_decimal) {
                    return Err(invalid(
                        kind,
                        format!("decoding.{key} must be a decimal written as a string"),
                    ));
                }
            }
            if let Some(template) = document.get("chat_template_sha256") {
                digest(kind, Some(template), "chat_template_sha256")?;
            }
            expect(&refs_of(kind, document)?[0], KIND_WEIGHTS_MANIFEST)?;
        }
        KIND_REFERENCE_RUN => {
            let date = text(kind, document, "date")?;
            let well_formed = date.len() == 10
                && date
                    .char_indices()
                    .all(|(i, c)| if i == 4 || i == 7 { c == '-' } else { c.is_ascii_digit() });
            if !well_formed {
                return Err(invalid(kind, "date must be YYYY-MM-DD"));
            }
            let set = |key: &str| -> Result<u64> {
                let entry = document
                    .get(key)
                    .ok_or_else(|| invalid(kind, format!("{key} is missing")))?;
                digest(kind, entry.get("root"), &format!("{key}.root"))?;
                let count = integer(kind, entry, "count")?;
                if count == 0 {
                    return Err(invalid(kind, format!("{key}.count must be at least 1")));
                }
                Ok(count)
            };
            let prompts = set("prompts")?;
            let outputs = set("outputs")?;
            let samples = integer(kind, document, "samples_per_prompt")?;
            if samples == 0 || prompts.checked_mul(samples) != Some(outputs) {
                return Err(invalid(
                    kind,
                    format!(
                        "outputs.count ({outputs}) must equal prompts.count ({prompts}) × samples_per_prompt ({samples})"
                    ),
                ));
            }
            if let Some(determinism) = document.get("determinism") {
                let repeats = integer(kind, determinism, "repeats")?;
                let matches = integer(kind, determinism, "exact_matches")?;
                if matches > repeats {
                    return Err(invalid(kind, "determinism.exact_matches exceeds repeats"));
                }
            }
            for band in document
                .get("bands")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid(kind, "bands must be an array"))?
            {
                text(kind, band, "check")?;
                text(kind, band, "metric")?;
                for key in ["reference", "low", "high"] {
                    decimal(kind, band, key)?;
                }
                if integer(kind, band, "samples")? == 0 {
                    return Err(invalid(kind, "a band measured on zero samples is not a band"));
                }
            }
            expect(&refs_of(kind, document)?[0], KIND_REFERENCE_SETUP)?;
        }
        KIND_PROFILE => {
            text(kind, document, "model")?;
            text(kind, document, "version")?;
            let maturity = text(kind, document, "maturity")?;
            if !MATURITY_LEVELS.contains(&maturity) {
                return Err(invalid(kind, "maturity must be skeleton, working or full"));
            }
            let refs = refs_of(kind, document)?;
            if maturity != "skeleton" && refs.len() < 2 {
                return Err(invalid(
                    kind,
                    "a working or full profile must cite at least one reference run",
                ));
            }
            expect(&refs[0], KIND_WEIGHTS_MANIFEST)?;
            for run in &refs[1..] {
                expect(run, KIND_REFERENCE_RUN)?;
            }
        }
        _ => {
            refs_of(kind, document)?;
        }
    }
    Ok(())
}

/// Content-addressed document storage: `objects/<sha256>.json` beside the ledger.
///
/// Files hold canonical bytes, so `sha256sum objects/<digest>.json` prints the
/// file's own name. Reads check that before returning anything.
#[derive(Clone, Debug)]
pub struct ObjectStore {
    dir: PathBuf,
}

impl ObjectStore {
    /// The store for the ledger at `ledger`: an `objects` directory beside it.
    pub fn beside(ledger: &Path) -> Self {
        let parent = ledger
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        Self {
            dir: parent.join("objects"),
        }
    }

    /// Directory the store writes into.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Path a document with this digest lives at.
    pub fn path_for(&self, digest: &[u8; 32]) -> PathBuf {
        self.dir.join(format!("{}.json", hex::encode(digest)))
    }

    /// Stores a document and returns its digest.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::InvalidDocument`] if the value has no canonical
    /// encoding, or [`TvcError::Io`] if it cannot be written.
    pub fn put(&self, document: &Value) -> Result<[u8; 32]> {
        let bytes = to_canonical_bytes(document)?;
        let digest = sha256_bytes(&bytes);
        std::fs::create_dir_all(&self.dir)
            .map_err(|error| TvcError::Io(format!("{}: {error}", self.dir.display())))?;
        let path = self.path_for(&digest);
        if !path.exists() {
            std::fs::write(&path, &bytes)
                .map_err(|error| TvcError::Io(format!("{}: {error}", path.display())))?;
        }
        Ok(digest)
    }

    /// Reads a document back, refusing a file whose bytes do not hash to its name.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::Io`] if the file is missing, or
    /// [`TvcError::InvalidDocument`] if it was edited or is not canonical.
    pub fn get(&self, digest: &[u8; 32]) -> Result<Value> {
        let path = self.path_for(digest);
        let bytes = std::fs::read(&path)
            .map_err(|error| TvcError::Io(format!("{}: {error}", path.display())))?;
        let actual = sha256_bytes(&bytes);
        if &actual != digest {
            return Err(TvcError::InvalidDocument(format!(
                "{} hashes to {}; the file was edited",
                path.display(),
                hex::encode(&actual)
            )));
        }
        parse_canonical(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn d(byte: u8) -> String {
        hex::encode(&[byte; 32])
    }

    fn kinds(byte_to_kind: &'static [(u8, &'static str)]) -> impl Fn(&[u8; 32]) -> Option<String> {
        move |digest: &[u8; 32]| {
            byte_to_kind
                .iter()
                .find(|(byte, _)| digest == &[*byte; 32])
                .map(|(_, kind)| (*kind).to_owned())
        }
    }

    const KNOWN: &[(u8, &str)] = &[
        (1, KIND_WEIGHTS_MANIFEST),
        (2, KIND_REFERENCE_SETUP),
        (3, KIND_REFERENCE_RUN),
    ];

    fn setup() -> Value {
        json!({
            "kind": KIND_REFERENCE_SETUP,
            "weights": d(1),
            "engine": "vllm",
            "engine_version": "0.11.0",
            "dtype": "bfloat16",
            "hardware": "1x NVIDIA L4",
            "context_length": 32768,
            "decoding": {"temperature": "0", "top_p": "1", "max_tokens": "512"},
        })
    }

    fn run() -> Value {
        json!({
            "kind": KIND_REFERENCE_RUN,
            "setup": d(2),
            "date": "2026-10-04",
            "prompts": {"root": d(7), "count": 12},
            "outputs": {"root": d(8), "count": 36},
            "samples_per_prompt": 3,
            "determinism": {"repeats": 5, "exact_matches": 5},
            "bands": [{"check": "PW-01", "metric": "prompt_tokens", "reference": "612",
                       "low": "612", "high": "612", "samples": 30}],
        })
    }

    fn profile() -> Value {
        json!({
            "kind": KIND_PROFILE,
            "model": "Qwen/Qwen2.5-0.5B-Instruct",
            "version": "0.1",
            "maturity": "working",
            "weights": d(1),
            "runs": [d(3)],
        })
    }

    #[test]
    fn well_formed_documents_validate_and_list_their_refs() {
        let lookup = kinds(KNOWN);
        validate_document(KIND_REFERENCE_SETUP, &setup(), &lookup).unwrap();
        validate_document(KIND_REFERENCE_RUN, &run(), &lookup).unwrap();
        validate_document(KIND_PROFILE, &profile(), &lookup).unwrap();
        assert_eq!(refs_of(KIND_PROFILE, &profile()).unwrap(), vec![[1; 32], [3; 32]]);
        assert_eq!(refs_of(KIND_REFERENCE_RUN, &run()).unwrap(), vec![[2; 32]]);
    }

    #[test]
    fn a_reference_to_the_wrong_kind_is_refused() {
        let lookup = kinds(KNOWN);
        let mut wrong = run();
        wrong["setup"] = json!(d(1)); // a manifest, not a setup
        assert!(validate_document(KIND_REFERENCE_RUN, &wrong, &lookup).is_err());

        let mut unknown = run();
        unknown["setup"] = json!(d(9));
        assert!(validate_document(KIND_REFERENCE_RUN, &unknown, &lookup).is_err());
    }

    #[test]
    fn output_counts_must_match_prompts_times_samples() {
        let mut bad = run();
        bad["outputs"]["count"] = json!(35);
        assert!(validate_document(KIND_REFERENCE_RUN, &bad, &kinds(KNOWN)).is_err());
    }

    #[test]
    fn floats_and_free_text_numbers_are_refused() {
        let lookup = kinds(KNOWN);
        let mut float = setup();
        float["decoding"]["temperature"] = json!(0.7);
        assert!(validate_document(KIND_REFERENCE_SETUP, &float, &lookup).is_err());

        let mut prose = setup();
        prose["decoding"]["temperature"] = json!("zero");
        assert!(validate_document(KIND_REFERENCE_SETUP, &prose, &lookup).is_err());

        let mut band = run();
        band["bands"][0]["low"] = json!("about 600");
        assert!(validate_document(KIND_REFERENCE_RUN, &band, &lookup).is_err());
    }

    #[test]
    fn a_working_profile_needs_a_run_and_maturity_is_a_closed_set() {
        let lookup = kinds(KNOWN);
        let mut no_runs = profile();
        no_runs["runs"] = json!([]);
        assert!(validate_document(KIND_PROFILE, &no_runs, &lookup).is_err());
        no_runs["maturity"] = json!("skeleton");
        assert!(validate_document(KIND_PROFILE, &no_runs, &lookup).is_ok());

        let mut maturity = profile();
        maturity["maturity"] = json!("great");
        assert!(validate_document(KIND_PROFILE, &maturity, &lookup).is_err());
    }

    #[test]
    fn the_kind_field_must_match_the_claimed_kind() {
        assert!(validate_document(KIND_PROFILE, &setup(), &kinds(KNOWN)).is_err());
    }

    #[test]
    fn unknown_kinds_are_stored_without_field_checks() {
        let other = json!({"kind": "certificate/v1", "anything": "goes", "refs": [d(3)]});
        validate_document("certificate/v1", &other, &kinds(KNOWN)).unwrap();
        assert_eq!(refs_of("certificate/v1", &other).unwrap(), vec![[3; 32]]);
    }

    #[test]
    fn the_object_store_round_trips_and_detects_edits() {
        let dir = std::env::temp_dir().join(format!("tvc-objects-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = ObjectStore::beside(&dir.join("registry.jsonl"));
        let digest = store.put(&setup()).unwrap();
        assert_eq!(store.get(&digest).unwrap(), setup());
        // The file's name is its own sha256.
        let bytes = std::fs::read(store.path_for(&digest)).unwrap();
        assert_eq!(sha256_bytes(&bytes), digest);

        std::fs::write(store.path_for(&digest), b"{\"kind\":\"edited\"}").unwrap();
        assert!(matches!(store.get(&digest), Err(TvcError::InvalidDocument(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn decimals_are_recognised_strictly() {
        for good in ["0", "0.7", "-1.25", "612", "100.0"] {
            assert!(is_decimal(good), "{good}");
        }
        for bad in ["", ".5", "5.", "1e3", "+1", "0x10", "1,000", "NaN"] {
            assert!(!is_decimal(bad), "{bad}");
        }
    }
}
