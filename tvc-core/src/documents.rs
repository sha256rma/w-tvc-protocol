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
//! Protocol v2 adds the documents a verdict is judged by:
//!
//! ```text
//!   battery/v1            a test: committed prompt pool, draw rule, statistic code
//!   reference-setup/v2    setup v1 plus the whole stack (kernels, GPU, seed, harness)
//!   reference-run/v2      run v1 plus its battery and evidence-log digest
//!   honest-set/v1         honest serving variants of the same weights
//!   calibration/v1        threshold per battery and budget, honest FPR, power
//!   audit/v1              one endpoint, one window: calibrations, draws, statistics, verdict
//!   profile/v2            profile v1 plus its calibrations
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

// Protocol v2: calibrations and audits. Additive; every v1 kind still validates.

/// Document kind for a test definition: its committed prompt pool, how items
/// are drawn per audit, decoding, and the code that computes its statistic.
pub const KIND_BATTERY: &str = "battery/v1";
/// Document kind for a reference setup that records the whole serving stack.
pub const KIND_REFERENCE_SETUP_V2: &str = "reference-setup/v2";
/// Document kind for a reference run that names its battery and evidence log.
pub const KIND_REFERENCE_RUN_V2: &str = "reference-run/v2";
/// Document kind for the honest serving variants a calibration is built on.
pub const KIND_HONEST_SET: &str = "honest-set/v1";
/// Document kind for thresholds per battery and query budget, with measured
/// false-positive rates and power.
pub const KIND_CALIBRATION: &str = "calibration/v1";
/// Document kind for one check of one endpoint in one time window.
pub const KIND_AUDIT: &str = "audit/v1";
/// Document kind for a profile that also names its calibrations (each of
/// which names its honest set).
pub const KIND_PROFILE_V2: &str = "profile/v2";

/// Either version of a reference setup.
pub const SETUP_KINDS: [&str; 2] = [KIND_REFERENCE_SETUP, KIND_REFERENCE_SETUP_V2];
/// Either version of a reference run.
pub const RUN_KINDS: [&str; 2] = [KIND_REFERENCE_RUN, KIND_REFERENCE_RUN_V2];

/// Per-battery verdicts an audit may record.
pub const BATTERY_VERDICTS: [&str; 3] = ["inside-band", "outside-band", "inconclusive-T0"];
/// Overall verdicts an audit may record.
pub const AUDIT_VERDICTS: [&str; 4] = [
    "consistent",
    "inconsistent-with-declared-configuration",
    "different-model",
    "misconfigured",
];

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

fn array<'a>(kind: &str, value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(kind, format!("{key} must be an array")))
}

fn object<'a>(kind: &str, value: &'a Value, key: &str) -> Result<&'a Value> {
    match value.get(key) {
        Some(found) if found.is_object() => Ok(found),
        _ => Err(invalid(kind, format!("{key} must be an object"))),
    }
}

/// Keeps the first occurrence of each digest. A ledger claim may not name the
/// same document twice, and a calibration can cite one battery for several budgets.
fn dedup(refs: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    let mut seen = std::collections::BTreeSet::new();
    refs.into_iter().filter(|r| seen.insert(*r)).collect()
}

fn positive(kind: &str, value: &Value, key: &str) -> Result<u64> {
    match integer(kind, value, key)? {
        0 => Err(invalid(kind, format!("{key} must be at least 1"))),
        n => Ok(n),
    }
}

/// A committed item set written as `{root, count}`.
fn item_set(kind: &str, value: &Value, key: &str) -> Result<u64> {
    let entry = object(kind, value, key)?;
    digest(kind, entry.get("root"), &format!("{key}.root"))?;
    positive(kind, entry, "count").map_err(|_| invalid(kind, format!("{key}.count must be at least 1")))
}

fn one_of(kind: &str, value: &Value, key: &str, allowed: &[&str]) -> Result<()> {
    let found = text(kind, value, key)?;
    if allowed.contains(&found) {
        Ok(())
    } else {
        Err(invalid(kind, format!("{key} must be one of {}", allowed.join(", "))))
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ`, the only time format v2 documents use.
fn utc_time(kind: &str, value: &Value, key: &str) -> Result<()> {
    let found = text(kind, value, key)?;
    let shape = "0000-00-00T00:00:00Z";
    let ok = found.len() == shape.len()
        && found.chars().zip(shape.chars()).all(|(c, s)| match s {
            '0' => c.is_ascii_digit(),
            other => c == other,
        });
    if ok {
        Ok(())
    } else {
        Err(invalid(kind, format!("{key} must be a UTC time written YYYY-MM-DDTHH:MM:SSZ")))
    }
}

fn decimals_object(kind: &str, document: &Value, key: &str) -> Result<()> {
    let map = document
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(kind, format!("{key} must be an object")))?;
    for (name, value) in map {
        if !value.as_str().is_some_and(is_decimal) {
            return Err(invalid(kind, format!("{key}.{name} must be a decimal written as a string")));
        }
    }
    Ok(())
}

/// Compares two decimals written as strings, exactly. No floating point is
/// involved, so every verifier in every language reaches the same answer.
///
/// # Errors
///
/// Returns [`TvcError::InvalidDocument`] if either is not a decimal.
pub fn decimal_cmp(a: &str, b: &str) -> Result<core::cmp::Ordering> {
    use core::cmp::Ordering;
    for value in [a, b] {
        if !is_decimal(value) {
            return Err(TvcError::InvalidDocument(format!("{value:?} is not a decimal")));
        }
    }
    // (negative, whole digits without leading zeros, fraction without trailing zeros)
    fn parts(value: &str) -> (bool, &str, &str) {
        let (negative, unsigned) = match value.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, value),
        };
        let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
        let whole = whole.trim_start_matches('0');
        let fraction = fraction.trim_end_matches('0');
        let zero = whole.is_empty() && fraction.is_empty();
        (negative && !zero, whole, fraction)
    }
    fn magnitude(a: (&str, &str), b: (&str, &str)) -> Ordering {
        a.0.len()
            .cmp(&b.0.len())
            .then_with(|| a.0.cmp(b.0))
            .then_with(|| a.1.cmp(b.1))
    }
    let (a_neg, a_whole, a_frac) = parts(a);
    let (b_neg, b_whole, b_frac) = parts(b);
    Ok(match (a_neg, b_neg) {
        (false, true) => Ordering::Greater,
        (true, false) => Ordering::Less,
        (false, false) => magnitude((a_whole, a_frac), (b_whole, b_frac)),
        (true, true) => magnitude((b_whole, b_frac), (a_whole, a_frac)),
    })
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
        KIND_REFERENCE_SETUP | KIND_REFERENCE_SETUP_V2 => {
            Ok(vec![digest(kind, document.get("weights"), "weights")?])
        }
        KIND_REFERENCE_RUN => Ok(vec![digest(kind, document.get("setup"), "setup")?]),
        KIND_REFERENCE_RUN_V2 => Ok(vec![
            digest(kind, document.get("setup"), "setup")?,
            digest(kind, document.get("battery"), "battery")?,
        ]),
        KIND_BATTERY => Ok(Vec::new()),
        KIND_PROFILE | KIND_PROFILE_V2 => {
            let mut refs = vec![digest(kind, document.get("weights"), "weights")?];
            for run in array(kind, document, "runs")? {
                refs.push(digest(kind, Some(run), "runs[]")?);
            }
            if kind == KIND_PROFILE_V2 {
                for calibration in array(kind, document, "calibrations")? {
                    refs.push(digest(kind, Some(calibration), "calibrations[]")?);
                }
            }
            Ok(dedup(refs))
        }
        KIND_HONEST_SET => {
            let mut refs = vec![digest(kind, document.get("reference_run"), "reference_run")?];
            for member in array(kind, document, "members")? {
                refs.push(digest(kind, member.get("setup"), "members[].setup")?);
                refs.push(digest(kind, member.get("run"), "members[].run")?);
            }
            Ok(dedup(refs))
        }
        KIND_CALIBRATION => {
            let mut refs = vec![
                digest(kind, document.get("reference_run"), "reference_run")?,
                digest(kind, document.get("honest_set"), "honest_set")?,
            ];
            for entry in array(kind, document, "entries")? {
                refs.push(digest(kind, entry.get("battery"), "entries[].battery")?);
                for power in array(kind, entry, "power")? {
                    refs.push(digest(kind, power.get("against"), "entries[].power[].against")?);
                }
            }
            Ok(dedup(refs))
        }
        KIND_AUDIT => {
            let mut refs = Vec::new();
            for calibration in array(kind, document, "calibrations")? {
                refs.push(digest(kind, Some(calibration), "calibrations[]")?);
            }
            for draw in array(kind, document, "draws")? {
                refs.push(digest(kind, draw.get("battery"), "draws[].battery")?);
            }
            if let Some(better) = document.get("better_match") {
                for calibration in array(kind, better, "calibrations")? {
                    refs.push(digest(kind, Some(calibration), "better_match.calibrations[]")?);
                }
            }
            Ok(dedup(refs))
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

    let expect_any = |reference: &[u8; 32], wanted: &[&str]| -> Result<()> {
        match kind_of(reference) {
            Some(found) if wanted.contains(&found.as_str()) => Ok(()),
            Some(found) => Err(invalid(
                kind,
                format!("{} is a {found}, expected a {}", hex::encode(reference), wanted.join(" or ")),
            )),
            None => Err(invalid(
                kind,
                format!("{} is not a known document", hex::encode(reference)),
            )),
        }
    };
    let expect = |reference: &[u8; 32], wanted: &str| expect_any(reference, &[wanted]);

    match kind {
        KIND_WEIGHTS_MANIFEST => {
            WeightsManifest::from_json(document)?;
        }
        KIND_REFERENCE_SETUP | KIND_REFERENCE_SETUP_V2 => {
            if kind == KIND_REFERENCE_SETUP_V2 {
                for key in ["kernel_mode", "gpu", "driver"] {
                    text(kind, document, key)?;
                }
                integer(kind, document, "seed")?;
                let harness = object(kind, document, "harness")?;
                text(kind, harness, "repo")?;
                text(kind, harness, "commit")?;
                digest(kind, document.get("lock_sha256"), "lock_sha256")?;
                object(kind, document, "request")?;
            }
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
        KIND_REFERENCE_RUN | KIND_REFERENCE_RUN_V2 => {
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
            let refs = refs_of(kind, document)?;
            if kind == KIND_REFERENCE_RUN_V2 {
                digest(kind, document.get("evidence_sha256"), "evidence_sha256")?;
                expect_any(&refs[0], &SETUP_KINDS)?;
                expect(&refs[1], KIND_BATTERY)?;
            } else {
                expect(&refs[0], KIND_REFERENCE_SETUP)?;
            }
        }
        KIND_PROFILE | KIND_PROFILE_V2 => {
            text(kind, document, "model")?;
            text(kind, document, "version")?;
            let maturity = text(kind, document, "maturity")?;
            if !MATURITY_LEVELS.contains(&maturity) {
                return Err(invalid(kind, "maturity must be skeleton, working or full"));
            }
            let refs = refs_of(kind, document)?;
            let runs = array(kind, document, "runs")?;
            if maturity != "skeleton" && runs.is_empty() {
                return Err(invalid(
                    kind,
                    "a working or full profile must cite at least one reference run",
                ));
            }
            expect(&refs[0], KIND_WEIGHTS_MANIFEST)?;
            if kind == KIND_PROFILE {
                for run in &refs[1..] {
                    expect(run, KIND_REFERENCE_RUN)?;
                }
            } else {
                for run in runs {
                    expect_any(&digest(kind, Some(run), "runs[]")?, &RUN_KINDS)?;
                }
                for calibration in array(kind, document, "calibrations")? {
                    expect(&digest(kind, Some(calibration), "calibrations[]")?, KIND_CALIBRATION)?;
                }
                if maturity == "full" && array(kind, document, "calibrations")?.is_empty() {
                    return Err(invalid(kind, "a full profile must name at least one calibration"));
                }
            }
        }
        KIND_BATTERY => {
            text(kind, document, "id")?;
            text(kind, document, "version")?;
            let pool = item_set(kind, document, "pool")?;
            let draw = object(kind, document, "draw")?;
            let k = positive(kind, draw, "k")?;
            if k > pool {
                return Err(invalid(kind, format!("draw.k ({k}) exceeds pool.count ({pool})")));
            }
            decimals_object(kind, document, "decoding")?;
            text(kind, document, "normalisation")?;
            let statistic = object(kind, document, "statistic")?;
            text(kind, statistic, "name")?;
            let code = object(kind, statistic, "code")?;
            for key in ["repo", "commit", "path"] {
                text(kind, code, key)?;
            }
            digest(kind, code.get("sha256"), "statistic.code.sha256")?;
            for signal in array(kind, document, "signals")? {
                if signal.as_str().is_none_or(|s| s.trim().is_empty()) {
                    return Err(invalid(kind, "signals must be non-empty strings"));
                }
            }
        }
        KIND_HONEST_SET => {
            let members = array(kind, document, "members")?;
            if members.is_empty() {
                return Err(invalid(kind, "an honest set needs at least one member"));
            }
            for member in members {
                text(kind, member, "differs")?;
            }
            expect_any(&digest(kind, document.get("reference_run"), "reference_run")?, &RUN_KINDS)?;
            for member in members {
                expect_any(&digest(kind, member.get("setup"), "members[].setup")?, &SETUP_KINDS)?;
                expect_any(&digest(kind, member.get("run"), "members[].run")?, &RUN_KINDS)?;
            }
        }
        KIND_CALIBRATION => {
            decimal(kind, document, "quantile")?;
            text(kind, document, "method")?;
            expect_any(&digest(kind, document.get("reference_run"), "reference_run")?, &RUN_KINDS)?;
            expect(&digest(kind, document.get("honest_set"), "honest_set")?, KIND_HONEST_SET)?;
            let entries = array(kind, document, "entries")?;
            if entries.is_empty() {
                return Err(invalid(kind, "a calibration needs at least one entry"));
            }
            let mut seen = std::collections::BTreeSet::new();
            for entry in entries {
                let battery = digest(kind, entry.get("battery"), "entries[].battery")?;
                expect(&battery, KIND_BATTERY)?;
                let k = positive(kind, entry, "k")?;
                if !seen.insert((battery, k)) {
                    return Err(invalid(kind, "two entries for the same battery and k"));
                }
                for key in ["threshold", "honest_fpr_mean", "honest_fpr_max"] {
                    decimal(kind, entry, key)?;
                }
                for power in array(kind, entry, "power")? {
                    expect_any(&digest(kind, power.get("against"), "power[].against")?, &RUN_KINDS)?;
                    text(kind, power, "label")?;
                    decimal(kind, power, "eps")?;
                    decimal(kind, power, "rejection_rate")?;
                }
            }
            for label in array(kind, document, "cannot_detect")? {
                if label.as_str().is_none_or(|s| s.trim().is_empty()) {
                    return Err(invalid(kind, "cannot_detect must list non-empty strings"));
                }
            }
        }
        KIND_AUDIT => {
            let endpoint = object(kind, document, "endpoint")?;
            text(kind, endpoint, "host")?;
            text(kind, endpoint, "model")?;
            let window = object(kind, document, "window")?;
            utc_time(kind, window, "start")?;
            utc_time(kind, window, "end")?;
            if text(kind, window, "end")? < text(kind, window, "start")? {
                return Err(invalid(kind, "window.end is before window.start"));
            }
            let calibrations = array(kind, document, "calibrations")?;
            if calibrations.is_empty() {
                return Err(invalid(kind, "an audit must cite at least one calibration"));
            }
            for calibration in calibrations {
                expect(&digest(kind, Some(calibration), "calibrations[]")?, KIND_CALIBRATION)?;
            }
            for draw in array(kind, document, "draws")? {
                expect(&digest(kind, draw.get("battery"), "draws[].battery")?, KIND_BATTERY)?;
                let k = positive(kind, draw, "k")?;
                let indices = array(kind, draw, "indices")?;
                if indices.len() as u64 != k || !indices.iter().all(Value::is_u64) {
                    return Err(invalid(kind, "draws[].indices must hold exactly k integers"));
                }
            }
            item_set(kind, document, "responses")?;
            audit_results(kind, document)?;
            let t0 = object(kind, document, "t0")?;
            if !t0.get("matches").is_some_and(Value::is_boolean) {
                return Err(invalid(kind, "t0.matches must be true or false"));
            }
            one_of(kind, document, "verdict", &AUDIT_VERDICTS)?;
            decimal(kind, document, "confidence")?;
            match document.get("better_match") {
                Some(better) => {
                    let calibrations = array(kind, better, "calibrations")?;
                    if calibrations.is_empty() {
                        return Err(invalid(kind, "better_match must cite at least one calibration"));
                    }
                    for calibration in calibrations {
                        expect(&digest(kind, Some(calibration), "better_match.calibrations[]")?, KIND_CALIBRATION)?;
                    }
                    audit_results(kind, better)?;
                }
                None if text(kind, document, "verdict")? == "different-model" => {
                    return Err(invalid(kind, "a different-model verdict must name the better match"));
                }
                None => {}
            }
        }
        _ => {
            refs_of(kind, document)?;
        }
    }
    Ok(())
}

/// Checks the `results` array of an audit or of its `better_match`.
fn audit_results(kind: &str, value: &Value) -> Result<()> {
    let results = array(kind, value, "results")?;
    if results.is_empty() {
        return Err(invalid(kind, "results must not be empty"));
    }
    for result in results {
        digest(kind, result.get("battery"), "results[].battery")?;
        positive(kind, result, "k")?;
        decimal(kind, result, "statistic")?;
        decimal(kind, result, "threshold")?;
        one_of(kind, result, "verdict", &BATTERY_VERDICTS)?;
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

    const KNOWN_V2: &[(u8, &str)] = &[
        (1, KIND_WEIGHTS_MANIFEST),
        (2, KIND_REFERENCE_SETUP),
        (3, KIND_REFERENCE_RUN),
        (4, KIND_BATTERY),
        (5, KIND_REFERENCE_SETUP_V2),
        (6, KIND_REFERENCE_RUN_V2),
        (10, KIND_HONEST_SET),
        (11, KIND_CALIBRATION),
        (12, KIND_REFERENCE_RUN_V2),
    ];

    fn battery() -> Value {
        json!({
            "kind": KIND_BATTERY, "id": "T1", "version": "2",
            "pool": {"root": d(7), "count": 40},
            "draw": {"k": 8, "context": "draw_context(endpoint, window.start date, battery)"},
            "decoding": {"temperature": "1", "max_tokens": "16"},
            "normalisation": "first word, NFC, case fold",
            "statistic": {"name": "mean JSD", "code": {"repo": "r", "commit": "c", "path": "p", "sha256": d(9)}},
            "signals": ["S-02"],
        })
    }

    fn setup_v2() -> Value {
        let mut doc = setup();
        doc["kind"] = json!(KIND_REFERENCE_SETUP_V2);
        for (key, value) in [("kernel_mode", json!("batch-invariant")), ("gpu", json!("NVIDIA L4")),
                             ("driver", json!("580")), ("seed", json!(0)),
                             ("harness", json!({"repo": "r", "commit": "c"})), ("lock_sha256", json!(d(9))),
                             ("request", json!({"system_prompt": null}))] {
            doc[key] = value;
        }
        doc
    }

    fn run_v2() -> Value {
        let mut doc = run();
        doc["kind"] = json!(KIND_REFERENCE_RUN_V2);
        doc["setup"] = json!(d(5));
        doc["battery"] = json!(d(4));
        doc["evidence_sha256"] = json!(d(9));
        doc
    }

    fn honest() -> Value {
        json!({"kind": KIND_HONEST_SET, "reference_run": d(6),
               "members": [{"setup": d(5), "run": d(12), "differs": "kernel_mode: default"}]})
    }

    fn calibration() -> Value {
        json!({"kind": KIND_CALIBRATION, "reference_run": d(6), "honest_set": d(10),
               "quantile": "0.95", "method": "leave-one-out over the honest set",
               "entries": [
                 {"battery": d(4), "k": 5, "threshold": "0.22", "honest_fpr_mean": "0.06", "honest_fpr_max": "0.1",
                  "power": [{"against": d(12), "label": "AWQ 4-bit", "eps": "1", "rejection_rate": "1"}]},
                 {"battery": d(4), "k": 20, "threshold": "0.12", "honest_fpr_mean": "0.05", "honest_fpr_max": "0.1",
                  "power": []}],
               "cannot_detect": ["GPTQ int8 weight-only"]})
    }

    fn audit() -> Value {
        json!({"kind": KIND_AUDIT,
               "endpoint": {"host": "api.example.com", "model": "qwen/qwen-2.5-7b-instruct", "provider": "A"},
               "window": {"start": "2026-10-04T09:00:00Z", "end": "2026-10-04T09:20:00Z"},
               "calibrations": [d(11)],
               "draws": [{"battery": d(4), "k": 2, "indices": [3, 17]}],
               "responses": {"root": d(8), "count": 40},
               "results": [{"battery": d(4), "k": 20, "statistic": "0.3", "threshold": "0.12", "verdict": "outside-band"}],
               "t0": {"matches": true},
               "verdict": "inconsistent-with-declared-configuration",
               "confidence": "0.95"})
    }

    #[test]
    fn v2_documents_validate_and_list_their_refs() {
        let lookup = kinds(KNOWN_V2);
        for (kind, doc) in [(KIND_BATTERY, battery()), (KIND_REFERENCE_SETUP_V2, setup_v2()),
                            (KIND_REFERENCE_RUN_V2, run_v2()), (KIND_HONEST_SET, honest()),
                            (KIND_CALIBRATION, calibration()), (KIND_AUDIT, audit())] {
            validate_document(kind, &doc, &lookup).unwrap_or_else(|e| panic!("{kind}: {e}"));
        }
        assert_eq!(refs_of(KIND_REFERENCE_RUN_V2, &run_v2()).unwrap(), vec![[5; 32], [4; 32]]);
        assert_eq!(refs_of(KIND_HONEST_SET, &honest()).unwrap(), vec![[6; 32], [5; 32], [12; 32]]);
        // One battery cited by two entries appears once.
        assert_eq!(refs_of(KIND_CALIBRATION, &calibration()).unwrap(), vec![[6; 32], [10; 32], [4; 32], [12; 32]]);
        assert_eq!(refs_of(KIND_AUDIT, &audit()).unwrap(), vec![[11; 32], [4; 32]]);
    }

    #[test]
    fn a_setup_v2_needs_the_whole_stack() {
        let mut missing = setup_v2();
        missing.as_object_mut().unwrap().remove("kernel_mode");
        assert!(validate_document(KIND_REFERENCE_SETUP_V2, &missing, &kinds(KNOWN_V2)).is_err());
    }

    #[test]
    fn a_battery_cannot_draw_more_than_its_pool() {
        let mut big = battery();
        big["draw"]["k"] = json!(41);
        assert!(validate_document(KIND_BATTERY, &big, &kinds(KNOWN_V2)).is_err());
    }

    #[test]
    fn v2_references_must_point_at_the_right_kinds() {
        let lookup = kinds(KNOWN_V2);
        let mut cal = calibration();
        cal["honest_set"] = json!(d(6)); // a run, not an honest set
        assert!(validate_document(KIND_CALIBRATION, &cal, &lookup).is_err());
        let mut au = audit();
        au["calibrations"] = json!([d(10)]);
        assert!(validate_document(KIND_AUDIT, &au, &lookup).is_err());
        let mut run = run_v2();
        run["battery"] = json!(d(6));
        assert!(validate_document(KIND_REFERENCE_RUN_V2, &run, &lookup).is_err());
    }

    #[test]
    fn calibrations_refuse_floats_and_duplicate_budgets() {
        let lookup = kinds(KNOWN_V2);
        let mut float = calibration();
        float["entries"][0]["threshold"] = json!(0.22);
        assert!(validate_document(KIND_CALIBRATION, &float, &lookup).is_err());
        let mut twice = calibration();
        twice["entries"][1]["k"] = json!(5);
        assert!(validate_document(KIND_CALIBRATION, &twice, &lookup).is_err());
    }

    #[test]
    fn audits_check_their_shape() {
        let lookup = kinds(KNOWN_V2);
        let mut short = audit();
        short["draws"][0]["indices"] = json!([3]);
        assert!(validate_document(KIND_AUDIT, &short, &lookup).is_err());
        let mut time = audit();
        time["window"]["start"] = json!("2026-10-04 09:00");
        assert!(validate_document(KIND_AUDIT, &time, &lookup).is_err());
        let mut backwards = audit();
        backwards["window"]["end"] = json!("2026-10-03T09:00:00Z");
        assert!(validate_document(KIND_AUDIT, &backwards, &lookup).is_err());
        let mut verdict = audit();
        verdict["verdict"] = json!("fake");
        assert!(validate_document(KIND_AUDIT, &verdict, &lookup).is_err());
        let mut unnamed = audit();
        unnamed["verdict"] = json!("different-model");
        assert!(validate_document(KIND_AUDIT, &unnamed, &lookup).is_err());
    }

    #[test]
    fn a_full_profile_v2_names_a_calibration() {
        let lookup = kinds(KNOWN_V2);
        let mut profile = json!({"kind": KIND_PROFILE_V2, "model": "m", "version": "1", "maturity": "full",
                                 "weights": d(1), "runs": [d(6)], "calibrations": [d(11)]});
        validate_document(KIND_PROFILE_V2, &profile, &lookup).unwrap();
        assert_eq!(refs_of(KIND_PROFILE_V2, &profile).unwrap(), vec![[1; 32], [6; 32], [11; 32]]);
        profile["calibrations"] = json!([d(10)]); // an honest set, not a calibration
        assert!(validate_document(KIND_PROFILE_V2, &profile, &lookup).is_err());
        profile["calibrations"] = json!([]);
        assert!(validate_document(KIND_PROFILE_V2, &profile, &lookup).is_err());
        profile["maturity"] = json!("working");
        validate_document(KIND_PROFILE_V2, &profile, &lookup).unwrap();
    }

    #[test]
    fn decimals_compare_exactly() {
        use core::cmp::Ordering::*;
        for (a, b, want) in [("0.1", "0.10", Equal), ("0.10001", "0.1", Greater), ("2", "10", Less),
                             ("-0", "0", Equal), ("-1.5", "-1.25", Less), ("-0.1", "0", Less),
                             ("007", "7.000", Equal), ("0.000044", "0.000084", Less)] {
            assert_eq!(decimal_cmp(a, b).unwrap(), want, "{a} vs {b}");
        }
        assert!(decimal_cmp("1e3", "1").is_err());
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
