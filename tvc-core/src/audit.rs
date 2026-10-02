//! The rules an `audit/v1` document must follow, as plain functions.
//!
//! The auditor runs these to fill in an audit, and a verifier runs the same
//! ones to check it, so the two can't disagree.
//!
//! - [`draw_context`] fixes which prompts an audit uses. It's built from the
//!   endpoint, the day the window opens and the battery, so the auditor can't
//!   pick prompts that suit a provider. The indices then come from
//!   [`crate::itemset::select`] over the battery's committed pool.
//! - [`battery_verdict`] compares a statistic with the calibrated threshold.
//! - [`overall_verdict`] combines the battery verdicts with the T0 gate: when
//!   the prompt-token check fails, the provider changed the prompt (a system
//!   prompt, a template), and text tests can't tell that from a different model.

use serde_json::{json, Value};

use crate::canonical::to_canonical_bytes;
use crate::documents::decimal_cmp;
use crate::error::{Result, TvcError};
use crate::hex;

/// The bytes an audit's draw from one battery is derived from.
///
/// Canonical JSON of `{"battery": <digest hex>, "date": <YYYY-MM-DD of the
/// window start>, "endpoint": <the audit's endpoint object>}`.
///
/// # Errors
///
/// Returns [`TvcError::InvalidDocument`] if `window_start` is too short to hold
/// a date or the endpoint has no canonical encoding.
pub fn draw_context(endpoint: &Value, window_start: &str, battery: &[u8; 32]) -> Result<Vec<u8>> {
    let date = window_start
        .get(..10)
        .ok_or_else(|| TvcError::InvalidDocument("window.start holds no date".to_owned()))?;
    to_canonical_bytes(&json!({
        "battery": hex::encode(battery),
        "date": date,
        "endpoint": endpoint,
    }))
}

/// One battery's verdict.
///
/// Outside the band when the statistic is strictly above the threshold. When
/// T0 did not match, an outside result is `inconclusive-T0` rather than
/// `outside-band`.
///
/// # Errors
///
/// Returns [`TvcError::InvalidDocument`] if either value is not a decimal.
pub fn battery_verdict(statistic: &str, threshold: &str, t0_matches: bool) -> Result<&'static str> {
    let outside = decimal_cmp(statistic, threshold)? == core::cmp::Ordering::Greater;
    Ok(match (outside, t0_matches) {
        (false, _) => "inside-band",
        (true, true) => "outside-band",
        (true, false) => "inconclusive-T0",
    })
}

/// The audit's overall verdict.
///
/// - T0 did not match: `misconfigured`. The provider changed the prompt, and
///   that is reported on its own, never as a different model.
/// - Every battery inside its band: `consistent`.
/// - Otherwise, when the audit names a better match and every result against
///   that reference is inside its band: `different-model`.
/// - Otherwise: `inconsistent-with-declared-configuration`.
pub fn overall_verdict(battery_verdicts: &[&str], t0_matches: bool, better_match_inside: Option<bool>) -> &'static str {
    if !t0_matches {
        "misconfigured"
    } else if battery_verdicts.iter().all(|v| *v == "inside-band") {
        "consistent"
    } else if better_match_inside == Some(true) {
        "different-model"
    } else {
        "inconsistent-with-declared-configuration"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_context_depends_on_endpoint_day_and_battery_only() {
        let endpoint = json!({"host": "api.example.com", "model": "m"});
        let a = draw_context(&endpoint, "2026-10-04T09:00:00Z", &[1; 32]).unwrap();
        let later_same_day = draw_context(&endpoint, "2026-10-04T23:00:00Z", &[1; 32]).unwrap();
        assert_eq!(a, later_same_day);
        assert_ne!(a, draw_context(&endpoint, "2026-10-05T09:00:00Z", &[1; 32]).unwrap());
        assert_ne!(a, draw_context(&endpoint, "2026-10-04T09:00:00Z", &[2; 32]).unwrap());
        let other = json!({"host": "api.example.com", "model": "n"});
        assert_ne!(a, draw_context(&other, "2026-10-04T09:00:00Z", &[1; 32]).unwrap());
    }

    #[test]
    fn battery_verdicts_follow_the_threshold_and_the_t0_gate() {
        assert_eq!(battery_verdict("0.05", "0.1", true).unwrap(), "inside-band");
        assert_eq!(battery_verdict("0.1", "0.1", true).unwrap(), "inside-band");
        assert_eq!(battery_verdict("0.10001", "0.1", true).unwrap(), "outside-band");
        assert_eq!(battery_verdict("0.2", "0.1", false).unwrap(), "inconclusive-T0");
        assert_eq!(battery_verdict("0.05", "0.1", false).unwrap(), "inside-band");
        assert!(battery_verdict("0.1e1", "0.1", true).is_err());
    }

    #[test]
    fn overall_verdicts() {
        assert_eq!(overall_verdict(&["inside-band", "inside-band"], true, None), "consistent");
        assert_eq!(
            overall_verdict(&["inside-band", "outside-band"], true, None),
            "inconsistent-with-declared-configuration"
        );
        assert_eq!(overall_verdict(&["outside-band"], true, Some(true)), "different-model");
        assert_eq!(
            overall_verdict(&["outside-band"], true, Some(false)),
            "inconsistent-with-declared-configuration"
        );
        assert_eq!(overall_verdict(&["inconclusive-T0"], false, Some(true)), "misconfigured");
    }
}
