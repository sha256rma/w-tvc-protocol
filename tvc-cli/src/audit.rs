//! Commands for checking an audit: one endpoint, checked in one time window.
//!
//! ```text
//! tvc audit-draw   --battery <digest> --endpoint '<json>' --start <UTC time>
//! tvc verify-audit --audit <digest> --publisher <key> [--reveal r.json ...] [--json]
//! ```
//!
//! An audit is fair when three things hold, and `verify-audit` checks each:
//!
//! 1. The thresholds were fixed first. The calibration the audit is judged
//!    against sits earlier in the ledger, and an anchor proof made before the
//!    audit was recorded covers it.
//! 2. The prompts weren't picked. Each battery's indices re-derive from its
//!    committed pool and a context built from the endpoint, the day and the
//!    battery, so the auditor had no choice to make.
//! 3. The verdict follows from the numbers. Every threshold matches the
//!    calibration, and every battery verdict and the overall verdict are
//!    recomputed with the same rules the auditor used ([`tvc_core::audit`]).
//!
//! What it can't check: that the published statistics are what the endpoint
//! really answered. Revealed responses (`--reveal`) open against the audit's
//! sealed response root, which settles a dispute about any one of them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use tvc_core::audit::{battery_verdict, draw_context, overall_verdict};
use tvc_core::documents::{decimal_cmp, ObjectStore, KIND_AUDIT, KIND_BATTERY};
use tvc_core::hex;
use tvc_core::itemset::{select, ItemReveal};
use tvc_core::registry::ModelRegistry;

use crate::anchor::{Anchor, AnchorStatus, NullAnchor, OpenTimestampsCalendar};
use crate::reference::{check_closure, closure, exit, Check, Status};

fn digest_arg(text: &str, flag: &str) -> Result<[u8; 32], String> {
    hex::decode_array::<32>(text.trim())
        .map_err(|error| format!("{flag} must be a 64-character lowercase hex digest: {error}"))
}

fn digest_of(value: &Value) -> Option<[u8; 32]> {
    hex::decode_array::<32>(value.as_str()?).ok()
}

/// A battery's committed pool and fixed draw size.
fn pool_of(battery: &Value) -> Option<([u8; 32], u64, u64)> {
    Some((
        digest_of(&battery["pool"]["root"])?,
        battery["pool"]["count"].as_u64()?,
        battery["draw"]["k"].as_u64()?,
    ))
}

/// `tvc audit-draw`: the indices an audit of `endpoint` starting at `start`
/// must use from this battery.
pub fn audit_draw(ledger: &Path, battery: &str, endpoint: &str, start: &str) -> Result<(), String> {
    let battery = digest_arg(battery, "--battery")?;
    let registry = ModelRegistry::open(ledger).map_err(|e| e.to_string())?;
    match registry.get_document(&battery) {
        Some(record) if record.kind() == KIND_BATTERY => {}
        Some(record) => return Err(format!("{} is a {}, not a battery", hex::encode(&battery), record.kind())),
        None => return Err(format!("{} is not a document in {}", hex::encode(&battery), ledger.display())),
    }
    let document = ObjectStore::beside(ledger).get(&battery).map_err(|e| e.to_string())?;
    let (root, count, k) = pool_of(&document).ok_or("the battery has no pool or draw size")?;
    let endpoint: Value = serde_json::from_str(endpoint).map_err(|e| format!("--endpoint is not JSON: {e}"))?;
    let context = draw_context(&endpoint, start, &battery).map_err(|e| e.to_string())?;
    let indices = select(&root, &context, count, k).map_err(|e| e.to_string())?;
    println!("  battery            {} {}", document["id"].as_str().unwrap_or(""), hex::encode(&battery));
    println!("  context            {}", String::from_utf8_lossy(&context));
    println!("  draw               {k} of {count}");
    println!("  indices            {}", indices.iter().map(u64::to_string).collect::<Vec<_>>().join(" "));
    Ok(())
}

/// `tvc verify-audit`. Returns the process exit code.
pub fn verify_audit(
    ledger: &Path,
    audit: &str,
    publisher: &str,
    reveals: &[PathBuf],
    as_json: bool,
) -> Result<u8, String> {
    let audit = digest_arg(audit, "--audit")?;
    let publisher = digest_arg(publisher, "--publisher")?;

    let mut chain = Check::new("ledger_chain_intact", exit::LEDGER);
    let mut in_ledger = Check::new("audit_in_ledger", exit::SIGNATURE);
    let mut signed = Check::new("signed_by_publisher", exit::SIGNATURE);
    let mut objects = Check::new("objects_match_digests", exit::DOCUMENT);
    let mut formed = Check::new("documents_well_formed", exit::DOCUMENT);
    let mut consistent = Check::new("references_match_claims", exit::DOCUMENT);
    let mut order = Check::new("calibration_before_audit", exit::ORDER);
    let mut anchored = Check::new("calibration_anchored_first", exit::ANCHOR);
    let mut draws = Check::new("draws_rederive", exit::DRAW);
    let mut thresholds = Check::new("thresholds_match", exit::VERDICT);
    let mut verdict = Check::new("verdict_follows", exit::VERDICT);
    let mut opened = Check::new("reveals_open", exit::DOCUMENT);

    let registry = match ModelRegistry::open(ledger).and_then(|r| r.verify_chain().map(|()| r)) {
        Ok(registry) => {
            chain.pass(format!("{} records, head {}", registry.len(), &registry.head_hex()[..16]));
            Some(registry)
        }
        Err(error) => {
            chain.fail(error.to_string());
            None
        }
    };

    let mut summary = None;
    match &registry {
        Some(registry) => match registry.get_document(&audit) {
            Some(record) if record.kind() == KIND_AUDIT => {
                in_ledger.pass(format!("sequence {}", record.sequence));
                let store = ObjectStore::beside(ledger);
                let docs = closure(registry, &store, audit, &mut objects);
                check_closure(registry, &docs, &publisher, &mut signed, &mut formed, &mut consistent);
                signed.pass(format!("{} documents, all signed by {}", docs.len(), &hex::encode(&publisher)[..16]));
                objects.pass(format!("{} objects re-hashed", docs.len()));
                formed.pass(format!("{} documents checked", docs.len()));
                consistent.pass(format!("{} documents checked", docs.len()));
                let by_digest: BTreeMap<[u8; 32], &Value> = docs
                    .iter()
                    .filter_map(|(record, document)| document.as_ref().map(|d| (record.document(), d)))
                    .collect();
                match by_digest.get(&audit) {
                    Some(document) => {
                        summary = Some(json!({
                            "endpoint": document["endpoint"],
                            "window": document["window"],
                            "verdict": document["verdict"],
                            "confidence": document["confidence"],
                        }));
                        let mut checks = AuditChecks {
                            order: &mut order,
                            anchored: &mut anchored,
                            draws: &mut draws,
                            thresholds: &mut thresholds,
                            verdict: &mut verdict,
                            opened: &mut opened,
                        };
                        check_audit(ledger, registry, record.sequence, document, &by_digest, reveals, &mut checks);
                    }
                    None => {
                        for check in [&mut order, &mut anchored, &mut draws, &mut thresholds, &mut verdict, &mut opened] {
                            check.skip("the audit document could not be read");
                        }
                    }
                }
            }
            Some(record) => {
                in_ledger.fail(format!("it is a {}, not an audit", record.kind()));
                skip_rest(&mut [&mut signed, &mut objects, &mut formed, &mut consistent, &mut order, &mut anchored, &mut draws, &mut thresholds, &mut verdict, &mut opened]);
            }
            None => {
                in_ledger.fail("no document with this digest in the ledger");
                skip_rest(&mut [&mut signed, &mut objects, &mut formed, &mut consistent, &mut order, &mut anchored, &mut draws, &mut thresholds, &mut verdict, &mut opened]);
            }
        },
        None => skip_rest(&mut [&mut in_ledger, &mut signed, &mut objects, &mut formed, &mut consistent, &mut order, &mut anchored, &mut draws, &mut thresholds, &mut verdict, &mut opened]),
    }

    let checks = [chain, in_ledger, signed, objects, formed, consistent, order, anchored, draws, thresholds, verdict, opened];
    let code = checks.iter().find(|c| c.status == Status::Fail).map_or(0, |c| c.exit);
    if as_json {
        let rendered: Vec<Value> = checks
            .iter()
            .map(|c| json!({"name": c.name, "status": c.status.label(), "detail": c.detail}))
            .collect();
        let report = json!({
            "audit": hex::encode(&audit),
            "publisher": hex::encode(&publisher),
            "ok": code == 0,
            "exit_code": code,
            "audit_says": summary,
            "checks": rendered,
        });
        println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
    } else {
        println!("Audit {}", hex::encode(&audit));
        if let Some(summary) = &summary {
            println!(
                "  {} at {}, {} to {}: {} (confidence {})",
                summary["endpoint"]["model"].as_str().unwrap_or("?"),
                summary["endpoint"]["host"].as_str().unwrap_or("?"),
                summary["window"]["start"].as_str().unwrap_or("?"),
                summary["window"]["end"].as_str().unwrap_or("?"),
                summary["verdict"].as_str().unwrap_or("?"),
                summary["confidence"].as_str().unwrap_or("?"),
            );
        }
        for check in &checks {
            println!("  {:<4}  {:<26}  {}", check.status.label().to_uppercase(), check.name, check.detail);
        }
        println!();
        println!(
            "{}",
            if code == 0 {
                "Every check that ran passed."
            } else {
                "At least one check failed; see above."
            }
        );
    }
    Ok(code)
}

fn skip_rest(checks: &mut [&mut Check]) {
    for check in checks {
        check.skip("not reached");
    }
}

struct AuditChecks<'a> {
    order: &'a mut Check,
    anchored: &'a mut Check,
    draws: &'a mut Check,
    thresholds: &'a mut Check,
    verdict: &'a mut Check,
    opened: &'a mut Check,
}

fn check_audit(
    ledger: &Path,
    registry: &ModelRegistry,
    audit_sequence: u64,
    audit: &Value,
    docs: &BTreeMap<[u8; 32], &Value>,
    reveals: &[PathBuf],
    checks: &mut AuditChecks,
) {
    // 1. The calibration came first, and the outside world saw it first.
    let calibration = digest_of(&audit["calibration"]);
    let calibration_sequence = calibration
        .and_then(|d| registry.get_document(&d))
        .map(|record| record.sequence);
    match calibration_sequence {
        Some(sequence) if sequence < audit_sequence => {
            checks.order.pass(format!("calibration is record {sequence}, the audit record {audit_sequence}"));
            check_anchored_first(ledger, registry, sequence, audit_sequence, checks.anchored);
        }
        Some(sequence) => {
            checks.order.fail(format!("calibration is record {sequence}, after the audit (record {audit_sequence})"));
            checks.anchored.skip("the calibration is not earlier than the audit");
        }
        None => {
            checks.order.fail("the calibration is not in the ledger");
            checks.anchored.skip("no calibration");
        }
    }

    // 2. Each draw re-derives from the battery's pool and the fixed context.
    let mut drawn = Vec::new();
    for draw in audit["draws"].as_array().into_iter().flatten() {
        let Some(battery) = digest_of(&draw["battery"]) else {
            checks.draws.fail("a draw names no battery");
            continue;
        };
        let Some((root, count, k)) = docs.get(&battery).and_then(|b| pool_of(b)) else {
            checks.draws.fail(format!("battery {} could not be read", &hex::encode(&battery)[..16]));
            continue;
        };
        let id = docs[&battery]["id"].as_str().unwrap_or("?").to_owned();
        if draw["k"].as_u64() != Some(k) {
            checks.draws.fail(format!("{id}: the audit drew {} items; the battery fixes {k}", draw["k"]));
            continue;
        }
        let wanted = draw_context(&audit["endpoint"], audit["window"]["start"].as_str().unwrap_or(""), &battery)
            .and_then(|context| select(&root, &context, count, k));
        let published: Vec<u64> = draw["indices"].as_array().into_iter().flatten().filter_map(Value::as_u64).collect();
        match wanted {
            Ok(indices) if indices == published => drawn.push((battery, id)),
            Ok(_) => checks.draws.fail(format!("{id}: the indices are not the ones the pool and context give")),
            Err(error) => checks.draws.fail(format!("{id}: {error}")),
        }
    }
    for result in audit["results"].as_array().into_iter().flatten() {
        let battery = digest_of(&result["battery"]);
        if !drawn.iter().any(|(d, _)| Some(*d) == battery) && checks.draws.status != Status::Fail {
            checks.draws.fail("a result names a battery the audit drew no items from");
        }
    }
    checks.draws.pass(format!(
        "{} battery draw(s) re-derived: {}",
        drawn.len(),
        drawn.iter().map(|(_, id)| id.as_str()).collect::<Vec<_>>().join(", ")
    ));

    // 3. Thresholds come from the calibration; verdicts follow from them.
    let t0 = audit["t0"]["matches"].as_bool().unwrap_or(false);
    let main = judge(&audit["results"], calibration.and_then(|d| docs.get(&d).copied()), t0, checks);
    let better = audit.get("better_match").map(|better| {
        let calibration = digest_of(&better["calibration"]).and_then(|d| docs.get(&d).copied());
        judge(&better["results"], calibration, true, checks)
            .is_some_and(|verdicts| verdicts.iter().all(|v| *v == "inside-band"))
    });
    if let Some(verdicts) = main {
        let expected = overall_verdict(&verdicts, t0, better);
        match audit["verdict"].as_str() {
            Some(found) if found == expected => {}
            found => checks.verdict.fail(format!(
                "the audit says {}, its numbers give {expected}",
                found.unwrap_or("nothing")
            )),
        }
        checks.verdict.pass(format!(
            "{} battery verdict(s) and the overall verdict ({expected}) recomputed",
            verdicts.len()
        ));
    }
    checks.thresholds.pass("every threshold is the calibration's for its battery and budget");

    // 4. Revealed responses or prompts open against the audit's commitments.
    if reveals.is_empty() {
        checks.opened.skip("no --reveal given");
        return;
    }
    let mut roots: Vec<(String, [u8; 32], u64)> = Vec::new();
    if let (Some(root), Some(count)) = (digest_of(&audit["responses"]["root"]), audit["responses"]["count"].as_u64()) {
        roots.push(("responses".to_owned(), root, count));
    }
    for (battery, id) in &drawn {
        if let Some((root, count, _)) = pool_of(docs[battery]) {
            roots.push((format!("{id} pool"), root, count));
        }
    }
    let mut opened = Vec::new();
    for path in reveals {
        let reveal = std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|text| serde_json::from_str::<Value>(&text).map_err(|e| e.to_string()))
            .and_then(|value| ItemReveal::from_json(&value).map_err(|e| e.to_string()));
        match reveal {
            Ok(reveal) => match roots.iter().find(|(_, root, count)| reveal.verify(root, *count).is_ok()) {
                Some((name, _, _)) => opened.push(format!("item {} of the {name}", reveal.index)),
                None => checks.opened.fail(format!("{} opens against none of the audit's commitments", path.display())),
            },
            Err(error) => checks.opened.fail(format!("{}: {error}", path.display())),
        }
    }
    checks.opened.pass(opened.join(", "));
}

/// Checks a results list against a calibration and recomputes each battery
/// verdict. Returns the recomputed verdicts, or `None` if the calibration is missing.
fn judge(results: &Value, calibration: Option<&Value>, t0: bool, checks: &mut AuditChecks) -> Option<Vec<&'static str>> {
    let Some(calibration) = calibration else {
        checks.thresholds.fail("the calibration could not be read");
        checks.verdict.skip("no calibration");
        return None;
    };
    let mut table: BTreeMap<(String, u64), String> = BTreeMap::new();
    for entry in calibration["entries"].as_array().into_iter().flatten() {
        if let (Some(battery), Some(k), Some(threshold)) =
            (entry["battery"].as_str(), entry["k"].as_u64(), entry["threshold"].as_str())
        {
            table.insert((battery.to_owned(), k), threshold.to_owned());
        }
    }
    let mut verdicts = Vec::new();
    for result in results.as_array().into_iter().flatten() {
        let battery = result["battery"].as_str().unwrap_or("");
        let k = result["k"].as_u64().unwrap_or(0);
        let short = &battery[..battery.len().min(16)];
        let Some(threshold) = table.get(&(battery.to_owned(), k)) else {
            checks.thresholds.fail(format!("the calibration has no threshold for battery {short} at k={k}"));
            continue;
        };
        let published = result["threshold"].as_str().unwrap_or("");
        if decimal_cmp(published, threshold).ok() != Some(core::cmp::Ordering::Equal) {
            checks.thresholds.fail(format!(
                "battery {short} at k={k}: the audit used {published}, the calibration says {threshold}"
            ));
        }
        match battery_verdict(result["statistic"].as_str().unwrap_or(""), threshold, t0) {
            Ok(expected) => {
                if result["verdict"].as_str() != Some(expected) {
                    checks.verdict.fail(format!(
                        "battery {short} at k={k}: the audit says {}, the numbers give {expected}",
                        result["verdict"].as_str().unwrap_or("nothing")
                    ));
                }
                verdicts.push(expected);
            }
            Err(error) => checks.verdict.fail(error.to_string()),
        }
    }
    Some(verdicts)
}

/// Passes when an anchor proof covering the calibration was made before the
/// audit was recorded, and says how far that proof gets (calendar or block).
fn check_anchored_first(ledger: &Path, registry: &ModelRegistry, calibration: u64, audit: u64, check: &mut Check) {
    let anchors = crate::stored_anchors(ledger, registry);
    let Some(first) = anchors.iter().find(|a| a.covered >= calibration && a.covered < audit) else {
        match anchors.iter().find(|a| a.covered >= calibration) {
            Some(later) => check.fail(format!(
                "the first anchor covering the calibration covers records to {}, which includes the audit (record {audit})",
                later.covered
            )),
            None => check.fail("no stored anchor covers the calibration; run tvc anchor before auditing"),
        }
        return;
    };
    let head = match first.proof.committed_digest() {
        Ok(head) => head,
        Err(error) => return check.fail(error),
    };
    let name = first.path.display();
    let status = if first.proof.is_null() {
        NullAnchor.verify(head, &first.proof)
    } else {
        OpenTimestampsCalendar::default().verify(head, &first.proof)
    };
    match status {
        Ok(AnchorStatus::BitcoinAttested { height, .. }) => check.pass(format!(
            "{name} covers records to {} and claims Bitcoin block {height}; the audit window must start after that block's time",
            first.covered
        )),
        Ok(AnchorStatus::Pending { .. }) => check.pass(format!(
            "{name} covers records to {}; a calendar holds it, not yet in a Bitcoin block (run tvc verify-anchor)",
            first.covered
        )),
        Ok(AnchorStatus::Unattested) => check.skip(format!(
            "{name} is an offline anchor only; no outside party saw the calibration"
        )),
        Err(error) => check.fail(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tvc_core::canonical::canonical_digest;
    use tvc_core::documents::refs_of;
    use tvc_core::signer::{DocumentClaim, PublisherKeypair};

    struct Fixture {
        dir: PathBuf,
        ledger: PathBuf,
        key: PublisherKeypair,
        battery: [u8; 32],
        calibration: [u8; 32],
        better_calibration: [u8; 32],
    }

    fn d(byte: u8) -> String {
        hex::encode(&[byte; 32])
    }

    fn publish(fixture_ledger: &Path, key: &PublisherKeypair, document: Value) -> [u8; 32] {
        let mut registry = ModelRegistry::open(fixture_ledger).unwrap();
        let kind = document["kind"].as_str().unwrap().to_owned();
        let digest = canonical_digest(&document).unwrap();
        let claim = DocumentClaim::new(kind.clone(), digest, refs_of(&kind, &document).unwrap(), 1_790_000_000);
        let signed = key.sign_document(&claim, &[3; 32]).unwrap();
        ObjectStore::beside(fixture_ledger).put(&document).unwrap();
        registry.register_document(signed).unwrap();
        digest
    }

    fn anchor_now(ledger: &Path) {
        let registry = ModelRegistry::open(ledger).unwrap();
        let proof = NullAnchor.stamp(registry.head()).unwrap();
        crate::keep_anchor(ledger, registry.len() as u64 - 1, &registry.head(), &proof).unwrap();
    }

    fn reference(ledger: &Path, key: &PublisherKeypair, model: &str, battery: [u8; 32]) -> ([u8; 32], [u8; 32]) {
        let manifest = publish(ledger, key, json!({"kind": "weights-manifest/v1", "model": model,
            "files": [{"path": "model.safetensors", "size": 1, "sha256": d(1)}]}));
        let setup = publish(ledger, key, json!({"kind": "reference-setup/v2", "weights": hex::encode(&manifest),
            "engine": "vllm", "engine_version": "0.30.0", "dtype": "bfloat16", "hardware": "1x L4",
            "context_length": 4096, "decoding": {"top_p": "1"}, "kernel_mode": "batch-invariant", "gpu": "L4",
            "driver": "580", "seed": 0, "harness": {"repo": "r", "commit": "c"}, "lock_sha256": d(2),
            "request": {"system_prompt": null}}));
        let run = |seed: u8| json!({"kind": "reference-run/v2", "setup": hex::encode(&setup), "battery": hex::encode(&battery),
            "date": "2026-10-03", "prompts": {"root": d(7), "count": 40}, "outputs": {"root": d(seed), "count": 400},
            "samples_per_prompt": 10, "bands": [], "evidence_sha256": d(seed)});
        let reference_run = publish(ledger, key, run(20));
        let member = publish(ledger, key, run(21));
        let honest = publish(ledger, key, json!({"kind": "honest-set/v1", "reference_run": hex::encode(&reference_run),
            "members": [{"setup": hex::encode(&setup), "run": hex::encode(&member), "differs": "seed: 1"}]}));
        (reference_run, honest)
    }

    fn publish_calibration(ledger: &Path, key: &PublisherKeypair, battery: [u8; 32], run: [u8; 32], honest: [u8; 32], threshold: &str) -> [u8; 32] {
        publish(ledger, key, json!({"kind": "calibration/v1", "reference_run": hex::encode(&run),
            "honest_set": hex::encode(&honest), "quantile": "0.95", "method": "leave-one-out over the honest set",
            "entries": [{"battery": hex::encode(&battery), "k": 20, "threshold": threshold,
                         "honest_fpr_mean": "0.05", "honest_fpr_max": "0.1", "power": []}],
            "cannot_detect": ["GPTQ int8 weight-only"]}))
    }

    fn fixture(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("tvc-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ledger = dir.join("registry.jsonl");
        let key = PublisherKeypair::from_secret_bytes(&[9; 32]).unwrap();
        let battery = publish(&ledger, &key, json!({"kind": "battery/v1", "id": "T1", "version": "2",
            "pool": {"root": d(7), "count": 40}, "draw": {"k": 8, "context": "tvc_core::audit::draw_context"},
            "decoding": {"temperature": "1"}, "normalisation": "first word",
            "statistic": {"name": "mean JSD", "code": {"repo": "r", "commit": "c", "path": "p", "sha256": d(3)}},
            "signals": ["S-02"]}));
        let (run, honest) = reference(&ledger, &key, "claimed/model", battery);
        let calibration = publish_calibration(&ledger, &key, battery, run, honest, "0.12");
        let (other_run, other_honest) = reference(&ledger, &key, "other/model", battery);
        let better_calibration = publish_calibration(&ledger, &key, battery, other_run, other_honest, "0.15");
        anchor_now(&ledger);
        Fixture { dir, ledger, key, battery, calibration, better_calibration }
    }

    fn endpoint() -> Value {
        json!({"host": "api.example.com", "model": "claimed/model", "provider": "Provider A"})
    }

    fn audit_doc(f: &Fixture, statistic: &str) -> Value {
        let start = "2026-10-04T09:00:00Z";
        let context = draw_context(&endpoint(), start, &f.battery).unwrap();
        let indices = select(&[7; 32], &context, 40, 8).unwrap();
        let t0 = true;
        let verdict = battery_verdict(statistic, "0.12", t0).unwrap();
        json!({"kind": "audit/v1", "endpoint": endpoint(),
               "window": {"start": start, "end": "2026-10-04T09:20:00Z"},
               "calibration": hex::encode(&f.calibration),
               "draws": [{"battery": hex::encode(&f.battery), "k": 8, "indices": indices}],
               "responses": {"root": d(30), "count": 160},
               "results": [{"battery": hex::encode(&f.battery), "k": 20, "statistic": statistic, "threshold": "0.12", "verdict": verdict}],
               "t0": {"matches": t0},
               "verdict": overall_verdict(&[verdict], t0, None),
               "confidence": "0.95"})
    }

    fn verify(f: &Fixture, audit: [u8; 32]) -> u8 {
        verify_audit(&f.ledger, &hex::encode(&audit), &hex::encode(&f.key.public_key()), &[], true).unwrap()
    }

    #[test]
    fn an_honest_audit_passes() {
        let f = fixture("honest");
        let audit = publish(&f.ledger, &f.key, audit_doc(&f, "0.05"));
        assert_eq!(verify(&f, audit), 0);
        let outside = publish(&f.ledger, &f.key, audit_doc(&f, "0.3"));
        assert_eq!(verify(&f, outside), 0);
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    #[test]
    fn an_edited_threshold_is_caught() {
        let f = fixture("threshold");
        let mut doc = audit_doc(&f, "0.3");
        doc["results"][0]["threshold"] = json!("0.5");
        doc["results"][0]["verdict"] = json!("inside-band");
        doc["verdict"] = json!("consistent");
        let audit = publish(&f.ledger, &f.key, doc);
        assert_eq!(verify(&f, audit), exit::VERDICT);
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    #[test]
    fn hand_picked_prompts_are_caught() {
        let f = fixture("draw");
        let mut doc = audit_doc(&f, "0.05");
        doc["draws"][0]["indices"] = json!([0, 1, 2, 3, 4, 5, 6, 7]);
        let audit = publish(&f.ledger, &f.key, doc);
        assert_eq!(verify(&f, audit), exit::DRAW);
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    #[test]
    fn a_flipped_verdict_is_caught() {
        let f = fixture("verdict");
        let mut doc = audit_doc(&f, "0.3");
        doc["verdict"] = json!("consistent");
        let audit = publish(&f.ledger, &f.key, doc);
        assert_eq!(verify(&f, audit), exit::VERDICT);
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    #[test]
    fn a_calibration_nobody_saw_before_the_audit_fails() {
        let f = fixture("anchor");
        // A calibration published and used without an anchor in between.
        let late = {
            let registry = ModelRegistry::open(&f.ledger).unwrap();
            let record = registry.get_document(&f.calibration).unwrap();
            let doc = ObjectStore::beside(&f.ledger).get(&record.document()).unwrap();
            let mut doc = doc;
            doc["quantile"] = json!("0.99");
            publish(&f.ledger, &f.key, doc)
        };
        let mut audit = audit_doc(&f, "0.05");
        audit["calibration"] = json!(hex::encode(&late));
        let audit = publish(&f.ledger, &f.key, audit);
        assert_eq!(verify(&f, audit), exit::ANCHOR);
        // Anchoring afterwards does not help: the proof also covers the audit.
        anchor_now(&f.ledger);
        assert_eq!(verify(&f, audit), exit::ANCHOR);
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    #[test]
    fn a_t0_mismatch_makes_the_audit_misconfigured() {
        let f = fixture("t0");
        let mut doc = audit_doc(&f, "0.3");
        doc["t0"] = json!({"matches": false, "detail": "prompt_tokens 25 above the template"});
        doc["results"][0]["verdict"] = json!("inconclusive-T0");
        doc["verdict"] = json!("misconfigured");
        let audit = publish(&f.ledger, &f.key, doc.clone());
        assert_eq!(verify(&f, audit), 0);
        doc["verdict"] = json!("inconsistent-with-declared-configuration");
        doc["confidence"] = json!("0.9");
        let wrong = publish(&f.ledger, &f.key, doc);
        assert_eq!(verify(&f, wrong), exit::VERDICT);
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    #[test]
    fn different_model_needs_a_better_match_inside_its_band() {
        let f = fixture("better");
        let mut doc = audit_doc(&f, "0.3");
        doc["better_match"] = json!({"calibration": hex::encode(&f.better_calibration),
            "results": [{"battery": hex::encode(&f.battery), "k": 20, "statistic": "0.1", "threshold": "0.15", "verdict": "inside-band"}]});
        doc["verdict"] = json!("different-model");
        let audit = publish(&f.ledger, &f.key, doc.clone());
        assert_eq!(verify(&f, audit), 0);
        doc["better_match"]["results"][0]["statistic"] = json!("0.2");
        doc["better_match"]["results"][0]["verdict"] = json!("outside-band");
        let not_better = publish(&f.ledger, &f.key, doc);
        assert_eq!(verify(&f, not_better), exit::VERDICT);
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    #[test]
    fn the_wrong_publisher_is_refused() {
        let f = fixture("signer");
        let audit = publish(&f.ledger, &f.key, audit_doc(&f, "0.05"));
        let other = PublisherKeypair::from_secret_bytes(&[8; 32]).unwrap();
        let code = verify_audit(&f.ledger, &hex::encode(&audit), &hex::encode(&other.public_key()), &[], true).unwrap();
        assert_eq!(code, exit::SIGNATURE);
        let _ = std::fs::remove_dir_all(&f.dir);
    }
}
