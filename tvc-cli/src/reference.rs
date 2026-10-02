//! Commands for publishing and checking reference profiles.
//!
//! The flow, for whoever runs a reference:
//!
//! ```text
//! tvc manifest       --dir <model> --model <name> [--hf-repo R --hf-commit C] --out manifest.json
//! tvc publish        --doc manifest.json
//! tvc publish        --doc setup.json                   (cites the manifest)
//! tvc commit-items   --items prompts.jsonl --private prompts.private.json
//! tvc commit-items   --items outputs.jsonl --private outputs.private.json
//! tvc publish        --doc run.json                     (cites the setup, holds both roots)
//! tvc publish        --doc profile.json                 (cites the manifest and runs)
//! tvc anchor
//! ```
//!
//! and for anyone checking it:
//!
//! ```text
//! tvc verify-reference --profile <digest> --publisher <key> [--weights-dir <model>]
//! tvc check-hf         --manifest manifest.json
//! tvc verify-reveal    --reveal r.json --run <digest> --set prompts
//! ```

use std::collections::{BTreeSet, VecDeque};
use std::path::Path;

use serde_json::{json, Value};
use tvc_core::canonical::canonical_digest;
use tvc_core::documents::{
    refs_of, validate_document, ObjectStore, KIND_PROFILE, KIND_PROFILE_V2, RUN_KINDS,
    KIND_REFERENCE_RUN_V2,
};
use tvc_core::hex;
use tvc_core::itemset::{select, ItemReveal, ItemSet};
use tvc_core::manifest::WeightsManifest;
use tvc_core::registry::{DocumentRecord, ModelRegistry};
use tvc_core::signer::{unix_now, DocumentClaim};

use crate::anchor::{Anchor, AnchorProof, AnchorStatus, OpenTimestampsCalendar};
use crate::hf;

fn read_json(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("{}: not JSON: {error}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    std::fs::write(path, text + "\n").map_err(|error| format!("{}: {error}", path.display()))
}

fn digest_arg(text: &str, flag: &str) -> Result<[u8; 32], String> {
    hex::decode_array::<32>(text.trim())
        .map_err(|error| format!("{flag} must be a 64-character lowercase hex digest: {error}"))
}

fn open(ledger: &Path) -> Result<ModelRegistry, String> {
    ModelRegistry::open(ledger).map_err(|error| error.to_string())
}

/// `tvc manifest`
pub fn manifest(
    dir: &Path,
    model: &str,
    hf_repo: Option<String>,
    hf_commit: Option<String>,
    out: &Path,
) -> Result<(), String> {
    let built = WeightsManifest::from_dir(dir, model, hf_repo, hf_commit).map_err(|e| e.to_string())?;
    let document = built.to_json();
    write_json(out, &document)?;
    let total: u64 = built.files.iter().map(|f| f.size).sum();
    println!("Hashed {} files ({total} bytes) under {}.", built.files.len(), dir.display());
    for file in &built.files {
        println!("  {}  {:>14}  {}", &hex::encode(&file.sha256)[..16], file.size, file.path);
    }
    println!();
    println!("  manifest           {}", out.display());
    println!(
        "  digest             {}",
        hex::encode(&canonical_digest(&document).map_err(|e| e.to_string())?)
    );
    Ok(())
}

/// `tvc verify-dir`
pub fn verify_dir(manifest_path: &Path, dir: &Path) -> Result<(), String> {
    let manifest = WeightsManifest::from_json(&read_json(manifest_path)?).map_err(|e| e.to_string())?;
    let mismatches = manifest.verify_dir(dir).map_err(|e| e.to_string())?;
    if mismatches.is_empty() {
        println!(
            "{} holds exactly the {} files in the manifest, byte for byte.",
            dir.display(),
            manifest.files.len()
        );
        return Ok(());
    }
    for mismatch in &mismatches {
        println!("  FAIL  {mismatch}");
    }
    Err(format!("{} differs from the manifest in {} place(s)", dir.display(), mismatches.len()))
}

/// `tvc check-hf`
pub fn check_hf(manifest_path: &Path) -> Result<(), String> {
    let manifest = WeightsManifest::from_json(&read_json(manifest_path)?).map_err(|e| e.to_string())?;
    let report = hf::check(&manifest)?;
    println!(
        "Comparing against huggingface.co/{} at {}:",
        manifest.hf_repo.as_deref().unwrap_or(""),
        manifest.hf_commit.as_deref().unwrap_or("")
    );
    for file in &report.files {
        let line = match &file.status {
            hf::FileStatus::LfsMatch => "PASS  sha256 matches the hub's LFS record (not downloaded)".to_owned(),
            hf::FileStatus::DownloadedMatch => "PASS  downloaded and hashed; matches".to_owned(),
            hf::FileStatus::Mismatch(reason) => format!("FAIL  {reason}"),
            hf::FileStatus::NotInRepository => "FAIL  not in the repository at this commit".to_owned(),
        };
        println!("  {line:<60}  {}", file.path);
    }
    if !report.unlisted.is_empty() {
        println!();
        println!("In the repository but not in the manifest (not used by this reference):");
        for path in &report.unlisted {
            println!("  {path}");
        }
    }
    if report.all_match() {
        Ok(())
    } else {
        Err("the manifest does not match the repository".to_owned())
    }
}

/// `tvc commit-items`
pub fn commit_items(items_path: &Path, private_path: &Path) -> Result<(), String> {
    if private_path.exists() {
        return Err(format!(
            "{} already exists; refusing to overwrite the only copy of a set's salts",
            private_path.display()
        ));
    }
    let text = std::fs::read_to_string(items_path)
        .map_err(|error| format!("{}: {error}", items_path.display()))?;
    let mut items = Vec::new();
    for (number, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        items.push(
            serde_json::from_str::<Value>(line)
                .map_err(|error| format!("{} line {}: {error}", items_path.display(), number + 1))?,
        );
    }
    let salts = (0..items.len())
        .map(|_| crate::os_random())
        .collect::<Result<Vec<_>, _>>()?;
    let set = ItemSet::commit(items, salts).map_err(|e| e.to_string())?;
    write_private(private_path, &set.to_private_json())?;

    let root = set.root();
    println!("Committed {} items from {}.", root.length, items_path.display());
    println!("  root               {}", hex::encode(&root.tree_root));
    println!("  count              {}", root.length);
    println!("  private file       {}", private_path.display());
    println!();
    println!("Put the root and count in the reference-run document. Keep the private file");
    println!("private: it holds every item and its salt, and anyone with it can reveal them.");
    Ok(())
}

fn write_private(path: &Path, value: &Value) -> Result<(), String> {
    use std::io::Write;
    let text = serde_json::to_string_pretty(value).map_err(|error| error.to_string())? + "\n";
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(text.as_bytes())
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// `tvc reveal`
pub fn reveal(private_path: &Path, index: usize, out: &Path) -> Result<(), String> {
    let set = ItemSet::from_private_json(&read_json(private_path)?).map_err(|e| e.to_string())?;
    let revealed = set.reveal(index).map_err(|e| e.to_string())?;
    write_json(out, &revealed.to_json())?;
    println!("Revealed item {index} of {} to {}.", set.len(), out.display());
    Ok(())
}

/// Loads a reference-run document and returns the (root, count) of one of its sets.
fn run_set(ledger: &Path, run: &[u8; 32], set: &str) -> Result<([u8; 32], u64), String> {
    let registry = open(ledger)?;
    let record = registry
        .get_document(run)
        .ok_or_else(|| format!("{} is not a document in {}", hex::encode(run), ledger.display()))?;
    if !RUN_KINDS.contains(&record.kind()) {
        return Err(format!("{} is a {}, not a reference run", hex::encode(run), record.kind()));
    }
    let document = ObjectStore::beside(ledger).get(run).map_err(|e| e.to_string())?;
    if set != "prompts" && set != "outputs" {
        return Err("--set must be prompts or outputs".to_owned());
    }
    let entry = &document[set];
    let root = hex::decode_array::<32>(entry["root"].as_str().unwrap_or(""))
        .map_err(|error| format!("run document {set}.root: {error}"))?;
    let count = entry["count"].as_u64().ok_or("run document has no count")?;
    Ok((root, count))
}

/// `tvc verify-reveal`
pub fn verify_reveal(reveal_path: &Path, ledger: &Path, run: &str, set: &str) -> Result<(), String> {
    let run = digest_arg(run, "--run")?;
    let (root, count) = run_set(ledger, &run, set)?;
    let revealed = ItemReveal::from_json(&read_json(reveal_path)?).map_err(|e| e.to_string())?;
    revealed.verify(&root, count).map_err(|e| e.to_string())?;
    println!(
        "Item {} opens against the {set} root of reference run {}.",
        revealed.index,
        hex::encode(&run)
    );
    println!("It was in the committed set when that run was published; it was not added later.");
    println!();
    println!("{}", serde_json::to_string_pretty(&revealed.item).map_err(|e| e.to_string())?);
    Ok(())
}

/// `tvc sample`
pub fn sample(ledger: &Path, run: &str, set: &str, k: u64, context: &str) -> Result<(), String> {
    let run = digest_arg(run, "--run")?;
    let (root, count) = run_set(ledger, &run, set)?;
    let chosen = select(&root, context.as_bytes(), count, k).map_err(|e| e.to_string())?;
    println!(
        "{k} of {count} {set}, chosen from the committed root and the context {context:?}:"
    );
    println!("  {}", chosen.iter().map(u64::to_string).collect::<Vec<_>>().join(" "));
    Ok(())
}

/// `tvc publish`
pub fn publish(doc_path: &Path, ledger: &Path) -> Result<(), String> {
    let document = read_json(doc_path)?;
    let kind = document
        .get("kind")
        .and_then(Value::as_str)
        .ok_or("the document has no kind field")?
        .to_owned();
    let mut registry = open(ledger)?;

    let kind_of = |digest: &[u8; 32]| registry.get_document(digest).map(|r| r.kind().to_owned());
    validate_document(&kind, &document, &kind_of).map_err(|e| e.to_string())?;
    let refs = refs_of(&kind, &document).map_err(|e| e.to_string())?;
    let digest = canonical_digest(&document).map_err(|e| e.to_string())?;
    let keypair = crate::publisher_key()?;

    let claim = DocumentClaim::new(kind.clone(), digest, refs, unix_now());
    let signed = keypair
        .sign_document(&claim, &crate::os_random()?)
        .map_err(|e| e.to_string())?;
    let store = ObjectStore::beside(ledger);
    store.put(&document).map_err(|e| e.to_string())?;
    let record = registry.register_document(signed).map_err(|e| e.to_string())?;

    println!("Published a {kind} in {}.", ledger.display());
    println!("  document           {}", hex::encode(&digest));
    println!("  object             {}", store.path_for(&digest).display());
    println!("  signer             {}", keypair.public_key_hex());
    println!("  sequence           {}", record.sequence);
    println!("  ledger head        {}", registry.head_hex());
    Ok(())
}

/// `tvc show`
pub fn show(ledger: &Path, digest: &str) -> Result<(), String> {
    let digest = digest_arg(digest, "--digest")?;
    let registry = open(ledger)?;
    let record = registry
        .get_document(&digest)
        .ok_or_else(|| format!("{} is not a document in {}", hex::encode(&digest), ledger.display()))?;
    let document = ObjectStore::beside(ledger).get(&digest).map_err(|e| e.to_string())?;
    println!("  kind               {}", record.kind());
    println!("  sequence           {}", record.sequence);
    println!("  signer             {}", hex::encode(&record.signed.signer));
    println!("  timestamp          {}", record.signed.claim.timestamp);
    for reference in &record.signed.claim.refs {
        println!("  cites              {}", hex::encode(reference));
    }
    println!();
    println!("{}", serde_json::to_string_pretty(&document).map_err(|e| e.to_string())?);
    Ok(())
}

// ---------------------------------------------------------------------------
// verify-reference
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Pass,
    Fail,
    Skip,
}

impl Status {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skip => "skip",
        }
    }
}

pub(crate) struct Check {
    pub(crate) name: &'static str,
    /// Process exit code when this is the first failing check.
    pub(crate) exit: u8,
    pub(crate) status: Status,
    pub(crate) detail: String,
}

impl Check {
    pub(crate) fn new(name: &'static str, exit: u8) -> Self {
        Self {
            name,
            exit,
            status: Status::Pass,
            detail: String::new(),
        }
    }

    pub(crate) fn fail(&mut self, detail: impl Into<String>) {
        if self.status != Status::Fail {
            self.status = Status::Fail;
            self.detail = detail.into();
        }
    }

    pub(crate) fn skip(&mut self, detail: impl Into<String>) {
        self.status = Status::Skip;
        self.detail = detail.into();
    }

    pub(crate) fn pass(&mut self, detail: impl Into<String>) {
        if self.status == Status::Pass {
            self.detail = detail.into();
        }
    }
}

/// Exit codes `verify-reference` uses, one per failure class.
pub mod exit {
    /// The ledger could not be opened or its hash chain is broken.
    pub const LEDGER: u8 = 2;
    /// The profile is missing, or a document is not signed by the pinned key.
    pub const SIGNATURE: u8 = 3;
    /// A document is missing, edited, malformed or inconsistent with its claim.
    pub const DOCUMENT: u8 = 4;
    /// Weights on disk differ from the manifest.
    pub const WEIGHTS: u8 = 5;
    /// The anchor proof does not cover this profile.
    pub const ANCHOR: u8 = 6;
    /// A document an audit relies on was published after the audit.
    pub const ORDER: u8 = 7;
    /// An audit's prompt draw does not re-derive from the committed pool.
    pub const DRAW: u8 = 8;
    /// An audit's thresholds or verdict do not follow from its calibration.
    pub const VERDICT: u8 = 9;
}

/// Every document `start` depends on through the ledger's signed claims,
/// `start` first, each with its stored object (`None` if it could not be read).
/// Objects that fail to load are reported through `objects`.
pub(crate) fn closure(
    registry: &ModelRegistry,
    store: &ObjectStore,
    start: [u8; 32],
    objects: &mut Check,
) -> Vec<(DocumentRecord, Option<Value>)> {
    let mut out = Vec::new();
    let mut queue = VecDeque::from([start]);
    let mut seen = BTreeSet::new();
    while let Some(digest) = queue.pop_front() {
        if !seen.insert(digest) {
            continue;
        }
        let Some(record) = registry.get_document(&digest) else {
            continue;
        };
        queue.extend(record.signed.claim.refs.iter().copied());
        let document = store.get(&digest).map_err(|e| e.to_string());
        if let Err(error) = &document {
            objects.fail(format!("{}: {error}", &hex::encode(&digest)[..16]));
        }
        out.push((record.clone(), document.ok()));
    }
    out
}

/// Signature, shape and claim-consistency checks over a closure.
pub(crate) fn check_closure(
    registry: &ModelRegistry,
    closure: &[(DocumentRecord, Option<Value>)],
    publisher: &[u8; 32],
    signed: &mut Check,
    formed: &mut Check,
    consistent: &mut Check,
) {
    let kind_of = |d: &[u8; 32]| registry.get_document(d).map(|r| r.kind().to_owned());
    for (record, document) in closure {
        let short = &record.digest_hex()[..16];
        if let Err(error) = record.signed.verify_signed_by(publisher) {
            signed.fail(format!("{} ({}): {error}", record.kind(), short));
        }
        let Some(document) = document else { continue };
        if let Err(error) = validate_document(record.kind(), document, &kind_of) {
            formed.fail(error.to_string());
        }
        match refs_of(record.kind(), document) {
            Ok(refs) if refs == record.signed.claim.refs => {}
            Ok(_) => consistent.fail(format!(
                "the {} document cites different documents than its signed claim",
                record.kind()
            )),
            Err(error) => consistent.fail(error.to_string()),
        }
    }
}

/// `tvc verify-reference`. Returns the process exit code.
pub fn verify_reference(
    ledger: &Path,
    profile: &str,
    publisher: &str,
    weights_dir: Option<&Path>,
    as_json: bool,
) -> Result<u8, String> {
    let profile = digest_arg(profile, "--profile")?;
    let publisher = digest_arg(publisher, "--publisher")?;

    let mut chain = Check::new("ledger_chain_intact", exit::LEDGER);
    let mut in_ledger = Check::new("profile_in_ledger", exit::SIGNATURE);
    let mut signed = Check::new("signed_by_publisher", exit::SIGNATURE);
    let mut objects = Check::new("objects_match_digests", exit::DOCUMENT);
    let mut formed = Check::new("documents_well_formed", exit::DOCUMENT);
    let mut consistent = Check::new("references_match_claims", exit::DOCUMENT);
    let mut same_weights = Check::new("runs_use_profile_weights", exit::DOCUMENT);
    let mut on_disk = Check::new("weights_on_disk", exit::WEIGHTS);
    let mut anchored = Check::new("anchored_after_profile", exit::ANCHOR);

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

    let mut closure: Vec<(DocumentRecord, Option<Value>)> = Vec::new();
    if let Some(registry) = &registry {
        match registry.get_document(&profile) {
            Some(record) if record.kind() == KIND_PROFILE || record.kind() == KIND_PROFILE_V2 => {
                in_ledger.pass(format!("sequence {}", record.sequence));
            }
            Some(record) => in_ledger.fail(format!("it is a {}, not a profile", record.kind())),
            None => in_ledger.fail("no document with this digest in the ledger"),
        }

        // Every document the profile depends on, through the ledger's claims.
        let store = ObjectStore::beside(ledger);
        closure.extend(self::closure(registry, &store, profile, &mut objects));
        check_closure(registry, &closure, &publisher, &mut signed, &mut formed, &mut consistent);
        let count = closure.len();
        let loaded = closure.iter().filter(|(_, document)| document.is_some()).count();
        signed.pass(format!("{count} documents, all signed by {}", &hex::encode(&publisher)[..16]));
        objects.pass(format!("{count} objects re-hashed"));
        formed.pass(format!("{loaded} of {count} documents could be read and checked"));
        consistent.pass(format!("{loaded} of {count} documents could be read and checked"));

        // Each run's setup must describe the same weights the profile names.
        // That means the profile's own runs and its honest set. A calibration
        // also cites substitute runs, which ran other weights on purpose.
        let by_digest: std::collections::BTreeMap<[u8; 32], &Value> = closure
            .iter()
            .filter_map(|(record, document)| document.as_ref().map(|d| (record.document(), d)))
            .collect();
        let get = |value: &Value| -> Option<&Value> {
            hex::decode_array::<32>(value.as_str()?).ok().and_then(|d| by_digest.get(&d).copied())
        };
        let profile_document = by_digest.get(&profile).copied();
        let profile_weights = profile_document.and_then(|p| p["weights"].as_str()).map(str::to_owned);
        let mut own_runs: Vec<&Value> = profile_document
            .and_then(|p| p["runs"].as_array())
            .into_iter()
            .flatten()
            .filter_map(get)
            .collect();
        let honest_set = profile_document.and_then(|p| p.get("honest_set")).and_then(get);
        let mut own_setups: Vec<&Value> = Vec::new();
        if let Some(set) = honest_set {
            own_runs.extend(get(&set["reference_run"]));
            for member in set["members"].as_array().into_iter().flatten() {
                own_runs.extend(get(&member["run"]));
                own_setups.extend(get(&member["setup"]));
            }
        }
        own_setups.extend(own_runs.iter().filter_map(|run| get(&run["setup"])));
        own_setups.sort_by_key(|setup| std::ptr::from_ref::<Value>(setup) as usize);
        own_setups.dedup_by(|a, b| std::ptr::eq(*a, *b));
        let mismatched = own_setups
            .iter()
            .filter(|setup| setup["weights"].as_str().map(str::to_owned) != profile_weights)
            .count();
        if mismatched > 0 {
            same_weights.fail(format!("{mismatched} setup(s) ran different weights than the profile names"));
        } else {
            same_weights.pass(format!("{} setup(s), one weights manifest", own_setups.len()));
        }

        // v2: a run's prompts are its battery's pool; a full profile has the
        // honest set and measured power its maturity promises.
        if profile_document.is_some_and(|p| p["kind"] == KIND_PROFILE_V2) {
            for run in own_runs.iter().filter(|run| run["kind"] == KIND_REFERENCE_RUN_V2) {
                match get(&run["battery"]) {
                    Some(battery) if battery["pool"]["root"] == run["prompts"]["root"] => {}
                    Some(_) if run["prompts_subset_of_pool"] == Value::Bool(true) => {}
                    Some(battery) => formed.fail(format!(
                        "a {} run's prompts are not its battery's committed pool",
                        battery["id"].as_str().unwrap_or("?")
                    )),
                    None => formed.fail("a v2 run's battery could not be read"),
                }
            }
            if profile_document.is_some_and(|p| p["maturity"] == "full") {
                let members = honest_set.and_then(|s| s["members"].as_array()).map_or(0, Vec::len);
                let substitutes: BTreeSet<&str> = profile_document
                    .and_then(|p| p["calibrations"].as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(get)
                    .flat_map(|c| c["entries"].as_array().into_iter().flatten())
                    .flat_map(|e| e["power"].as_array().into_iter().flatten())
                    .filter_map(|p| p["against"].as_str())
                    .collect();
                if members < 4 || substitutes.len() < 2 {
                    formed.fail(format!(
                        "a full profile needs an honest set of at least 4 and power against at least 2 runs; it has {members} and {}",
                        substitutes.len()
                    ));
                }
            }
        }
        let profile_manifest = profile_document.and_then(|p| get(&p["weights"]));
        match (weights_dir, profile_manifest) {
            (None, _) => on_disk.skip("no --weights-dir given"),
            (Some(_), None) => on_disk.fail("the profile has no weights manifest"),
            (Some(dir), Some(document)) => match WeightsManifest::from_json(document)
                .and_then(|m| m.verify_dir(dir))
            {
                Ok(found) if found.is_empty() => on_disk.pass(format!("{} matches byte for byte", dir.display())),
                Ok(found) => on_disk.fail(format!("{} difference(s), first: {}", found.len(), found[0])),
                Err(error) => on_disk.fail(error.to_string()),
            },
        }

        check_anchor(ledger, registry, &profile, &mut anchored);
    } else {
        for check in [&mut in_ledger, &mut signed, &mut objects, &mut formed, &mut consistent, &mut same_weights, &mut on_disk, &mut anchored] {
            check.skip("ledger could not be read");
        }
    }

    let checks = [chain, in_ledger, signed, objects, formed, consistent, same_weights, on_disk, anchored];
    let code = checks
        .iter()
        .find(|c| c.status == Status::Fail)
        .map_or(0, |c| c.exit);

    if as_json {
        let rendered: Vec<Value> = checks
            .iter()
            .map(|c| json!({"name": c.name, "status": c.status.label(), "detail": c.detail}))
            .collect();
        let report = json!({
            "profile": hex::encode(&profile),
            "publisher": hex::encode(&publisher),
            "ok": code == 0,
            "exit_code": code,
            "checks": rendered,
        });
        println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
    } else {
        println!("Reference profile {}", hex::encode(&profile));
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

fn check_anchor(ledger: &Path, registry: &ModelRegistry, profile: &[u8; 32], check: &mut Check) {
    let proof_path = crate::anchor_proof_path(ledger);
    if !proof_path.exists() {
        check.skip("no registry.head.ots yet; run tvc anchor");
        return;
    }
    let proof = match AnchorProof::from_file(&proof_path) {
        Ok(proof) => proof,
        Err(error) => return check.fail(error),
    };
    let anchored = match proof.committed_digest() {
        Ok(digest) => digest,
        Err(error) => return check.fail(error),
    };
    let profile_sequence = registry.get_document(profile).map_or(u64::MAX, |r| r.sequence);
    let anchored_sequence = registry
        .records()
        .iter()
        .map(|r| (r.sequence, r.digest))
        .chain(registry.documents().iter().map(|r| (r.sequence, r.digest)))
        .find(|(_, digest)| digest == &anchored)
        .map(|(sequence, _)| sequence);
    match anchored_sequence {
        None => return check.fail("the anchored head is not a record in this ledger"),
        Some(sequence) if sequence < profile_sequence => {
            return check.fail(format!(
                "the anchor covers the ledger up to record {sequence}, before this profile (record {profile_sequence}); run tvc anchor again"
            ))
        }
        Some(_) => {}
    }
    if proof.is_null() {
        check.skip("offline anchor only; no outside party has seen this head");
        return;
    }
    match OpenTimestampsCalendar::default().verify(anchored, &proof) {
        Ok(AnchorStatus::BitcoinAttested { height, .. }) => check.pass(format!(
            "covered by a proof claiming Bitcoin block {height} (check it with tvc verify-anchor)"
        )),
        Ok(AnchorStatus::Pending { .. }) => check.pass(
            "covered by a calendar commitment, not yet in a Bitcoin block (pending)",
        ),
        Ok(AnchorStatus::Unattested) => check.skip("offline anchor only"),
        Err(error) => check.fail(error),
    }
}
