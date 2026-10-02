//! `tvc` — publisher and auditor command line for the W-TVC model registry.
//!
//! # Where randomness and secrets enter
//!
//! `tvc-core` has no entropy source and no environment access by design. This
//! binary is the one place both appear, so the trust boundary is a file you can
//! read rather than a library default you have to take on faith:
//!
//! - Randomness comes from the operating system via `getrandom`, for key
//!   generation and for BIP-340 auxiliary randomness.
//! - The publisher's signing key is read from `TVC_SECRET_KEY`, never from a
//!   flag. Command-line arguments are visible in `ps` output and land in shell
//!   history; an environment variable is merely bad rather than broadcast.
//!
//! # Exit codes
//!
//! `0` on success, `1` on failure. Every verification failure is a non-zero exit
//! with a message naming what failed, so this is usable in a build gate.

mod anchor;
mod audit;
mod hf;
mod reference;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tvc_core::canonical::canonical_digest;
use tvc_core::commitment::{
    commit_weights, commit_weights_with_proof, Quantizer, SchemeCommitment, Tensor,
    WeightCommitment, WeightVector,
};
use tvc_core::documents::{refs_of, validate_document, ObjectStore};
use tvc_core::itemset::ItemSet;
use tvc_core::manifest::WeightsManifest;
use tvc_core::error::TvcError;
use tvc_core::registry::{ModelRegistry, GENESIS_DIGEST};
use tvc_core::signer::{unix_now, DocumentClaim, PublisherKeypair, RegistrationPayload};
use tvc_core::{hex, PROTOCOL_VERSION};

use anchor::{Anchor, AnchorProof, AnchorStatus, NullAnchor, OpenTimestampsCalendar};

/// Environment variable holding the publisher's 32-byte signing key, as hex.
const SECRET_KEY_VAR: &str = "TVC_SECRET_KEY";

#[derive(Parser)]
#[command(
    name = "tvc",
    about = "Weight commitments, publisher attestations, and the public model registry.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a publisher keypair from operating-system randomness.
    Keygen,

    /// Compute the weight commitment C for a model file, without registering it.
    Commit {
        /// Path to a `.safetensors` file.
        #[arg(long)]
        weights: PathBuf,
        /// Fixed-point fractional bits used when quantising.
        #[arg(long, default_value_t = Quantizer::DEFAULT_FRACTIONAL_BITS)]
        fractional_bits: u32,
    },

    /// Commit to a model's weights, sign the claim, and append it to the registry.
    Register {
        /// Path to a `.safetensors` file.
        #[arg(long)]
        weights: PathBuf,
        /// Stable model identifier, for example `meta-llama/Llama-3.2-1B`.
        #[arg(long)]
        model_id: String,
        /// Version string for this release, for example `1.0.0`.
        #[arg(long)]
        version: String,
        /// Path to the registry ledger.
        #[arg(long, default_value = "registry.jsonl")]
        registry: PathBuf,
        /// Fixed-point fractional bits used when quantising.
        #[arg(long, default_value_t = Quantizer::DEFAULT_FRACTIONAL_BITS)]
        fractional_bits: u32,
        /// Proving-system commitment scheme, for example `kzg-bn254/v1`.
        ///
        /// Required together with --proof-commitment. Supply both when the model
        /// is served closed and a circuit will later prove against it.
        #[arg(long, requires = "proof_commitment")]
        proof_scheme: Option<String>,
        /// Proving-system commitment, as lowercase hex.
        #[arg(long, requires = "proof_scheme")]
        proof_commitment: Option<String>,
    },

    /// Print the latest registration for a model.
    Get {
        /// Stable model identifier.
        #[arg(long)]
        model_id: String,
        /// Path to the registry ledger.
        #[arg(long, default_value = "registry.jsonl")]
        registry: PathBuf,
    },

    /// Verify a registration's signature, and optionally the weights behind it.
    Verify {
        /// Stable model identifier.
        #[arg(long)]
        model_id: String,
        /// Path to the registry ledger.
        #[arg(long, default_value = "registry.jsonl")]
        registry: PathBuf,
        /// Publisher x-only public key to pin, as 64 hex characters.
        #[arg(long)]
        publisher: Option<String>,
        /// Recompute C from this `.safetensors` file and compare it.
        #[arg(long)]
        weights: Option<PathBuf>,
        /// Check the registered proving-system commitment instead of the weights.
        ///
        /// This is the closed-model path: it needs no weights, and reports the
        /// circuit identity a proof would have to be verified against.
        #[arg(long)]
        zk: bool,
    },

    /// Re-derive every digest in the ledger and report its head.
    Audit {
        /// Path to the registry ledger.
        #[arg(long, default_value = "registry.jsonl")]
        registry: PathBuf,
    },

    /// Submit the ledger head to the public OpenTimestamps calendar network.
    Anchor {
        /// Path to the registry ledger.
        #[arg(long, default_value = "registry.jsonl")]
        registry: PathBuf,
    },

    /// Check a stored anchor proof, and ask the calendar for an upgrade.
    VerifyAnchor {
        /// Path to the registry ledger.
        #[arg(long, default_value = "registry.jsonl")]
        registry: PathBuf,
        /// Only read the stored proof; do not contact any calendar.
        #[arg(long)]
        offline: bool,
    },

    /// Hash every file in a model directory into a weights manifest.
    Manifest {
        /// The model directory, e.g. a Hugging Face download.
        #[arg(long)]
        dir: PathBuf,
        /// Model name the reference refers to.
        #[arg(long)]
        model: String,
        /// Hugging Face repository the files came from.
        #[arg(long, requires = "hf_commit")]
        hf_repo: Option<String>,
        /// Hugging Face commit (40 hex characters) the files came from.
        #[arg(long, requires = "hf_repo")]
        hf_commit: Option<String>,
        /// Where to write the manifest.
        #[arg(long, default_value = "manifest.json")]
        out: PathBuf,
    },

    /// Check that a directory holds exactly the files a manifest lists.
    VerifyDir {
        /// Path to the manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// The model directory to check.
        #[arg(long)]
        dir: PathBuf,
    },

    /// Compare a manifest with the files Hugging Face publishes at its commit.
    CheckHf {
        /// Path to the manifest.
        #[arg(long)]
        manifest: PathBuf,
    },

    /// Commit to a JSONL file of secret items (prompts or outputs).
    CommitItems {
        /// One JSON value per line.
        #[arg(long)]
        items: PathBuf,
        /// Where to write the private file holding items and salts.
        #[arg(long)]
        private: PathBuf,
    },

    /// Reveal one committed item with its proof.
    Reveal {
        /// The private file written by commit-items.
        #[arg(long)]
        private: PathBuf,
        /// Zero-based index of the item.
        #[arg(long)]
        index: usize,
        /// Where to write the reveal.
        #[arg(long, default_value = "reveal.json")]
        out: PathBuf,
    },

    /// Check a revealed item against a published reference run.
    VerifyReveal {
        /// The reveal file.
        #[arg(long)]
        reveal: PathBuf,
        /// Digest of the reference-run document.
        #[arg(long)]
        run: String,
        /// Which set the item belongs to: prompts or outputs.
        #[arg(long)]
        set: String,
        /// Path to the registry ledger.
        #[arg(long, default_value = "registry.jsonl")]
        registry: PathBuf,
    },

    /// Pick items from a committed set in a way nobody can steer.
    Sample {
        /// Digest of the reference-run document.
        #[arg(long)]
        run: String,
        /// Which set to pick from: prompts or outputs.
        #[arg(long)]
        set: String,
        /// How many to pick.
        #[arg(long)]
        k: u64,
        /// What the selection is for, e.g. an endpoint and a date.
        #[arg(long)]
        context: String,
        /// Path to the registry ledger.
        #[arg(long, default_value = "registry.jsonl")]
        registry: PathBuf,
    },

    /// Sign a document and append its claim to the ledger.
    Publish {
        /// A JSON document with a kind field.
        #[arg(long)]
        doc: PathBuf,
        /// Path to the registry ledger.
        #[arg(long, default_value = "registry.jsonl")]
        registry: PathBuf,
    },

    /// Print a published document and the claim about it.
    Show {
        /// The document's digest.
        #[arg(long)]
        digest: String,
        /// Path to the registry ledger.
        #[arg(long, default_value = "registry.jsonl")]
        registry: PathBuf,
    },

    /// Check a reference profile and everything it cites, check by check.
    ///
    /// Exit codes: 0 every check that ran passed; 2 ledger; 3 profile or
    /// signature; 4 document; 5 weights on disk; 6 anchor.
    VerifyReference {
        /// Digest of the profile document.
        #[arg(long)]
        profile: String,
        /// Publisher x-only public key to pin, as 64 hex characters.
        #[arg(long)]
        publisher: String,
        /// Also re-hash a local copy of the weights against the manifest.
        #[arg(long)]
        weights_dir: Option<PathBuf>,
        /// Print the result as JSON.
        #[arg(long)]
        json: bool,
        /// Path to the registry ledger.
        #[arg(long, default_value = "registry.jsonl")]
        registry: PathBuf,
    },

    /// Print the prompt indices an audit must draw from a battery.
    ///
    /// The indices come from the battery's committed pool and a context built
    /// from the endpoint, the day the window starts, and the battery, so an
    /// auditor cannot choose them.
    AuditDraw {
        /// Digest of the battery document.
        #[arg(long)]
        battery: String,
        /// The audit's endpoint object, as JSON, exactly as the audit records it.
        #[arg(long)]
        endpoint: String,
        /// Window start, `YYYY-MM-DDTHH:MM:SSZ`.
        #[arg(long)]
        start: String,
        /// Path to the registry ledger.
        #[arg(long, default_value = "registry.jsonl")]
        registry: PathBuf,
    },

    /// Check an audit: its calibration came first, its prompts were not
    /// picked, and its verdict follows from its numbers.
    ///
    /// Exit codes: 0 every check that ran passed; 2 ledger; 3 audit or
    /// signature; 4 document or reveal; 6 anchor; 7 order; 8 draw; 9 thresholds
    /// or verdict.
    VerifyAudit {
        /// Digest of the audit document.
        #[arg(long)]
        audit: String,
        /// Publisher x-only public key to pin, as 64 hex characters.
        #[arg(long)]
        publisher: String,
        /// A revealed response or prompt (`tvc reveal` output) to open against the audit.
        #[arg(long)]
        reveal: Vec<PathBuf>,
        /// Print the result as JSON.
        #[arg(long)]
        json: bool,
        /// Path to the registry ledger.
        #[arg(long, default_value = "registry.jsonl")]
        registry: PathBuf,
    },

    /// Publish and check a reference end to end, offline, then try to cheat it.
    Demo {
        /// Directory to write demo artefacts into.
        #[arg(long, default_value = "demo-out")]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Command::VerifyReference {
        profile,
        publisher,
        weights_dir,
        json,
        registry,
    } = &cli.command
    {
        return match reference::verify_reference(
            registry,
            profile,
            publisher,
            weights_dir.as_deref(),
            *json,
        ) {
            Ok(code) => ExitCode::from(code),
            Err(message) => {
                eprintln!("error: {message}");
                ExitCode::FAILURE
            }
        };
    }

    if let Command::VerifyAudit {
        audit,
        publisher,
        reveal,
        json,
        registry,
    } = &cli.command
    {
        return match audit::verify_audit(registry, audit, publisher, reveal, *json) {
            Ok(code) => ExitCode::from(code),
            Err(message) => {
                eprintln!("error: {message}");
                ExitCode::FAILURE
            }
        };
    }

    let outcome = match cli.command {
        Command::Keygen => keygen(),
        Command::Commit {
            weights,
            fractional_bits,
        } => commit(&weights, fractional_bits),
        Command::Register {
            weights,
            model_id,
            version,
            registry,
            fractional_bits,
            proof_scheme,
            proof_commitment,
        } => register(
            &weights,
            &model_id,
            &version,
            &registry,
            fractional_bits,
            proof_scheme.as_deref(),
            proof_commitment.as_deref(),
        ),
        Command::Get { model_id, registry } => get(&model_id, &registry),
        Command::Verify {
            model_id,
            registry,
            publisher,
            weights,
            zk,
        } => verify(
            &model_id,
            &registry,
            publisher.as_deref(),
            weights.as_deref(),
            zk,
        ),
        Command::Audit { registry } => audit(&registry),
        Command::Anchor { registry } => anchor_ledger(&registry),
        Command::VerifyAnchor { registry, offline } => verify_anchor(&registry, offline),
        Command::Manifest {
            dir,
            model,
            hf_repo,
            hf_commit,
            out,
        } => reference::manifest(&dir, &model, hf_repo, hf_commit, &out),
        Command::VerifyDir { manifest, dir } => reference::verify_dir(&manifest, &dir),
        Command::CheckHf { manifest } => reference::check_hf(&manifest),
        Command::CommitItems { items, private } => reference::commit_items(&items, &private),
        Command::Reveal {
            private,
            index,
            out,
        } => reference::reveal(&private, index, &out),
        Command::VerifyReveal {
            reveal,
            run,
            set,
            registry,
        } => reference::verify_reveal(&reveal, &registry, &run, &set),
        Command::Sample {
            run,
            set,
            k,
            context,
            registry,
        } => reference::sample(&registry, &run, &set, k, &context),
        Command::Publish { doc, registry } => reference::publish(&doc, &registry),
        Command::Show { digest, registry } => reference::show(&registry, &digest),
        Command::VerifyReference { .. } | Command::VerifyAudit { .. } => unreachable!("handled above"),
        Command::AuditDraw {
            battery,
            endpoint,
            start,
            registry,
        } => audit::audit_draw(&registry, &battery, &endpoint, &start),
        Command::Demo { out } => demo(&out),
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Fills a buffer from the operating system's randomness source.
fn os_random() -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| format!("could not read operating-system randomness: {error}"))?;
    Ok(bytes)
}

/// Loads the publisher's signing key from the environment.
fn publisher_key() -> Result<PublisherKeypair, String> {
    let raw = std::env::var(SECRET_KEY_VAR).map_err(|_| {
        format!("{SECRET_KEY_VAR} is not set; run `tvc keygen` and export the secret key")
    })?;
    let bytes = hex::decode_array::<32>(raw.trim())
        .map_err(|error| format!("{SECRET_KEY_VAR} must be 64 lowercase hex characters: {error}"))?;
    PublisherKeypair::from_secret_bytes(&bytes).map_err(describe)
}

fn load_weights(path: &Path, fractional_bits: u32) -> Result<WeightVector, String> {
    let quantizer = Quantizer::new(fractional_bits).map_err(describe)?;
    WeightVector::from_safetensors_file(path, quantizer)
        .map_err(|error| format!("{}: {}", path.display(), describe(error)))
}

fn print_commitment(commitment: &WeightCommitment, weights: &WeightVector) {
    println!("  hash scheme        {}", commitment.hash.scheme);
    println!("  tensors            {}", weights.manifest().len());
    println!("  elements           {}", commitment.length);
    println!("  fractional bits    {}", commitment.fractional_bits);
    println!("  manifest digest    {}", hex::encode(&commitment.manifest_digest));
    println!("  hash commitment    {}", commitment.hash.hex());
    match &commitment.proof {
        Some(proof) => {
            println!("  proof scheme       {}", proof.scheme);
            println!("  proof commitment   {}", proof.hex());
        }
        None => println!("  proof commitment   (none registered)"),
    }
    println!("  commitment C       {}", commitment.root_hex());
}

fn keygen() -> Result<(), String> {
    let keypair = PublisherKeypair::generate(&os_random()?).map_err(describe)?;

    println!("Publisher keypair generated.");
    println!();
    println!("  public key   {}", keypair.public_key_hex());
    println!("  secret key   {}", keypair.expose_secret_hex().as_str());
    println!();
    println!("The public key is the publisher's entire identity; publish it freely.");
    println!("The secret key was printed once and is not stored. Put it somewhere safe:");
    println!();
    println!("  export {SECRET_KEY_VAR}={}", keypair.expose_secret_hex().as_str());
    println!();
    println!("Anyone holding it can sign registrations for any model under this identity.");
    Ok(())
}

fn commit(weights_path: &Path, fractional_bits: u32) -> Result<(), String> {
    let weights = load_weights(weights_path, fractional_bits)?;
    let commitment = commit_weights(&weights).map_err(describe)?;

    println!("Weight commitment for {}:", weights_path.display());
    print_commitment(&commitment, &weights);
    Ok(())
}

/// Parses the optional proving-system commitment pair.
fn parse_proof_commitment(
    scheme: Option<&str>,
    bytes: Option<&str>,
) -> Result<Option<SchemeCommitment>, String> {
    match (scheme, bytes) {
        (Some(scheme), Some(bytes)) => {
            let decoded = hex::decode(bytes.trim()).map_err(|error| {
                format!("--proof-commitment must be lowercase hex: {}", describe(error))
            })?;
            if decoded.is_empty() {
                return Err("--proof-commitment must not be empty".to_owned());
            }
            Ok(Some(SchemeCommitment::new(scheme, decoded)))
        }
        (None, None) => Ok(None),
        // clap's `requires` already enforces this; belt and braces.
        _ => Err("--proof-scheme and --proof-commitment must be given together".to_owned()),
    }
}

fn register(
    weights_path: &Path,
    model_id: &str,
    version: &str,
    ledger: &Path,
    fractional_bits: u32,
    proof_scheme: Option<&str>,
    proof_commitment: Option<&str>,
) -> Result<(), String> {
    let keypair = publisher_key()?;
    let proof = parse_proof_commitment(proof_scheme, proof_commitment)?;
    let weights = load_weights(weights_path, fractional_bits)?;
    let commitment = commit_weights_with_proof(&weights, proof).map_err(describe)?;

    let payload =
        RegistrationPayload::new(model_id, version, commitment.clone(), unix_now());
    let attestation = keypair.sign(&payload, &os_random()?).map_err(describe)?;

    let mut registry = ModelRegistry::open(ledger).map_err(describe)?;
    let record = registry.register_signed(attestation).map_err(describe)?;

    println!("Registered {} in {}.", record.address(), ledger.display());
    println!();
    print_commitment(&commitment, &weights);
    println!("  publisher          {}", record.registration.publisher_hex());
    println!("  timestamp          {}", payload.timestamp);
    println!("  sequence           {}", record.sequence);
    println!("  record digest      {}", record.digest_hex());
    println!("  ledger head        {}", registry.head_hex());
    Ok(())
}

fn get(model_id: &str, ledger: &Path) -> Result<(), String> {
    let registry = ModelRegistry::open(ledger).map_err(describe)?;
    let record = registry.get_model_commitment(model_id).map_err(describe)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&record.to_json()).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn verify(
    model_id: &str,
    ledger: &Path,
    publisher: Option<&str>,
    weights_path: Option<&Path>,
    zk: bool,
) -> Result<(), String> {
    let registry = ModelRegistry::open(ledger).map_err(describe)?;

    let record = match publisher {
        Some(text) => {
            let pinned = hex::decode_array::<32>(text.trim()).map_err(|error| {
                format!("--publisher must be 64 lowercase hex characters: {}", describe(error))
            })?;
            registry
                .verify_model_registration_by(model_id, &pinned)
                .map_err(describe)?
        }
        None => registry
            .verify_model_registration_detailed(model_id)
            .map_err(describe)?,
    };

    println!("Signature verified for {}.", record.address());
    println!("  publisher          {}", record.registration.publisher_hex());
    println!("  commitment C       {}", record.weight_commitment().root_hex());
    println!("  record digest      {}", record.digest_hex());

    if publisher.is_none() {
        println!();
        println!("note: no --publisher pinned. This proves somebody signed this claim,");
        println!("      not that the signer is a publisher you trust.");
    }

    if let Some(path) = weights_path {
        let commitment = record.weight_commitment();
        let weights = load_weights(path, commitment.fractional_bits)?;
        registry
            .verify_weights(model_id, record.version(), &weights)
            .map_err(describe)?;
        println!();
        println!("Weights at {} match the registered commitment.", path.display());
    }

    if zk {
        println!();
        match &record.weight_commitment().proof {
            Some(proof) => {
                println!("Proving-system commitment registered:");
                println!("  scheme             {}", proof.scheme);
                println!("  commitment         {}", proof.hex());
                println!("  quantised at       2^-{} fractional bits", record.weight_commitment().fractional_bits);
                println!();
                println!("A circuit proving an inference for this model must prove against");
                println!("this commitment, over weights quantised at that same scale.");
            }
            None => {
                return Err(format!(
                    "{} registered no proving-system commitment; there is nothing for a circuit to bind to",
                    record.address()
                ))
            }
        }
    }

    if weights_path.is_none() && !zk {
        println!();
        println!("note: the signature is all that was checked. It says a key made this");
        println!("      claim, not that any particular weights are behind it. Pass");
        println!("      --weights to re-derive C, or --zk for the closed-model path.");
    }

    Ok(())
}

fn audit(ledger: &Path) -> Result<(), String> {
    let registry = ModelRegistry::open(ledger).map_err(describe)?;
    registry.verify_chain().map_err(describe)?;

    println!("Ledger {} is intact.", ledger.display());
    println!("  records            {}", registry.len());
    println!("  head               {}", registry.head_hex());
    if registry.head() == GENESIS_DIGEST {
        println!("  (empty ledger; head is the genesis digest)");
    }
    println!();
    let mut lines: Vec<(u64, String)> = registry
        .records()
        .iter()
        .map(|record| {
            (
                record.sequence,
                format!(
                    "{:<20} {:<44} C={} by {}",
                    "model-registration",
                    record.address(),
                    &record.weight_commitment().root_hex()[..16],
                    &record.registration.publisher_hex()[..16]
                ),
            )
        })
        .chain(registry.documents().iter().map(|record| {
            (
                record.sequence,
                format!(
                    "{:<20} {:<44} cites {} by {}",
                    record.kind(),
                    hex::encode(&record.document()),
                    record.signed.claim.refs.len(),
                    &hex::encode(&record.signed.signer)[..16]
                ),
            )
        }))
        .collect();
    lines.sort();
    for (sequence, line) in lines {
        println!("  [{sequence}] {line}");
    }
    Ok(())
}

/// Path the anchor proof for `ledger` is stored at: alongside the ledger,
/// always named `registry.head.ots` regardless of the ledger's own filename.
fn anchor_proof_path(ledger: &Path) -> PathBuf {
    match ledger.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join("registry.head.ots"),
        _ => PathBuf::from("registry.head.ots"),
    }
}

/// Directory every anchor proof ever made for `ledger` is kept in, so a later
/// anchor doesn't erase the evidence that an earlier head existed in time.
/// Files are named `<covered sequence>-<head prefix>.ots`.
fn anchors_dir(ledger: &Path) -> PathBuf {
    match ledger.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join("anchors"),
        _ => PathBuf::from("anchors"),
    }
}

/// One stored anchor proof and the last ledger record it covers.
pub(crate) struct StoredAnchor {
    pub path: PathBuf,
    pub covered: u64,
    pub proof: AnchorProof,
}

/// Every anchor proof stored for `ledger`: `registry.head.ots` and everything
/// in `anchors/`, each with the last record it covers, oldest first. A proof
/// that commits to a digest which is not a record of this ledger is skipped.
pub(crate) fn stored_anchors(ledger: &Path, registry: &ModelRegistry) -> Vec<StoredAnchor> {
    let digests = record_digests(registry);
    let mut paths = vec![anchor_proof_path(ledger)];
    if let Ok(entries) = std::fs::read_dir(anchors_dir(ledger)) {
        let mut found: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "ots"))
            .collect();
        found.sort();
        paths.extend(found);
    }
    let mut anchors: Vec<StoredAnchor> = paths
        .into_iter()
        .filter_map(|path| {
            let proof = AnchorProof::from_file(&path).ok()?;
            let committed = proof.committed_digest().ok()?;
            let covered = digests.iter().find(|(_, digest)| digest == &committed)?.0;
            Some(StoredAnchor { path, covered, proof })
        })
        .collect();
    anchors.sort_by_key(|anchor| anchor.covered);
    anchors
}

/// Copies a proof into `anchors/` under its covered sequence, unless one is there.
pub(crate) fn keep_anchor(ledger: &Path, covered: u64, head: &[u8; 32], proof: &AnchorProof) -> Result<PathBuf, String> {
    let dir = anchors_dir(ledger);
    std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let path = dir.join(format!("{covered:06}-{}.ots", &hex::encode(head)[..16]));
    if !path.exists() {
        proof.to_file(&path)?;
    }
    Ok(path)
}

fn anchor_ledger(ledger: &Path) -> Result<(), String> {
    let registry = ModelRegistry::open(ledger).map_err(describe)?;
    let head = registry.head();
    let proof_path = anchor_proof_path(ledger);

    // A proof made before anchor history existed lives only in registry.head.ots.
    // Keep it before that file is overwritten.
    if let Ok(old) = AnchorProof::from_file(&proof_path) {
        if let Ok(committed) = old.committed_digest() {
            if let Some((sequence, _)) = record_digests(&registry).into_iter().find(|(_, d)| d == &committed) {
                keep_anchor(ledger, sequence, &committed, &old)?;
            }
        }
    }

    let proof = OpenTimestampsCalendar::default().stamp(head)?;
    proof.to_file(&proof_path)?;
    let kept = keep_anchor(ledger, registry.len().saturating_sub(1) as u64, &head, &proof)?;

    println!("Submitted the ledger head to the public OpenTimestamps calendar network.");
    println!("  ledger             {}", ledger.display());
    println!("  head               {}", hex::encode(&head));
    println!("  proof              {}", proof_path.display());
    println!("  kept as            {}", kept.display());
    println!();
    println!("A calendar has recorded this commitment. Until it is folded into a Bitcoin");
    println!("block (usually a few hours), that is the calendar operator's word only.");
    println!("`tvc verify-anchor` asks the calendar for the upgraded proof and stores it");
    println!("once it exists.");
    Ok(())
}

/// Every record's (sequence, digest) in ledger order.
fn record_digests(registry: &ModelRegistry) -> Vec<(u64, [u8; 32])> {
    let mut all: Vec<(u64, [u8; 32])> = registry
        .records()
        .iter()
        .map(|r| (r.sequence, r.digest))
        .chain(registry.documents().iter().map(|r| (r.sequence, r.digest)))
        .collect();
    all.sort();
    all
}

fn verify_anchor(ledger: &Path, offline: bool) -> Result<(), String> {
    let registry = ModelRegistry::open(ledger).map_err(describe)?;
    let proof_path = anchor_proof_path(ledger);
    let mut proof = AnchorProof::from_file(&proof_path)
        .map_err(|error| format!("no anchor proof to verify: {error}"))?;

    // The proof may cover an earlier head than today's: the ledger can grow
    // after it was anchored. Say exactly how much of it the proof covers.
    let anchored = proof.committed_digest()?;
    let digests = record_digests(&registry);
    let covered = digests
        .iter()
        .find(|(_, digest)| digest == &anchored)
        .map(|(sequence, _)| *sequence)
        .ok_or_else(|| {
            format!(
                "anchor mismatch: the proof commits to {}, which is not a record in this ledger",
                hex::encode(&anchored)
            )
        })?;

    let calendar = OpenTimestampsCalendar::default();
    let mut status = if proof.is_null() {
        NullAnchor.verify(anchored, &proof)?
    } else {
        calendar.verify(anchored, &proof)?
    };
    let mut upgraded = false;
    if matches!(status, AnchorStatus::Pending { .. }) && !offline {
        if let Some(better) = calendar.upgrade(anchored, &proof)? {
            better.to_file(&proof_path)?;
            proof = better;
            status = calendar.verify(anchored, &proof)?;
            upgraded = true;
        }
    }

    println!("  ledger             {}", ledger.display());
    println!("  anchored head      {}", hex::encode(&anchored));
    println!("  covers records     0 to {covered} of {}", registry.len());
    if (covered as usize) + 1 < registry.len() {
        println!(
            "                     records {} to {} came later and are not covered; run tvc anchor again",
            covered + 1,
            registry.len() - 1
        );
    }
    match status {
        AnchorStatus::Unattested => {
            println!("  status             offline anchor only; no outside party has seen this head");
        }
        AnchorStatus::Pending { calendars } => {
            println!("  status             pending");
            for calendar in calendars {
                println!("  calendar           {calendar}");
            }
            println!();
            if offline {
                println!("note: --offline, so the calendars were not asked for an upgrade.");
            } else {
                println!("note: the calendars have not folded it into a Bitcoin block yet. Try again later.");
            }
        }
        AnchorStatus::BitcoinAttested {
            height,
            merkle_root,
        } => {
            let display: Vec<u8> = merkle_root.iter().rev().copied().collect();
            println!("  status             attested to Bitcoin block {height}");
            println!("  merkle root        {}", hex::encode(&display));
            if upgraded {
                println!("                     (upgraded just now; {} rewritten)", proof_path.display());
            }
            println!();
            println!("This build does not fetch Bitcoin blocks. To finish the check, open block");
            println!("{height} on any block explorer and compare its merkle root with the value above.");
            println!("If they match, the anchored head existed no later than that block's time.");
        }
    }
    verify_anchor_history(ledger, &registry, offline)
}

/// Checks, and upgrades where possible, every proof kept in `anchors/`.
fn verify_anchor_history(ledger: &Path, registry: &ModelRegistry, offline: bool) -> Result<(), String> {
    let calendar = OpenTimestampsCalendar::default();
    let kept: Vec<StoredAnchor> = stored_anchors(ledger, registry)
        .into_iter()
        .filter(|anchor| anchor.path.starts_with(anchors_dir(ledger)))
        .collect();
    if kept.is_empty() {
        return Ok(());
    }
    println!();
    println!("Anchor history ({}):", anchors_dir(ledger).display());
    for anchor in kept {
        let head = anchor.proof.committed_digest()?;
        let mut proof = anchor.proof;
        let mut status = if proof.is_null() {
            NullAnchor.verify(head, &proof)?
        } else {
            calendar.verify(head, &proof)?
        };
        if matches!(status, AnchorStatus::Pending { .. }) && !offline {
            if let Some(better) = calendar.upgrade(head, &proof)? {
                better.to_file(&anchor.path)?;
                proof = better;
                status = calendar.verify(head, &proof)?;
            }
        }
        let label = match status {
            AnchorStatus::Unattested => "offline anchor only".to_owned(),
            AnchorStatus::Pending { .. } => "pending".to_owned(),
            AnchorStatus::BitcoinAttested { height, .. } => format!("Bitcoin block {height}"),
        };
        let name = anchor.path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        println!("  records 0 to {:<5}  {:<34}  {label}", anchor.covered, name);
    }
    Ok(())
}

/// Writes a deterministic safetensors file, standing in for a downloaded model.
///
/// Deterministic so the demo's digests are reproducible and can be compared
/// across machines; the generator is a plain LCG, which is emphatically not a
/// source of cryptographic randomness and is used only to produce plausible
/// weights.
fn write_demo_model(path: &Path, seed: u64, tweak: Option<(usize, f32)>) -> Result<(), String> {
    let mut state = seed;
    let mut next = || {
        state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        ((state >> 33) as f32 / (1u64 << 31) as f32) - 1.0
    };

    let mut attention: Vec<f32> = (0..64).map(|_| next()).collect();
    let mut projection: Vec<f32> = (0..32).map(|_| next()).collect();
    if let Some((index, value)) = tweak {
        if index < attention.len() {
            attention[index] = value;
        } else {
            projection[index - attention.len()] = value;
        }
    }

    let tensors = vec![
        Tensor::from_f32("model.layers.0.attention.weight", vec![8, 8], &attention)
            .map_err(describe)?,
        Tensor::from_f32("model.layers.0.projection.weight", vec![4, 8], &projection)
            .map_err(describe)?,
    ];

    // Assemble the safetensors container: 8-byte little-endian header length,
    // the JSON header, then the concatenated little-endian tensor data.
    let mut header = serde_json::Map::new();
    let mut body = Vec::new();
    for tensor in &tensors {
        let start = body.len();
        body.extend_from_slice(&tensor.data);
        header.insert(
            tensor.name.clone(),
            serde_json::json!({
                "dtype": tensor.dtype.as_str(),
                "shape": tensor.shape,
                "data_offsets": [start, body.len()],
            }),
        );
    }
    let header = serde_json::to_vec(&serde_json::Value::Object(header))
        .map_err(|error| error.to_string())?;

    let mut file = (header.len() as u64).to_le_bytes().to_vec();
    file.extend_from_slice(&header);
    file.extend_from_slice(&body);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::write(path, file).map_err(|error| format!("{}: {error}", path.display()))
}

/// Signs a document, appends its claim to the ledger and stores it beside it.
fn demo_publish(
    registry: &mut ModelRegistry,
    store: &ObjectStore,
    keypair: &PublisherKeypair,
    document: &serde_json::Value,
) -> Result<[u8; 32], String> {
    let kind = document["kind"].as_str().ok_or("document has no kind")?.to_owned();
    let kind_of = |d: &[u8; 32]| registry.get_document(d).map(|r| r.kind().to_owned());
    validate_document(&kind, document, &kind_of).map_err(describe)?;
    let refs = refs_of(&kind, document).map_err(describe)?;
    let digest = canonical_digest(document).map_err(describe)?;
    let claim = DocumentClaim::new(kind.clone(), digest, refs, unix_now());
    let signed = keypair.sign_document(&claim, &os_random()?).map_err(describe)?;
    store.put(document).map_err(describe)?;
    let record = registry.register_document(signed).map_err(describe)?;
    println!("   [{}] {:<20} {}", record.sequence, kind, hex::encode(&digest));
    Ok(digest)
}

fn demo(out: &Path) -> Result<(), String> {
    let model_dir = out.join("model");
    let ledger = out.join("registry.jsonl");
    let store = ObjectStore::beside(&ledger);
    let _ = std::fs::remove_file(&ledger);
    let _ = std::fs::remove_file(anchor_proof_path(&ledger));
    let _ = std::fs::remove_dir_all(store.dir());
    let _ = std::fs::remove_dir_all(&model_dir);

    println!("W-TVC demo: a reference anyone can check ({PROTOCOL_VERSION})");
    println!("Everything runs offline. The model and its outputs are synthetic; the");
    println!("checks are the real ones. Artefacts in {}", out.display());
    println!();

    println!("1. The reference weights: hash every file in the model directory.");
    write_demo_model(&model_dir.join("model.safetensors"), 0x5eed, None)?;
    std::fs::write(model_dir.join("config.json"), b"{\"layers\":1}\n")
        .map_err(|error| error.to_string())?;
    let manifest = WeightsManifest::from_dir(&model_dir, "acme-labs/demo-llm", None, None)
        .map_err(describe)?;
    for file in &manifest.files {
        println!("   {}  {:>6} bytes  {}", &hex::encode(&file.sha256)[..16], file.size, file.path);
    }
    println!();

    println!("2. Publish the reference as four signed records, each citing the one before.");
    let keypair = PublisherKeypair::generate(&os_random()?).map_err(describe)?;
    let mut registry = ModelRegistry::open(&ledger).map_err(describe)?;
    let weights = demo_publish(&mut registry, &store, &keypair, &manifest.to_json())?;
    let setup = demo_publish(
        &mut registry,
        &store,
        &keypair,
        &serde_json::json!({
            "kind": "reference-setup/v1",
            "weights": hex::encode(&weights),
            "engine": "demo",
            "engine_version": "0",
            "dtype": "float32",
            "hardware": "this machine",
            "context_length": 4096,
            "decoding": {"temperature": "0", "seed": "42"},
        }),
    )?;

    // Secret test prompts, and what the reference model said to them. In a
    // real run the outputs come from the model; here they are written by hand.
    let prompts = vec![
        serde_json::json!({"id": 0, "prompt": "What is the capital of Australia?"}),
        serde_json::json!({"id": 1, "prompt": "What is 4821 multiplied by 37?"}),
        serde_json::json!({"id": 2, "prompt": "Repeat exactly: 東京は日本の首都です。"}),
        serde_json::json!({"id": 3, "prompt": "What does <|im_start|> mean to you?"}),
    ];
    let outputs = vec![
        serde_json::json!({"id": 0, "response": "Canberra."}),
        serde_json::json!({"id": 1, "response": "178377"}),
        serde_json::json!({"id": 2, "response": "東京は日本の首都です。"}),
        serde_json::json!({"id": 3, "response": "It looks like a control token."}),
    ];
    let salts = |n: usize| (0..n).map(|_| os_random()).collect::<Result<Vec<_>, _>>();
    let prompt_set = ItemSet::commit(prompts, salts(4)?).map_err(describe)?;
    let output_set = ItemSet::commit(outputs, salts(4)?).map_err(describe)?;
    let run = demo_publish(
        &mut registry,
        &store,
        &keypair,
        &serde_json::json!({
            "kind": "reference-run/v1",
            "setup": hex::encode(&setup),
            "date": "2026-10-04",
            "prompts": {"root": hex::encode(&prompt_set.root().tree_root), "count": 4},
            "outputs": {"root": hex::encode(&output_set.root().tree_root), "count": 4},
            "samples_per_prompt": 1,
            "bands": [],
        }),
    )?;
    let profile = demo_publish(
        &mut registry,
        &store,
        &keypair,
        &serde_json::json!({
            "kind": "profile/v1",
            "model": "acme-labs/demo-llm",
            "version": "0.1",
            "maturity": "working",
            "weights": hex::encode(&weights),
            "runs": [hex::encode(&run)],
        }),
    )?;
    println!("   The prompts and outputs are not published, only their roots.");
    println!();

    println!("3. Timestamp the ledger head. (Offline here, so no outside party sees it;");
    println!("   `tvc anchor` sends it to the public OpenTimestamps calendars instead.)");
    NullAnchor
        .stamp(registry.head())?
        .to_file(&anchor_proof_path(&ledger))?;
    println!();

    println!("4. Check the whole reference as an outsider would, pinning the publisher key.");
    let code = reference::verify_reference(
        &ledger,
        &hex::encode(&profile),
        &keypair.public_key_hex(),
        Some(&model_dir),
        false,
    )?;
    if code != 0 {
        return Err(format!("demo invariant broken: an honest reference failed with code {code}"));
    }
    println!();

    println!("5. A provider disputes a verdict. Reveal the one prompt it is about.");
    let revealed = prompt_set.reveal(1).map_err(describe)?;
    revealed
        .verify(&prompt_set.root().tree_root, 4)
        .map_err(describe)?;
    println!("   prompt 1 opens against the root published in step 2: {}", revealed.item["prompt"]);
    println!("   it was in the set before any check used it; it was not written afterwards.");
    println!();

    println!("6. Now try to cheat, five ways.");
    let refuse = |label: &str, outcome: Result<(), String>| -> Result<(), String> {
        match outcome {
            Err(reason) => {
                println!("   refused  {label}");
                println!("            {reason}");
                Ok(())
            }
            Ok(()) => Err(format!("demo invariant broken: {label} was accepted")),
        }
    };

    let mut easier = revealed.clone();
    easier.item = serde_json::json!({"id": 1, "prompt": "What is 2 plus 2?"});
    refuse(
        "swap in an easier prompt after the fact",
        easier.verify(&prompt_set.root().tree_root, 4).map_err(describe),
    )?;

    let mut moved = revealed.clone();
    moved.index = 2;
    refuse(
        "present prompt 1 as if it were prompt 2",
        moved.verify(&prompt_set.root().tree_root, 4).map_err(describe),
    )?;

    // One weight changed out of 96: the smallest possible substitution.
    write_demo_model(&model_dir.join("model.safetensors"), 0x5eed, Some((7, 0.5)))?;
    refuse(
        "run the reference on weights with one value changed",
        match manifest.verify_dir(&model_dir).map_err(describe)? {
            found if found.is_empty() => Ok(()),
            found => Err(found[0].to_string()),
        },
    )?;
    write_demo_model(&model_dir.join("model.safetensors"), 0x5eed, None)?;

    let late = serde_json::json!({
        "kind": "reference-run/v1",
        "setup": hex::encode(&[0xab; 32]),
        "date": "2026-10-04",
        "prompts": {"root": hex::encode(&[1; 32]), "count": 1},
        "outputs": {"root": hex::encode(&[2; 32]), "count": 1},
        "samples_per_prompt": 1,
        "bands": [],
    });
    let claim = DocumentClaim::new(
        "reference-run/v1",
        canonical_digest(&late).map_err(describe)?,
        vec![[0xab; 32]],
        unix_now(),
    );
    let signed = keypair.sign_document(&claim, &os_random()?).map_err(describe)?;
    refuse(
        "publish a run citing a setup that is not in the ledger yet",
        registry.register_document(signed).map(|_| ()).map_err(describe),
    )?;

    let impostor = PublisherKeypair::generate(&os_random()?).map_err(describe)?;
    let profile_claim = registry.get_document(&profile).ok_or("profile vanished")?;
    refuse(
        "pass off this reference as another publisher's",
        profile_claim
            .signed
            .verify_signed_by(&impostor.public_key())
            .map_err(describe),
    )?;

    println!();
    println!("Done. Look around with:");
    println!("  tvc audit --registry {}", ledger.display());
    println!("  tvc show --digest {} --registry {}", hex::encode(&profile), ledger.display());
    Ok(())
}

/// Renders a core error for the terminal.
fn describe(error: TvcError) -> String {
    error.to_string()
}
