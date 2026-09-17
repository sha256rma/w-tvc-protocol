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

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tvc_core::commitment::{
    commit_weights, commit_weights_with_proof, open_weight, verify_weight_opening, Quantizer,
    SchemeCommitment, Tensor, WeightCommitment, WeightVector,
};
use tvc_core::error::TvcError;
use tvc_core::registry::{ModelRegistry, GENESIS_DIGEST};
use tvc_core::signer::{unix_now, PublisherKeypair, RegistrationPayload};
use tvc_core::{hex, PROTOCOL_VERSION};

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

    /// Run the full setup flow end to end, including a rejected substitution.
    Demo {
        /// Directory to write demo artefacts into.
        #[arg(long, default_value = "demo-out")]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

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
    for record in registry.records() {
        println!(
            "  [{}] {:<44} C={} by {}",
            record.sequence,
            record.address(),
            &record.weight_commitment().root_hex()[..16],
            &record.registration.publisher_hex()[..16]
        );
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

fn demo(out: &Path) -> Result<(), String> {
    const MODEL_ID: &str = "acme-labs/demo-llm";
    const VERSION: &str = "1.0.0";

    let ledger = out.join("registry.jsonl");
    let honest_path = out.join("honest.safetensors");
    let substituted_path = out.join("substituted.safetensors");
    let _ = std::fs::remove_file(&ledger);

    println!("W-TVC setup demo — {PROTOCOL_VERSION}");
    println!("Artefacts in {}", out.display());
    println!();

    println!("1. Simulate a published model.");
    write_demo_model(&honest_path, 0x5eed, None)?;
    let weights = load_weights(&honest_path, Quantizer::DEFAULT_FRACTIONAL_BITS)?;
    println!("   {} — {} tensors, {} weights", honest_path.display(), weights.manifest().len(), weights.len());
    println!();

    println!("2. Commit to its weights.");
    let commitment = commit_weights(&weights).map_err(describe)?;
    print_commitment(&commitment, &weights);
    println!();

    println!("3. Sign the registration with a publisher keypair.");
    let keypair = PublisherKeypair::generate(&os_random()?).map_err(describe)?;
    let payload = RegistrationPayload::new(MODEL_ID, VERSION, commitment.clone(), unix_now());
    let attestation = keypair.sign(&payload, &os_random()?).map_err(describe)?;
    println!("   publisher          {}", keypair.public_key_hex());
    println!(
        "   sighash            {}",
        hex::encode(&payload.sighash(&keypair.public_key()))
    );
    println!("   signature          {}", attestation.signature_hex());
    println!();

    println!("4. Append it to the public registry.");
    let mut registry = ModelRegistry::open(&ledger).map_err(describe)?;
    let record = registry.register_signed(attestation).map_err(describe)?;
    println!("   {}", ledger.display());
    println!("   sequence           {}", record.sequence);
    println!("   record digest      {}", record.digest_hex());
    println!("   ledger head        {}", registry.head_hex());
    println!();

    println!("5. Verify the entry as a consumer would.");
    registry
        .verify_model_registration_by(MODEL_ID, &keypair.public_key())
        .map_err(describe)?;
    println!("   signature verifies against the pinned publisher key");
    registry
        .verify_weights(MODEL_ID, VERSION, &weights)
        .map_err(describe)?;
    println!("   weights on disk recommit to the registered C");
    registry.verify_chain().map_err(describe)?;
    println!("   ledger hash chain is intact");

    let opening = open_weight(&weights, 7).map_err(describe)?;
    verify_weight_opening(&commitment, 7, &weights.elements()[7], &opening).map_err(describe)?;
    println!(
        "   opening for W[7] = {} verifies in {} steps",
        weights.elements()[7].to_hex(),
        opening.siblings.len()
    );
    println!();

    println!("6. Substitute the model and confirm the registry catches it.");
    // One weight changed out of 96 — the smallest possible downgrade.
    write_demo_model(&substituted_path, 0x5eed, Some((7, 0.5)))?;
    let substituted = load_weights(&substituted_path, Quantizer::DEFAULT_FRACTIONAL_BITS)?;

    match registry.verify_weights(MODEL_ID, VERSION, &substituted) {
        Err(TvcError::CommitmentMismatch { expected, observed }) => {
            println!("   rejected, as it must be:");
            println!("     registered C     {expected}");
            println!("     substituted C    {observed}");
        }
        Err(other) => return Err(format!("demo produced an unexpected failure: {}", describe(other))),
        Ok(_) => {
            return Err("demo invariant broken: substituted weights were accepted".to_owned())
        }
    }

    println!();
    println!("Done. Inspect the ledger with:");
    println!("  tvc audit --registry {}", ledger.display());
    println!("  tvc get --model-id {MODEL_ID} --registry {}", ledger.display());
    Ok(())
}

/// Renders a core error for the terminal.
fn describe(error: TvcError) -> String {
    error.to_string()
}
