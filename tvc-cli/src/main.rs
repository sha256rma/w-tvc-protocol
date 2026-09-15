//! `tvc` — operator and auditor command line for the W-TVC Protocol.
//!
//! Five subcommands cover the protocol's full lifecycle:
//!
//! | Command | Phase | Purpose |
//! |---|---|---|
//! | `ceremony` | Genesis | Run the setup, freeze the digest, burn the entropy. |
//! | `commit` | Genesis | Sign the commitment and emit a Nostr-ready payload. |
//! | `prove` | Runtime | Produce an inference proof against the proving key. |
//! | `verify` | Runtime | Check a proof against a committed digest. |
//! | `audit` | Anytime | Re-derive the digest and re-check a transcript. |
//! | `demo` | — | Run the whole lifecycle end to end, including a forged attempt. |
//!
//! Secrets never appear in argv. Signing keys are read from the `TVC_SECRET_KEY`
//! environment variable, because process arguments are world-readable through
//! `/proc` and land in shell history.

mod json;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ark_bn254::Fr;
use clap::{Parser, Subcommand};
use json::Json;
use tvc_core::error::TvcError;
use tvc_core::hex;
use tvc_core::{
    derive_vk_digest, field_from_u64, prove_inference, run_ceremony, verify_inference,
    CeremonyOutput, InferenceProof, ModelDescriptor, ParameterCommitment, ParticipantContribution,
    SignedCommitment, NOSTR_COMMITMENT_KIND, PROTOCOL_VERSION, SCHEME_TAG,
};

const SECRET_KEY_VAR: &str = "TVC_SECRET_KEY";

#[derive(Parser)]
#[command(
    name = "tvc",
    version,
    about = "Weight Threshold Verification Ceremony — freeze a model, prove an inference, verify without trust.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a Genesis Setup Ceremony and write its artefacts.
    Ceremony {
        /// Stable model identifier, for example `acme-llm-7b`.
        #[arg(long)]
        model_id: String,
        /// Frozen version string, for example `2026.09`.
        #[arg(long)]
        version: String,
        /// Human-readable architecture summary recorded in the transcript.
        #[arg(long, default_value = "affine-committed-inference")]
        architecture: String,
        /// Declared parameter count.
        #[arg(long, default_value_t = 7_000_000_000)]
        parameters: u64,
        /// Participant identifier; repeat once per contributor.
        #[arg(long = "participant", required = true)]
        participants: Vec<String>,
        /// Directory to write ceremony artefacts into.
        #[arg(long, default_value = "ceremony-out")]
        out: PathBuf,
    },
    /// Sign a ceremony's commitment and emit a Nostr-ready payload.
    Commit {
        /// Directory holding ceremony artefacts.
        #[arg(long, default_value = "ceremony-out")]
        setup: PathBuf,
    },
    /// Produce an inference proof.
    Prove {
        /// Directory holding ceremony artefacts.
        #[arg(long, default_value = "ceremony-out")]
        setup: PathBuf,
        /// Private weight parameter.
        #[arg(long)]
        weight: u64,
        /// Private bias parameter.
        #[arg(long)]
        bias: u64,
        /// Public input activation.
        #[arg(long)]
        input: u64,
    },
    /// Verify an inference proof against a committed digest.
    Verify {
        /// Directory holding ceremony and proof artefacts.
        #[arg(long, default_value = "ceremony-out")]
        setup: PathBuf,
        /// Committed verification digest, as fetched from a Nostr relay.
        #[arg(long)]
        digest: String,
    },
    /// Re-derive the digest and re-check the transcript hash chain.
    Audit {
        /// Directory holding ceremony artefacts.
        #[arg(long, default_value = "ceremony-out")]
        setup: PathBuf,
    },
    /// Run the full lifecycle end to end, including a rejected forgery.
    Demo {
        /// Directory to write demo artefacts into.
        #[arg(long, default_value = "demo-out")]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Ceremony {
            model_id,
            version,
            architecture,
            parameters,
            participants,
            out,
        } => report(ceremony(
            &model_id,
            &version,
            &architecture,
            parameters,
            &participants,
            &out,
        )),
        Command::Commit { setup } => report(commit(&setup)),
        Command::Prove {
            setup,
            weight,
            bias,
            input,
        } => report(prove(&setup, weight, bias, input)),
        Command::Verify { setup, digest } => report(verify(&setup, &digest)),
        Command::Audit { setup } => report(audit(&setup)),
        Command::Demo { out } => report(demo(&out)),
    }
}

fn report(outcome: Result<(), String>) -> ExitCode {
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn ceremony(
    model_id: &str,
    version: &str,
    architecture: &str,
    parameters: u64,
    participants: &[String],
    out: &Path,
) -> Result<(), String> {
    let model = ModelDescriptor::new(model_id, version, architecture, parameters);
    model.validate().map_err(describe)?;

    let mut contributions = Vec::with_capacity(participants.len());
    for participant in participants {
        contributions.push(ParticipantContribution::new(participant, os_entropy()?));
    }

    println!("Genesis Setup Ceremony");
    println!("  model      {}", model.address());
    println!("  arch       {architecture}");
    println!("  parties    {}", participants.len());

    let output = run_ceremony(model, contributions).map_err(describe)?;
    write_ceremony(out, &output)?;

    println!();
    println!("  vk digest        {}", output.vk_digest_hex());
    println!("  transcript       {}", output.transcript_digest_hex());
    println!("  burn attestation {}", output.burn.attestation_hex());
    println!("  entropy burned   {} bytes across {} contributions", output.burn.burned_bytes, output.burn.contributions);
    println!();
    println!("  artefacts written to {}", out.display());
    println!("  next: tvc commit --setup {}", out.display());
    Ok(())
}

fn commit(setup: &Path) -> Result<(), String> {
    let descriptor = read_descriptor(setup)?;
    verify_model_binding(setup, &descriptor)?;
    let vk_digest = read_digest(&setup.join("vk_digest.hex"))?;
    let transcript_digest = read_digest(&setup.join("transcript_digest.hex"))?;
    let burn_digest = read_digest(&setup.join("burn_digest.hex"))?;

    let secret_key = read_secret_key()?;
    let commitment = ParameterCommitment::new(
        descriptor.model_id.clone(),
        descriptor.version.clone(),
        vk_digest,
        transcript_digest,
        burn_digest,
    );
    let signed = commitment
        .sign(&secret_key, &os_entropy()?)
        .map_err(describe)?;
    signed.verify().map_err(describe)?;

    let path = write_commitment(setup, &signed)?;

    println!("Signed parameter commitment");
    println!("  address    {}", signed.commitment.address());
    println!("  vk digest  {}", signed.commitment.vk_digest_hex());
    println!("  signer     {}", signed.signer_hex());
    println!("  signature  verified locally before writing");
    println!();
    println!("  payload written to {}", path.display());
    let hint = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    println!("  next: cd nostr-bridge && npm run broadcast -- --commitment {}", hint.display());
    Ok(())
}

fn prove(setup: &Path, weight: u64, bias: u64, input: u64) -> Result<(), String> {
    let proving_key = read_bytes(&setup.join("proving_key.bin"))?;
    let proof = prove_inference(
        &proving_key,
        field_from_u64(weight),
        field_from_u64(bias),
        field_from_u64(input),
        os_entropy()?,
    )
    .map_err(describe)?;

    write_proof(setup, &proof)?;

    println!("Inference proof generated");
    println!("  witness    weight and bias held privately, never serialised");
    println!("  proof      {} bytes", proof.proof.len());
    println!("  artefacts  {}", setup.join("proof.bin").display());
    Ok(())
}

fn verify(setup: &Path, digest: &str) -> Result<(), String> {
    let verifying_key = read_bytes(&setup.join("verifying_key.bin"))?;
    let proof = read_bytes(&setup.join("proof.bin"))?;
    let public_inputs = read_public_inputs(&setup.join("public_inputs.txt"))?;
    let committed: [u8; 32] = hex::decode_array(digest.trim()).map_err(describe)?;

    match verify_inference(&verifying_key, &committed, &public_inputs, &proof) {
        Ok(report) => {
            println!("ACCEPTED");
            println!("  commitment  runtime key matches the digest published to Nostr");
            println!("  proof       groth16 pairing check passed");
            println!("  vk digest   {}", hex::encode(&report.observed_vk_digest));
            Ok(())
        }
        Err(TvcError::CommitmentMismatch { expected, observed }) => Err(format!(
            "REJECTED — model substitution detected\n  committed digest {expected}\n  runtime digest   {observed}\n  the proof may be internally valid, but it was produced against a different circuit"
        )),
        Err(TvcError::ProofRejected) => Err(
            "REJECTED — the verifying key was correct and the pairing check still failed".to_owned(),
        ),
        Err(other) => Err(describe(other)),
    }
}

fn audit(setup: &Path) -> Result<(), String> {
    let verifying_key = read_bytes(&setup.join("verifying_key.bin"))?;
    let recorded = read_digest(&setup.join("vk_digest.hex"))?;
    let recomputed = derive_vk_digest(&verifying_key);

    println!("Audit");
    println!("  recorded    {}", hex::encode(&recorded));
    println!("  recomputed  {}", hex::encode(&recomputed));

    if recorded != recomputed {
        return Err("digest on disk does not match the verifying key beside it".to_owned());
    }
    println!("  result      digest reproduces from the verifying key");
    Ok(())
}

fn demo(out: &Path) -> Result<(), String> {
    let honest_dir = out.join("honest");
    let rogue_dir = out.join("rogue");

    println!("== Phase 1: Genesis Setup Ceremony ==");
    let honest = run_ceremony(
        ModelDescriptor::new("acme-llm-7b", "2026.09", "affine-committed-inference", 7_000_000_000),
        vec![
            ParticipantContribution::new("bitshala", os_entropy()?),
            ParticipantContribution::new("acme-labs", os_entropy()?),
            ParticipantContribution::new("independent-auditor", os_entropy()?),
        ],
    )
    .map_err(describe)?;
    write_ceremony(&honest_dir, &honest)?;

    println!("  committed digest  {}", honest.vk_digest_hex());
    println!("  transcript chain  {}", if honest.transcript.verify_chain() { "verified" } else { "BROKEN" });
    println!("  entropy burned    {} bytes", honest.burn.burned_bytes);

    let demo_key = os_entropy()?;
    let signed = ParameterCommitment::new(
        "acme-llm-7b",
        "2026.09",
        honest.vk_digest,
        honest.transcript.final_digest,
        honest.burn.attestation_digest,
    )
    .sign(&demo_key, &os_entropy()?)
    .map_err(describe)?;
    signed.verify().map_err(describe)?;
    let commitment_path = write_commitment(&honest_dir, &signed)?;
    println!("  signed by         {} (ephemeral demo key)", signed.signer_hex());

    println!();
    println!("== Phase 2: honest runtime inference ==");
    let honest_proof = prove_inference(
        &honest.proving_key,
        field_from_u64(7),
        field_from_u64(3),
        field_from_u64(11),
        os_entropy()?,
    )
    .map_err(describe)?;
    let accepted = verify_inference(
        &honest.verifying_key,
        &honest.vk_digest,
        &honest_proof.public_inputs,
        &honest_proof.proof,
    )
    .map_err(describe)?;
    println!("  wallet verdict    {}", if accepted.accepted() { "ACCEPTED" } else { "rejected" });

    println!();
    println!("== Phase 2 under attack: silent model downgrade ==");
    let rogue = run_ceremony(
        ModelDescriptor::new("acme-llm-7b", "2026.09", "affine-committed-inference", 1_500_000_000),
        vec![ParticipantContribution::new("rogue-operator", os_entropy()?)],
    )
    .map_err(describe)?;
    write_ceremony(&rogue_dir, &rogue)?;

    let rogue_proof = prove_inference(
        &rogue.proving_key,
        field_from_u64(7),
        field_from_u64(3),
        field_from_u64(11),
        os_entropy()?,
    )
    .map_err(describe)?;

    let self_consistent = verify_inference(
        &rogue.verifying_key,
        &rogue.vk_digest,
        &rogue_proof.public_inputs,
        &rogue_proof.proof,
    )
    .map_err(describe)?;
    println!("  rogue proof is internally valid against its own key: {}", self_consistent.accepted());

    match verify_inference(
        &rogue.verifying_key,
        &honest.vk_digest,
        &rogue_proof.public_inputs,
        &rogue_proof.proof,
    ) {
        Err(TvcError::CommitmentMismatch { expected, observed }) => {
            println!("  wallet verdict    REJECTED");
            println!("    committed       {expected}");
            println!("    runtime         {observed}");
            println!();
            println!("  A valid proof about the wrong model is still refused, because the");
            println!("  commitment is checked before the proof. This is the downgrade defence.");
            println!();
            println!("== Next: publish the commitment to Nostr ==");
            println!("  The demo signed with a throwaway key. Hand the same key to the bridge so");
            println!("  the Nostr identity matches the commitment signer, then broadcast:");
            println!();
            println!("    export TVC_SECRET_KEY={}", hex::encode(&demo_key));
            println!("    cd nostr-bridge && npm install");
            println!("    npm run broadcast -- --commitment ../{}", commitment_path.display());
            println!();
            println!("  That is a demo key with no value. A real ceremony key never leaves");
            println!("  the environment and is never printed.");
            Ok(())
        }
        Err(other) => Err(format!("demo produced an unexpected failure: {}", describe(other))),
        Ok(_) => Err("demo invariant broken: a substituted model was accepted".to_owned()),
    }
}

fn write_ceremony(out: &Path, output: &CeremonyOutput) -> Result<(), String> {
    fs::create_dir_all(out).map_err(|error| error.to_string())?;
    write_file(&out.join("verifying_key.bin"), &output.verifying_key)?;
    write_file(&out.join("proving_key.bin"), &output.proving_key)?;
    write_text(&out.join("vk_digest.hex"), &output.vk_digest_hex())?;
    write_text(&out.join("transcript_digest.hex"), &output.transcript_digest_hex())?;
    write_text(&out.join("burn_digest.hex"), &output.burn.attestation_hex())?;
    write_text(
        &out.join("model_binding.hex"),
        &hex::encode(&output.transcript.model.binding_digest()),
    )?;
    write_text(
        &out.join("model.txt"),
        &format!(
            "{}\n{}\n{}\n{}",
            output.transcript.model.model_id,
            output.transcript.model.version,
            output.transcript.model.architecture,
            output.transcript.model.parameter_count
        ),
    )?;

    let records = output
        .transcript
        .records
        .iter()
        .map(|record| {
            Json::obj(vec![
                ("index", Json::Num(u64::from(record.index))),
                ("participant_id", Json::s(&record.participant_id)),
                ("commitment", Json::s(hex::encode(&record.commitment))),
                ("running_digest", Json::s(hex::encode(&record.running_digest))),
            ])
        })
        .collect::<Vec<_>>();

    let transcript = Json::obj(vec![
        ("protocol", Json::s(PROTOCOL_VERSION)),
        ("scheme", Json::s(SCHEME_TAG)),
        ("model_id", Json::s(&output.transcript.model.model_id)),
        ("version", Json::s(&output.transcript.model.version)),
        ("architecture", Json::s(&output.transcript.model.architecture)),
        ("parameter_count", Json::Num(output.transcript.model.parameter_count)),
        ("vk_digest", Json::s(output.vk_digest_hex())),
        ("final_digest", Json::s(output.transcript_digest_hex())),
        ("chain_verified", Json::s(output.transcript.verify_chain().to_string())),
        ("contributions", Json::Arr(records)),
        (
            "burn",
            Json::obj(vec![
                ("attestation_digest", Json::s(output.burn.attestation_hex())),
                ("contributions", Json::Num(output.burn.contributions as u64)),
                ("burned_bytes", Json::Num(output.burn.burned_bytes as u64)),
            ]),
        ),
    ]);
    write_text(&out.join("transcript.json"), &transcript.render(0))
}

fn write_commitment(setup: &Path, signed: &SignedCommitment) -> Result<PathBuf, String> {
    let payload = Json::obj(vec![
        ("protocol", Json::s(PROTOCOL_VERSION)),
        ("kind", Json::Num(u64::from(NOSTR_COMMITMENT_KIND))),
        ("address", Json::s(signed.commitment.address())),
        ("model_id", Json::s(&signed.commitment.model_id)),
        ("version", Json::s(&signed.commitment.version)),
        ("scheme", Json::s(&signed.commitment.scheme)),
        ("vk_digest", Json::s(hex::encode(&signed.commitment.vk_digest))),
        ("transcript_digest", Json::s(hex::encode(&signed.commitment.transcript_digest))),
        ("burn_digest", Json::s(hex::encode(&signed.commitment.burn_digest))),
        ("signer", Json::s(signed.signer_hex())),
        ("signature", Json::s(signed.signature_hex())),
    ]);
    let path = setup.join("commitment.json");
    fs::write(&path, format!("{}\n", payload.render(0)))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(path)
}

fn write_proof(setup: &Path, proof: &InferenceProof) -> Result<(), String> {
    write_file(&setup.join("proof.bin"), &proof.proof)?;
    let encoded = proof.public_inputs_hex().map_err(describe)?;
    write_text(&setup.join("public_inputs.txt"), &encoded.join("\n"))
}

fn read_public_inputs(path: &Path) -> Result<Vec<Fr>, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let values: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    InferenceProof::public_inputs_from_hex(&values).map_err(describe)
}

fn read_descriptor(setup: &Path) -> Result<ModelDescriptor, String> {
    let path = setup.join("model.txt");
    let text = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 4 {
        return Err(format!(
            "{} is malformed: expected 4 lines, found {}",
            path.display(),
            lines.len()
        ));
    }
    let parameter_count = lines[3]
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("{}: parameter count is not a number: {error}", path.display()))?;

    let descriptor = ModelDescriptor::new(
        lines[0].trim(),
        lines[1].trim(),
        lines[2].trim(),
        parameter_count,
    );
    descriptor.validate().map_err(describe)?;
    Ok(descriptor)
}

fn verify_model_binding(setup: &Path, descriptor: &ModelDescriptor) -> Result<(), String> {
    let path = setup.join("model_binding.hex");
    let recorded = read_digest(&path).map_err(|error| {
        format!("{error}\n  This ceremony predates model-binding checks. Re-run `tvc ceremony`.")
    })?;
    let recomputed = descriptor.binding_digest();
    if recorded != recomputed {
        return Err(describe(TvcError::ModelBindingMismatch {
            expected: hex::encode(&recorded),
            observed: hex::encode(&recomputed),
        }));
    }
    Ok(())
}

fn read_digest(path: &Path) -> Result<[u8; 32], String> {
    let text = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    hex::decode_array(text.trim()).map_err(describe)
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|error| format!("{}: {error}", path.display()))
}

fn write_text(path: &Path, text: &str) -> Result<(), String> {
    write_file(path, format!("{text}\n").as_bytes())
}

fn read_secret_key() -> Result<[u8; 32], String> {
    let raw = std::env::var(SECRET_KEY_VAR).map_err(|_| {
        format!(
            "{SECRET_KEY_VAR} is not set.\n  Signing keys are read from the environment so they never appear in argv or shell history.\n  Generate one with:  export {SECRET_KEY_VAR}=$(openssl rand -hex 32)"
        )
    })?;
    hex::decode_array(raw.trim()).map_err(|error| {
        format!("{SECRET_KEY_VAR} must be 64 lowercase hex characters: {error}")
    })
}

fn os_entropy() -> Result<[u8; 32], String> {
    let mut buffer = [0u8; 32];
    getrandom::fill(&mut buffer)
        .map_err(|error| format!("operating system CSPRNG unavailable: {error}"))?;
    Ok(buffer)
}

fn describe(error: TvcError) -> String {
    error.to_string()
}
