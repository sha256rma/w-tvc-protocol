//! End-to-end integration tests for the setup and registration flow.
//!
//! Where the unit tests inside each module check one property in isolation, these
//! drive the whole path a publisher and a consumer actually take — file on disk,
//! commitment, signature, ledger, verification — and assert the failure modes
//! that the flow exists to catch.

use std::path::{Path, PathBuf};

use tvc_core::commitment::{
    commit_weights, commit_weights_with_proof, open_weight, verify_weight_opening, Quantizer,
    SchemeCommitment, Tensor, WeightVector,
};
use tvc_core::registry::{ModelMetadata, ModelRegistry};
use tvc_core::signer::{PublisherKeypair, RegistrationPayload};
use tvc_core::TvcError;

const MODEL_ID: &str = "meta-llama/Llama-3.2-1B";
const VERSION: &str = "1.0.0";
const TIMESTAMP: u64 = 1_760_000_000;

/// A scratch directory that removes itself when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "tvc-e2e-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Deterministic stand-in for trained weights.
fn synthetic_weights(count: usize, seed: u64) -> Vec<f32> {
    let mut state = seed;
    (0..count)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            ((state >> 33) as f32 / (1u64 << 31) as f32) - 1.0
        })
        .collect()
}

fn model_tensors(values: &[f32]) -> Vec<Tensor> {
    vec![
        Tensor::from_f32("model.layers.0.self_attn.q_proj.weight", vec![4, 4], &values[..16])
            .unwrap(),
        Tensor::from_f32("model.layers.0.mlp.down_proj.weight", vec![2, 4], &values[16..24])
            .unwrap(),
    ]
}

/// Writes tensors as a safetensors container, so the loader is exercised for real.
fn write_safetensors(path: &Path, tensors: &[Tensor]) {
    let mut header = serde_json::Map::new();
    let mut body: Vec<u8> = Vec::new();

    for tensor in tensors {
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

    let header = serde_json::to_vec(&serde_json::Value::Object(header)).unwrap();
    let mut file = (header.len() as u64).to_le_bytes().to_vec();
    file.extend_from_slice(&header);
    file.extend_from_slice(&body);
    std::fs::write(path, file).unwrap();
}

fn publisher() -> PublisherKeypair {
    PublisherKeypair::generate(&[0x11; 32]).unwrap()
}

#[test]
fn the_full_setup_flow_registers_and_verifies() {
    let scratch = Scratch::new("full-flow");
    let model_path = scratch.join("model.safetensors");
    let ledger = scratch.join("registry.jsonl");

    // 1. Simulate a Hugging Face model on disk.
    write_safetensors(&model_path, &model_tensors(&synthetic_weights(24, 0x5eed)));

    // 2. Load, quantise, and commit.
    let weights = WeightVector::from_safetensors_file(&model_path, Quantizer::default()).unwrap();
    assert_eq!(weights.len(), 24);
    assert_eq!(weights.manifest().len(), 2);
    let commitment = commit_weights(&weights).unwrap();
    assert!(commitment.is_self_consistent());

    // 3. Sign the registration payload.
    let publisher = publisher();
    let payload = RegistrationPayload::new(MODEL_ID, VERSION, commitment.clone(), TIMESTAMP);
    let attestation = publisher.sign(&payload, &[0x22; 32]).unwrap();
    assert_eq!(attestation.verify(), Ok(()));

    // 4. Append to the registry.
    let mut registry = ModelRegistry::open(&ledger).unwrap();
    let record = registry
        .register_model(
            ModelMetadata::new(MODEL_ID, VERSION, TIMESTAMP),
            commitment.clone(),
            attestation.signature,
            publisher.public_key(),
        )
        .unwrap();
    assert_eq!(record.sequence, 0);
    assert_eq!(registry.head(), record.digest);

    // 5. Verify everything a consumer would.
    let fetched = registry.get_model_commitment(MODEL_ID).unwrap();
    assert_eq!(fetched.weight_commitment().root, commitment.root);
    assert!(registry.verify_model_registration(MODEL_ID));
    assert!(registry
        .verify_model_registration_by(MODEL_ID, &publisher.public_key())
        .is_ok());
    assert!(registry.verify_weights(MODEL_ID, VERSION, &weights).is_ok());
    assert_eq!(registry.verify_chain(), Ok(()));

    // The commitment is openable without shipping the weights.
    let opening = open_weight(&weights, 5).unwrap();
    assert_eq!(
        verify_weight_opening(&commitment, 5, &weights.elements()[5], &opening),
        Ok(())
    );
}

#[test]
fn a_registration_survives_a_process_restart() {
    let scratch = Scratch::new("restart");
    let ledger = scratch.join("registry.jsonl");
    let weights = WeightVector::from_tensors(
        model_tensors(&synthetic_weights(24, 0x5eed)),
        Quantizer::default(),
    )
    .unwrap();
    let commitment = commit_weights(&weights).unwrap();
    let publisher = publisher();

    let (written, head) = {
        let mut registry = ModelRegistry::open(&ledger).unwrap();
        let attestation = publisher
            .sign(
                &RegistrationPayload::new(MODEL_ID, VERSION, commitment.clone(), TIMESTAMP),
                &[0x22; 32],
            )
            .unwrap();
        let record = registry.register_signed(attestation).unwrap();
        (record, registry.head())
    };

    // A second `open` is a cold read: every digest is re-derived from the file.
    let reopened = ModelRegistry::open(&ledger).unwrap();
    assert_eq!(reopened.get_model_commitment(MODEL_ID).unwrap(), written);
    assert_eq!(reopened.head(), head);
    assert!(reopened
        .verify_weights(MODEL_ID, VERSION, &weights)
        .is_ok());
}

#[test]
fn a_single_changed_weight_breaks_the_commitment() {
    let scratch = Scratch::new("substitution");
    let ledger = scratch.join("registry.jsonl");

    let honest = synthetic_weights(24, 0x5eed);
    let weights =
        WeightVector::from_tensors(model_tensors(&honest), Quantizer::default()).unwrap();

    let mut registry = ModelRegistry::open(&ledger).unwrap();
    let publisher = publisher();
    let attestation = publisher
        .sign(
            &RegistrationPayload::new(
                MODEL_ID,
                VERSION,
                commit_weights(&weights).unwrap(),
                TIMESTAMP,
            ),
            &[0x22; 32],
        )
        .unwrap();
    registry.register_signed(attestation).unwrap();

    let mut altered = honest;
    altered[5] += 0.001;
    let substituted =
        WeightVector::from_tensors(model_tensors(&altered), Quantizer::default()).unwrap();

    assert!(matches!(
        registry.verify_weights(MODEL_ID, VERSION, &substituted),
        Err(TvcError::CommitmentMismatch { .. })
    ));
}

#[test]
fn quantisation_absorbs_noise_below_the_committed_scale() {
    // The honest bound on what a registration claims: weights differing by less
    // than half a quantisation step commit identically, by construction.
    let honest = synthetic_weights(24, 0x5eed);
    let baseline =
        WeightVector::from_tensors(model_tensors(&honest), Quantizer::default()).unwrap();

    let mut jittered = honest;
    // A quarter of one step at 16 fractional bits.
    jittered[5] += 0.25 / 65_536.0;
    let jittered =
        WeightVector::from_tensors(model_tensors(&jittered), Quantizer::default()).unwrap();

    assert_eq!(
        commit_weights(&baseline).unwrap().root,
        commit_weights(&jittered).unwrap().root,
        "sub-step noise must not change the commitment"
    );
}

#[test]
fn a_rival_cannot_republish_a_model_under_its_own_key() {
    let scratch = Scratch::new("impersonation");
    let ledger = scratch.join("registry.jsonl");
    let weights = WeightVector::from_tensors(
        model_tensors(&synthetic_weights(24, 0x5eed)),
        Quantizer::default(),
    )
    .unwrap();
    let commitment = commit_weights(&weights).unwrap();

    let genuine = publisher();
    let rival = PublisherKeypair::generate(&[0x99; 32]).unwrap();

    let mut registry = ModelRegistry::open(&ledger).unwrap();

    // The rival registers the same name and the same weights, signed by its key.
    // Nothing stops it: a registry cannot adjudicate who owns a name.
    let rival_attestation = rival
        .sign(
            &RegistrationPayload::new(MODEL_ID, "9.9.9", commitment, TIMESTAMP),
            &[0x33; 32],
        )
        .unwrap();
    registry.register_signed(rival_attestation).unwrap();

    // A bare check passes, which is exactly why a bare check is not enough.
    assert!(registry.verify_model_registration(MODEL_ID));

    // Pinning the genuine publisher's key is what exposes it.
    assert!(matches!(
        registry.verify_model_registration_by(MODEL_ID, &genuine.public_key()),
        Err(TvcError::SignerMismatch { .. })
    ));
}

#[test]
fn a_closed_weights_model_is_verifiable_without_the_weights() {
    // The case the whole dual commitment exists for. A consumer of a closed
    // model never sees W, so the hash half is unavailable to them. What they can
    // check is that the publisher they trust is on record for a specific circuit
    // identity — and that is what a future proof must be verified against.
    let scratch = Scratch::new("closed-weights");
    let ledger = scratch.join("registry.jsonl");

    let weights = WeightVector::from_tensors(
        model_tensors(&synthetic_weights(24, 0x5eed)),
        Quantizer::default(),
    )
    .unwrap();
    // Stands in for the proving system's witness-column commitment. tvc-core
    // does not compute it; it guarantees it is signed for.
    let circuit_commitment = SchemeCommitment::new("kzg-bn254/v1", vec![0x42; 32]);
    let commitment =
        commit_weights_with_proof(&weights, Some(circuit_commitment.clone())).unwrap();

    let publisher = publisher();
    {
        let mut registry = ModelRegistry::open(&ledger).unwrap();
        let payload =
            RegistrationPayload::new(MODEL_ID, VERSION, commitment.clone(), TIMESTAMP);
        registry
            .register_signed(publisher.sign(&payload, &[0x22; 32]).unwrap())
            .unwrap();
    }

    // Everything below is what a consumer can do holding only the ledger and a
    // pinned key. No weights anywhere in this block.
    let registry = ModelRegistry::open(&ledger).unwrap();
    registry
        .verify_model_registration_by(MODEL_ID, &publisher.public_key())
        .unwrap();
    registry
        .verify_proof_commitment(MODEL_ID, VERSION, Some(&circuit_commitment))
        .unwrap();

    // A different circuit identity under the same signature is not possible:
    // the commitment is bound into C, which is bound into the signature.
    assert!(matches!(
        registry.verify_proof_commitment(
            MODEL_ID,
            VERSION,
            Some(&SchemeCommitment::new("kzg-bn254/v1", vec![0x43; 32]))
        ),
        Err(TvcError::ProofCommitmentMismatch { .. })
    ));

    // And the publisher, who does hold W, can still prove the hash half.
    assert!(registry.verify_weights(MODEL_ID, VERSION, &weights).is_ok());
}

#[test]
fn a_tampered_ledger_is_detected_on_reopen() {
    let scratch = Scratch::new("tamper");
    let ledger = scratch.join("registry.jsonl");
    let weights = WeightVector::from_tensors(
        model_tensors(&synthetic_weights(24, 0x5eed)),
        Quantizer::default(),
    )
    .unwrap();
    let publisher = publisher();

    {
        let mut registry = ModelRegistry::open(&ledger).unwrap();
        for version in ["1.0.0", "1.1.0", "2.0.0"] {
            let attestation = publisher
                .sign(
                    &RegistrationPayload::new(
                        MODEL_ID,
                        version,
                        commit_weights(&weights).unwrap(),
                        TIMESTAMP,
                    ),
                    &[0x22; 32],
                )
                .unwrap();
            registry.register_signed(attestation).unwrap();
        }
    }
    assert_eq!(ModelRegistry::open(&ledger).unwrap().len(), 3);

    // Rewrite the middle record's timestamp, leaving its digest as recorded.
    let text = std::fs::read_to_string(&ledger).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let mut wire: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
    wire["timestamp"] = serde_json::json!(TIMESTAMP + 86_400);
    lines[1] = wire.to_string();
    std::fs::write(&ledger, format!("{}\n", lines.join("\n"))).unwrap();

    assert!(matches!(
        ModelRegistry::open(&ledger),
        Err(TvcError::LedgerCorrupt { line: 2, .. })
    ));
}

#[test]
fn the_ledger_is_greppable_json_lines() {
    // The format is part of the contract: an auditor must be able to read the
    // ledger with ordinary tools, not only with this crate.
    let scratch = Scratch::new("format");
    let ledger = scratch.join("registry.jsonl");
    let weights = WeightVector::from_tensors(
        model_tensors(&synthetic_weights(24, 0x5eed)),
        Quantizer::default(),
    )
    .unwrap();
    let publisher = publisher();

    let mut registry = ModelRegistry::open(&ledger).unwrap();
    for version in ["1.0.0", "2.0.0"] {
        let attestation = publisher
            .sign(
                &RegistrationPayload::new(
                    MODEL_ID,
                    version,
                    commit_weights(&weights).unwrap(),
                    TIMESTAMP,
                ),
                &[0x22; 32],
            )
            .unwrap();
        registry.register_signed(attestation).unwrap();
    }

    let text = std::fs::read_to_string(&ledger).unwrap();
    assert_eq!(text.lines().count(), 2);
    for line in text.lines() {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["model_id"], MODEL_ID);
        assert_eq!(value["hash_scheme"], "merkle-sha256/v1");
        assert!(value["weight_commitment"].as_str().unwrap().len() == 64);
    }
}
