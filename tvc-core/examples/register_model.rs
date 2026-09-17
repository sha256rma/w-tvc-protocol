//! End-to-end walkthrough of the model setup and registration flow.
//!
//! Run with:
//!
//! ```text
//!   cargo run --example register_model
//! ```
//!
//! Every step below is the same library call a publisher would make; only the
//! weights are synthetic and only the entropy is fixed. Both are called out where
//! they happen.
//!
//! The flow is:
//!
//! 1. Simulate a Hugging Face model and write it as a real `.safetensors` file.
//! 2. Load and quantise it, then compute the weight commitment `C`.
//! 3. Sign `(model_id, version, C, timestamp)` with a publisher keypair.
//! 4. Append the attestation to the append-only registry.
//! 5. Verify the entry: signature, publisher identity, and weights.
//!
//! It closes by substituting a single weight and confirming the registry rejects
//! it, because a setup layer that only demonstrates the happy path demonstrates
//! nothing.

use std::path::{Path, PathBuf};

use tvc_core::commitment::{
    commit_weights, open_weight, verify_weight_opening, Quantizer, Tensor, WeightVector,
};
use tvc_core::registry::{ModelMetadata, ModelRegistry};
use tvc_core::signer::{unix_now, PublisherKeypair, RegistrationPayload};
use tvc_core::{hex, TvcError};

const MODEL_ID: &str = "meta-llama/Llama-3.2-1B";
const VERSION: &str = "1.0.0";

/// Fixed entropy, so this example prints the same keys and digests every run.
///
/// A real publisher generates a key with `tvc keygen`, which reads the operating
/// system's randomness. Anything derived from the constants below is valueless
/// and is published here deliberately.
const DEMO_KEY_ENTROPY: [u8; 32] = [0x11; 32];
const DEMO_AUX_RAND: [u8; 32] = [0x22; 32];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = PathBuf::from("example-out");
    std::fs::create_dir_all(&out)?;
    let ledger = out.join("registry.jsonl");
    let model_path = out.join("llama-3.2-1b.safetensors");
    // Start from an empty ledger so the example is repeatable.
    let _ = std::fs::remove_file(&ledger);

    // ---------------------------------------------------------------------
    // 1. Simulate the model.
    //
    // Two small tensors standing in for a checkpoint, written out in the real
    // safetensors container so step 2 exercises the actual parser rather than an
    // in-memory shortcut.
    // ---------------------------------------------------------------------
    println!("1. Simulating {MODEL_ID}");
    let tensors = vec![
        Tensor::from_f32(
            "model.layers.0.self_attn.q_proj.weight",
            vec![4, 4],
            &synthetic_weights(16, 0x5eed),
        )?,
        Tensor::from_f32(
            "model.layers.0.mlp.down_proj.weight",
            vec![2, 4],
            &synthetic_weights(8, 0xbeef),
        )?,
    ];
    write_safetensors(&model_path, &tensors)?;
    println!("   wrote {}", model_path.display());

    // ---------------------------------------------------------------------
    // 2. Load, quantise, and commit.
    // ---------------------------------------------------------------------
    println!("\n2. Computing the weight commitment");
    let weights = WeightVector::from_safetensors_file(&model_path, Quantizer::default())?;
    let commitment = commit_weights(&weights)?;
    println!("   tensors            {}", weights.manifest().len());
    println!("   weights            {}", weights.len());
    println!("   fractional bits    {}", commitment.fractional_bits);
    println!("   scheme             {}", commitment.scheme);
    println!("   commitment C       {}", commitment.root_hex());

    // ---------------------------------------------------------------------
    // 3. Sign the registration payload.
    // ---------------------------------------------------------------------
    println!("\n3. Signing the registration payload");
    let publisher = PublisherKeypair::generate(&DEMO_KEY_ENTROPY)?;
    let timestamp = unix_now();
    let payload = RegistrationPayload::new(MODEL_ID, VERSION, commitment.clone(), timestamp);
    let attestation = publisher.sign(&payload, &DEMO_AUX_RAND)?;
    println!("   publisher          {}", publisher.public_key_hex());
    println!("   address            {}", payload.address());
    println!(
        "   sighash            {}",
        hex::encode(&payload.sighash(&publisher.public_key()))
    );
    println!("   signature          {}", attestation.signature_hex());

    // ---------------------------------------------------------------------
    // 4. Append to the registry.
    //
    // `register_model` takes the four pieces separately, matching the public API
    // shape. `register_signed(attestation)` is the same thing and cannot pair a
    // payload with the wrong signature by argument order.
    // ---------------------------------------------------------------------
    println!("\n4. Appending to the public registry");
    let mut registry = ModelRegistry::open(&ledger)?;
    let record = registry.register_model(
        ModelMetadata::new(MODEL_ID, VERSION, timestamp),
        commitment.clone(),
        attestation.signature,
        publisher.public_key(),
    )?;
    println!("   ledger             {}", ledger.display());
    println!("   sequence           {}", record.sequence);
    println!("   record digest      {}", record.digest_hex());
    println!("   ledger head        {}", registry.head_hex());

    // ---------------------------------------------------------------------
    // 5. Verify, as a consumer would.
    // ---------------------------------------------------------------------
    println!("\n5. Verifying the registry entry");

    let fetched = registry.get_model_commitment(MODEL_ID)?;
    assert_eq!(fetched.weight_commitment().root, commitment.root);
    println!("   fetched C matches the commitment that was signed");

    assert!(registry.verify_model_registration(MODEL_ID));
    println!("   stored signature verifies against the stored claim");

    registry.verify_model_registration_by(MODEL_ID, &publisher.public_key())?;
    println!("   signature is from the pinned publisher key");

    registry.verify_weights(MODEL_ID, VERSION, &weights)?;
    println!("   weights on disk recommit to the registered C");

    registry.verify_chain()?;
    println!("   ledger hash chain is intact across {} record(s)", registry.len());

    // A commitment is openable: prove one weight without shipping the model.
    let opening = open_weight(&weights, 5)?;
    verify_weight_opening(&commitment, 5, &weights.elements()[5], &opening)?;
    println!(
        "   opening for W[5] = {} verifies in {} step(s)",
        weights.elements()[5].to_hex(),
        opening.siblings.len()
    );

    // ---------------------------------------------------------------------
    // 6. The negative case: one weight changed out of twenty-four.
    // ---------------------------------------------------------------------
    println!("\n6. Substituting the model");
    let mut altered = synthetic_weights(16, 0x5eed);
    altered[5] += 0.001;
    let substituted = WeightVector::from_tensors(
        vec![
            Tensor::from_f32("model.layers.0.self_attn.q_proj.weight", vec![4, 4], &altered)?,
            Tensor::from_f32(
                "model.layers.0.mlp.down_proj.weight",
                vec![2, 4],
                &synthetic_weights(8, 0xbeef),
            )?,
        ],
        Quantizer::default(),
    )?;

    match registry.verify_weights(MODEL_ID, VERSION, &substituted) {
        Err(TvcError::CommitmentMismatch { expected, observed }) => {
            println!("   rejected, as it must be:");
            println!("     registered C     {expected}");
            println!("     substituted C    {observed}");
        }
        other => panic!("substituted weights must be rejected, got {other:?}"),
    }

    println!("\nDone. Ledger written to {}", ledger.display());
    Ok(())
}

/// Deterministic stand-in for trained weights.
///
/// A plain linear congruential generator: reproducible across machines so this
/// example's digests are stable, and emphatically not a source of cryptographic
/// randomness.
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

/// Writes tensors as a safetensors container.
///
/// Layout is an 8-byte little-endian header length, the JSON header describing
/// each tensor's dtype, shape and byte range, then the concatenated data.
fn write_safetensors(path: &Path, tensors: &[Tensor]) -> Result<(), Box<dyn std::error::Error>> {
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

    let header = serde_json::to_vec(&serde_json::Value::Object(header))?;
    let mut file = (header.len() as u64).to_le_bytes().to_vec();
    file.extend_from_slice(&header);
    file.extend_from_slice(&body);
    std::fs::write(path, file)?;
    Ok(())
}
