//! # W-TVC: signed, checkable records of which model weights were run
//!
//! Two uses share this crate and its ledger.
//!
//! **Reference transparency** (the current focus). A model checker such as
//! SPOT compares endpoints with reference answers from running the real model.
//! [`manifest`], [`itemset`] and [`documents`] let it publish which weight files
//! a reference used, how they were run, and a salted commitment to the secret
//! prompts and outputs, so anyone can check the reference without trusting the
//! checker. See `docs/spec.md` in the repository for the formats.
//!
//! **Weight registration** (earlier work, below). A publisher binds a quantised
//! commitment to its weights to its key, so anyone holding a copy can check it.
//!
//! ## The problem
//!
//! "This is Llama-3.2-1B" is, today, a filename and a README. Nothing connects a
//! set of weights to a claim by a named party, so a mirror can serve a smaller
//! derived model under a flagship name, a fine-tune can be redistributed as the
//! base model, and a consumer has no way to tell. The usual answer is to trust a
//! hosting platform's account system — which works exactly as far as that
//! platform's perimeter, and not one step past it.
//!
//! ## The approach
//!
//! Make the weights themselves the thing that is named, and let a key rather than
//! a platform do the naming.
//!
//! | Stage | What happens |
//! |---|---|
//! | **Commit** | Weight tensors are quantised to a field vector and reduced to a 32-byte commitment `C`. |
//! | **Attest** | The publishing lab signs `(model_id, version, C, timestamp)` with a BIP-340 Schnorr signature. |
//! | **Register** | The signed attestation is appended to a hash-chained, append-only ledger. |
//! | **Verify** | Anyone recomputes `C` from weights in hand and checks the signature against a pinned publisher key. |
//!
//! No step needs a trusted third party at verification time. A consumer needs the
//! ledger, the weights, and the publisher's 32-byte public key.
//!
//! ## Module map
//!
//! | Module | Role |
//! |---|---|
//! | [`canonical`] | Canonical JSON and the plain SHA-256 that names a document. |
//! | [`manifest`] | Per-file SHA-256 manifests of a model directory, and checking a directory against one. |
//! | [`itemset`] | Salted commitments to secret items, single-item reveals, and Fiat-Shamir selection. |
//! | [`documents`] | The four reference document kinds, their validation, and the object store. |
//! | [`commitment`] | Weight loading, quantisation, and `C = Commit(W)`. Split into a scheme layer ([`commitment::VectorCommitment`]) and a protocol layer ([`commitment::WeightCommitment`]). |
//! | [`signer`] | Publisher keys, registration payloads, document claims, BIP-340 signatures. |
//! | [`registry`] | The append-only, hash-chained ledger of registrations (v2) and document claims (v3). |
//! | [`digest`] | BIP-340 tagged hashing and domain separation. |
//! | [`hex`] | Strict lowercase hex codec used on every boundary. |
//! | [`error`] | The error taxonomy. |
//!
//! ## What is real and what is scaffolding
//!
//! Honesty about scope is load-bearing for a protocol that asks to be trusted, so
//! this is stated in the code and not only in the README.
//!
//! **Real, and exercised by the test suite.** BIP-340 Schnorr signing and
//! verification over secp256k1. Tagged, length-prefixed, domain-separated
//! hashing. safetensors parsing with full range validation. Deterministic
//! fixed-point quantisation into the BN254 scalar field. The SHA-256 Merkle
//! vector commitment and its openings, including rejection of an opening moved to
//! another index. The append-only ledger's hash chain and its tamper checks,
//! including detection of edited, deleted and reordered records.
//!
//! **Scaffolding, with a documented upgrade path.** Four things.
//! [`commitment::MerkleVectorCommitment`] is a hash-based vector commitment, not
//! a succinct one; [`commitment::VectorCommitment`] is the seam where KZG or
//! Pedersen goes when openings need to be constant-size, and because `C` is
//! always a tagged hash over the scheme's commitment, swapping the scheme never
//! reaches [`signer`] or [`registry`]. The tree hash is SHA-256, which is
//! expensive to verify inside an arithmetic circuit; a field-native hash is the
//! change that fixes that, deferred until the proving system is chosen. ONNX
//! ingestion is not implemented — [`commitment::Tensor`] is the interface a
//! loader produces, and only safetensors has one today. And the registry is a
//! local file. Its head can be timestamped on Bitcoin with `tvc anchor`, which
//! lives in the CLI because this crate makes no network calls; replicating the
//! ledger itself is not done here.
//!
//! **Bounded by design, not by omission.** Openings are `O(log n)` from a
//! [`commitment::MerkleProver`] but the tree is held in memory, so this phase
//! targets models in the tens of millions of parameters. Streaming and
//! memory-mapped trees are what lift that, and they change no interface here.
//!
//! **Not in this crate at all.** The arithmetic circuit and the proving system.
//! This is the setup layer; a commitment made here is the input a circuit will
//! later read, which is why the weight vector lives in BN254's scalar field.
//!
//! ## End-to-end example
//!
//! ```
//! use tvc_core::commitment::{commit_weights, Quantizer, Tensor, WeightVector};
//! use tvc_core::registry::{ModelMetadata, ModelRegistry};
//! use tvc_core::signer::{PublisherKeypair, RegistrationPayload};
//!
//! # let scratch = std::env::temp_dir().join(format!("tvc-doctest-{}", std::process::id()));
//! # std::fs::create_dir_all(&scratch)?;
//! # let ledger = scratch.join("registry.jsonl");
//! // 1. Load and quantise the weights.
//! let tensor = Tensor::from_f32("layer.0.weight", vec![2, 2], &[0.5, -1.5, 2.0, 0.125])?;
//! let weights = WeightVector::from_tensors(vec![tensor], Quantizer::default())?;
//!
//! // 2. Commit to them.
//! let commitment = commit_weights(&weights)?;
//!
//! // 3. Sign the claim. Both random inputs come from the OS in production.
//! let publisher = PublisherKeypair::generate(&[0x11; 32])?;
//! let payload = RegistrationPayload::new(
//!     "acme-labs/tiny-model",
//!     "1.0.0",
//!     commitment.clone(),
//!     1_760_000_000,
//! );
//! let attestation = publisher.sign(&payload, &[0x22; 32])?;
//!
//! // 4. Append it to the registry.
//! let mut registry = ModelRegistry::open(&ledger)?;
//! let record = registry.register_model(
//!     ModelMetadata::new("acme-labs/tiny-model", "1.0.0", 1_760_000_000),
//!     commitment,
//!     attestation.signature,
//!     publisher.public_key(),
//! )?;
//!
//! // 5. Verify: the signature is the publisher's, and the weights are the ones signed for.
//! registry.verify_model_registration_by("acme-labs/tiny-model", &publisher.public_key())?;
//! registry.verify_weights("acme-labs/tiny-model", "1.0.0", &weights)?;
//! registry.verify_chain()?;
//! assert_eq!(registry.head(), record.digest);
//! # std::fs::remove_dir_all(&scratch)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![doc(html_root_url = "https://docs.rs/tvc-core/0.2.0")]

pub mod canonical;
pub mod commitment;
pub mod digest;
pub mod documents;
pub mod error;
pub mod hex;
pub mod itemset;
pub mod manifest;
pub mod registry;
pub mod signer;

pub use commitment::{
    commit_weights, commit_weights_with_proof, open_weight, verify_weight_opening, Dtype,
    FieldElement, MerkleCommitment, MerkleOpening, MerkleProver, MerkleVectorCommitment, NoParams,
    Quantizer, SchemeCommitment, Tensor, TensorSpec, VectorCommitment, WeightCommitment,
    WeightVector, MERKLE_SCHEME_TAG,
};
pub use error::{Result, TvcError};
pub use itemset::{select, ItemReveal, ItemSet};
pub use manifest::{ManifestFile, ManifestMismatch, WeightsManifest};
pub use registry::{
    DocumentRecord, ModelMetadata, ModelRecord, ModelRegistry, FORMAT_VERSION, GENESIS_DIGEST,
    MODEL_RECORD_VERSION,
};
pub use signer::{
    unix_now, validate_kind, validate_model_id, validate_version, DocumentClaim, PublisherKeypair,
    RegistrationPayload, SignedDocument, SignedRegistration,
};

/// Semantic version of the protocol this crate implements.
pub const PROTOCOL_VERSION: &str = "w-tvc-registry/1";
