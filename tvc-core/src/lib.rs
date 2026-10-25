//! # W-TVC: public, checkable references for open-model inference
//!
//! A model checker such as SPOT decides whether an inference endpoint serves the
//! open-weight model it claims. It compares the endpoint's answers with
//! reference answers from running the official weights, and it calls a
//! difference "altered" only when it lies outside what honest setups of the
//! same model produce. This crate makes each piece of that checkable without
//! trusting the checker:
//!
//! - which weight files a reference ran ([`manifest`]);
//! - how it ran them, and a salted commitment to the secret prompts and outputs
//!   ([`documents`], [`itemset`]);
//! - which honest setups set the thresholds, and the thresholds themselves
//!   ([`documents`]);
//! - which questions an audit drew and how its verdict follows from its numbers
//!   ([`audit`]);
//! - that all of it was published, signed and in order, before the audit
//!   ([`registry`]).
//!
//! See `docs/spec.md` in the repository for the formats.
//!
//! ## Module map
//!
//! | Module | Role |
//! |---|---|
//! | [`canonical`] | Canonical JSON and the plain SHA-256 that names a document. |
//! | [`manifest`] | Per-file SHA-256 manifests of a model directory, and checking a directory against one. |
//! | [`itemset`] | Salted commitments to secret items, single-item reveals, and Fiat-Shamir selection. |
//! | [`merkle`] | The SHA-256 Merkle tree under item sets, with canonical openings. |
//! | [`documents`] | The document kinds (weights, setups, batteries, runs, honest sets, calibrations, audits, profiles), their validation, and the object store. |
//! | [`audit`] | How an audit draws its prompts and reaches its verdict, shared by auditor and verifier. |
//! | [`signer`] | Signing keys, document claims, BIP-340 signatures. |
//! | [`registry`] | The append-only, hash-chained ledger of signed document claims. |
//! | [`digest`] | BIP-340 tagged hashing and domain separation. |
//! | [`hex`] | Strict lowercase hex codec used on every boundary. |
//! | [`error`] | The error taxonomy. |
//!
//! The ledger is a local file. Its head is timestamped on Bitcoin with
//! `tvc anchor`, which lives in the CLI because this crate makes no network
//! calls.
//!
//! ## Example
//!
//! ```
//! use tvc_core::canonical::canonical_digest;
//! use tvc_core::registry::ModelRegistry;
//! use tvc_core::signer::{DocumentClaim, PublisherKeypair};
//!
//! # let scratch = std::env::temp_dir().join(format!("tvc-doctest-{}", std::process::id()));
//! # std::fs::create_dir_all(&scratch)?;
//! # let ledger = scratch.join("registry.jsonl");
//! // A document, named by the SHA-256 of its canonical JSON.
//! let manifest = serde_json::json!({
//!     "kind": "weights-manifest/v1",
//!     "model": "acme-labs/tiny-model",
//!     "files": [{"path": "model.safetensors", "size": 4, "sha256": "00".repeat(32)}],
//! });
//! let digest = canonical_digest(&manifest)?;
//!
//! // Sign a claim about it. Both random inputs come from the OS in production.
//! let publisher = PublisherKeypair::generate(&[0x11; 32])?;
//! let claim = DocumentClaim::new("weights-manifest/v1", digest, vec![], 1_760_000_000);
//! let signed = publisher.sign_document(&claim, &[0x22; 32])?;
//!
//! // Append it to the ledger, and check the chain.
//! let mut registry = ModelRegistry::open(&ledger)?;
//! let record = registry.register_document(signed)?;
//! registry.verify_chain()?;
//! assert_eq!(registry.head(), record.digest);
//! assert_eq!(registry.get_document(&digest).unwrap().signed.signer, publisher.public_key());
//! # std::fs::remove_dir_all(&scratch)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![doc(html_root_url = "https://docs.rs/tvc-core/0.2.0")]

pub mod audit;
pub mod canonical;
pub mod digest;
pub mod documents;
pub mod error;
pub mod hex;
pub mod itemset;
pub mod manifest;
pub mod merkle;
pub mod registry;
pub mod signer;

pub use error::{Result, TvcError};
pub use itemset::{select, ItemReveal, ItemSet};
pub use manifest::{ManifestFile, ManifestMismatch, WeightsManifest};
pub use merkle::{MerkleCommitment, MerkleOpening, MerkleProver};
pub use registry::{DocumentRecord, ModelRegistry, FORMAT_VERSION, GENESIS_DIGEST};
pub use signer::{unix_now, validate_kind, DocumentClaim, PublisherKeypair, SignedDocument};

/// Semantic version of the protocol this crate implements.
pub const PROTOCOL_VERSION: &str = "w-tvc-registry/1";
