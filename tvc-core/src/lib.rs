//! # W-TVC Protocol — Weight Threshold Verification Ceremony
//!
//! Cryptographic core for proving that an AI inference was served by the model
//! its provider claims, without a hardware TEE, a per-request attestation
//! service, or any trusted party on the runtime path.
//!
//! ## The problem
//!
//! A wallet asking a remote model to authorise a payment has no way to tell which
//! model answered. The provider can silently route the request to a cheaper
//! distillation — *token downgrading* — and bill for the flagship. Today the
//! usual answer is a hardware enclave: trust Intel, AMD, or NVIDIA to vouch for
//! the binary. That replaces a trusted provider with a trusted silicon vendor,
//! and a decade of enclave CVEs makes that a poor trade. It also cannot work for
//! a model served from hardware you do not control.
//!
//! ## The approach
//!
//! Move the trust from silicon to arithmetic, and do the expensive part once.
//!
//! | Phase | When | What happens |
//! |---|---|---|
//! | **Genesis** | Once per model version | A ceremony freezes the circuit's structural parameters into a permanent 32-byte digest, destroys the setup entropy, and publishes a signed commitment to Nostr relays. |
//! | **Runtime** | Every inference | The provider emits a zero-knowledge proof. The wallet fetches the digest from any relay and verifies the proof against it locally. |
//!
//! Groth16's trusted setup depends only on the *shape* of the constraint system,
//! never on a witness. The shape is fixed by the model architecture, so one
//! verifying key covers every inference that model version will ever serve. That
//! is what makes a write-once commitment sufficient and keeps the runtime path
//! free of any authority to ask.
//!
//! ## Module map
//!
//! | Module | Role |
//! |---|---|
//! | [`circuit`] | The committed inference relation as an R1CS. |
//! | [`mpc_setup`] | Phase 1: the ceremony, the transcript, the digest. |
//! | [`crypto_burn`] | Destruction of setup entropy and its attestation. |
//! | [`proof_verifier`] | Phase 2: proving, verification, BIP-340 commitments. |
//! | [`digest`] | BIP-340 tagged hashing and domain separation. |
//! | [`hex`] | Strict lowercase hex codec used on the relay boundary. |
//! | [`error`] | The error taxonomy. |
//!
//! ## What is real and what is scaffolding
//!
//! Honesty about scope is load-bearing for a protocol that asks to be trusted, so
//! this is stated in the code and not only in the README.
//!
//! **Real and exercised by the test suite.** Groth16 setup, proving, and
//! verification over BN254 via `arkworks`. BIP-340 Schnorr signing and
//! verification over secp256k1. Tagged, length-prefixed, domain-separated
//! hashing. The hash-chained ceremony transcript and its tamper checks. Volatile
//! zeroization of setup entropy. The commitment-before-proof verification order,
//! including a test that a validly-proven *substituted* model is rejected.
//!
//! **Scaffolding, with a documented upgrade path.** Two things.
//! [`circuit::InferenceCircuit`] is an affine relation over `Fr`, not a neural
//! network; a production deployment replaces it with a quantised circuit over the
//! real weight tensor. [`mpc_setup::run_ceremony`] aggregates participant entropy
//! on one machine rather than running a Phase-2 MPC, so its honest claim today is
//! "trust the operator, audit the transcript", not 1-of-N. Neither substitution
//! changes any interface downstream of [`mpc_setup::CeremonyOutput`].
//!
//! ## End-to-end example
//!
//! ```
//! use tvc_core::circuit::InferenceCircuit;
//! use tvc_core::mpc_setup::{field_from_u64, run_ceremony, ModelDescriptor, ParticipantContribution};
//! use tvc_core::proof_verifier::{prove_inference, verify_inference, ParameterCommitment};
//!
//! let setup = run_ceremony(
//!     ModelDescriptor::new("acme-llm-7b", "2026.09", "affine-committed-inference", 7_000_000_000),
//!     vec![
//!         ParticipantContribution::new("bitshala", [1u8; 32]),
//!         ParticipantContribution::new("acme-labs", [2u8; 32]),
//!     ],
//! )?;
//!
//! assert!(setup.transcript.verify_chain());
//!
//! let commitment = ParameterCommitment::new(
//!     "acme-llm-7b",
//!     "2026.09",
//!     setup.vk_digest,
//!     setup.transcript.final_digest,
//!     setup.burn.attestation_digest,
//! );
//! let signed = commitment.sign(&[0x11; 32], &[0x22; 32])?;
//! signed.verify()?;
//!
//! let proof = prove_inference(
//!     &setup.proving_key,
//!     field_from_u64(7),
//!     field_from_u64(3),
//!     field_from_u64(11),
//!     [42u8; 32],
//! )?;
//!
//! let report = verify_inference(
//!     &setup.verifying_key,
//!     &signed.commitment.vk_digest,
//!     &proof.public_inputs,
//!     &proof.proof,
//! )?;
//! assert!(report.accepted());
//!
//! let _ = InferenceCircuit::blueprint();
//! # Ok::<(), tvc_core::error::TvcError>(())
//! ```

#![doc(html_root_url = "https://docs.rs/tvc-core/0.1.0")]

pub mod circuit;
pub mod crypto_burn;
pub mod digest;
pub mod error;
pub mod hex;
pub mod mpc_setup;
pub mod proof_verifier;

pub use circuit::{InferenceCircuit, PUBLIC_INPUT_ARITY};
pub use crypto_burn::{BurnAttestation, ToxicWaste};
pub use error::{Result, TvcError};
pub use mpc_setup::{
    derive_vk_digest, field_from_u64, run_ceremony, CeremonyOutput, CeremonyTranscript,
    ContributionRecord, ModelDescriptor, ParticipantContribution, SCHEME_TAG,
};
pub use proof_verifier::{
    prove_inference, verify_inference, InferenceProof, ParameterCommitment, SignedCommitment,
    VerificationReport,
};

/// Semantic version of the protocol this crate implements.
pub const PROTOCOL_VERSION: &str = "w-tvc/1";

/// Nostr event kind carrying a signed parameter commitment.
///
/// Chosen from the addressable range (`30000`–`39999`) defined by NIP-01, so a
/// commitment is addressed by `(kind, pubkey, d)` and a wallet can always resolve
/// the current commitment for a model version without scanning history.
pub const NOSTR_COMMITMENT_KIND: u16 = 30200;
