//! Error taxonomy for the W-TVC protocol.
//!
//! Every fallible boundary in this crate returns [`TvcError`]. The variants are
//! deliberately coarse at the type level and precise in their payloads so that a
//! verifying wallet can branch on *class* of failure (is this a malformed input
//! or a cryptographic rejection?) without string matching.
//!
//! The distinction that matters operationally is between
//! [`TvcError::CommitmentMismatch`] and [`TvcError::ProofRejected`]:
//!
//! - `CommitmentMismatch` means the verifying key presented at runtime is not the
//!   key that was frozen by the ceremony. This is the model-substitution alarm:
//!   the proof may well be internally valid, but it was produced against a
//!   different circuit than the one the consortium attested to.
//! - `ProofRejected` means the verifying key was correct and the proof still
//!   failed to satisfy the pairing check. This is an invalid-execution alarm.
//!
//! Conflating the two would let a downgrading provider hide a model swap behind a
//! generic "verification failed", so they are kept structurally distinct.

use core::fmt;

/// Fallible result specialised to [`TvcError`].
pub type Result<T> = core::result::Result<T, TvcError>;

/// Every failure mode reachable through the public surface of `tvc-core`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TvcError {
    /// A ceremony was requested with no contributing participants.
    EmptyCeremony,
    /// Two participants presented the same identifier, breaking transcript
    /// auditability because contributions could no longer be attributed.
    DuplicateParticipant(String),
    /// The R1CS constraint system could not be synthesised.
    Synthesis(String),
    /// Canonical serialisation or deserialisation of an arkworks object failed.
    Codec(String),
    /// The runtime verifying key does not hash to the committed digest.
    CommitmentMismatch {
        /// Digest published by the ceremony and fetched from a Nostr relay.
        expected: String,
        /// Digest recomputed from the verifying key supplied at runtime.
        observed: String,
    },
    /// The Groth16 pairing check rejected the proof under a matching key.
    ProofRejected,
    /// A witness assignment was requested from a circuit holding no witness.
    MissingWitness,
    /// A byte string was not valid lowercase hexadecimal of the expected length.
    MalformedHex(String),
    /// A secp256k1 key, signature, or message was structurally invalid.
    Signature(String),
    /// The BIP-340 signature over a parameter commitment did not verify.
    CommitmentUnsigned,
    /// A model identifier contained a character that is unsafe to transport.
    InvalidIdentifier {
        /// Which descriptor field was rejected.
        field: &'static str,
        /// Why it was rejected.
        reason: String,
    },
    /// Ceremony artefacts describe a different model than the one they froze.
    ModelBindingMismatch {
        /// Binding digest recorded by the ceremony.
        expected: String,
        /// Binding digest recomputed from the descriptor read back from disk.
        observed: String,
    },
}

impl fmt::Display for TvcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCeremony => {
                write!(f, "ceremony requires at least one participant contribution")
            }
            Self::DuplicateParticipant(id) => {
                write!(f, "duplicate ceremony participant identifier: {id}")
            }
            Self::Synthesis(detail) => write!(f, "constraint synthesis failed: {detail}"),
            Self::Codec(detail) => write!(f, "canonical codec failure: {detail}"),
            Self::CommitmentMismatch { expected, observed } => write!(
                f,
                "parameter commitment mismatch: committed vk digest {expected}, runtime vk digest {observed}"
            ),
            Self::ProofRejected => {
                write!(f, "groth16 pairing check rejected the inference proof")
            }
            Self::MissingWitness => {
                write!(f, "circuit holds no witness assignment")
            }
            Self::MalformedHex(detail) => write!(f, "malformed hex encoding: {detail}"),
            Self::Signature(detail) => write!(f, "secp256k1 failure: {detail}"),
            Self::CommitmentUnsigned => {
                write!(f, "BIP-340 signature over parameter commitment did not verify")
            }
            Self::InvalidIdentifier { field, reason } => {
                write!(f, "invalid model {field}: {reason}")
            }
            Self::ModelBindingMismatch { expected, observed } => write!(
                f,
                "model binding mismatch: ceremony froze {expected}, descriptor on disk yields {observed}"
            ),
        }
    }
}

impl std::error::Error for TvcError {}

impl From<ark_serialize::SerializationError> for TvcError {
    fn from(value: ark_serialize::SerializationError) -> Self {
        Self::Codec(value.to_string())
    }
}

impl From<ark_relations::r1cs::SynthesisError> for TvcError {
    fn from(value: ark_relations::r1cs::SynthesisError) -> Self {
        Self::Synthesis(value.to_string())
    }
}

impl From<secp256k1::Error> for TvcError {
    fn from(value: secp256k1::Error) -> Self {
        Self::Signature(value.to_string())
    }
}
