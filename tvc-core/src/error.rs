//! Error taxonomy for the model identity layer.
//!
//! Every fallible boundary in this crate returns [`TvcError`]. The variants are
//! coarse at the type level and precise in their payloads, so a verifier can
//! branch on *class* of failure — is this malformed input, or a cryptographic
//! rejection? — without matching on strings.
//!
//! Three distinctions are load-bearing and deliberately not collapsed:
//!
//! - [`TvcError::CommitmentMismatch`] means the weights presented do not hash to
//!   the commitment the registry holds. This is the model-substitution alarm: the
//!   signature may be perfectly valid, but it vouches for different weights.
//! - [`TvcError::AttestationUnsigned`] means the commitment and metadata are
//!   internally consistent but nobody with the claimed key signed them.
//! - [`TvcError::SignerMismatch`] means a *valid* signature was produced by a key
//!   other than the one the caller pinned. Folding this into
//!   `AttestationUnsigned` would let any key vouch for any model, which is no
//!   trust anchor at all.
//!
//! A publisher that swaps weights after registering should trip the first; a
//! relay that republishes someone else's model under its own key should trip the
//! third. Conflating them hides exactly the attacks this layer exists to catch.

use core::fmt;

/// Fallible result specialised to [`TvcError`].
pub type Result<T> = core::result::Result<T, TvcError>;

/// Every failure mode reachable through the public surface of `tvc-core`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TvcError {
    /// A model identifier, version, or publisher name was unsafe to transport.
    InvalidIdentifier {
        /// Which field was rejected.
        field: &'static str,
        /// Why it was rejected.
        reason: String,
    },
    /// A byte string was not valid lowercase hexadecimal of the expected length.
    MalformedHex(String),
    /// A secp256k1 key, signature, or message was structurally invalid.
    Signature(String),
    /// The BIP-340 signature over a registration payload did not verify.
    AttestationUnsigned,
    /// A valid signature was produced by a key other than the pinned one.
    SignerMismatch {
        /// x-only public key the caller pinned, lowercase hex.
        expected: String,
        /// x-only public key that actually signed, lowercase hex.
        observed: String,
    },
    /// Recomputed weight commitment differs from the committed one.
    CommitmentMismatch {
        /// Commitment recorded in the registry.
        expected: String,
        /// Commitment recomputed from the weights supplied.
        observed: String,
    },
    /// A commitment was requested over a weight vector holding no elements.
    EmptyWeights,
    /// A tensor file could not be parsed into tensors.
    MalformedTensorFile(String),
    /// A tensor used an element type this crate does not quantise.
    UnsupportedDtype(String),
    /// A weight fell outside the range the chosen fixed-point scale can encode.
    QuantizationOverflow {
        /// Name of the tensor holding the offending element.
        tensor: String,
        /// The value that could not be represented, already rendered.
        ///
        /// Held as text rather than `f64` deliberately: NaN is one of the values
        /// this variant reports, and `NaN != NaN` would make equality on the
        /// error type quietly useless.
        value: String,
    },
    /// An opening was requested for an index outside the committed vector.
    IndexOutOfRange {
        /// Index requested.
        index: usize,
        /// Number of elements actually committed.
        length: usize,
    },
    /// A Merkle opening did not reproduce the committed root.
    OpeningRejected,
    /// A model version already holds a registration; the ledger is append-only.
    DuplicateRegistration(String),
    /// No registration exists for the requested model.
    UnknownModel(String),
    /// The ledger on disk is not a well-formed append-only record.
    LedgerCorrupt {
        /// One-based line number of the offending record, or 0 for whole-file faults.
        line: usize,
        /// What was wrong with it.
        reason: String,
    },
    /// The ledger's hash chain does not reproduce its recorded head.
    LedgerChainBroken {
        /// One-based line number where the chain first diverges.
        line: usize,
        /// Digest the record claims to extend.
        expected: String,
        /// Digest actually produced by the records before it.
        observed: String,
    },
    /// The registered proving-system commitment is not the expected one.
    ///
    /// Distinct from [`Self::CommitmentMismatch`], which is about the weights
    /// themselves. This one fires when the weights were never in hand — the
    /// closed-model case — and the circuit identity on record is not the one a
    /// verifier was told to expect.
    ProofCommitmentMismatch {
        /// Proving-system commitment the caller pinned, or `none`.
        expected: String,
        /// Proving-system commitment the registry holds, or `none`.
        observed: String,
    },
    /// The ledger file grew since this handle read it, so its view is stale.
    ///
    /// Raised instead of appending, because an append computed against a stale
    /// head would write a duplicate sequence number and fork the hash chain.
    LedgerChangedUnderneath {
        /// Byte length this handle last observed.
        expected: u64,
        /// Byte length found when the append was attempted.
        observed: u64,
    },
    /// An underlying filesystem operation failed.
    Io(String),
    /// A published document is not well formed for its declared kind.
    ///
    /// Raised for anything a third party would read back and act on: a JSON
    /// value that has no canonical encoding, a manifest whose paths could
    /// escape the model directory, a reference record pointing at the wrong
    /// kind of document, or an item reveal that does not open against its root.
    InvalidDocument(String),
}

impl fmt::Display for TvcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier { field, reason } => {
                write!(f, "invalid {field}: {reason}")
            }
            Self::MalformedHex(detail) => write!(f, "malformed hex encoding: {detail}"),
            Self::Signature(detail) => write!(f, "secp256k1 failure: {detail}"),
            Self::AttestationUnsigned => write!(
                f,
                "BIP-340 signature over the registration payload did not verify"
            ),
            Self::SignerMismatch { expected, observed } => write!(
                f,
                "signer mismatch: pinned publisher key {expected}, attestation signed by {observed}"
            ),
            Self::CommitmentMismatch { expected, observed } => write!(
                f,
                "weight commitment mismatch: registry holds {expected}, supplied weights commit to {observed}"
            ),
            Self::EmptyWeights => write!(f, "cannot commit to an empty weight vector"),
            Self::MalformedTensorFile(detail) => write!(f, "malformed tensor file: {detail}"),
            Self::UnsupportedDtype(dtype) => {
                write!(f, "unsupported tensor element type: {dtype}")
            }
            Self::QuantizationOverflow { tensor, value } => write!(
                f,
                "weight {value} in tensor {tensor} exceeds the range of the chosen fixed-point scale"
            ),
            Self::IndexOutOfRange { index, length } => write!(
                f,
                "index {index} is outside the committed vector of {length} elements"
            ),
            Self::OpeningRejected => {
                write!(f, "merkle opening did not reproduce the committed root")
            }
            Self::DuplicateRegistration(address) => write!(
                f,
                "{address} is already registered; the registry is append-only, publish a new version instead"
            ),
            Self::UnknownModel(model_id) => write!(f, "no registration found for {model_id}"),
            Self::LedgerCorrupt { line, reason } => {
                write!(f, "registry ledger corrupt at line {line}: {reason}")
            }
            Self::LedgerChainBroken {
                line,
                expected,
                observed,
            } => write!(
                f,
                "registry ledger hash chain broken at line {line}: record extends {expected}, but the preceding records produce {observed}"
            ),
            Self::ProofCommitmentMismatch { expected, observed } => write!(
                f,
                "proving-system commitment mismatch: expected {expected}, registry holds {observed}"
            ),
            Self::LedgerChangedUnderneath { expected, observed } => write!(
                f,
                "another writer appended to the ledger: it was {expected} bytes when read, {observed} now; reopen the registry and retry"
            ),
            Self::Io(detail) => write!(f, "filesystem failure: {detail}"),
            Self::InvalidDocument(detail) => write!(f, "invalid document: {detail}"),
        }
    }
}

impl std::error::Error for TvcError {}

impl From<secp256k1::Error> for TvcError {
    fn from(value: secp256k1::Error) -> Self {
        Self::Signature(value.to_string())
    }
}

impl From<std::io::Error> for TvcError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}
