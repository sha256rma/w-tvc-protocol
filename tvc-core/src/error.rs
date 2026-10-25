//! Error taxonomy for the ledger and its documents.
//!
//! Every fallible boundary in this crate returns [`TvcError`]. The variants are
//! coarse at the type level and precise in their payloads, so a verifier can
//! branch on *class* of failure (is this malformed input, or a cryptographic
//! rejection?) without matching on strings.
//!
//! Two distinctions are load-bearing and deliberately not collapsed:
//!
//! - [`TvcError::AttestationUnsigned`] means nobody with the claimed key signed
//!   the claim.
//! - [`TvcError::SignerMismatch`] means a *valid* signature was produced by a key
//!   other than the one the caller pinned. Folding this into
//!   `AttestationUnsigned` would let any key vouch for any document, which is no
//!   trust anchor at all.

use core::fmt;

/// Fallible result specialised to [`TvcError`].
pub type Result<T> = core::result::Result<T, TvcError>;

/// Every failure mode reachable through the public surface of `tvc-core`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TvcError {
    /// A document kind or other identifier was unsafe to transport.
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
    /// The BIP-340 signature over a claim did not verify.
    AttestationUnsigned,
    /// A valid signature was produced by a key other than the pinned one.
    SignerMismatch {
        /// x-only public key the caller pinned, lowercase hex.
        expected: String,
        /// x-only public key that actually signed, lowercase hex.
        observed: String,
    },
    /// A Merkle tree was requested over no leaves.
    EmptyTree,
    /// An opening was requested for an index outside the committed tree.
    IndexOutOfRange {
        /// Index requested.
        index: usize,
        /// Number of elements actually committed.
        length: usize,
    },
    /// The document is already in the ledger, which is append-only.
    DuplicateDocument(String),
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
                "BIP-340 signature over the claim did not verify"
            ),
            Self::SignerMismatch { expected, observed } => write!(
                f,
                "signer mismatch: pinned key {expected}, claim signed by {observed}"
            ),
            Self::EmptyTree => write!(f, "cannot build a Merkle tree over no leaves"),
            Self::IndexOutOfRange { index, length } => write!(
                f,
                "index {index} is outside the committed tree of {length} leaves"
            ),
            Self::DuplicateDocument(what) => write!(
                f,
                "{what} is already in the ledger, which is append-only"
            ),
            Self::LedgerCorrupt { line, reason } => {
                write!(f, "ledger corrupt at line {line}: {reason}")
            }
            Self::LedgerChainBroken {
                line,
                expected,
                observed,
            } => write!(
                f,
                "ledger hash chain broken at line {line}: record extends {expected}, but the preceding records produce {observed}"
            ),
            Self::LedgerChangedUnderneath { expected, observed } => write!(
                f,
                "another writer appended to the ledger: it was {expected} bytes when read, {observed} now; reopen the ledger and retry"
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
