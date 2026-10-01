//! The append-only public registry of model registrations.
//!
//! # Storage shape
//!
//! One JSON object per line, appended and never rewritten. The format is chosen
//! for what it makes *hard*, not for elegance: a line-delimited file has no
//! in-place update operation, so the ordinary way to change history is to rewrite
//! the file — a visible act — rather than to `UPDATE ... WHERE`, an invisible one.
//! It also diffs, greps, tails and replicates with tools an auditor already has.
//!
//! SQLite would give transactions and indexes, and is the right answer once this
//! registry serves concurrent writers. It is the wrong answer today: it would put
//! a mutable B-tree under an append-only claim and add a C dependency to a crate
//! whose whole argument is a small auditable surface.
//!
//! # Why a hash chain rather than trust in the file
//!
//! Append-only is a *policy* that the filesystem does not enforce. Anyone with
//! write access can open the ledger and edit a line. So each record carries the
//! digest of the record before it, and its own digest over that link plus every
//! field it asserts. Editing, reordering, or deleting any record changes every
//! digest after it, and [`ModelRegistry::verify_chain`] catches it at the exact
//! line where the divergence starts.
//!
//! This does not make tampering impossible — a determined editor can recompute
//! the whole chain. It makes tampering *detectable by anyone who saw an earlier
//! head*, which is what turns a file into a ledger. Publishing the head digest
//! anywhere append-only, or simply distributing it to consumers, is what closes
//! that gap; this crate is deliberately agnostic about where.
//!
//! # What registration does and does not establish
//!
//! [`ModelRegistry::register_model`] refuses to store an attestation whose
//! signature does not verify, so every record in a well-formed ledger is signed
//! by the key it names. That is the only claim the registry makes. It does not
//! adjudicate *which* key should own a name: two publishers can register the same
//! `model_id` under different keys, exactly as two people can claim a username on
//! two different servers. Consumers resolve that by pinning a key —
//! [`ModelRegistry::verify_model_registration_by`] — not by trusting the
//! registry's ordering.
//!
//! # Concurrency
//!
//! A [`ModelRegistry`] owns an in-memory index and appends through one handle.
//! Single-writer use is the supported mode for this phase, and a second writer is
//! **refused rather than tolerated**: an exclusive advisory lock serialises the
//! append, and under that lock the file's length is compared against what this
//! handle last read.
//!
//! The length check is the part that matters. A record's sequence number and its
//! `previous` digest are computed from in-memory state read earlier, so the lock
//! alone would not help — two processes can each read a ledger of N records,
//! queue on the lock, and append in turn, both claiming sequence N. That fork is
//! silent at write time and only surfaces when somebody later reads the file.
//! Comparing lengths turns it into [`TvcError::LedgerChangedUnderneath`] at the
//! moment it happens, and the loser reopens and retries.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};

use fs2::FileExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::commitment::{commit_weights, SchemeCommitment, WeightCommitment, WeightVector};
use crate::digest::{tagged_hash, DOMAIN_LEDGER_CHAIN, DOMAIN_LEDGER_DOCUMENT};
use crate::error::{Result, TvcError};
use crate::hex;
use crate::signer::{DocumentClaim, RegistrationPayload, SignedDocument, SignedRegistration};

/// Digest the first record in a ledger extends.
pub const GENESIS_DIGEST: [u8; 32] = [0u8; 32];

/// Ledger record format this build writes.
///
/// The version is folded into every record digest, so it cannot be edited after
/// the fact, and it governs how strictly a reader treats what it does not
/// recognise. The split is deliberate:
///
/// - **Unknown *fields* are ignored.** An append-only ledger outlives the code
///   that wrote it, so a v1 reader must not choke on a record a later version
///   enriched with an optional field. Nothing is lost by ignoring them, because
///   the digest and the signature cover the typed fields only — an unknown field
///   is inert by construction and no consumer should ever trust one.
/// - **An unknown *version* is a hard stop.** A future version may compute the
///   digest differently, and a reader that cannot reproduce a digest cannot
///   honestly report the record as verified. Failing loudly beats verifying
///   something other than what was signed.
///
/// One ledger can hold lines of more than one version. Version 3 lines are
/// signed documents ([`DocumentRecord`]). Model registrations are still written
/// as version 2 lines ([`MODEL_RECORD_VERSION`]): their digest construction did
/// not change, and rewriting them would only break ledgers already in use.
pub const FORMAT_VERSION: u32 = 3;

/// Format version a [`ModelRecord`] line is written and read at.
pub const MODEL_RECORD_VERSION: u32 = 2;

/// The metadata half of a registration: who and when, without the commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelMetadata {
    /// Stable model identifier, for example `meta-llama/Llama-3.2-1B`.
    pub model_id: String,
    /// Version string for this release, for example `1.0.0`.
    pub version: String,
    /// Seconds since the Unix epoch at which the publisher made the claim.
    ///
    /// Recorded as asserted. The registry has no way to check a publisher's clock
    /// and does not pretend to: the timestamp is part of what was signed, so it
    /// is exactly as trustworthy as the key that signed it.
    pub timestamp: u64,
}

impl ModelMetadata {
    /// Assembles metadata.
    pub fn new(model_id: impl Into<String>, version: impl Into<String>, timestamp: u64) -> Self {
        Self {
            model_id: model_id.into(),
            version: version.into(),
            timestamp,
        }
    }

    /// Recombines this metadata with a commitment into a signable payload.
    pub fn into_payload(self, weight_commitment: WeightCommitment) -> RegistrationPayload {
        RegistrationPayload::new(
            self.model_id,
            self.version,
            weight_commitment,
            self.timestamp,
        )
    }
}

/// One immutable entry in the registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelRecord {
    /// Record format version, see [`FORMAT_VERSION`].
    pub format_version: u32,
    /// Zero-based position in the ledger.
    pub sequence: u64,
    /// The signed claim this record stores.
    pub registration: SignedRegistration,
    /// Digest of the preceding record, or [`GENESIS_DIGEST`] for the first.
    pub previous: [u8; 32],
    /// Digest over [`Self::previous`] and every field of this record.
    pub digest: [u8; 32],
}

impl ModelRecord {
    /// Stable model identifier.
    pub fn model_id(&self) -> &str {
        &self.registration.payload.model_id
    }

    /// Version string.
    pub fn version(&self) -> &str {
        &self.registration.payload.version
    }

    /// Addressable identity, `<model_id>:<version>`.
    pub fn address(&self) -> String {
        self.registration.payload.address()
    }

    /// The registered weight commitment `C`.
    pub fn weight_commitment(&self) -> &WeightCommitment {
        &self.registration.payload.weight_commitment
    }

    /// The publishing lab's x-only public key.
    pub fn publisher(&self) -> [u8; 32] {
        self.registration.publisher
    }

    /// Lowercase hex rendering of [`Self::digest`].
    pub fn digest_hex(&self) -> String {
        hex::encode(&self.digest)
    }

    /// Recomputes this record's digest from its contents and a preceding digest.
    fn compute_digest(
        format_version: u32,
        sequence: u64,
        previous: &[u8; 32],
        registration: &SignedRegistration,
    ) -> [u8; 32] {
        let payload = &registration.payload;
        let commitment = &payload.weight_commitment;
        let version_bytes = format_version.to_be_bytes();
        let sequence_bytes = sequence.to_be_bytes();
        let timestamp_bytes = payload.timestamp.to_be_bytes();

        let mut parts: Vec<&[u8]> = vec![
            previous,
            &version_bytes,
            &sequence_bytes,
            payload.model_id.as_bytes(),
            payload.version.as_bytes(),
            &commitment.root,
        ];
        let binding = commitment.binding_parts();
        parts.extend(binding.iter().map(Vec::as_slice));
        parts.push(&timestamp_bytes);
        parts.push(&registration.publisher);
        parts.push(&registration.signature);

        tagged_hash(DOMAIN_LEDGER_CHAIN, &parts)
    }

    /// Renders this record as the JSON object the ledger stores.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(WireRecord::from(self)).expect("record is always serialisable")
    }
}

/// On-disk encoding of a [`ModelRecord`].
///
/// Every binary field is lowercase hex, so the ledger stays readable in a
/// terminal and survives any transport that mangles binary. Field names are
/// explicit rather than positional: a ledger outlives the code that wrote it.
///
/// `deny_unknown_fields` is deliberately **not** set — see [`FORMAT_VERSION`]
/// for why. A field this build does not recognise is ignored and contributes
/// nothing to [`ModelRecord::digest`], so it is inert and must never be trusted
/// by anything reading the raw JSON.
#[derive(Serialize, Deserialize)]
struct WireRecord {
    /// Format version, named `v` because it is on every line of every ledger.
    v: u32,
    sequence: u64,
    model_id: String,
    version: String,
    /// The published 32-byte anchor `C`.
    weight_commitment: String,
    /// Scheme of the hash-based commitment, always present.
    hash_scheme: String,
    /// The hash commitment itself; length varies by scheme.
    hash_commitment: String,
    /// Scheme of the proving-system commitment, when one has been chosen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof_scheme: Option<String>,
    /// The proving-system commitment, when one has been chosen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof_commitment: Option<String>,
    length: u64,
    fractional_bits: u32,
    manifest_digest: String,
    timestamp: u64,
    publisher: String,
    signature: String,
    previous: String,
    digest: String,
}

impl From<&ModelRecord> for WireRecord {
    fn from(record: &ModelRecord) -> Self {
        let payload = &record.registration.payload;
        let commitment = &payload.weight_commitment;
        Self {
            v: record.format_version,
            sequence: record.sequence,
            model_id: payload.model_id.clone(),
            version: payload.version.clone(),
            weight_commitment: hex::encode(&commitment.root),
            hash_scheme: commitment.hash.scheme.clone(),
            hash_commitment: commitment.hash.hex(),
            proof_scheme: commitment.proof.as_ref().map(|p| p.scheme.clone()),
            proof_commitment: commitment.proof.as_ref().map(SchemeCommitment::hex),
            length: commitment.length,
            fractional_bits: commitment.fractional_bits,
            manifest_digest: hex::encode(&commitment.manifest_digest),
            timestamp: payload.timestamp,
            publisher: record.registration.publisher_hex(),
            signature: record.registration.signature_hex(),
            previous: hex::encode(&record.previous),
            digest: record.digest_hex(),
        }
    }
}

impl WireRecord {
    /// Rebuilds a record, re-deriving the digest rather than trusting the file.
    fn into_record(self, line: usize) -> Result<ModelRecord> {
        let at = |reason: String| TvcError::LedgerCorrupt { line, reason };
        let field = |name: &str, value: &str| -> Result<[u8; 32]> {
            hex::decode_array::<32>(value)
                .map_err(|error| TvcError::LedgerCorrupt { line, reason: format!("{name}: {error}") })
        };

        if self.v != MODEL_RECORD_VERSION {
            return Err(at(format!(
                "model record format version {} is not {MODEL_RECORD_VERSION}; this build cannot reproduce its digest",
                self.v
            )));
        }

        // A proof commitment is present only when both of its fields are, so a
        // record carrying one without the other is malformed rather than
        // silently treated as absent — absence and presence bind differently.
        let proof = match (self.proof_scheme, self.proof_commitment) {
            (Some(scheme), Some(bytes)) => Some(SchemeCommitment::new(
                scheme,
                hex::decode(&bytes).map_err(|error| at(format!("proof_commitment: {error}")))?,
            )),
            (None, None) => None,
            _ => {
                return Err(at(
                    "proof_scheme and proof_commitment must both be present or both absent"
                        .to_owned(),
                ))
            }
        };

        let registration = SignedRegistration {
            payload: RegistrationPayload::new(
                self.model_id,
                self.version,
                WeightCommitment {
                    root: field("weight_commitment", &self.weight_commitment)?,
                    hash: SchemeCommitment::new(
                        self.hash_scheme,
                        hex::decode(&self.hash_commitment)
                            .map_err(|error| at(format!("hash_commitment: {error}")))?,
                    ),
                    proof,
                    length: self.length,
                    fractional_bits: self.fractional_bits,
                    manifest_digest: field("manifest_digest", &self.manifest_digest)?,
                },
                self.timestamp,
            ),
            signature: hex::decode_array::<64>(&self.signature)
                .map_err(|error| at(format!("signature: {error}")))?,
            publisher: field("publisher", &self.publisher)?,
        };

        let previous = field("previous", &self.previous)?;
        let recorded = field("digest", &self.digest)?;
        let computed = ModelRecord::compute_digest(self.v, self.sequence, &previous, &registration);
        if computed != recorded {
            return Err(at(format!(
                "record digest {} does not match its contents, which hash to {}",
                hex::encode(&recorded),
                hex::encode(&computed)
            )));
        }

        Ok(ModelRecord {
            format_version: self.v,
            sequence: self.sequence,
            registration,
            previous,
            digest: recorded,
        })
    }
}

/// One signed document claim in the ledger.
///
/// The ledger holds the claim (kind, document digest, references, timestamp,
/// signer, signature), never the document itself. Documents are stored beside
/// the ledger, content-addressed, so one can be published later than the claim
/// about it and still be checked against it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentRecord {
    /// Record format version, always [`FORMAT_VERSION`] for documents.
    pub format_version: u32,
    /// Zero-based position in the ledger, shared with model records.
    pub sequence: u64,
    /// The signed claim.
    pub signed: SignedDocument,
    /// Digest of the preceding record of any kind, or [`GENESIS_DIGEST`].
    pub previous: [u8; 32],
    /// Digest over [`Self::previous`] and every field of this record.
    pub digest: [u8; 32],
}

impl DocumentRecord {
    /// Document kind.
    pub fn kind(&self) -> &str {
        &self.signed.claim.kind
    }

    /// SHA-256 of the document's canonical bytes.
    pub fn document(&self) -> [u8; 32] {
        self.signed.claim.document
    }

    /// Lowercase hex rendering of [`Self::digest`].
    pub fn digest_hex(&self) -> String {
        hex::encode(&self.digest)
    }

    fn compute_digest(
        format_version: u32,
        sequence: u64,
        previous: &[u8; 32],
        signed: &SignedDocument,
    ) -> [u8; 32] {
        let claim = &signed.claim;
        let version_bytes = format_version.to_be_bytes();
        let sequence_bytes = sequence.to_be_bytes();
        let reference_count = (claim.refs.len() as u64).to_be_bytes();
        let timestamp_bytes = claim.timestamp.to_be_bytes();
        let mut parts: Vec<&[u8]> = vec![
            previous,
            &version_bytes,
            &sequence_bytes,
            claim.kind.as_bytes(),
            &claim.document,
            &reference_count,
        ];
        parts.extend(claim.refs.iter().map(<[u8; 32]>::as_slice));
        parts.push(&timestamp_bytes);
        parts.push(&signed.signer);
        parts.push(&signed.signature);
        tagged_hash(DOMAIN_LEDGER_DOCUMENT, &parts)
    }

    /// Renders this record as the JSON object the ledger stores.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(WireDocument::from(self)).expect("record is always serialisable")
    }
}

/// On-disk encoding of a [`DocumentRecord`]. Unknown fields are ignored for
/// the same reason as on [`WireRecord`].
#[derive(Serialize, Deserialize)]
struct WireDocument {
    v: u32,
    sequence: u64,
    kind: String,
    document: String,
    refs: Vec<String>,
    timestamp: u64,
    signer: String,
    signature: String,
    previous: String,
    digest: String,
}

impl From<&DocumentRecord> for WireDocument {
    fn from(record: &DocumentRecord) -> Self {
        let claim = &record.signed.claim;
        Self {
            v: record.format_version,
            sequence: record.sequence,
            kind: claim.kind.clone(),
            document: hex::encode(&claim.document),
            refs: claim.refs.iter().map(|r| hex::encode(r)).collect(),
            timestamp: claim.timestamp,
            signer: hex::encode(&record.signed.signer),
            signature: hex::encode(&record.signed.signature),
            previous: hex::encode(&record.previous),
            digest: record.digest_hex(),
        }
    }
}

impl WireDocument {
    fn into_record(self, line: usize) -> Result<DocumentRecord> {
        let at = |reason: String| TvcError::LedgerCorrupt { line, reason };
        let field = |name: &str, value: &str| -> Result<[u8; 32]> {
            hex::decode_array::<32>(value).map_err(|error| at(format!("{name}: {error}")))
        };
        let refs = self
            .refs
            .iter()
            .map(|r| field("refs", r))
            .collect::<Result<Vec<_>>>()?;
        let signed = SignedDocument {
            claim: DocumentClaim::new(self.kind, field("document", &self.document)?, refs, self.timestamp),
            signature: hex::decode_array::<64>(&self.signature)
                .map_err(|error| at(format!("signature: {error}")))?,
            signer: field("signer", &self.signer)?,
        };
        let previous = field("previous", &self.previous)?;
        let recorded = field("digest", &self.digest)?;
        let computed = DocumentRecord::compute_digest(self.v, self.sequence, &previous, &signed);
        if computed != recorded {
            return Err(at(format!(
                "record digest {} does not match its contents, which hash to {}",
                hex::encode(&recorded),
                hex::encode(&computed)
            )));
        }
        Ok(DocumentRecord {
            format_version: self.v,
            sequence: self.sequence,
            signed,
            previous,
            digest: recorded,
        })
    }
}

/// Where a ledger entry lives in the in-memory index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    Model(usize),
    Document(usize),
}

/// An append-only, file-backed ledger of model registrations and signed documents.
#[derive(Debug)]
pub struct ModelRegistry {
    path: PathBuf,
    records: Vec<ModelRecord>,
    documents: Vec<DocumentRecord>,
    /// Every entry, in ledger order.
    order: Vec<Slot>,
    /// Maps a document digest to its position in `documents`.
    by_document: BTreeMap<[u8; 32], usize>,
    /// Maps `<model_id>:<version>` to its position in `records`.
    by_address: BTreeMap<String, usize>,
    /// Byte length of the ledger when this handle last read or wrote it.
    ///
    /// The guard against a lost update. A record's sequence number and its
    /// `previous` digest are both computed from in-memory state, so appending
    /// against a file another process has extended would fork the chain — and
    /// the advisory lock alone does not prevent it, because the read happens in
    /// [`Self::open`] and the write happens here, with the lock held only for the
    /// latter. Comparing the length under the lock closes that window.
    observed_len: u64,
}

impl ModelRegistry {
    /// Opens a ledger, creating it if absent, and verifies it end to end.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::Io`] if the file cannot be opened,
    /// [`TvcError::LedgerCorrupt`] if a line is not a well-formed record, and
    /// [`TvcError::LedgerChainBroken`] if the records do not form one chain.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)?;
        // A shared lock keeps a concurrent appender from landing a partial line
        // in the middle of this read. It is advisory, so it binds only processes
        // that also take it — every writer in this crate does.
        file.lock_shared()?;

        let mut registry = Self {
            path,
            records: Vec::new(),
            documents: Vec::new(),
            order: Vec::new(),
            by_document: BTreeMap::new(),
            by_address: BTreeMap::new(),
            observed_len: 0,
        };

        let mut previous = GENESIS_DIGEST;
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line_number = index + 1;
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let corrupt = |reason: String| TvcError::LedgerCorrupt {
                line: line_number,
                reason,
            };

            let value: serde_json::Value = serde_json::from_str(&line)
                .map_err(|error| corrupt(format!("not a registry record: {error}")))?;
            let version = value
                .get("v")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| corrupt("not a registry record: no format version".to_owned()))?;

            let (sequence, record_previous, digest) = if version == u64::from(FORMAT_VERSION) {
                let wire: WireDocument = serde_json::from_value(value)
                    .map_err(|error| corrupt(format!("not a document record: {error}")))?;
                let record = wire.into_record(line_number)?;
                // A stored claim whose signature no longer verifies, or that
                // points at a document not yet in the ledger, means the file was
                // edited after the fact; refuse to serve it as valid.
                registry
                    .check_document(&record.signed)
                    .map_err(|error| corrupt(format!("stored document claim is invalid: {error}")))?;
                let summary = (record.sequence, record.previous, record.digest);
                registry
                    .by_document
                    .insert(record.document(), registry.documents.len());
                registry.order.push(Slot::Document(registry.documents.len()));
                registry.documents.push(record);
                summary
            } else {
                let wire: WireRecord = serde_json::from_value(value)
                    .map_err(|error| corrupt(format!("not a registry record: {error}")))?;
                let record = wire.into_record(line_number)?;
                record
                    .registration
                    .verify()
                    .map_err(|error| corrupt(format!("stored attestation does not verify: {error}")))?;
                let address = record.address();
                if registry.by_address.contains_key(&address) {
                    return Err(corrupt(format!(
                        "{address} appears twice; the registry is append-only"
                    )));
                }
                let summary = (record.sequence, record.previous, record.digest);
                registry.by_address.insert(address, registry.records.len());
                registry.order.push(Slot::Model(registry.records.len()));
                registry.records.push(record);
                summary
            };

            let expected_sequence = registry.order.len() as u64 - 1;
            if sequence != expected_sequence {
                return Err(corrupt(format!(
                    "sequence {sequence} out of order; expected {expected_sequence}"
                )));
            }
            if record_previous != previous {
                return Err(TvcError::LedgerChainBroken {
                    line: line_number,
                    expected: hex::encode(&record_previous),
                    observed: hex::encode(&previous),
                });
            }
            previous = digest;
        }

        registry.observed_len = std::fs::metadata(&registry.path)?.len();
        Ok(registry)
    }

    /// Appends a registration to the ledger.
    ///
    /// The signature is checked *before* anything is written, so a ledger never
    /// contains an attestation that does not verify. Registration of a
    /// `(model_id, version)` that already exists is refused rather than
    /// overwritten: superseding a release means publishing a new version, which
    /// is what makes the history meaningful.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::AttestationUnsigned`] or [`TvcError::SignerMismatch`]
    /// if the signature does not verify under `public_key`,
    /// [`TvcError::InvalidIdentifier`] for an unsafe field,
    /// [`TvcError::DuplicateRegistration`] if the version is already registered,
    /// and [`TvcError::Io`] if the append fails.
    pub fn register_model(
        &mut self,
        metadata: ModelMetadata,
        commitment: WeightCommitment,
        signature: [u8; 64],
        public_key: [u8; 32],
    ) -> Result<ModelRecord> {
        self.register_signed(SignedRegistration {
            payload: metadata.into_payload(commitment),
            signature,
            publisher: public_key,
        })
    }

    /// Appends an already-assembled [`SignedRegistration`].
    ///
    /// Equivalent to [`Self::register_model`], and preferable at call sites that
    /// already hold the signed bundle: it cannot pair a payload with the wrong
    /// signature by argument order.
    ///
    /// # Errors
    ///
    /// As [`Self::register_model`].
    pub fn register_signed(&mut self, registration: SignedRegistration) -> Result<ModelRecord> {
        registration.verify()?;

        let address = registration.payload.address();
        if self.by_address.contains_key(&address) {
            return Err(TvcError::DuplicateRegistration(address));
        }

        let sequence = self.order.len() as u64;
        let previous = self.head();
        let record = ModelRecord {
            digest: ModelRecord::compute_digest(
                MODEL_RECORD_VERSION,
                sequence,
                &previous,
                &registration,
            ),
            format_version: MODEL_RECORD_VERSION,
            sequence,
            registration,
            previous,
        };

        let line = serde_json::to_string(&WireRecord::from(&record))
            .map_err(|error| TvcError::Io(format!("could not encode record: {error}")))?;
        self.append_line(line)?;

        self.by_address.insert(address, self.records.len());
        self.order.push(Slot::Model(self.records.len()));
        self.records.push(record.clone());
        Ok(record)
    }

    /// Appends a signed document claim to the ledger.
    ///
    /// Checked before anything is written: the signature must verify under the
    /// embedded key, the same document digest must not already be in the
    /// ledger, and every reference must name a document that is already in the
    /// ledger. The last rule is what makes ledger order mean something: a
    /// record can only build on what came before it, so a reference run cannot
    /// cite a setup that was published after it.
    ///
    /// The ledger does not see the document, only its digest. Whether the
    /// document's own fields agree with the claim's references is checked by
    /// whoever holds the document; see `tvc verify-reference`.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::AttestationUnsigned`], [`TvcError::InvalidIdentifier`]
    /// or [`TvcError::InvalidDocument`] for a bad claim,
    /// [`TvcError::DuplicateRegistration`] for a repeated document, and the
    /// append errors of [`Self::register_signed`].
    pub fn register_document(&mut self, signed: SignedDocument) -> Result<DocumentRecord> {
        self.check_document(&signed)?;

        let sequence = self.order.len() as u64;
        let previous = self.head();
        let record = DocumentRecord {
            digest: DocumentRecord::compute_digest(FORMAT_VERSION, sequence, &previous, &signed),
            format_version: FORMAT_VERSION,
            sequence,
            signed,
            previous,
        };
        let line = serde_json::to_string(&WireDocument::from(&record))
            .map_err(|error| TvcError::Io(format!("could not encode record: {error}")))?;
        self.append_line(line)?;

        self.by_document
            .insert(record.document(), self.documents.len());
        self.order.push(Slot::Document(self.documents.len()));
        self.documents.push(record.clone());
        Ok(record)
    }

    /// The rules a document claim must meet against the entries before it.
    fn check_document(&self, signed: &SignedDocument) -> Result<()> {
        signed.verify()?;
        let claim = &signed.claim;
        if self.by_document.contains_key(&claim.document) {
            return Err(TvcError::DuplicateRegistration(format!(
                "document {}",
                hex::encode(&claim.document)
            )));
        }
        for reference in &claim.refs {
            if !self.by_document.contains_key(reference) {
                return Err(TvcError::InvalidDocument(format!(
                    "reference {} is not an earlier document in this ledger",
                    hex::encode(reference)
                )));
            }
        }
        Ok(())
    }

    /// Writes one record line under the exclusive lock, refusing a stale view.
    fn append_line(&mut self, mut line: String) -> Result<()> {
        line.push('\n');
        let mut file = OpenOptions::new().append(true).create(true).open(&self.path)?;
        // An exclusive advisory lock, released by the operating system when this
        // handle drops — including on a crash or a kill, which is why this is an
        // OS lock rather than a sidecar lockfile that would be orphaned.
        file.lock_exclusive()?;
        let outcome = (|| -> Result<u64> {
            // Refuse to append against a stale view. Without this, two processes
            // that both opened the ledger at N records would both write sequence
            // N, and the fork is only discovered on some later read.
            let current = file.metadata()?.len();
            if current != self.observed_len {
                return Err(TvcError::LedgerChangedUnderneath {
                    expected: self.observed_len,
                    observed: current,
                });
            }
            file.write_all(line.as_bytes())?;
            // `flush` on a `File` is a no-op; `sync_all` is what actually reaches
            // the disk. The in-memory index must never claim a record the file
            // does not durably hold, so this is awaited before the record is
            // published to readers.
            file.sync_all()?;
            Ok(current + line.len() as u64)
        })();
        let _ = file.unlock();
        self.observed_len = outcome?;
        Ok(())
    }

    /// Returns the most recent registration for a model identifier.
    ///
    /// "Most recent" is ledger order, not timestamp order: timestamps are
    /// publisher-asserted and a publisher can claim any clock it likes, whereas
    /// ledger order is a fact about what was appended.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::UnknownModel`] if nothing is registered under that
    /// identifier.
    pub fn get_model_commitment(&self, model_id: &str) -> Result<ModelRecord> {
        self.versions(model_id)
            .last()
            .map(|record| (*record).clone())
            .ok_or_else(|| TvcError::UnknownModel(model_id.to_owned()))
    }

    /// Returns one exact `(model_id, version)` registration.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::UnknownModel`] if that version was never registered.
    pub fn get_version(&self, model_id: &str, version: &str) -> Result<ModelRecord> {
        let address = format!("{model_id}:{version}");
        self.by_address
            .get(&address)
            .map(|index| self.records[*index].clone())
            .ok_or(TvcError::UnknownModel(address))
    }

    /// Every registration for a model identifier, in ledger order.
    pub fn versions(&self, model_id: &str) -> Vec<&ModelRecord> {
        self.records
            .iter()
            .filter(|record| record.model_id() == model_id)
            .collect()
    }

    /// Every model registration in the ledger, in order.
    pub fn records(&self) -> &[ModelRecord] {
        &self.records
    }

    /// Every signed document claim in the ledger, in order.
    pub fn documents(&self) -> &[DocumentRecord] {
        &self.documents
    }

    /// The claim about one document, by its digest.
    pub fn get_document(&self, document: &[u8; 32]) -> Option<&DocumentRecord> {
        self.by_document
            .get(document)
            .map(|index| &self.documents[*index])
    }

    /// Digest of the last record, or [`GENESIS_DIGEST`] for an empty ledger.
    ///
    /// This is the value to publish or pin: holding an earlier head is what lets
    /// a consumer detect that history was rewritten underneath them.
    pub fn head(&self) -> [u8; 32] {
        match self.order.last() {
            None => GENESIS_DIGEST,
            Some(Slot::Model(index)) => self.records[*index].digest,
            Some(Slot::Document(index)) => self.documents[*index].digest,
        }
    }

    /// Lowercase hex rendering of [`Self::head`].
    pub fn head_hex(&self) -> String {
        hex::encode(&self.head())
    }

    /// Whether the stored signature validates against the stored metadata and
    /// commitment for the latest registration of `model_id`.
    ///
    /// Returns `false` for an unknown model as well as for a failed check, which
    /// is what the boolean shape can express. Use
    /// [`Self::verify_model_registration_detailed`] when the reason matters.
    pub fn verify_model_registration(&self, model_id: &str) -> bool {
        self.verify_model_registration_detailed(model_id).is_ok()
    }

    /// As [`Self::verify_model_registration`], but reports why it failed.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::UnknownModel`] if nothing is registered, or
    /// [`TvcError::AttestationUnsigned`] if the stored signature does not verify.
    pub fn verify_model_registration_detailed(&self, model_id: &str) -> Result<ModelRecord> {
        let record = self.get_model_commitment(model_id)?;
        record.registration.verify()?;
        Ok(record)
    }

    /// Verifies the latest registration and pins it to an expected publisher key.
    ///
    /// This is the check a consumer actually wants. A bare signature check proves
    /// only that *somebody* signed; it is this call that says the somebody was
    /// the lab whose key you already trust.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::UnknownModel`], [`TvcError::SignerMismatch`], or
    /// [`TvcError::AttestationUnsigned`].
    pub fn verify_model_registration_by(
        &self,
        model_id: &str,
        expected_publisher: &[u8; 32],
    ) -> Result<ModelRecord> {
        let record = self.get_model_commitment(model_id)?;
        record.registration.verify_signed_by(expected_publisher)?;
        Ok(record)
    }

    /// Recommits a weight vector and checks it against a stored registration.
    ///
    /// This is the model-substitution check: a signature proves a lab made a
    /// claim, and this proves the weights in hand are the weights the claim was
    /// about.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::UnknownModel`], or [`TvcError::CommitmentMismatch`]
    /// carrying both commitments when the weights are not the registered ones.
    pub fn verify_weights(
        &self,
        model_id: &str,
        version: &str,
        weights: &WeightVector,
    ) -> Result<ModelRecord> {
        let record = self.get_version(model_id, version)?;
        let registered = record.weight_commitment();
        let recomputed = commit_weights(weights)?;
        // Compare at the *hash* layer, not at `root`. The weights determine the
        // hash commitment and nothing else: `root` also binds the proving-system
        // commitment, which cannot be derived from the weights at all. Comparing
        // roots would make every dual-commitment record fail weight verification
        // even when the weights are exactly right.
        if recomputed.hash != registered.hash || !registered.is_self_consistent() {
            return Err(TvcError::CommitmentMismatch {
                expected: registered.hash.hex(),
                observed: recomputed.hash.hex(),
            });
        }
        Ok(record)
    }

    /// As [`Self::verify_weights`], but also pins the proving-system commitment.
    ///
    /// For a closed-weights model the hash check is unavailable — you do not have
    /// the weights — and this is the call that matters once a proving layer
    /// exists: it confirms the registry holds the proof commitment a circuit is
    /// about to be verified against. Pass `None` to assert that no proving-system
    /// commitment was registered.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::UnknownModel`], [`TvcError::CommitmentMismatch`] if
    /// the weights do not match, or [`TvcError::ProofCommitmentMismatch`] if the
    /// proving-system commitment is not the expected one.
    pub fn verify_weights_with_proof(
        &self,
        model_id: &str,
        version: &str,
        weights: &WeightVector,
        expected_proof: Option<SchemeCommitment>,
    ) -> Result<ModelRecord> {
        let record = self.verify_weights(model_id, version, weights)?;
        self.check_proof_commitment(&record, expected_proof.as_ref())?;
        Ok(record)
    }

    /// Confirms the registered proving-system commitment is the expected one.
    ///
    /// Usable without the weights, which is the point: this is the only half of
    /// the registration a consumer of a closed model can check directly.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::UnknownModel`] or [`TvcError::ProofCommitmentMismatch`].
    pub fn verify_proof_commitment(
        &self,
        model_id: &str,
        version: &str,
        expected: Option<&SchemeCommitment>,
    ) -> Result<ModelRecord> {
        let record = self.get_version(model_id, version)?;
        self.check_proof_commitment(&record, expected)?;
        Ok(record)
    }

    fn check_proof_commitment(
        &self,
        record: &ModelRecord,
        expected: Option<&SchemeCommitment>,
    ) -> Result<()> {
        let describe = |value: Option<&SchemeCommitment>| match value {
            Some(commitment) => format!("{}:{}", commitment.scheme, commitment.hex()),
            None => "none".to_owned(),
        };
        let stored = record.weight_commitment().proof.as_ref();
        if stored != expected {
            return Err(TvcError::ProofCommitmentMismatch {
                expected: describe(expected),
                observed: describe(stored),
            });
        }
        Ok(())
    }

    /// Re-derives every digest in the ledger and confirms the chain is intact.
    ///
    /// [`Self::open`] already performs this check; calling it again is how a
    /// long-lived process confirms nothing edited the file underneath it.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::LedgerChainBroken`] at the first divergent record.
    pub fn verify_chain(&self) -> Result<()> {
        let mut previous = GENESIS_DIGEST;
        for (index, slot) in self.order.iter().enumerate() {
            let line = index + 1;
            let (record_previous, recorded, computed) = match slot {
                Slot::Model(position) => {
                    let record = &self.records[*position];
                    let computed = ModelRecord::compute_digest(
                        record.format_version,
                        record.sequence,
                        &record.previous,
                        &record.registration,
                    );
                    (record.previous, record.digest, computed)
                }
                Slot::Document(position) => {
                    let record = &self.documents[*position];
                    let computed = DocumentRecord::compute_digest(
                        record.format_version,
                        record.sequence,
                        &record.previous,
                        &record.signed,
                    );
                    (record.previous, record.digest, computed)
                }
            };
            if record_previous != previous {
                return Err(TvcError::LedgerChainBroken {
                    line,
                    expected: hex::encode(&record_previous),
                    observed: hex::encode(&previous),
                });
            }
            if computed != recorded {
                return Err(TvcError::LedgerChainBroken {
                    line,
                    expected: hex::encode(&recorded),
                    observed: hex::encode(&computed),
                });
            }
            previous = recorded;
        }
        Ok(())
    }

    /// Flags records dated implausibly far in the future.
    ///
    /// Deliberately **not** part of [`Self::open`], and deliberately not a
    /// monotonicity check. Strict `T_curr >= T_prev` would reject honest records
    /// the moment two publishers with skewed clocks share a ledger; ordering is
    /// already established by the sequence number and the hash chain, which are
    /// facts about what was appended rather than claims about a clock. What a
    /// timestamp is good for is a loose sanity bound, so that is what this is.
    ///
    /// It is a separate call because it depends on the reader's wall clock: a
    /// verification that changes answer with the time of day does not belong in
    /// the path that decides whether a ledger is well formed.
    ///
    /// Returns the sequence numbers of records claiming a time more than
    /// `max_skew_secs` beyond `now`.
    pub fn records_dated_ahead(&self, now: u64, max_skew_secs: u64) -> Vec<u64> {
        let ceiling = now.saturating_add(max_skew_secs);
        self.records
            .iter()
            .filter(|record| record.registration.payload.timestamp > ceiling)
            .map(|record| record.sequence)
            .collect()
    }

    /// Number of records in the ledger, of every kind.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether the ledger holds no records.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Path of the backing file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{commit_weights, Quantizer, Tensor, WeightVector};
    use crate::signer::PublisherKeypair;

    /// A scratch directory that removes itself, so tests leave no residue.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "tvc-registry-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn ledger(&self) -> PathBuf {
            self.0.join("registry.jsonl")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn weights(values: &[f32]) -> WeightVector {
        let tensor = Tensor::from_f32("w", vec![values.len() as u64], values).unwrap();
        WeightVector::from_tensors(vec![tensor], Quantizer::default()).unwrap()
    }

    fn commitment_of(values: &[f32]) -> WeightCommitment {
        commit_weights(&weights(values)).unwrap()
    }

    fn publisher() -> PublisherKeypair {
        PublisherKeypair::generate(&[5u8; 32]).unwrap()
    }

    fn sign(
        keypair: &PublisherKeypair,
        model_id: &str,
        version: &str,
        commitment: WeightCommitment,
    ) -> SignedRegistration {
        let payload = RegistrationPayload::new(model_id, version, commitment, 1_760_000_000);
        keypair.sign(&payload, &[1u8; 32]).unwrap()
    }

    #[test]
    fn a_registration_round_trips_through_the_ledger() {
        let scratch = Scratch::new("roundtrip");
        let keypair = publisher();
        let commitment = commitment_of(&[1.0, 2.0, 3.0]);

        let written = {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            registry
                .register_model(
                    ModelMetadata::new("meta-llama/Llama-3.2-1B", "1.0.0", 1_760_000_000),
                    commitment.clone(),
                    sign(&keypair, "meta-llama/Llama-3.2-1B", "1.0.0", commitment).signature,
                    keypair.public_key(),
                )
                .unwrap()
        };

        let reopened = ModelRegistry::open(scratch.ledger()).unwrap();
        let read = reopened
            .get_model_commitment("meta-llama/Llama-3.2-1B")
            .unwrap();
        assert_eq!(read, written);
        assert!(reopened.verify_model_registration("meta-llama/Llama-3.2-1B"));
        assert_eq!(reopened.verify_chain(), Ok(()));
        assert_eq!(reopened.head(), written.digest);
    }

    #[test]
    fn an_unsigned_registration_is_never_stored() {
        let scratch = Scratch::new("unsigned");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();

        let mut forged = sign(&keypair, "acme/model", "1.0.0", commitment_of(&[1.0]));
        forged.signature[0] ^= 0xff;

        assert_eq!(
            registry.register_signed(forged),
            Err(TvcError::AttestationUnsigned)
        );
        assert!(registry.is_empty());
        assert_eq!(std::fs::read_to_string(scratch.ledger()).unwrap(), "");
    }

    #[test]
    fn a_swapped_commitment_is_never_stored() {
        let scratch = Scratch::new("swapped");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();

        // A genuine signature over honest weights, re-pointed at different ones.
        let mut substituted = sign(&keypair, "acme/model", "1.0.0", commitment_of(&[1.0, 2.0]));
        substituted.payload.weight_commitment = commitment_of(&[9.0, 9.0]);

        assert_eq!(
            registry.register_signed(substituted),
            Err(TvcError::AttestationUnsigned)
        );
        assert!(registry.is_empty());
    }

    #[test]
    fn re_registering_a_version_is_refused() {
        let scratch = Scratch::new("duplicate");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();

        let first = sign(&keypair, "acme/model", "1.0.0", commitment_of(&[1.0]));
        registry.register_signed(first).unwrap();

        let second = sign(&keypair, "acme/model", "1.0.0", commitment_of(&[2.0]));
        assert_eq!(
            registry.register_signed(second),
            Err(TvcError::DuplicateRegistration(
                "acme/model:1.0.0".to_owned()
            ))
        );
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn a_new_version_supersedes_without_erasing() {
        let scratch = Scratch::new("versions");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();

        registry
            .register_signed(sign(&keypair, "acme/model", "1.0.0", commitment_of(&[1.0])))
            .unwrap();
        registry
            .register_signed(sign(&keypair, "acme/model", "2.0.0", commitment_of(&[2.0])))
            .unwrap();

        assert_eq!(registry.versions("acme/model").len(), 2);
        assert_eq!(
            registry.get_model_commitment("acme/model").unwrap().version(),
            "2.0.0"
        );
        assert_eq!(
            registry.get_version("acme/model", "1.0.0").unwrap().version(),
            "1.0.0",
            "history must remain readable"
        );
    }

    #[test]
    fn an_unknown_model_is_reported_not_guessed() {
        let scratch = Scratch::new("unknown");
        let registry = ModelRegistry::open(scratch.ledger()).unwrap();
        assert_eq!(
            registry.get_model_commitment("nobody/nothing"),
            Err(TvcError::UnknownModel("nobody/nothing".to_owned()))
        );
        assert!(!registry.verify_model_registration("nobody/nothing"));
    }

    #[test]
    fn substituted_weights_fail_against_the_registered_commitment() {
        let scratch = Scratch::new("substitution");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();

        let honest = weights(&[1.0, 2.0, 3.0, 4.0]);
        registry
            .register_signed(sign(
                &keypair,
                "acme/model",
                "1.0.0",
                commit_weights(&honest).unwrap(),
            ))
            .unwrap();

        assert!(registry.verify_weights("acme/model", "1.0.0", &honest).is_ok());

        let downgraded = weights(&[1.0, 2.0, 3.0, 4.25]);
        assert!(matches!(
            registry.verify_weights("acme/model", "1.0.0", &downgraded),
            Err(TvcError::CommitmentMismatch { .. })
        ));
    }

    #[test]
    fn pinning_the_wrong_publisher_is_rejected() {
        let scratch = Scratch::new("pinning");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();
        let impostor = PublisherKeypair::generate(&[8u8; 32]).unwrap();

        registry
            .register_signed(sign(&keypair, "acme/model", "1.0.0", commitment_of(&[1.0])))
            .unwrap();

        assert!(registry
            .verify_model_registration_by("acme/model", &keypair.public_key())
            .is_ok());
        assert!(matches!(
            registry.verify_model_registration_by("acme/model", &impostor.public_key()),
            Err(TvcError::SignerMismatch { .. })
        ));
    }

    #[test]
    fn an_edited_record_is_caught_on_reopen() {
        let scratch = Scratch::new("edited");
        let keypair = publisher();
        {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            registry
                .register_signed(sign(&keypair, "acme/model", "1.0.0", commitment_of(&[1.0])))
                .unwrap();
        }

        // Rewrite the commitment in place, leaving the digest as recorded.
        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        let mut wire: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        wire["weight_commitment"] = serde_json::Value::String(hex::encode(&[0xabu8; 32]));
        std::fs::write(scratch.ledger(), format!("{wire}\n")).unwrap();

        assert!(matches!(
            ModelRegistry::open(scratch.ledger()),
            Err(TvcError::LedgerCorrupt { line: 1, .. })
        ));
    }

    #[test]
    fn a_deleted_record_breaks_the_chain() {
        let scratch = Scratch::new("deleted");
        let keypair = publisher();
        {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            for version in ["1.0.0", "2.0.0", "3.0.0"] {
                registry
                    .register_signed(sign(&keypair, "acme/model", version, commitment_of(&[1.0])))
                    .unwrap();
            }
        }

        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.remove(1);
        std::fs::write(scratch.ledger(), format!("{}\n", lines.join("\n"))).unwrap();

        assert!(matches!(
            ModelRegistry::open(scratch.ledger()),
            Err(TvcError::LedgerCorrupt { line: 2, .. } | TvcError::LedgerChainBroken { line: 2, .. })
        ));
    }

    #[test]
    fn a_reordered_ledger_breaks_the_chain() {
        let scratch = Scratch::new("reordered");
        let keypair = publisher();
        {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            for version in ["1.0.0", "2.0.0"] {
                registry
                    .register_signed(sign(&keypair, "acme/model", version, commitment_of(&[1.0])))
                    .unwrap();
            }
        }

        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(scratch.ledger(), format!("{}\n{}\n", lines[1], lines[0])).unwrap();

        assert!(ModelRegistry::open(scratch.ledger()).is_err());
    }

    #[test]
    fn a_truncated_ledger_still_verifies_as_a_shorter_history() {
        // Truncation cannot be caught by the chain alone; it is caught by holding
        // an earlier head. This test pins that honest limitation in place.
        let scratch = Scratch::new("truncated");
        let keypair = publisher();
        let head_before = {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            for version in ["1.0.0", "2.0.0"] {
                registry
                    .register_signed(sign(&keypair, "acme/model", version, commitment_of(&[1.0])))
                    .unwrap();
            }
            registry.head()
        };

        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        std::fs::write(scratch.ledger(), format!("{}\n", text.lines().next().unwrap())).unwrap();

        let truncated = ModelRegistry::open(scratch.ledger()).unwrap();
        assert_eq!(truncated.verify_chain(), Ok(()));
        assert_eq!(truncated.len(), 1);
        assert_ne!(
            truncated.head(),
            head_before,
            "a consumer holding the earlier head detects the rollback"
        );
    }

    #[test]
    fn garbage_lines_are_rejected_with_their_position() {
        let scratch = Scratch::new("garbage");
        std::fs::write(scratch.ledger(), "{\"not\":\"a record\"}\n").unwrap();
        assert!(matches!(
            ModelRegistry::open(scratch.ledger()),
            Err(TvcError::LedgerCorrupt { line: 1, .. })
        ));
    }

    #[test]
    fn a_dual_commitment_round_trips_and_stays_bound() {
        use crate::commitment::commit_weights_with_proof;

        let scratch = Scratch::new("dual");
        let keypair = publisher();
        let vector = weights(&[1.0, 2.0, 3.0, 4.0]);
        let commitment = commit_weights_with_proof(
            &vector,
            Some(SchemeCommitment::new("kzg-bn254/v1", vec![0xab; 32])),
        )
        .unwrap();

        let written = {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            let payload = RegistrationPayload::new(
                "acme/closed-model",
                "1.0.0",
                commitment.clone(),
                1_760_000_000,
            );
            registry
                .register_signed(keypair.sign(&payload, &[1u8; 32]).unwrap())
                .unwrap()
        };

        let reopened = ModelRegistry::open(scratch.ledger()).unwrap();
        let read = reopened.get_model_commitment("acme/closed-model").unwrap();
        assert_eq!(read, written);

        let stored = read.weight_commitment();
        assert!(stored.has_proof_commitment());
        assert_eq!(stored.proof.as_ref().unwrap().scheme, "kzg-bn254/v1");
        assert_eq!(stored.proof.as_ref().unwrap().bytes, vec![0xab; 32]);
        assert!(stored.is_self_consistent());

        // The hash half still works for anyone holding the weights.
        assert!(reopened
            .verify_weights_with_proof("acme/closed-model", "1.0.0", &vector, stored.proof.clone())
            .is_ok());
    }

    #[test]
    fn weights_verify_against_a_dual_commitment_record() {
        // Regression: `root` binds the proving-system commitment too, so weight
        // verification has to compare the hash layer. Comparing roots rejected
        // correct weights for every closed-model record.
        use crate::commitment::commit_weights_with_proof;

        let scratch = Scratch::new("dual-weights");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();
        let vector = weights(&[1.0, 2.0, 3.0]);
        let commitment = commit_weights_with_proof(
            &vector,
            Some(SchemeCommitment::new("kzg-bn254/v1", vec![0x5; 32])),
        )
        .unwrap();
        let payload =
            RegistrationPayload::new("acme/model", "1.0.0", commitment, 1_760_000_000);
        registry
            .register_signed(keypair.sign(&payload, &[1u8; 32]).unwrap())
            .unwrap();

        assert!(registry.verify_weights("acme/model", "1.0.0", &vector).is_ok());
        assert!(matches!(
            registry.verify_weights("acme/model", "1.0.0", &weights(&[1.0, 2.0, 3.5])),
            Err(TvcError::CommitmentMismatch { .. })
        ));
    }

    #[test]
    fn the_proof_commitment_is_checkable_without_the_weights() {
        // The only half of a closed-model registration a consumer can check
        // directly, and the hook the circuit layer will use.
        use crate::commitment::commit_weights_with_proof;

        let scratch = Scratch::new("proof-only");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();
        let expected = SchemeCommitment::new("kzg-bn254/v1", vec![0x9; 32]);
        let commitment =
            commit_weights_with_proof(&weights(&[1.0, 2.0]), Some(expected.clone())).unwrap();
        let payload =
            RegistrationPayload::new("acme/model", "1.0.0", commitment, 1_760_000_000);
        registry
            .register_signed(keypair.sign(&payload, &[1u8; 32]).unwrap())
            .unwrap();

        assert!(registry
            .verify_proof_commitment("acme/model", "1.0.0", Some(&expected))
            .is_ok());
        assert!(matches!(
            registry.verify_proof_commitment(
                "acme/model",
                "1.0.0",
                Some(&SchemeCommitment::new("kzg-bn254/v1", vec![0xff; 32]))
            ),
            Err(TvcError::ProofCommitmentMismatch { .. })
        ));
        // A different scheme over the same bytes is also a mismatch.
        assert!(matches!(
            registry.verify_proof_commitment(
                "acme/model",
                "1.0.0",
                Some(&SchemeCommitment::new("poseidon-bn254/v1", vec![0x9; 32]))
            ),
            Err(TvcError::ProofCommitmentMismatch { .. })
        ));
        assert!(matches!(
            registry.verify_proof_commitment("acme/model", "1.0.0", None),
            Err(TvcError::ProofCommitmentMismatch { .. })
        ));
    }

    #[test]
    fn a_proof_commitment_cannot_be_added_after_signing() {
        // The whole point of binding both under one signature: a publisher who
        // signed for open weights cannot silently acquire a circuit identity.
        let keypair = publisher();
        let commitment = commitment_of(&[1.0, 2.0]);
        let payload =
            RegistrationPayload::new("acme/model", "1.0.0", commitment, 1_760_000_000);
        let mut signed = keypair.sign(&payload, &[1u8; 32]).unwrap();
        assert_eq!(signed.verify(), Ok(()));

        signed.payload.weight_commitment = signed
            .payload
            .weight_commitment
            .clone()
            .with_proof(SchemeCommitment::new("kzg-bn254/v1", vec![0xcd; 32]));

        assert_eq!(signed.verify(), Err(TvcError::AttestationUnsigned));
    }

    #[test]
    fn a_half_present_proof_commitment_is_malformed() {
        use crate::commitment::commit_weights_with_proof;

        let scratch = Scratch::new("half-proof");
        let keypair = publisher();
        let commitment = commit_weights_with_proof(
            &weights(&[1.0]),
            Some(SchemeCommitment::new("kzg-bn254/v1", vec![0xab; 32])),
        )
        .unwrap();
        {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            let payload =
                RegistrationPayload::new("acme/model", "1.0.0", commitment, 1_760_000_000);
            registry
                .register_signed(keypair.sign(&payload, &[1u8; 32]).unwrap())
                .unwrap();
        }

        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        let mut wire: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        wire.as_object_mut().unwrap().remove("proof_scheme");
        std::fs::write(scratch.ledger(), format!("{wire}\n")).unwrap();

        assert!(matches!(
            ModelRegistry::open(scratch.ledger()),
            Err(TvcError::LedgerCorrupt { line: 1, .. })
        ));
    }

    #[test]
    fn an_open_weights_record_carries_no_proof_fields() {
        let scratch = Scratch::new("no-proof-fields");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();
        registry
            .register_signed(sign(&keypair, "acme/model", "1.0.0", commitment_of(&[1.0])))
            .unwrap();

        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        let wire: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        let object = wire.as_object().unwrap();
        assert!(!object.contains_key("proof_scheme"));
        assert!(!object.contains_key("proof_commitment"));
        assert!(object.contains_key("hash_scheme"));
    }

    #[test]
    fn an_unrecognised_field_is_ignored_not_rejected() {
        // Forward compatibility: a ledger outlives the binary that wrote it, so a
        // record enriched by a later version must still open here. The field is
        // inert — it is covered by neither the digest nor the signature — which
        // is exactly why ignoring it is safe and why nothing may trust it.
        let scratch = Scratch::new("unknown-field");
        let keypair = publisher();
        {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            registry
                .register_signed(sign(&keypair, "acme/model", "1.0.0", commitment_of(&[1.0])))
                .unwrap();
        }

        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        let mut wire: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        wire["identity_attestation"] = serde_json::json!({"future": "field"});
        std::fs::write(scratch.ledger(), format!("{wire}\n")).unwrap();

        let reopened = ModelRegistry::open(scratch.ledger()).unwrap();
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened.verify_chain(), Ok(()));
        assert!(reopened.verify_model_registration("acme/model"));
    }

    #[test]
    fn an_unrecognised_format_version_is_refused() {
        // The other half of the compatibility split: a version this build does
        // not know may compute its digest differently, and reporting a record as
        // verified when its digest cannot be reproduced would be a lie.
        let scratch = Scratch::new("future-version");
        let keypair = publisher();
        {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            registry
                .register_signed(sign(&keypair, "acme/model", "1.0.0", commitment_of(&[1.0])))
                .unwrap();
        }

        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        let mut wire: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        wire["v"] = serde_json::json!(FORMAT_VERSION + 1);
        std::fs::write(scratch.ledger(), format!("{wire}\n")).unwrap();

        assert!(matches!(
            ModelRegistry::open(scratch.ledger()),
            Err(TvcError::LedgerCorrupt { line: 1, .. })
        ));
    }

    #[test]
    fn the_format_version_is_bound_into_the_record_digest() {
        let scratch = Scratch::new("version-bound");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();
        let record = registry
            .register_signed(sign(&keypair, "acme/model", "1.0.0", commitment_of(&[1.0])))
            .unwrap();

        assert_ne!(
            ModelRecord::compute_digest(
                FORMAT_VERSION + 1,
                record.sequence,
                &record.previous,
                &record.registration
            ),
            record.digest
        );
    }

    #[test]
    fn records_dated_ahead_flags_only_implausible_timestamps() {
        // Loose sanity, not monotonicity: two publishers with skewed clocks must
        // not invalidate each other, so ordering stays the sequence number's job.
        let scratch = Scratch::new("clock");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();

        let early = RegistrationPayload::new("acme/model", "1.0.0", commitment_of(&[1.0]), 2_000);
        let backwards = RegistrationPayload::new("acme/model", "2.0.0", commitment_of(&[2.0]), 1_000);
        let far_ahead =
            RegistrationPayload::new("acme/model", "3.0.0", commitment_of(&[3.0]), 9_000_000);
        for payload in [early, backwards, far_ahead] {
            registry
                .register_signed(keypair.sign(&payload, &[1u8; 32]).unwrap())
                .unwrap();
        }

        // A clock that runs backwards between records is accepted, by design.
        assert_eq!(registry.verify_chain(), Ok(()));
        assert_eq!(registry.records_dated_ahead(10_000, 300), vec![2]);
        assert!(registry.records_dated_ahead(9_000_000, 300).is_empty());
    }

    #[test]
    fn many_registrations_survive_reopening_as_one_chain() {
        let scratch = Scratch::new("durability");
        let keypair = publisher();
        for index in 0..8u32 {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            registry
                .register_signed(sign(
                    &keypair,
                    "acme/model",
                    &format!("1.0.{index}"),
                    commitment_of(&[index as f32]),
                ))
                .unwrap();
        }
        let reopened = ModelRegistry::open(scratch.ledger()).unwrap();
        assert_eq!(reopened.len(), 8);
        assert_eq!(reopened.verify_chain(), Ok(()));
        assert_eq!(reopened.get_model_commitment("acme/model").unwrap().version(), "1.0.7");
    }

    #[test]
    fn a_stale_handle_is_refused_rather_than_forking_the_chain() {
        // Two handles that both read the ledger at the same point. Without the
        // length check under the lock, both would write the same sequence number
        // and the fork would only surface on a later read.
        let scratch = Scratch::new("stale");
        let keypair = publisher();

        let mut first = ModelRegistry::open(scratch.ledger()).unwrap();
        let mut second = ModelRegistry::open(scratch.ledger()).unwrap();

        first
            .register_signed(sign(&keypair, "acme/model", "1.0.0", commitment_of(&[1.0])))
            .unwrap();

        assert!(matches!(
            second.register_signed(sign(&keypair, "acme/other", "1.0.0", commitment_of(&[2.0]))),
            Err(TvcError::LedgerChangedUnderneath { .. })
        ));

        // The ledger is intact, and reopening lets the loser proceed.
        let mut reopened = ModelRegistry::open(scratch.ledger()).unwrap();
        assert_eq!(reopened.verify_chain(), Ok(()));
        assert_eq!(reopened.len(), 1);
        reopened
            .register_signed(sign(&keypair, "acme/other", "1.0.0", commitment_of(&[2.0])))
            .unwrap();
        assert_eq!(reopened.verify_chain(), Ok(()));
        assert_eq!(reopened.records()[1].sequence, 1);
    }

    #[test]
    fn sequential_appends_through_one_handle_stay_valid() {
        let scratch = Scratch::new("sequential");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();
        for index in 0..5u32 {
            registry
                .register_signed(sign(
                    &keypair,
                    "acme/model",
                    &format!("1.0.{index}"),
                    commitment_of(&[index as f32]),
                ))
                .unwrap();
        }
        assert_eq!(registry.verify_chain(), Ok(()));
        assert_eq!(ModelRegistry::open(scratch.ledger()).unwrap().len(), 5);
    }

    #[test]
    fn the_ledger_is_one_json_object_per_line() {
        let scratch = Scratch::new("format");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();
        registry
            .register_signed(sign(&keypair, "acme/model", "1.0.0", commitment_of(&[1.0])))
            .unwrap();

        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.ends_with('\n'));
        assert!(serde_json::from_str::<serde_json::Value>(text.trim()).is_ok());
    }

    fn signed_document(
        keypair: &PublisherKeypair,
        kind: &str,
        document: [u8; 32],
        refs: Vec<[u8; 32]>,
    ) -> SignedDocument {
        keypair
            .sign_document(&DocumentClaim::new(kind, document, refs, 1_760_000_000), &[4u8; 32])
            .unwrap()
    }

    #[test]
    fn documents_and_registrations_share_one_chain_across_reopen() {
        let scratch = Scratch::new("mixed");
        let keypair = publisher();
        let head = {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            registry
                .register_signed(sign(&keypair, "acme/model", "1.0.0", commitment_of(&[1.0])))
                .unwrap();
            let manifest = signed_document(&keypair, "weights-manifest/v1", [1; 32], vec![]);
            registry.register_document(manifest).unwrap();
            let setup = signed_document(&keypair, "reference-setup/v1", [2; 32], vec![[1; 32]]);
            let record = registry.register_document(setup).unwrap();
            assert_eq!(record.sequence, 2);
            assert_eq!(registry.head(), record.digest);
            registry.head()
        };

        let reopened = ModelRegistry::open(scratch.ledger()).unwrap();
        assert_eq!(reopened.len(), 3);
        assert_eq!(reopened.records().len(), 1);
        assert_eq!(reopened.documents().len(), 2);
        assert_eq!(reopened.head(), head);
        assert_eq!(reopened.verify_chain(), Ok(()));
        assert_eq!(
            reopened.get_document(&[2; 32]).unwrap().kind(),
            "reference-setup/v1"
        );

        // Model lines stay v2, document lines are v3, in the same file.
        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        let versions: Vec<u64> = text
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["v"].as_u64().unwrap())
            .collect();
        assert_eq!(versions, vec![2, 3, 3]);
    }

    #[test]
    fn a_reference_to_a_document_not_yet_published_is_refused() {
        let scratch = Scratch::new("forward-ref");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();
        let run = signed_document(&keypair, "reference-run/v1", [3; 32], vec![[2; 32]]);
        assert!(matches!(
            registry.register_document(run),
            Err(TvcError::InvalidDocument(_))
        ));
        assert!(registry.is_empty());
    }

    #[test]
    fn the_same_document_cannot_be_published_twice() {
        let scratch = Scratch::new("dup-doc");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();
        registry
            .register_document(signed_document(&keypair, "weights-manifest/v1", [1; 32], vec![]))
            .unwrap();
        assert!(matches!(
            registry.register_document(signed_document(&keypair, "profile/v1", [1; 32], vec![])),
            Err(TvcError::DuplicateRegistration(_))
        ));
    }

    #[test]
    fn an_unsigned_document_claim_is_never_stored() {
        let scratch = Scratch::new("unsigned-doc");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let mut forged = signed_document(&publisher(), "weights-manifest/v1", [1; 32], vec![]);
        forged.signature[0] ^= 0xff;
        assert_eq!(registry.register_document(forged), Err(TvcError::AttestationUnsigned));
        assert!(registry.is_empty());
    }

    #[test]
    fn a_document_line_edited_on_disk_is_caught() {
        let scratch = Scratch::new("edit-doc");
        let keypair = publisher();
        {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            registry
                .register_document(signed_document(&keypair, "weights-manifest/v1", [1; 32], vec![]))
                .unwrap();
        }
        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        let mut wire: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        wire["document"] = serde_json::json!(hex::encode(&[9u8; 32]));
        std::fs::write(scratch.ledger(), format!("{wire}\n")).unwrap();
        assert!(matches!(
            ModelRegistry::open(scratch.ledger()),
            Err(TvcError::LedgerCorrupt { line: 1, .. })
        ));
    }

    #[test]
    fn a_rewritten_line_with_a_recomputed_digest_still_fails_on_its_signature() {
        // An editor who knows the digest rule recomputes it after changing the
        // timestamp. The digest now checks out; the signature does not.
        let scratch = Scratch::new("redigest-doc");
        let keypair = publisher();
        let mut record = {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            registry
                .register_document(signed_document(&keypair, "weights-manifest/v1", [1; 32], vec![]))
                .unwrap()
        };
        record.signed.claim.timestamp -= 86_400;
        record.digest = DocumentRecord::compute_digest(
            record.format_version,
            record.sequence,
            &record.previous,
            &record.signed,
        );
        std::fs::write(scratch.ledger(), format!("{}\n", record.to_json())).unwrap();
        assert!(matches!(
            ModelRegistry::open(scratch.ledger()),
            Err(TvcError::LedgerCorrupt { line: 1, .. })
        ));
    }

    #[test]
    fn swapping_a_document_before_the_one_it_cites_breaks_the_ledger() {
        let scratch = Scratch::new("reorder-doc");
        let keypair = publisher();
        {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            registry
                .register_document(signed_document(&keypair, "weights-manifest/v1", [1; 32], vec![]))
                .unwrap();
            registry
                .register_document(signed_document(&keypair, "reference-setup/v1", [2; 32], vec![[1; 32]]))
                .unwrap();
        }
        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(scratch.ledger(), format!("{}\n{}\n", lines[1], lines[0])).unwrap();
        assert!(ModelRegistry::open(scratch.ledger()).is_err());
    }

    #[test]
    fn an_unknown_document_version_is_refused() {
        let scratch = Scratch::new("future-doc");
        let keypair = publisher();
        {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            registry
                .register_document(signed_document(&keypair, "weights-manifest/v1", [1; 32], vec![]))
                .unwrap();
        }
        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        let mut wire: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        wire["v"] = serde_json::json!(FORMAT_VERSION + 1);
        std::fs::write(scratch.ledger(), format!("{wire}\n")).unwrap();
        assert!(matches!(
            ModelRegistry::open(scratch.ledger()),
            Err(TvcError::LedgerCorrupt { line: 1, .. })
        ));
    }

    #[test]
    fn a_stale_handle_cannot_append_a_document_either() {
        let scratch = Scratch::new("stale-doc");
        let keypair = publisher();
        let mut first = ModelRegistry::open(scratch.ledger()).unwrap();
        let mut second = ModelRegistry::open(scratch.ledger()).unwrap();
        first
            .register_document(signed_document(&keypair, "weights-manifest/v1", [1; 32], vec![]))
            .unwrap();
        assert!(matches!(
            second.register_document(signed_document(&keypair, "weights-manifest/v1", [5; 32], vec![])),
            Err(TvcError::LedgerChangedUnderneath { .. })
        ));
    }
}
