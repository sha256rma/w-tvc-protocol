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

use crate::commitment::{commit_weights, WeightCommitment, WeightVector};
use crate::digest::{tagged_hash, DOMAIN_LEDGER_CHAIN};
use crate::error::{Result, TvcError};
use crate::hex;
use crate::signer::{RegistrationPayload, SignedRegistration};

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
pub const FORMAT_VERSION: u32 = 1;

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
        tagged_hash(
            DOMAIN_LEDGER_CHAIN,
            &[
                previous,
                &format_version.to_be_bytes(),
                &sequence.to_be_bytes(),
                payload.model_id.as_bytes(),
                payload.version.as_bytes(),
                commitment.scheme.as_bytes(),
                &commitment.root,
                &commitment.scheme_commitment,
                &commitment.length.to_be_bytes(),
                &commitment.fractional_bits.to_be_bytes(),
                &commitment.manifest_digest,
                &payload.timestamp.to_be_bytes(),
                &registration.publisher,
                &registration.signature,
            ],
        )
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
    scheme: String,
    weight_commitment: String,
    /// The underlying scheme's own commitment; length varies by scheme.
    scheme_commitment: String,
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
            scheme: commitment.scheme.clone(),
            weight_commitment: hex::encode(&commitment.root),
            scheme_commitment: hex::encode(&commitment.scheme_commitment),
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

        if self.v != FORMAT_VERSION {
            return Err(at(format!(
                "record format version {} is not {FORMAT_VERSION}; this build cannot reproduce its digest",
                self.v
            )));
        }

        let registration = SignedRegistration {
            payload: RegistrationPayload::new(
                self.model_id,
                self.version,
                WeightCommitment {
                    scheme: self.scheme,
                    root: field("weight_commitment", &self.weight_commitment)?,
                    scheme_commitment: hex::decode(&self.scheme_commitment)
                        .map_err(|error| at(format!("scheme_commitment: {error}")))?,
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

/// An append-only, file-backed registry of model registrations.
#[derive(Debug)]
pub struct ModelRegistry {
    path: PathBuf,
    records: Vec<ModelRecord>,
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

            let wire: WireRecord = serde_json::from_str(&line).map_err(|error| {
                TvcError::LedgerCorrupt {
                    line: line_number,
                    reason: format!("not a registry record: {error}"),
                }
            })?;
            let record = wire.into_record(line_number)?;

            if record.sequence != registry.records.len() as u64 {
                return Err(TvcError::LedgerCorrupt {
                    line: line_number,
                    reason: format!(
                        "sequence {} out of order; expected {}",
                        record.sequence,
                        registry.records.len()
                    ),
                });
            }
            if record.previous != previous {
                return Err(TvcError::LedgerChainBroken {
                    line: line_number,
                    expected: hex::encode(&record.previous),
                    observed: hex::encode(&previous),
                });
            }
            // A stored record whose signature no longer verifies means the file
            // was edited after the fact; refuse to serve it as if it were valid.
            record.registration.verify().map_err(|error| TvcError::LedgerCorrupt {
                line: line_number,
                reason: format!("stored attestation does not verify: {error}"),
            })?;

            let address = record.address();
            if registry.by_address.contains_key(&address) {
                return Err(TvcError::LedgerCorrupt {
                    line: line_number,
                    reason: format!("{address} appears twice; the registry is append-only"),
                });
            }

            previous = record.digest;
            registry.by_address.insert(address, registry.records.len());
            registry.records.push(record);
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

        let sequence = self.records.len() as u64;
        let previous = self.head();
        let record = ModelRecord {
            digest: ModelRecord::compute_digest(
                FORMAT_VERSION,
                sequence,
                &previous,
                &registration,
            ),
            format_version: FORMAT_VERSION,
            sequence,
            registration,
            previous,
        };

        let mut line = serde_json::to_string(&WireRecord::from(&record))
            .map_err(|error| TvcError::Io(format!("could not encode record: {error}")))?;
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

        self.by_address.insert(address, self.records.len());
        self.records.push(record.clone());
        Ok(record)
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

    /// Every record in the ledger, in order.
    pub fn records(&self) -> &[ModelRecord] {
        &self.records
    }

    /// Digest of the last record, or [`GENESIS_DIGEST`] for an empty ledger.
    ///
    /// This is the value to publish or pin: holding an earlier head is what lets
    /// a consumer detect that history was rewritten underneath them.
    pub fn head(&self) -> [u8; 32] {
        self.records
            .last()
            .map_or(GENESIS_DIGEST, |record| record.digest)
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
        let recomputed = commit_weights(weights)?;
        if recomputed.root != record.weight_commitment().root {
            return Err(TvcError::CommitmentMismatch {
                expected: record.weight_commitment().root_hex(),
                observed: recomputed.root_hex(),
            });
        }
        Ok(record)
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
        for (index, record) in self.records.iter().enumerate() {
            let line = index + 1;
            if record.previous != previous {
                return Err(TvcError::LedgerChainBroken {
                    line,
                    expected: hex::encode(&record.previous),
                    observed: hex::encode(&previous),
                });
            }
            let computed = ModelRecord::compute_digest(
                record.format_version,
                record.sequence,
                &record.previous,
                &record.registration,
            );
            if computed != record.digest {
                return Err(TvcError::LedgerChainBroken {
                    line,
                    expected: record.digest_hex(),
                    observed: hex::encode(&computed),
                });
            }
            previous = record.digest;
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

    /// Number of records in the ledger.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the ledger holds no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
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
}
