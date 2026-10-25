//! The append-only ledger of signed document claims.
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
//! # What the ledger does and does not establish
//!
//! [`ModelRegistry::register_document`] refuses a claim whose signature does not
//! verify, so every record in a well-formed ledger is signed by the key it
//! names. It also refuses a claim that cites a document not already in the
//! ledger, which is what makes ledger order mean "came before". It does not
//! decide *which* keys may sign which kinds; a verifier pins those keys, as
//! `tvc verify-reference` and `tvc verify-audit` do.
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

use crate::digest::{tagged_hash, DOMAIN_LEDGER_DOCUMENT};
use crate::error::{Result, TvcError};
use crate::hex;
use crate::signer::{DocumentClaim, SignedDocument};

/// Digest the first record in a ledger extends.
pub const GENESIS_DIGEST: [u8; 32] = [0u8; 32];

/// Ledger record format this build reads and writes.
///
/// The version is folded into every record digest, so it cannot be edited after
/// the fact, and an unknown version is a hard stop: a future version may compute
/// the digest differently, and a reader that cannot reproduce a digest cannot
/// honestly report the record as verified. Unknown *fields* are ignored, for the
/// reason given on the wire type.
///
/// Versions 1 and 2 were model-weight registrations, written by an earlier
/// build that no longer exists. This build refuses them.
pub const FORMAT_VERSION: u32 = 3;

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
    /// Zero-based position in the ledger.
    pub sequence: u64,
    /// The signed claim.
    pub signed: SignedDocument,
    /// Digest of the preceding record, or [`GENESIS_DIGEST`].
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

/// On-disk encoding of a [`DocumentRecord`].
///
/// Unknown fields are ignored: a ledger outlives the code that wrote it, and a
/// field covered by neither the digest nor the signature is inert, so nothing
/// is lost by ignoring it and nothing may trust it.
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

/// An append-only, file-backed ledger of signed document claims.
#[derive(Debug)]
pub struct ModelRegistry {
    path: PathBuf,
    /// Every record, in ledger order.
    documents: Vec<DocumentRecord>,
    /// Maps a document digest to its position in `documents`.
    by_document: BTreeMap<[u8; 32], usize>,
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
            documents: Vec::new(),
            by_document: BTreeMap::new(),
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
                .map_err(|error| corrupt(format!("not a ledger record: {error}")))?;
            let version = value
                .get("v")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| corrupt("not a ledger record: no format version".to_owned()))?;
            if version != u64::from(FORMAT_VERSION) {
                return Err(corrupt(format!(
                    "format version {version} is not one this build reads (version {FORMAT_VERSION})"
                )));
            }

            let wire: WireDocument = serde_json::from_value(value)
                .map_err(|error| corrupt(format!("not a document record: {error}")))?;
            let record = wire.into_record(line_number)?;
            // A stored claim whose signature no longer verifies, or that points
            // at a document not yet in the ledger, means the file was edited
            // after the fact; refuse to serve it as valid.
            registry
                .check_document(&record.signed)
                .map_err(|error| corrupt(format!("stored document claim is invalid: {error}")))?;

            let expected_sequence = registry.documents.len() as u64;
            if record.sequence != expected_sequence {
                return Err(corrupt(format!(
                    "sequence {} out of order; expected {expected_sequence}",
                    record.sequence
                )));
            }
            if record.previous != previous {
                return Err(TvcError::LedgerChainBroken {
                    line: line_number,
                    expected: hex::encode(&record.previous),
                    observed: hex::encode(&previous),
                });
            }
            previous = record.digest;
            registry
                .by_document
                .insert(record.document(), registry.documents.len());
            registry.documents.push(record);
        }

        registry.observed_len = std::fs::metadata(&registry.path)?.len();
        Ok(registry)
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
    /// [`TvcError::DuplicateDocument`] for a repeated document,
    /// [`TvcError::LedgerChangedUnderneath`] if another handle appended since
    /// this one read the file, and [`TvcError::Io`] if the append fails.
    pub fn register_document(&mut self, signed: SignedDocument) -> Result<DocumentRecord> {
        self.check_document(&signed)?;

        let sequence = self.documents.len() as u64;
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
        self.documents.push(record.clone());
        Ok(record)
    }

    /// The rules a document claim must meet against the entries before it.
    fn check_document(&self, signed: &SignedDocument) -> Result<()> {
        signed.verify()?;
        let claim = &signed.claim;
        if self.by_document.contains_key(&claim.document) {
            return Err(TvcError::DuplicateDocument(format!(
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
        self.documents.last().map_or(GENESIS_DIGEST, |record| record.digest)
    }

    /// Lowercase hex rendering of [`Self::head`].
    pub fn head_hex(&self) -> String {
        hex::encode(&self.head())
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
        for (index, record) in self.documents.iter().enumerate() {
            let line = index + 1;
            let computed = DocumentRecord::compute_digest(
                record.format_version,
                record.sequence,
                &record.previous,
                &record.signed,
            );
            if record.previous != previous {
                return Err(TvcError::LedgerChainBroken {
                    line,
                    expected: hex::encode(&record.previous),
                    observed: hex::encode(&previous),
                });
            }
            if computed != record.digest {
                return Err(TvcError::LedgerChainBroken {
                    line,
                    expected: hex::encode(&record.digest),
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
    /// the moment two signers with skewed clocks share a ledger; ordering is
    /// already established by the sequence number and the hash chain, which are
    /// facts about what was appended rather than claims about a clock. What a
    /// timestamp is good for is a loose sanity bound, so that is what this is.
    ///
    /// Returns the sequence numbers of records claiming a time more than
    /// `max_skew_secs` beyond `now`.
    pub fn records_dated_ahead(&self, now: u64, max_skew_secs: u64) -> Vec<u64> {
        let ceiling = now.saturating_add(max_skew_secs);
        self.documents
            .iter()
            .filter(|record| record.signed.claim.timestamp > ceiling)
            .map(|record| record.sequence)
            .collect()
    }

    /// Number of records in the ledger.
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    /// Whether the ledger holds no records.
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    /// Path of the backing file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn publisher() -> PublisherKeypair {
        PublisherKeypair::generate(&[5u8; 32]).unwrap()
    }

    fn signed_at(
        keypair: &PublisherKeypair,
        kind: &str,
        document: [u8; 32],
        refs: Vec<[u8; 32]>,
        timestamp: u64,
    ) -> SignedDocument {
        keypair
            .sign_document(&DocumentClaim::new(kind, document, refs, timestamp), &[4u8; 32])
            .unwrap()
    }

    fn signed_document(
        keypair: &PublisherKeypair,
        kind: &str,
        document: [u8; 32],
        refs: Vec<[u8; 32]>,
    ) -> SignedDocument {
        signed_at(keypair, kind, document, refs, 1_760_000_000)
    }

    /// A ledger of `n` independent manifests, documents `[1; 32]`, `[2; 32]`, ...
    fn ledger_of(scratch: &Scratch, n: u8) -> [u8; 32] {
        let keypair = publisher();
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        for index in 1..=n {
            registry
                .register_document(signed_document(&keypair, "weights-manifest/v1", [index; 32], vec![]))
                .unwrap();
        }
        registry.head()
    }

    #[test]
    fn a_document_round_trips_through_the_ledger() {
        let scratch = Scratch::new("roundtrip");
        let keypair = publisher();
        let head = {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            registry
                .register_document(signed_document(&keypair, "weights-manifest/v1", [1; 32], vec![]))
                .unwrap();
            let setup = signed_document(&keypair, "reference-setup/v2", [2; 32], vec![[1; 32]]);
            let record = registry.register_document(setup).unwrap();
            assert_eq!(record.sequence, 1);
            assert_eq!(registry.head(), record.digest);
            registry.head()
        };

        let reopened = ModelRegistry::open(scratch.ledger()).unwrap();
        assert_eq!(reopened.len(), 2);
        assert_eq!(reopened.head(), head);
        assert_eq!(reopened.verify_chain(), Ok(()));
        assert_eq!(reopened.get_document(&[2; 32]).unwrap().kind(), "reference-setup/v2");
        assert_eq!(reopened.get_document(&[2; 32]).unwrap().signed.signer, keypair.public_key());
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
            Err(TvcError::DuplicateDocument(_))
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
        ledger_of(&scratch, 1);
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
    fn a_deleted_record_breaks_the_chain() {
        let scratch = Scratch::new("deleted");
        ledger_of(&scratch, 3);
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
        ledger_of(&scratch, 2);
        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(scratch.ledger(), format!("{}\n{}\n", lines[1], lines[0])).unwrap();
        assert!(ModelRegistry::open(scratch.ledger()).is_err());
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
    fn a_truncated_ledger_still_verifies_as_a_shorter_history() {
        // Truncation cannot be caught by the chain alone; it is caught by holding
        // an earlier head. This test pins that honest limitation in place.
        let scratch = Scratch::new("truncated");
        let head_before = ledger_of(&scratch, 2);
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
        // inert — covered by neither the digest nor the signature — which is
        // exactly why ignoring it is safe and why nothing may trust it.
        let scratch = Scratch::new("unknown-field");
        ledger_of(&scratch, 1);
        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        let mut wire: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        wire["witness"] = serde_json::json!({"future": "field"});
        std::fs::write(scratch.ledger(), format!("{wire}\n")).unwrap();

        let reopened = ModelRegistry::open(scratch.ledger()).unwrap();
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened.verify_chain(), Ok(()));
    }

    #[test]
    fn an_unknown_format_version_is_refused() {
        // A version this build does not know may compute its digest differently,
        // and reporting a record as verified when its digest cannot be reproduced
        // would be a lie. That includes the retired version 2 registrations.
        for version in [2, FORMAT_VERSION + 1] {
            let scratch = Scratch::new(&format!("version-{version}"));
            ledger_of(&scratch, 1);
            let text = std::fs::read_to_string(scratch.ledger()).unwrap();
            let mut wire: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
            wire["v"] = serde_json::json!(version);
            std::fs::write(scratch.ledger(), format!("{wire}\n")).unwrap();
            assert!(matches!(
                ModelRegistry::open(scratch.ledger()),
                Err(TvcError::LedgerCorrupt { line: 1, .. })
            ));
        }
    }

    #[test]
    fn the_format_version_is_bound_into_the_record_digest() {
        let scratch = Scratch::new("version-bound");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let record = registry
            .register_document(signed_document(&publisher(), "weights-manifest/v1", [1; 32], vec![]))
            .unwrap();
        assert_ne!(
            DocumentRecord::compute_digest(
                FORMAT_VERSION + 1,
                record.sequence,
                &record.previous,
                &record.signed
            ),
            record.digest
        );
    }

    #[test]
    fn records_dated_ahead_flags_only_implausible_timestamps() {
        // Loose sanity, not monotonicity: two signers with skewed clocks must not
        // invalidate each other, so ordering stays the sequence number's job.
        let scratch = Scratch::new("clock");
        let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
        let keypair = publisher();
        for (document, timestamp) in [([1; 32], 2_000), ([2; 32], 1_000), ([3; 32], 9_000_000)] {
            registry
                .register_document(signed_at(&keypair, "weights-manifest/v1", document, vec![], timestamp))
                .unwrap();
        }
        // A clock that runs backwards between records is accepted, by design.
        assert_eq!(registry.verify_chain(), Ok(()));
        assert_eq!(registry.records_dated_ahead(10_000, 300), vec![2]);
        assert!(registry.records_dated_ahead(9_000_000, 300).is_empty());
    }

    #[test]
    fn many_documents_survive_reopening_as_one_chain() {
        let scratch = Scratch::new("durability");
        let keypair = publisher();
        for index in 1..=8u8 {
            let mut registry = ModelRegistry::open(scratch.ledger()).unwrap();
            registry
                .register_document(signed_document(&keypair, "weights-manifest/v1", [index; 32], vec![]))
                .unwrap();
        }
        let reopened = ModelRegistry::open(scratch.ledger()).unwrap();
        assert_eq!(reopened.len(), 8);
        assert_eq!(reopened.verify_chain(), Ok(()));
        assert_eq!(reopened.documents()[7].sequence, 7);
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
            .register_document(signed_document(&keypair, "weights-manifest/v1", [1; 32], vec![]))
            .unwrap();
        assert!(matches!(
            second.register_document(signed_document(&keypair, "weights-manifest/v1", [5; 32], vec![])),
            Err(TvcError::LedgerChangedUnderneath { .. })
        ));

        // The ledger is intact, and reopening lets the loser proceed.
        let mut reopened = ModelRegistry::open(scratch.ledger()).unwrap();
        assert_eq!(reopened.verify_chain(), Ok(()));
        reopened
            .register_document(signed_document(&keypair, "weights-manifest/v1", [5; 32], vec![]))
            .unwrap();
        assert_eq!(reopened.verify_chain(), Ok(()));
        assert_eq!(reopened.documents()[1].sequence, 1);
    }

    #[test]
    fn the_ledger_is_one_json_object_per_line() {
        let scratch = Scratch::new("format");
        ledger_of(&scratch, 1);
        let text = std::fs::read_to_string(scratch.ledger()).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.ends_with('\n'));
        let line: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(line["v"], serde_json::json!(FORMAT_VERSION));
    }
}
