//! Anchoring the registry's ledger head to a public, independent timestamp.
//!
//! # The gap this closes
//!
//! [`ModelRegistry::verify_chain`](tvc_core::registry::ModelRegistry::verify_chain)
//! catches an edited, reordered, or deleted record. It cannot catch a
//! *truncated* one: a shorter ledger is still a valid chain, just a shorter
//! history. The README calls this out plainly — the only defence is a
//! consumer who already holds an earlier head. An anchor is how that earlier
//! head becomes something nobody has to personally remember: publish a
//! commitment to it somewhere append-only and outside this project's control,
//! and a later truncation has to explain away that commitment too.
//!
//! # What an anchor proof actually establishes
//!
//! [`Anchor::stamp`] submits a 32-byte digest — the ledger head — to a
//! calendar server and gets back a proof that the calendar received it no
//! later than now. That proof starts life as a
//! [`AnchorStatus::Pending`]: a promise, backed by nothing but the calendar
//! operator's word, that the commitment will eventually be folded into a
//! Bitcoin block. It becomes [`AnchorStatus::BitcoinAttested`] once the
//! calendar can show a block height for it.
//!
//! **[`AnchorStatus::BitcoinAttested`] is not a verified fact.** Checking it
//! for real means fetching that block's header from the Bitcoin chain and
//! confirming the digest this proof reduces to is the header's merkle root —
//! this module does not do that. It has no Bitcoin data source, and adding
//! one is future work. What [`OpenTimestampsCalendar::verify`] reports is
//! only what the *proof itself claims*, read back out of bytes this crate
//! already holds. Treat a reported block height as a lead to check against a
//! block explorer, not as a settled question.
//!
//! # Why the wire format is real OpenTimestamps
//!
//! A calendar's response to a digest submission is not a custom envelope —
//! it is already the serialised form of the OpenTimestamps `Timestamp` type,
//! byte for byte. Prefixing it with the standard `DetachedTimestampFile`
//! header (see [`HEADER_MAGIC`]) turns it into an ordinary `.ots` file with no
//! transformation beyond concatenation, so `registry.head.ots` opens in any
//! OpenTimestamps client, not only this one. The tag bytes and structure below
//! are transcribed from the reference implementation
//! ([`python-opentimestamps`](https://github.com/opentimestamps/python-opentimestamps)),
//! not reinvented.
//!
//! # Why this crate does not depend on an OpenTimestamps library
//!
//! Two exist on crates.io. `opentimestamps` parses and replays `.ots` files
//! but has shipped no calendar client since 2017. `opentimestamps-client` has
//! one, but as of this writing it is eight days old, has a single owner who
//! disclaims it against any quality or security standard, and pulls in an
//! async runtime and a parallelism library for what is here a handful of
//! blocking HTTP calls. Neither fits a crate that otherwise justifies every
//! dependency by name. What is implemented below is deliberately small: parse
//! enough of the format to find attestations, and nothing that requires
//! evaluating the hash operations along the way — this module never checks a
//! computed digest against a block header, so it never needs to compute one.
//!
//! # Network boundary
//!
//! [`Anchor::stamp`] is the only function in this binary that calls out to
//! the network on `tvc anchor`'s behalf, exactly as `tvc-core` keeps
//! randomness and environment access confined to `main.rs`. [`Anchor::verify`]
//! never does: it reads bytes already on disk. [`NullAnchor`] calls out to
//! nothing at all, which is what makes it safe for tests and for `tvc demo`.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use tvc_core::hex;

/// Result type for this module.
///
/// Every other command in this binary already reports failure as a `String`
/// rendered on `stderr`; an anchor failure — a network error, a malformed
/// proof, a digest that does not match — is exactly that kind of failure and
/// nothing a caller needs to match on by variant.
pub type Result<T> = std::result::Result<T, String>;

/// Stamps a digest with an outside party, and later reports what the
/// resulting proof has come to establish.
///
/// Implementations are free to make `verify` as strong or as weak as they
/// honestly can: [`NullAnchor`] can only ever report
/// [`AnchorStatus::Unattested`], because it never asked anyone. See the
/// module docs for exactly what [`OpenTimestampsCalendar`] can and cannot
/// report.
pub trait Anchor {
    /// Submits `head` for timestamping and returns the resulting proof.
    ///
    /// # Errors
    ///
    /// Returns a message describing why the submission failed — a network
    /// error, or every configured calendar refusing the digest.
    fn stamp(&self, head: [u8; 32]) -> Result<AnchorProof>;

    /// Checks a stored proof against `head` and reports what it establishes.
    ///
    /// # Errors
    ///
    /// Returns a message when `proof` is not well-formed for this
    /// implementation, or when it commits to a digest other than `head` — the
    /// caller asked whether this proof anchors *this* ledger, and a digest
    /// mismatch is a "no", not a status to report.
    fn verify(&self, head: [u8; 32], proof: &AnchorProof) -> Result<AnchorStatus>;
}

/// An opaque, on-disk timestamp proof.
///
/// The byte layout is whichever [`Anchor`] implementation produced it —
/// [`NullAnchor`]'s own small marker, or a real `.ots` file from
/// [`OpenTimestampsCalendar`]. Nothing outside this module inspects the bytes
/// directly; ask the same kind of [`Anchor`] that made the proof to read it
/// back.
pub struct AnchorProof {
    bytes: Vec<u8>,
}

impl AnchorProof {
    /// Writes the proof to `path`, overwriting whatever was there.
    ///
    /// # Errors
    ///
    /// Returns a message if the file cannot be written.
    pub fn to_file(&self, path: &Path) -> Result<()> {
        std::fs::write(path, &self.bytes).map_err(|error| format!("{}: {error}", path.display()))
    }

    /// Reads a previously stored proof back from `path`.
    ///
    /// # Errors
    ///
    /// Returns a message if the file cannot be read. The bytes are not
    /// interpreted here — that happens in [`Anchor::verify`], which knows
    /// which format to expect.
    pub fn from_file(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
        Ok(Self { bytes })
    }
}

/// What an anchor proof establishes about a ledger head, as of the moment it
/// was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorStatus {
    /// No calendar was ever asked. [`NullAnchor`]'s only possible answer, and
    /// nothing more than a marker that offline mode was in effect.
    Unattested,
    /// One or more calendars have recorded the commitment but have not yet
    /// folded it into a Bitcoin block. Ask again later.
    Pending {
        /// Calendar URIs the proof says to poll for an upgrade.
        calendars: Vec<String>,
    },
    /// The proof claims a Bitcoin block at this height commits to the
    /// anchored head.
    ///
    /// This is a claim read out of the proof, not a fact this crate has
    /// checked. See the module docs for what confirming it for real would
    /// require.
    BitcoinAttested {
        /// Block height the proof claims, as reported by the calendar.
        height: u64,
    },
}

/// An anchor that stamps nothing and asks nothing.
///
/// For tests and for offline runs of `tvc demo`, where a real calendar
/// submission would make the test suite depend on the network and on
/// whether a third party's server is up. [`NullAnchor::verify`] can only ever
/// report [`AnchorStatus::Unattested`] — it has no calendar to have heard
/// back from, and does not pretend otherwise.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullAnchor;

/// Marker bytes for a [`NullAnchor`] proof.
///
/// Deliberately not a valid OpenTimestamps header, so a null proof can never
/// be mistaken for — or accidentally parsed as — a real one.
const NULL_MAGIC: &[u8; 12] = b"w-tvc/null01";

impl Anchor for NullAnchor {
    fn stamp(&self, head: [u8; 32]) -> Result<AnchorProof> {
        let mut bytes = Vec::with_capacity(NULL_MAGIC.len() + 32);
        bytes.extend_from_slice(NULL_MAGIC);
        bytes.extend_from_slice(&head);
        Ok(AnchorProof { bytes })
    }

    fn verify(&self, head: [u8; 32], proof: &AnchorProof) -> Result<AnchorStatus> {
        if proof.bytes.len() != NULL_MAGIC.len() + 32
            || &proof.bytes[..NULL_MAGIC.len()] != NULL_MAGIC.as_slice()
        {
            return Err("not a null-anchor proof".to_owned());
        }
        let committed = &proof.bytes[NULL_MAGIC.len()..];
        if committed != head {
            return Err(format!(
                "anchor mismatch: proof commits to {}, ledger head is {}",
                hex::encode(committed),
                hex::encode(&head)
            ));
        }
        Ok(AnchorStatus::Unattested)
    }
}

/// Header magic for a `DetachedTimestampFile`, transcribed from
/// `opentimestamps.core.timestamp.DetachedTimestampFile.HEADER_MAGIC` in the
/// reference implementation. Chosen there to look like data to `file(1)`
/// while still giving a human something recognisable in a hexdump.
const HEADER_MAGIC: &[u8; 31] =
    b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";

/// `DetachedTimestampFile` major version this module writes and accepts.
const MAJOR_VERSION: u8 = 1;

/// `OpSHA256` tag: the file-hash operation this module records. The ledger
/// head is already a 32-byte digest built from SHA-256 output, so this is the
/// closest accurate label for what kind of digest is being anchored, not a
/// claim that a plain SHA-256 was taken over some other file.
const OP_SHA256: u8 = 0x08;
const OP_SHA1: u8 = 0x02;
const OP_RIPEMD160: u8 = 0x03;
const OP_KECCAK256: u8 = 0x67;
const OP_APPEND: u8 = 0xf0;
const OP_PREPEND: u8 = 0xf1;
const OP_REVERSE: u8 = 0xf2;
const OP_HEXLIFY: u8 = 0xf3;

const PENDING_ATTESTATION_TAG: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const BITCOIN_ATTESTATION_TAG: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];

/// Recursion depth allowed while walking a timestamp tree.
///
/// Matches the reference implementation's own default, which exists for the
/// same reason it does here: nothing about a legitimate calendar proof nests
/// this deep, so a proof that does is malformed or adversarial either way.
const MAX_TREE_DEPTH: u32 = 256;

/// Maximum bytes read back from a calendar response.
///
/// The reference client imposes the same limit on the same call for the same
/// reason: a calendar has no cause to answer a single-digest submission with
/// more than a few hundred bytes, and a client that reads an unbounded body
/// can be made to hold an unbounded amount of it.
const CALENDAR_RESPONSE_LIMIT: u64 = 10_000;

/// Anchors a digest to the public OpenTimestamps calendar network.
///
/// [`Anchor::stamp`] submits the digest to each configured aggregator in
/// turn and keeps the first response that succeeds. The reference client
/// submits to every aggregator concurrently and merges the results into one
/// proof carrying every calendar's attestation path; this does not — a
/// single successful submission is already enough to anchor the head, and
/// merging correctly is meaningfully more code for a benefit this project
/// does not need yet.
pub struct OpenTimestampsCalendar {
    aggregators: Vec<String>,
    timeout: Duration,
}

/// The public aggregator pool the reference OpenTimestamps client submits to
/// by default (`opentimestamps.calendar.DEFAULT_AGGREGATORS`). An aggregator
/// relays a digest to one or more calendars; the calendar to poll later for
/// an upgrade is the URI the proof itself comes back with, which need not be
/// any of these.
const DEFAULT_AGGREGATORS: [&str; 4] = [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
];

impl Default for OpenTimestampsCalendar {
    fn default() -> Self {
        Self {
            aggregators: DEFAULT_AGGREGATORS
                .iter()
                .map(|url| (*url).to_owned())
                .collect(),
            timeout: Duration::from_secs(20),
        }
    }
}

impl Anchor for OpenTimestampsCalendar {
    fn stamp(&self, head: [u8; 32]) -> Result<AnchorProof> {
        if self.aggregators.is_empty() {
            return Err("no aggregator configured".to_owned());
        }

        let mut last_error = String::new();
        for url in &self.aggregators {
            match submit_digest(url, &head, self.timeout) {
                Ok(response) => {
                    let mut bytes =
                        Vec::with_capacity(HEADER_MAGIC.len() + 2 + head.len() + response.len());
                    bytes.extend_from_slice(HEADER_MAGIC);
                    bytes.push(MAJOR_VERSION);
                    bytes.push(OP_SHA256);
                    bytes.extend_from_slice(&head);
                    bytes.extend_from_slice(&response);
                    return Ok(AnchorProof { bytes });
                }
                Err(error) => last_error = format!("{url}: {error}"),
            }
        }
        Err(format!(
            "every aggregator refused the submission; last error: {last_error}"
        ))
    }

    fn verify(&self, head: [u8; 32], proof: &AnchorProof) -> Result<AnchorStatus> {
        let parsed = parse_proof(&proof.bytes)?;
        if parsed.digest != head {
            return Err(format!(
                "anchor mismatch: proof commits to {}, ledger head is {}",
                hex::encode(&parsed.digest),
                hex::encode(&head)
            ));
        }
        status_of(&parsed.attestations)
    }
}

/// Submits `digest` to one aggregator and returns its raw response body.
///
/// The endpoint, method, headers and size limit reproduce
/// `opentimestamps.calendar.RemoteCalendar.submit` in the reference client.
fn submit_digest(base_url: &str, digest: &[u8; 32], timeout: Duration) -> Result<Vec<u8>> {
    let endpoint = format!("{}/digest", base_url.trim_end_matches('/'));
    let response = ureq::post(&endpoint)
        .set("Accept", "application/vnd.opentimestamps.v1")
        .set("Content-Type", "application/octet-stream")
        .timeout(timeout)
        .send_bytes(digest)
        .map_err(|error| error.to_string())?;

    let mut body = Vec::new();
    response
        .into_reader()
        .take(CALENDAR_RESPONSE_LIMIT)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    if body.is_empty() {
        return Err("calendar returned an empty response".to_owned());
    }
    Ok(body)
}

/// An attestation found while walking a timestamp tree.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedAttestation {
    Pending(String),
    Bitcoin(u64),
    Other([u8; 8]),
}

/// A `DetachedTimestampFile`, reduced to what this module reports on.
struct ParsedProof {
    digest: [u8; 32],
    attestations: Vec<ParsedAttestation>,
}

/// Turns the attestations found in a proof into the status this module is
/// prepared to report.
///
/// A Bitcoin attestation, when present, is reported over a pending one: it is
/// strictly more information about the same underlying commitment. A proof
/// with no attestations at all is not a status this module has a name for —
/// every real calendar response carries at least a pending one — so that
/// case is reported as an error rather than silently folded into
/// [`AnchorStatus::Unattested`], which means something different for
/// [`NullAnchor`].
fn status_of(attestations: &[ParsedAttestation]) -> Result<AnchorStatus> {
    if let Some(height) = attestations
        .iter()
        .find_map(|attestation| match attestation {
            ParsedAttestation::Bitcoin(height) => Some(*height),
            _ => None,
        })
    {
        return Ok(AnchorStatus::BitcoinAttested { height });
    }

    let calendars: Vec<String> = attestations
        .iter()
        .filter_map(|attestation| match attestation {
            ParsedAttestation::Pending(uri) => Some(uri.clone()),
            _ => None,
        })
        .collect();
    if !calendars.is_empty() {
        return Ok(AnchorStatus::Pending { calendars });
    }

    Err("proof carries no attestations; this is not a valid calendar response".to_owned())
}

/// A bounds-checked cursor over a byte slice.
///
/// Every read is checked before it happens, because both the network and the
/// disk are untrusted input here — the same posture `registry.rs` takes with
/// `WireRecord`.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or("proof is truncated")?;
        let slice = self.data.get(self.pos..end).ok_or("proof is truncated")?;
        self.pos = end;
        Ok(slice)
    }

    fn read_byte(&mut self) -> Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    /// Reads a LEB128 variable-length unsigned integer, as
    /// `StreamDeserializationContext.read_varuint` does in the reference
    /// implementation.
    fn read_varuint(&mut self) -> Result<u64> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.read_byte()?;
            let digit = u64::from(byte & 0x7f);
            let shifted = digit
                .checked_shl(shift)
                .ok_or("varuint too large to represent")?;
            value |= shifted;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift >= 64 {
                return Err("varuint too large to represent".to_owned());
            }
        }
    }

    fn read_varbytes(&mut self, max_len: usize) -> Result<&'a [u8]> {
        let len = self.read_varuint()?;
        let len = usize::try_from(len).map_err(|_| "varbytes length too large".to_owned())?;
        if len > max_len {
            return Err(format!(
                "varbytes exceeds the {max_len}-byte limit for this field"
            ));
        }
        self.read_bytes(len)
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
}

/// Parses a `DetachedTimestampFile` and collects every attestation reachable
/// in its timestamp tree.
///
/// This walks the op tree structurally — reading each operation's tag and,
/// for a binary operation, its argument — without evaluating what any
/// operation computes. That is enough to find every attestation correctly,
/// because `TimeAttestation`'s wire format does not depend on the tree
/// position it was found at. It is also all this module needs: nothing here
/// checks a computed digest against a Bitcoin block header, so nothing here
/// needs to compute one. See the module docs for what that leaves unverified.
fn parse_proof(bytes: &[u8]) -> Result<ParsedProof> {
    let mut cursor = Cursor::new(bytes);

    let magic = cursor.read_bytes(HEADER_MAGIC.len())?;
    if magic != HEADER_MAGIC.as_slice() {
        return Err("not an OpenTimestamps proof: header magic does not match".to_owned());
    }
    let major = cursor.read_byte()?;
    if major != MAJOR_VERSION {
        return Err(format!(
            "unsupported OpenTimestamps major version {major}; this build supports {MAJOR_VERSION}"
        ));
    }

    let hash_op = cursor.read_byte()?;
    let digest_len = match hash_op {
        OP_SHA1 | OP_RIPEMD160 => 20,
        OP_SHA256 | OP_KECCAK256 => 32,
        other => {
            return Err(format!(
                "unrecognised file hash operation tag 0x{other:02x}"
            ))
        }
    };
    let digest_bytes = cursor.read_bytes(digest_len)?;
    let digest: [u8; 32] = digest_bytes
        .try_into()
        .map_err(|_| "this build only anchors 32-byte digests".to_owned())?;

    let mut attestations = Vec::new();
    collect_attestations(&mut cursor, &mut attestations, 0)?;
    if cursor.remaining() != 0 {
        return Err("trailing bytes after the timestamp tree".to_owned());
    }

    Ok(ParsedProof {
        digest,
        attestations,
    })
}

/// Walks one `Timestamp` node: zero or more `0xff`-prefixed entries followed
/// by exactly one unprefixed entry, each entry being either an attestation
/// (tag `0x00`) or an operation carrying a nested `Timestamp`. Mirrors
/// `Timestamp.deserialize` in the reference implementation.
fn collect_attestations(
    cursor: &mut Cursor,
    out: &mut Vec<ParsedAttestation>,
    depth: u32,
) -> Result<()> {
    if depth >= MAX_TREE_DEPTH {
        return Err("timestamp tree exceeds the maximum nesting depth".to_owned());
    }

    loop {
        let tag = cursor.read_byte()?;
        if tag == 0xff {
            let inner = cursor.read_byte()?;
            visit_entry(cursor, inner, out, depth)?;
        } else {
            return visit_entry(cursor, tag, out, depth);
        }
    }
}

fn visit_entry(
    cursor: &mut Cursor,
    tag: u8,
    out: &mut Vec<ParsedAttestation>,
    depth: u32,
) -> Result<()> {
    if tag == 0x00 {
        out.push(parse_attestation(cursor)?);
        return Ok(());
    }
    skip_op_argument(cursor, tag)?;
    collect_attestations(cursor, out, depth + 1)
}

/// Consumes an operation's argument, if it has one.
///
/// A unary operation (a hash, `reverse`, or `hexlify`) is nothing but its
/// tag, already consumed by the caller. A binary operation (`append` or
/// `prepend`) carries a length-prefixed argument that must be consumed to
/// keep the cursor aligned with the next entry, even though this module never
/// evaluates what the operation produces.
fn skip_op_argument(cursor: &mut Cursor, tag: u8) -> Result<()> {
    match tag {
        OP_SHA1 | OP_RIPEMD160 | OP_SHA256 | OP_KECCAK256 | OP_REVERSE | OP_HEXLIFY => Ok(()),
        OP_APPEND | OP_PREPEND => {
            cursor.read_varbytes(4096)?;
            Ok(())
        }
        other => Err(format!(
            "unrecognised timestamp operation tag 0x{other:02x}; cannot continue walking the proof"
        )),
    }
}

/// Parses one `TimeAttestation`: an 8-byte tag, then a length-prefixed
/// payload whose shape depends on that tag.
fn parse_attestation(cursor: &mut Cursor) -> Result<ParsedAttestation> {
    let tag: [u8; 8] = cursor
        .read_bytes(8)?
        .try_into()
        .expect("read_bytes(8) returns exactly 8 bytes");
    let payload = cursor.read_varbytes(8192)?;
    let mut payload_cursor = Cursor::new(payload);

    let attestation = if tag == PENDING_ATTESTATION_TAG {
        let uri_bytes = payload_cursor.read_varbytes(1000)?;
        let uri = std::str::from_utf8(uri_bytes)
            .map_err(|_| "pending-attestation URI is not valid UTF-8".to_owned())?
            .to_owned();
        ParsedAttestation::Pending(uri)
    } else if tag == BITCOIN_ATTESTATION_TAG {
        let height = payload_cursor.read_varuint()?;
        ParsedAttestation::Bitcoin(height)
    } else {
        ParsedAttestation::Other(tag)
    };

    if payload_cursor.remaining() != 0 {
        return Err("attestation payload has trailing bytes".to_owned());
    }
    Ok(attestation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn null_anchor_and_head() -> (NullAnchor, [u8; 32]) {
        (NullAnchor, [0x42u8; 32])
    }

    #[test]
    fn a_null_anchor_round_trips() {
        let (anchor, head) = null_anchor_and_head();
        let proof = anchor.stamp(head).unwrap();
        assert_eq!(anchor.verify(head, &proof), Ok(AnchorStatus::Unattested));
    }

    #[test]
    fn a_null_anchor_rejects_a_mismatched_head() {
        let (anchor, head) = null_anchor_and_head();
        let proof = anchor.stamp(head).unwrap();
        assert!(anchor.verify([0x99u8; 32], &proof).is_err());
    }

    #[test]
    fn a_null_anchor_rejects_a_real_proof() {
        let calendar = OpenTimestampsCalendar::default();
        let real = build_ots_bytes(&[0x11u8; 32], &pending_attestation("https://a.example/cal"));
        let foreign = AnchorProof { bytes: real };
        assert!(NullAnchor.verify([0x11u8; 32], &foreign).is_err());
        // And the reverse: a calendar client does not accept a null proof either.
        let (_, head) = null_anchor_and_head();
        let null_proof = NullAnchor.stamp(head).unwrap();
        assert!(calendar.verify(head, &null_proof).is_err());
    }

    /// Builds the bytes a real `DetachedTimestampFile` would contain around a
    /// single already-serialised `TimeAttestation`.
    fn build_ots_bytes(digest: &[u8; 32], attestation: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(HEADER_MAGIC);
        bytes.push(MAJOR_VERSION);
        bytes.push(OP_SHA256);
        bytes.extend_from_slice(digest);
        // A lone attestation is a `Timestamp` with no ops: serialised as a bare
        // `0x00` tag followed by the attestation, per `Timestamp.serialize`.
        bytes.push(0x00);
        bytes.extend_from_slice(attestation);
        bytes
    }

    fn pending_attestation(uri: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PENDING_ATTESTATION_TAG);
        let mut payload = Vec::new();
        write_varuint(&mut payload, uri.len() as u64);
        payload.extend_from_slice(uri.as_bytes());
        write_varuint(&mut bytes, payload.len() as u64);
        bytes.extend_from_slice(&payload);
        bytes
    }

    fn bitcoin_attestation(height: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&BITCOIN_ATTESTATION_TAG);
        let mut payload = Vec::new();
        write_varuint(&mut payload, height);
        write_varuint(&mut bytes, payload.len() as u64);
        bytes.extend_from_slice(&payload);
        bytes
    }

    fn write_varuint(out: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    #[test]
    fn a_pending_proof_reports_its_calendar() {
        let digest = [0x11u8; 32];
        let bytes = build_ots_bytes(&digest, &pending_attestation("https://alice.example/cal"));
        let calendar = OpenTimestampsCalendar::default();
        let proof = AnchorProof { bytes };
        assert_eq!(
            calendar.verify(digest, &proof),
            Ok(AnchorStatus::Pending {
                calendars: vec!["https://alice.example/cal".to_owned()]
            })
        );
    }

    #[test]
    fn a_bitcoin_attested_proof_reports_its_height() {
        let digest = [0x22u8; 32];
        let bytes = build_ots_bytes(&digest, &bitcoin_attestation(861_000));
        let calendar = OpenTimestampsCalendar::default();
        let proof = AnchorProof { bytes };
        assert_eq!(
            calendar.verify(digest, &proof),
            Ok(AnchorStatus::BitcoinAttested { height: 861_000 })
        );
    }

    #[test]
    fn a_digest_mismatch_is_rejected() {
        let bytes = build_ots_bytes(&[0x33u8; 32], &pending_attestation("https://a.example/cal"));
        let calendar = OpenTimestampsCalendar::default();
        let proof = AnchorProof { bytes };
        assert!(calendar.verify([0x44u8; 32], &proof).is_err());
    }

    #[test]
    fn a_bad_header_magic_is_rejected() {
        let mut bytes =
            build_ots_bytes(&[0x55u8; 32], &pending_attestation("https://a.example/cal"));
        bytes[0] ^= 0xff;
        let calendar = OpenTimestampsCalendar::default();
        let proof = AnchorProof { bytes };
        assert!(calendar.verify([0x55u8; 32], &proof).is_err());
    }

    #[test]
    fn an_unsupported_major_version_is_rejected() {
        let mut bytes =
            build_ots_bytes(&[0x66u8; 32], &pending_attestation("https://a.example/cal"));
        bytes[HEADER_MAGIC.len()] = MAJOR_VERSION + 1;
        let calendar = OpenTimestampsCalendar::default();
        let proof = AnchorProof { bytes };
        assert!(calendar.verify([0x66u8; 32], &proof).is_err());
    }

    #[test]
    fn a_truncated_proof_is_rejected_not_panicked_on() {
        let mut bytes =
            build_ots_bytes(&[0x77u8; 32], &pending_attestation("https://a.example/cal"));
        bytes.truncate(HEADER_MAGIC.len() + 10);
        let calendar = OpenTimestampsCalendar::default();
        let proof = AnchorProof { bytes };
        assert!(calendar.verify([0x77u8; 32], &proof).is_err());
    }

    #[test]
    fn an_unrecognised_operation_tag_is_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(HEADER_MAGIC);
        bytes.push(MAJOR_VERSION);
        bytes.push(OP_SHA256);
        bytes.extend_from_slice(&[0x88u8; 32]);
        bytes.push(0xaa); // not a recognised op tag, and not 0x00 either.
        let calendar = OpenTimestampsCalendar::default();
        let proof = AnchorProof { bytes };
        assert!(calendar.verify([0x88u8; 32], &proof).is_err());
    }

    #[test]
    fn an_op_chain_ending_in_an_attestation_is_walked_correctly() {
        // sha256(head) -> pending attestation, exercising the recursive
        // op-then-subtree branch rather than the bare-attestation shortcut.
        let digest = [0x99u8; 32];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(HEADER_MAGIC);
        bytes.push(MAJOR_VERSION);
        bytes.push(OP_SHA256);
        bytes.extend_from_slice(&digest);
        bytes.push(OP_SHA256); // last (and only) op: no 0xff prefix needed.
        bytes.push(0x00);
        bytes.extend_from_slice(&pending_attestation("https://bob.example/cal"));

        let calendar = OpenTimestampsCalendar::default();
        let proof = AnchorProof { bytes };
        assert_eq!(
            calendar.verify(digest, &proof),
            Ok(AnchorStatus::Pending {
                calendars: vec!["https://bob.example/cal".to_owned()]
            })
        );
    }

    #[test]
    fn multiple_branches_are_all_collected() {
        // Two attestations reachable via the 0xff-continuation form, per
        // `Timestamp.serialize`'s handling of more than one attestation.
        let digest = [0xaau8; 32];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(HEADER_MAGIC);
        bytes.push(MAJOR_VERSION);
        bytes.push(OP_SHA256);
        bytes.extend_from_slice(&digest);
        bytes.push(0xff);
        bytes.push(0x00);
        bytes.extend_from_slice(&pending_attestation("https://a.example/cal"));
        bytes.push(0x00);
        bytes.extend_from_slice(&bitcoin_attestation(700_000));

        let calendar = OpenTimestampsCalendar::default();
        let proof = AnchorProof { bytes };
        // A Bitcoin attestation takes priority in the reported status even
        // though a pending one is also present.
        assert_eq!(
            calendar.verify(digest, &proof),
            Ok(AnchorStatus::BitcoinAttested { height: 700_000 })
        );
    }

    #[test]
    fn a_proof_with_no_attestations_is_reported_as_an_error() {
        // Structurally well-formed but empty of attestations should not be
        // silently reported as `Unattested`, which means something different
        // for `NullAnchor`.
        assert!(status_of(&[]).is_err());
    }
}
