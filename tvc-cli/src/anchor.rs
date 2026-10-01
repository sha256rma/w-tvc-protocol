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

use bitcoin_hashes::{ripemd160, sha1};
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
        let bytes =
            std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
        Ok(Self { bytes })
    }

    /// The digest this proof commits to, read from either proof format.
    ///
    /// A verifier uses this to ask "which ledger head was anchored", which can
    /// differ from the current head once the ledger has grown.
    ///
    /// # Errors
    ///
    /// Returns a message if the bytes are neither a null-anchor proof nor a
    /// parseable OpenTimestamps file.
    pub fn committed_digest(&self) -> Result<[u8; 32]> {
        if self.is_null() {
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&self.bytes[NULL_MAGIC.len()..]);
            return Ok(digest);
        }
        Ok(parse_proof(&self.bytes)?.digest)
    }

    /// Whether this is a [`NullAnchor`] proof, which no outside party saw.
    pub fn is_null(&self) -> bool {
        self.bytes.len() == NULL_MAGIC.len() + 32 && self.bytes.starts_with(NULL_MAGIC)
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
        /// The merkle root the proof says that block commits to, in the byte
        /// order a block header stores it. Block explorers print it reversed.
        merkle_root: Vec<u8>,
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
        status_of(&parsed.found)
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

/// One operation on the path from the anchored digest to an attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    /// A hash, `reverse`, or `hexlify`: the tag is the whole operation.
    Unary(u8),
    Append(Vec<u8>),
    Prepend(Vec<u8>),
}

/// Largest message an operation may take or produce, from the reference
/// implementation's `Op.MAX_MSG_LENGTH`. Keeps a hostile proof from growing
/// a message without bound.
const MAX_MSG_LEN: usize = 4096;

impl Op {
    fn read(cursor: &mut Cursor, tag: u8) -> Result<Self> {
        match tag {
            OP_SHA1 | OP_RIPEMD160 | OP_SHA256 | OP_KECCAK256 | OP_REVERSE | OP_HEXLIFY => {
                Ok(Self::Unary(tag))
            }
            OP_APPEND => Ok(Self::Append(cursor.read_varbytes(MAX_MSG_LEN)?.to_vec())),
            OP_PREPEND => Ok(Self::Prepend(cursor.read_varbytes(MAX_MSG_LEN)?.to_vec())),
            other => Err(format!(
                "unrecognised timestamp operation tag 0x{other:02x}; cannot continue walking the proof"
            )),
        }
    }

    /// Computes what this operation turns `msg` into.
    fn apply(&self, msg: &[u8]) -> Result<Vec<u8>> {
        if msg.len() > MAX_MSG_LEN {
            return Err("message on the proof path is too long".to_owned());
        }
        let result = match self {
            Self::Append(arg) => [msg, arg].concat(),
            Self::Prepend(arg) => [arg.as_slice(), msg].concat(),
            Self::Unary(OP_SHA256) => tvc_core::canonical::sha256_bytes(msg).to_vec(),
            Self::Unary(OP_SHA1) => sha1::Hash::hash(msg).to_byte_array().to_vec(),
            Self::Unary(OP_RIPEMD160) => ripemd160::Hash::hash(msg).to_byte_array().to_vec(),
            Self::Unary(OP_REVERSE) | Self::Unary(OP_HEXLIFY) if msg.is_empty() => {
                return Err("reverse or hexlify of an empty message".to_owned())
            }
            Self::Unary(OP_REVERSE) => msg.iter().rev().copied().collect(),
            Self::Unary(OP_HEXLIFY) => hex::encode(msg).into_bytes(),
            Self::Unary(OP_KECCAK256) => {
                return Err(
                    "keccak256 appears on this proof path; it is only used by Ethereum calendars, which this build does not follow"
                        .to_owned(),
                )
            }
            Self::Unary(other) => return Err(format!("unrecognised operation 0x{other:02x}")),
        };
        if result.len() > MAX_MSG_LEN {
            return Err("message on the proof path is too long".to_owned());
        }
        Ok(result)
    }

    fn serialize(&self, out: &mut Vec<u8>) {
        match self {
            Self::Unary(tag) => out.push(*tag),
            Self::Append(arg) | Self::Prepend(arg) => {
                out.push(if matches!(self, Self::Append(_)) { OP_APPEND } else { OP_PREPEND });
                write_varuint(out, arg.len() as u64);
                out.extend_from_slice(arg);
            }
        }
    }
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

/// An attestation with the message it attests and the operations leading to it.
#[derive(Debug, Clone)]
struct Found {
    attestation: ParsedAttestation,
    /// The message at the attested node. For a Bitcoin attestation this is the
    /// block's merkle root, in the byte order the header stores it.
    msg: Vec<u8>,
    /// Operations from the anchored digest down to this node.
    path: Vec<Op>,
}

/// A `DetachedTimestampFile`, reduced to what this module reports on.
struct ParsedProof {
    digest: [u8; 32],
    found: Vec<Found>,
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
fn status_of(found: &[Found]) -> Result<AnchorStatus> {
    if let Some((height, msg)) = found.iter().find_map(|f| match f.attestation {
        ParsedAttestation::Bitcoin(height) => Some((height, f.msg.clone())),
        _ => None,
    }) {
        return Ok(AnchorStatus::BitcoinAttested {
            height,
            merkle_root: msg,
        });
    }

    let calendars: Vec<String> = found
        .iter()
        .filter_map(|f| match &f.attestation {
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

/// Parses a `DetachedTimestampFile`, evaluating every operation, and collects
/// each attestation with the message it attests and the path to it.
///
/// The messages are what make two things possible: asking a calendar for an
/// upgraded proof (the calendar indexes commitments by the message at the
/// pending node), and telling a reader which merkle root to compare against
/// a Bitcoin block. What this does not do is fetch that block: confirming the
/// root is in the chain is left to the reader and a block explorer.
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

    let mut found = Vec::new();
    let mut path = Vec::new();
    collect(&mut cursor, &digest, &mut path, &mut found, 0)?;
    if cursor.remaining() != 0 {
        return Err("trailing bytes after the timestamp tree".to_owned());
    }

    Ok(ParsedProof { digest, found })
}

/// Walks one `Timestamp` node: zero or more `0xff`-prefixed entries followed
/// by exactly one unprefixed entry, each entry being either an attestation
/// (tag `0x00`) or an operation carrying a nested `Timestamp` over the
/// operation's result. Mirrors `Timestamp.deserialize` in the reference
/// implementation.
fn collect(
    cursor: &mut Cursor,
    msg: &[u8],
    path: &mut Vec<Op>,
    out: &mut Vec<Found>,
    depth: u32,
) -> Result<()> {
    if depth >= MAX_TREE_DEPTH {
        return Err("timestamp tree exceeds the maximum nesting depth".to_owned());
    }

    loop {
        let tag = cursor.read_byte()?;
        if tag == 0xff {
            let inner = cursor.read_byte()?;
            visit_entry(cursor, inner, msg, path, out, depth)?;
        } else {
            return visit_entry(cursor, tag, msg, path, out, depth);
        }
    }
}

fn visit_entry(
    cursor: &mut Cursor,
    tag: u8,
    msg: &[u8],
    path: &mut Vec<Op>,
    out: &mut Vec<Found>,
    depth: u32,
) -> Result<()> {
    if tag == 0x00 {
        out.push(Found {
            attestation: parse_attestation(cursor)?,
            msg: msg.to_vec(),
            path: path.clone(),
        });
        return Ok(());
    }
    let op = Op::read(cursor, tag)?;
    let next = op.apply(msg)?;
    path.push(op);
    let walked = collect(cursor, &next, path, out, depth + 1);
    path.pop();
    walked
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

/// Host suffixes of the calendars the reference client trusts by default
/// (`opentimestamps.calendar.DEFAULT_CALENDAR_WHITELIST`).
///
/// A pending attestation names a URL to poll. That URL comes out of a file, so
/// following it blindly would let a crafted proof point this tool at any
/// address. Only these calendars, over HTTPS, are contacted.
const CALENDAR_HOST_SUFFIXES: [&str; 3] = [
    ".calendar.opentimestamps.org",
    ".calendar.eternitywall.com",
    ".calendar.catallaxy.com",
];

/// Whether a pending attestation's calendar URI is one this tool will contact.
fn calendar_allowed(uri: &str) -> bool {
    let Some(rest) = uri.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or("");
    let charset_ok = uri
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-._/:".contains(&b));
    charset_ok
        && !host.contains(':')
        && CALENDAR_HOST_SUFFIXES
            .iter()
            .any(|suffix| host.ends_with(suffix) && host.len() > suffix.len())
}

/// Asks a calendar for its timestamp on `msg`. `None` means the calendar does
/// not have an upgrade yet (HTTP 404), which is the normal answer for the
/// first few hours.
fn fetch_timestamp(uri: &str, msg: &[u8], timeout: Duration) -> Result<Option<Vec<u8>>> {
    let url = format!("{}/timestamp/{}", uri.trim_end_matches('/'), hex::encode(msg));
    let response = match ureq::get(&url)
        .set("Accept", "application/vnd.opentimestamps.v1")
        .timeout(timeout)
        .call()
    {
        Ok(response) => response,
        Err(ureq::Error::Status(404, _)) => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let mut body = Vec::new();
    response
        .into_reader()
        .take(CALENDAR_RESPONSE_LIMIT)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    Ok(Some(body))
}

/// Builds a single-path proof: the anchored digest, the operations down to
/// one pending node, and the calendar's timestamp from that node on.
///
/// Valid OpenTimestamps by construction: a node with exactly one entry is
/// written as that entry with no `0xff` prefix, so a chain of operations is
/// just the operations in order, followed by the subtree the calendar sent.
fn single_path_proof(head: &[u8; 32], path: &[Op], subtree: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(HEADER_MAGIC);
    bytes.push(MAJOR_VERSION);
    bytes.push(OP_SHA256);
    bytes.extend_from_slice(head);
    for op in path {
        op.serialize(&mut bytes);
    }
    bytes.extend_from_slice(subtree);
    bytes
}

impl OpenTimestampsCalendar {
    /// Asks the calendars in a pending proof whether the commitment has been
    /// folded into a Bitcoin block yet, and if so returns the upgraded proof.
    ///
    /// Returns `Ok(None)` when the proof already carries a Bitcoin attestation
    /// or when no calendar has one yet. Only calendars on the reference
    /// client's default list are contacted.
    ///
    /// # Errors
    ///
    /// Returns a message if the proof does not commit to `head`, or if every
    /// calendar contacted failed for a reason other than "not yet".
    pub fn upgrade(&self, head: [u8; 32], proof: &AnchorProof) -> Result<Option<AnchorProof>> {
        let parsed = parse_proof(&proof.bytes)?;
        if parsed.digest != head {
            return Err(format!(
                "anchor mismatch: proof commits to {}, ledger head is {}",
                hex::encode(&parsed.digest),
                hex::encode(&head)
            ));
        }
        if parsed
            .found
            .iter()
            .any(|f| matches!(f.attestation, ParsedAttestation::Bitcoin(_)))
        {
            return Ok(None);
        }

        let mut errors = Vec::new();
        for found in &parsed.found {
            let ParsedAttestation::Pending(uri) = &found.attestation else {
                continue;
            };
            if !calendar_allowed(uri) {
                errors.push(format!("{uri}: not a calendar this tool contacts"));
                continue;
            }
            match fetch_timestamp(uri, &found.msg, self.timeout) {
                Ok(None) => {}
                Ok(Some(subtree)) => {
                    let candidate = single_path_proof(&head, &found.path, &subtree);
                    let upgraded = parse_proof(&candidate)
                        .map_err(|error| format!("{uri}: calendar sent an unreadable timestamp: {error}"))?;
                    if upgraded
                        .found
                        .iter()
                        .any(|f| matches!(f.attestation, ParsedAttestation::Bitcoin(_)))
                    {
                        return Ok(Some(AnchorProof { bytes: candidate }));
                    }
                }
                Err(error) => errors.push(format!("{uri}: {error}")),
            }
        }
        let pending = parsed
            .found
            .iter()
            .filter(|f| matches!(f.attestation, ParsedAttestation::Pending(_)))
            .count();
        if pending > 0 && errors.len() == pending {
            return Err(errors.join("; "));
        }
        Ok(None)
    }
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
            Ok(AnchorStatus::BitcoinAttested { height: 861_000, merkle_root: digest.to_vec() })
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
            Ok(AnchorStatus::BitcoinAttested { height: 700_000, merkle_root: digest.to_vec() })
        );
    }

    #[test]
    fn a_proof_with_no_attestations_is_reported_as_an_error() {
        // Structurally well-formed but empty of attestations should not be
        // silently reported as `Unattested`, which means something different
        // for `NullAnchor`.
        assert!(status_of(&[]).is_err());
    }

    /// prepend, sha256, append, sha256: the shape of one step up a Bitcoin
    /// merkle path, computed here independently of the parser.
    fn merkle_step_ops(left: &[u8], right: &[u8]) -> (Vec<Op>, Vec<u8>) {
        let ops = vec![
            Op::Prepend(left.to_vec()),
            Op::Unary(OP_SHA256),
            Op::Append(right.to_vec()),
            Op::Unary(OP_SHA256),
        ];
        let digest = [0x5au8; 32];
        let first = tvc_core::canonical::sha256_bytes(&[left, &digest[..]].concat());
        let second = tvc_core::canonical::sha256_bytes(&[&first[..], right].concat());
        (ops, second.to_vec())
    }

    #[test]
    fn the_message_at_an_attestation_is_computed_along_its_path() {
        let digest = [0x5au8; 32];
        let (ops, expected) = merkle_step_ops(&[1u8; 32], &[2u8; 32]);
        let mut subtree = vec![0x00];
        subtree.extend_from_slice(&bitcoin_attestation(900_123));
        let bytes = single_path_proof(&digest, &ops, &subtree);

        let parsed = parse_proof(&bytes).unwrap();
        assert_eq!(parsed.found.len(), 1);
        assert_eq!(parsed.found[0].msg, expected);
        assert_eq!(parsed.found[0].path, ops);
        assert_eq!(
            OpenTimestampsCalendar::default().verify(digest, &AnchorProof { bytes }),
            Ok(AnchorStatus::BitcoinAttested {
                height: 900_123,
                merkle_root: expected
            })
        );
    }

    #[test]
    fn a_pending_path_and_a_calendar_subtree_join_into_one_valid_proof() {
        // The upgrade step: keep the operations down to the pending node, then
        // append whatever the calendar returns for that node's message.
        let digest = [0x5au8; 32];
        let (ops, _) = merkle_step_ops(&[3u8; 32], &[4u8; 32]);
        let mut pending = vec![0x00];
        pending.extend_from_slice(&pending_attestation("https://alice.btc.calendar.opentimestamps.org"));
        let original = parse_proof(&single_path_proof(&digest, &ops, &pending)).unwrap();
        let node = &original.found[0];

        // A calendar's answer: two more operations, then a Bitcoin attestation.
        let mut calendar = Vec::new();
        Op::Append(vec![9u8; 32]).serialize(&mut calendar);
        Op::Unary(OP_SHA256).serialize(&mut calendar);
        calendar.push(0x00);
        calendar.extend_from_slice(&bitcoin_attestation(900_200));

        let upgraded = parse_proof(&single_path_proof(&digest, &node.path, &calendar)).unwrap();
        let expected =
            tvc_core::canonical::sha256_bytes(&[node.msg.as_slice(), &[9u8; 32]].concat()).to_vec();
        assert_eq!(upgraded.found.len(), 1);
        assert_eq!(upgraded.found[0].attestation, ParsedAttestation::Bitcoin(900_200));
        assert_eq!(upgraded.found[0].msg, expected);
    }

    #[test]
    fn hexlify_reverse_and_keccak_behave_as_specified() {
        assert_eq!(Op::Unary(OP_HEXLIFY).apply(&[0xab, 0x01]).unwrap(), b"ab01".to_vec());
        assert_eq!(Op::Unary(OP_REVERSE).apply(&[1, 2, 3]).unwrap(), vec![3, 2, 1]);
        assert!(Op::Unary(OP_REVERSE).apply(&[]).is_err());
        assert!(Op::Unary(OP_HEXLIFY).apply(&[]).is_err());
        assert!(Op::Unary(OP_KECCAK256).apply(&[1]).is_err());
        // sha1 and ripemd160 of "abc", from their published test vectors.
        assert_eq!(
            hex::encode(&Op::Unary(OP_SHA1).apply(b"abc").unwrap()),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex::encode(&Op::Unary(OP_RIPEMD160).apply(b"abc").unwrap()),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
    }

    #[test]
    fn a_message_cannot_grow_past_the_limit() {
        let big = vec![0u8; MAX_MSG_LEN];
        assert!(Op::Append(vec![1]).apply(&big).is_err());
        assert!(Op::Unary(OP_HEXLIFY).apply(&vec![1u8; MAX_MSG_LEN / 2 + 1]).is_err());
    }

    #[test]
    fn only_known_calendars_over_https_are_contacted() {
        for good in [
            "https://alice.btc.calendar.opentimestamps.org",
            "https://bob.btc.calendar.opentimestamps.org/",
            "https://finney.calendar.eternitywall.com",
            "https://btc.calendar.catallaxy.com",
        ] {
            assert!(calendar_allowed(good), "{good}");
        }
        for bad in [
            "http://alice.btc.calendar.opentimestamps.org",
            "https://calendar.opentimestamps.org.evil.example",
            "https://evil.example/alice.btc.calendar.opentimestamps.org",
            "https://alice.btc.calendar.opentimestamps.org:8443",
            "https://.calendar.opentimestamps.org",
            "https://alice.btc.calendar.opentimestamps.org?x=1",
            "https://169.254.169.254",
        ] {
            assert!(!calendar_allowed(bad), "{bad}");
        }
    }
}
