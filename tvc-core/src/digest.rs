//! Domain-separated hashing for every commitment this crate publishes.
//!
//! # Tagged hashing
//!
//! All digests use the BIP-340 tagged-hash construction:
//!
//! ```text
//!   tagged_hash(tag, m) = SHA256( SHA256(tag) || SHA256(tag) || m )
//! ```
//!
//! The doubled tag hash fills a full SHA-256 block, so the midstate after the
//! prefix is fixed per tag. The property that matters here is domain separation:
//! an item leaf, a Merkle internal node, and a ledger record digest are all 32
//! bytes over caller-controlled input. Without distinct tags an
//! adversary could present one as another — most sharply, offer a Merkle *leaf*
//! as if it were an internal node and claim a subtree that was never committed.
//! Reusing Bitcoin's construction rather than inventing one keeps these digests
//! auditable by anyone who already knows BIP-340.
//!
//! # Length prefixing
//!
//! Each message part is prefixed with its length as a big-endian `u64` before
//! being absorbed. Plain concatenation is ambiguous — `("ab", "c")` and
//! `("a", "bc")` hash identically — which would let a document kind absorb
//! bytes from an adjacent field and produce a signature that appears to commit to
//! something it does not. Length prefixing makes the encoding injective, so one
//! digest corresponds to exactly one tuple of inputs.

use bitcoin_hashes::{sha256, HashEngine};

/// Tag for an internal node of an item set's Merkle tree.
///
/// The value dates from when the same tree also committed to model weights. It
/// is kept as it was, because every item-set root already in a ledger was
/// computed under it.
pub const DOMAIN_MERKLE_NODE: &str = "W-TVC/v1/weight-node";
/// Tag for deriving a publisher signing scalar from caller-supplied entropy.
pub const DOMAIN_PUBLISHER_KEY: &str = "W-TVC/v1/publisher-key";
/// Tag for one salted reference item (a prompt or an output) in an item set.
pub const DOMAIN_ITEM_LEAF: &str = "W-TVC/v2/item-leaf";
/// Tag for deriving which items of a committed set get selected.
pub const DOMAIN_ITEM_SELECT: &str = "W-TVC/v2/item-select";
/// Prefix of the per-kind tag a document signature is computed under.
pub const DOMAIN_DOCUMENT_SIGHASH_PREFIX: &str = "W-TVC/v2/document/";
/// Tag for the record hash chain once documents are in the ledger.
pub const DOMAIN_LEDGER_DOCUMENT: &str = "W-TVC/v2/ledger-document";

/// Computes a BIP-340 tagged hash over length-prefixed message parts.
pub fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let tag_digest = sha256::Hash::hash(tag.as_bytes()).to_byte_array();

    let mut engine = sha256::Hash::engine();
    engine.input(&tag_digest);
    engine.input(&tag_digest);
    for part in parts {
        engine.input(&(part.len() as u64).to_be_bytes());
        engine.input(part);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_tags_separate_identical_messages() {
        let message: &[u8] = b"same bytes";
        assert_ne!(
            tagged_hash(DOMAIN_ITEM_LEAF, &[message]),
            tagged_hash(DOMAIN_MERKLE_NODE, &[message])
        );
    }

    #[test]
    fn length_prefixing_removes_concatenation_ambiguity() {
        assert_ne!(
            tagged_hash(DOMAIN_LEDGER_DOCUMENT, &[b"ab", b"c"]),
            tagged_hash(DOMAIN_LEDGER_DOCUMENT, &[b"a", b"bc"])
        );
    }

    #[test]
    fn matches_bip340_reference_construction() {
        let tag = "W-TVC/v2/ledger-document";
        let tag_digest = sha256::Hash::hash(tag.as_bytes()).to_byte_array();
        let mut engine = sha256::Hash::engine();
        engine.input(&tag_digest);
        engine.input(&tag_digest);
        engine.input(&(3u64).to_be_bytes());
        engine.input(b"abc");
        let expected = sha256::Hash::from_engine(engine).to_byte_array();
        assert_eq!(tagged_hash(tag, &[b"abc"]), expected);
    }
}
