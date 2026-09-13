//! Domain-separated hashing for every commitment the protocol publishes.
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
//! prefix is fixed per tag. The security property that matters here is domain
//! separation: a verifying-key digest and a ceremony-transcript digest are both
//! 32 bytes over caller-controlled input, and without distinct tags an adversary
//! could try to present one as the other. Reusing Bitcoin's own construction,
//! rather than inventing a scheme, keeps W-TVC digests auditable by anyone who
//! already knows BIP-340.
//!
//! # Length prefixing
//!
//! Each message part is prefixed with its length as a big-endian `u64` before
//! being absorbed. Plain concatenation is ambiguous — `("ab", "c")` and
//! `("a", "bc")` hash identically — which would let a participant identifier
//! absorb bytes from an adjacent field and forge a transcript entry that appears
//! to commit to something it does not. Length prefixing makes the encoding
//! injective, so one digest corresponds to exactly one tuple of inputs.

use bitcoin_hashes::{sha256, HashEngine};

/// Tag for the aggregated ceremony RNG seed.
pub const DOMAIN_CEREMONY_SEED: &str = "W-TVC/v1/ceremony-seed";
/// Tag for an individual participant's entropy commitment.
pub const DOMAIN_CONTRIBUTION: &str = "W-TVC/v1/contribution";
/// Tag for the running ceremony transcript hash chain.
pub const DOMAIN_TRANSCRIPT: &str = "W-TVC/v1/transcript";
/// Tag binding a model descriptor to its ceremony.
pub const DOMAIN_MODEL_BINDING: &str = "W-TVC/v1/model-binding";
/// Tag for the 32-byte functional verification digest of a verifying key.
pub const DOMAIN_VK_DIGEST: &str = "W-TVC/v1/vk-digest";
/// Tag for the toxic-waste burn attestation.
pub const DOMAIN_BURN_ATTESTATION: &str = "W-TVC/v1/burn-attestation";
/// Tag for the BIP-340 sighash over a published parameter commitment.
pub const DOMAIN_COMMITMENT_SIGHASH: &str = "W-TVC/v1/commitment-sighash";

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

/// Folds a new element into a running hash chain.
///
/// Used to build the ceremony transcript so that each entry commits to every
/// entry before it. Truncating or reordering contributions changes the final
/// digest, which is what makes the published transcript auditable after the fact.
pub fn chain(tag: &str, previous: &[u8; 32], element: &[u8]) -> [u8; 32] {
    tagged_hash(tag, &[previous.as_slice(), element])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_tags_separate_identical_messages() {
        let message: &[u8] = b"same bytes";
        assert_ne!(
            tagged_hash(DOMAIN_VK_DIGEST, &[message]),
            tagged_hash(DOMAIN_TRANSCRIPT, &[message])
        );
    }

    #[test]
    fn length_prefixing_removes_concatenation_ambiguity() {
        assert_ne!(
            tagged_hash(DOMAIN_TRANSCRIPT, &[b"ab", b"c"]),
            tagged_hash(DOMAIN_TRANSCRIPT, &[b"a", b"bc"])
        );
    }

    #[test]
    fn chain_is_order_dependent() {
        let base = [0u8; 32];
        let forward = chain(DOMAIN_TRANSCRIPT, &chain(DOMAIN_TRANSCRIPT, &base, b"a"), b"b");
        let reverse = chain(DOMAIN_TRANSCRIPT, &chain(DOMAIN_TRANSCRIPT, &base, b"b"), b"a");
        assert_ne!(forward, reverse);
    }

    #[test]
    fn matches_bip340_reference_construction() {
        let tag = "W-TVC/v1/vk-digest";
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
