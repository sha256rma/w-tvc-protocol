//! Committing to secret reference items now and revealing them one at a time.
//!
//! # The problem this solves
//!
//! A reference run is a set of prompts and the outputs the real model gave.
//! Publishing the prompts would let a provider recognise them and route only
//! those to the real model, so they stay secret. But a secret reference proves
//! nothing to anyone else. The way out is to publish a *commitment* to the set
//! now, and reveal individual items later, each with a short proof that it was
//! in the set all along.
//!
//! # Construction
//!
//! Each item is a JSON value. Its leaf is
//!
//! ```text
//! leaf_i = tagged_hash("W-TVC/v2/item-leaf", [i, salt_i, canonical(item_i)])
//! ```
//!
//! and the set's root is the canonical Merkle tree over the leaves, the same
//! tree and the same exactly-one-accepting-path openings as the weight
//! commitment uses. The index is in the leaf, so a revealed item cannot be
//! moved to another position. The 32-byte random salt is what keeps an
//! unrevealed item secret: without it, anyone could confirm a guess at a
//! short prompt ("What is the capital of Australia?") by hashing it. Salts are
//! kept privately with the items and revealed together with them.
//!
//! # Choosing items nobody can cherry-pick
//!
//! [`select`] derives which items to use or reveal from the root itself plus
//! a context string, in the Fiat–Shamir style. The root is fixed before the
//! selection is known, so neither SPOT nor an auditor can steer which items
//! get looked at.

use serde_json::{json, Value};

use crate::canonical::to_canonical_bytes;
use crate::commitment::{verify_merkle_path, MerkleCommitment, MerkleProver};
use crate::digest::{tagged_hash, DOMAIN_ITEM_LEAF, DOMAIN_ITEM_SELECT};
use crate::error::{Result, TvcError};
use crate::hex;

/// Length of the random salt mixed into every leaf.
pub const SALT_LEN: usize = 32;

/// Kind tag on the private file that holds items and salts.
pub const KIND_ITEM_SET_PRIVATE: &str = "item-set-private/v1";

/// Kind tag on a revealed item.
pub const KIND_ITEM_REVEAL: &str = "item-reveal/v1";

fn invalid(reason: impl Into<String>) -> TvcError {
    TvcError::InvalidDocument(reason.into())
}

/// Computes one item's leaf hash.
///
/// # Errors
///
/// Returns [`TvcError::InvalidDocument`] if the item has no canonical encoding.
pub fn item_leaf(index: u64, salt: &[u8; SALT_LEN], item: &Value) -> Result<[u8; 32]> {
    Ok(tagged_hash(
        DOMAIN_ITEM_LEAF,
        &[&index.to_be_bytes(), salt, &to_canonical_bytes(item)?],
    ))
}

/// A committed set of items, held privately by whoever committed to it.
#[derive(Clone, Debug)]
pub struct ItemSet {
    items: Vec<Value>,
    salts: Vec<[u8; SALT_LEN]>,
    prover: MerkleProver,
}

impl ItemSet {
    /// Commits to `items` under the given salts, one per item.
    ///
    /// Salts must come from a cryptographic randomness source. This crate has
    /// no entropy of its own; the CLI supplies operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::InvalidDocument`] for an empty set, a salt count that
    /// does not match the item count, or an item with no canonical encoding.
    pub fn commit(items: Vec<Value>, salts: Vec<[u8; SALT_LEN]>) -> Result<Self> {
        if items.is_empty() {
            return Err(invalid("an item set needs at least one item"));
        }
        if items.len() != salts.len() {
            return Err(invalid(format!(
                "{} items but {} salts",
                items.len(),
                salts.len()
            )));
        }
        let leaves = items
            .iter()
            .zip(&salts)
            .enumerate()
            .map(|(index, (item, salt))| item_leaf(index as u64, salt, item))
            .collect::<Result<Vec<_>>>()?;
        let prover = MerkleProver::from_leaves(leaves)?;
        Ok(Self {
            items,
            salts,
            prover,
        })
    }

    /// The public commitment: the tree root and the number of items.
    pub fn root(&self) -> MerkleCommitment {
        self.prover.commitment()
    }

    /// Number of items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the set is empty. Never true for a committed set.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The item at `index`, without its proof.
    pub fn item(&self, index: usize) -> Option<&Value> {
        self.items.get(index)
    }

    /// Reveals one item with the proof that it was in the committed set.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::IndexOutOfRange`] for an index past the end.
    pub fn reveal(&self, index: usize) -> Result<ItemReveal> {
        let opening = self.prover.open(index)?;
        Ok(ItemReveal {
            index: index as u64,
            count: self.items.len() as u64,
            salt: self.salts[index],
            item: self.items[index].clone(),
            siblings: opening.siblings,
        })
    }

    /// Renders the private file: every item with its salt, plus the root.
    ///
    /// This file must not be published. Anyone holding it can reveal any item.
    pub fn to_private_json(&self) -> Value {
        let root = self.root();
        let entries: Vec<Value> = self
            .items
            .iter()
            .zip(&self.salts)
            .map(|(item, salt)| json!({"salt": hex::encode(salt), "item": item}))
            .collect();
        json!({
            "kind": KIND_ITEM_SET_PRIVATE,
            "root": hex::encode(&root.tree_root),
            "count": root.length,
            "items": entries,
        })
    }

    /// Reads a private file back, recomputing the root and refusing a file
    /// whose items no longer hash to the root it records.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::InvalidDocument`] for a malformed file or a root mismatch.
    pub fn from_private_json(document: &Value) -> Result<Self> {
        if document.get("kind").and_then(Value::as_str) != Some(KIND_ITEM_SET_PRIVATE) {
            return Err(invalid("not an item-set-private/v1 file"));
        }
        let mut items = Vec::new();
        let mut salts = Vec::new();
        for entry in document
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("private item set has no items"))?
        {
            salts.push(hex::decode_array::<SALT_LEN>(
                entry
                    .get("salt")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("an item has no salt"))?,
            )?);
            items.push(
                entry
                    .get("item")
                    .cloned()
                    .ok_or_else(|| invalid("an entry has no item"))?,
            );
        }
        let set = Self::commit(items, salts)?;
        let recorded = document
            .get("root")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("private item set has no root"))?;
        if hex::encode(&set.root().tree_root) != recorded {
            return Err(invalid(
                "private item set does not hash to the root it records; it was edited",
            ));
        }
        Ok(set)
    }
}

/// One item, revealed, with the proof that it was committed at its position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemReveal {
    /// Position in the committed set.
    pub index: u64,
    /// Size of the committed set.
    pub count: u64,
    /// The item's salt.
    pub salt: [u8; SALT_LEN],
    /// The item itself.
    pub item: Value,
    /// Sibling hashes from the leaf to the root.
    pub siblings: Vec<[u8; 32]>,
}

impl ItemReveal {
    /// Checks this reveal against a published root and item count.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::InvalidDocument`] if the count disagrees with the
    /// published one or the item does not open against the root.
    pub fn verify(&self, root: &[u8; 32], count: u64) -> Result<()> {
        if self.count != count {
            return Err(invalid(format!(
                "reveal claims a set of {} items; the published set has {count}",
                self.count
            )));
        }
        let index = usize::try_from(self.index).map_err(|_| invalid("index out of range"))?;
        let leaf = item_leaf(self.index, &self.salt, &self.item)?;
        let commitment = MerkleCommitment {
            tree_root: *root,
            length: count,
        };
        if !verify_merkle_path(leaf, index, &commitment, &self.siblings) {
            return Err(invalid(format!(
                "item {} does not open against root {}",
                self.index,
                hex::encode(root)
            )));
        }
        Ok(())
    }

    /// Renders the reveal as a publishable document.
    pub fn to_json(&self) -> Value {
        let siblings: Vec<String> = self.siblings.iter().map(|s| hex::encode(s)).collect();
        json!({
            "kind": KIND_ITEM_REVEAL,
            "index": self.index,
            "count": self.count,
            "salt": hex::encode(&self.salt),
            "item": self.item,
            "siblings": siblings,
        })
    }

    /// Reads a reveal document.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::InvalidDocument`] for a malformed document.
    pub fn from_json(document: &Value) -> Result<Self> {
        if document.get("kind").and_then(Value::as_str) != Some(KIND_ITEM_REVEAL) {
            return Err(invalid("not an item-reveal/v1 document"));
        }
        let number = |key: &str| {
            document
                .get(key)
                .and_then(Value::as_u64)
                .ok_or_else(|| invalid(format!("reveal has no {key}")))
        };
        let siblings = document
            .get("siblings")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("reveal has no siblings"))?
            .iter()
            .map(|value| {
                hex::decode_array::<32>(value.as_str().ok_or_else(|| invalid("sibling is not hex"))?)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            index: number("index")?,
            count: number("count")?,
            salt: hex::decode_array::<SALT_LEN>(
                document
                    .get("salt")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("reveal has no salt"))?,
            )?,
            item: document
                .get("item")
                .cloned()
                .ok_or_else(|| invalid("reveal has no item"))?,
            siblings,
        })
    }
}

/// Picks `k` distinct item indices out of `count`, derived from `root` and
/// `context`.
///
/// Deterministic: anyone with the same inputs gets the same indices.
/// Unpredictable before `root` exists, so it cannot be steered. `context`
/// separates uses: a check run might pass the endpoint and date, an audit the
/// auditor's name. Indices come back sorted.
///
/// Each draw is a 64-bit integer from a counter-mode tagged hash, rejected
/// and redrawn if it falls in the final partial block of `u64` values, so every
/// index is equally likely.
///
/// # Errors
///
/// Returns [`TvcError::InvalidDocument`] if `count` is zero or `k > count`.
pub fn select(root: &[u8; 32], context: &[u8], count: u64, k: u64) -> Result<Vec<u64>> {
    if count == 0 || k > count {
        return Err(invalid(format!("cannot select {k} of {count} items")));
    }
    let limit = u64::MAX - (u64::MAX % count);
    let mut chosen = std::collections::BTreeSet::new();
    let mut counter = 0u64;
    while (chosen.len() as u64) < k {
        let digest = tagged_hash(DOMAIN_ITEM_SELECT, &[root, context, &counter.to_be_bytes()]);
        counter += 1;
        for chunk in digest.chunks_exact(8) {
            let draw = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk"));
            if draw < limit {
                chosen.insert(draw % count);
                if chosen.len() as u64 == k {
                    break;
                }
            }
        }
    }
    Ok(chosen.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(n: usize) -> ItemSet {
        let items = (0..n).map(|i| json!({"id": i, "prompt": format!("question {i}")})).collect();
        let salts = (0..n).map(|i| [i as u8 + 1; SALT_LEN]).collect();
        ItemSet::commit(items, salts).unwrap()
    }

    #[test]
    fn every_item_reveals_and_verifies_for_odd_and_even_sizes() {
        for n in [1usize, 2, 5, 8, 13] {
            let committed = set(n);
            let root = committed.root();
            for index in 0..n {
                let reveal = committed.reveal(index).unwrap();
                assert_eq!(reveal.verify(&root.tree_root, root.length), Ok(()), "n={n} i={index}");
                // And it survives the document round trip.
                let back = ItemReveal::from_json(&reveal.to_json()).unwrap();
                assert_eq!(back.verify(&root.tree_root, root.length), Ok(()));
            }
        }
    }

    #[test]
    fn an_altered_item_does_not_open() {
        let committed = set(5);
        let root = committed.root();
        let mut reveal = committed.reveal(2).unwrap();
        reveal.item = json!({"id": 2, "prompt": "an easier question"});
        assert!(reveal.verify(&root.tree_root, root.length).is_err());
    }

    #[test]
    fn a_wrong_salt_does_not_open() {
        let committed = set(5);
        let root = committed.root();
        let mut reveal = committed.reveal(2).unwrap();
        reveal.salt[0] ^= 1;
        assert!(reveal.verify(&root.tree_root, root.length).is_err());
    }

    #[test]
    fn a_reveal_cannot_be_moved_to_another_index() {
        let committed = set(6);
        let root = committed.root();
        let mut reveal = committed.reveal(2).unwrap();
        reveal.index = 3;
        assert!(reveal.verify(&root.tree_root, root.length).is_err());
    }

    #[test]
    fn a_truncated_or_padded_path_does_not_open() {
        let committed = set(9);
        let root = committed.root();
        let mut short = committed.reveal(4).unwrap();
        short.siblings.pop();
        assert!(short.verify(&root.tree_root, root.length).is_err());

        let mut long = committed.reveal(4).unwrap();
        long.siblings.push([0u8; 32]);
        assert!(long.verify(&root.tree_root, root.length).is_err());
    }

    #[test]
    fn a_reveal_claiming_another_set_size_is_refused() {
        let committed = set(4);
        let root = committed.root();
        let reveal = committed.reveal(1).unwrap();
        assert!(reveal.verify(&root.tree_root, root.length + 1).is_err());
    }

    #[test]
    fn the_salt_hides_a_guessable_item() {
        // Same item, different salts: different roots, so the root alone
        // confirms nothing about a guess.
        let item = vec![json!("What is the capital of Australia?")];
        let one = ItemSet::commit(item.clone(), vec![[1u8; SALT_LEN]]).unwrap();
        let two = ItemSet::commit(item, vec![[2u8; SALT_LEN]]).unwrap();
        assert_ne!(one.root().tree_root, two.root().tree_root);
    }

    #[test]
    fn item_leaves_are_separated_from_weight_leaves() {
        // Different domains, so a weight tree and an item tree over the same
        // bytes can never share a root.
        let leaf = item_leaf(0, &[0u8; SALT_LEN], &json!(0)).unwrap();
        let weight_leaf = tagged_hash(
            crate::digest::DOMAIN_WEIGHT_LEAF,
            &[&0u64.to_be_bytes(), &[0u8; 32]],
        );
        assert_ne!(leaf, weight_leaf);
    }

    #[test]
    fn the_private_file_round_trips_and_detects_edits() {
        let committed = set(4);
        let private = committed.to_private_json();
        let back = ItemSet::from_private_json(&private).unwrap();
        assert_eq!(back.root(), committed.root());

        let mut edited = private;
        edited["items"][1]["item"]["prompt"] = json!("swapped");
        assert!(ItemSet::from_private_json(&edited).is_err());
    }

    #[test]
    fn selection_is_deterministic_distinct_and_context_bound() {
        let root = set(50).root().tree_root;
        let first = select(&root, b"endpoint-a 2026-10-04", 50, 10).unwrap();
        assert_eq!(first, select(&root, b"endpoint-a 2026-10-04", 50, 10).unwrap());
        assert_eq!(first.len(), 10);
        assert!(first.windows(2).all(|w| w[0] < w[1]), "sorted and distinct");
        assert!(first.iter().all(|&i| i < 50));
        assert_ne!(first, select(&root, b"endpoint-b 2026-10-04", 50, 10).unwrap());
        // Selecting everything returns everything.
        assert_eq!(select(&root, b"x", 7, 7).unwrap(), (0..7).collect::<Vec<_>>());
        assert!(select(&root, b"x", 7, 8).is_err());
        assert!(select(&root, b"x", 0, 0).is_err());
    }
}
