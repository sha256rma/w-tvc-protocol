//! The SHA-256 Merkle tree under committed item sets.
//!
//! Levels are folded pairwise. When a level has an odd width, the final node is
//! **promoted** to the next level unchanged rather than hashed against a copy of
//! itself. Duplicating the last node is the classic Bitcoin CVE-2012-2459 shape,
//! where two different leaf counts yield one root. Promotion avoids the
//! duplication, and [`MerkleCommitment::length`] fixes the shape so a verifier
//! knows at which levels a promotion must have occurred.
//!
//! Callers hash their own leaves under their own tag (see [`crate::itemset`]);
//! this module only builds the tree, opens it and checks paths. Inner nodes are
//! hashed under [`DOMAIN_MERKLE_NODE`], whose value predates this module and is
//! kept so every root already in a ledger still verifies.

use crate::digest::{tagged_hash, DOMAIN_MERKLE_NODE};
use crate::error::{Result, TvcError};

/// A Merkle root together with the leaf count that fixes the tree's shape.
///
/// The length is part of the commitment rather than an argument to verification
/// because the tree's shape, and therefore which levels promote, is a function
/// of it. A verifier that did not know the length could not tell a canonical
/// path from a path with steps inserted or removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerkleCommitment {
    /// Root of the tree.
    pub tree_root: [u8; 32],
    /// Number of leaves.
    pub length: u64,
}

/// Proof that a committed tree holds a given leaf at a given index.
///
/// Only the sibling hashes are carried. Direction is derived from the index and
/// the number of steps from the length, so there is exactly one accepting proof
/// for any given fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleOpening {
    /// Sibling hashes from the leaf upwards, skipping promoted levels.
    pub siblings: Vec<[u8; 32]>,
}

fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    tagged_hash(DOMAIN_MERKLE_NODE, &[left, right])
}

/// A built tree that keeps every level, so openings are `O(log n)`.
#[derive(Clone, Debug)]
pub struct MerkleProver {
    /// Every level, leaves first, root last.
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleProver {
    /// Builds the tree over leaf hashes the caller has already computed.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::EmptyTree`] if there are no leaves.
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Result<Self> {
        if leaves.is_empty() {
            return Err(TvcError::EmptyTree);
        }

        let mut levels = vec![leaves];
        while levels.last().expect("non-empty").len() > 1 {
            let current = levels.last().expect("non-empty");
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut pairs = current.chunks_exact(2);
            for pair in &mut pairs {
                next.push(node(&pair[0], &pair[1]));
            }
            if let [promoted] = pairs.remainder() {
                next.push(*promoted);
            }
            levels.push(next);
        }
        Ok(Self { levels })
    }

    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    /// Whether the tree holds no leaves.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The root and leaf count this tree represents.
    pub fn commitment(&self) -> MerkleCommitment {
        MerkleCommitment {
            tree_root: *self
                .levels
                .last()
                .and_then(|top| top.first())
                .expect("non-empty"),
            length: self.len() as u64,
        }
    }

    /// Produces the canonical opening for one position.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::IndexOutOfRange`] if `index` is past the end.
    pub fn open(&self, index: usize) -> Result<MerkleOpening> {
        if index >= self.len() {
            return Err(TvcError::IndexOutOfRange {
                index,
                length: self.len(),
            });
        }

        let mut siblings = Vec::new();
        let mut position = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = position ^ 1;
            // A promoted node has no sibling at this level and emits no step.
            if sibling < level.len() {
                siblings.push(level[sibling]);
            }
            position /= 2;
        }
        Ok(MerkleOpening { siblings })
    }
}

/// Walks a canonical opening from a leaf hash to the root.
///
/// Direction comes from `index` and the expected step count from
/// `commitment.length`, so there is exactly one accepting path for any
/// (index, leaf) pair. Recomputing the level widths `W_k = ⌈W_{k-1}/2⌉` is what
/// makes promotion safe: a path with a step inserted at a promoted level, or
/// one removed at an unpromoted level, is rejected on step count.
pub(crate) fn verify_merkle_path(
    leaf: [u8; 32],
    index: usize,
    commitment: &MerkleCommitment,
    siblings: &[[u8; 32]],
) -> bool {
    if commitment.length == 0 || index as u64 >= commitment.length {
        return false;
    }

    let mut running = leaf;
    let mut position = index;
    let mut width = commitment.length as usize;
    let mut consumed = 0usize;

    while width > 1 {
        let sibling = position ^ 1;
        if sibling < width {
            let Some(hash) = siblings.get(consumed) else {
                return false; // path is shorter than the tree requires
            };
            running = if position % 2 == 1 {
                node(hash, &running)
            } else {
                node(&running, hash)
            };
            consumed += 1;
        }
        position /= 2;
        width = width.div_ceil(2);
    }

    // A path carrying steps the tree has no place for is rejected on shape.
    consumed == siblings.len() && running == commitment.tree_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: u8) -> Vec<[u8; 32]> {
        (0..n).map(|i| [i; 32]).collect()
    }

    #[test]
    fn every_position_opens_for_every_tree_width() {
        for n in 1..=9u8 {
            let tree = MerkleProver::from_leaves(leaves(n)).unwrap();
            let commitment = tree.commitment();
            for index in 0..n as usize {
                let opening = tree.open(index).unwrap();
                assert!(verify_merkle_path([index as u8; 32], index, &commitment, &opening.siblings));
            }
        }
    }

    #[test]
    fn a_wrong_leaf_or_index_is_rejected() {
        let tree = MerkleProver::from_leaves(leaves(5)).unwrap();
        let commitment = tree.commitment();
        let opening = tree.open(2).unwrap();
        assert!(!verify_merkle_path([9; 32], 2, &commitment, &opening.siblings));
        assert!(!verify_merkle_path([2; 32], 3, &commitment, &opening.siblings));
    }

    #[test]
    fn a_path_with_an_extra_step_is_rejected() {
        let tree = MerkleProver::from_leaves(leaves(5)).unwrap();
        let commitment = tree.commitment();
        let mut siblings = tree.open(4).unwrap().siblings;
        siblings.push([0; 32]);
        assert!(!verify_merkle_path([4; 32], 4, &commitment, &siblings));
    }

    #[test]
    fn an_empty_tree_and_an_out_of_range_index_are_refused() {
        assert_eq!(MerkleProver::from_leaves(vec![]).unwrap_err(), TvcError::EmptyTree);
        let tree = MerkleProver::from_leaves(leaves(3)).unwrap();
        assert!(matches!(tree.open(3), Err(TvcError::IndexOutOfRange { index: 3, length: 3 })));
    }
}
