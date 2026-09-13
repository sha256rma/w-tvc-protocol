//! Destruction of setup entropy — the "toxic waste" — after key extraction.
//!
//! # Why the waste is dangerous
//!
//! Groth16's structural keys are derived from secret field elements sampled
//! during setup. Anyone holding those elements can forge a proof for a statement
//! that is false while still passing the verifier's pairing check. In the W-TVC
//! threat model that is the whole game: a lab that retains its setup entropy can
//! serve a cheaper model and still mint proofs that satisfy the frozen verifying
//! key, and no downstream wallet could tell. The commitment is only worth what
//! the destruction of the entropy is worth.
//!
//! # How destruction is implemented
//!
//! [`ToxicWaste`] owns every secret byte the ceremony touched at this layer: the
//! per-participant entropy and the aggregated ceremony seed derived from it. It
//! derives [`Zeroize`] and [`ZeroizeOnDrop`], which gives two independent paths
//! to erasure:
//!
//! 1. **Explicit.** [`ToxicWaste::burn`] consumes the value by move, overwrites
//!    the secret buffers, and returns a [`BurnAttestation`]. This is the path the
//!    ceremony actually takes, and it is the one that produces auditable
//!    evidence. Taking `self` by value makes the burn a type-level event: the
//!    handle is gone afterwards, so no later code path can read the entropy,
//!    because no later code path has anything to read it from.
//! 2. **Implicit.** If a ceremony aborts early and the value is simply dropped,
//!    `ZeroizeOnDrop` runs the same overwrite in `Drop`, before the allocator
//!    reclaims the pages. An error path that forgets to burn still erases.
//!
//! The overwrite itself is `core::ptr::write_volatile`. A plain `*buf = [0u8;32]`
//! on a value that is never read again is dead-store eliminated by LLVM — the
//! compiler is entitled to delete a write whose result is unobservable, which is
//! how naive zeroization silently becomes a no-op under `--release`. A volatile
//! write is defined as an observable side effect, so it survives optimisation.
//! `zeroize` additionally zeroes a `Vec`'s **entire capacity**, not merely its
//! initialised prefix, so residue past `len` is covered.
//!
//! # What this does not protect against
//!
//! Stating the limits precisely, because a ceremony that oversells its hygiene is
//! worse than one that documents it:
//!
//! - **Prior reallocations.** If a `Vec` holding secrets grew, the old heap
//!   buffer was already copied and freed, and this type cannot reach it. Secret
//!   buffers here are allocated once at their final size to avoid the growth path.
//! - **Register and stack spills.** Field elements pass through registers and
//!   stack slots that no destructor owns. `arkworks` copies `Fr` values freely
//!   inside its setup routines; those temporaries are outside this type's reach.
//!   This is the strongest reason a real deployment runs the ceremony on an
//!   ephemeral, air-gapped machine that is destroyed afterwards.
//! - **Swap, hibernation, and core dumps.** Pages can reach persistent storage
//!   before any overwrite runs. Operators should disable swap and core dumps for
//!   the ceremony process; `mlock` is a reasonable hardening step and is not
//!   attempted here because it needs privileges this library should not assume.
//! - **Panic paths under `panic = "abort"`.** The release profile aborts instead
//!   of unwinding, and an aborting process does not run destructors. The implicit
//!   drop path therefore covers ordinary early returns, not panics. Disabling
//!   core dumps is what covers the panic case.
//!
//! # What a real ceremony adds
//!
//! Honest scope: burning entropy on one machine reduces to trusting whoever ran
//! that machine. A production W-TVC ceremony runs a Phase-2 MPC in which each
//! participant applies their contribution to the accumulator, publishes a proof
//! of correct contribution, and destroys their own share independently. The
//! security claim then weakens from "trust the operator" to "trust that at least
//! one of N participants was honest". See [`crate::mpc_setup`] for where that
//! upgrade lands in this codebase.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::digest::{tagged_hash, DOMAIN_BURN_ATTESTATION};
use crate::hex;

/// Secret material produced by a ceremony that must never outlive key extraction.
///
/// Constructed by [`crate::mpc_setup::run_ceremony`] and normally consumed by
/// [`ToxicWaste::burn`] within the same function body.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ToxicWaste {
    ceremony_seed: [u8; 32],
    participant_entropy: Vec<[u8; 32]>,
}

impl ToxicWaste {
    /// Takes ownership of the ceremony's secret material.
    ///
    /// `participant_entropy` is collected into an exactly-sized allocation so the
    /// buffer is never grown, which removes the reallocation-residue path
    /// described in the module documentation.
    pub fn new(ceremony_seed: [u8; 32], participant_entropy: Vec<[u8; 32]>) -> Self {
        let mut exact = Vec::with_capacity(participant_entropy.len());
        exact.extend_from_slice(&participant_entropy);
        Self {
            ceremony_seed,
            participant_entropy: exact,
        }
    }

    /// Borrows the ceremony seed for the duration of key extraction.
    ///
    /// Deliberately a borrow rather than a copy: handing out an owned `[u8; 32]`
    /// would create a second copy with no destructor, defeating the entire
    /// module. The borrow cannot outlive the `ToxicWaste` that will erase it.
    pub const fn ceremony_seed(&self) -> &[u8; 32] {
        &self.ceremony_seed
    }

    /// Number of independent entropy contributions held.
    pub fn contribution_count(&self) -> usize {
        self.participant_entropy.len()
    }

    /// Total secret bytes under management.
    pub fn secret_len(&self) -> usize {
        self.ceremony_seed.len() + self.participant_entropy.len() * 32
    }

    /// Overwrites every secret byte in place without consuming the value.
    ///
    /// Provided for callers that must erase at a point where ownership cannot be
    /// surrendered. [`ToxicWaste::burn`] is preferable wherever ownership is
    /// available, because it also removes the handle.
    pub fn zeroize_now(&mut self) {
        self.zeroize();
    }

    /// Destroys the setup entropy and returns evidence that it happened.
    ///
    /// Consumes `self`; the `Drop` implementation installed by `ZeroizeOnDrop`
    /// performs the volatile overwrite as the value goes out of scope at the end
    /// of this call. The returned [`BurnAttestation`] contains no secret material
    /// and is safe to publish alongside the ceremony transcript.
    pub fn burn(self, transcript_digest: [u8; 32], vk_digest: [u8; 32]) -> BurnAttestation {
        let burned_bytes = self.secret_len();
        let contributions = self.contribution_count();

        let attestation_digest = tagged_hash(
            DOMAIN_BURN_ATTESTATION,
            &[
                &transcript_digest,
                &vk_digest,
                &(contributions as u64).to_be_bytes(),
                &(burned_bytes as u64).to_be_bytes(),
            ],
        );

        BurnAttestation {
            transcript_digest,
            vk_digest,
            contributions,
            burned_bytes,
            attestation_digest,
        }
    }
}

impl core::fmt::Debug for ToxicWaste {
    /// Renders shape only.
    ///
    /// A derived `Debug` would print the entropy into logs, tracing spans, and
    /// panic messages, which is a far more probable leak than any memory-residue
    /// attack this module defends against.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ToxicWaste")
            .field("ceremony_seed", &"[redacted; 32 bytes]")
            .field("contributions", &self.participant_entropy.len())
            .finish()
    }
}

/// Publishable, secret-free evidence that setup entropy was destroyed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BurnAttestation {
    /// Digest of the ceremony transcript whose entropy was destroyed.
    pub transcript_digest: [u8; 32],
    /// Digest of the verifying key the destroyed entropy produced.
    pub vk_digest: [u8; 32],
    /// Number of independent contributions destroyed.
    pub contributions: usize,
    /// Count of secret bytes overwritten.
    pub burned_bytes: usize,
    /// Tagged hash binding the fields above into a single citable value.
    pub attestation_digest: [u8; 32],
}

impl BurnAttestation {
    /// Lowercase hex rendering of [`Self::attestation_digest`].
    pub fn attestation_hex(&self) -> String {
        hex::encode(&self.attestation_digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_now_clears_every_secret_byte() {
        let mut waste = ToxicWaste::new([0xab; 32], vec![[0xcd; 32], [0xef; 32]]);
        assert_ne!(waste.ceremony_seed, [0u8; 32]);
        assert_eq!(waste.contribution_count(), 2);

        waste.zeroize_now();

        assert_eq!(waste.ceremony_seed, [0u8; 32]);
        assert!(waste.participant_entropy.is_empty());
    }

    #[test]
    fn burn_reports_the_volume_it_destroyed() {
        let waste = ToxicWaste::new([7u8; 32], vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
        let attestation = waste.burn([9u8; 32], [4u8; 32]);
        assert_eq!(attestation.contributions, 3);
        assert_eq!(attestation.burned_bytes, 32 + 3 * 32);
        assert_eq!(attestation.attestation_hex().len(), 64);
    }

    #[test]
    fn attestation_digest_binds_its_inputs() {
        let a = ToxicWaste::new([7u8; 32], vec![[1u8; 32]]).burn([9u8; 32], [4u8; 32]);
        let b = ToxicWaste::new([7u8; 32], vec![[1u8; 32]]).burn([9u8; 32], [5u8; 32]);
        assert_ne!(a.attestation_digest, b.attestation_digest);
    }

    #[test]
    fn debug_never_renders_entropy() {
        let waste = ToxicWaste::new([0x41; 32], vec![[0x42; 32]]);
        let rendered = format!("{waste:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("41"));
    }
}
