//! Phase 1 — the Genesis Setup Ceremony.
//!
//! Runs once per model version. Consumes entropy from a set of participants,
//! synthesises the structural keys for [`crate::circuit::InferenceCircuit`],
//! derives the permanent 32-byte verification digest, destroys the entropy, and
//! emits an auditable transcript.
//!
//! # Trust model, stated without inflation
//!
//! **What this implementation provides.** An append-only, hash-chained
//! transcript over N independent entropy contributions. Each contribution is
//! committed under a domain-separated tag and folded into a running digest, so
//! the published transcript cannot be reordered, truncated, or extended after
//! the fact without changing [`CeremonyTranscript::final_digest`]. Every
//! participant can confirm their own contribution is present in the transcript
//! that produced the key. The setup RNG seed is derived from *all* contributions,
//! so no single participant chooses it alone.
//!
//! **What this implementation does not yet provide.** This is not a Phase-2 MPC.
//! The contributions are aggregated into one seed on one machine, which means
//! that at the instant of key extraction the combined entropy exists in a single
//! address space. The honest security claim is therefore *"trust the ceremony
//! operator, with a public transcript that makes participation auditable"* — not
//! the 1-of-N claim a real MPC delivers. Any document describing this code as
//! 1-of-N honest today would be wrong.
//!
//! **The upgrade path.** A true Phase-2 ceremony has each participant apply their
//! contribution to the accumulator on their own machine, publish a proof of
//! correct contribution, and destroy their own share locally; no machine ever
//! holds the combined secret. The interfaces in this module are shaped for that
//! substitution — [`ParticipantContribution`] becomes a contribution-with-proof
//! and [`run_ceremony`] becomes a round-driver — and nothing downstream of
//! [`CeremonyOutput`] changes when it lands. The digest, the burn attestation,
//! the BIP-340 commitment, the Nostr transport, and the wallet-side check are all
//! independent of how the key was produced.
//!
//! # Why the digest can be permanent
//!
//! Groth16's setup depends only on the R1CS *shape*, never on any witness. The
//! shape is fixed by the model architecture, so a verifying key computed once
//! remains valid for every inference that model will ever serve. That is what
//! makes a write-once Nostr commitment sufficient, and why no per-transaction
//! attestation service — or TEE — needs to sit on the runtime path.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::circuit::InferenceCircuit;
use crate::crypto_burn::{BurnAttestation, ToxicWaste};
use crate::digest::{
    chain, tagged_hash, DOMAIN_CEREMONY_SEED, DOMAIN_CONTRIBUTION, DOMAIN_MODEL_BINDING,
    DOMAIN_TRANSCRIPT, DOMAIN_VK_DIGEST,
};
use crate::error::{Result, TvcError};
use crate::hex;

/// Identifier for the proving system these keys belong to.
///
/// Absorbed into the verifying-key digest so a key from a different backend can
/// never collide with a W-TVC commitment even if its serialisation matched.
pub const SCHEME_TAG: &str = "groth16-bn254";

/// Immutable description of the model version being frozen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelDescriptor {
    /// Stable model identifier, for example `acme-llm-7b`.
    pub model_id: String,
    /// Version string for this frozen release, for example `2026.09`.
    pub version: String,
    /// Human-readable architecture summary recorded in the transcript.
    pub architecture: String,
    /// Declared parameter count, recorded so a downgrade is visible in metadata.
    pub parameter_count: u64,
}

impl ModelDescriptor {
    /// Builds a descriptor.
    pub fn new(
        model_id: impl Into<String>,
        version: impl Into<String>,
        architecture: impl Into<String>,
        parameter_count: u64,
    ) -> Self {
        Self {
            model_id: model_id.into(),
            version: version.into(),
            architecture: architecture.into(),
            parameter_count,
        }
    }

    /// Addressable identity of this model version.
    ///
    /// Doubles as the `d` tag of the Nostr commitment event, which is what makes
    /// the commitment addressable as `(kind, pubkey, d)`.
    pub fn address(&self) -> String {
        format!("{}:{}", self.model_id, self.version)
    }

    /// Digest binding every descriptor field into one value.
    pub fn binding_digest(&self) -> [u8; 32] {
        tagged_hash(
            DOMAIN_MODEL_BINDING,
            &[
                self.model_id.as_bytes(),
                self.version.as_bytes(),
                self.architecture.as_bytes(),
                &self.parameter_count.to_be_bytes(),
            ],
        )
    }
}

/// One participant's entropy contribution to the ceremony.
///
/// Holds secret material and erases it on drop, so a contribution that is
/// abandoned on an error path does not linger in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ParticipantContribution {
    participant_id: String,
    entropy: [u8; 32],
}

impl ParticipantContribution {
    /// Registers a participant's 32 bytes of entropy.
    ///
    /// The caller is responsible for sourcing `entropy` from a cryptographically
    /// secure generator; `tvc-cli` uses the operating system CSPRNG.
    pub fn new(participant_id: impl Into<String>, entropy: [u8; 32]) -> Self {
        Self {
            participant_id: participant_id.into(),
            entropy,
        }
    }

    /// Participant identifier as recorded in the transcript.
    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    /// Public commitment to this contribution.
    ///
    /// Published in the transcript so a participant can verify their entropy was
    /// included without the entropy itself ever being revealed.
    pub fn commitment(&self) -> [u8; 32] {
        tagged_hash(
            DOMAIN_CONTRIBUTION,
            &[self.participant_id.as_bytes(), &self.entropy],
        )
    }
}

impl core::fmt::Debug for ParticipantContribution {
    /// Renders the identifier and commitment, never the entropy.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParticipantContribution")
            .field("participant_id", &self.participant_id)
            .field("entropy", &"[redacted; 32 bytes]")
            .finish()
    }
}

/// A single audited entry in the ceremony transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContributionRecord {
    /// Zero-based position in the contribution order.
    pub index: u32,
    /// Participant identifier.
    pub participant_id: String,
    /// Public commitment to the participant's entropy.
    pub commitment: [u8; 32],
    /// Running transcript digest after folding this contribution in.
    pub running_digest: [u8; 32],
}

/// The full, publishable record of a ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeremonyTranscript {
    /// Model version this ceremony froze.
    pub model: ModelDescriptor,
    /// Ordered contribution records.
    pub records: Vec<ContributionRecord>,
    /// Terminal value of the hash chain over all contributions.
    pub final_digest: [u8; 32],
}

impl CeremonyTranscript {
    /// Recomputes the hash chain and confirms it reaches [`Self::final_digest`].
    ///
    /// This is the check a third-party auditor runs against a published
    /// transcript. It proves the records were not reordered, removed, or added to
    /// after the ceremony, given only the transcript itself.
    pub fn verify_chain(&self) -> bool {
        let mut running = self.model.binding_digest();
        for (position, record) in self.records.iter().enumerate() {
            if record.index as usize != position {
                return false;
            }
            running = fold(&running, record.index, &record.participant_id, &record.commitment);
            if running != record.running_digest {
                return false;
            }
        }
        running == self.final_digest
    }

    /// Confirms a named participant appears in the transcript.
    pub fn includes(&self, participant_id: &str) -> bool {
        self.records
            .iter()
            .any(|record| record.participant_id == participant_id)
    }
}

/// Everything a ceremony produces.
#[derive(Clone, Debug)]
pub struct CeremonyOutput {
    /// Canonically serialised Groth16 verifying key, compressed.
    pub verifying_key: Vec<u8>,
    /// Canonically serialised Groth16 proving key, compressed.
    pub proving_key: Vec<u8>,
    /// The permanent 32-byte functional verification digest.
    pub vk_digest: [u8; 32],
    /// Auditable transcript of contributions.
    pub transcript: CeremonyTranscript,
    /// Evidence that the setup entropy was destroyed.
    pub burn: BurnAttestation,
}

impl CeremonyOutput {
    /// Lowercase hex rendering of [`Self::vk_digest`].
    pub fn vk_digest_hex(&self) -> String {
        hex::encode(&self.vk_digest)
    }

    /// Lowercase hex rendering of the transcript's final digest.
    pub fn transcript_digest_hex(&self) -> String {
        hex::encode(&self.transcript.final_digest)
    }
}

/// Derives the permanent verification digest from a serialised verifying key.
///
/// Deliberately a function of the key bytes and the scheme tag alone, with no
/// model metadata mixed in. A wallet that has fetched a commitment from a relay
/// must be able to recompute this digest from the verifying key it was handed and
/// nothing else; binding model identity is the job of the signed commitment in
/// [`crate::proof_verifier`], not of the digest.
pub fn derive_vk_digest(verifying_key: &[u8]) -> [u8; 32] {
    tagged_hash(DOMAIN_VK_DIGEST, &[SCHEME_TAG.as_bytes(), verifying_key])
}

/// Executes a ceremony end to end.
///
/// Consumes `contributions` by value so that every participant's entropy is
/// erased when this function returns, on both the success and the error path.
///
/// # Errors
///
/// Returns [`TvcError::EmptyCeremony`] with no contributions, and
/// [`TvcError::DuplicateParticipant`] if two contributions share an identifier,
/// which would make the transcript ambiguous about who contributed what.
pub fn run_ceremony(
    model: ModelDescriptor,
    contributions: Vec<ParticipantContribution>,
) -> Result<CeremonyOutput> {
    if contributions.is_empty() {
        return Err(TvcError::EmptyCeremony);
    }
    for (position, contribution) in contributions.iter().enumerate() {
        if contributions[..position]
            .iter()
            .any(|earlier| earlier.participant_id == contribution.participant_id)
        {
            return Err(TvcError::DuplicateParticipant(
                contribution.participant_id.clone(),
            ));
        }
    }

    let mut running = model.binding_digest();
    let mut records = Vec::with_capacity(contributions.len());
    let mut entropy_pool = Vec::with_capacity(contributions.len());

    for (position, contribution) in contributions.iter().enumerate() {
        let index = position as u32;
        let commitment = contribution.commitment();
        running = fold(&running, index, contribution.participant_id(), &commitment);
        records.push(ContributionRecord {
            index,
            participant_id: contribution.participant_id().to_owned(),
            commitment,
            running_digest: running,
        });
        entropy_pool.push(contribution.entropy);
    }

    let transcript = CeremonyTranscript {
        model: model.clone(),
        records,
        final_digest: running,
    };

    let mut seed_parts: Vec<&[u8]> = Vec::with_capacity(entropy_pool.len() + 2);
    let model_binding = model.binding_digest();
    seed_parts.push(&model_binding);
    seed_parts.push(&transcript.final_digest);
    for entropy in &entropy_pool {
        seed_parts.push(entropy);
    }
    let ceremony_seed = tagged_hash(DOMAIN_CEREMONY_SEED, &seed_parts);
    drop(seed_parts);

    let waste = ToxicWaste::new(ceremony_seed, entropy_pool);

    let mut rng = StdRng::from_seed(*waste.ceremony_seed());
    let (proving_key, verifying_key) =
        Groth16::<Bn254>::circuit_specific_setup(InferenceCircuit::blueprint(), &mut rng)?;

    let mut verifying_key_bytes = Vec::new();
    verifying_key.serialize_compressed(&mut verifying_key_bytes)?;
    let mut proving_key_bytes = Vec::new();
    proving_key.serialize_compressed(&mut proving_key_bytes)?;

    let vk_digest = derive_vk_digest(&verifying_key_bytes);
    let burn = waste.burn(transcript.final_digest, vk_digest);

    Ok(CeremonyOutput {
        verifying_key: verifying_key_bytes,
        proving_key: proving_key_bytes,
        vk_digest,
        transcript,
        burn,
    })
}

/// Field element helper for callers assembling witnesses from integers.
pub fn field_from_u64(value: u64) -> Fr {
    Fr::from(value)
}

fn fold(previous: &[u8; 32], index: u32, participant_id: &str, commitment: &[u8; 32]) -> [u8; 32] {
    let mut element = Vec::with_capacity(4 + participant_id.len() + 32);
    element.extend_from_slice(&index.to_be_bytes());
    element.extend_from_slice(participant_id.as_bytes());
    element.extend_from_slice(commitment);
    chain(DOMAIN_TRANSCRIPT, previous, &element)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> ModelDescriptor {
        ModelDescriptor::new("acme-llm-7b", "2026.09", "affine-committed-inference", 7_000_000_000)
    }

    fn contributions() -> Vec<ParticipantContribution> {
        vec![
            ParticipantContribution::new("bitshala", [1u8; 32]),
            ParticipantContribution::new("acme-labs", [2u8; 32]),
            ParticipantContribution::new("independent-auditor", [3u8; 32]),
        ]
    }

    #[test]
    fn ceremony_produces_a_verifiable_transcript() {
        let output = run_ceremony(model(), contributions()).unwrap();
        assert!(output.transcript.verify_chain());
        assert_eq!(output.transcript.records.len(), 3);
        assert!(output.transcript.includes("bitshala"));
        assert_eq!(output.vk_digest_hex().len(), 64);
    }

    #[test]
    fn digest_is_a_pure_function_of_the_key() {
        let output = run_ceremony(model(), contributions()).unwrap();
        assert_eq!(derive_vk_digest(&output.verifying_key), output.vk_digest);
    }

    #[test]
    fn ceremony_is_deterministic_in_its_contributions() {
        let first = run_ceremony(model(), contributions()).unwrap();
        let second = run_ceremony(model(), contributions()).unwrap();
        assert_eq!(first.vk_digest, second.vk_digest);
        assert_eq!(first.transcript.final_digest, second.transcript.final_digest);
    }

    #[test]
    fn different_entropy_yields_a_different_key() {
        let baseline = run_ceremony(model(), contributions()).unwrap();
        let altered = run_ceremony(
            model(),
            vec![
                ParticipantContribution::new("bitshala", [9u8; 32]),
                ParticipantContribution::new("acme-labs", [2u8; 32]),
                ParticipantContribution::new("independent-auditor", [3u8; 32]),
            ],
        )
        .unwrap();
        assert_ne!(baseline.vk_digest, altered.vk_digest);
    }

    #[test]
    fn different_model_version_yields_a_different_key() {
        let baseline = run_ceremony(model(), contributions()).unwrap();
        let downgraded = run_ceremony(
            ModelDescriptor::new("acme-llm-7b", "2026.09", "affine-committed-inference", 1_500_000_000),
            contributions(),
        )
        .unwrap();
        assert_ne!(baseline.vk_digest, downgraded.vk_digest);
    }

    #[test]
    fn empty_and_duplicate_ceremonies_are_rejected() {
        assert_eq!(run_ceremony(model(), vec![]).unwrap_err(), TvcError::EmptyCeremony);
        let duplicated = vec![
            ParticipantContribution::new("same", [1u8; 32]),
            ParticipantContribution::new("same", [2u8; 32]),
        ];
        assert!(matches!(
            run_ceremony(model(), duplicated).unwrap_err(),
            TvcError::DuplicateParticipant(_)
        ));
    }

    #[test]
    fn reordered_transcript_fails_the_chain_check() {
        let output = run_ceremony(model(), contributions()).unwrap();
        let mut tampered = output.transcript.clone();
        tampered.records.swap(0, 1);
        assert!(!tampered.verify_chain());
    }

    #[test]
    fn truncated_transcript_fails_the_chain_check() {
        let output = run_ceremony(model(), contributions()).unwrap();
        let mut tampered = output.transcript.clone();
        tampered.records.pop();
        assert!(!tampered.verify_chain());
    }

    #[test]
    fn burn_attestation_matches_the_ceremony_it_describes() {
        let output = run_ceremony(model(), contributions()).unwrap();
        assert_eq!(output.burn.contributions, 3);
        assert_eq!(output.burn.vk_digest, output.vk_digest);
        assert_eq!(output.burn.transcript_digest, output.transcript.final_digest);
    }

    #[test]
    fn model_address_is_the_nostr_d_tag() {
        assert_eq!(model().address(), "acme-llm-7b:2026.09");
    }
}
