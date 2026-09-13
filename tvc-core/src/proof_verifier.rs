//! Phase 2 — runtime verification, and the signed commitment that anchors it.
//!
//! # The check that does the work
//!
//! [`verify_inference`] performs two tests in a deliberate order:
//!
//! 1. **Commitment check.** Recompute the digest of the verifying key handed over
//!    at runtime and compare it to the digest fetched from a Nostr relay. A
//!    mismatch aborts immediately with [`TvcError::CommitmentMismatch`].
//! 2. **Pairing check.** Only then run Groth16 verification of the proof against
//!    that key and the claimed public inputs.
//!
//! The ordering is the security argument, not an optimisation. A provider that
//! substitutes a cheaper model can still produce proofs that are *internally
//! valid* — correct proofs about the wrong circuit. Running the pairing check
//! first and the commitment check second, or treating the two as interchangeable
//! booleans, would accept exactly the attack this protocol exists to stop. The
//! only key a wallet will verify against is the key the consortium froze.
//!
//! # Why the anchor is BIP-340
//!
//! [`ParameterCommitment`] is signed with a secp256k1 Schnorr signature over a
//! tagged sighash. That is the same curve and signature scheme as a Nostr event
//! signature, so the consortium's ceremony identity and its Nostr publishing
//! identity are one key. A wallet that trusts `npub1...` to publish commitments
//! is trusting a single well-defined public key, with no certificate chain, no
//! registry, and no attestation service on the runtime path.
//!
//! The digest itself is deliberately *not* bound to model metadata (see
//! [`crate::mpc_setup::derive_vk_digest`]); the signature is what binds a key to
//! a claimed model identity. Separating the two means a wallet can verify the key
//! it holds is the key that was committed using only arithmetic, and separately
//! decide whether it trusts the signer's claim about which model that key is.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use secp256k1::{schnorr, Keypair, SecretKey, XOnlyPublicKey};

use crate::circuit::InferenceCircuit;
use crate::digest::{tagged_hash, DOMAIN_COMMITMENT_SIGHASH};
use crate::error::{Result, TvcError};
use crate::hex;
use crate::mpc_setup::{derive_vk_digest, SCHEME_TAG};

/// A consortium's published claim about one frozen model version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParameterCommitment {
    /// Stable model identifier.
    pub model_id: String,
    /// Frozen version string.
    pub version: String,
    /// Proving system tag, always [`SCHEME_TAG`] for this release.
    pub scheme: String,
    /// The permanent 32-byte functional verification digest.
    pub vk_digest: [u8; 32],
    /// Final digest of the ceremony transcript that produced the key.
    pub transcript_digest: [u8; 32],
    /// Digest of the toxic-waste burn attestation.
    pub burn_digest: [u8; 32],
}

impl ParameterCommitment {
    /// Assembles a commitment from ceremony output.
    pub fn new(
        model_id: impl Into<String>,
        version: impl Into<String>,
        vk_digest: [u8; 32],
        transcript_digest: [u8; 32],
        burn_digest: [u8; 32],
    ) -> Self {
        Self {
            model_id: model_id.into(),
            version: version.into(),
            scheme: SCHEME_TAG.to_owned(),
            vk_digest,
            transcript_digest,
            burn_digest,
        }
    }

    /// Addressable identity, used as the Nostr `d` tag.
    pub fn address(&self) -> String {
        format!("{}:{}", self.model_id, self.version)
    }

    /// The 32-byte message signed by the consortium key.
    ///
    /// Covers every field, so a relay or a malicious republisher cannot pair a
    /// genuine signature with an altered model identity or a different digest.
    pub fn sighash(&self) -> [u8; 32] {
        tagged_hash(
            DOMAIN_COMMITMENT_SIGHASH,
            &[
                self.model_id.as_bytes(),
                self.version.as_bytes(),
                self.scheme.as_bytes(),
                &self.vk_digest,
                &self.transcript_digest,
                &self.burn_digest,
            ],
        )
    }

    /// Signs this commitment with a BIP-340 Schnorr signature.
    ///
    /// `aux_rand` is supplied by the caller rather than sampled internally so the
    /// signing path has no hidden entropy source and is reproducible under test.
    /// Production callers must pass fresh randomness from the operating system.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::Signature`] if `secret_key` is not a valid scalar.
    pub fn sign(&self, secret_key: &[u8; 32], aux_rand: &[u8; 32]) -> Result<SignedCommitment> {
        let secret = SecretKey::from_secret_bytes(*secret_key)?;
        let keypair = Keypair::from_secret_key(&secret);
        let (signer, _parity) = keypair.x_only_public_key();
        let sighash = self.sighash();
        let signature = schnorr::sign_with_aux_rand(&sighash, &keypair, aux_rand);

        Ok(SignedCommitment {
            commitment: self.clone(),
            signature: *signature.as_ref(),
            signer: signer.to_byte_array(),
        })
    }

    /// Lowercase hex rendering of [`Self::vk_digest`].
    pub fn vk_digest_hex(&self) -> String {
        hex::encode(&self.vk_digest)
    }
}

/// A [`ParameterCommitment`] carrying its BIP-340 signature and signer key.
///
/// This is the payload that travels in a kind `30200` Nostr event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCommitment {
    /// The signed claim.
    pub commitment: ParameterCommitment,
    /// 64-byte BIP-340 Schnorr signature over [`ParameterCommitment::sighash`].
    pub signature: [u8; 64],
    /// 32-byte x-only public key of the consortium, equal to the Nostr pubkey.
    pub signer: [u8; 32],
}

impl SignedCommitment {
    /// Verifies the signature against the embedded signer key.
    ///
    /// Establishes only that *this* key signed *this* claim. Deciding whether the
    /// key is the one a wallet should trust is policy, handled by
    /// [`Self::verify_signed_by`].
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::CommitmentUnsigned`] when verification fails.
    pub fn verify(&self) -> Result<()> {
        let pubkey = XOnlyPublicKey::from_byte_array(self.signer)?;
        let signature = schnorr::Signature::from_byte_array(self.signature);
        signature
            .verify(&self.commitment.sighash(), &pubkey)
            .map_err(|_| TvcError::CommitmentUnsigned)
    }

    /// Verifies the signature and pins it to an expected consortium key.
    ///
    /// This is what a wallet calls. Accepting any valid signature would let an
    /// arbitrary relay-published key vouch for a model, which is no trust anchor
    /// at all; the wallet must already know whose commitments it honours.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::CommitmentUnsigned`] if the signer differs from
    /// `expected_signer` or the signature does not verify.
    pub fn verify_signed_by(&self, expected_signer: &[u8; 32]) -> Result<()> {
        if &self.signer != expected_signer {
            return Err(TvcError::CommitmentUnsigned);
        }
        self.verify()
    }

    /// Lowercase hex rendering of the signer's x-only public key.
    pub fn signer_hex(&self) -> String {
        hex::encode(&self.signer)
    }

    /// Lowercase hex rendering of the signature.
    pub fn signature_hex(&self) -> String {
        hex::encode(&self.signature)
    }
}

/// A runtime inference proof together with its public inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceProof {
    /// Canonically serialised compressed Groth16 proof.
    pub proof: Vec<u8>,
    /// Public inputs in circuit allocation order.
    pub public_inputs: Vec<Fr>,
}

impl InferenceProof {
    /// Lowercase hex rendering of the serialised proof.
    pub fn proof_hex(&self) -> String {
        hex::encode(&self.proof)
    }

    /// Serialises the public inputs to hex strings for transport.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::Codec`] if a field element fails to serialise.
    pub fn public_inputs_hex(&self) -> Result<Vec<String>> {
        self.public_inputs
            .iter()
            .map(|value| {
                let mut bytes = Vec::new();
                value.serialize_compressed(&mut bytes)?;
                Ok(hex::encode(&bytes))
            })
            .collect()
    }

    /// Parses public inputs previously rendered by [`Self::public_inputs_hex`].
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::MalformedHex`] or [`TvcError::Codec`] on malformed input.
    pub fn public_inputs_from_hex(values: &[String]) -> Result<Vec<Fr>> {
        values
            .iter()
            .map(|text| {
                let bytes = hex::decode(text)?;
                Fr::deserialize_compressed(bytes.as_slice()).map_err(TvcError::from)
            })
            .collect()
    }
}

/// Outcome of a successful runtime verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationReport {
    /// Digest recomputed from the verifying key presented at runtime.
    pub observed_vk_digest: [u8; 32],
    /// True once the recomputed digest matched the published commitment.
    pub commitment_matched: bool,
    /// True once the Groth16 pairing check accepted the proof.
    pub proof_valid: bool,
}

impl VerificationReport {
    /// True only when both the commitment and the proof checks passed.
    pub const fn accepted(&self) -> bool {
        self.commitment_matched && self.proof_valid
    }
}

/// Generates a proof that committed parameters produced a claimed output.
///
/// `proof_seed` must be fresh for every proof. Groth16 proofs are randomised, and
/// reusing the same randomness across two proofs from the same proving key
/// degrades the zero-knowledge property the protocol relies on to keep model
/// weights private.
///
/// # Errors
///
/// Returns [`TvcError::Codec`] if `proving_key` is malformed, or
/// [`TvcError::Synthesis`] if constraint generation fails.
pub fn prove_inference(
    proving_key: &[u8],
    weight: Fr,
    bias: Fr,
    input: Fr,
    proof_seed: [u8; 32],
) -> Result<InferenceProof> {
    let key = ProvingKey::<Bn254>::deserialize_compressed(proving_key)?;
    let circuit = InferenceCircuit::witness(weight, bias, input);
    let public_inputs = circuit.public_inputs()?.to_vec();

    let mut rng = StdRng::from_seed(proof_seed);
    let proof = Groth16::<Bn254>::prove(&key, circuit, &mut rng)?;

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)?;

    Ok(InferenceProof {
        proof: proof_bytes,
        public_inputs,
    })
}

/// Verifies an inference proof against a published parameter commitment.
///
/// Checks the verifying key against `committed_vk_digest` *before* touching the
/// proof. See the module documentation for why that order is load-bearing.
///
/// # Errors
///
/// - [`TvcError::CommitmentMismatch`] if the runtime key is not the committed key.
/// - [`TvcError::Codec`] if the key or proof is malformed.
/// - [`TvcError::ProofRejected`] if the pairing check fails.
pub fn verify_inference(
    verifying_key: &[u8],
    committed_vk_digest: &[u8; 32],
    public_inputs: &[Fr],
    proof: &[u8],
) -> Result<VerificationReport> {
    let observed_vk_digest = derive_vk_digest(verifying_key);
    if &observed_vk_digest != committed_vk_digest {
        return Err(TvcError::CommitmentMismatch {
            expected: hex::encode(committed_vk_digest),
            observed: hex::encode(&observed_vk_digest),
        });
    }

    let key = VerifyingKey::<Bn254>::deserialize_compressed(verifying_key)?;
    let parsed_proof = Proof::<Bn254>::deserialize_compressed(proof)?;

    let proof_valid = Groth16::<Bn254>::verify(&key, public_inputs, &parsed_proof)?;
    if !proof_valid {
        return Err(TvcError::ProofRejected);
    }

    Ok(VerificationReport {
        observed_vk_digest,
        commitment_matched: true,
        proof_valid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc_setup::{run_ceremony, ModelDescriptor, ParticipantContribution};

    fn ceremony() -> crate::mpc_setup::CeremonyOutput {
        run_ceremony(
            ModelDescriptor::new("acme-llm-7b", "2026.09", "affine-committed-inference", 7_000_000_000),
            vec![
                ParticipantContribution::new("bitshala", [1u8; 32]),
                ParticipantContribution::new("acme-labs", [2u8; 32]),
            ],
        )
        .unwrap()
    }

    #[test]
    fn honest_proof_verifies_against_the_committed_digest() {
        let setup = ceremony();
        let proof = prove_inference(
            &setup.proving_key,
            Fr::from(7u64),
            Fr::from(3u64),
            Fr::from(11u64),
            [42u8; 32],
        )
        .unwrap();

        let report = verify_inference(
            &setup.verifying_key,
            &setup.vk_digest,
            &proof.public_inputs,
            &proof.proof,
        )
        .unwrap();

        assert!(report.accepted());
    }

    #[test]
    fn substituted_model_is_rejected_on_the_commitment_not_the_proof() {
        let committed = ceremony();
        let substitute = run_ceremony(
            ModelDescriptor::new("acme-llm-7b", "2026.09", "affine-committed-inference", 7_000_000_000),
            vec![ParticipantContribution::new("rogue-operator", [9u8; 32])],
        )
        .unwrap();

        let proof = prove_inference(
            &substitute.proving_key,
            Fr::from(7u64),
            Fr::from(3u64),
            Fr::from(11u64),
            [42u8; 32],
        )
        .unwrap();

        let verified_against_substitute = verify_inference(
            &substitute.verifying_key,
            &substitute.vk_digest,
            &proof.public_inputs,
            &proof.proof,
        )
        .unwrap();
        assert!(verified_against_substitute.accepted());

        let error = verify_inference(
            &substitute.verifying_key,
            &committed.vk_digest,
            &proof.public_inputs,
            &proof.proof,
        )
        .unwrap_err();
        assert!(matches!(error, TvcError::CommitmentMismatch { .. }));
    }

    #[test]
    fn tampered_public_output_is_rejected_by_the_pairing_check() {
        let setup = ceremony();
        let proof = prove_inference(
            &setup.proving_key,
            Fr::from(7u64),
            Fr::from(3u64),
            Fr::from(11u64),
            [42u8; 32],
        )
        .unwrap();

        let mut forged = proof.public_inputs.clone();
        forged[1] += Fr::from(1u64);

        let error =
            verify_inference(&setup.verifying_key, &setup.vk_digest, &forged, &proof.proof).unwrap_err();
        assert_eq!(error, TvcError::ProofRejected);
    }

    #[test]
    fn public_inputs_survive_a_hex_roundtrip() {
        let setup = ceremony();
        let proof = prove_inference(
            &setup.proving_key,
            Fr::from(7u64),
            Fr::from(3u64),
            Fr::from(11u64),
            [42u8; 32],
        )
        .unwrap();
        let encoded = proof.public_inputs_hex().unwrap();
        let decoded = InferenceProof::public_inputs_from_hex(&encoded).unwrap();
        assert_eq!(decoded, proof.public_inputs);
    }

    #[test]
    fn commitment_signature_roundtrips() {
        let setup = ceremony();
        let commitment = ParameterCommitment::new(
            "acme-llm-7b",
            "2026.09",
            setup.vk_digest,
            setup.transcript.final_digest,
            setup.burn.attestation_digest,
        );
        let signed = commitment.sign(&[0x11; 32], &[0x22; 32]).unwrap();

        assert!(signed.verify().is_ok());
        assert!(signed.verify_signed_by(&signed.signer).is_ok());
        assert_eq!(signed.signer_hex().len(), 64);
        assert_eq!(signed.signature_hex().len(), 128);
    }

    #[test]
    fn altered_commitment_breaks_its_signature() {
        let setup = ceremony();
        let commitment = ParameterCommitment::new(
            "acme-llm-7b",
            "2026.09",
            setup.vk_digest,
            setup.transcript.final_digest,
            setup.burn.attestation_digest,
        );
        let mut signed = commitment.sign(&[0x11; 32], &[0x22; 32]).unwrap();
        signed.commitment.version = "2026.10".to_owned();

        assert_eq!(signed.verify().unwrap_err(), TvcError::CommitmentUnsigned);
    }

    #[test]
    fn commitment_from_an_untrusted_key_is_rejected() {
        let setup = ceremony();
        let commitment = ParameterCommitment::new(
            "acme-llm-7b",
            "2026.09",
            setup.vk_digest,
            setup.transcript.final_digest,
            setup.burn.attestation_digest,
        );
        let signed = commitment.sign(&[0x11; 32], &[0x22; 32]).unwrap();
        let unrelated = [0x33; 32];

        assert_eq!(
            signed.verify_signed_by(&unrelated).unwrap_err(),
            TvcError::CommitmentUnsigned
        );
    }
}
