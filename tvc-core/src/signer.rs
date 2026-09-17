//! Publisher identity, the registration payload, and BIP-340 attestations.
//!
//! # What a signature here actually claims
//!
//! A [`SignedRegistration`] is one lab saying: *"I, the holder of this key,
//! assert that model `model_id` at `version` has weight commitment `C`, as of
//! `timestamp`."* It does not claim the weights are good, that the lab trained
//! them, or that `model_id` is a name anyone else recognises. It binds an
//! identity to a commitment, and that is the whole job — everything downstream,
//! including the eventual circuit layer, rests on this one binding.
//!
//! Every field is covered by [`RegistrationPayload::sighash`]. Signing the
//! commitment alone would be the classic mistake: a relay could then lift a
//! genuine signature onto a different `model_id` and publish a real lab's
//! attestation for a model it never saw.
//!
//! # Why BIP-340 Schnorr rather than ECDSA
//!
//! Three reasons, in order of weight. Schnorr signatures over secp256k1 are
//! **non-malleable** — ECDSA admits a second valid signature for the same message
//! and key by negating `s`, which in an append-only registry means one
//! attestation can be republished as two distinct-looking records. They have a
//! **canonical 64-byte encoding**, where ECDSA's DER is a parsing minefield with a
//! long history of signature-mutation bugs. And the scheme is **linear**, so a
//! consortium of labs can later co-sign one registration as a single aggregate
//! key without any change to what a verifier does.
//!
//! The x-only public key is the publisher's whole identity: 32 bytes, no
//! certificate chain, no registry of registries. A verifier that trusts a lab
//! pins one key and calls [`SignedRegistration::verify_signed_by`].
//!
//! # Key handling
//!
//! [`PublisherKeypair`] holds its scalar in a [`Zeroizing`] buffer and
//! reconstructs the `secp256k1` key for each signature, so the secret is wiped
//! when the keypair drops. It is deliberately not [`Clone`] and deliberately not
//! serialisable: a signing key should leave this process only through
//! [`PublisherKeypair::expose_secret_hex`], whose name is the warning.
//!
//! Randomness is always caller-supplied — for key generation and for the signing
//! nonce alike. `tvc-core` has no hidden entropy source, which keeps every test
//! reproducible and makes the point at which real OS randomness enters the system
//! a visible, auditable call site rather than a library default.

use std::time::{SystemTime, UNIX_EPOCH};

use secp256k1::{schnorr, Keypair, SecretKey, XOnlyPublicKey};
use zeroize::Zeroizing;

use crate::commitment::WeightCommitment;
use crate::digest::{tagged_hash, DOMAIN_PUBLISHER_KEY, DOMAIN_REGISTRATION_SIGHASH};
use crate::error::{Result, TvcError};
use crate::hex;

/// Maximum length of a model identifier.
///
/// Generous enough for Hugging Face's `namespace/repo` form with room to spare,
/// and bounded so a single field cannot bloat a ledger record.
pub const MODEL_ID_MAX_LEN: usize = 128;

/// Maximum length of a version string.
pub const VERSION_MAX_LEN: usize = 64;

/// Rejects model identifiers that cannot survive this layer's transports intact.
///
/// The permitted alphabet is ASCII alphanumerics plus `-`, `_`, `.` and `/`.
/// Slash is allowed because a Hugging Face identifier is `namespace/repo`, and
/// rejecting it would make the registry unable to name the models it exists for.
/// The exclusions are each for a concrete reason, not out of caution:
///
/// - **`:`** would make [`RegistrationPayload::address`] ambiguous. The address is
///   `<model_id>:<version>`, so a colon inside a component means a consumer
///   splitting on `:` recovers a different `(model, version)` pair than the one
///   that was signed.
/// - **Whitespace and control characters** would let two visually identical
///   identifiers hash differently, or survive a `trim()` as a third value, and
///   they corrupt the line-delimited ledger.
/// - **A `.` or `..` component, or a leading or trailing `/`,** is refused so a
///   model identifier can never be pasted into a path and escape its directory,
///   and so two spellings of one name cannot exist. `org/./model` and
///   `org/model` are different ASCII strings — and so hash differently and sign
///   differently — while resolving identically on every path resolver and most
///   HTTP routers. Nothing here builds such a path today; this makes sure
///   nothing later can.
///
/// # Errors
///
/// Returns [`TvcError::InvalidIdentifier`] naming the field and the reason.
pub fn validate_model_id(value: &str) -> Result<()> {
    let field = "model_id";
    check_length(field, value, MODEL_ID_MAX_LEN)?;

    for character in value.chars() {
        let permitted = character.is_ascii_alphanumeric()
            || character == '-'
            || character == '_'
            || character == '.'
            || character == '/';
        if !permitted {
            return Err(TvcError::InvalidIdentifier {
                field,
                reason: format!(
                    "{character:?} is not permitted; use ASCII letters, digits, '-', '_', '.' or '/'"
                ),
            });
        }
    }
    if value.starts_with('/') || value.ends_with('/') {
        return Err(TvcError::InvalidIdentifier {
            field,
            reason: "must not begin or end with '/'".to_owned(),
        });
    }
    if value
        .split('/')
        .any(|component| component == "." || component == ".." || component.is_empty())
    {
        return Err(TvcError::InvalidIdentifier {
            field,
            reason: "must not contain an empty, '.' or '..' path component".to_owned(),
        });
    }
    Ok(())
}

/// Rejects version strings that cannot survive this layer's transports intact.
///
/// Stricter than [`validate_model_id`]: no slash, because a version is a single
/// opaque label and allowing separators invites it being parsed as structure.
///
/// # Errors
///
/// Returns [`TvcError::InvalidIdentifier`] naming the field and the reason.
pub fn validate_version(value: &str) -> Result<()> {
    let field = "version";
    check_length(field, value, VERSION_MAX_LEN)?;

    for character in value.chars() {
        let permitted = character.is_ascii_alphanumeric()
            || character == '-'
            || character == '_'
            || character == '.';
        if !permitted {
            return Err(TvcError::InvalidIdentifier {
                field,
                reason: format!(
                    "{character:?} is not permitted; use ASCII letters, digits, '-', '_' or '.'"
                ),
            });
        }
    }
    Ok(())
}

fn check_length(field: &'static str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() {
        return Err(TvcError::InvalidIdentifier {
            field,
            reason: "must not be empty".to_owned(),
        });
    }
    if value.len() > maximum {
        return Err(TvcError::InvalidIdentifier {
            field,
            reason: format!("must be at most {maximum} bytes, got {}", value.len()),
        });
    }
    Ok(())
}

/// Seconds since the Unix epoch, for use as a registration timestamp.
///
/// # Panics
///
/// Panics only if the system clock is set before 1970.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs()
}

/// A publisher's secp256k1 signing identity.
pub struct PublisherKeypair {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl PublisherKeypair {
    /// Adopts an existing 32-byte secp256k1 scalar as a signing key.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::Signature`] if the bytes are not a valid scalar, which
    /// means zero or at least the group order.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Result<Self> {
        let key = SecretKey::from_secret_bytes(*secret)?;
        let (public, _parity) = Keypair::from_secret_key(&key).x_only_public_key();
        Ok(Self {
            secret: Zeroizing::new(*secret),
            public: public.to_byte_array(),
        })
    }

    /// Derives a signing key from caller-supplied entropy.
    ///
    /// The entropy is passed through a tagged hash for **domain separation only**
    /// — so the same 32 bytes used elsewhere in this protocol yield an unrelated
    /// scalar. It adds no entropy whatsoever. `entropy` must come from a
    /// cryptographically secure source; the CLI uses the operating system's.
    ///
    /// A counter is folded in and incremented until the digest lands in range.
    /// Not all 32-byte strings are valid secp256k1 scalars — zero and anything at
    /// or above the group order are not — so resampling rather than failing is
    /// what makes this a total function. The gap is about `2^-128` wide, so the
    /// loop effectively never runs twice and the resulting bias is unobservable;
    /// it is here so the one caller in a hundred billion years is not an error.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::Signature`] only if every candidate in a long run is
    /// out of range, which is not reachable in practice.
    pub fn generate(entropy: &[u8; 32]) -> Result<Self> {
        for counter in 0u32..64 {
            let derived = Zeroizing::new(tagged_hash(
                DOMAIN_PUBLISHER_KEY,
                &[entropy, &counter.to_be_bytes()],
            ));
            if let Ok(keypair) = Self::from_secret_bytes(&derived) {
                return Ok(keypair);
            }
        }
        Err(TvcError::Signature(
            "no valid scalar derived from the supplied entropy".to_owned(),
        ))
    }

    /// The publisher's x-only public key: its entire public identity.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Lowercase hex rendering of [`Self::public_key`].
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public)
    }

    /// Renders the signing key as hex, for the operator to place in a secret store.
    ///
    /// Named to be conspicuous at every call site. The returned string is a
    /// [`Zeroizing`] buffer, so it is wiped when dropped, but anything the caller
    /// prints or copies it into is the caller's responsibility.
    pub fn expose_secret_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.secret.as_slice()))
    }

    /// Signs a registration payload with a BIP-340 Schnorr signature.
    ///
    /// `aux_rand` is the BIP-340 auxiliary randomness. It is supplied by the
    /// caller rather than sampled internally so the signing path has no hidden
    /// entropy source and stays reproducible under test. Production callers must
    /// pass fresh randomness from the operating system: reusing `aux_rand` across
    /// two different payloads is not fatal for BIP-340 the way nonce reuse is for
    /// ECDSA, but it forfeits the side-channel hardening the field exists for.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::InvalidIdentifier`] if the payload does not validate,
    /// so an unsafe identifier can never acquire a signature.
    pub fn sign(
        &self,
        payload: &RegistrationPayload,
        aux_rand: &[u8; 32],
    ) -> Result<SignedRegistration> {
        payload.validate()?;
        let key = SecretKey::from_secret_bytes(*self.secret)?;
        let keypair = Keypair::from_secret_key(&key);
        let signature = schnorr::sign_with_aux_rand(&payload.sighash(&self.public), &keypair, aux_rand);

        Ok(SignedRegistration {
            payload: payload.clone(),
            signature: *signature.as_ref(),
            publisher: self.public,
        })
    }
}

impl core::fmt::Debug for PublisherKeypair {
    /// Prints only the public key, so a keypair can never be logged by accident.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublisherKeypair")
            .field("public", &self.public_key_hex())
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The structured claim a publisher signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationPayload {
    /// Stable model identifier, for example `meta-llama/Llama-3.2-1B`.
    pub model_id: String,
    /// Version string for this release, for example `1.0.0`.
    pub version: String,
    /// The weight commitment `C` being attested to.
    pub weight_commitment: WeightCommitment,
    /// Seconds since the Unix epoch at which the claim was made.
    pub timestamp: u64,
}

impl RegistrationPayload {
    /// Assembles a payload.
    pub fn new(
        model_id: impl Into<String>,
        version: impl Into<String>,
        weight_commitment: WeightCommitment,
        timestamp: u64,
    ) -> Self {
        Self {
            model_id: model_id.into(),
            version: version.into(),
            weight_commitment,
            timestamp,
        }
    }

    /// Confirms every field is safe to transport and to write to the ledger.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::InvalidIdentifier`] naming the offending field, or
    /// [`TvcError::CommitmentMismatch`] if the commitment does not bind its own
    /// stated inputs.
    pub fn validate(&self) -> Result<()> {
        validate_model_id(&self.model_id)?;
        validate_version(&self.version)?;
        if !self.weight_commitment.is_self_consistent() {
            return Err(TvcError::CommitmentMismatch {
                expected: self.weight_commitment.root_hex(),
                observed: hex::encode(&self.weight_commitment.rebind()),
            });
        }
        Ok(())
    }

    /// Addressable identity of this model version, `<model_id>:<version>`.
    ///
    /// Unambiguous because [`validate_version`] forbids `:` in either component.
    pub fn address(&self) -> String {
        format!("{}:{}", self.model_id, self.version)
    }

    /// The 32-byte message the publisher signs.
    ///
    /// Covers the publisher key, the identity, the commitment, every one of the
    /// commitment's binding inputs, and the timestamp.
    ///
    /// Two of those are redundant against a correct verifier, and deliberately
    /// included anyway:
    ///
    /// - The **binding inputs** are already folded into `root`. Repeating them
    ///   means tampering with a carried field is caught by the signature check
    ///   itself, not only by a separate rebind.
    /// - The **publisher key** is already bound by BIP-340, whose challenge is
    ///   `e = H(R ‖ P ‖ m)`. A signature therefore cannot be re-attributed to
    ///   another key: verifying under `P'` computes a different challenge and
    ///   fails. Including `P` in `m` buys something narrower — the payload
    ///   becomes self-describing, so anyone re-deriving this sighash out of band,
    ///   without the signature wrapper in front of them, is naming the publisher
    ///   explicitly rather than implicitly.
    pub fn sighash(&self, publisher: &[u8; 32]) -> [u8; 32] {
        let commitment = &self.weight_commitment;
        tagged_hash(
            DOMAIN_REGISTRATION_SIGHASH,
            &[
                publisher,
                self.model_id.as_bytes(),
                self.version.as_bytes(),
                commitment.scheme.as_bytes(),
                &commitment.root,
                &commitment.scheme_commitment,
                &commitment.length.to_be_bytes(),
                &commitment.fractional_bits.to_be_bytes(),
                &commitment.manifest_digest,
                &self.timestamp.to_be_bytes(),
            ],
        )
    }
}

/// A [`RegistrationPayload`] carrying its signature and the key that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRegistration {
    /// The signed claim.
    pub payload: RegistrationPayload,
    /// 64-byte BIP-340 Schnorr signature over [`RegistrationPayload::sighash`].
    pub signature: [u8; 64],
    /// 32-byte x-only public key of the publishing lab.
    pub publisher: [u8; 32],
}

impl SignedRegistration {
    /// Verifies the signature against the embedded publisher key.
    ///
    /// Establishes only that *this* key signed *this* claim. Whether the key is
    /// one anybody should trust is policy, handled by [`Self::verify_signed_by`].
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::AttestationUnsigned`] when verification fails, or the
    /// payload's own validation error when a field is unsafe.
    pub fn verify(&self) -> Result<()> {
        self.payload.validate()?;
        let pubkey = XOnlyPublicKey::from_byte_array(self.publisher)?;
        let signature = schnorr::Signature::from_byte_array(self.signature);
        signature
            .verify(&self.payload.sighash(&self.publisher), &pubkey)
            .map_err(|_| TvcError::AttestationUnsigned)
    }

    /// Verifies the signature and pins it to an expected publisher key.
    ///
    /// This is what a consumer of the registry calls. Accepting any valid
    /// signature would let an arbitrary key vouch for a famous model name, which
    /// is no trust anchor at all; the consumer must already know whose
    /// attestations it honours.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::SignerMismatch`] if the signer differs from
    /// `expected_publisher`, or [`TvcError::AttestationUnsigned`] if the
    /// signature does not verify.
    pub fn verify_signed_by(&self, expected_publisher: &[u8; 32]) -> Result<()> {
        if &self.publisher != expected_publisher {
            return Err(TvcError::SignerMismatch {
                expected: hex::encode(expected_publisher),
                observed: self.publisher_hex(),
            });
        }
        self.verify()
    }

    /// Lowercase hex rendering of the publisher's x-only public key.
    pub fn publisher_hex(&self) -> String {
        hex::encode(&self.publisher)
    }

    /// Lowercase hex rendering of the signature.
    pub fn signature_hex(&self) -> String {
        hex::encode(&self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{commit_weights, Quantizer, Tensor, WeightVector};

    fn commitment_of(values: &[f32]) -> WeightCommitment {
        let tensor = Tensor::from_f32("w", vec![values.len() as u64], values).unwrap();
        let vector = WeightVector::from_tensors(vec![tensor], Quantizer::default()).unwrap();
        commit_weights(&vector).unwrap()
    }

    fn payload() -> RegistrationPayload {
        RegistrationPayload::new(
            "meta-llama/Llama-3.2-1B",
            "1.0.0",
            commitment_of(&[1.0, 2.0, 3.0]),
            1_760_000_000,
        )
    }

    fn keypair() -> PublisherKeypair {
        PublisherKeypair::generate(&[7u8; 32]).unwrap()
    }

    #[test]
    fn hugging_face_identifiers_are_accepted() {
        for good in [
            "meta-llama/Llama-3.2-1B",
            "mistralai/Mistral-7B-Instruct-v0.3",
            "acme-labs/internal_model.v2",
            "bare-model-name",
        ] {
            assert!(validate_model_id(good).is_ok(), "expected {good:?} to pass");
        }
    }

    #[test]
    fn a_colon_in_an_identifier_is_rejected() {
        // "acme:llm" + version "2026.09" would address as "acme:llm:2026.09",
        // which a consumer splitting on the first colon reads as ("acme", "llm:2026.09").
        assert!(validate_model_id("acme:llm").is_err());
        assert!(validate_version("1:0").is_err());
    }

    #[test]
    fn path_traversal_shapes_are_rejected() {
        for bad in [
            "../etc/passwd",
            "org/../../escape",
            "/leading",
            "trailing/",
            "a//b",
            "org/./model",
            ".",
            "org/.",
        ] {
            assert!(validate_model_id(bad).is_err(), "expected {bad:?} to fail");
        }
    }

    #[test]
    fn whitespace_control_and_length_bounds_are_enforced() {
        for bad in ["bad id", "bad\nid", "bad\tid", "bad\u{0}id", ""] {
            assert!(validate_model_id(bad).is_err(), "expected {bad:?} to fail");
        }
        assert!(validate_model_id(&"m".repeat(MODEL_ID_MAX_LEN)).is_ok());
        assert!(validate_model_id(&"m".repeat(MODEL_ID_MAX_LEN + 1)).is_err());
        assert!(validate_version(&"v".repeat(VERSION_MAX_LEN + 1)).is_err());
    }

    #[test]
    fn a_slash_is_refused_in_a_version() {
        assert!(validate_version("1.0/beta").is_err());
    }

    #[test]
    fn a_signed_registration_verifies() {
        let signed = keypair().sign(&payload(), &[3u8; 32]).unwrap();
        assert_eq!(signed.verify(), Ok(()));
        assert_eq!(signed.verify_signed_by(&keypair().public_key()), Ok(()));
    }

    #[test]
    fn a_signature_does_not_transfer_to_another_model_id() {
        let signed = keypair().sign(&payload(), &[3u8; 32]).unwrap();
        let mut forged = signed.clone();
        forged.payload.model_id = "openai/gpt-4".to_owned();
        assert_eq!(forged.verify(), Err(TvcError::AttestationUnsigned));
    }

    #[test]
    fn a_signature_does_not_transfer_to_another_version_or_time() {
        let signed = keypair().sign(&payload(), &[3u8; 32]).unwrap();

        let mut reversioned = signed.clone();
        reversioned.payload.version = "2.0.0".to_owned();
        assert_eq!(reversioned.verify(), Err(TvcError::AttestationUnsigned));

        let mut backdated = signed;
        backdated.payload.timestamp -= 1;
        assert_eq!(backdated.verify(), Err(TvcError::AttestationUnsigned));
    }

    #[test]
    fn a_signature_does_not_transfer_to_other_weights() {
        let signed = keypair().sign(&payload(), &[3u8; 32]).unwrap();
        let mut substituted = signed;
        substituted.payload.weight_commitment = commitment_of(&[9.0, 9.0, 9.0]);
        assert_eq!(substituted.verify(), Err(TvcError::AttestationUnsigned));
    }

    #[test]
    fn another_key_cannot_republish_an_attestation() {
        let signed = keypair().sign(&payload(), &[3u8; 32]).unwrap();
        let impostor = PublisherKeypair::generate(&[9u8; 32]).unwrap();

        // The signature is genuine; it is simply not the key the verifier pinned.
        assert_eq!(signed.verify(), Ok(()));
        assert!(matches!(
            signed.verify_signed_by(&impostor.public_key()),
            Err(TvcError::SignerMismatch { .. })
        ));
    }

    #[test]
    fn an_unsafe_identifier_cannot_acquire_a_signature() {
        let mut unsafe_payload = payload();
        unsafe_payload.model_id = "acme:llm".to_owned();
        assert!(matches!(
            keypair().sign(&unsafe_payload, &[3u8; 32]),
            Err(TvcError::InvalidIdentifier { field: "model_id", .. })
        ));
    }

    #[test]
    fn a_commitment_that_does_not_bind_its_inputs_is_refused() {
        let mut tampered = payload();
        tampered.weight_commitment.length = 4096;
        assert!(matches!(
            tampered.validate(),
            Err(TvcError::CommitmentMismatch { .. })
        ));
    }

    #[test]
    fn the_sighash_names_the_publisher() {
        // BIP-340 already binds the key inside the challenge, so this is not what
        // stops re-attribution. What it buys is a self-describing payload: the
        // same claim under two publishers is two different messages, visible to
        // anyone re-deriving the sighash without the signature in hand.
        let payload = payload();
        let first = PublisherKeypair::generate(&[1u8; 32]).unwrap();
        let second = PublisherKeypair::generate(&[2u8; 32]).unwrap();
        assert_ne!(
            payload.sighash(&first.public_key()),
            payload.sighash(&second.public_key())
        );
    }

    #[test]
    fn a_signature_does_not_verify_under_a_substituted_publisher() {
        // The signature travels with the key that made it; swapping the key in
        // the record makes the record fail rather than change hands.
        let signed = keypair().sign(&payload(), &[3u8; 32]).unwrap();
        let mut relabelled = signed;
        relabelled.publisher = PublisherKeypair::generate(&[9u8; 32]).unwrap().public_key();
        assert_eq!(relabelled.verify(), Err(TvcError::AttestationUnsigned));
    }

    #[test]
    fn key_derivation_terminates_for_arbitrary_entropy() {
        // The resampling loop must be total, including for degenerate input.
        for entropy in [[0u8; 32], [0xff; 32]] {
            assert!(PublisherKeypair::generate(&entropy).is_ok());
        }
    }

    #[test]
    fn signing_is_deterministic_in_its_aux_randomness() {
        let left = keypair().sign(&payload(), &[1u8; 32]).unwrap();
        let right = keypair().sign(&payload(), &[1u8; 32]).unwrap();
        assert_eq!(left.signature, right.signature);
        assert_ne!(
            left.signature,
            keypair().sign(&payload(), &[2u8; 32]).unwrap().signature
        );
    }

    #[test]
    fn key_derivation_is_deterministic_and_separated() {
        assert_eq!(
            PublisherKeypair::generate(&[1u8; 32]).unwrap().public_key(),
            PublisherKeypair::generate(&[1u8; 32]).unwrap().public_key()
        );
        assert_ne!(
            PublisherKeypair::generate(&[1u8; 32]).unwrap().public_key(),
            PublisherKeypair::from_secret_bytes(&[1u8; 32]).unwrap().public_key(),
            "derivation must not be the identity function"
        );
    }

    #[test]
    fn debug_never_reveals_the_secret() {
        let keypair = keypair();
        let rendered = format!("{keypair:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(keypair.expose_secret_hex().as_str()));
    }

    #[test]
    fn an_invalid_scalar_is_rejected() {
        assert!(PublisherKeypair::from_secret_bytes(&[0u8; 32]).is_err());
    }
}
