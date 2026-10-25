//! Signing identities and BIP-340 signatures over document claims.
//!
//! # What a signature here actually claims
//!
//! A [`SignedDocument`] is one key holder saying: *"I published the document
//! whose canonical SHA-256 is `document`, of kind `kind`, building on the
//! documents `refs`, as of `timestamp`."* It does not claim the document is
//! true. It binds an identity to a document, and everything downstream (a
//! reference, an honest set, a calibration, an audit) rests on that binding.
//!
//! Every field is covered by [`DocumentClaim::sighash`], and the kind is part
//! of the signing tag, so a signature can't be lifted onto another document,
//! another kind, other citations or another time.
//!
//! # Why BIP-340 Schnorr rather than ECDSA
//!
//! Three reasons, in order of weight. Schnorr signatures over secp256k1 are
//! **non-malleable**. ECDSA admits a second valid signature for the same message
//! and key by negating `s`, which in an append-only ledger means one claim can
//! be republished as two distinct-looking records. They have a **canonical
//! 64-byte encoding**, where ECDSA's DER is a parsing minefield with a long
//! history of signature-mutation bugs. And the scheme is **linear**, so several
//! parties can later co-sign one claim as a single aggregate key without any
//! change to what a verifier does.
//!
//! The x-only public key is a signer's whole identity: 32 bytes, no certificate
//! chain. A verifier pins the keys it trusts and calls
//! [`SignedDocument::verify_signed_by`].
//!
//! # Key handling
//!
//! [`PublisherKeypair`] holds its scalar in a [`Zeroizing`] buffer and
//! reconstructs the `secp256k1` key for each signature, so the secret is wiped
//! when the keypair drops. It is deliberately not [`Clone`] and deliberately not
//! serialisable: a signing key should leave this process only through
//! [`PublisherKeypair::expose_secret_hex`], whose name is the warning.
//!
//! Randomness is always caller-supplied, for key generation and for the signing
//! nonce alike. `tvc-core` has no hidden entropy source, which keeps every test
//! reproducible and makes the point at which real OS randomness enters the
//! system a visible, auditable call site rather than a library default.

use std::time::{SystemTime, UNIX_EPOCH};

use secp256k1::{schnorr, Keypair, SecretKey, XOnlyPublicKey};
use zeroize::Zeroizing;

use crate::digest::{tagged_hash, DOMAIN_DOCUMENT_SIGHASH_PREFIX, DOMAIN_PUBLISHER_KEY};
use crate::error::{Result, TvcError};
use crate::hex;

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

/// Seconds since the Unix epoch, for use as a claim timestamp.
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

    /// Signs a claim about a published document with a BIP-340 signature.
    ///
    /// `aux_rand` is the BIP-340 auxiliary randomness. It is supplied by the
    /// caller rather than sampled internally so the signing path has no hidden
    /// entropy source and stays reproducible under test. Production callers must
    /// pass fresh randomness from the operating system: reusing `aux_rand`
    /// across two claims is not fatal for BIP-340 the way nonce reuse is for
    /// ECDSA, but it forfeits the side-channel hardening the field exists for.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::InvalidIdentifier`] or [`TvcError::InvalidDocument`]
    /// if the claim does not validate, so an unsafe kind name can never
    /// acquire a signature.
    pub fn sign_document(
        &self,
        claim: &DocumentClaim,
        aux_rand: &[u8; 32],
    ) -> Result<SignedDocument> {
        claim.validate()?;
        let key = SecretKey::from_secret_bytes(*self.secret)?;
        let keypair = Keypair::from_secret_key(&key);
        let signature = schnorr::sign_with_aux_rand(&claim.sighash(&self.public), &keypair, aux_rand);
        Ok(SignedDocument {
            claim: claim.clone(),
            signature: *signature.as_ref(),
            signer: self.public,
        })
    }
}

/// Maximum length of a document kind.
pub const KIND_MAX_LEN: usize = 64;

/// Rejects document kinds that are not `<name>/v<number>`.
///
/// The name is lowercase ASCII letters, digits and `-`, starting with a letter
/// or digit, for example `reference-run/v1`. The version is part of the kind on
/// purpose: a reader that does not know `reference-run/v2` should treat it as an
/// unknown kind, not misread it as v1.
///
/// # Errors
///
/// Returns [`TvcError::InvalidIdentifier`] naming the reason.
pub fn validate_kind(kind: &str) -> Result<()> {
    let field = "kind";
    check_length(field, kind, KIND_MAX_LEN)?;
    let refuse = |reason: &str| {
        Err(TvcError::InvalidIdentifier {
            field,
            reason: format!("{kind:?} {reason}; expected <name>/v<number>, e.g. reference-run/v1"),
        })
    };
    let Some((name, version)) = kind.split_once("/v") else {
        return refuse("has no /v<number> suffix");
    };
    let name_ok = name
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !name_ok {
        return refuse("has a name outside [a-z0-9-]");
    }
    if version.is_empty() || !version.chars().all(|c| c.is_ascii_digit()) {
        return refuse("has a version that is not a number");
    }
    Ok(())
}

/// What a signer asserts about one published document.
///
/// *"I, the holder of this key, published the document whose canonical
/// SHA-256 is `document`, of kind `kind`, building on the documents `refs`,
/// as of `timestamp`."* The document itself is not in the claim, only its
/// digest, so a claim can be made about a document whose content is published
/// separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentClaim {
    /// Document kind, for example `reference-run/v1`.
    pub kind: String,
    /// SHA-256 of the document's canonical bytes.
    pub document: [u8; 32],
    /// Digests of earlier documents this one builds on, in the order the
    /// document lists them.
    pub refs: Vec<[u8; 32]>,
    /// Seconds since the Unix epoch, as asserted by the signer.
    pub timestamp: u64,
}

impl DocumentClaim {
    /// Assembles a claim.
    pub fn new(
        kind: impl Into<String>,
        document: [u8; 32],
        refs: Vec<[u8; 32]>,
        timestamp: u64,
    ) -> Self {
        Self {
            kind: kind.into(),
            document,
            refs,
            timestamp,
        }
    }

    /// Confirms the kind is well formed and no reference is repeated or self-referential.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::InvalidIdentifier`] for a bad kind, or
    /// [`TvcError::InvalidDocument`] for a repeated or self reference.
    pub fn validate(&self) -> Result<()> {
        validate_kind(&self.kind)?;
        let mut seen = std::collections::BTreeSet::new();
        for reference in &self.refs {
            if reference == &self.document {
                return Err(TvcError::InvalidDocument(
                    "a document cannot refer to itself".to_owned(),
                ));
            }
            if !seen.insert(*reference) {
                return Err(TvcError::InvalidDocument(format!(
                    "reference {} appears twice",
                    hex::encode(reference)
                )));
            }
        }
        Ok(())
    }

    /// The 32-byte message a signer signs.
    ///
    /// Signed under a tag that includes the kind
    /// (`W-TVC/v2/document/<kind>`), so a signature over a `reference-run/v1`
    /// claim can never be presented as one over a `profile/v1` claim with the
    /// same digest. The kind is also absorbed as a part, which makes the
    /// message self-describing for anyone re-deriving it by hand.
    pub fn sighash(&self, signer: &[u8; 32]) -> [u8; 32] {
        let tag = format!("{DOMAIN_DOCUMENT_SIGHASH_PREFIX}{}", self.kind);
        let reference_count = (self.refs.len() as u64).to_be_bytes();
        let timestamp = self.timestamp.to_be_bytes();
        let mut parts: Vec<&[u8]> = vec![
            signer,
            self.kind.as_bytes(),
            &self.document,
            &reference_count,
        ];
        parts.extend(self.refs.iter().map(<[u8; 32]>::as_slice));
        parts.push(&timestamp);
        tagged_hash(&tag, &parts)
    }
}

/// A [`DocumentClaim`] with its signature and the key that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDocument {
    /// The signed claim.
    pub claim: DocumentClaim,
    /// 64-byte BIP-340 signature over [`DocumentClaim::sighash`].
    pub signature: [u8; 64],
    /// 32-byte x-only public key of the signer.
    pub signer: [u8; 32],
}

impl SignedDocument {
    /// Verifies the signature against the embedded signer key.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::AttestationUnsigned`] if it does not verify, or the
    /// claim's own validation error.
    pub fn verify(&self) -> Result<()> {
        self.claim.validate()?;
        let pubkey = XOnlyPublicKey::from_byte_array(self.signer)?;
        schnorr::Signature::from_byte_array(self.signature)
            .verify(&self.claim.sighash(&self.signer), &pubkey)
            .map_err(|_| TvcError::AttestationUnsigned)
    }

    /// Verifies the signature and pins it to an expected signer.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::SignerMismatch`] for another key, or as [`Self::verify`].
    pub fn verify_signed_by(&self, expected: &[u8; 32]) -> Result<()> {
        if &self.signer != expected {
            return Err(TvcError::SignerMismatch {
                expected: hex::encode(expected),
                observed: hex::encode(&self.signer),
            });
        }
        self.verify()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> PublisherKeypair {
        PublisherKeypair::generate(&[7u8; 32]).unwrap()
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
        let left = keypair().sign_document(&claim("profile/v2"), &[1u8; 32]).unwrap();
        let right = keypair().sign_document(&claim("profile/v2"), &[1u8; 32]).unwrap();
        assert_eq!(left.signature, right.signature);
        assert_ne!(
            left.signature,
            keypair().sign_document(&claim("profile/v2"), &[2u8; 32]).unwrap().signature
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

    fn claim(kind: &str) -> DocumentClaim {
        DocumentClaim::new(kind, [0xd0; 32], vec![[0x0a; 32]], 1_760_000_000)
    }

    #[test]
    fn a_signed_document_verifies_and_pins() {
        let signed = keypair().sign_document(&claim("reference-run/v1"), &[3u8; 32]).unwrap();
        assert_eq!(signed.verify(), Ok(()));
        assert_eq!(signed.verify_signed_by(&keypair().public_key()), Ok(()));
        let other = PublisherKeypair::generate(&[9u8; 32]).unwrap();
        assert!(matches!(
            signed.verify_signed_by(&other.public_key()),
            Err(TvcError::SignerMismatch { .. })
        ));
    }

    #[test]
    fn a_document_signature_does_not_transfer_between_kinds() {
        let signed = keypair().sign_document(&claim("reference-run/v1"), &[3u8; 32]).unwrap();
        let mut relabelled = signed;
        relabelled.claim.kind = "profile/v1".to_owned();
        assert_eq!(relabelled.verify(), Err(TvcError::AttestationUnsigned));
    }

    #[test]
    fn every_claim_field_is_covered_by_the_signature() {
        let signed = keypair().sign_document(&claim("reference-run/v1"), &[3u8; 32]).unwrap();

        let mut other_document = signed.clone();
        other_document.claim.document[0] ^= 1;
        assert_eq!(other_document.verify(), Err(TvcError::AttestationUnsigned));

        let mut other_refs = signed.clone();
        other_refs.claim.refs.push([0x0b; 32]);
        assert_eq!(other_refs.verify(), Err(TvcError::AttestationUnsigned));

        let mut no_refs = signed.clone();
        no_refs.claim.refs.clear();
        assert_eq!(no_refs.verify(), Err(TvcError::AttestationUnsigned));

        let mut backdated = signed;
        backdated.claim.timestamp -= 1;
        assert_eq!(backdated.verify(), Err(TvcError::AttestationUnsigned));
    }

    #[test]
    fn the_sighash_names_the_signer() {
        // The same claim under two signers is two different messages, visible to
        // anyone re-deriving the sighash without the signature in hand.
        let first = PublisherKeypair::generate(&[1u8; 32]).unwrap();
        let second = PublisherKeypair::generate(&[2u8; 32]).unwrap();
        let claim = claim("reference-run/v2");
        assert_ne!(claim.sighash(&first.public_key()), claim.sighash(&second.public_key()));
    }

    #[test]
    fn a_signature_does_not_verify_under_a_substituted_signer() {
        let signed = keypair().sign_document(&claim("reference-run/v2"), &[3u8; 32]).unwrap();
        let mut relabelled = signed;
        relabelled.signer = PublisherKeypair::generate(&[9u8; 32]).unwrap().public_key();
        assert_eq!(relabelled.verify(), Err(TvcError::AttestationUnsigned));
    }

    #[test]
    fn kinds_must_be_name_slash_version() {
        for good in ["reference-run/v1", "weights-manifest/v1", "profile/v12", "x9/v0"] {
            assert!(validate_kind(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "reference-run",
            "reference-run/1",
            "Reference-Run/v1",
            "reference run/v1",
            "-run/v1",
            "run/v",
            "run/v1x",
            "a/b/v1",
        ] {
            assert!(validate_kind(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn repeated_or_self_references_are_refused() {
        let mut repeated = claim("profile/v1");
        repeated.refs = vec![[1; 32], [1; 32]];
        assert!(keypair().sign_document(&repeated, &[3u8; 32]).is_err());

        let mut circular = claim("profile/v1");
        circular.refs = vec![circular.document];
        assert!(keypair().sign_document(&circular, &[3u8; 32]).is_err());
    }
}
