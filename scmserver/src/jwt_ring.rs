// =============================================================================
// jwt_ring.rs — the crypto backend jsonwebtoken uses, built on ring
//
// jsonwebtoken 10+ needs a crypto provider. Its own choices are aws-lc-rs (C
// code, a risk for the zigbuild cross-builds) or RustCrypto (pulls in the
// `rsa` crate, see Cargo.toml and .cargo/audit.toml). ring is already in the
// build as rustls's provider, so this file adapts it instead.
//
// Verify only: OpenSCM checks ID tokens from a sign-in provider and never
// issues a token, so signing is refused. Algorithms are the ones
// sso_login.rs accepts: RS256/384/512, PS256/384/512, ES256/384, EdDSA.
// =============================================================================

use jsonwebtoken::crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils};
use jsonwebtoken::errors::{ErrorKind, Result};
use jsonwebtoken::jwk::ThumbprintHash;
use jsonwebtoken::signature::{self, Verifier};
use jsonwebtoken::{Algorithm, DecodingKey, DecodingKeyKind, EncodingKey};
use ring::signature::{self as rs, RsaParameters, RsaPublicKeyComponents, UnparsedPublicKey};

// ─────────────────────────────────────────────────────────────────────────────
// Static: PROVIDER
// Only the verifier and the digest are real; the key utilities are for
// building JWKs from private keys, which OpenSCM never does.
// ─────────────────────────────────────────────────────────────────────────────
static PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: no_signer,
    verifier_factory: new_verifier,
    key_utils: KeyUtils {
        rsa_pub_components_from_private_key: |_| Err(ErrorKind::InvalidAlgorithm.into()),
        rsa_pub_components_from_public_key: |_| Err(ErrorKind::InvalidAlgorithm.into()),
        ec_pub_components_from_private_key: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
        ed_pub_components_from_private_key: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
        compute_digest,
    },
};

// ─────────────────────────────────────────────────────────────────────────────
// Function: install
// Makes this the process's jsonwebtoken provider. Safe to call any number of
// times; only the first call does anything.
// ─────────────────────────────────────────────────────────────────────────────
pub fn install() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Err only if a provider is already installed: nothing to do then.
        let _ = PROVIDER.install_default();
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: no_signer
// OpenSCM never signs a token.
// ─────────────────────────────────────────────────────────────────────────────
fn no_signer(_: &Algorithm, _: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
    Err(ErrorKind::InvalidAlgorithm.into())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: compute_digest
// JWK thumbprints.
// ─────────────────────────────────────────────────────────────────────────────
fn compute_digest(data: &[u8], hash: ThumbprintHash) -> Result<Vec<u8>> {
    let alg = match hash {
        ThumbprintHash::SHA256 => &ring::digest::SHA256,
        ThumbprintHash::SHA384 => &ring::digest::SHA384,
        ThumbprintHash::SHA512 => &ring::digest::SHA512,
        _ => return Err(ErrorKind::InvalidAlgorithm.into()),
    };
    Ok(ring::digest::digest(alg, data).as_ref().to_vec())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: new_verifier
// A verifier for one algorithm and key. The key must be of the algorithm's
// family: an RSA key cannot check an ES256 signature, and so on.
// ─────────────────────────────────────────────────────────────────────────────
fn new_verifier(alg: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
    if !matches!(
        alg,
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512
            | Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512
            | Algorithm::ES256 | Algorithm::ES384 | Algorithm::EdDSA
    ) {
        return Err(ErrorKind::InvalidAlgorithm.into());
    }
    if alg.family() != key.family() {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    Ok(Box::new(RingVerifier { alg: *alg, key: key.clone() }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: rsa_params
// ring's parameters for an RSA algorithm (keys of 2048 to 8192 bits).
// ─────────────────────────────────────────────────────────────────────────────
fn rsa_params(alg: Algorithm) -> Option<&'static RsaParameters> {
    Some(match alg {
        Algorithm::RS256 => &rs::RSA_PKCS1_2048_8192_SHA256,
        Algorithm::RS384 => &rs::RSA_PKCS1_2048_8192_SHA384,
        Algorithm::RS512 => &rs::RSA_PKCS1_2048_8192_SHA512,
        Algorithm::PS256 => &rs::RSA_PSS_2048_8192_SHA256,
        Algorithm::PS384 => &rs::RSA_PSS_2048_8192_SHA384,
        Algorithm::PS512 => &rs::RSA_PSS_2048_8192_SHA512,
        _ => return None,
    })
}

struct RingVerifier {
    alg: Algorithm,
    key: DecodingKey,
}

impl Verifier<Vec<u8>> for RingVerifier {
    // ─────────────────────────────────────────────────────────────────────────
    // Verifier::verify
    // `msg` is header.claims as sent; `sig` the decoded signature. ECDSA
    // signatures in a JWT are fixed-length r||s, not DER.
    // ─────────────────────────────────────────────────────────────────────────
    fn verify(&self, msg: &[u8], sig: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        let checked = match (self.alg, self.key.kind()) {
            (Algorithm::ES256, DecodingKeyKind::SecretOrDer(point)) => {
                UnparsedPublicKey::new(&rs::ECDSA_P256_SHA256_FIXED, point).verify(msg, sig)
            }
            (Algorithm::ES384, DecodingKeyKind::SecretOrDer(point)) => {
                UnparsedPublicKey::new(&rs::ECDSA_P384_SHA384_FIXED, point).verify(msg, sig)
            }
            (Algorithm::EdDSA, DecodingKeyKind::SecretOrDer(public)) => {
                UnparsedPublicKey::new(&rs::ED25519, public).verify(msg, sig)
            }
            (alg, DecodingKeyKind::RsaModulusExponent { n, e }) => match rsa_params(alg) {
                Some(p) => RsaPublicKeyComponents { n, e }.verify(p, msg, sig),
                None => return Err(signature::Error::new()),
            },
            (alg, DecodingKeyKind::SecretOrDer(der)) => match rsa_params(alg) {
                Some(p) => UnparsedPublicKey::new(p, der).verify(msg, sig),
                None => return Err(signature::Error::new()),
            },
        };
        checked.map_err(|_| signature::Error::new())
    }
}

impl JwtVerifier for RingVerifier {
    fn algorithm(&self) -> Algorithm {
        self.alg
    }
}
