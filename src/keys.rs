use crate::{Signature, truncated_hash};
use bls12_381::{G1Affine, G2Affine, Scalar};
use ff::Field;
use rand::RngCore;

/// The secret key used to sign messages.
pub struct SecretKey(Scalar);

impl SecretKey {
    /// Generates a new secret key, a scalar selected at random.
    pub fn random(rng: impl RngCore) -> Self {
        Self(Scalar::random(rng))
    }

    /// Produces a BLS signature of a message.
    ///
    /// IMPORTANT: it hashes the message using [`truncated_hash()`], which drops
    /// 2 bits from the hashed value before mapping to the group. This reduces the
    /// security bits of the scheme.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let hash = truncated_hash(message);
        Signature(G1Affine::from(hash * self.0))
    }
}

/// The public key used to verify signatures.
#[derive(Clone, Copy)]
pub struct PublicKey(pub(crate) G2Affine);

impl From<&SecretKey> for PublicKey {
    /// Compute a public key, a point in G2, obtained by multiplying sk
    /// by G2's generator.
    fn from(sk: &SecretKey) -> PublicKey {
        PublicKey(G2Affine::from(G2Affine::generator() * sk.0))
    }
}
