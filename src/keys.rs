use crate::{Error, Signature, truncated_hash};
use bls12_381::{G1Affine, G2Affine, Scalar};
use ff::Field;
use rand::RngCore;

/// The secret key used to sign messages.
#[derive(Debug, PartialEq)]
pub struct SecretKey(Scalar);

impl SecretKey {
    /// Generates a new secret key, a scalar selected at random.
    pub fn random(rng: impl RngCore) -> Self {
        Self(Scalar::random(rng))
    }

    /// Produces a BLS signature of a message.
    ///
    /// IMPORTANT: it hashes the message using truncated_hash(), which drops
    /// 2 bits from the hashed value before mapping to the group. This reduces the
    /// security bits of the scheme.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let hash = truncated_hash(message);
        Signature(G1Affine::from(hash * self.0))
    }

    /// Serializes the secret key into a byte representation in little-endian.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Deserializes a byte representation in little-endian into a secret key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let scalar = Scalar::from_bytes(bytes);
        match scalar.is_some().unwrap_u8() {
            1 => Ok(SecretKey(scalar.unwrap())),
            _ => Err(Error::InvalidBytes),
        }
    }
}

/// The public key used to verify signatures.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PublicKey(pub(crate) G2Affine);

impl PublicKey {
    /// Serializes the public key into a byte representation in compressed form.
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_compressed()
    }

    /// Deserializes a byte representation in compressed form into a public key.
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, Error> {
        let point = G2Affine::from_compressed(bytes);
        match point.is_some().unwrap_u8() {
            1 => Ok(PublicKey(point.unwrap())),
            _ => Err(Error::InvalidBytes),
        }
    }

    /// Serializes the public key into a byte representation in uncompressed form
    /// suitable for its usage with EVM precompiles.
    pub fn to_evm_bytes(&self) -> [u8; 256] {
        let bytes = self.0.to_uncompressed();
        let mut evm_bytes = [0u8; 256];

        evm_bytes[16..64].copy_from_slice(&bytes[48..96]);
        evm_bytes[80..128].copy_from_slice(&bytes[..48]);
        evm_bytes[144..192].copy_from_slice(&bytes[144..]);
        evm_bytes[208..].copy_from_slice(&bytes[96..144]);

        evm_bytes
    }

    /// Deserializes a byte representation in EVM-style uncompressed form into a public key.
    pub fn from_evm_bytes(bytes: &[u8; 256]) -> Result<Self, Error> {
        let mut point_bytes = [0u8; 192];

        point_bytes[48..96].copy_from_slice(&bytes[16..64]);
        point_bytes[..48].copy_from_slice(&bytes[80..128]);
        point_bytes[144..].copy_from_slice(&bytes[144..192]);
        point_bytes[96..144].copy_from_slice(&bytes[208..]);

        let point = G2Affine::from_uncompressed(&point_bytes);
        match point.is_some().unwrap_u8() {
            1 => Ok(PublicKey(point.unwrap())),
            _ => Err(Error::InvalidBytes),
        }
    }
}

impl From<&SecretKey> for PublicKey {
    /// Compute a public key, a point in G2, obtained by multiplying sk
    /// by G2's generator.
    fn from(sk: &SecretKey) -> PublicKey {
        PublicKey(G2Affine::from(G2Affine::generator() * sk.0))
    }
}
