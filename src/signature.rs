use crate::{Error, PublicKey, truncated_hash};
use bls12_381::{
    G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, multi_miller_loop,
};

/// The BLS signature of a specific message. It also can be the aggregation
/// of many signatures, either of the same or different messages.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Signature(pub(crate) G1Affine);

impl Signature {
    /// Verifies a BLS signature, given the message and the corresponding
    /// public key, and returns a bool.
    pub fn verify(&self, message: &[u8], pk: &PublicKey) -> bool {
        let hash = truncated_hash(message);

        let pairings_check = multi_miller_loop(&[
            (&self.0, &G2Affine::generator().into()),
            (&(-hash).into(), &pk.0.into()),
        ])
        .final_exponentiation();

        pairings_check == Gt::identity()
    }

    /// Verifies an aggregated BLS signature of a given message, given the corresponding public
    /// keys, and returns a bool.
    pub fn verify_aggregated_same_msg(&self, message: &[u8], pks: &[PublicKey]) -> bool {
        let aggregated_pk = pks
            .iter()
            .fold(G2Projective::identity(), |acc, pk| acc + pk.0);

        self.verify(message, &PublicKey(G2Affine::from(aggregated_pk)))
    }

    /// Verifies an aggregated BLS signature of different messages, given the corresponding public
    /// keys, and returns a bool.
    pub fn verify_aggregated_diff_msg(&self, messages: &[&[u8]], pks: &[PublicKey]) -> bool {
        let mut pairing_inputs = vec![(-self.0, G2Prepared::from(G2Affine::generator()))];

        for i in 0..messages.len() {
            let hash = G1Affine::from(truncated_hash(messages[i]));
            let pk = G2Prepared::from(pks[i].0);
            pairing_inputs.push((hash, pk));
        }

        let ref_vec: Vec<_> = pairing_inputs.iter().map(|(x, y)| (x, y)).collect();
        let pairings_check = multi_miller_loop(&ref_vec).final_exponentiation();

        pairings_check == Gt::identity()
    }

    /// Aggregates a set of BLS signatures.
    pub fn aggregate(sigs: &[Signature]) -> Self {
        let aggregated_sig = sigs
            .iter()
            .fold(G1Projective::identity(), |acc, sig| acc + sig.0);

        Self(G1Affine::from(aggregated_sig))
    }

    /// Serializes the signature into a byte representation in compressed form
    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.to_compressed()
    }

    /// Deserializes a byte representation in compressed form into a signature
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, Error> {
        let point = G1Affine::from_compressed(bytes);
        match point.is_some().unwrap_u8() {
            1 => Ok(Signature(point.unwrap())),
            _ => Err(Error::InvalidBytes),
        }
    }

    /// Negates a signature to prepare it for pairing verification, and serializes it
    /// into a byte representation in uncompressed form suitable for its usage with
    /// EVM precompiles.
    pub fn to_evm_bytes(&self) -> [u8; 128] {
        let bytes = (-self.0).to_uncompressed();
        let mut evm_bytes = [0u8; 128];
        evm_bytes[16..64].copy_from_slice(&bytes[..48]);
        evm_bytes[80..].copy_from_slice(&bytes[48..]);

        evm_bytes
    }

    /// Deserializes a byte representation in EVM-style uncompressed form into a signature,
    /// and negates it to reverse the previous negation.
    pub fn from_evm_bytes(bytes: &[u8; 128]) -> Result<Self, Error> {
        let mut point_bytes = [0u8; 96];

        point_bytes[..48].copy_from_slice(&bytes[16..64]);
        point_bytes[48..].copy_from_slice(&bytes[80..]);

        let point = G1Affine::from_uncompressed(&point_bytes);
        match point.is_some().unwrap_u8() {
            1 => Ok(Signature(-point.unwrap())),
            _ => Err(Error::InvalidBytes),
        }
    }
}
