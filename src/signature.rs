use crate::{PublicKey, truncated_hash};
use bls12_381::{
    G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, multi_miller_loop,
};

#[derive(Clone, Copy)]
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

    /// Aggregates a set of BLS signatures
    pub fn aggregate(sigs: &[Signature]) -> Self {
        let aggregated_sig = sigs
            .iter()
            .fold(G1Projective::identity(), |acc, sig| acc + sig.0);

        Self(G1Affine::from(aggregated_sig))
    }
}
