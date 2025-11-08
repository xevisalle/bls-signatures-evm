//! # bls-signatures-evm
//!
//! This library includes the implementation of BLS signatures
//! over the elliptic curve BLS12-381.
//!
//! Ref: https://www.iacr.org/archive/asiacrypt2001/22480516.pdf

#[doc = include_str!("../README.md")]
use bls12_381::{
    G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar, multi_miller_loop,
};
use ff::Field;
use rand::RngCore;
use sha3::{Digest, Keccak256};

// Hashes a message to the curve's G1. To do so, it first produces the keccak256
// hash of the message, then truncates 2 bits, and finally multiplies by the
// generator of G1.
fn truncated_hash(message: &[u8]) -> G1Projective {
    let mut hasher = Keccak256::new();
    hasher.update(message);

    let mut hash: [u8; 32] = hasher.finalize().into();
    hash[31] &= 0b0011_1111;

    G1Affine::generator() * Scalar::from_bytes(&hash).unwrap()
}

/// Generates a keypair (sk, pk), where sk is a scalar selected at random, and
/// pk is a point in G2, obtained by multiplying sk by G2's generator.
pub fn generate_keypair(rng: impl RngCore) -> (Scalar, G2Affine) {
    let sk = Scalar::random(rng);
    (sk, G2Affine::from(G2Affine::generator() * sk))
}

/// Produces a BLS signature of a message, given a secret key.
///
/// IMPORTANT: it hashes the message using [`truncated_hash()`], which drops
/// 2 bits from the hashed value before mapping to the group. This reduces the
/// security bits of the scheme.
pub fn sign(sk: Scalar, message: &[u8]) -> G1Affine {
    let hash = truncated_hash(message);
    G1Affine::from(hash * sk)
}

/// Verifies a BLS signature, given the corresponding public key, and
/// returns a bool.
pub fn verify(pk: G2Affine, message: &[u8], sig: G1Affine) -> bool {
    let hash = truncated_hash(message);

    let pairings_check = multi_miller_loop(&[
        (&sig, &G2Affine::generator().into()),
        (&(-hash).into(), &pk.into()),
    ])
    .final_exponentiation();

    pairings_check == Gt::identity()
}

/// Aggregates a set of BLS signatures
pub fn aggregate(sigs: &[G1Affine]) -> G1Affine {
    let aggregated_sig = sigs
        .iter()
        .fold(G1Projective::identity(), |acc, sig| acc + sig);

    G1Affine::from(aggregated_sig)
}

/// Verifies an aggregated BLS signature of a given message, given the corresponding public
/// keys, and returns a bool.
pub fn verify_aggregated_same_msg(pks: &[G2Affine], message: &[u8], sig: G1Affine) -> bool {
    let aggregated_pk = pks
        .iter()
        .fold(G2Projective::identity(), |acc, pk| acc + pk);

    verify(G2Affine::from(aggregated_pk), message, sig)
}

/// Verifies an aggregated BLS signature of different messages, given the corresponding public
/// keys, and returns a bool.
pub fn verify_aggregated_diff_msg(pks: &[G2Affine], messages: &[&[u8]], sig: G1Affine) -> bool {
    let mut pairing_inputs = vec![(-sig, G2Prepared::from(G2Affine::generator()))];

    for i in 0..messages.len() {
        let hash = G1Affine::from(truncated_hash(messages[i]));
        let pk = G2Prepared::from(pks[i]);
        pairing_inputs.push((hash, pk));
    }

    let ref_vec: Vec<_> = pairing_inputs.iter().map(|(x, y)| (x, y)).collect();
    let pairings_check = multi_miller_loop(&ref_vec).final_exponentiation();

    pairings_check == Gt::identity()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_sign_verify() {
        let (sk, pk) = generate_keypair(&mut OsRng);

        let msg = 1234u64.to_be_bytes();
        let sig = sign(sk, &msg);

        assert!(verify(pk, &msg, sig));

        let msg = Scalar::random(&mut OsRng).to_bytes();
        let sig = sign(sk, &msg);

        assert!(verify(pk, &msg, sig));
    }

    #[test]
    fn test_aggr_same_message() {
        let (sk1, pk1) = generate_keypair(&mut OsRng);
        let (sk2, pk2) = generate_keypair(&mut OsRng);

        let msg = 1234u64.to_be_bytes();
        let sig1 = sign(sk1, &msg);
        let sig2 = sign(sk2, &msg);

        let sig = aggregate(&[sig1, sig2]);

        assert!(verify_aggregated_same_msg(&[pk1, pk2], &msg, sig));
    }

    #[test]
    fn test_aggr_diff_message() {
        let (sk1, pk1) = generate_keypair(&mut OsRng);
        let (sk2, pk2) = generate_keypair(&mut OsRng);

        let msg1 = 1234u64.to_be_bytes();
        let msg2 = 5678u64.to_be_bytes();
        let sig1 = sign(sk1, &msg1);
        let sig2 = sign(sk2, &msg2);

        let sig = aggregate(&[sig1, sig2]);

        assert!(verify_aggregated_diff_msg(
            &[pk1, pk2],
            &[&msg1, &msg2],
            sig
        ));
    }

    #[test]
    fn test_wrong_key() {
        let (sk, _) = generate_keypair(&mut OsRng);
        let (_, wrong_pk) = generate_keypair(&mut OsRng);

        let msg = 1234u64.to_be_bytes();
        let sig = sign(sk, &msg);

        assert!(!verify(wrong_pk, &msg, sig));
    }

    #[test]
    fn test_wrong_message() {
        let (sk, pk) = generate_keypair(&mut OsRng);

        let msg = 1234u64.to_be_bytes();
        let sig = sign(sk, &msg);

        let wrong_msg = 5678u64.to_be_bytes();
        assert!(!verify(pk, &wrong_msg, sig));
    }
}
