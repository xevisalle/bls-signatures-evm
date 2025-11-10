//! # bls-signatures-evm
//!
//! This library includes the implementation of BLS signatures
//! over the elliptic curve BLS12-381.
//!
//! Ref: https://www.iacr.org/archive/asiacrypt2001/22480516.pdf

#[doc = include_str!("../README.md")]
use bls12_381::{G1Affine, G1Projective, Scalar};
use sha3::{Digest, Keccak256};

// Hashes a message to the curve's G1. To do so, it first produces the keccak256
// hash of the message, then truncates 2 bits, and finally multiplies by the
// generator of G1.
fn truncated_hash(message: &[u8]) -> G1Projective {
    let mut hasher = Keccak256::new();
    hasher.update(message);

    let mut hash: [u8; 32] = hasher.finalize().into();
    hash[0] &= 0b0011_1111;

    // We reverse to ensure we get the same result in Solidity
    hash.reverse();
    G1Affine::generator() * Scalar::from_bytes(&hash).unwrap()
}

mod keys;
pub use keys::{PublicKey, SecretKey};

mod signature;
pub use signature::Signature;
