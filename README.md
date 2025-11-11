# BLS signatures in Rust

This repository includes the implementation of BLS signatures in Rust, using the BLS12-381 elliptic curve. It uses keccak256 as a hashing function, to have maximum optimization for verifications on EVMs. Plus, it offers an EVM-specific serialization, compatible with the BLS12-381 precompiles. 

For a BLS signature verification in Solidity compatible with this implementation, check out [this library](https://github.com/xevisalle/solidity-ecc).

**DISCLAIMER:** the code in this repository has NOT went through an exhaustive security review. Use at your own risk.

## Example

```rust
use bls_signatures_evm::*;
use rand::rngs::OsRng;
    
// Generate the secret and public keys
let sk = SecretKey::random(&mut OsRng);
let pk = PublicKey::from(&sk);

// Sign a message with a secret key
let msg = 1234u64.to_be_bytes();
let sig = sk.sign(&msg);

// Verify a signature with a public key 
assert!(sig.verify(&msg, &pk));

// Sign the same message with another key
let sk2 = SecretKey::random(&mut OsRng);
let pk2 = PublicKey::from(&sk2);
let sig2 = sk2.sign(&msg);

// Aggregate both signatures
let aggr_sig = Signature::aggregate(&[sig, sig2]);

// Verify the aggregated signature using the public keys
assert!(aggr_sig.verify_aggregated_same_msg(&msg, &[pk, pk2]));

// Sign a different message with the second key
let msg_diff = 5678u64.to_be_bytes();
let sig_diff = sk2.sign(&msg_diff);

// Aggregate both signatures of different messages
let aggr_sig_diff = Signature::aggregate(&[sig, sig_diff]);

// Verify the aggregated signature using the public keys
assert!(aggr_sig_diff.verify_aggregated_diff_msg(
    &[&msg, &msg_diff],
    &[pk, pk2]
));
```

## Serialization for EVM BLS12-381 precompiles

We implement serialization methods for both `Signature` and `PublicKey` compatible with the EVM BLS12-381 precompiles, that saves us some gas since they don't have to be formatted in-contract. Check out the following example:

```rust
use bls_signatures_evm::*;
use rand::rngs::OsRng;

let sk = SecretKey::random(&mut OsRng);
let pk = PublicKey::from(&sk);

let msg = 1234u64.to_be_bytes();
let sig = sk.sign(&msg);

// We serialize both the public key and the signature
let serialized_pk: [u8; 256] = pk.to_evm_bytes();
let serialized_sig: [u8; 128] = sig.to_evm_bytes();
```

## Benchmarks

To benchmark the library, simply run:

```shell
cargo bench
```
