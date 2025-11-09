# BLS signatures in Rust

This repository includes the implementation of BLS signatures in Rust, using the BLS12-381 elliptic curve. It uses keccak256 as a hashing function, to have maximum optimization for verifications on EVMs.

**DISCLAIMER:** the code in this repository has NOT went through an exhaustive security review. Use at your own risk.

## Example

```rust
use bls_signatures_evm::*;
use rand::rngs::OsRng;
    
// Generate the secret and public keys
let (sk, pk) = generate_keypair(&mut OsRng);

// Sign a message with a secret key
let msg = 1234u64.to_be_bytes();
let sig = sign(sk, &msg);

// Verify a signature with a public key 
assert!(verify(pk, &msg, sig));

// Sign the same message with another key
let (sk2, pk2) = generate_keypair(&mut OsRng);
let sig2 = sign(sk2, &msg);

// Aggregate both signatures
let aggr_sig = aggregate(&[sig, sig2]);

// Verify the aggregated signature using the public keys
assert!(verify_aggregated_same_msg(&[pk, pk2], &msg, aggr_sig));

// Sign a different message with the second key
let msg_diff = 5678u64.to_be_bytes();
let sig_diff = sign(sk2, &msg_diff);

// Aggregate both signatures of different messages
let aggr_sig_diff = aggregate(&[sig, sig_diff]);

// Verify the aggregated signature using the public keys
assert!(verify_aggregated_diff_msg(
    &[pk, pk2],
    &[&msg, &msg_diff],
    aggr_sig_diff
));
```

## Benchmarks

To benchmark the library, simply run:

```ignore
cargo bench
```
