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
```
