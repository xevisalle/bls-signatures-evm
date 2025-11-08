use criterion::{Criterion, criterion_group, criterion_main};

use bls_signatures_evm::*;
use rand::rngs::OsRng;

fn bls_benchmark(c: &mut Criterion) {
    let (sk, pk) = generate_keypair(&mut OsRng);
    let msg = 1234u64.to_be_bytes();
    c.bench_function("Sign a message", |b| b.iter(|| sign(sk, &msg)));

    let sig = sign(sk, &msg);
    c.bench_function("Verify a signature", |b| b.iter(|| verify(pk, &msg, sig)));
}

criterion_group!(benches, bls_benchmark);
criterion_main!(benches);
