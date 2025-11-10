use criterion::{Criterion, criterion_group, criterion_main};

use bls_signatures_evm::*;
use rand::rngs::OsRng;

fn bls_benchmark(c: &mut Criterion) {
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from(&sk);

    let msg = 1234u64.to_be_bytes();
    c.bench_function("Sign a message", |b| b.iter(|| sk.sign(&msg)));

    let sig = sk.sign(&msg);
    c.bench_function("Verify a signature", |b| b.iter(|| sig.verify(&msg, &pk)));
}

criterion_group!(benches, bls_benchmark);
criterion_main!(benches);
