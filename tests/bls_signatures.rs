use bls_signatures_evm::*;
use bls12_381::Scalar;
use ff::Field;
use rand::rngs::OsRng;

#[test]
fn test_sign_verify() {
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from(&sk);

    let msg = 1234u64.to_be_bytes();
    let sig = sk.sign(&msg);

    assert!(sig.verify(&msg, &pk));

    let msg = Scalar::random(&mut OsRng).to_bytes();
    let sig = sk.sign(&msg);

    assert!(sig.verify(&msg, &pk));
}

#[test]
fn test_aggr_same_message() {
    let sk1 = SecretKey::random(&mut OsRng);
    let pk1 = PublicKey::from(&sk1);
    let sk2 = SecretKey::random(&mut OsRng);
    let pk2 = PublicKey::from(&sk2);

    let msg = 1234u64.to_be_bytes();
    let sig1 = sk1.sign(&msg);
    let sig2 = sk2.sign(&msg);

    let sig = Signature::aggregate(&[sig1, sig2]);

    assert!(sig.verify_aggregated_same_msg(&msg, &[pk1, pk2]));
}

#[test]
fn test_aggr_diff_message() {
    let sk1 = SecretKey::random(&mut OsRng);
    let pk1 = PublicKey::from(&sk1);
    let sk2 = SecretKey::random(&mut OsRng);
    let pk2 = PublicKey::from(&sk2);

    let msg1 = 1234u64.to_be_bytes();
    let msg2 = 5678u64.to_be_bytes();
    let sig1 = sk1.sign(&msg1);
    let sig2 = sk2.sign(&msg2);

    let sig = Signature::aggregate(&[sig1, sig2]);

    assert!(sig.verify_aggregated_diff_msg(&[&msg1, &msg2], &[pk1, pk2],));
}

#[test]
fn test_wrong_key() {
    let sk = SecretKey::random(&mut OsRng);
    let wrong_pk = PublicKey::from(&SecretKey::random(&mut OsRng));

    let msg = 1234u64.to_be_bytes();
    let sig = sk.sign(&msg);

    assert!(!sig.verify(&msg, &wrong_pk));
}

#[test]
fn test_wrong_message() {
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from(&sk);

    let msg = 1234u64.to_be_bytes();
    let sig = sk.sign(&msg);

    let wrong_msg = 5678u64.to_be_bytes();
    assert!(!sig.verify(&wrong_msg, &pk));
}
