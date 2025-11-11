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

#[test]
fn test_serialization() {
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from(&sk);

    let msg = 1234u64.to_be_bytes();
    let sig = sk.sign(&msg);

    assert_eq!(sk, SecretKey::from_bytes(&sk.to_bytes()).unwrap());
    assert_eq!(pk, PublicKey::from_bytes(&pk.to_bytes()).unwrap());
    assert_eq!(sig, Signature::from_bytes(&sig.to_bytes()).unwrap());
}

#[test]
fn test_evm_serialization() {
    let sig_bytes = hex::decode("000000000000000000000000000000000760474b2b63d08796f528dcba365d9cc58c6dc5e4604ecca71a892a9cf323f6bf1b72da86af83e4b595cbf9e2e1b9f10000000000000000000000000000000005c80439057731aeb0d5283f29e5afd253b68a845d322ea28d1de01a4b26389eb5930ded7853c0ecd8cd6f229420b5cd").unwrap();

    let pk_bytes = hex::decode("000000000000000000000000000000000ffe13c2e8ccdb19d846ed0674282d4c6d13642f4ecaefab42eecb70c17c7c95c84bb18095508ee2cf1c9b307d5d36870000000000000000000000000000000005571d872653e05eb3aa495c389ca9a114f58fa3eafdf102c764b64edae10a0983f187fc1ca8140f75c16e4ecef0bda900000000000000000000000000000000176b15b96630b2f9829d62d05e510b4d7a54eddc22c031e0b4d43380ee764a4dfea6ef326ed29b5c11b1556e58daabed00000000000000000000000000000000008ffd3017493b2189bf3493e6ed6d3a6f43c9f68a78ec65c9cea10cd6cc3d416fe802e3000129d6769dc16b21a70bed").unwrap();

    let sig = Signature::from_evm_bytes(&sig_bytes.clone().try_into().unwrap()).unwrap();
    assert_eq!(sig_bytes, sig.to_evm_bytes());

    let pk = PublicKey::from_evm_bytes(&pk_bytes.clone().try_into().unwrap()).unwrap();
    assert_eq!(pk_bytes, pk.to_evm_bytes());
}
