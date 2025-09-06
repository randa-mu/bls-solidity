use utils::hash_to_curve::CustomPairingHashToCurve;

use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::{BigInt, PrimeField, Zero};

use dcipher_agents::ser::EvmSerialize;

use digest::Digest;

use serde::{Deserialize, Serialize};

use std::fs::File;

#[derive(Serialize, Deserialize)]
struct TestCase {
    dst: String,
    message: String,
    // points are marshalled then hex encoded
    pk: String,
    m_expected: String,
    scheme: String, // either "BN254" or "BLS12381"
    sig: String,
    sig_compressed: String,
    drand_round_number: u64, // Optional: 0 if n/a
    application: String,
}

static BN254_DST: &str = "BN254G1_XMD:KECCAK-256_SVDW_RO";
static BLS12_DST: &str = "BLS12_381G1_XMD:SHA-256_SSWU_RO";

fn hex_serialize(p: &impl ark_serialize::CanonicalSerialize) -> String {
    let mut buf = vec![];
    p.serialize_uncompressed(&mut buf).unwrap();
    hex::encode(buf)
}

fn hex_deserialize<T: ark_serialize::CanonicalDeserialize>(s: &str) -> T {
    let bytes = hex::decode(s).unwrap();
    T::deserialize_compressed(&mut &bytes[..]).unwrap()
}

fn bn254_g2_deser(bytes: Vec<u8>) -> ark_bn254::G2Affine {
    use ark_bn254::{Fq, Fq2};

    let x_c1 = Fq::from_be_bytes_mod_order(&bytes[0..32]);
    let x_c0 = Fq::from_be_bytes_mod_order(&bytes[32..64]);
    let y_c1 = Fq::from_be_bytes_mod_order(&bytes[64..96]);
    let y_c0 = Fq::from_be_bytes_mod_order(&bytes[96..128]);

    ark_bn254::G2Affine::new(Fq2::new(x_c0, x_c1), Fq2::new(y_c0, y_c1))
}

fn bn254_g1_deser(bytes: Vec<u8>) -> ark_bn254::G1Affine {
    use ark_bn254::Fq;

    let x = Fq::from_be_bytes_mod_order(&bytes[0..32]);
    let y = Fq::from_be_bytes_mod_order(&bytes[32..64]);

    ark_bn254::G1Affine::new(x, y)
}

fn main() -> anyhow::Result<()> {
    let msg = "hello";

    let sk = ark_bls12_381::Fr::new(BigInt::new([0, 0, 0, 0xdeadbeef]));

    serde_json::to_writer_pretty(
        File::create("testcases.json")?,
        &[
            test_case_bls12_381(msg, sk),
            test_case_bn254(msg, ark_bn254::Fr::new(BigInt::new([0, 0, 0, 0xdeadbeef]))),
            quicknet_test_case(
                "8d2c8bbc37170dbacc5e280a21d4e195cff5f32a19fd6a58633fa4e4670478b5fb39bc13dd8f8c4372c5a76191198ac5",
                20791007,
            ),
            quicknet_test_case(
                "8a60486975062d9f06633c284cf1a7b46fb343f56f329f180530ca40a9e86320244f4fbfc37ae866cf25ef499665a31f",
                20905307,
            ),
            evmnet_test_case(
                "01d65d6128f4b2df3d08de85543d8efe06b0281d0770246ae3672e8ddd3efda0269373123458f0b5c0073eeed1c816a06809e127421513e34ee07df6987910b3",
                9337227,
            ),
        ],
    )?;
    Ok(())
}

fn test_case_bls12_381(msg: &str, sk: ark_bls12_381::Fr) -> TestCase {
    let dst = BLS12_DST;
    let p = (ark_bls12_381::G2Affine::generator() * sk).into_affine();
    let m =
        Bls12_381::hash_to_g1_custom::<sha2::Sha256>(msg.as_bytes(), dst.as_bytes()).into_affine();
    let s = (m * sk).into_affine();

    assert!(
        Bls12_381::multi_pairing(&[m, s], &[p, -ark_bls12_381::G2Affine::generator()]).is_zero()
    );

    TestCase {
        dst: dst.to_owned(),
        scheme: "BLS12381".to_owned(),
        message: hex::encode(msg),
        pk: hex_serialize(&p),
        m_expected: hex_serialize(&m),
        sig: hex_serialize(&s),
        sig_compressed: hex::encode(s.ser_bytes()),
        drand_round_number: 0,
        application: "".to_owned(),
    }
}

fn test_case_bn254(msg: &str, sk: ark_bn254::Fr) -> TestCase {
    let dst = BN254_DST;
    let p = (ark_bn254::G2Affine::generator() * sk).into_affine();
    let m =
        Bn254::hash_to_g1_custom::<sha3::Keccak256>(msg.as_bytes(), dst.as_bytes()).into_affine();
    let s = (m * sk).into_affine();

    assert!(Bn254::multi_pairing(&[m, s], &[p, -ark_bn254::G2Affine::generator()]).is_zero());

    TestCase {
        dst: dst.to_owned(),
        scheme: "BN254".to_owned(),
        message: hex::encode(msg),
        pk: hex::encode(p.ser_bytes()),
        m_expected: hex::encode(m.ser_bytes()),
        sig: hex::encode(s.ser_bytes()),
        sig_compressed: "not applicable".to_owned(),
        drand_round_number: 0,
        application: "".to_owned(),
    }
}

fn quicknet_test_case(sig: &str, round: u64) -> TestCase {
    let dst = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    let pk = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
    let p = hex_deserialize(pk);
    let s = hex_deserialize(sig);
    let msg = &sha2::Sha256::digest(round.to_be_bytes());
    let m = Bls12_381::hash_to_g1_custom::<sha2::Sha256>(msg, dst.as_bytes());

    assert!(
        Bls12_381::multi_pairing(&[m, s], &[p, -ark_bls12_381::G2Affine::generator()]).is_zero()
    );

    TestCase {
        dst: dst.to_owned(),
        scheme: "BLS12381".to_owned(),
        message: hex::encode(msg),
        pk: hex_serialize(&p), // uncompressed
        m_expected: hex_serialize(&m),
        sig: hex_serialize(&s),
        sig_compressed: sig.to_owned(),
        drand_round_number: round,
        application: "".to_owned(),
    }
}

fn evmnet_test_case(sig: &str, round: u64) -> TestCase {
    let dst = "BLS_SIG_BN254G1_XMD:KECCAK-256_SVDW_RO_NUL_";

    let pk = "07e1d1d335df83fa98462005690372c643340060d205306a9aa8106b6bd0b3820557ec32c2ad488e4d4f6008f89a346f18492092ccc0d594610de2732c8b808f0095685ae3a85ba243747b1b2f426049010f6b73a0cf1d389351d5aaaa1047f6297d3a4f9749b33eb2d904c9d9ebf17224150ddd7abd7567a9bec6c74480ee0b";
    let p = bn254_g2_deser(hex::decode(pk).unwrap());
    let s = bn254_g1_deser(hex::decode(sig).unwrap());
    let msg = &sha3::Keccak256::digest(round.to_be_bytes());
    let m = Bn254::hash_to_g1_custom::<sha3::Keccak256>(msg, dst.as_bytes()).into_affine();

    assert!(Bn254::multi_pairing(&[m, s], &[p, -ark_bn254::G2Affine::generator()]).is_zero());

    TestCase {
        dst: dst.to_owned(),
        scheme: "BN254".to_owned(),
        message: hex::encode(msg),
        pk: pk.to_owned(),
        m_expected: hex::encode(m.ser_bytes()),
        sig: sig.to_owned(),
        sig_compressed: "not applicable".to_owned(),
        drand_round_number: round,
        application: "".to_owned(),
    }
}
