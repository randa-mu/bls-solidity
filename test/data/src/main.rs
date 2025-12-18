use utils::hash_to_curve::CustomPairingHashToCurve;
use utils::serialize::point::{
    PointDeserializeCompressed, PointDeserializeUncompressed, PointSerializeCompressed,
    PointSerializeUncompressed,
};

use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::{BigInt, Zero};

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
static BLS12_DST: &str = "BLS12381G1_XMD:SHA-256_SSWU_RO";

// Chain ID 31337: anvil
static HEX_CHAINID: &str = "0x0000000000000000000000000000000000000000000000000000000000007a69";

fn hex_ser_compressed(p: &impl PointSerializeCompressed) -> String {
    hex::encode(p.ser_compressed().unwrap())
}

fn hex_ser_uncompressed(p: &impl PointSerializeUncompressed) -> String {
    hex::encode(p.ser_uncompressed().unwrap())
}

fn hex_deser_compressed<T: PointDeserializeCompressed>(s: &str) -> T {
    let bytes = hex::decode(s).unwrap();
    T::deser_compressed(&mut &bytes[..]).unwrap()
}

fn hex_deser_uncompressed<T: PointDeserializeUncompressed>(s: &str) -> T {
    let bytes = hex::decode(s).unwrap();
    T::deser_uncompressed(&mut &bytes[..]).unwrap()
}

fn main() -> anyhow::Result<()> {
    let msg = "hello";

    let bls12_sk = ark_bls12_381::Fr::new(BigInt::new([0, 0, 0, 0xdeadbeef]));
    let bn254_sk = ark_bn254::Fr::new(BigInt::new([0, 0, 0, 0xdeadbeef]));

    serde_json::to_writer_pretty(
        File::create("testcases.json")?,
        &[
            bls12_test_case(msg, bls12_sk),
            bn254_test_case(msg, bn254_sk),
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
            dcipher_bls12_test_case("dcipher-helloworld-v01", msg, bls12_sk),
            dcipher_bn254_test_case("dcipher-helloworld-v01", msg, bn254_sk),
        ],
    )?;
    Ok(())
}

fn dcipher_bls12_test_case(app: &str, msg: &str, sk: ark_bls12_381::Fr) -> TestCase {
    let dst = format!("{app}-{BLS12_DST}_{HEX_CHAINID}_");
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
        pk: hex_ser_uncompressed(&p),
        m_expected: hex_ser_uncompressed(&m),
        sig: hex_ser_uncompressed(&s),
        sig_compressed: hex_ser_compressed(&s),
        drand_round_number: 0,
        application: app.to_owned(),
    }
}

fn dcipher_bn254_test_case(app: &str, msg: &str, sk: ark_bn254::Fr) -> TestCase {
    let dst = format!("{app}-{BN254_DST}_{HEX_CHAINID}_");
    let p = (ark_bn254::G2Affine::generator() * sk).into_affine();
    let m =
        Bn254::hash_to_g1_custom::<sha3::Keccak256>(msg.as_bytes(), dst.as_bytes()).into_affine();
    let s = (m * sk).into_affine();

    assert!(Bn254::multi_pairing(&[m, s], &[p, -ark_bn254::G2Affine::generator()]).is_zero());

    TestCase {
        dst: dst.to_owned(),
        scheme: "BN254".to_owned(),
        message: hex::encode(msg),
        pk: hex_ser_uncompressed(&p),
        m_expected: hex_ser_uncompressed(&m),
        sig: hex_ser_uncompressed(&s),
        sig_compressed: hex_ser_compressed(&s),
        drand_round_number: 0,
        application: app.to_owned(),
    }
}

fn bls12_test_case(msg: &str, sk: ark_bls12_381::Fr) -> TestCase {
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
        pk: hex_ser_uncompressed(&p),
        m_expected: hex_ser_uncompressed(&m),
        sig: hex_ser_uncompressed(&s),
        sig_compressed: hex_ser_compressed(&s),
        drand_round_number: 0,
        application: "".to_owned(),
    }
}

fn bn254_test_case(msg: &str, sk: ark_bn254::Fr) -> TestCase {
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
        pk: hex_ser_uncompressed(&p),
        m_expected: hex_ser_uncompressed(&m),
        sig: hex_ser_uncompressed(&s),
        sig_compressed: hex_ser_compressed(&s),
        drand_round_number: 0,
        application: "".to_owned(),
    }
}

fn quicknet_test_case(sig: &str, round: u64) -> TestCase {
    let dst = format!("BLS_SIG_{BLS12_DST}_NUL_");

    let pk = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
    let p = hex_deser_compressed(pk);
    let s = hex_deser_compressed(sig);
    let msg = &sha2::Sha256::digest(round.to_be_bytes());
    let m = Bls12_381::hash_to_g1_custom::<sha2::Sha256>(msg, dst.as_bytes());

    assert!(
        Bls12_381::multi_pairing(&[m, s], &[p, -ark_bls12_381::G2Affine::generator()]).is_zero()
    );

    TestCase {
        dst: dst.to_owned(),
        scheme: "BLS12381".to_owned(),
        message: hex::encode(msg),
        pk: hex_ser_uncompressed(&p),
        m_expected: hex_ser_uncompressed(&m),
        sig: hex_ser_uncompressed(&s),
        sig_compressed: sig.to_owned(),
        drand_round_number: round,
        application: "".to_owned(),
    }
}

fn evmnet_test_case(sig: &str, round: u64) -> TestCase {
    let dst = format!("BLS_SIG_{BN254_DST}_NUL_");

    let pk = "07e1d1d335df83fa98462005690372c643340060d205306a9aa8106b6bd0b3820557ec32c2ad488e4d4f6008f89a346f18492092ccc0d594610de2732c8b808f0095685ae3a85ba243747b1b2f426049010f6b73a0cf1d389351d5aaaa1047f6297d3a4f9749b33eb2d904c9d9ebf17224150ddd7abd7567a9bec6c74480ee0b";
    let p = hex_deser_uncompressed(pk);
    let s = hex_deser_uncompressed(sig);
    let msg = &sha3::Keccak256::digest(round.to_be_bytes());
    let m = Bn254::hash_to_g1_custom::<sha3::Keccak256>(msg, dst.as_bytes()).into_affine();

    assert!(Bn254::multi_pairing(&[m, s], &[p, -ark_bn254::G2Affine::generator()]).is_zero());

    TestCase {
        dst: dst.to_owned(),
        scheme: "BN254".to_owned(),
        message: hex::encode(msg),
        pk: pk.to_owned(),
        m_expected: hex_ser_uncompressed(&m),
        sig: sig.to_owned(),
        sig_compressed: hex_ser_compressed(&s),
        drand_round_number: round,
        application: "".to_owned(),
    }
}
