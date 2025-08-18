use ark_ec::AffineRepr;
use utils::hash_to_curve::CustomPairingHashToCurve;

use ark_ec::pairing::Pairing;
use ark_ff::fields::Field;
use ark_ff::Zero;
use ark_ff::BigInt;
use rand::RngCore;
use std::fs::File;

use ark_ec::CurveGroup;
use std::str::FromStr;

use digest::Digest;
use digest::{core_api::BlockSizeUser, DynDigest};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct TestCase {
    dst: String,
    message: String,
    // points are marshalled then hex encoded
    pk: String,
    m_expected: String,
    sig: String,
    sig_compressed: String,
}

fn generate_sk() -> ark_bls12_381::Fr {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 32];
    loop {
        rng.fill_bytes(&mut buf);
        if let Some(sk) = ark_bls12_381::Fr::from_random_bytes(&buf) {
            break sk;
        }
    }
}

fn hex_serialize(p: &impl ark_serialize::CanonicalSerialize) -> String {
    let mut buf = vec![];
    p.serialize_uncompressed(&mut buf).unwrap();
    hex::encode(buf)
}

fn hex_serialize_compressed(p: &impl ark_serialize::CanonicalSerialize) -> String {
    let mut buf = vec![];
    p.serialize_compressed(&mut buf).unwrap();
    hex::encode(buf)
}

fn hex_deserialize<T: ark_serialize::CanonicalDeserialize>(s: &str) -> T {
    let bytes = hex::decode(s).unwrap();
    T::deserialize_compressed(&mut &bytes[..]).unwrap()
}

fn main() -> anyhow::Result<()> {
    let msg = "hello";

    let sk = ark_bls12_381::Fr::new(BigInt::new([0,0,0, 0xdeadbeef]));


    serde_json::to_writer_pretty(
        File::create("bls2_g1_sha256.json")?,
    &test_case::<sha2::Sha256>(
        "BLS12_381G1_XMD:SHA-256_SVDW_RO",
        msg,
        sk,
    ))?;
    serde_json::to_writer_pretty(
        File::create("bls2_g1_keccak256.json")?,
    &test_case::<sha3::Keccak256>(
        "BLS12_381G1_XMD:KECCAK-256_SVDW_RO",
        msg,
        sk,
    ))?;
    serde_json::to_writer_pretty(
        File::create("drand_quicknet.json")?,
        &drand_test_case(),
    )?;
    Ok(())
}

fn test_case<H: DynDigest + BlockSizeUser + Default + Clone>(
    dst: &str,
    msg: &str,
    sk: ark_bls12_381::Fr,
) -> TestCase {
    let pk = ark_bls12_381::G2Affine::generator() * sk;
    let m = ark_ec::bls12::Bls12::<ark_bls12_381::Config>::hash_to_g1_custom::<H>(
        msg.as_bytes(),
        dst.as_bytes(),
    );
    let sig = (m * sk).into_affine();

    TestCase {
        dst: dst.to_string(),
        message: hex::encode(msg),
        pk: hex_serialize(&pk),
        m_expected: hex_serialize(&m),
        sig: hex_serialize(&sig),
        sig_compressed: hex_serialize_compressed(&sig),
    }
}

fn drand_test_case() -> TestCase {
    let dst = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    let pk = hex_deserialize("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a");
    let sig = hex_deserialize("8a60486975062d9f06633c284cf1a7b46fb343f56f329f180530ca40a9e86320244f4fbfc37ae866cf25ef499665a31f");
    let round = 20905307u64;
    let msg = &sha2::Sha256::digest(round.to_be_bytes());

    let m = ark_ec::bls12::Bls12::<ark_bls12_381::Config>::hash_to_g1_custom::<sha2::Sha256>(
        msg,
        dst.as_bytes(),
    );

    assert!(ark_bls12_381::Bls12_381::multi_pairing(
        &[m, sig],
        &[pk, -ark_bls12_381::G2Affine::generator()]
    )
    .is_zero());

    TestCase {
        dst: dst.to_string(),
        message: hex::encode(msg),
        pk: hex_serialize(&pk),
        m_expected: hex_serialize(&m),
        sig: hex_serialize(&sig),
        sig_compressed: hex_serialize_compressed(&sig),
    }
}
