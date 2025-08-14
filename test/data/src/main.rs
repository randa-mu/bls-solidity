use ark_ec::AffineRepr;
use utils::hash_to_curve::CustomPairingHashToCurve;

use ark_ff::fields::Field;
use rand::RngCore;
use std::fs::File;
use std::path::Path;

use ark_ec::CurveGroup;
use std::str::FromStr;

use digest::{DynDigest, core_api::BlockSizeUser};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct TestCase {
    dst: String,
    message: String,
    // points are marshalled then hex encoded
    pk: String,
    m_expected: String,
    sig: String,
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

fn main() -> anyhow::Result<()> {
    let msg = "hello";

    let sk = ark_bls12_381::Fr::from_str(
        "19153223051490343243824650241849417450498737914923078729384628564540018524693",
    )
    .unwrap();

    test_case::<sha2::Sha256>(
        "BLS12_381G1_XMD:SHA-256_SVDW_RO",
        msg,
        sk,
        &Path::new("bls2_g1_sha256.json"),
    )?;
    test_case::<sha3::Keccak256>(
        "BLS12_381G1_XMD:KECCAK-256_SVDW_RO",
        msg,
        sk,
        &Path::new("bls2_g1_keccak256.json"),
    )?;
    Ok(())
}

fn test_case<H: DynDigest + BlockSizeUser + Default + Clone>(
    dst: &str,
    msg: &str,
    sk: ark_bls12_381::Fr,
    dest: &Path,
) -> anyhow::Result<()> {
    let pk = ark_bls12_381::G2Affine::generator() * sk;
    let m = ark_ec::bls12::Bls12::<ark_bls12_381::Config>::hash_to_g1_custom::<H>(
        msg.as_bytes(),
        dst.as_bytes(),
    );
    let sig = (m * sk).into_affine();

    let tc = TestCase {
        dst: dst.to_string(),
        message: msg.to_string(),
        pk: hex_serialize(&pk),
        m_expected: hex_serialize(&m),
        sig: hex_serialize(&sig),
    };

    serde_json::to_writer_pretty(&mut File::create(dest)?, &tc)?;
    Ok(())
}
