use ark_ec::AffineRepr;
use make_test_signature::signer::{BLS12_381SignatureOnG1Signer, bls12381_hash_to_g1_custom};

use ark_ff::fields::Field;
use dcipher_signer::BlsSigner;
use rand::RngCore;

use ark_bls12_381::{Fq, G1Affine, G2Affine};
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use std::str::FromStr;

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

fn solidity_repr_g1(p: G1Affine) -> String {
    format!(
        "BLS2.PointG1({}, {})",
        solidity_repr_fp(p.x),
        solidity_repr_fp(p.y)
    )
}

fn solidity_repr_g2(p: G2Affine) -> String {
    format!(
        "BLS2.PointG2({}, {})",
        solidity_repr_fq2(p.x),
        solidity_repr_fq2(p.y)
    )
}

fn solidity_repr_fp(x: Fq) -> String {
    let bytes = x.into_bigint().to_bytes_be();
    assert!(bytes.len() == 48);
    format!(
        "0x{}, 0x{}",
        hex::encode(&bytes[0..16]),
        hex::encode(&bytes[16..48])
    )
}

fn solidity_repr_fq2(x: ark_bls12_381::Fq2) -> String {
    let x0 = solidity_repr_fp(x.c0);
    let x1 = solidity_repr_fp(x.c1);
    format!("{}, {}", x0, x1)
}

fn main() -> anyhow::Result<()> {
    let dst = b"BLS12_381G1_XMD:KECCAK-256_SVDW_RO";

    let sk = ark_bls12_381::Fr::from_str(
        "19153223051490343243824650241849417450498737914923078729384628564540018524693",
    )
    .unwrap();
    let pk = ark_bls12_381::G2Affine::generator() * sk;
    let cs = BLS12_381SignatureOnG1Signer::new(sk, dst.to_vec());

    let msg = "hello";
    let m_expected = bls12381_hash_to_g1_custom::<sha3::Keccak256>(msg.as_ref(), dst);
    let sig = cs.sign(msg)?;
    println!("pk = {};", solidity_repr_g2(pk.into()));
    println!("message = \"{}\";", msg);
    println!("m_expected = {};", solidity_repr_g1(m_expected.into()));
    println!("sig = {};", solidity_repr_g1(sig));
    Ok(())
}
