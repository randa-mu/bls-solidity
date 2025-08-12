use ark_ec::AffineRepr;
use make_test_signature::signer::BLS12_381SignatureOnG1Signer;

use ark_ff::fields::Field;
use dcipher_signer::BlsSigner;
use rand::RngCore;

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

fn main() -> anyhow::Result<()> {
    let sk = generate_sk();
    let pk = ark_bls12_381::G2Affine::generator() * sk;

    let chain_id = 1;
    let dst = format!(
        "dcipher-randomness-v01-BLS12_381G1_XMD:KECCAK-256_SVDW_RO_0x{:064x}_",
        chain_id
    )
    .into_bytes();
    let cs = BLS12_381SignatureOnG1Signer::new(sk, dst);

    let msg = "hello";
    let sig = cs.sign(msg)?;
    println!("pk = {}", pk);
    println!("sig = {}", sig);
    println!("msg = {}", msg);
    Ok(())
}
