use ark_ec::AffineRepr;
use dcipher_agents::signer::BN254SignatureOnG1Signer;

use ark_ff::fields::Field;
use dcipher_agents::signer::BlsSigner;
use rand::RngCore;

fn generate_sk() -> ark_bn254::Fr {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 32];
    loop {
        rng.fill_bytes(&mut buf);
        if let Some(sk) = ark_bn254::Fr::from_random_bytes(&buf) {
            break sk;
        }
    }
}

fn main() -> anyhow::Result<()> {
    let sk = generate_sk();
    let pk = ark_bn254::G2Affine::generator() * sk;

    let chain_id = 1;
    let dst = format!(
        "dcipher-randomness-v01-BN254G1_XMD:KECCAK-256_SVDW_RO_0x{:064x}_",
        chain_id
    )
    .into_bytes();
    let cs = BN254SignatureOnG1Signer::new(sk, dst);

    let msg = "hello";
    let sig = cs.sign(msg)?;
    println!("pk = {}", pk);
    println!("sig = {}", sig);
    println!("msg = {}", msg);
    Ok(())
}
