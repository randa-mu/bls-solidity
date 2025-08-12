use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use dcipher_signer::{BlsSigner, BlsVerifier};
use std::convert::Infallible;
use std::ops::Neg;

use ark_ec::CurveGroup;

use ark_std::Zero;

use digest::core_api::BlockSizeUser;
use digest::DynDigest;

// use utils::hash_to_curve::bn254_bls12_381::bls12_381::bls12381_hash_to_g1_custom;
fn bls12381_hash_to_g1_custom<H: DynDigest + BlockSizeUser + Default + Clone>(
    message: &[u8],
    dst: &[u8],
) -> ark_bls12_381::G1Projective {
    use ark_bls12_381::{Config, G1Projective};
    use ark_ec::{
        bls12::Bls12Config,
        hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    };
    use ark_ff::field_hashers::DefaultFieldHasher;

    let hasher = MapToCurveBasedHasher::<
        G1Projective,
        DefaultFieldHasher<H, 128>,
        WBMap<<Config as Bls12Config>::G1Config>,
    >::new(dst)
    .unwrap();

    hasher.hash(message).unwrap().into()
}

/// Concrete implementation of a [`BlsSigner`] on the BLS12_381 curve w/ signatures on G1.
#[derive(Clone)]
pub struct BLS12_381SignatureOnG1Signer {
    sk: ark_bls12_381::Fr,
    dst: Vec<u8>,
}

impl BLS12_381SignatureOnG1Signer {
    pub fn new(sk: ark_bls12_381::Fr, dst: Vec<u8>) -> Self {
        Self { sk, dst }
    }
}

impl BlsVerifier for BLS12_381SignatureOnG1Signer {
    type SignatureGroup = ark_bls12_381::G1Affine;
    type PublicKeyGroup = ark_bls12_381::G2Affine;

    fn verify(
        &self,
        m: impl AsRef<[u8]>,
        signature: Self::SignatureGroup,
        public_key: Self::PublicKeyGroup,
    ) -> bool {
        if !signature.is_on_curve()
            || !signature.is_in_correct_subgroup_assuming_on_curve()
            || signature.is_zero()
        {
            return false;
        }

        let m = bls12381_hash_to_g1_custom::<sha3::Keccak256>(m.as_ref(), &self.dst);
        ark_bls12_381::Bls12_381::multi_pairing(
            [m.neg(), signature.into()],
            [public_key, Self::PublicKeyGroup::generator()],
        )
        .is_zero()
    }
}

impl BlsSigner for BLS12_381SignatureOnG1Signer {
    type Error = Infallible;

    fn sign(&self, m: impl AsRef<[u8]>) -> Result<Self::SignatureGroup, Self::Error> {
        let m = bls12381_hash_to_g1_custom::<sha3::Keccak256>(m.as_ref(), &self.dst);
        let sig = m * self.sk;
        Ok(sig.into_affine())
    }
}
