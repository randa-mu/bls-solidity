use std::env;
use num_bigint::BigUint;
// use num_traits::{Zero, One};
use ark_bn254;
use ark_bls12_381;
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::PrimeField;
use hex::FromHex;
use ark_ff::{BigInt, Zero};

use ark_std::{UniformRand, test_rng};

use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;

use utils::hash_to_curve::CustomPairingHashToCurve;
use utils::serialize::point::{
    PointDeserializeCompressed, PointDeserializeUncompressed, PointSerializeCompressed,
    PointSerializeUncompressed,
};


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

fn hex_format_bytes(bytes: &[u8]) -> String {
    let hex_str = format!("{:x}", BigUint::from_bytes_be(bytes));
    if hex_str.len() % 2 == 1 {
        format!("0{}", hex_str)
    } else {
        hex_str
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: bls_ffi <version> ...");
        eprintln!("Versions:");
        eprintln!("  - BN254 <message_hex> <private key> -> Generate BLS signature using BN254 curve");
        eprintln!("  - BLS12381 <message_hex> <private key> -> Generate BLS signature using BLS12-381 curve");
        eprintln!("  - modexp1 <base_hex> <exponent_hex> -> Compute modular exponentiation (base^exponent mod modulus)");
        eprintln!("  - ModexpInverse <base_hex> -> Compute modular inverse (base^(N-2) mod N)");
        eprintln!("  - ModexpSqrt <base_hex> -> Compute modular square root (base^((N+1)/4) mod N)");
        eprintln!("  - mapToPointBN254 <u_hex> -> Map a field element to a point on BN254 curve");
        std::process::exit(1);
    }
    let version = &args[1]; 

    if version == "BN254" {
        // Usage: bls_ffi BN254 <message_hex> <private key>
        if args.len() != 4 {
            eprintln!("Usage: bls_ffi BN254 <message_hex> <private key>");
            std::process::exit(1);
        }
        let message_hex = &args[2];
        let private_key_hex = &args[3];
        // Decode the message, strip "0x" prefix if present
        let msg_hex = message_hex.strip_prefix("0x").unwrap_or(message_hex);
        let msg_bytes = hex::decode(msg_hex).unwrap();

        // Generate a random private key using the provided private key (string "0x" prefixed hex)
        let private_key_bytes = hex::decode(private_key_hex.strip_prefix("0x").unwrap_or(private_key_hex)).unwrap();
        println!("private_key_bytes: 0x{}", hex::encode(&private_key_bytes));
        let mut private_key_array = [0u8; 64];
        private_key_array.copy_from_slice(&private_key_bytes[..64]);

        let dst = b"BLS_DST";
        let private_key = ark_bn254::Fr::from_le_bytes_mod_order(&private_key_array);

        // Compute the public key (private_key * G2 generator)
        let public_key = (ark_bn254::G2Affine::generator() * private_key).into_affine();

        // Hash the message to a point on G1
        let hashed_message = ark_bn254::Bn254::hash_to_g1_custom::<sha3::Keccak256>(&msg_bytes, dst).into_affine();
        // Compute the signature (private_key * hashed_message)
        let signature = (hashed_message * private_key).into_affine();
        let hex_public_key = hex_ser_uncompressed(&public_key);
        let hex_signature = hex_ser_uncompressed(&signature);
        let hex_hashed_message = hex_ser_uncompressed(&hashed_message);

        // Print the public key, signature, and private key in hex format
        println!("public_key: 0x{}", hex_public_key);
        println!("signature: 0x{}", hex_signature);
        println!("hashed_message: 0x{}", hex_hashed_message);
    } else if version == "BLS12381" {
        // Usage: bls_ffi BLS12381 <message_hex> <private key>
        if args.len() != 4 {
            eprintln!("Usage: bls_ffi BLS12381 <message_hex> <private key>");
            std::process::exit(1);
        }
        let message_hex = &args[2];
        let private_key_hex = &args[3];
        // Decode the message, strip "0x" prefix if present
        let msg_hex = message_hex.strip_prefix("0x").unwrap_or(message_hex);
        let msg_bytes = hex::decode(msg_hex).unwrap();

        // Generate a random private key using the provided private key (string "0x" prefixed hex)
        let private_key_bytes = hex::decode(private_key_hex.strip_prefix("0x").unwrap_or(private_key_hex)).unwrap();
        println!("private_key_bytes: 0x{}", hex::encode(&private_key_bytes));
        let mut private_key_array = [0u8; 64];
        private_key_array.copy_from_slice(&private_key_bytes[..64]);

        let dst = b"BLS_DST";
        let private_key = ark_bls12_381::Fr::from_le_bytes_mod_order(&private_key_array);
        // Compute the public key (private_key * G2 generator)
        let public_key = (ark_bls12_381::G2Affine::generator() * private_key).into_affine();
        // Hash the message to a point on G1
        let hashed_message = ark_bls12_381::Bls12_381::hash_to_g1_custom::<sha2::Sha256>(&msg_bytes, dst).into_affine();
        // Compute the signature (private_key * hashed_message)
        let signature = (hashed_message * private_key).into_affine();
        let hex_public_key = hex_ser_uncompressed(&public_key);
        let hex_signature = hex_ser_uncompressed(&signature);
        let hex_hashed_message = hex_ser_uncompressed(&hashed_message);

        // Print the public key, signature, and private key in hex format
        println!("public_key: 0x{}", hex_public_key);
        println!("signature: 0x{}", hex_signature);
        println!("hashed_message: 0x{}", hex_hashed_message);
    } else if version == "modexp1" {
        // Usage: bls_ffi modexp1 <base_hex> <exponent_hex> <modulus_hex>
        if args.len() != 4 {
            eprintln!("Usage: bls_ffi modexp1 <base_hex> <exponent_hex>");
            std::process::exit(1);
        }
        let base_hex = &args[2];
        let exponent_hex = &args[3];

        let base = BigUint::parse_bytes(base_hex.strip_prefix("0x").unwrap_or(base_hex).as_bytes(), 16).unwrap();
        let exponent = BigUint::parse_bytes(exponent_hex.strip_prefix("0x").unwrap_or(exponent_hex).as_bytes(), 16).unwrap();
        // BN254 field order
        let modulus = BigUint::parse_bytes(b"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16).unwrap();

        let result = base.modpow(&exponent, &modulus);

        println!("modexp_result: 0x{}", hex_format_bytes(&result.to_bytes_be()));
    } else if version == "ModexpInverse" {
        // Usage: bls_ffi ModexpInverse <base_hex>
        // compute $base^(N - 2) mod N$
        if args.len() != 3 {
            eprintln!("Usage: bls_ffi ModexpInverse <base_hex>");
            std::process::exit(1);
        }
        let base_hex = &args[2];

        let base = BigUint::parse_bytes(base_hex.strip_prefix("0x").unwrap_or(base_hex).as_bytes(), 16).unwrap();
        // BN254 field order
        let modulus = BigUint::parse_bytes(b"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16).unwrap();
        let exponent = &modulus - BigUint::from(2u32);
        
        let result = base.modpow(&exponent, &modulus);
        println!("modexp_result: 0x{}", hex_format_bytes(&result.to_bytes_be()));
    } else if version == "ModexpSqrt" {
        // Usage: bls_ffi ModexpSqrt <base_hex>
        // compute $input^{(N + 1) / 4} mod N$
        if args.len() != 3 {
            eprintln!("Usage: bls_ffi ModexpSqrt <base_hex>");
            std::process::exit(1);
        }
        let base_hex = &args[2];

        let base = BigUint::parse_bytes(base_hex.strip_prefix("0x").unwrap_or(base_hex).as_bytes(), 16).unwrap();
        // BN254 field order
        let modulus = BigUint::parse_bytes(b"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16).unwrap();
        let exponent = (&modulus + BigUint::from(1u32)) / BigUint::from(4u32);
        
        let result = base.modpow(&exponent, &modulus);

        println!("modexp_result: 0x{}", hex_format_bytes(&result.to_bytes_be()));
    } else if version == "mapToPointBN254" {
        // Usage: bls_ffi mapToPointBN254 <u_hex>
        if args.len() != 3 {
            eprintln!("Usage: bls_ffi mapToPointBN254 <u_hex>");
            std::process::exit(1);
        }
        let u_hex = &args[2];
        let u = BigUint::parse_bytes(u_hex.strip_prefix("0x").unwrap_or(u_hex).as_bytes(), 16).unwrap();
        // BN254 field order
        let n = BigUint::parse_bytes(b"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16).unwrap();
        // Constants from Solidity
        let c1 = BigUint::from(4u32);
        let c2 = BigUint::parse_bytes(b"183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3", 16).unwrap();
        let c3 = BigUint::parse_bytes(b"16789af3a83522eb353c98fc6b36d713d5d8d1cc5dffffffa", 16).unwrap();
        let c4 = BigUint::parse_bytes(b"10216f7ba065e00de81ac1e7808072c9dd2b2385cd7b438469602eb24829a9bd", 16).unwrap();
        let z = BigUint::from(1u32);
        // Helper functions
        fn modn(x: &BigUint, n: &BigUint) -> BigUint { x % n }
        fn addmod(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint { (a + b) % n }
        fn mulmod(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint { (a * b) % n }
        fn inv0(a: &BigUint, n: &BigUint) -> BigUint {
            if a.is_zero() {
            BigUint::zero()
            } else {
            a.modpow(&(n - BigUint::from(2u32)), n)
            }
        }
        fn sgn0(x: &BigUint) -> u8 { if x.bit(0) { 1 } else { 0 } }
        fn g(x: &BigUint, n: &BigUint) -> BigUint { addmod(&mulmod(&mulmod(x, x, n), x, n), &BigUint::from(3u32), n) }
        fn legendre(u: &BigUint, n: &BigUint) -> i8 {
            let exp = (n.clone() - BigUint::from(1u32)) / BigUint::from(2u32);
            let x = u.modpow(&exp, n);
            if x == n.clone() - BigUint::from(1u32) { -1 }
            else if x == BigUint::zero() { 0 }
            else if x == BigUint::from(1u32) { 1 }
            else { panic!("MapToPointFailed: legendre({})", u) }
        }
        fn sqrt(xx: &BigUint, n: &BigUint) -> Option<BigUint> {
            let exp = (n.clone() + BigUint::from(1u32)) / BigUint::from(4u32);
            let x = xx.modpow(&exp, n);
            if mulmod(&x, &x, n) == *xx { Some(x) } else { None }
        }
        // SvdW mapping
        if u >= n {
            eprintln!("InvalidFieldElement: u >= N");
            std::process::exit(1);
        }
        println!("u = {}", u);
        let tv1 = mulmod(&mulmod(&u, &u, &n), &c1, &n);
        let tv2 = addmod(&BigUint::from(1u32), &tv1, &n);
        let tv1_ = addmod(&BigUint::from(1u32), &(n.clone() - tv1.clone()), &n);
        let tv3 = inv0(&mulmod(&tv1_, &tv2, &n), &n);
        let tv5 = mulmod(&mulmod(&mulmod(&u, &tv1_, &n), &tv3, &n), &c3, &n);
        let x1 = addmod(&c2, &(n.clone() - tv5.clone()), &n);
        let x2 = addmod(&c2, &tv5, &n);
        let tv7 = mulmod(&tv2, &tv2, &n);
        let tv8 = mulmod(&tv7, &tv3, &n);
        let x3 = addmod(&z, &mulmod(&c4, &mulmod(&tv8, &tv8, &n), &n), &n);

        println!("x3 = {}", x3);
        
        let mut px = None;
        let mut py = None;
        let mut gx = None;
        if legendre(&g(&x1, &n), &n) == 1 {
            px = Some(x1.clone());
            gx = Some(g(&x1, &n));
            py = sqrt(&gx.clone().unwrap(), &n);
            if py.is_none() {
                eprintln!("MapToPointFailed: no sqrt for gx");
                std::process::exit(1);
            }
        } else if legendre(&g(&x2, &n), &n) == 1 {
            px = Some(x2.clone());
            gx = Some(g(&x2, &n));
            py = sqrt(&gx.clone().unwrap(), &n);
            if py.is_none() {
                eprintln!("MapToPointFailed: no sqrt for gx");
                std::process::exit(1);
            }
        } else {
            px = Some(x3.clone());
            gx = Some(g(&x3, &n));
            py = sqrt(&gx.clone().unwrap(), &n);
            if py.is_none() {
                eprintln!("MapToPointFailed: no sqrt for gx");
                std::process::exit(1);
            }
        }
        let mut py_val = py.unwrap();
        if sgn0(&u) != sgn0(&py_val) {
            py_val = &n - &py_val;
        }
        
        println!("px = {}", px.clone().unwrap());
        println!("py = {}", py_val);
        println!("mapToPointBN254: x = 0x{}", hex_format_bytes(&px.unwrap().to_bytes_be()));
        println!("mapToPointBN254: y = 0x{}", hex_format_bytes(&py_val.to_bytes_be()));
    } else {
        eprintln!("Unsupported version: {}", version);
        std::process::exit(1);
    }
}

