// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {Test, console} from "forge-std-1.10.0/src/Test.sol";
import {ModexpInverse, ModexpSqrt, ModUtils} from "./ModExp.sol";

/// @title  Boneh–Lynn–Shacham (BLS) signature scheme on Barreto-Lynn-Scott 381-bit curve (BLS12-381) used to verify BLS signatures
/// @notice We use BLS signature aggregation to reduce the size of signature data to store on chain.
/// @dev We use G1 points for signatures and messages, and G2 points for public keys or vice versa
/// @dev base field elements are 48-bytes, and are represented as an uint128 followed by and uint256.
/// @dev G1 is 96 bytes and G2 is 192 bytes. Compression is not currently available.
library BLS2 {
    struct PointG1 {
        uint128 x_hi;
        uint256 x_lo;
        uint128 y_hi;
        uint256 y_lo;
    }

    struct PointG2 {
        uint128 x0_hi;
        uint256 x0_lo;
        uint128 x1_hi;
        uint256 x1_lo;
        uint128 y0_hi;
        uint256 y0_lo;
        uint128 y1_hi;
        uint256 y1_lo;
    }

    // GfP2 implements a field of size p² as a quadratic extension of the base field.
    struct GfP2 {
        uint256 x;
        uint256 y;
    }

    uint128 private constant N_G2_X0_HI = 0x024aa2b2f08f0a91260805272dc51051;
    uint256 private constant N_G2_X0_LO = 0xc6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8;
    uint128 private constant N_G2_X1_HI = 0x13e02b6052719f607dacd3a088274f65;
    uint256 private constant N_G2_X1_LO = 0x596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e;
    uint128 private constant N_G2_Y0_HI = 0x0d1b3cc2c7027888be51d9ef691d77bc;
    uint256 private constant N_G2_Y0_LO = 0xb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa;
    uint128 private constant N_G2_Y1_HI = 0x13fa4d4a0ad8b1ce186ed5061789213d;
    uint256 private constant N_G2_Y1_LO = 0x993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed;

    // Field order
    uint128 private constant p_hi = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 private constant p_lo = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    error InvalidDSTLength(bytes dst);

    // follows RFC9380 §5
    function hashToPoint(bytes memory dst, bytes memory message) internal view returns (PointG1 memory out) {
        bytes memory uniform_bytes = expandMsg(dst, message, 128);
        bytes memory buf = new bytes(225);
        bytes memory buf2 = new bytes(256);
        bool ok;
        for (uint256 i = 0; i < 2; i++) {
            assembly {
                // inplace mod in uniform_bytes[64*i]
                let p := add(32, uniform_bytes)
                let q := add(32, buf)

                p := add(p, mul(64, i))
                mstore(q, 64) // length of base
                q := add(q, 32)
                mstore(q, 1) // length of exponent 1
                q := add(q, 32)
                mstore(q, 64) // length of modulus
                q := add(q, 32)
                mcopy(q, p, 64) // copy base
                q := add(q, 64)
                mstore8(q, 1) // exponent
                q := add(q, 1)
                mstore(q, p_hi)
                q := add(q, 32)
                mstore(q, p_lo)
                ok := staticcall(gas(), 5, add(32, buf), 225, p, 64)

                // EIP-2537 map_fp_to_g1
                let r := add(32, buf2)
                r := add(r, mul(128, i))
                ok := and(ok, staticcall(gas(), 16, p, 64, r, 128))
            }
            require(ok);
        }
        assembly {
            ok := staticcall(gas(), 0x0b, add(buf2, 32), 256, out, 128)
        }
        require(ok, "g1add failed");
    }

    // FIXME copypaste from BLS.sol
    function expandMsg(bytes memory DST, bytes memory message, uint8 n_bytes) internal pure returns (bytes memory) {
        uint256 domainLen = DST.length;
        if (domainLen > 255) {
            revert InvalidDSTLength(DST);
        }
        bytes memory zpad = new bytes(136);
        bytes memory b_0 = abi.encodePacked(zpad, message, uint8(0), n_bytes, uint8(0), DST, uint8(domainLen));
        bytes32 b0 = keccak256(b_0);

        bytes memory b_i = abi.encodePacked(b0, uint8(1), DST, uint8(domainLen));
        bytes32 bi = keccak256(b_i);
        bytes memory out = new bytes(n_bytes);
        uint256 ell = (n_bytes + uint256(31)) >> 5;
        for (uint256 i = 1; i < ell; i++) {
            b_i = abi.encodePacked(b0 ^ bi, uint8(1 + i), DST, uint8(domainLen));
            assembly {
                let p := add(32, out)
                p := add(p, mul(32, sub(i, 1)))
                mstore(p, bi)
            }
            bi = keccak256(b_i);
        }
        assembly {
            let p := add(32, out)
            p := add(p, mul(32, sub(ell, 1)))
            mstore(p, bi)
        }
        return out;
    }

    /// @notice Verify signed message on g1 against signature on g1 and public key on g2
    /// @param signature Signature to check
    /// @param pubkey Public key of signer
    /// @param message Message to check
    /// @return pairingSuccess bool indicating if the pairing check was successful
    /// @return callSuccess bool indicating if the static call to the evm precompile was successful
    function verifySingle(PointG1 memory signature, PointG2 memory pubkey, PointG1 memory message)
        internal
        view
        returns (bool pairingSuccess, bool callSuccess)
    {
        uint256[24] memory input = [
            signature.x_hi,
            signature.x_lo,
            signature.y_hi,
            signature.y_lo,
            N_G2_X0_HI,
            N_G2_X0_LO,
            N_G2_X1_HI,
            N_G2_X1_LO,
            N_G2_Y0_HI,
            N_G2_Y0_LO,
            N_G2_Y1_HI,
            N_G2_Y1_LO,
            message.x_hi,
            message.x_lo,
            message.y_hi,
            message.y_lo,
            pubkey.x0_hi,
            pubkey.x0_lo,
            pubkey.x1_hi,
            pubkey.x1_lo,
            pubkey.y0_hi,
            pubkey.y0_lo,
            pubkey.y1_hi,
            pubkey.y1_lo
        ];
        uint256[1] memory out;
        assembly {
            callSuccess := staticcall(sub(gas(), 2000), 0xf, input, 768, out, 0x20)
        }
        return (out[0] != 0, callSuccess);
    }
}
