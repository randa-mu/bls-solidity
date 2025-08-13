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
        bytes[96] x;
        bytes[96] y;
    }

    // GfP2 implements a field of size p² as a quadratic extension of the base field.
    struct GfP2 {
        uint256 x;
        uint256 y;
    }

    // Field order
    uint128 private constant p_hi = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 private constant p_lo = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    // Generator of G1
    // per EIP-2537
    function H1() external pure returns (PointG1 memory r) {
        r.x_hi = 0x17f1d3a73197d7942695638c4fa9ac0f;
        r.x_lo = 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
        r.y_hi = 0x08b3f481e3aaa0f1a09e30ed741d8ae4;
        r.y_lo = 0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1;
    }

    error BlsAddFailed(bytes[48][4] input);
    error InvalidFieldElement(bytes[48] x);
    error MapToPointFailed(uint256 noSqrt);
    error InvalidDSTLength(bytes dst);
    error ModExpFailed(uint256 base, uint256 exponent, uint256 modulus);

    // follows RFC9380 §5
    function hashToPoint(bytes memory dst, bytes memory message) internal view returns (PointG1 memory) {
        bytes memory uniform_bytes = expandMsg(dst, message, 128);
        console.logBytes(uniform_bytes);
        bytes memory buf = new bytes(1024);
        bytes memory buf2 = new bytes(256);
        bool ok;
        uint256 p;
        uint256 q;
        for (uint256 i = 0; i < 2; i++) {
            // inplace mod in uniform_bytes[64*i]
            assembly {
                p := add(32, uniform_bytes)
                p := add(p, mul(64, i))
                q := add(32, buf)
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
                q := add(32, buf)
                ok := staticcall(gas(), 5, q, 225, p, 64)
            }
            require(ok, "expmod failed");
            // EIP-2537 map_fp_to_g1
            assembly {
                let r := add(32, buf2)
                r := add(r, mul(128, i))
                ok := staticcall(gas(), 16, p, 64, r, 128)
            }
            require(ok, "map_fp_to_g1 failed");
        }
        bytes memory buf3 = new bytes(128);
        (ok, buf3) = address(0x0b).staticcall(buf2);
        require(ok, "g1add failed");
        return abi.decode(buf3, (PointG1));
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
}
