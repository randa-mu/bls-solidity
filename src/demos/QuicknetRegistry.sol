// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS2} from "../libraries/BLS2.sol";

contract QuicknetRegistry {
    mapping(uint64 => bytes32) public roundRandomness;

    string public constant DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    function PUBLIC_KEY() public pure returns (BLS2.PointG2 memory) {
        return BLS2.PointG2(
            0x03cf0f2896adee7eb8b5f01fcad39122,
            0x12c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d106451,
            0x0d1fec758c921cc22b0e17e63aaf4bcb,
            0x5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a,
            0x01a714f2edb74119a2f2b0d5a7c75ba9,
            0x02d163700a61bc224ededd8e63aef7be1aaf8e93d7a9718b047ccddb3eb5d68b,
            0x0e5db2b6bfbb01c867749cadffca88b3,
            0x6c24f3012ba09fc4d3022c5c37dce0f977d3adb5d183c7477c442b1f04515273
        );
    }

    event RoundProven(uint64 indexed roundNumber, bytes signature);

    function proveRound(bytes memory signature, uint64 roundNumber) external {
        (bool callSuccess, bool pairingSuccess) = BLS2.verifySingle(
            BLS2.g1UnmarshalCompressed(signature),
            PUBLIC_KEY(),
            BLS2.hashToPoint(bytes(DST), abi.encodePacked(sha256(abi.encodePacked(roundNumber))))
        );
        require(callSuccess && pairingSuccess, "Invalid signature");

        roundRandomness[roundNumber] = sha256(signature);

        emit RoundProven(roundNumber, signature);
    }
}
