// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS} from "src/libraries/BLS.sol";

contract EvmnetRegistry {
    mapping(uint64 => bytes32) public roundRandomness;

    string public constant DST = "BLS_SIG_BN254G1_XMD:KECCAK-256_SVDW_RO_NUL_";

    function PUBLIC_KEY() public pure returns (BLS.PointG2 memory) {
        return BLS.PointG2(
            [
                0x557ec32c2ad488e4d4f6008f89a346f18492092ccc0d594610de2732c8b808f,
                0x7e1d1d335df83fa98462005690372c643340060d205306a9aa8106b6bd0b382
            ],
            [
                0x297d3a4f9749b33eb2d904c9d9ebf17224150ddd7abd7567a9bec6c74480ee0b,
                0x95685ae3a85ba243747b1b2f426049010f6b73a0cf1d389351d5aaaa1047f6
            ]
        );
    }

    event RoundProven(uint64 indexed roundNumber, bytes signature);

    function proveRound(bytes memory signature, uint64 roundNumber) external {
        (bool callSuccess, bool pairingSuccess) = BLS.verifySingle(
            BLS.g1Unmarshal(signature),
            PUBLIC_KEY(),
            BLS.hashToPoint(bytes(DST), abi.encodePacked(keccak256(abi.encodePacked(roundNumber))))
        );
        require(callSuccess && pairingSuccess, "Invalid signature");

        roundRandomness[roundNumber] = sha256(signature);

        emit RoundProven(roundNumber, signature);
    }
}
