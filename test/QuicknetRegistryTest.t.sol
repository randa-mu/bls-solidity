pragma solidity ^0.8;

import {Test} from "forge-std-1.10.0/src/Test.sol";

import {Common} from "test/Common.sol";

import {QuicknetRegistry} from "src/demos/QuicknetRegistry.sol";

contract QuicknetRegistryTest is Test, Common {
    QuicknetRegistry dut;

    function setUp() public {
        dut = new QuicknetRegistry();
    }

    function table_prove_sample(TestCase memory tc) public {
        if (!eq(tc.scheme, "BLS12381") || tc.drand_round_number == 0) {
            return; // skip this row but not the whole table
        }
        dut.proveRound(parseHex(tc.sig_compressed), tc.drand_round_number);
        assertEq(dut.roundRandomness(tc.drand_round_number), sha256(parseHex(tc.sig_compressed)));
    }
}
