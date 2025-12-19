pragma solidity ^0.8;

import {Test} from "forge-std-1.10.0/src/Test.sol";

import {Common} from "test/Common.sol";

import {EvmnetRegistry} from "src/demos/EvmnetRegistry.sol";

contract EvmnetRegistryTest is Test, Common {
    EvmnetRegistry dut;

    function setUp() public {
        dut = new EvmnetRegistry();
    }

    function fixture_tc() public view returns (TestCase[] memory) {
        return loadBn254TestCases();
    }

    function table_prove_sample(TestCase memory tc) public {
        if (tc.drand_round_number == 0) {
            return; // skip this row but not the whole table
        }
        dut.proveRound(parseHex(tc.sig), tc.drand_round_number);
        assertEq(dut.roundRandomness(tc.drand_round_number), sha256(parseHex(tc.sig)));
    }
}
