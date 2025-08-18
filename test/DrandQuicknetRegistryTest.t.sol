pragma solidity ^0.8;

import {Test, console} from "forge-std-1.10.0/src/Test.sol";

import {TestCase, parseHex, readTestCase} from "test/BLS2Test.sol";

import {DrandQuicknetRegistry} from "src/demos/DrandQuicknetRegistry.sol";

contract DrandQuicknetRegistryTest is Test {
    function test_prove_sample() public {
        DrandQuicknetRegistry registry = new DrandQuicknetRegistry{salt: hex"deadbeef"}();
        TestCase memory tc = readTestCase("test/data/drand_quicknet.json");
        registry.proveRound(parseHex(tc.sig_compressed), 20905307);
        assertEq(registry.roundRandomness(20905307), sha256(parseHex(tc.sig_compressed)));
    }
}
