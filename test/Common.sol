pragma solidity ^0.8;

import {TestBase} from "forge-std-1.10.0/src/Base.sol";

abstract contract Common is TestBase {
    // This is a common base contract for BLS2 tests and QuicknetRegistry tests.
    // It provides utility functions to read test cases and parse hex strings.
    struct TestCase {
        // alphabetical order due to vm.parseJson quirks
        uint64 drand_round_number; // Optional: 0 if n/a
        string dst;
        string m_expected;
        string message;
        string pk;
        string scheme; // either "BN254" or "BLS12381"
        string sig;
        string sig_compressed;
    }

    function eq(string memory a, string memory b) public pure returns (bool) {
        return keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }

    function parseHex(string memory hexString) public pure returns (bytes memory) {
        bytes memory buf = bytes(hexString);
        bytes memory result = new bytes(buf.length / 2);
        string memory alphabet = "0123456789abcdef";
        for (uint256 i = 0; i < buf.length; i += 2) {
            result[i / 2] = bytes1(
                uint8(
                    vm.indexOf(alphabet, string(abi.encodePacked(buf[i]))) * 16
                        + vm.indexOf(alphabet, string(abi.encodePacked(buf[i + 1])))
                )
            );
        }
        return result;
    }

    function fixture_tc() public view returns (TestCase[] memory testcases) {
        bytes memory data = vm.parseJson(vm.readFile("test/data/testcases.json"));
        return abi.decode(data, (TestCase[]));
    }
}
