pragma solidity ^0.8;

import {Test, console} from "forge-std-1.10.0/src/Test.sol";

// helpers
import {BLS} from "src/libraries/BLS.sol";
import {BLS2} from "src/libraries/BLS2.sol";

struct TestCase {
    // alphabetical order due to vm.parseJson quirks
    string dst;
    string m_expected;
    string message;
    string pk;
    string sig;
}

contract BLS2Test is Test {
    function parseHex(string memory hexString) internal pure returns (bytes memory) {
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

    function eqBytes(bytes memory a, bytes memory b) internal pure returns (bool) {
        return keccak256(a) == keccak256(b);
    }

    function readTestCase(string memory path) internal view returns (TestCase memory) {
        bytes memory data = vm.parseJson(vm.readFile(path));
        return abi.decode(data, (TestCase));
    }

    function test_marshal_unmarshal() public {
        TestCase memory tc = readTestCase("test/data/bls2_g1_sha256.json");

        bytes memory g1data = parseHex(tc.sig);
        assert(eqBytes(BLS2.g1Marshal(BLS2.g1Unmarshal(g1data)), g1data));

        bytes memory g2data = parseHex(tc.pk);
        assert(eqBytes(BLS2.g2Marshal(BLS2.g2Unmarshal(g2data)), g2data));
    }

    // TODO keccak support + test case

    function test_sample_signature() public view {
        TestCase memory tc = readTestCase("test/data/bls2_g1_sha256.json");

        BLS2.PointG2 memory pk = BLS2.g2Unmarshal(parseHex(tc.pk));
        BLS2.PointG1 memory sig = BLS2.g1Unmarshal(parseHex(tc.sig));
        BLS2.PointG1 memory m_expected = BLS2.g1Unmarshal(parseHex(tc.m_expected));

        BLS2.PointG1 memory m = BLS2.hashToPoint(bytes(tc.dst), bytes(tc.message));
        console.log("m.x_hi", m.x_hi);
        console.log("m.x_lo", m.x_lo);
        console.log("m.y_hi", m.y_hi);
        console.log("m.y_lo", m.y_lo);
        console.log("m_expected.x_hi", m_expected.x_hi);
        console.log("m_expected.x_lo", m_expected.x_lo);
        console.log("m_expected.y_hi", m_expected.y_hi);
        console.log("m_expected.y_lo", m_expected.y_lo);
        assert(m.x_hi == m_expected.x_hi);
        assert(m.x_lo == m_expected.x_lo);
        assert(m.y_hi == m_expected.y_hi);
        assert(m.y_lo == m_expected.y_lo);
        (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(sig, pk, m);
        assert(pairingSuccess);
        assert(callSuccess);
    }
}
