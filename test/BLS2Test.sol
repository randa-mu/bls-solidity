pragma solidity ^0.8;

import {Test, console} from "forge-std-1.10.0/src/Test.sol";

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

        BLS2.PointG1 memory m = BLS2.hashToPoint(bytes(tc.dst), parseHex(tc.message));
        assert(m.x_hi == m_expected.x_hi);
        assert(m.x_lo == m_expected.x_lo);
        assert(m.y_hi == m_expected.y_hi);
        assert(m.y_lo == m_expected.y_lo);
        (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(sig, pk, m);
        assert(pairingSuccess);
        assert(callSuccess);
    }

    function test_drand_quicknet_signature() public view {
        TestCase memory tc = readTestCase("test/data/drand_quicknet.json");

        BLS2.PointG2 memory pk = BLS2.g2Unmarshal(parseHex(tc.pk));
        BLS2.PointG1 memory sig = BLS2.g1Unmarshal(parseHex(tc.sig));
        BLS2.PointG1 memory m_expected = BLS2.g1Unmarshal(parseHex(tc.m_expected));

        BLS2.PointG1 memory m = BLS2.hashToPoint(bytes(tc.dst), parseHex(tc.message));
        (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(sig, pk, m);
        assert(pairingSuccess);
        assert(callSuccess);
    }

    function test_drand_quicknet_unmarshal_compressed() public view {
        bytes memory expected_bytes = parseHex(readTestCase("test/data/drand_quicknet.json").sig);
	BLS2.PointG1 memory expected = BLS2.g1Unmarshal(expected_bytes);

	bytes memory input = hex"8d2c8bbc37170dbacc5e280a21d4e195cff5f32a19fd6a58633fa4e4670478b5fb39bc13dd8f8c4372c5a76191198ac5";

        BLS2.PointG1 memory actual = BLS2.g1UnmarshalCompressed(input);

        console.log("m.x_hi", actual.x_hi);
        console.log("m.x_lo", actual.x_lo);
        console.log("m.y_hi", actual.y_hi);
        console.log("m.y_lo", actual.y_lo);
        console.log("m_expected.x_hi", expected.x_hi);
        console.log("m_expected.x_lo", expected.x_lo);
        console.log("m_expected.y_hi", expected.y_hi);
        console.log("m_expected.y_lo", expected.y_lo);
	assert(actual.x_hi == expected.x_hi);
	assert(actual.x_lo == expected.x_lo);
	assert(actual.y_hi == expected.y_hi);
	assert(actual.y_lo == expected.y_lo);
    }
}
