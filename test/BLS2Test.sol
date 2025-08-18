pragma solidity ^0.8;

import {Test, console} from "forge-std-1.10.0/src/Test.sol";
import {Vm} from "forge-std-1.10.0/src/Vm.sol";

import {BLS2} from "src/libraries/BLS2.sol";

Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

struct TestCase {
    // alphabetical order due to vm.parseJson quirks
    string dst;
    string m_expected;
    string message;
    string pk;
    string sig;
    string sig_compressed;
}

function readTestCase(string memory path) view returns (TestCase memory) {
    bytes memory data = vm.parseJson(vm.readFile(path));
    return abi.decode(data, (TestCase));
}

function parseHex(string memory hexString) pure returns (bytes memory) {
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

contract BLS2Test is Test {
    function fixture_tc() public view returns (TestCase[] memory testcases) {
        testcases = new TestCase[](2);
        testcases[0] = readTestCase("test/data/bls2_g1_sha256.json");
        testcases[1] = readTestCase("test/data/drand_quicknet.json");
        // TODO keccak test case
    }

    function table_marshal_unmarshal(TestCase memory tc) public pure {
        bytes memory g1data = parseHex(tc.sig);
        assertEq(BLS2.g1Marshal(BLS2.g1Unmarshal(g1data)), g1data);

        bytes memory g2data = parseHex(tc.pk);
        assertEq(BLS2.g2Marshal(BLS2.g2Unmarshal(g2data)), g2data);
    }

    function table_verify(TestCase memory tc) public {
        BLS2.PointG2 memory pk = BLS2.g2Unmarshal(parseHex(tc.pk));
        BLS2.PointG1 memory sig = BLS2.g1Unmarshal(parseHex(tc.sig));
        BLS2.PointG1 memory m_expected = BLS2.g1Unmarshal(parseHex(tc.m_expected));

        BLS2.PointG1 memory m = BLS2.hashToPoint(bytes(tc.dst), parseHex(tc.message));
        assert(m.x_hi == m_expected.x_hi);
        assert(m.x_lo == m_expected.x_lo);
        assert(m.y_hi == m_expected.y_hi);
        assert(m.y_lo == m_expected.y_lo);
        (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(sig, pk, m);
        vm.snapshotGasLastCall("BLS2.verifySingle");
        assert(pairingSuccess);
        assert(callSuccess);
    }

    function table_unmarshal_compressed(TestCase memory tc) public {
        BLS2.PointG1 memory expected = BLS2.g1Unmarshal(parseHex(tc.sig));
        BLS2.PointG1 memory actual = BLS2.g1UnmarshalCompressed(parseHex(tc.sig_compressed));
        vm.snapshotGasLastCall("BLS2.g1UnmarshalCompressed");

        assert(actual.x_hi == expected.x_hi);
        assert(actual.x_lo == expected.x_lo);
        assert(actual.y_hi == expected.y_hi);
        assert(actual.y_lo == expected.y_lo);
    }
}
