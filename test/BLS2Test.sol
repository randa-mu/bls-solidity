pragma solidity ^0.8;

import {Test} from "forge-std-1.10.0/src/Test.sol";

import {BLS2} from "src/libraries/BLS2.sol";

import {Common} from "test/Common.sol";

contract BLS2Test is Test, Common {
    function table_marshal_unmarshal(TestCase memory tc) public pure {
        if (!eq(tc.scheme, "BLS12381")) {
            return; // Skip row but not whole table
        }
        bytes memory g1data = parseHex(tc.sig);
        assertEq(BLS2.g1Marshal(BLS2.g1Unmarshal(g1data)), g1data);

        bytes memory g2data = parseHex(tc.pk);
        assertEq(BLS2.g2Marshal(BLS2.g2Unmarshal(g2data)), g2data);
    }

    function table_verify(TestCase memory tc) public {
        if (!eq(tc.scheme, "BLS12381")) {
            return; // Skip row but not whole table
        }
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

    function table_unmarshal_compressed(TestCase memory tc) public {
        if (!eq(tc.scheme, "BLS12381")) {
            return; // Skip row but not whole table
        }

        BLS2.PointG1 memory expected = BLS2.g1Unmarshal(parseHex(tc.sig));
        BLS2.PointG1 memory actual = BLS2.g1UnmarshalCompressed(parseHex(tc.sig_compressed));

        assert(actual.x_hi == expected.x_hi);
        assert(actual.x_lo == expected.x_lo);
        assert(actual.y_hi == expected.y_hi);
        assert(actual.y_lo == expected.y_lo);
    }
}
