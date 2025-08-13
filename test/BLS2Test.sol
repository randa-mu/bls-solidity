pragma solidity ^0.8;

import {Test, console} from "forge-std-1.10.0/src/Test.sol";

// helpers
import {BLS} from "src/libraries/BLS.sol";
import {BLS2} from "src/libraries/BLS2.sol";

contract BLSTest is Test {
    function test_sample_signature() public view {
        BLS2.PointG2 memory pk;
        BLS2.PointG1 memory sig;
        BLS2.PointG1 memory m_expected;
        string memory message = "hello";
        string memory dst = "BLS12_381G1_XMD:KECCAK-256_SVDW_RO";

        // pasted
        // pk = BLS2.PointG2(0x0736e4fdafcb1b37029b49e4fe525c6a, 0x3c982c71be446835ad74b1b86686c5eb130b3df18ca51ad742cae7e21cc552b7, 0x151d28ec5db81b4d27911c358da9f9ef, 0x3dcb2a2ecefbea7f4d9223ee5632c4f093dbdc6905404a9606061a27fcaf023f, 0x103e3d0230bf1b1d7bd8edf575e58dbc, 0xde710b38bb748a1ce6ded4796561793638b23b4d8af4c263405f6137c9ca1f57, 0x19a06c0da612175f5126038cfbc66d40, 0xc07a99aeb7a95c89525ceb7aa8ecd370156f468a15c428f80159b58a98a44f35);
        message = "hello";
        m_expected = BLS2.PointG1(
            0x0cb2f2bb960dd951ed7582d68ff0ff1d,
            0x2c7b68a701167b8970347c4e005c89f33a585bd57b9f5d364b08cf725e7ee928,
            0x0bbc5425b8533f92d8e58cb356c0ba05,
            0x296640f07bbca079ea22549603a1d0d5256ae674ec596ef14abadb20235fe23a
        );
        sig = BLS2.PointG1(
            0x181223d268e322a7def6648be0edc580,
            0x8c5c8f90892c450997d0355330a436b721b766d3a08f2603c8fd585d97f5c73b,
            0x0cb50a82c6fd69958223491c767024a6,
            0x798268c84c7e39eddf77fda25e5d054f1245bc2b2716bd0ff494bec4c9104d8e
        );

        BLS2.PointG1 memory m = BLS2.hashToPoint(bytes(dst), bytes(message));
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
        // BLS2.verifySingle(sig, pk, m);
    }
}
