pragma solidity ^0.8;

import {Test, console} from "forge-std-1.10.0/src/Test.sol";

// helpers
import {BLS} from "src/libraries/BLS.sol";
import {BLS2} from "src/libraries/BLS2.sol";

contract BLS2Test is Test {
	function memeq(bytes memory a, bytes memory b) internal pure returns (bool) {
		return keccak256(a) == keccak256(b);
	}

    function test_sample_signature() public view {
        BLS2.PointG2 memory pk;
        BLS2.PointG1 memory sig;
        BLS2.PointG1 memory m_expected;
        string memory message = "hello";
        string memory dst = "BLS12_381G1_XMD:SHA-256_SVDW_RO";

        // pasted
pk = BLS2.PointG2(0x0736e4fdafcb1b37029b49e4fe525c6a, 0x3c982c71be446835ad74b1b86686c5eb130b3df18ca51ad742cae7e21cc552b7, 0x151d28ec5db81b4d27911c358da9f9ef, 0x3dcb2a2ecefbea7f4d9223ee5632c4f093dbdc6905404a9606061a27fcaf023f, 0x103e3d0230bf1b1d7bd8edf575e58dbc, 0xde710b38bb748a1ce6ded4796561793638b23b4d8af4c263405f6137c9ca1f57, 0x19a06c0da612175f5126038cfbc66d40, 0xc07a99aeb7a95c89525ceb7aa8ecd370156f468a15c428f80159b58a98a44f35);
message = "hello";
m_expected = BLS2.g1Unmarshal(hex"0cd00b645f411ec4d3e72182c66788c8b0933c1c020ae997cb5e9aedf08d6fc0b2968ec615c7cd05e366843a6b07b43c0eda73157f463f1a1a5af323b7489fd745b9e8d394db63dfede5af5e09dfb3754132a9977137591f57ca4b1820e5bff5");
sig = BLS2.g1Unmarshal(hex"01c837700bce85224f0eb37aad128820b76e7156e73f3ac8aef53257e7ee0d140edb1a418d6782f19b784df994ecb6c1064f7a358c9db560b5dc6f80fcaac12f1430e74b211a61a8b4c41b0bb843b536cb774b478a296226c97c2fd3fc2390a9");

assert(memeq(BLS2.g1Marshal(sig), hex"01c837700bce85224f0eb37aad128820b76e7156e73f3ac8aef53257e7ee0d140edb1a418d6782f19b784df994ecb6c1064f7a358c9db560b5dc6f80fcaac12f1430e74b211a61a8b4c41b0bb843b536cb774b478a296226c97c2fd3fc2390a9"));

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
        (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(sig, pk, m);
        assert(pairingSuccess);
        assert(callSuccess);
    }
}
