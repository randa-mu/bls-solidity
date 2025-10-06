pragma solidity ^0.8;

import {Test, console} from "forge-std-1.10.0/src/Test.sol";

import {BLS} from "src/libraries/BLS.sol";

import {Common} from "test/Common.sol";

contract BLSTest is Test, Common {
    function test_sample_signature() public {
        BLS.PointG2 memory pk = BLS.PointG2(
            [
                5838992826193349966357268616665404381433472226083567344457223955089099207810,
                7443551230336632695654952939029281494467559716523100842530624021561054602204
            ],
            [
                8587802453880553245650725475740899117965522901638095133768179426207296887795,
                21457554579773484299265442011477624571798879699696467812994904700443263942520
            ]
        );
        BLS.PointG1 memory sig = BLS.PointG1(
            7901903815049524482096231647574410489430116000772174647307272692982723667747,
            9602902115719281793852526489338977181632383432254830939648007541154086057984
        );
        string memory message = "hello";
        string memory dst =
            "dcipher-randomness-v01-BN254G1_XMD:KECCAK-256_SVDW_RO_0x0000000000000000000000000000000000000000000000000000000000000001";
        BLS.PointG1 memory messageP = BLS.hashToPoint(bytes(dst), bytes(message));
        BLS.verifySingle(sig, pk, messageP);
    }

    function table_marshal_unmarshal(TestCase memory tc) public pure {
        if (!eq(tc.scheme, "BN254")) {
            return; // Skip row but not whole table
        }
        bytes memory g1data = parseHex(tc.sig);
        assertEq(BLS.g1Marshal(BLS.g1Unmarshal(g1data)), g1data);

        bytes memory g2data = parseHex(tc.pk);
        assertEq(BLS.g2Marshal(BLS.g2Unmarshal(g2data)), g2data);
    }

    function table_verify(TestCase memory tc) public {
        if (!eq(tc.scheme, "BN254")) {
            return; // Skip row but not whole table
        }
        BLS.PointG2 memory pk = BLS.g2Unmarshal(parseHex(tc.pk));
        BLS.PointG1 memory sig = BLS.g1Unmarshal(parseHex(tc.sig));
        BLS.PointG1 memory m_expected = BLS.g1Unmarshal(parseHex(tc.m_expected));

        BLS.PointG1 memory m = BLS.hashToPoint(bytes(tc.dst), parseHex(tc.message));
        assert(m.x == m_expected.x);
        assert(m.y == m_expected.y);

        (bool pairingSuccess, bool callSuccess) = BLS.verifySingle(sig, pk, m);
        assert(pairingSuccess);
        assert(callSuccess);
    }

    function test_snapshot_verify_uncompressed() public {
        // snapshots do not work well in table tests as of Foundry 1.3.1, workaround here.
        TestCase memory tc = fixture_tc()[4];
        BLS.PointG2 memory pk = BLS.g2Unmarshal(parseHex(tc.pk));
        bytes memory sigBytes = parseHex(tc.sig);
        bytes memory msg = parseHex(tc.message);

        vm.startSnapshotGas("BLS", "verify_uncompressed");
        BLS.PointG1 memory sig = BLS.g1Unmarshal(sigBytes);
        BLS.PointG1 memory m = BLS.hashToPoint(bytes(tc.dst), msg);
        (bool pairingSuccess, bool callSuccess) = BLS.verifySingle(sig, pk, m);
        vm.stopSnapshotGas();
        assert(pairingSuccess && callSuccess);
    }
}
