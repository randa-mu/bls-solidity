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

    function test_marshal_unmarshal_with_dcipher_adkg_cli_output() public {
        // Test g2Unmarshal with known values
        bytes memory g2data =
            hex"23cea71feea4dcee7a26226cebce3f5bfa7caf2022a5196e0299481b501169191ce5b8ddbe79ec2d49e2f558a6ca952c2a6e607d6e9a5d2406cb0610dd3bb6cd2638f452d5d029d83e3cd216ffa983b38011646cbf96d2b30956b92ae5836c3913ae657a3c88cbd18ebc7d4b1e577b4faedc71f9ace79db7823b8efa20bbf3f3";
        BLS.PointG2 memory pk = BLS.g2Unmarshal(g2data);

        // Test g2Marshal with known values
        BLS.PointG2 memory testPk = BLS.PointG2([pk.x[0], pk.x[1]], [pk.y[0], pk.y[1]]);

        bytes memory marshaledG2 = BLS.g2Marshal(testPk);
        assert(keccak256(marshaledG2) == keccak256(g2data));

        BLS.PointG2 memory unmarshaledG2 = BLS.g2Unmarshal(marshaledG2);
        assertEq(unmarshaledG2.x[0], testPk.x[0]);
        assertEq(unmarshaledG2.x[1], testPk.x[1]);
        assertEq(unmarshaledG2.y[0], testPk.y[0]);
        assertEq(unmarshaledG2.y[1], testPk.y[1]);
    }
}
