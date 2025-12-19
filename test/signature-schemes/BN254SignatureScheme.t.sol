pragma solidity ^0.8;

import {Test} from "forge-std-1.10.0/src/Test.sol";

import {BN254SignatureScheme} from "src/signature-schemes/BN254SignatureScheme.sol";

import {Common} from "test/Common.sol";

contract BN254SignatureSchemeTest is Test, Common {
    function fixture_tc() public view returns (TestCase[] memory) {
        return loadBn254TestCases();
    }

    function table_verify(TestCase memory tc) public {
        if (eq(tc.application, "")) {
            return; // Skip row but not whole table
        }
        BN254SignatureScheme scheme = new BN254SignatureScheme(parseHex(tc.pk), tc.application);
        bytes memory m = scheme.hashToBytes(parseHex(tc.message));
        assert(scheme.verifySignature(m, parseHex(tc.sig)));
    }
}
