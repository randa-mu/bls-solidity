pragma solidity ^0.8;

import {Test} from "forge-std-1.10.0/src/Test.sol";

import {BLS12381SignatureScheme} from "src/signature-schemes/BLS12381SignatureScheme.sol";

import {Common} from "test/Common.sol";

contract BLS12381SignatureSchemeSchemeTest is Test, Common {
    function fixture_tc() public view returns (TestCase[] memory) {
        return loadBls12TestCases();
    }

    function table_verify(TestCase memory tc) public {
        if (eq(tc.application, "")) {
            return; // Skip row but not whole table
        }
        BLS12381SignatureScheme scheme = new BLS12381SignatureScheme(parseHex(tc.pk), tc.application);
        bytes memory m = scheme.hashToBytes(parseHex(tc.message));
        assert(scheme.verifySignature(m, parseHex(tc.sig)));
    }
}
