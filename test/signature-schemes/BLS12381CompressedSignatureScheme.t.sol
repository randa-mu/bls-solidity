pragma solidity ^0.8;

import {Test} from "forge-std-1.10.0/src/Test.sol";

import {BLS12381CompressedSignatureScheme} from "src/signature-schemes/BLS12381CompressedSignatureScheme.sol";

import {Common} from "test/Common.sol";

contract BLS12381CompressedSignatureSchemeTest is Test, Common {
    function table_verify(TestCase memory tc) public {
        if (!eq(tc.scheme, "BLS12381") || eq(tc.application, "")) {
            return; // Skip row but not whole table
        }
        BLS12381CompressedSignatureScheme scheme =
            new BLS12381CompressedSignatureScheme(parseHex(tc.pk), tc.application);
        bytes memory m = scheme.hashToBytes(parseHex(tc.message));
        assert(scheme.verifySignature(m, parseHex(tc.sig_compressed)));
    }
}
