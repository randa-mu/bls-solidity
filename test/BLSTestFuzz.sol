// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std-1.10.0/src/Test.sol";

import {BLS} from "src/libraries/BLS.sol";

contract BLSTestFuzz is Test {
    function testFfiBlsVerifyGenerated(bytes32[2] memory privateKey, bytes memory message) public {
        // Generate a random message
        string memory messageHex = vm.toString(message);
        bytes memory privateKeyBytes = abi.encodePacked(privateKey[0], privateKey[1]);

        // Call the Rust binary to generate the test case
        string[] memory cmd = new string[](4);
        cmd[0] = "./target/release/bls_ffi";
        cmd[1] = "BN254";
        cmd[2] = messageHex;
        cmd[3] = vm.toString(privateKeyBytes);

        bytes memory out = vm.ffi(cmd);
        string memory output = string(out);

        // Parse the output (public key, signature)
        string memory publicKeyHex = _extractValue(output, "public_key: ");
        string memory signatureHex = _extractValue(output, "signature: ");

        emit log_named_string("Message", messageHex);
        emit log_named_string("Public Key", publicKeyHex);
        emit log_named_string("Signature", signatureHex);

        // Convert public key and signature from hex to bytes
        bytes memory publicKeyBytes = vm.parseBytes(publicKeyHex);
        bytes memory signatureBytes = vm.parseBytes(signatureHex);

        // Hash the message to a point on G1
        BLS.PointG1 memory hashedMessage = BLS.hashToPoint("BLS_DST", message);
        emit log_named_bytes("Hashed Message sol", BLS.g1Marshal(hashedMessage));

        // Verify the signature using the public key
        (bool pairingSuccess, bool callSuccess) =
            BLS.verifySingle(BLS.g1Unmarshal(signatureBytes), BLS.g2Unmarshal(publicKeyBytes), hashedMessage);

        // Assert that the signature is valid
        assertTrue(pairingSuccess && callSuccess, "BLS signature verification failed");
    }

    function testFfiMapToPointBN254(uint256 u) public {
        // Restrict u to valid field element
        if (u >= 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47) {
            return;
        }

        // Call Rust FFI for mapToPointBN254
        string[] memory cmd = new string[](3);
        cmd[0] = "./target/release/bls_ffi";
        cmd[1] = "mapToPointBN254";
        cmd[2] = vm.toString(abi.encodePacked(u));
        bytes memory out = vm.ffi(cmd);
        string memory output = string(out);

        emit log_named_uint("Input u", u);
        emit log_named_string("vm.ffi output as string", output);
        // Call Solidity's mapToPoint
        uint256[2] memory solPoint = BLS.mapToPoint(u);
        emit log_named_uint("Solidity mapToPoint x", solPoint[0]);
        emit log_named_uint("Solidity mapToPoint y", solPoint[1]);

        // Parse Rust output
        string memory xHex = _extractValue(output, "mapToPointBN254: x = ");
        string memory yHex = _extractValue(output, "mapToPointBN254: y = ");
        uint256 xRust = _bytesToUint256(vm.parseBytes(xHex));
        uint256 yRust = _bytesToUint256(vm.parseBytes(yHex));
        emit log_named_uint("Rust mapToPoint x", xRust);
        emit log_named_uint("Rust mapToPoint y", yRust);

        // Compare results
        assertEq(solPoint[0], xRust, "mapToPoint x mismatch");
        assertEq(solPoint[1], yRust, "mapToPoint y mismatch");
    }

    function _extractValue(string memory output, string memory key) internal pure returns (string memory) {
        // Extract the value corresponding to the key from the output
        bytes memory outputBytes = bytes(output);
        bytes memory keyBytes = bytes(key);
        uint256 start = _indexOf(outputBytes, keyBytes) + keyBytes.length;
        uint256 end = start;

        // Find the end of the value (newline character)
        while (end < outputBytes.length && outputBytes[end] != 0x0a) {
            end++;
        }

        // Copy the range [start:end] into a new bytes array
        bytes memory value = new bytes(end - start);
        for (uint256 i = start; i < end; i++) {
            value[i - start] = outputBytes[i];
        }

        return string(value);
    }

    function _indexOf(bytes memory haystack, bytes memory needle) internal pure returns (uint256) {
        for (uint256 i = 0; i <= haystack.length - needle.length; i++) {
            bool isMatch = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    isMatch = false;
                    break;
                }
            }
            if (isMatch) {
                return i;
            }
        }
        revert("Key not found");
    }

    function _bytesToUint256(bytes memory b) internal pure returns (uint256 number) {
        for (uint256 i = 0; i < b.length; i++) {
            number = number << 8;
            number = number | uint8(b[i]);
        }
    }
}
