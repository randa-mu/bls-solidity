// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std-1.10.0/src/Test.sol";

import {BLS2} from "src/libraries/BLS2.sol";

contract BLS2TestFuzz is Test {
    function testFfiBlsVerifyGenerated(bytes32[2] memory privateKey, bytes memory message) public {
        // Generate a random message
        string memory messageHex = vm.toString(message);
        bytes memory privateKeyBytes = abi.encodePacked(privateKey[0], privateKey[1]);

        // Call the Rust binary to generate the test case
        string[] memory cmd = new string[](4);
        cmd[0] = "./test/bls_ffi/target/release/bls_ffi";
        cmd[1] = "BLS12381";
        cmd[2] = messageHex;
        cmd[3] = vm.toString(privateKeyBytes);

        bytes memory out = vm.ffi(cmd);
        string memory output = string(out);
        emit log_named_string("vm.ffi output as string", output);

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
        BLS2.PointG1 memory hashedMessage = BLS2.hashToPoint("BLS_DST", message);
        emit log_named_bytes("Hashed Message sol", BLS2.g1Marshal(hashedMessage));

        // Verify the signature using the public key
        (bool pairingSuccess, bool callSuccess) =
            BLS2.verifySingle(BLS2.g1Unmarshal(signatureBytes), BLS2.g2Unmarshal(publicKeyBytes), hashedMessage);

        // Assert that the signature is valid
        assertTrue(pairingSuccess && callSuccess, "BLS2 signature verification failed");
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
}
