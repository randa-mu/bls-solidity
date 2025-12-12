// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std-1.10.0/src/Test.sol";
import {ModexpInverse} from "src/libraries/ModExp.sol";
import {ModexpSqrt} from "src/libraries/ModExp.sol";

contract ModExpFuzz is Test {
    // BN254 field order
    uint256 constant N = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    function testFfiModExpInverse(uint256 base) public {
        // Convert base to hex string
        string memory baseHex = vm.toString(abi.encodePacked(base));

        // Call the Rust binary to compute ModexpInverse
        string[] memory cmd = new string[](3);
        cmd[0] = "./target/release/bls_ffi";
        cmd[1] = "ModexpInverse";
        cmd[2] = baseHex;

        bytes memory out = vm.ffi(cmd);
        string memory output = string(out);

        emit log_named_uint("Base", base);
        emit log_named_string("FFI Output", output);
        // Parse the output (modexp_result: 0x...)
        string memory resultHex = _extractValue(output, "modexp_result: ");
        bytes memory resultBytes = vm.parseBytes(resultHex);
        uint256 rustResult = _bytesToUint256(resultBytes);

        // Compute modexp in Solidity
        uint256 solResult = ModexpInverse.run(base);

        assertEq(rustResult, solResult, "Rust ModexpInverse and Solidity ModexpInverse should match");
    }

    function testFfiModExpSqrt(uint256 base) public {
        // Convert base to hex string
        string memory baseHex = vm.toString(abi.encodePacked(base));

        // Call the Rust binary to compute ModexpSqrt
        string[] memory cmd = new string[](3);
        cmd[0] = "./target/release/bls_ffi";
        cmd[1] = "ModexpSqrt";
        cmd[2] = baseHex;

        bytes memory out = vm.ffi(cmd);
        string memory output = string(out);

        emit log_named_uint("Base", base);
        emit log_named_string("FFI Output", output);
        // Parse the output (modexp_result: 0x...)
        string memory resultHex = _extractValue(output, "modexp_result: ");
        bytes memory resultBytes = vm.parseBytes(resultHex);
        uint256 rustResult = _bytesToUint256(resultBytes);

        // Compute modexp in Solidity
        uint256 solResult = ModexpSqrt.run(base);

        assertEq(rustResult, solResult, "Rust ModexpSqrt and Solidity ModexpSqrt should match");
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
