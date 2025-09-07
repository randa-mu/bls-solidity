// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

/// @title BytesLib
/// @author Randamu
/// @notice Utility library for bytes-related operations
library BytesLib {
    /// @dev Checks if a bytes array is empty.
    /// @param data The bytes array to check.
    /// @return bool Returns true if the bytes array is empty, false otherwise.
    function isEmpty(bytes memory data) internal pure returns (bool) {
        return data.length == 0;
    }

    /// @dev Checks if all bytes in a bytes array are zero.
    /// @param data The bytes array to check.
    /// @return bool Returns true if all bytes are zero, false if at least one byte is non-zero.
    function isAllZero(bytes memory data) internal pure returns (bool) {
        for (uint256 i = 0; i < data.length; i++) {
            if (data[i] != 0x00) {
                return false; // Found a non-zero byte
            }
        }
        return true; // All bytes are zero
    }

    /// @dev Checks if the length of a bytes array is within the given bounds.
    /// @param data The bytes array to check.
    /// @param minLength The minimum length that the bytes array must be.
    /// @param maxLength The maximum length that the bytes array must be.
    /// @return bool Returns true if the length of the bytes array is within [minLength, maxLength], false otherwise.
    /// @notice Reverts if minLength is greater than maxLength.
    function isLengthWithinBounds(bytes memory data, uint256 minLength, uint256 maxLength)
        internal
        pure
        returns (bool)
    {
        require(minLength <= maxLength, "Invalid bounds: minLength cannot be greater than maxLength");
        uint256 dataLength = data.length;
        return dataLength >= minLength && dataLength <= maxLength;
    }

    /// @dev Decodes a bytes array back to a uint256.
    /// @param data The bytes array to decode.
    /// @return uint256 The decoded uint256 value.
    /// @notice Reverts if the length of the bytes array is less than 32 bytes.
    function decodeBytesToUint(bytes memory data) public pure returns (uint256) {
        require(data.length >= 32, "Data must be at least 32 bytes long");
        return abi.decode(data, (uint256)); // Decode bytes back to uint
    }

    /// @dev Converts bytes32 to 0x-prefixed hex string.
    /// @param data The bytes32 data to convert.
    function toHexString(bytes32 data) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory str = new bytes(2 + 64); // "0x" + 64 hex chars
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < 32; i++) {
            str[2 + i * 2] = hexChars[uint8(data[i] >> 4)];
            str[2 + i * 2 + 1] = hexChars[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }
}
