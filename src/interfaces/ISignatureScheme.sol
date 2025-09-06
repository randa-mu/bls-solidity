// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

/// @title ISignatureScheme interface
/// @author Randamu
/// @notice Interface for signature schemes, e.g., BN254, BLS, etc.
interface ISignatureScheme {
    /// @notice Returns the scheme identifier as a string, e.g., "Barreto-Naehrig Curve" or "BN254"
    /// BN254 is an elliptic curve that belongs to the pairing-friendly curves family,
    /// designed for efficient computation of pairing-based cryptographic
    /// protocols (such as zk-SNARKs, zero-knowledge proofs, and other cryptographic constructions)
    function SCHEME_ID() external view returns (string memory);

    /// @notice returns the DST used in message hashing to BLS point
    function DST() external view returns (bytes memory);

    /// @notice Verifies a signature using the given signature scheme.
    /// @param message The message that was signed. Message is a G1 point represented as bytes.
    /// @param signature The signature to verify. Signature is a G1 point represented as bytes.
    /// @return isValid boolean which evaluates to true if the signature is valid, false otherwise.
    function verifySignature(bytes calldata message, bytes calldata signature) external view returns (bool isValid);

    /// @notice Hashes a message to a G1 point on the elliptic curve.
    /// @param message The message to be hashed.
    /// @return bytes A point on the elliptic curve in G1, represented as bytes.
    function hashToBytes(bytes calldata message) external view returns (bytes memory);

    /// @notice Retrieves the public key associated with the decryption process.
    /// @dev Returns the public key as bytes.
    /// @return Bytes string representing the public key points on the elliptic curve.
    function getPublicKeyBytes() external view returns (bytes memory);
}
