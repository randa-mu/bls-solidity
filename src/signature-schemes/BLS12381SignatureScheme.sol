// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS2} from "../libraries/BLS2.sol";
import {BytesLib} from "../libraries/BytesLib.sol";

import {ISignatureScheme} from "../interfaces/ISignatureScheme.sol";

/// @title BLS12381SignatureScheme contract
/// @author Randamu
/// @notice A contract that implements a BLS12381 signature scheme
contract BLS12381SignatureScheme is ISignatureScheme {
    using BytesLib for bytes32;

    /// @notice Identifier for the BLS12381 signature scheme
    string public constant SCHEME_ID = "BLS12381";

    /// @notice Domain separation tag for the BLS signature scheme
    bytes public DST;

    /// @notice Links public keys of threshold network statically to signature scheme contracts and remove from constructor of sender contracts. Admin cannot update, simply use new scheme id.
    BLS2.PointG2 private publicKey;

    /// @notice Sets the DST with the current chain ID as a hex string (converted to bytes)
    constructor(bytes memory publicKeyBytes, string memory application) {
        DST =
            abi.encodePacked(application, "-BLS12381G1_XMD:SHA-256_SSWU_RO_", bytes32(block.chainid).toHexString(), "_");
        publicKey = BLS2.g2Unmarshal(publicKeyBytes);
    }

    /// @notice Retrieves the public key associated with the decryption process.
    /// @dev Returns the public key as bytes.
    /// @return Bytes string representing the public key points on the elliptic curve.
    function getPublicKeyBytes() public view returns (bytes memory) {
        return BLS2.g2Marshal(publicKey);
    }

    /// @notice Verifies a signature using the given signature scheme.
    /// @param message The message that was signed. Message is a G1 point represented as bytes.
    /// @param signature The signature to verify. Signature is a G1 point represented as bytes.
    /// @return isValid boolean which evaluates to true if the signature is valid, false otherwise.
    function verifySignature(bytes calldata message, bytes calldata signature) external view returns (bool isValid) {
        /// @dev Converts message hash bytes to G1 point
        BLS2.PointG1 memory _message = BLS2.g1Unmarshal(message);
        /// @dev Converts signature bytes to G1 point
        BLS2.PointG1 memory _signature = BLS2.g1Unmarshal(signature);

        /// @dev Calls EVM precompile for pairing check
        (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(_signature, publicKey, _message);
        return pairingSuccess && callSuccess;
    }

    /// @notice Hashes a message to a point on G1 and
    /// returns the point encoded as bytes
    /// @param message The input message to hash
    /// @return The encoded point in bytes format
    function hashToBytes(bytes calldata message) external view returns (bytes memory) {
        BLS2.PointG1 memory point = BLS2.hashToPoint(DST, message);
        return BLS2.g1Marshal(point);
    }
}
