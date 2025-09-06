// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS} from "src/libraries/BLS.sol";

import {BytesLib} from "src/libraries/BytesLib.sol";

import {ISignatureScheme} from "src/interfaces/ISignatureScheme.sol";

/// @title BN254SignatureScheme contract
/// @author Randamu
/// @notice A contract that implements a BN254 signature scheme
contract BN254SignatureScheme is ISignatureScheme {
    using BytesLib for bytes32;

    /// @notice Enum to represent the contract type
    enum ContractType {
        Bridge,
        Upgrade
    }

    /// @notice Links public keys of threshold network statically to signature scheme contracts and remove from constructor of sender contracts. Admin cannot update, simply use new scheme id.
    BLS.PointG2 private publicKey;

    /// @notice Signature scheme identifier
    string public constant SCHEME_ID = "BN254";

    /// @notice Domain separation tag for the BLS signature scheme
    bytes public DST;

    /// @notice Custom error for invalid contract type in the constructor.
    /// @notice Should either be "bridge" or "upgrade"
    error InvalidContractType();

    /// @notice Constructor for the BN254SignatureScheme contract.
    /// @param contractType The type of contract (0 for Bridge, 1 for Upgrade).
    constructor(bytes memory publicKeyBytes, ContractType contractType) {
        // Validate the contract type
        if (contractType != ContractType.Bridge && contractType != ContractType.Upgrade) {
            revert InvalidContractType();
        }

        publicKey = BLS.g2Unmarshal(publicKeyBytes);

        // Set the DST based on the contract type
        string memory typeString = contractType == ContractType.Bridge ? "bridge" : "upgrade";
        DST = abi.encodePacked(
            "dcipher-", typeString, "-v01-BN254G1_XMD:KECCAK-256_SVDW_RO_", bytes32(block.chainid).toHexString(), "_"
        );
    }

    /// @notice Retrieves the public key associated with the decryption process.
    /// @dev Returns the public key as bytes.
    /// @return Bytes string representing the public key points on the elliptic curve.
    function getPublicKeyBytes() public view returns (bytes memory) {
        return BLS.g2Marshal(publicKey);
    }

    /// @notice Verifies a signature using the given signature scheme.
    /// @param message The message that was signed. Message is a G1 point represented as bytes.
    /// @param signature The signature to verify. Signature is a G1 point represented as bytes.
    /// @param publicKey_ The public key of the signer. Public key is a G2 point represented as bytes.
    /// @return isValid boolean which evaluates to true if the signature is valid, false otherwise.
    function verifySignature(bytes calldata message, bytes calldata signature, bytes calldata publicKey_)
        external
        view
        returns (bool isValid)
    {
        /// @dev Converts message hash bytes to G1 point
        BLS.PointG1 memory _message = BLS.g1Unmarshal(message);
        /// @dev Converts signature bytes to G1 point
        BLS.PointG1 memory _signature = BLS.g1Unmarshal(signature);
        /// @dev Converts public key bytes to G2 point
        BLS.PointG2 memory _publicKey = BLS.g2Unmarshal(publicKey_);

        /// @dev Calls EVM precompile for pairing check
        (bool pairingSuccess, bool callSuccess) = BLS.verifySingle(_signature, _publicKey, _message);
        return pairingSuccess && callSuccess;
    }

    /// @notice Hashes a message to a point on the BN254 curve
    /// @param message The input message to hash
    /// @return (x, y) The coordinates of the resulting point on the curve
    function hashToPoint(bytes calldata message) public view returns (uint256, uint256) {
        BLS.PointG1 memory point = BLS.hashToPoint(DST, message);
        return (point.x, point.y);
    }

    /// @notice Hashes a message to a point on G1 and
    /// returns the point encoded as bytes
    /// @param message The input message to hash
    /// @return The encoded point in bytes format
    function hashToBytes(bytes calldata message) external view returns (bytes memory) {
        (uint256 x, uint256 y) = hashToPoint(message);
        return BLS.g1Marshal(BLS.PointG1({x: x, y: y}));
    }
}
