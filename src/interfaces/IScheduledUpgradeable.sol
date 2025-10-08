// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS} from "../libraries/BLS.sol";

import {ISignatureScheme} from "./ISignatureScheme.sol";

/// @title IScheduledUpgradeable
/// @author Randamu
/// @notice Interface for the ScheduledUpgradeable contract
interface IScheduledUpgradeable {
    // ---------------------- Events ----------------------
    /// @notice Emitted when the minimum contract upgrade delay is updated
    /// @param newDelay The new minimum delay for upgrade operations
    event MinimumContractUpgradeDelayUpdated(uint256 newDelay);
    /// @notice Emitted when a contract upgrade is scheduled
    /// @param newImplementation The address of the new implementation contract
    /// @param executeAfter The timestamp after which the upgrade can be executed
    event UpgradeScheduled(address indexed newImplementation, uint256 executeAfter);

    /// @notice Emitted when a scheduled upgrade is cancelled
    /// @param cancelledImplementation The address of the cancelled implementation contract
    event UpgradeCancelled(address indexed cancelledImplementation);

    /// @notice Emitted when a scheduled upgrade is executed
    /// @param newImplementation The address of the new implementation contract
    event UpgradeExecuted(address indexed newImplementation);

    /// @notice Emitted when the BLS validator contract is updated
    /// @param contractUpgradeBlsValidator The new BLS validator contract address
    event ContractUpgradeBLSValidatorUpdated(address indexed contractUpgradeBlsValidator);

    // ---------------------- Functions ----------------------

    /// @notice Schedules a contract upgrade.
    /// @param newImplementation Address of the new implementation contract to upgrade to
    /// @param upgradeCalldata Calldata to be executed during the upgrade
    /// @param upgradeTime Timestamp after which the upgrade can be executed
    /// @param signature BLS signature from the admin threshold validating the upgrade scheduling
    function scheduleUpgrade(
        address newImplementation,
        bytes calldata upgradeCalldata,
        uint256 upgradeTime,
        bytes calldata signature
    ) external;

    /// @notice Cancels a previously scheduled contract upgrade.
    /// @param signature BLS signature from the admin threshold validating the upgrade cancellation
    function cancelUpgrade(bytes calldata signature) external;

    /// @notice Executes a previously scheduled contract upgrade.
    function executeUpgrade() external;

    /// @notice Sets the BLS validator contract address.
    /// @param _contractUpgradeBlsValidator The new BLS validator contract address
    /// @param signature BLS signature from the admin threshold validating the update
    function setContractUpgradeBlsValidator(address _contractUpgradeBlsValidator, bytes calldata signature) external;

    /// @notice Sets the minimum delay required for scheduling contract upgrades.
    /// @param _minimumContractUpgradeDelay The new minimum delay in seconds
    /// @param signature BLS signature from the admin threshold validating the update
    function setMinimumContractUpgradeDelay(uint256 _minimumContractUpgradeDelay, bytes calldata signature) external;

    // ---------------------- Getters ----------------------

    /// @notice Returns the current nonce for upgrade operations.
    function currentNonce() external view returns (uint256);

    /// @notice Returns the address of the scheduled implementation upgrade.
    function scheduledImplementation() external view returns (address);

    /// @notice Returns the timestamp for the scheduled implementation upgrade.
    function scheduledTimestampForUpgrade() external view returns (uint256);

    /// @notice Returns the address of the BLS validator contract.
    function contractUpgradeBlsValidator() external view returns (ISignatureScheme);

    /// @notice Returns the minimum delay required for scheduling contract upgrades.
    function minimumContractUpgradeDelay() external view returns (uint256);

    /// @notice Converts contract upgrade parameters to a BLS G1 point and its byte representation.
    /// @param action The action being performed ("schedule" or "cancel")
    /// @param pendingImplementation The address of the already pending implementation (or zero address if none)
    /// @param newImplementation The address of the new implementation contract
    /// @param upgradeCalldata The calldata to be executed during the upgrade
    /// @param upgradeTime The timestamp after which the upgrade can be executed
    /// @param nonce The nonce for the upgrade request
    /// @return message The original encoded message
    /// @return messageAsG1Bytes The byte representation of the BLS G1 point
    function contractUpgradeParamsToBytes(
        string memory action,
        address pendingImplementation,
        address newImplementation,
        bytes memory upgradeCalldata,
        uint256 upgradeTime,
        uint256 nonce
    ) external view returns (bytes memory, bytes memory);

    /// @notice Converts BLS validator update parameters to a BLS G1 point and its byte representation.
    /// @param action The action being performed (e.g., "change-contract-upgrade-bls-validator" or "change-swap-request-bls-validator")
    /// @param blsValidator The address of the new BLS validator contract
    /// @param nonce The nonce for the update request
    /// @return message The original encoded message
    /// @return messageAsG1Bytes The byte representation of the BLS G1 point
    function blsValidatorUpdateParamsToBytes(string memory action, address blsValidator, uint256 nonce)
        external
        view
        returns (bytes memory, bytes memory);

    /// @notice Converts minimum contract upgrade delay parameters to a BLS G1 point and its byte representation.
    /// @param _minimumContractUpgradeDelay The new minimum delay in seconds
    /// @param action The action being performed ("change-upgrade-delay")
    /// @param nonce The nonce for the update request
    /// @return message The original encoded message
    /// @return messageAsG1Bytes The byte representation of the BLS G1 point
    function minimumContractUpgradeDelayParamsToBytes(
        string memory action,
        uint256 _minimumContractUpgradeDelay,
        uint256 nonce
    ) external view returns (bytes memory, bytes memory);

    /// @notice Returns the current chain ID.
    /// @return chainId The current chain ID
    function getChainId() external view returns (uint256 chainId);
}
