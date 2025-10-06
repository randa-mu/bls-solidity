// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

/// @title ErrorsLib
/// @notice Library containing custom error definitions
library ErrorsLib {
    /// @notice Thrown when a zero address is provided where a valid address is required
    error ZeroAddress();

    /// @notice Thrown when the upgrade delay is shorter than the minimum required
    error UpgradeDelayTooShort();

    /// @notice Thrown when attempting to upgrade to the same version that is already scheduled
    error SameVersionUpgradeNotAllowed();

    /// @notice Thrown when the upgrade time doesn't respect the minimum delay requirement
    /// @param minimumDelay The minimum delay that must be respected
    error UpgradeTimeMustRespectDelay(uint256 minimumDelay);

    /// @notice Thrown when BLS signature verification fails
    error BLSSignatureVerificationFailed();

    /// @notice Thrown when attempting to cancel an upgrade after the deadline has passed
    /// @param scheduledTimestamp The timestamp when the upgrade was scheduled to execute
    error TooLateToCancelUpgrade(uint256 scheduledTimestamp);

    /// @notice Thrown when attempting to execute an upgrade but no upgrade is pending
    error NoUpgradePending();

    /// @notice Thrown when attempting to execute an upgrade before its scheduled time
    /// @param scheduledTimestamp The timestamp when the upgrade can be executed
    error UpgradeTooEarly(uint256 scheduledTimestamp);

    /// @notice Thrown when the upgrade execution fails
    error UpgradeFailed();

    /// @notice Thrown when attempting to upgrade without going through the executeUpgrade function
    error UpgradeMustGoThroughExecuteUpgrade();
}
