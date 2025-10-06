// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IScheduledUpgradeable, ISignatureScheme} from "../interfaces/IScheduledUpgradeable.sol";
import {ErrorsLib} from "../libraries/ErrorsLib.sol";
import {BLS} from "../libraries/BLS.sol";

/// @title ScheduledUpgradeable
/// @author Randamu
/// @notice Abstract contract for scheduling, cancelling, and executing contract upgrades.
/// @dev Handles BLS (BN254) signature verification for scheduling and cancelling upgrades.
abstract contract ScheduledUpgradeable is IScheduledUpgradeable, Initializable, UUPSUpgradeable {
    /// @notice Unique nonce for each message to prevent replay attacks
    uint256 public currentNonce;

    /// @notice Address of the scheduled implementation upgrade
    address public scheduledImplementation;

    /// @notice Calldata for the scheduled implementation upgrade
    bytes internal scheduledImplementationCalldata;

    /// @notice Timestamp for the scheduled implementation upgrade
    uint256 public scheduledTimestampForUpgrade;

    /// @notice Minimum delay for upgrade operations
    uint256 public minimumContractUpgradeDelay;

    /// @notice BLS validator used for validating admin threshold signatures for stopping timed upgrades
    ISignatureScheme public contractUpgradeBlsValidator;

    // ---------------------- Initializer ----------------------

    /// @notice Initializes upgrade scheduling logic.
    /// @param _contractUpgradeBlsValidator Address of the BLS validator contract
    /// @param _minimumContractUpgradeDelay Minimum delay for upgrades in seconds
    function __ScheduledUpgradeable_init(address _contractUpgradeBlsValidator, uint256 _minimumContractUpgradeDelay)
        internal
        onlyInitializing
    {
        require(_contractUpgradeBlsValidator != address(0), ErrorsLib.ZeroAddress());
        require(_minimumContractUpgradeDelay >= 2 days, ErrorsLib.UpgradeDelayTooShort());

        contractUpgradeBlsValidator = ISignatureScheme(_contractUpgradeBlsValidator);
        minimumContractUpgradeDelay = _minimumContractUpgradeDelay;
    }

    // ---------------------- External Functions ----------------------

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
    ) public virtual {
        require(newImplementation != address(0), ErrorsLib.ZeroAddress());
        require(scheduledImplementation != newImplementation, ErrorsLib.SameVersionUpgradeNotAllowed());
        require(
            upgradeTime >= block.timestamp + minimumContractUpgradeDelay,
            ErrorsLib.UpgradeTimeMustRespectDelay(minimumContractUpgradeDelay)
        );

        string memory action = "schedule";
        uint256 nonce = ++currentNonce;
        (, bytes memory messageAsG1Bytes) = contractUpgradeParamsToBytes(
            action, scheduledImplementation, newImplementation, upgradeCalldata, upgradeTime, nonce
        );

        require(
            contractUpgradeBlsValidator.verifySignature(messageAsG1Bytes, signature),
            ErrorsLib.BLSSignatureVerificationFailed()
        );

        scheduledImplementation = newImplementation;
        scheduledTimestampForUpgrade = upgradeTime;
        scheduledImplementationCalldata = upgradeCalldata;

        emit UpgradeScheduled(newImplementation, upgradeTime);
    }

    /// @notice Cancels a previously scheduled contract upgrade.
    /// @param signature BLS signature from the admin threshold validating the upgrade cancellation
    function cancelUpgrade(bytes calldata signature) public virtual {
        require(
            block.timestamp < scheduledTimestampForUpgrade,
            ErrorsLib.TooLateToCancelUpgrade(scheduledTimestampForUpgrade)
        );

        string memory action = "cancel";
        uint256 nonce = ++currentNonce;
        (, bytes memory messageAsG1Bytes) = contractUpgradeParamsToBytes(
            action,
            scheduledImplementation,
            scheduledImplementation,
            scheduledImplementationCalldata,
            scheduledTimestampForUpgrade,
            nonce
        );

        require(
            contractUpgradeBlsValidator.verifySignature(messageAsG1Bytes, signature),
            ErrorsLib.BLSSignatureVerificationFailed()
        );

        address cancelledImplementation = scheduledImplementation;

        scheduledImplementation = address(0);
        scheduledTimestampForUpgrade = 0;
        scheduledImplementationCalldata = "";

        emit UpgradeCancelled(cancelledImplementation);
    }

    /// @notice Executes a previously scheduled contract upgrade.
    /// @dev Can only be called after the scheduled upgrade time has passed
    function executeUpgrade() public virtual {
        require(scheduledImplementation != address(0), ErrorsLib.NoUpgradePending());
        require(
            block.timestamp >= scheduledTimestampForUpgrade, ErrorsLib.UpgradeTooEarly(scheduledTimestampForUpgrade)
        );

        address impl = scheduledImplementation;
        bytes memory callData = scheduledImplementationCalldata;

        scheduledImplementation = address(0);
        scheduledTimestampForUpgrade = 0;
        scheduledImplementationCalldata = "";

        (bool success, bytes memory ret) =
            address(this).call(abi.encodeWithSelector(this.upgradeToAndCall.selector, impl, callData));

        if (!success) {
            if (ret.length > 0) {
                assembly {
                    let size := mload(ret)
                    revert(add(ret, 32), size)
                }
            }
            revert ErrorsLib.UpgradeFailed();
        }

        emit UpgradeExecuted(impl);
    }

    // ---------------------- View Functions ----------------------

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
    ) public view virtual returns (bytes memory, bytes memory) {
        bytes memory message = abi.encode(
            action,
            address(this),
            pendingImplementation,
            newImplementation,
            upgradeCalldata,
            upgradeTime,
            nonce,
            getChainId()
        );
        bytes memory messageAsG1Bytes = contractUpgradeBlsValidator.hashToBytes(message);
        return (message, messageAsG1Bytes);
    }

    /// @notice Converts BLS validator update parameters to a BLS G1 point and its byte representation.
    /// @param action The action being performed (e.g., "change-contract-upgrade-bls-validator" or "change-swap-request-bls-validator")
    /// @param blsValidator The address of the new BLS validator contract
    /// @param nonce The nonce for the update request
    /// @return message The original encoded message
    /// @return messageAsG1Bytes The byte representation of the BLS G1 point
    function blsValidatorUpdateParamsToBytes(string memory action, address blsValidator, uint256 nonce)
        public
        view
        virtual
        returns (bytes memory, bytes memory)
    {
        bytes memory message = abi.encode(action, address(this), blsValidator, nonce, getChainId());
        bytes memory messageAsG1Bytes = contractUpgradeBlsValidator.hashToBytes(message);
        return (message, messageAsG1Bytes);
    }

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
    ) public view virtual returns (bytes memory, bytes memory) {
        bytes memory message = abi.encode(action, address(this), _minimumContractUpgradeDelay, nonce, getChainId());
        bytes memory messageAsG1Bytes = contractUpgradeBlsValidator.hashToBytes(message);
        return (message, messageAsG1Bytes);
    }

    /// @notice Returns the current chain ID.
    /// @return chainId The current chain ID
    function getChainId() public view returns (uint256 chainId) {
        chainId = block.chainid;
    }

    // ---------------------- Internal Functions ----------------------

    /// @dev Required by UUPS to restrict upgrades.
    function _authorizeUpgrade(address) internal view virtual override {
        require(msg.sender == address(this), ErrorsLib.UpgradeMustGoThroughExecuteUpgrade());
    }

    // ---------------------- Admin Functions ----------------------

    /// @notice Updates the BLS validator contract used for validating admin threshold signatures.
    /// @param _contractUpgradeBlsValidator Address of the new BLS validator contract
    /// @param signature BLS signature from the current BLS validator validating the update
    function setContractUpgradeBlsValidator(address _contractUpgradeBlsValidator, bytes calldata signature)
        public
        virtual
    {
        require(_contractUpgradeBlsValidator != address(0), ErrorsLib.ZeroAddress());
        string memory action = "change-contract-upgrade-bls-validator";
        uint256 nonce = ++currentNonce;
        (, bytes memory messageAsG1Bytes) = blsValidatorUpdateParamsToBytes(action, _contractUpgradeBlsValidator, nonce);

        require(
            contractUpgradeBlsValidator.verifySignature(messageAsG1Bytes, signature),
            ErrorsLib.BLSSignatureVerificationFailed()
        );
        contractUpgradeBlsValidator = ISignatureScheme(_contractUpgradeBlsValidator);
        emit ContractUpgradeBLSValidatorUpdated(address(contractUpgradeBlsValidator));
    }

    /// @notice Updates the minimum delay required for scheduling contract upgrades.
    /// @param _minimumContractUpgradeDelay The new minimum delay in seconds
    /// @param signature BLS signature from the current BLS validator validating the update
    function setMinimumContractUpgradeDelay(uint256 _minimumContractUpgradeDelay, bytes calldata signature)
        public
        virtual
    {
        require(_minimumContractUpgradeDelay >= 2 days, ErrorsLib.UpgradeDelayTooShort());
        string memory action = "change-upgrade-delay";
        uint256 nonce = ++currentNonce;
        (, bytes memory messageAsG1Bytes) =
            minimumContractUpgradeDelayParamsToBytes(action, _minimumContractUpgradeDelay, nonce);

        require(
            contractUpgradeBlsValidator.verifySignature(messageAsG1Bytes, signature),
            ErrorsLib.BLSSignatureVerificationFailed()
        );
        minimumContractUpgradeDelay = _minimumContractUpgradeDelay;
        emit MinimumContractUpgradeDelayUpdated(minimumContractUpgradeDelay);
    }
}
