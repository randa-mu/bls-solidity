// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {Test, console} from "forge-std-1.10.0/src/Test.sol";
import {ScheduledUpgradeable} from "src/upgradeable/ScheduledUpgradeable.sol";
import {ErrorsLib} from "src/libraries/ErrorsLib.sol";
import {IScheduledUpgradeable, ISignatureScheme} from "src/interfaces/IScheduledUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @notice Mock contracts for testing
contract MockBLSValidator is ISignatureScheme {
    bool public shouldVerify = true;

    function verifySignature(bytes memory, bytes memory) external view returns (bool) {
        return shouldVerify;
    }

    function hashToBytes(bytes memory message) external pure returns (bytes memory) {
        return abi.encodePacked(keccak256(message));
    }

    function setShouldVerify(bool _shouldVerify) external {
        shouldVerify = _shouldVerify;
    }

    // Add the missing required functions
    function DST() external pure returns (bytes memory) {
        return "mock-dst";
    }

    function SCHEME_ID() external pure returns (string memory) {
        return "MOCK_BLS";
    }

    function getPublicKeyBytes() external pure returns (bytes memory) {
        return hex"0123456789abcdef"; // Mock public key bytes
    }
}

contract MockImplementation {
    uint256 public version = 1;

    function initialize() external {
        version = 2;
    }
}

contract MockImplementationV2 {
    uint256 public version = 2;

    function initialize() external {
        version = 3;
    }
}

/// @notice Implementation of ScheduledUpgradeable for testing
contract TestScheduledUpgradeable is ScheduledUpgradeable {
    function initialize(address _contractUpgradeBlsValidator, uint256 _minimumContractUpgradeDelay)
        external
        initializer
    {
        __ScheduledUpgradeable_init(_contractUpgradeBlsValidator, _minimumContractUpgradeDelay);
    }

    function exposed_authorizeUpgrade(address newImplementation) external view {
        _authorizeUpgrade(newImplementation);
    }
}

contract ScheduledUpgradeableTest is Test {
    TestScheduledUpgradeable public scheduledUpgradeable;
    MockBLSValidator public blsValidator;
    MockImplementation public mockImpl;

    address public constant ADMIN = address(0x1);
    uint256 public constant MIN_DELAY = 2 days;
    uint256 public UPGRADE_TIME = block.timestamp + 3 days;
    bytes public constant MOCK_SIGNATURE = hex"1234567890abcdef";
    bytes public constant UPGRADE_CALLDATA = abi.encodeWithSignature("initialize()");

    event UpgradeScheduled(address indexed newImplementation, uint256 upgradeTime);
    event UpgradeCancelled(address indexed cancelledImplementation);
    event UpgradeExecuted(address indexed newImplementation);
    event ContractUpgradeBLSValidatorUpdated(address indexed newValidator);
    event MinimumContractUpgradeDelayUpdated(uint256 newDelay);

    function setUp() public {
        blsValidator = new MockBLSValidator();
        mockImpl = new MockImplementation();
        scheduledUpgradeable = new TestScheduledUpgradeable();

        scheduledUpgradeable.initialize(address(blsValidator), MIN_DELAY);
    }

    // ---------------------- Initialization Tests ----------------------

    function test_initialize_success() public {
        TestScheduledUpgradeable newContract = new TestScheduledUpgradeable();

        newContract.initialize(address(blsValidator), MIN_DELAY);

        assertEq(address(newContract.contractUpgradeBlsValidator()), address(blsValidator));
        assertEq(newContract.minimumContractUpgradeDelay(), MIN_DELAY);
        assertEq(newContract.currentNonce(), 0);
        assertEq(newContract.scheduledImplementation(), address(0));
        assertEq(newContract.scheduledTimestampForUpgrade(), 0);
    }

    function test_initialize_revertsOnZeroAddress() public {
        TestScheduledUpgradeable newContract = new TestScheduledUpgradeable();

        vm.expectRevert(ErrorsLib.ZeroAddress.selector);
        newContract.initialize(address(0), MIN_DELAY);
    }

    function test_initialize_revertsOnShortDelay() public {
        TestScheduledUpgradeable newContract = new TestScheduledUpgradeable();

        vm.expectRevert(ErrorsLib.UpgradeDelayTooShort.selector);
        newContract.initialize(address(blsValidator), 1 days);
    }

    // ---------------------- Schedule Upgrade Tests ----------------------

    function test_scheduleUpgrade_success() public {
        vm.warp(block.timestamp);
        uint256 upgradeTime = block.timestamp + MIN_DELAY + 1;

        vm.expectEmit(true, false, false, true);
        emit UpgradeScheduled(address(mockImpl), upgradeTime);

        scheduledUpgradeable.scheduleUpgrade(address(mockImpl), UPGRADE_CALLDATA, upgradeTime, MOCK_SIGNATURE);

        assertEq(scheduledUpgradeable.scheduledImplementation(), address(mockImpl));
        assertEq(scheduledUpgradeable.scheduledTimestampForUpgrade(), upgradeTime);
        assertEq(scheduledUpgradeable.currentNonce(), 1);
    }

    function test_scheduleUpgrade_revertsOnZeroAddress() public {
        uint256 upgradeTime = block.timestamp + MIN_DELAY + 1;

        vm.expectRevert(ErrorsLib.ZeroAddress.selector);
        scheduledUpgradeable.scheduleUpgrade(address(0), UPGRADE_CALLDATA, upgradeTime, MOCK_SIGNATURE);
    }

    function test_scheduleUpgrade_revertsOnSameVersion() public {
        uint256 upgradeTime = block.timestamp + MIN_DELAY + 1;

        // Schedule first upgrade
        scheduledUpgradeable.scheduleUpgrade(address(mockImpl), UPGRADE_CALLDATA, upgradeTime, MOCK_SIGNATURE);

        // Try to schedule same implementation again
        vm.expectRevert(ErrorsLib.SameVersionUpgradeNotAllowed.selector);
        scheduledUpgradeable.scheduleUpgrade(address(mockImpl), UPGRADE_CALLDATA, upgradeTime + 1, MOCK_SIGNATURE);
    }

    function test_scheduleUpgrade_revertsOnShortDelay() public {
        uint256 upgradeTime = block.timestamp + MIN_DELAY - 1;

        vm.expectRevert(abi.encodeWithSelector(ErrorsLib.UpgradeTimeMustRespectDelay.selector, MIN_DELAY));
        scheduledUpgradeable.scheduleUpgrade(address(mockImpl), UPGRADE_CALLDATA, upgradeTime, MOCK_SIGNATURE);
    }

    function test_scheduleUpgrade_revertsOnInvalidSignature() public {
        blsValidator.setShouldVerify(false);
        uint256 upgradeTime = block.timestamp + MIN_DELAY + 1;

        vm.expectRevert(ErrorsLib.BLSSignatureVerificationFailed.selector);
        scheduledUpgradeable.scheduleUpgrade(address(mockImpl), UPGRADE_CALLDATA, upgradeTime, MOCK_SIGNATURE);
    }

    // ---------------------- Cancel Upgrade Tests ----------------------

    function test_cancelUpgrade_success() public {
        uint256 upgradeTime = block.timestamp + MIN_DELAY + 1;

        // Schedule upgrade
        scheduledUpgradeable.scheduleUpgrade(address(mockImpl), UPGRADE_CALLDATA, upgradeTime, MOCK_SIGNATURE);

        vm.expectEmit(true, false, false, false);
        emit UpgradeCancelled(address(mockImpl));

        scheduledUpgradeable.cancelUpgrade(MOCK_SIGNATURE);

        assertEq(scheduledUpgradeable.scheduledImplementation(), address(0));
        assertEq(scheduledUpgradeable.scheduledTimestampForUpgrade(), 0);
        assertEq(scheduledUpgradeable.currentNonce(), 2);
    }

    function test_cancelUpgrade_revertsWhenTooLate() public {
        uint256 upgradeTime = block.timestamp + MIN_DELAY + 1;

        // Schedule upgrade
        scheduledUpgradeable.scheduleUpgrade(address(mockImpl), UPGRADE_CALLDATA, upgradeTime, MOCK_SIGNATURE);

        // Move time past upgrade time
        vm.warp(upgradeTime + 1);

        vm.expectRevert(abi.encodeWithSelector(ErrorsLib.TooLateToCancelUpgrade.selector, upgradeTime));
        scheduledUpgradeable.cancelUpgrade(MOCK_SIGNATURE);
    }

    function test_cancelUpgrade_revertsOnInvalidSignature() public {
        uint256 upgradeTime = block.timestamp + MIN_DELAY + 1;

        // Schedule upgrade
        scheduledUpgradeable.scheduleUpgrade(address(mockImpl), UPGRADE_CALLDATA, upgradeTime, MOCK_SIGNATURE);

        blsValidator.setShouldVerify(false);

        vm.expectRevert(ErrorsLib.BLSSignatureVerificationFailed.selector);
        scheduledUpgradeable.cancelUpgrade(MOCK_SIGNATURE);
    }

    // ---------------------- Execute Upgrade Tests ----------------------

    function test_executeUpgrade_revertsNoPendingUpgrade() public {
        vm.expectRevert(ErrorsLib.NoUpgradePending.selector);
        scheduledUpgradeable.executeUpgrade();
    }

    function test_executeUpgrade_revertsWhenTooEarly() public {
        uint256 upgradeTime = block.timestamp + MIN_DELAY + 1;

        // Schedule upgrade
        scheduledUpgradeable.scheduleUpgrade(address(mockImpl), UPGRADE_CALLDATA, upgradeTime, MOCK_SIGNATURE);

        vm.expectRevert(abi.encodeWithSelector(ErrorsLib.UpgradeTooEarly.selector, upgradeTime));
        scheduledUpgradeable.executeUpgrade();
    }

    // ---------------------- Admin Functions Tests ----------------------

    function test_setContractUpgradeBlsValidator_success() public {
        MockBLSValidator newValidator = new MockBLSValidator();

        vm.expectEmit(true, false, false, false);
        emit ContractUpgradeBLSValidatorUpdated(address(newValidator));

        scheduledUpgradeable.setContractUpgradeBlsValidator(address(newValidator), MOCK_SIGNATURE);

        assertEq(address(scheduledUpgradeable.contractUpgradeBlsValidator()), address(newValidator));
        assertEq(scheduledUpgradeable.currentNonce(), 1);
    }

    function test_setContractUpgradeBlsValidator_revertsOnZeroAddress() public {
        vm.expectRevert(ErrorsLib.ZeroAddress.selector);
        scheduledUpgradeable.setContractUpgradeBlsValidator(address(0), MOCK_SIGNATURE);
    }

    function test_setContractUpgradeBlsValidator_revertsOnInvalidSignature() public {
        MockBLSValidator newValidator = new MockBLSValidator();
        blsValidator.setShouldVerify(false);

        vm.expectRevert(ErrorsLib.BLSSignatureVerificationFailed.selector);
        scheduledUpgradeable.setContractUpgradeBlsValidator(address(newValidator), MOCK_SIGNATURE);
    }

    function test_setMinimumContractUpgradeDelay_success() public {
        uint256 newDelay = 3 days;

        vm.expectEmit(false, false, false, true);
        emit MinimumContractUpgradeDelayUpdated(newDelay);

        scheduledUpgradeable.setMinimumContractUpgradeDelay(newDelay, MOCK_SIGNATURE);

        assertEq(scheduledUpgradeable.minimumContractUpgradeDelay(), newDelay);
        assertEq(scheduledUpgradeable.currentNonce(), 1);
    }

    function test_setMinimumContractUpgradeDelay_revertsOnShortDelay() public {
        vm.expectRevert(ErrorsLib.UpgradeDelayTooShort.selector);
        scheduledUpgradeable.setMinimumContractUpgradeDelay(1 days, MOCK_SIGNATURE);
    }

    function test_setMinimumContractUpgradeDelay_revertsOnInvalidSignature() public {
        blsValidator.setShouldVerify(false);

        vm.expectRevert(ErrorsLib.BLSSignatureVerificationFailed.selector);
        scheduledUpgradeable.setMinimumContractUpgradeDelay(3 days, MOCK_SIGNATURE);
    }

    // ---------------------- Authorization Tests ----------------------

    function test_authorizeUpgrade_revertsWhenNotSelf() public {
        vm.expectRevert(ErrorsLib.UpgradeMustGoThroughExecuteUpgrade.selector);
        scheduledUpgradeable.exposed_authorizeUpgrade(address(mockImpl));
    }

    function test_authorizeUpgrade_successWhenSelf() public {
        // This would be called internally during executeUpgrade
        vm.prank(address(scheduledUpgradeable));
        scheduledUpgradeable.exposed_authorizeUpgrade(address(mockImpl));
        // Should not revert
    }

    // ---------------------- View Functions Tests ----------------------

    function test_getChainId() public {
        assertEq(scheduledUpgradeable.getChainId(), block.chainid);
    }

    function test_contractUpgradeParamsToBytes() public {
        string memory action = "schedule";
        address pendingImpl = address(0);
        address newImpl = address(mockImpl);
        uint256 upgradeTime = block.timestamp + MIN_DELAY;
        uint256 nonce = 1;

        (bytes memory message, bytes memory messageAsG1Bytes) = scheduledUpgradeable.contractUpgradeParamsToBytes(
            action, pendingImpl, newImpl, UPGRADE_CALLDATA, upgradeTime, nonce
        );

        bytes memory expectedMessage = abi.encode(
            action,
            address(scheduledUpgradeable),
            pendingImpl,
            newImpl,
            UPGRADE_CALLDATA,
            upgradeTime,
            nonce,
            block.chainid
        );

        assertEq(message, expectedMessage);
        assertEq(messageAsG1Bytes, abi.encodePacked(keccak256(expectedMessage)));
    }

    function test_blsValidatorUpdateParamsToBytes() public {
        string memory action = "change-contract-upgrade-bls-validator";
        address newValidator = address(0x123);
        uint256 nonce = 1;

        (bytes memory message, bytes memory messageAsG1Bytes) =
            scheduledUpgradeable.blsValidatorUpdateParamsToBytes(action, newValidator, nonce);

        bytes memory expectedMessage =
            abi.encode(action, address(scheduledUpgradeable), newValidator, nonce, block.chainid);

        assertEq(message, expectedMessage);
        assertEq(messageAsG1Bytes, abi.encodePacked(keccak256(expectedMessage)));
    }

    function test_minimumContractUpgradeDelayParamsToBytes() public {
        string memory action = "change-upgrade-delay";
        uint256 newDelay = 3 days;
        uint256 nonce = 1;

        (bytes memory message, bytes memory messageAsG1Bytes) =
            scheduledUpgradeable.minimumContractUpgradeDelayParamsToBytes(action, newDelay, nonce);

        bytes memory expectedMessage = abi.encode(action, address(scheduledUpgradeable), newDelay, nonce, block.chainid);

        assertEq(message, expectedMessage);
        assertEq(messageAsG1Bytes, abi.encodePacked(keccak256(expectedMessage)));
    }
}
