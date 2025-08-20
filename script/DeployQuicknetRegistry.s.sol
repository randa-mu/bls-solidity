// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {Script} from "forge-std-1.10.0/src/Script.sol";

import {QuicknetRegistry} from "src/demos/QuicknetRegistry.sol";

contract QuicknetDemo is Script {
    function run() public {
        vm.broadcast();
        // Deploy with CREATE2 deterministic address
        new QuicknetRegistry{salt: ""}();
    }
}
