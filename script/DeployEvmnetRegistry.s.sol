// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {Script} from "forge-std-1.10.0/src/Script.sol";

import {EvmnetRegistry} from "src/demos/EvmnetRegistry.sol";

contract EvmnetDemo is Script {
    function run() public {
        vm.broadcast();
        // Deploy with CREATE2 deterministic address
        new EvmnetRegistry{salt: ""}();
    }
}
