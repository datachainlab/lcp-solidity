// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {Options} from "openzeppelin-foundry-upgrades/Options.sol";

contract ContractUpgrade is Test {
    function testUpgradeIAS() public {
        if (!vm.envOr("TEST_UPGRADEABLE", false)) {
            return;
        }
        Options memory opts;
        opts.constructorData = abi.encode(address(0x01), true);
        Upgrades.validateImplementation("LCPClientIASOwnableUpgradeable.sol", opts);
    }

    function testUpgradeZKDCAP() public {
        if (!vm.envOr("TEST_UPGRADEABLE", false)) {
            return;
        }
        Options memory opts;
        opts.constructorData = abi.encode(address(0x01), true, 0x01, address(0x01));
        Upgrades.validateImplementation("LCPClientZKDCAPOwnableUpgradeable.sol", opts);
    }
}
