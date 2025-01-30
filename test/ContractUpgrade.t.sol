// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {Options} from "openzeppelin-foundry-upgrades/Options.sol";
import {LCPClientIASOwnableUpgradeable} from "../contracts/LCPClientIASOwnableUpgradeable.sol";

contract ContractUpgrade is Test {
    string internal constant rootCAFile = "test/data/certs/Intel_SGX_Attestation_RootCA.der";

    function testUpgrade() public {
        if (!vm.envOr("TEST_UPGRADEABLE", false)) {
            return;
        }
        Options memory opts;
        opts.constructorData = abi.encode(address(0x01), true);
        bytes memory rootCACert = vm.readFileBinary(rootCAFile);
        vm.warp(2524607999);
        Upgrades.deployUUPSProxy(
            "LCPClientIASOwnableUpgradeable.sol",
            abi.encodeCall(LCPClientIASOwnableUpgradeable.initialize, rootCACert),
            opts
        );
    }
}
