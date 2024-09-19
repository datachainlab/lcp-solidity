// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {LCPClientBase} from "./LCPClientBase.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/// @custom:oz-upgrades-unsafe-allow external-library-linking
contract LCPClientOwnableUpgradeable is LCPClientBase, UUPSUpgradeable, OwnableUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address ibcHandler, bool developmentMode) LCPClientBase(ibcHandler, developmentMode) {}

    function initialize(bytes memory rootCACert) public initializer {
        initializeRootCACert(rootCACert);
        __UUPSUpgradeable_init();
        __Ownable_init(msg.sender);
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}
}
