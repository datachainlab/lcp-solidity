// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {LCPClientZKDCAPBase} from "./LCPClientZKDCAPBase.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/// @custom:oz-upgrades-unsafe-allow external-library-linking
contract LCPClientZKDCAPOwnableUpgradeable is LCPClientZKDCAPBase, UUPSUpgradeable, OwnableUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address ibcHandler_, bool developmentMode_, bytes memory intelRootCA, address riscZeroVerifier_)
        LCPClientZKDCAPBase(ibcHandler_, developmentMode_, intelRootCA, riscZeroVerifier_)
    {}

    function initialize() public initializer {
        __UUPSUpgradeable_init();
        __Ownable_init(msg.sender);
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}
}
