// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {LCPClientZKDCAPBase} from "./LCPClientZKDCAPBase.sol";

contract LCPClientZKDCAP is LCPClientZKDCAPBase {
    constructor(address ibcHandler_, bytes memory intelRootCA, address riscZeroVerifier)
        LCPClientZKDCAPBase(ibcHandler_, intelRootCA, riscZeroVerifier)
    {}
}
