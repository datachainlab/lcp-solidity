// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {LCPClientBase} from "./LCPClientBase.sol";

contract LCPClient is LCPClientBase {
    constructor(address ibcHandler_, bool developmentMode_, bytes memory rootCACert)
        LCPClientBase(ibcHandler_, developmentMode_)
    {
        initializeRootCACert(rootCACert);
    }
}
