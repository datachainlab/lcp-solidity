// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {LCPClientIASBase} from "./LCPClientIASBase.sol";

contract LCPClientIAS is LCPClientIASBase {
    constructor(address ibcHandler_, bool developmentMode_, bytes memory rootCACert)
        LCPClientIASBase(ibcHandler_, developmentMode_)
    {
        initializeRootCACert(rootCACert);
    }
}
