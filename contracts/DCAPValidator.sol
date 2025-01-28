// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {ILCPClientErrors} from "./ILCPClientErrors.sol";

library DCAPValidator {
    enum TCBStatus {
        UpToDate,
        OutOfDate,
        Revoked,
        ConfigurationNeeded,
        OutOfDateConfigurationNeeded,
        SWHardeningNeeded,
        ConfigurationAndSWHardeningNeeded
    }

    struct Output {
        TCBStatus tcbStatus;
        bytes32 sgxIntelRootCAHash;
        uint64 validityNotBeforeMax;
        uint64 validityNotAfterMin;
        bytes32 mrenclave;
        address enclaveKey;
        address operator;
        string[] advisoryIDs;
    }

    function parseCommit(bytes calldata commit) internal pure returns (Output memory) {
        require(bytes2(commit[0:2]) == hex"0000", "unexpected version");
        require(uint16(bytes2(commit[2:4])) == 3, "unexpected quote version");
        require(uint32(bytes4(commit[4:8])) == 0, "unexpected tee type");

        Output memory output;
        output.tcbStatus = TCBStatus(uint8(commit[8]));
        output.sgxIntelRootCAHash = bytes32(commit[15:47]);
        output.validityNotBeforeMax = uint64(bytes8(commit[47:55]));
        output.validityNotAfterMin = uint64(bytes8(commit[55:63]));

        uint256 sgxQuoteBodyOffset = 63;
        uint256 mrenclaveOffset = sgxQuoteBodyOffset + 16 + 4 + 28 + 16;
        output.mrenclave = bytes32(commit[mrenclaveOffset:mrenclaveOffset + 32]);

        uint256 reportDataOffset = sgxQuoteBodyOffset + 320;
        require(commit[reportDataOffset] == 0x01, "unexpected report data version");
        output.enclaveKey = address(bytes20(commit[reportDataOffset + 1:reportDataOffset + 1 + 20]));
        output.operator = address(bytes20(commit[reportDataOffset + 1 + 20:reportDataOffset + 1 + 20 + 20]));

        uint256 advisoryIDsOffset = reportDataOffset + 64;
        output.advisoryIDs = abi.decode(commit[advisoryIDsOffset:commit.length], (string[]));
        return output;
    }

    function tcbStatusToString(TCBStatus tcbStatus) internal pure returns (string memory) {
        if (tcbStatus == TCBStatus.UpToDate) {
            return "UpToDate";
        } else if (tcbStatus == TCBStatus.OutOfDate) {
            return "OutOfDate";
        } else if (tcbStatus == TCBStatus.Revoked) {
            return "Revoked";
        } else if (tcbStatus == TCBStatus.ConfigurationNeeded) {
            return "ConfigurationNeeded";
        } else if (tcbStatus == TCBStatus.OutOfDateConfigurationNeeded) {
            return "OutOfDateConfigurationNeeded";
        } else if (tcbStatus == TCBStatus.SWHardeningNeeded) {
            return "SWHardeningNeeded";
        } else if (tcbStatus == TCBStatus.ConfigurationAndSWHardeningNeeded) {
            return "ConfigurationAndSWHardeningNeeded";
        } else {
            revert ILCPClientErrors.LCPClientZKDCAPUnrecognizedTCBStatus();
        }
    }
}
