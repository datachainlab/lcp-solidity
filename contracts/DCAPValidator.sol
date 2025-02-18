// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

library DCAPValidator {
    uint256 internal constant SGX_QUOTE_BODY_OFFSET = 67;
    uint256 internal constant ATTRIBUTES_OFFSET = SGX_QUOTE_BODY_OFFSET + 16 + 4 + 28;
    uint256 internal constant MRENCLAVE_OFFSET = ATTRIBUTES_OFFSET + 16;
    uint256 internal constant MRENCLAVE_END_OFFSET = MRENCLAVE_OFFSET + 32;
    uint256 internal constant REPORT_DATA_OFFSET = SGX_QUOTE_BODY_OFFSET + 320;
    uint256 internal constant REPORT_DATA_ENCLAVE_KEY_OFFSET = REPORT_DATA_OFFSET + 1;
    uint256 internal constant REPORT_DATA_OPERATOR_OFFSET = REPORT_DATA_ENCLAVE_KEY_OFFSET + 20;
    uint256 internal constant REPORT_DATA_OPERATOR_END_OFFSET = REPORT_DATA_OPERATOR_OFFSET + 20;
    uint256 internal constant ADVISORY_IDS_OFFSET = REPORT_DATA_OFFSET + 64;

    uint8 internal constant TCB_STATUS_UP_TO_DATE = 0;
    uint8 internal constant TCB_STATUS_OUT_OF_DATE = 1;
    uint8 internal constant TCB_STATUS_REVOKED = 2;
    uint8 internal constant TCB_STATUS_CONFIGURATION_NEEDED = 3;
    uint8 internal constant TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED = 4;
    uint8 internal constant TCB_STATUS_SW_HARDENING_NEEDED = 5;
    uint8 internal constant TCB_STATUS_CONFIGURATION_AND_SW_HARDENING_NEEDED = 6;

    struct Output {
        uint8 tcbStatus;
        bytes32 sgxIntelRootCAHash;
        uint64 validityNotBeforeMax;
        uint64 validityNotAfterMin;
        bool enclaveDebugEnabled;
        bytes32 mrenclave;
        address enclaveKey;
        address operator;
        string[] advisoryIDs;
    }

    function parseOutput(bytes calldata outputBytes) public pure returns (Output memory) {
        require(bytes2(outputBytes[0:2]) == hex"0000", "unexpected version");
        require(uint16(bytes2(outputBytes[2:4])) == 3, "unexpected quote version");
        require(uint32(bytes4(outputBytes[4:8])) == 0, "unexpected tee type");

        Output memory output;
        output.tcbStatus = uint8(outputBytes[8]);
        output.sgxIntelRootCAHash = bytes32(outputBytes[19:51]);
        output.validityNotBeforeMax = uint64(bytes8(outputBytes[51:59]));
        output.validityNotAfterMin = uint64(bytes8(outputBytes[59:67]));
        output.enclaveDebugEnabled = uint8(outputBytes[ATTRIBUTES_OFFSET]) & uint8(2) != 0;
        output.mrenclave = bytes32(outputBytes[MRENCLAVE_OFFSET:MRENCLAVE_END_OFFSET]);

        require(outputBytes[REPORT_DATA_OFFSET] == 0x01, "unexpected report data version");
        output.enclaveKey = address(bytes20(outputBytes[REPORT_DATA_ENCLAVE_KEY_OFFSET:REPORT_DATA_OPERATOR_OFFSET]));
        output.operator = address(bytes20(outputBytes[REPORT_DATA_OPERATOR_OFFSET:REPORT_DATA_OPERATOR_END_OFFSET]));
        output.advisoryIDs = abi.decode(outputBytes[ADVISORY_IDS_OFFSET:outputBytes.length], (string[]));
        return output;
    }

    function tcbStatusToString(uint8 tcbStatus) public pure returns (string memory) {
        if (tcbStatus == TCB_STATUS_UP_TO_DATE) {
            return "UpToDate";
        } else if (tcbStatus == TCB_STATUS_OUT_OF_DATE) {
            return "OutOfDate";
        } else if (tcbStatus == TCB_STATUS_REVOKED) {
            return "Revoked";
        } else if (tcbStatus == TCB_STATUS_CONFIGURATION_NEEDED) {
            return "ConfigurationNeeded";
        } else if (tcbStatus == TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED) {
            return "OutOfDateConfigurationNeeded";
        } else if (tcbStatus == TCB_STATUS_SW_HARDENING_NEEDED) {
            return "SWHardeningNeeded";
        } else if (tcbStatus == TCB_STATUS_CONFIGURATION_AND_SW_HARDENING_NEEDED) {
            return "ConfigurationAndSWHardeningNeeded";
        } else {
            revert("unexpected TCB status");
        }
    }
}
