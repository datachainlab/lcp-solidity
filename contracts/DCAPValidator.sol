// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

library DCAPValidator {
    /// @notice The offset of the SGX quote body in the output bytes
    uint256 internal constant SGX_QUOTE_BODY_OFFSET = 67;
    /// @notice The offset of the attributes of the SGX quote body in the output bytes
    uint256 internal constant ATTRIBUTES_OFFSET = SGX_QUOTE_BODY_OFFSET + 16 + 4 + 28;
    /// @notice The offset of the MRENCLAVE of the SGX quote body in the output bytes
    uint256 internal constant MRENCLAVE_OFFSET = ATTRIBUTES_OFFSET + 16;
    /// @notice The end offset of the MRENCLAVE of the SGX quote body in the output bytes
    uint256 internal constant MRENCLAVE_END_OFFSET = MRENCLAVE_OFFSET + 32;
    /// @notice The offset of the report data of the SGX quote body in the output bytes
    uint256 internal constant REPORT_DATA_OFFSET = SGX_QUOTE_BODY_OFFSET + 320;
    /// @notice The offset of the enclave key in the report data of the SGX quote body in the output bytes
    uint256 internal constant REPORT_DATA_ENCLAVE_KEY_OFFSET = REPORT_DATA_OFFSET + 1;
    /// @notice The offset of the operator in the report data of the SGX quote body in the output bytes
    uint256 internal constant REPORT_DATA_OPERATOR_OFFSET = REPORT_DATA_ENCLAVE_KEY_OFFSET + 20;
    /// @notice The end offset of the operator in the report data of the SGX quote body in the output bytes
    uint256 internal constant REPORT_DATA_OPERATOR_END_OFFSET = REPORT_DATA_OPERATOR_OFFSET + 20;
    /// @notice The offset of the advisory IDs in the output bytes
    uint256 internal constant ADVISORY_IDS_OFFSET = REPORT_DATA_OFFSET + 64;

    /// @notice The TCB status
    uint8 internal constant TCB_STATUS_UP_TO_DATE = 0;
    uint8 internal constant TCB_STATUS_OUT_OF_DATE = 1;
    uint8 internal constant TCB_STATUS_REVOKED = 2;
    uint8 internal constant TCB_STATUS_CONFIGURATION_NEEDED = 3;
    uint8 internal constant TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED = 4;
    uint8 internal constant TCB_STATUS_SW_HARDENING_NEEDED = 5;
    uint8 internal constant TCB_STATUS_CONFIGURATION_AND_SW_HARDENING_NEEDED = 6;

    /// @notice The string representation of the TCB status
    string internal constant TCB_STATUS_UP_TO_DATE_STRING = "UpToDate";
    string internal constant TCB_STATUS_OUT_OF_DATE_STRING = "OutOfDate";
    string internal constant TCB_STATUS_REVOKED_STRING = "Revoked";
    string internal constant TCB_STATUS_CONFIGURATION_NEEDED_STRING = "ConfigurationNeeded";
    string internal constant TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED_STRING = "OutOfDateConfigurationNeeded";
    string internal constant TCB_STATUS_SW_HARDENING_NEEDED_STRING = "SWHardeningNeeded";
    string internal constant TCB_STATUS_CONFIGURATION_AND_SW_HARDENING_NEEDED_STRING =
        "ConfigurationAndSWHardeningNeeded";

    /// @notice The keccak256 hash of the string representation of the TCB status
    bytes32 internal constant TCB_STATUS_UP_TO_DATE_KECCAK256_HASH = keccak256(bytes(TCB_STATUS_UP_TO_DATE_STRING));

    /**
     * @notice The output of the quote verification
     * @dev This struct corresponds to `QuoteVerificationOutput` in the dcap-quote-verifier library.
     *      Note that some fields from the original output are omitted or parsed in greater detail in Solidity for our use case.
     *      ref. https://github.com/datachainlab/zkdcap/blob/9616d7976a84e97a128fa02175ec994b95e3c137/crates/quote-verifier/src/verifier.rs#L19
     */
    struct Output {
        string tcbStatus;
        uint32 minTcbEvaluationDataNumber;
        bytes32 sgxIntelRootCAHash;
        uint64 validityNotBefore;
        uint64 validityNotAfter;
        bool enclaveDebugEnabled;
        bytes32 mrenclave;
        address enclaveKey;
        address operator;
        string[] advisoryIDs;
    }

    /**
     * @notice Parse the output bytes from the quote verification
     * @param outputBytes The output bytes from the quote verification
     * @return output The parsed output
     */
    function parseOutput(bytes calldata outputBytes) public pure returns (Output memory) {
        require(bytes2(outputBytes[0:2]) == hex"0000", "unexpected version");
        require(uint16(bytes2(outputBytes[2:4])) == 3, "unexpected quote version");
        require(uint32(bytes4(outputBytes[4:8])) == 0, "unexpected tee type");

        Output memory output;
        output.tcbStatus = tcbStatusToString(uint8(outputBytes[8]));
        output.minTcbEvaluationDataNumber = uint32(bytes4(outputBytes[9:13]));
        output.sgxIntelRootCAHash = bytes32(outputBytes[19:51]);
        output.validityNotBefore = uint64(bytes8(outputBytes[51:59]));
        output.validityNotAfter = uint64(bytes8(outputBytes[59:67]));
        output.enclaveDebugEnabled = uint8(outputBytes[ATTRIBUTES_OFFSET]) & uint8(2) != 0;
        output.mrenclave = bytes32(outputBytes[MRENCLAVE_OFFSET:MRENCLAVE_END_OFFSET]);
        // The initial byte of the report data is the version of the report data
        require(outputBytes[REPORT_DATA_OFFSET] == 0x01, "unexpected report data version");
        output.enclaveKey = address(bytes20(outputBytes[REPORT_DATA_ENCLAVE_KEY_OFFSET:REPORT_DATA_OPERATOR_OFFSET]));
        output.operator = address(bytes20(outputBytes[REPORT_DATA_OPERATOR_OFFSET:REPORT_DATA_OPERATOR_END_OFFSET]));
        output.advisoryIDs = abi.decode(outputBytes[ADVISORY_IDS_OFFSET:outputBytes.length], (string[]));
        return output;
    }

    /**
     * @notice Convert the TCB status to a string
     * @param tcbStatus The TCB status
     * @return The string representation of the TCB status
     */
    function tcbStatusToString(uint8 tcbStatus) internal pure returns (string memory) {
        // The if-else chain is ordered based on the expected frequency of allowed TCB statuses
        // (most common statuses first), rather than the order of the enum definition.
        // This ordering may result in minor gas savings by reducing the average number of comparisons in common cases.
        if (tcbStatus == TCB_STATUS_UP_TO_DATE) {
            return TCB_STATUS_UP_TO_DATE_STRING;
        } else if (tcbStatus == TCB_STATUS_SW_HARDENING_NEEDED) {
            return TCB_STATUS_SW_HARDENING_NEEDED_STRING;
        } else if (tcbStatus == TCB_STATUS_CONFIGURATION_NEEDED) {
            return TCB_STATUS_CONFIGURATION_NEEDED_STRING;
        } else if (tcbStatus == TCB_STATUS_CONFIGURATION_AND_SW_HARDENING_NEEDED) {
            return TCB_STATUS_CONFIGURATION_AND_SW_HARDENING_NEEDED_STRING;
        } else if (tcbStatus == TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED) {
            return TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED_STRING;
        } else if (tcbStatus == TCB_STATUS_OUT_OF_DATE) {
            return TCB_STATUS_OUT_OF_DATE_STRING;
        } else if (tcbStatus == TCB_STATUS_REVOKED) {
            return TCB_STATUS_REVOKED_STRING;
        } else {
            revert("unexpected TCB status");
        }
    }
}
