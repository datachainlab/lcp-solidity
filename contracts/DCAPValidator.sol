// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

library DCAPValidator {
    uint256 internal constant SGX_DCAP_VERIFIER_MIN_COMMIT_SIZE = 40 + 13 + 384;

    struct DCAPVerifierCommit {
        uint64 attestationTime;
        bytes32 sgxIntelRootCAHash;
        // VerifiedOutput offset: 40(8+32) bytes
        // [quote_vesion][tee_type][tcb_status][fmspc][quote_body_raw_bytes][advisory_ids]
        // 2 bytes + 4 bytes + 1 byte + 6 bytes + var (SGX_ENCLAVE_REPORT = 384; TD10_REPORT = 584) + var
        uint8 tcbStatus;
        bytes32 mrenclave;
        // reportData
        address enclaveKey;
        address operator;
        string[] advisoryIDs;
    }

    /*
    pub struct SGX_ENCLAVE_REPORT {
        pub cpu_svn: [u8; 16],      // [16 bytes]
                                    // Security Version of the CPU (raw value)
        pub misc_select: [u8; 4],   // [4 bytes]
                                    // SSA Frame extended feature set. 
                                    // Reports what SECS.MISCSELECT settings are used in the enclave. You can limit the
                                    // allowed MISCSELECT settings in the sigstruct using MISCSELECT/MISCMASK.
        pub reserved_1: [u8; 28],   // [28 bytes]
                                    // Reserved for future use - 0
        pub attributes: [u8; 16],   // [16 bytes]
                                    // Set of flags describing attributes of the enclave.
                                    // Reports what SECS.ATTRIBUTES settings are used in the enclave. The ISV can limit what
                                    // SECS.ATTRIBUTES can be used when loading the enclave through parameters to the SGX Signtool.
                                    // The Signtool will produce a SIGSTRUCT with ATTRIBUTES and ATTRIBUTESMASK 
                                    // which determine allowed ATTRIBUTES.
                                    // - For each SIGSTRUCT.ATTRIBUTESMASK bit that is set, then corresponding bit in the
                                    // SECS.ATTRIBUTES must match the same bit in SIGSTRUCT.ATTRIBUTES.
        pub mrenclave: [u8; 32],    // [32 bytes] 
                                    // Measurement of the enclave. 
                                    // The MRENCLAVE value is the SHA256 hash of the ENCLAVEHASH field in the SIGSTRUCT.
        pub reserved_2: [u8; 32],   // [32 bytes] 
                                    // Reserved for future use - 0
        pub mrsigner: [u8; 32],     // [32 bytes]
                                    // Measurement of the enclave signer. 
                                    // The MRSIGNER value is the SHA256 hash of the MODULUS field in the SIGSTRUCT.
        pub reserved_3: [u8; 96],   // [96 bytes]
                                    // Reserved for future use - 0
        pub isv_prod_id: u16,       // [2 bytes]
                                    // Product ID of the enclave. 
                                    // The ISV should configure a unique ISVProdID for each product which may
                                    // want to share sealed data between enclaves signed with a specific MRSIGNER. The ISV
                                    // may want to supply different data to identical enclaves signed for different products.
        pub isv_svn: u16,           // [2 bytes]
                                    // Security Version of the enclave
        pub reserved_4: [u8; 60],   // [60 bytes]
                                    // Reserved for future use - 0
        pub report_data: [u8; 64],  // [64 bytes]
                                    // Additional report data.
                                    // The enclave is free to provide 64 bytes of custom data to the REPORT.
                                    // This can be used to provide specific data from the enclave or it can be used to hold 
                                    // a hash of a larger block of data which is provided with the quote. 
                                    // The verification of the quote signature confirms the integrity of the
                                    // report data (and the rest of the REPORT body).
    }
    */
    function parseCommit(bytes calldata commit) internal pure returns (DCAPVerifierCommit memory) {
        DCAPVerifierCommit memory verifierCommit;
        verifierCommit.attestationTime = uint64(bytes8(commit[0:8]));
        verifierCommit.sgxIntelRootCAHash = bytes32(commit[8:40]);
        require(uint16(bytes2(commit[40:42])) == 3, "unexpected quote version");
        require(uint32(bytes4(commit[42:46])) == 0, "unexpected tee type");
        verifierCommit.tcbStatus = uint8(commit[46]);
        uint256 sgxQuoteBodyOffset = 53;
        uint256 mrenclaveOffset = sgxQuoteBodyOffset + 16 + 4 + 28 + 16;
        verifierCommit.mrenclave = bytes32(commit[mrenclaveOffset:mrenclaveOffset + 32]);

        uint256 reportDataOffset = sgxQuoteBodyOffset + 320;
        /// ReportData is a 64-byte value that is embedded in the Quote
        /// | version: 1 byte | enclave key: 20 bytes | operator: 20 bytes | nonce: 22 bytes |
        require(commit[reportDataOffset] == 0x01, "unexpected report data version");
        verifierCommit.enclaveKey = address(bytes20(commit[reportDataOffset + 1:reportDataOffset + 1 + 20]));
        verifierCommit.operator = address(bytes20(commit[reportDataOffset + 1 + 20:reportDataOffset + 1 + 20 + 20]));
        if (commit.length > SGX_DCAP_VERIFIER_MIN_COMMIT_SIZE) {
            // remain bytes are advisory IDs
            verifierCommit.advisoryIDs = abi.decode(commit[SGX_DCAP_VERIFIER_MIN_COMMIT_SIZE:commit.length], (string[]));
        }
        return verifierCommit;
    }

    function tcbStatusToString(uint8 tcbStatus) internal pure returns (string memory) {
        if (tcbStatus == 0) {
            return "UpToDate";
        } else if (tcbStatus == 1) {
            return "SWHardeningNeeded";
        } else if (tcbStatus == 2) {
            return "ConfigurationAndSWHardeningNeeded";
        } else if (tcbStatus == 3) {
            return "ConfigurationNeeded";
        } else if (tcbStatus == 4) {
            return "OutOfDate";
        } else if (tcbStatus == 5) {
            return "OutOfDateConfigurationNeeded";
        } else if (tcbStatus == 6) {
            return "Revoked";
        } else if (tcbStatus == 7) {
            return "Unrecognized";
        } else {
            revert("unknown tcb status");
        }
    }
}
