// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import "forge-std/console.sol";
import "../contracts/LCPClientIAS.sol";
import "../contracts/AVRValidator.sol";
import "../contracts/RemoteAttestation.sol";
import "./TestHelper.t.sol";

contract ReportTest is BasicTest {
    struct TestCase {
        string path;
        bool verifyError;
        address enclaveKey;
        address operator;
    }

    RemoteAttestation.ReportAllowedStatus internal allowedStatuses;

    mapping(string => uint256) internal allowedAdvisoriesForValidateAdvisories;

    TestCase[] internal cases;

    function setUp() public {
        // valid cases
        cases.push(
            TestCase({
                path: "./test/data/reports/valid/001-avr",
                verifyError: false,
                enclaveKey: 0x836Fec0cC99Ed0242ed02fBAAb648652B2372E41,
                operator: address(0)
            })
        );
        cases.push(
            TestCase({
                path: "./test/data/reports/valid/002-avr",
                verifyError: false,
                enclaveKey: 0xC9f79d5de52dbe84120055FF286642C5c328466e,
                operator: 0xcb96F8d6C2d543102184d679D7829b39434E4EEc
            })
        );

        // invalid cases
        cases.push(
            TestCase({
                path: "./test/data/reports/invalid/001-avr",
                verifyError: true,
                enclaveKey: address(0),
                operator: address(0)
            })
        );
    }

    function testVerify() public {
        vm.warp(1692703263);
        AVRValidator.RSAParams memory rootParams =
            AVRValidator.verifyRootCACert(vm.readFileBinary("./test/data/certs/Intel_SGX_Attestation_RootCA.der"));

        for (uint256 i = 0; i < cases.length; i++) {
            TestCase storage c = cases[i];

            initAllowedStatusAdvisories(
                readNestedString(c.path, ".avr", ".isvEnclaveQuoteStatus"),
                readNestedStringArray(c.path, ".avr", ".advisoryIDs")
            );

            bytes memory signingCert = readSigningCert(c.path);
            AVRValidator.RSAParams memory signingParams =
                AVRValidator.verifySigningCert(rootParams.modulus, rootParams.exponent, signingCert);

            bytes memory report = readReport(c.path);
            bytes memory signature = readSignature(c.path);
            bool ok =
                AVRValidator.verifySignature(sha256(report), signature, signingParams.exponent, signingParams.modulus);
            if (c.verifyError) {
                require(!ok, "must be failed to verify report");
                continue;
            } else {
                require(ok, "failed to verify report");
            }
            AVRValidator.ReportExtractedElements memory reElem =
                AVRValidator.validateAndExtractElements(true, report, allowedStatuses);
            require(c.enclaveKey == reElem.enclaveKey, "enclave key mismatch");
            require(c.operator == reElem.operator, "operator mismatch");
        }
    }

    function testAvrForDebugEnclave() public {
        for (uint256 i = 0; i < cases.length; i++) {
            TestCase storage c = cases[i];
            if (c.verifyError) {
                continue;
            }
            bytes memory report = readReport(c.path);
            try AVRValidator.validateAndExtractElements(false, report, allowedStatuses) returns (
                AVRValidator.ReportExtractedElements memory
            ) {
                revert("An AVR for debug enclave must be disallowed");
            } catch (bytes memory) {}
        }
    }

    function testValidateAdvisories() public {
        uint256 offset;

        allowedAdvisoriesForValidateAdvisories["INTEL-SA-00000"] = RemoteAttestation.FLAG_ALLOWED;
        allowedAdvisoriesForValidateAdvisories["INTEL-SA-00001"] = RemoteAttestation.FLAG_ALLOWED;

        {
            offset = TestAVRValidator.validateAdvisories(bytes("[]"), 0, allowedAdvisoriesForValidateAdvisories);
            assertEq(offset, 2);
        }

        {
            offset = TestAVRValidator.validateAdvisories(
                bytes("[\"INTEL-SA-00000\"]"), 0, allowedAdvisoriesForValidateAdvisories
            );
            assertEq(offset, 18);
        }

        {
            offset = TestAVRValidator.validateAdvisories(
                bytes("[\"INTEL-SA-00000\",\"INTEL-SA-00001\"]"), 0, allowedAdvisoriesForValidateAdvisories
            );
            assertEq(offset, 35);
        }
    }

    function initAllowedStatusAdvisories(string memory quoteStatus, string[] memory advisories) internal {
        allowedStatuses.allowedQuoteStatuses[quoteStatus] = RemoteAttestation.FLAG_ALLOWED;
        for (uint256 i = 0; i < advisories.length; i++) {
            allowedStatuses.allowedAdvisories[advisories[i]] = RemoteAttestation.FLAG_ALLOWED;
        }
    }

    function readReport(string memory path) internal returns (bytes memory) {
        return readJSON(path, ".avr");
    }

    function readSignature(string memory path) internal returns (bytes memory) {
        return readDecodedBytes(path, ".signature");
    }

    function readSigningCert(string memory path) internal returns (bytes memory) {
        return readDecodedBytes(path, ".signing_cert");
    }
}
