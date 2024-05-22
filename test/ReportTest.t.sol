// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import "forge-std/console.sol";
import "../contracts/LCPClient.sol";
import "../contracts/AVRValidator.sol";
import "./TestHelper.t.sol";

contract ReportTest is BasicTest {
    struct TestCase {
        string path;
        address addr;
        string timestamp;
        bool verifyError;
    }

    mapping(string => uint256) internal allowedQuoteStatuses;
    mapping(string => uint256) internal allowedAdvisories;

    mapping(string => uint256) internal allowedAdvisoriesForValidateAdvisories;

    TestCase[] internal cases;

    function setUp() public {
        // TODO add more cases

        // valid cases
        cases.push(
            TestCase({
                path: "./test/data/reports/valid/avr-01",
                addr: 0x4D165CB1BEEDA5fAF1713A5C212007be2a53D97B,
                timestamp: "2022-12-01T09:49:53.473230",
                verifyError: false
            })
        );
        cases.push(
            TestCase({
                path: "./test/data/reports/valid/avr-02",
                addr: 0xa3ED9460b7C564Ca7487c0CD2DD5584a1C76f5Fa,
                timestamp: "2022-12-05T02:01:12.282060",
                verifyError: false
            })
        );

        // invalid cases
        cases.push(
            TestCase({
                path: "./test/data/reports/invalid/avr-01",
                addr: address(0),
                timestamp: "2022-12-01T09:49:53.473230",
                verifyError: true
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
            (address signer,,) =
                AVRValidator.validateAndExtractElements(true, report, allowedQuoteStatuses, allowedAdvisories);
            require(c.addr == signer, "unexpected signer");
        }
    }

    function testAvrForDebugEnclave() public {
        for (uint256 i = 0; i < cases.length; i++) {
            TestCase storage c = cases[i];
            if (c.verifyError) {
                continue;
            }
            bytes memory report = readReport(c.path);
            try AVRValidator.validateAndExtractElements(false, report, allowedQuoteStatuses, allowedAdvisories)
            returns (address, uint256, bytes32) {
                revert("An AVR for debug enclave must be disallowed");
            } catch (bytes memory) {}
        }
    }

    function testTimestampParsing() public view {
        // TODO add tests for DateUtils
        for (uint256 i = 0; i < cases.length; i++) {
            TestCase storage c = cases[i];
            if (c.verifyError) {
                continue;
            }
            uint256 timestamp = TestLCPUtils.attestationTimestampToSeconds(bytes(c.timestamp));
            console.log(timestamp);
        }
    }

    function testValidateAdvisories() public {
        uint256 offset;

        allowedAdvisoriesForValidateAdvisories["INTEL-SA-00000"] = AVRValidator.FLAG_ALLOWED;
        allowedAdvisoriesForValidateAdvisories["INTEL-SA-00001"] = AVRValidator.FLAG_ALLOWED;

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
        allowedQuoteStatuses[quoteStatus] = AVRValidator.FLAG_ALLOWED;
        for (uint256 i = 0; i < advisories.length; i++) {
            allowedAdvisories[advisories[i]] = AVRValidator.FLAG_ALLOWED;
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
