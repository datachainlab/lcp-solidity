// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/StdJson.sol";
import "../contracts/AVRValidator.sol";
import "../contracts/LCPUtils.sol";
import "../contracts/LCPCommitment.sol";

abstract contract BasicTest is Test {
    using stdJson for string;

    function readJSON(string memory path, string memory filter) internal virtual returns (bytes memory) {
        string memory json = vm.readFile(path);
        return json.readBytes(filter);
    }

    function readDecodedBytes(string memory path, string memory filter) internal returns (bytes memory) {
        return Base64.decode(string(readJSON(path, filter)));
    }

    function readNestedString(string memory path, string memory firstFilter, string memory secondFilter)
        internal
        view
        virtual
        returns (string memory)
    {
        string memory json = vm.readFile(path);
        string memory data = json.readString(firstFilter);
        return data.readString(secondFilter);
    }

    function readNestedStringArray(string memory path, string memory firstFilter, string memory secondFilter)
        internal
        view
        virtual
        returns (string[] memory)
    {
        string memory json = vm.readFile(path);
        string memory data = json.readString(firstFilter);
        return data.readStringArray(secondFilter);
    }
}

library TestLCPUtils {
    function attestationTimestampToSeconds(bytes calldata timestamp) public pure returns (uint256) {
        return LCPUtils.attestationTimestampToSeconds(timestamp);
    }

    function rfc5280TimeToSeconds(bytes calldata timestamp) public pure returns (uint256) {
        return LCPUtils.rfc5280TimeToSeconds(timestamp);
    }
}

library TestAVRValidator {
    function validateAdvisories(
        bytes calldata report,
        uint256 offset,
        mapping(string => uint256) storage allowedAdvisories
    ) public view returns (uint256) {
        return AVRValidator.validateAdvisories(report, offset, allowedAdvisories);
    }
}

library LCPCommitmentTestHelper {
    function trustingPeriodContextEval(
        LCPCommitment.TrustingPeriodContext memory context,
        uint256 currentTimestampNanos
    ) public pure {
        LCPCommitment.trustingPeriodContextEval(context, currentTimestampNanos);
    }

    function parseUpdateStateProxyMessage(bytes calldata commitmentBytes)
        public
        pure
        returns (LCPCommitment.UpdateStateProxyMessage memory commitment)
    {
        return LCPCommitment.parseUpdateStateProxyMessage(commitmentBytes);
    }

    function parseVerifyMembershipCommitmentProof(bytes calldata proofBytes)
        public
        pure
        returns (LCPCommitment.CommitmentProof memory, LCPCommitment.VerifyMembershipProxyMessage memory)
    {
        return LCPCommitment.parseVerifyMembershipCommitmentProof(proofBytes);
    }

    function parseMisbehaviourProxyMessage(bytes calldata messageBytes)
        public
        pure
        returns (LCPCommitment.MisbehaviourProxyMessage memory)
    {
        return LCPCommitment.parseMisbehaviourProxyMessage(messageBytes);
    }
}
