// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/StdJson.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "../contracts/AVRValidator.sol";
import "../contracts/LCPUtils.sol";
import "../contracts/LCPCommitment.sol";
import "../contracts/LCPOperator.sol";

abstract contract BasicTest is Test {
    using stdJson for string;

    function readJSON(string memory path, string memory filter) internal virtual returns (bytes memory) {
        string memory json = vm.readFile(path);
        string memory ret = abi.decode(vm.parseJson(json, filter), (string));
        return bytes(ret);
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
        string memory data = abi.decode(vm.parseJson(json, firstFilter), (string));
        return data.readString(secondFilter);
    }

    function readNestedStringArray(string memory path, string memory firstFilter, string memory secondFilter)
        internal
        view
        virtual
        returns (string[] memory)
    {
        string memory json = vm.readFile(path);
        string memory data = abi.decode(vm.parseJson(json, firstFilter), (string));
        return data.readStringArray(secondFilter);
    }

    function newCommitmentProofs(bytes memory message, bytes memory signature)
        internal
        pure
        returns (LCPCommitment.CommitmentProofs memory)
    {
        LCPCommitment.CommitmentProofs memory commitmentProofs;
        commitmentProofs.message = message;
        commitmentProofs.signatures = new bytes[](1);
        commitmentProofs.signatures[0] = signature;
        return commitmentProofs;
    }

    function createWallets(uint256 count) internal returns (Vm.Wallet[] memory) {
        Vm.Wallet[] memory wallets = new Vm.Wallet[](count);
        for (uint256 i = 0; i < count; i++) {
            wallets[i] = vm.createWallet(string(abi.encodePacked("wallet-", Strings.toString(i))));
        }
        sort(wallets);
        return wallets;
    }

    function sort(Vm.Wallet[] memory wallets) internal pure {
        for (uint256 i = 0; i < wallets.length; i++) {
            for (uint256 j = i + 1; j < wallets.length; j++) {
                if (wallets[i].addr > wallets[j].addr) {
                    (wallets[i], wallets[j]) = (wallets[j], wallets[i]);
                }
            }
        }
    }

    function generateClientId(uint64 clientCounter) internal pure returns (string memory) {
        return string(abi.encodePacked("lcp-", Strings.toString(clientCounter)));
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

    function parseUpdateStateProxyMessage(bytes calldata messageBytes)
        public
        pure
        returns (LCPCommitment.UpdateStateProxyMessage memory)
    {
        LCPCommitment.HeaderedProxyMessage memory hm = abi.decode(messageBytes, (LCPCommitment.HeaderedProxyMessage));
        // MSB first
        // 0-1:  version
        // 2-3:  message type
        // 4-31: reserved
        if (hm.header != LCPCommitment.LCP_MESSAGE_HEADER_UPDATE_STATE) {
            revert LCPCommitment.LCPCommitmentUnexpectedProxyMessageHeader();
        }
        return abi.decode(hm.message, (LCPCommitment.UpdateStateProxyMessage));
    }

    function parseVerifyMembershipCommitmentProofs(bytes calldata proofBytes)
        public
        pure
        returns (LCPCommitment.CommitmentProofs memory, LCPCommitment.VerifyMembershipProxyMessage memory)
    {
        return LCPCommitment.parseVerifyMembershipCommitmentProofs(proofBytes);
    }

    function parseMisbehaviourProxyMessage(bytes calldata messageBytes)
        public
        pure
        returns (LCPCommitment.MisbehaviourProxyMessage memory)
    {
        LCPCommitment.HeaderedProxyMessage memory hm = abi.decode(messageBytes, (LCPCommitment.HeaderedProxyMessage));
        // MSB first
        // 0-1:  version
        // 2-3:  message type
        // 4-31: reserved
        if (hm.header != LCPCommitment.LCP_MESSAGE_HEADER_MISBEHAVIOUR) {
            revert LCPCommitment.LCPCommitmentUnexpectedProxyMessageHeader();
        }
        return abi.decode(hm.message, (LCPCommitment.MisbehaviourProxyMessage));
    }
}

library LCPOperatorTestHelper {
    function computeEIP712UpdateOperators(
        uint256 chainId,
        address verifyingContract,
        string calldata clientId,
        uint64 nonce,
        address[] memory newOperators,
        uint64 thresholdNumerator,
        uint64 thresholdDenominator
    ) public pure returns (bytes memory) {
        return LCPOperator.computeEIP712UpdateOperators(
            chainId, verifyingContract, clientId, nonce, newOperators, thresholdNumerator, thresholdDenominator
        );
    }

    function computeEIP712RegisterEnclaveKey(bytes calldata avr) public pure returns (bytes memory) {
        return LCPOperator.computeEIP712RegisterEnclaveKey(avr);
    }
}
