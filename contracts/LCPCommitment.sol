// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {Height} from "@hyperledger-labs/yui-ibc-solidity/contracts/proto/Client.sol";

library LCPCommitment {
    uint16 internal constant LCP_MESSAGE_VERSION = 1;
    uint16 internal constant LCP_MESSAGE_TYPE_UPDATE_STATE = 1;
    uint16 internal constant LCP_MESSAGE_TYPE_STATE = 2;
    uint16 internal constant LCP_MESSAGE_TYPE_MISBEHAVIOUR = 3;
    uint16 internal constant LCP_MESSAGE_CONTEXT_TYPE_EMPTY = 0;
    uint16 internal constant LCP_MESSAGE_CONTEXT_TYPE_TRUSTING_PERIOD = 1;

    bytes32 internal constant LCP_MESSAGE_HEADER_UPDATE_STATE =
        bytes32(uint256(LCP_MESSAGE_VERSION) << 240 | uint256(LCP_MESSAGE_TYPE_UPDATE_STATE) << 224);
    bytes32 internal constant LCP_MESSAGE_HEADER_STATE =
        bytes32(uint256(LCP_MESSAGE_VERSION) << 240 | uint256(LCP_MESSAGE_TYPE_STATE) << 224);
    bytes32 internal constant LCP_MESSAGE_HEADER_MISBEHAVIOUR =
        bytes32(uint256(LCP_MESSAGE_VERSION) << 240 | uint256(LCP_MESSAGE_TYPE_MISBEHAVIOUR) << 224);

    error LCPCommitmentUnexpectedProxyMessageHeader();
    error LCPCommtimentInvalidTrustingPeriodContextLength();
    error LCPCommitmentUnknownValidationContextType();
    error LCPCommtimentTrustingPeriodContextOutOfTrustingPeriod();
    error LCPCommitmentTrustingPeriodHeaderFromFuture();

    struct HeaderedProxyMessage {
        bytes32 header;
        bytes message;
    }

    struct UpdateStateProxyMessage {
        Height.Data prevHeight;
        bytes32 prevStateId;
        Height.Data postHeight;
        bytes32 postStateId;
        uint128 timestamp;
        bytes context;
        EmittedState[] emittedStates;
    }

    struct EmittedState {
        Height.Data height;
        bytes state;
    }

    struct MisbehaviourProxyMessage {
        PrevState[] prevStates;
        bytes context;
        bytes clientMessage;
    }

    struct PrevState {
        Height.Data height;
        bytes32 stateId;
    }

    struct ValidationContext {
        bytes32 header;
        bytes context;
    }

    struct TrustingPeriodContext {
        uint128 untrustedHeaderTimestamp;
        uint128 trustedStateTimestamp;
        uint128 trustingPeriod;
        uint128 clockDrift;
    }

    function parseValidationContext(bytes memory context) internal pure returns (ValidationContext memory) {
        return abi.decode(context, (ValidationContext));
    }

    function extractContextType(bytes32 header) internal pure returns (uint16) {
        // MSB first
        // 0-1:  type
        // 2-31: reserved
        return uint16(uint256(header) >> 240);
    }

    function validationContextEval(bytes memory context, uint256 currentTimestampNanos) internal pure {
        ValidationContext memory vc = parseValidationContext(context);
        // MSB first
        // 0-1:  type
        // 2-31: reserved
        uint16 contextType = extractContextType(vc.header);
        if (contextType == LCP_MESSAGE_CONTEXT_TYPE_EMPTY) {
            return;
        } else if (contextType == LCP_MESSAGE_CONTEXT_TYPE_TRUSTING_PERIOD) {
            if (vc.context.length != 64) {
                revert LCPCommtimentInvalidTrustingPeriodContextLength();
            }
            return trustingPeriodContextEval(parseTrustingPeriodContext(vc.context), currentTimestampNanos);
        } else {
            revert LCPCommitmentUnknownValidationContextType();
        }
    }

    function parseTrustingPeriodContext(bytes memory context) internal pure returns (TrustingPeriodContext memory) {
        (bytes32 timestamps, bytes32 params) = abi.decode(context, (bytes32, bytes32));
        // timestamps
        // 0-15: untrusted_header_timestamp
        // 16-31: trusted_state_timestamp
        uint128 untrustedHeaderTimestamp = uint128(uint256(timestamps) >> 128);
        uint128 trustedStateTimestamp = uint128(uint256(timestamps));

        // params
        // 0-15: trusting_period
        // 16-31: clock_drift
        uint128 trustingPeriod = uint128(uint256(params) >> 128);
        uint128 clockDrift = uint128(uint256(params));

        return TrustingPeriodContext(untrustedHeaderTimestamp, trustedStateTimestamp, trustingPeriod, clockDrift);
    }

    function trustingPeriodContextEval(TrustingPeriodContext memory context, uint256 currentTimestampNanos)
        internal
        pure
    {
        if (currentTimestampNanos >= context.trustedStateTimestamp + context.trustingPeriod) {
            revert LCPCommtimentTrustingPeriodContextOutOfTrustingPeriod();
        } else if (currentTimestampNanos + context.clockDrift <= context.untrustedHeaderTimestamp) {
            revert LCPCommitmentTrustingPeriodHeaderFromFuture();
        }
        return;
    }

    struct CommitmentProofs {
        bytes message;
        bytes[] signatures;
    }

    struct VerifyMembershipProxyMessage {
        bytes prefix;
        bytes path;
        bytes32 value;
        Height.Data height;
        bytes32 stateId;
    }

    function parseVerifyMembershipProxyMessage(bytes memory messageBytes)
        internal
        pure
        returns (VerifyMembershipProxyMessage memory)
    {
        HeaderedProxyMessage memory hm = abi.decode(messageBytes, (HeaderedProxyMessage));
        // MSB first
        // 0-1:  version
        // 2-3:  message type
        // 4-31: reserved
        if (hm.header != LCP_MESSAGE_HEADER_STATE) {
            revert LCPCommitmentUnexpectedProxyMessageHeader();
        }
        return abi.decode(hm.message, (VerifyMembershipProxyMessage));
    }

    function parseVerifyMembershipCommitmentProofs(bytes calldata commitmentProofsBytes)
        internal
        pure
        returns (CommitmentProofs memory, VerifyMembershipProxyMessage memory)
    {
        CommitmentProofs memory commitmentProofs = abi.decode(commitmentProofsBytes, (CommitmentProofs));
        return (commitmentProofs, parseVerifyMembershipProxyMessage(commitmentProofs.message));
    }
}
