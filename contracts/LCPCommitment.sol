// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import "@hyperledger-labs/yui-ibc-solidity/contracts/proto/Client.sol";

library LCPCommitment {
    uint16 constant LCPCommitmentVersion = 1;
    uint16 constant LCPCommitmentTypeUpdateClient = 1;
    uint16 constant LCPCommitmentTypeState = 2;
    uint16 constant LCPCommitmentContextTypeEmpty = 0;
    uint16 constant LCPCommitmentContextTypeTrustingPeriod = 1;

    struct HeaderedMessage {
        bytes32 header;
        bytes message;
    }

    struct UpdateClientMessage {
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

    function parseUpdateClientMessage(bytes memory commitmentBytes)
        internal
        pure
        returns (UpdateClientMessage memory commitment)
    {
        HeaderedMessage memory hm = abi.decode(commitmentBytes, (HeaderedMessage));
        // MSB first
        // 0-1:  version
        // 2-3:  message type
        // 4-31: reserved
        bytes32 header = bytes32(uint256(LCPCommitmentVersion) << 240 | uint256(LCPCommitmentTypeUpdateClient) << 224);
        require(hm.header == header, "unexpected header");
        return abi.decode(hm.message, (UpdateClientMessage));
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
        if (contextType == LCPCommitmentContextTypeEmpty) {
            return;
        } else if (contextType == LCPCommitmentContextTypeTrustingPeriod) {
            require(vc.context.length == 64, "invalid trusting period context length");
            return trustingPeriodContextEval(parseTrustingPeriodContext(vc.context), currentTimestampNanos);
        } else {
            revert("unknown context type");
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
            require(false, "out of trusting period");
        } else if (currentTimestampNanos + context.clockDrift <= context.untrustedHeaderTimestamp) {
            require(false, "header is from the future");
        }
        return;
    }

    struct CommitmentProof {
        bytes commitment;
        address signer;
        bytes signature;
    }

    struct VerifyMembershipMessage {
        bytes prefix;
        bytes path;
        bytes32 value;
        Height.Data height;
        bytes32 stateId;
    }

    function parseVerifyMembershipMessage(bytes memory message)
        internal
        pure
        returns (VerifyMembershipMessage memory)
    {
        HeaderedMessage memory hm = abi.decode(message, (HeaderedMessage));
        // MSB first
        // 0-1:  version
        // 2-3:  message type
        // 4-31: reserved
        bytes32 header = bytes32(uint256(LCPCommitmentVersion) << 240 | uint256(LCPCommitmentTypeState) << 224);
        require(hm.header == header, "unexpected header");
        return abi.decode(hm.message, (VerifyMembershipMessage));
    }

    function parseVerifyMembershipCommitmentProof(bytes calldata proofBytes)
        internal
        pure
        returns (CommitmentProof memory, VerifyMembershipMessage memory)
    {
        CommitmentProof memory commitmentProof = abi.decode(proofBytes, (CommitmentProof));
        return (commitmentProof, parseVerifyMembershipMessage(commitmentProof.commitment));
    }
}
