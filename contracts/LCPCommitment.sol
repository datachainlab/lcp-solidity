// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import "@hyperledger-labs/yui-ibc-solidity/contracts/proto/Client.sol";

library LCPCommitment {
    uint16 constant LCPCommitmentVersion = 1;
    uint16 constant LCPCommitmentTypeUpdateClient = 1;
    uint16 constant LCPCommitmentTypeState = 2;
    uint16 constant LCPCommitmentContextTypeEmpty = 0;
    uint16 constant LCPCommitmentContextTypeTrustingPeriod = 1;

    struct HeaderedCommitment {
        bytes32 header;
        bytes commitment;
    }

    struct UpdateClientCommitment {
        bytes32 prevStateId;
        bytes32 newStateId;
        bytes newState;
        Height.Data prevHeight;
        Height.Data newHeight;
        uint128 timestamp;
        bytes context;
    }

    function parseUpdateClientCommitment(bytes memory commitmentBytes)
        internal
        pure
        returns (UpdateClientCommitment memory commitment)
    {
        HeaderedCommitment memory hc = abi.decode(commitmentBytes, (HeaderedCommitment));
        // MSB first
        // 0-1:  version
        // 2-3:  commitment type
        // 4-31: reserved
        bytes32 header = bytes32(uint256(LCPCommitmentVersion) << 240 | uint256(LCPCommitmentTypeUpdateClient) << 224);
        require(hc.header == header, "unexpected header");
        return abi.decode(hc.commitment, (UpdateClientCommitment));
    }

    struct HeaderedCommitmentContext {
        bytes32 header;
        bytes context;
    }

    struct TrustingPeriodContext {
        uint128 untrustedHeaderTimestamp;
        uint128 trustedStateTimestamp;
        uint128 trustingPeriod;
        uint128 clockDrift;
    }

    function parseHeaderedCommitmentContext(bytes memory context)
        internal
        pure
        returns (HeaderedCommitmentContext memory)
    {
        return abi.decode(context, (HeaderedCommitmentContext));
    }

    function extractContextType(bytes32 header) internal pure returns (uint16) {
        // MSB first
        // 0-1:  type
        // 2-31: reserved
        return uint16(uint256(header) >> 240);
    }

    function validateCommitmentContext(bytes memory context, uint256 currentTimestampNanos) internal pure {
        HeaderedCommitmentContext memory hc = parseHeaderedCommitmentContext(context);
        // MSB first
        // 0-1:  type
        // 2-31: reserved
        uint16 contextType = extractContextType(hc.header);
        if (contextType == LCPCommitmentContextTypeEmpty) {
            return;
        } else if (contextType == LCPCommitmentContextTypeTrustingPeriod) {
            require(hc.context.length == 64, "invalid trusting period context length");
            return validateTrustingPeriodContext(parseTrustingPeriodContext(hc.context), currentTimestampNanos);
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

    function validateTrustingPeriodContext(TrustingPeriodContext memory context, uint256 currentTimestampNanos)
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

    struct StateCommitment {
        bytes prefix;
        bytes path;
        bytes32 value;
        Height.Data height;
        bytes32 stateId;
    }

    function parseStateCommitment(bytes memory commitmentBytes) internal pure returns (StateCommitment memory) {
        HeaderedCommitment memory hc = abi.decode(commitmentBytes, (HeaderedCommitment));
        // MSB first
        // 0-1:  version
        // 2-3:  commitment type
        // 4-31: reserved
        bytes32 header = bytes32(uint256(LCPCommitmentVersion) << 240 | uint256(LCPCommitmentTypeState) << 224);
        require(hc.header == header, "unexpected header");
        return abi.decode(hc.commitment, (StateCommitment));
    }

    function parseStateCommitmentAndProof(bytes calldata proofBytes)
        internal
        pure
        returns (CommitmentProof memory, StateCommitment memory)
    {
        CommitmentProof memory commitmentProof = abi.decode(proofBytes, (CommitmentProof));
        return (commitmentProof, parseStateCommitment(commitmentProof.commitment));
    }
}
