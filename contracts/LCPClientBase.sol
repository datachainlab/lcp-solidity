// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {ILightClient} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/ILightClient.sol";
import {IBCHeight} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/IBCHeight.sol";
import {Height} from "@hyperledger-labs/yui-ibc-solidity/contracts/proto/Client.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {
    IbcLightclientsLcpV1ClientState as ProtoClientState,
    IbcLightclientsLcpV1ConsensusState as ProtoConsensusState,
    IbcLightclientsLcpV1UpdateClientMessage as UpdateClientMessage,
    IbcLightclientsLcpV1UpdateOperatorsMessage as UpdateOperatorsMessage
} from "./proto/ibc/lightclients/lcp/v1/LCP.sol";
import {LCPCommitment} from "./LCPCommitment.sol";
import {LCPOperator} from "./LCPOperator.sol";
import {LCPProtoMarshaler} from "./LCPProtoMarshaler.sol";
import {RemoteAttestation} from "./RemoteAttestation.sol";
import {ILCPClientErrors} from "./ILCPClientErrors.sol";

abstract contract LCPClientBase is ILightClient, ILCPClientErrors {
    using IBCHeight for Height.Data;

    // --------------------- Data structures ---------------------

    struct ConsensusState {
        bytes32 stateId;
        uint64 timestamp;
    }

    struct EKInfo {
        uint64 expiredAt;
        address operator;
    }

    struct ClientStorage {
        ProtoClientState.Data clientState;
        uint256[50] __gap0;
        RemoteAttestation.ReportAllowedStatus allowedStatuses;
        uint256[50] __gap1;
        // height => consensus state
        mapping(uint128 => ConsensusState) consensusStates;
        // enclave key => EKInfo
        mapping(address => EKInfo) ekInfos;
        bytes32 zkDCAPRisc0ImageId;
    }

    // --------------------- Immutable fields ---------------------

    /// @dev ibcHandler is the address of the IBC handler contract.
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address internal immutable ibcHandler;

    // --------------------- Storage fields ---------------------

    /// @dev clientId => client storage
    mapping(string => ClientStorage) internal clientStorages;

    // --------------------- Constructor ---------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    /// @param ibcHandler_ the address of the IBC handler contract
    constructor(address ibcHandler_) {
        ibcHandler = ibcHandler_;
    }

    // --------------------- Modifiers ---------------------

    modifier onlyIBC() {
        require(msg.sender == ibcHandler);
        _;
    }

    // --------------------- Internal methods ---------------------

    function _initializeClient(
        ClientStorage storage clientStorage,
        bytes calldata protoClientState,
        bytes calldata protoConsensusState
    ) internal returns (ProtoClientState.Data memory, ProtoConsensusState.Data memory) {
        ProtoClientState.Data memory clientState = LCPProtoMarshaler.unmarshalClientState(protoClientState);
        ProtoConsensusState.Data memory consensusState = LCPProtoMarshaler.unmarshalConsensusState(protoConsensusState);

        // validate an initial state
        if (clientState.latest_height.revision_number != 0 || clientState.latest_height.revision_height != 0) {
            revert LCPClientClientStateInvalidLatestHeight();
        }
        if (clientState.frozen) {
            revert LCPClientClientStateFrozen();
        }
        if (clientState.key_expiration == 0) {
            revert LCPClientClientStateInvalidKeyExpiration();
        }
        if (clientState.mrenclave.length != 32) {
            revert LCPClientClientStateInvalidMrenclaveLength();
        }
        if (clientState.operators_nonce != 0) {
            revert LCPClientClientStateInvalidOperatorsNonce();
        }
        if (
            clientState.operators.length != 0
                && (clientState.operators_threshold_numerator == 0 || clientState.operators_threshold_denominator == 0)
        ) {
            revert LCPClientClientStateInvalidOperatorsThreshold();
        }
        if (clientState.operators_threshold_numerator > clientState.operators_threshold_denominator) {
            revert LCPClientClientStateInvalidOperatorsThreshold();
        }
        if (consensusState.timestamp != 0) {
            revert LCPClientConsensusStateInvalidTimestamp();
        }
        if (consensusState.state_id.length != 0) {
            revert LCPClientConsensusStateInvalidStateId();
        }

        // ensure the operators are sorted(ascending order) and unique
        address prev;
        for (uint256 i = 0; i < clientState.operators.length; i++) {
            if (clientState.operators[i].length != 20) {
                revert LCPClientClientStateInvalidOperatorAddressLength();
            }
            address addr = address(bytes20(clientState.operators[i]));
            if (addr == address(0)) {
                revert LCPClientClientStateInvalidOperatorAddress();
            }
            if (prev != address(0)) {
                if (prev >= addr) {
                    revert LCPClientOperatorsInvalidOrder(prev, addr);
                }
            }
            prev = addr;
        }
        clientStorage.clientState = clientState;

        // set allowed quote status and advisories
        for (uint256 i = 0; i < clientState.allowed_quote_statuses.length; i++) {
            string memory allowedQuoteStatus = clientState.allowed_quote_statuses[i];
            if (bytes(allowedQuoteStatus).length == 0) {
                revert LCPClientClientStateInvalidAllowedQuoteStatus();
            }
            clientStorage.allowedStatuses.allowedQuoteStatuses[allowedQuoteStatus] = RemoteAttestation.FLAG_ALLOWED;
        }
        for (uint256 i = 0; i < clientState.allowed_advisory_ids.length; i++) {
            string memory allowedAdvisoryId = clientState.allowed_advisory_ids[i];
            if (bytes(allowedAdvisoryId).length == 0) {
                revert LCPClientClientStateInvalidAllowedAdvisoryId();
            }
            clientStorage.allowedStatuses.allowedAdvisories[allowedAdvisoryId] = RemoteAttestation.FLAG_ALLOWED;
        }
        return (clientState, consensusState);
    }

    // --------------------- Public methods ---------------------

    /**
     * @dev getTimestampAtHeight returns the timestamp of the consensus state at the given height.
     */
    function getTimestampAtHeight(string calldata clientId, Height.Data calldata height)
        public
        view
        override
        returns (uint64)
    {
        ConsensusState storage consensusState = clientStorages[clientId].consensusStates[height.toUint128()];
        if (consensusState.timestamp == 0) {
            revert LCPClientConsensusStateNotFound();
        }
        return consensusState.timestamp;
    }

    /**
     * @dev getLatestHeight returns the latest height of the client state corresponding to `clientId`.
     */
    function getLatestHeight(string calldata clientId) public view override returns (Height.Data memory) {
        ProtoClientState.Data storage clientState = clientStorages[clientId].clientState;
        if (clientState.latest_height.revision_height == 0) {
            revert LCPClientClientStateNotFound();
        }
        return clientState.latest_height;
    }

    /**
     * @dev getStatus returns the status of the client corresponding to `clientId`.
     */
    function getStatus(string calldata clientId) public view override returns (ClientStatus) {
        return clientStorages[clientId].clientState.frozen ? ClientStatus.Frozen : ClientStatus.Active;
    }

    /**
     * @dev getLatestInfo returns the latest height, the latest timestamp, and the status of the client corresponding to `clientId`.
     */
    function getLatestInfo(string calldata clientId)
        public
        view
        override
        returns (Height.Data memory latestHeight, uint64 latestTimestamp, ClientStatus status)
    {
        ClientStorage storage clientStorage = clientStorages[clientId];
        latestHeight = clientStorage.clientState.latest_height;
        latestTimestamp = clientStorage.consensusStates[latestHeight.toUint128()].timestamp;
        status = clientStorage.clientState.frozen ? ClientStatus.Frozen : ClientStatus.Active;
    }

    /**
     * @dev updateClient updates the client state and the consensus state of the client corresponding to `clientId`.
     */
    function updateClient(string calldata clientId, UpdateClientMessage.Data calldata message)
        public
        returns (Height.Data[] memory heights)
    {
        ClientStorage storage clientStorage = clientStorages[clientId];
        verifySignatures(clientStorage, keccak256(message.proxy_message), message.signatures);

        LCPCommitment.HeaderedProxyMessage memory hm =
            abi.decode(message.proxy_message, (LCPCommitment.HeaderedProxyMessage));
        if (hm.header == LCPCommitment.LCP_MESSAGE_HEADER_UPDATE_STATE) {
            return updateState(clientStorage, abi.decode(hm.message, (LCPCommitment.UpdateStateProxyMessage)));
        } else if (hm.header == LCPCommitment.LCP_MESSAGE_HEADER_MISBEHAVIOUR) {
            return submitMisbehaviour(clientStorage, abi.decode(hm.message, (LCPCommitment.MisbehaviourProxyMessage)));
        } else {
            revert LCPClientUnknownProxyMessageHeader();
        }
    }

    /**
     * @dev verifyMembership is a generic proof verification method which verifies a proof of the existence of a value at a given CommitmentPath at the specified height.
     * The caller is expected to construct the full CommitmentPath from a CommitmentPrefix and a standardized path (as defined in ICS 24).
     */
    function verifyMembership(
        string calldata clientId,
        Height.Data calldata height,
        uint64,
        uint64,
        bytes calldata proof,
        bytes memory prefix,
        bytes memory path,
        bytes calldata value
    ) public view returns (bool) {
        (
            LCPCommitment.CommitmentProofs memory commitmentProofs,
            LCPCommitment.VerifyMembershipProxyMessage memory message
        ) = LCPCommitment.parseVerifyMembershipCommitmentProofs(proof);
        ClientStorage storage clientStorage = clientStorages[clientId];
        validateProxyMessage(clientStorage, message, height, prefix, path);
        if (keccak256(value) != message.value) {
            revert LCPClientMembershipVerificationInvalidValue();
        }
        verifyCommitmentProofs(clientStorage, commitmentProofs);
        return true;
    }

    /**
     * @dev verifyNonMembership is a generic proof verification method which verifies the absence of a given CommitmentPath at a specified height.
     * The caller is expected to construct the full CommitmentPath from a CommitmentPrefix and a standardized path (as defined in ICS 24).
     */
    function verifyNonMembership(
        string calldata clientId,
        Height.Data calldata height,
        uint64,
        uint64,
        bytes calldata proof,
        bytes calldata prefix,
        bytes calldata path
    ) public view returns (bool) {
        (
            LCPCommitment.CommitmentProofs memory commitmentProofs,
            LCPCommitment.VerifyMembershipProxyMessage memory message
        ) = LCPCommitment.parseVerifyMembershipCommitmentProofs(proof);
        ClientStorage storage clientStorage = clientStorages[clientId];
        validateProxyMessage(clientStorage, message, height, prefix, path);
        if (message.value != bytes32(0)) {
            revert LCPClientMembershipVerificationInvalidValue();
        }
        verifyCommitmentProofs(clientStorage, commitmentProofs);
        return true;
    }

    /**
     * @dev getClientState returns the clientState corresponding to `clientId`.
     *      If it's not found, the function returns false.
     */
    function getClientState(string calldata clientId) public view returns (bytes memory clientStateBytes, bool) {
        ProtoClientState.Data storage clientState = clientStorages[clientId].clientState;
        if (clientState.mrenclave.length == 0) {
            return (clientStateBytes, false);
        }
        return (LCPProtoMarshaler.marshal(clientState), true);
    }

    /**
     * @dev getConsensusState returns the consensusState corresponding to `clientId` and `height`.
     *      If it's not found, the function returns false.
     */
    function getConsensusState(string calldata clientId, Height.Data calldata height)
        public
        view
        returns (bytes memory consensusStateBytes, bool)
    {
        ConsensusState storage consensusState = clientStorages[clientId].consensusStates[height.toUint128()];
        if (consensusState.timestamp == 0 && consensusState.stateId == bytes32(0)) {
            return (consensusStateBytes, false);
        }
        return (LCPProtoMarshaler.marshalConsensusState(consensusState.stateId, consensusState.timestamp), true);
    }

    // --------------------- Internal methods ---------------------

    function updateState(ClientStorage storage clientStorage, LCPCommitment.UpdateStateProxyMessage memory pmsg)
        internal
        returns (Height.Data[] memory heights)
    {
        ConsensusState storage consensusState;
        ProtoClientState.Data storage clientState = clientStorage.clientState;
        if (clientState.frozen) {
            revert LCPClientClientStateFrozen();
        }

        if (clientState.latest_height.revision_number == 0 && clientState.latest_height.revision_height == 0) {
            if (pmsg.emittedStates.length == 0) {
                revert LCPClientUpdateStateEmittedStatesMustNotEmpty();
            }
        } else {
            consensusState = clientStorage.consensusStates[pmsg.prevHeight.toUint128()];
            if (pmsg.prevStateId == bytes32(0)) {
                revert LCPClientUpdateStatePrevStateIdMustNotEmpty();
            }
            if (consensusState.stateId != pmsg.prevStateId) {
                revert LCPClientUpdateStateUnexpectedPrevStateId();
            }
        }

        LCPCommitment.validationContextEval(pmsg.context, block.timestamp * 1e9);

        uint128 postHeight = pmsg.postHeight.toUint128();
        consensusState = clientStorage.consensusStates[postHeight];
        if (consensusState.stateId != bytes32(0)) {
            if (consensusState.stateId != pmsg.postStateId || consensusState.timestamp != uint64(pmsg.timestamp)) {
                revert LCPClientUpdateStateInconsistentConsensusState();
            }
            // return empty heights if the consensus state is already stored
            return heights;
        }
        consensusState.stateId = pmsg.postStateId;
        consensusState.timestamp = uint64(pmsg.timestamp);

        uint128 latestHeight = clientState.latest_height.toUint128();
        if (latestHeight < postHeight) {
            clientState.latest_height = pmsg.postHeight;
        }
        heights = new Height.Data[](1);
        heights[0] = pmsg.postHeight;
        return heights;
    }

    function submitMisbehaviour(ClientStorage storage clientStorage, LCPCommitment.MisbehaviourProxyMessage memory pmsg)
        internal
        returns (Height.Data[] memory heights)
    {
        ProtoClientState.Data storage clientState = clientStorage.clientState;
        if (clientState.frozen) {
            revert LCPClientClientStateFrozen();
        }
        uint256 prevStatesNum = pmsg.prevStates.length;
        if (prevStatesNum == 0) {
            revert LCPClientMisbehaviourPrevStatesMustNotEmpty();
        }

        for (uint256 i = 0; i < prevStatesNum; i++) {
            LCPCommitment.PrevState memory prev = pmsg.prevStates[i];
            uint128 prevHeight = prev.height.toUint128();
            if (prev.stateId == bytes32(0)) {
                revert LCPClientUpdateStatePrevStateIdMustNotEmpty();
            }
            if (clientStorage.consensusStates[prevHeight].stateId != prev.stateId) {
                revert LCPClientUpdateStateUnexpectedPrevStateId();
            }
        }

        LCPCommitment.validationContextEval(pmsg.context, block.timestamp * 1e9);

        clientStorage.clientState.frozen = true;
        return heights;
    }

    function updateOperators(string calldata clientId, UpdateOperatorsMessage.Data calldata message)
        public
        returns (Height.Data[] memory heights)
    {
        ProtoClientState.Data storage clientState = clientStorages[clientId].clientState;
        uint256 opNum = clientState.operators.length;
        uint256 sigNum = message.signatures.length;
        if (opNum == 0) {
            revert LCPClientUpdateOperatorsPermissionless();
        }
        if (sigNum != opNum) {
            revert LCPClientInvalidSignaturesLength();
        }
        if (message.new_operators_threshold_numerator == 0 || message.new_operators_threshold_denominator == 0) {
            revert LCPClientClientStateInvalidOperatorsThreshold();
        }
        uint64 nonce = clientState.operators_nonce;
        uint64 nextNonce = nonce + 1;
        if (message.nonce != nextNonce) {
            revert LCPClientClientStateUnexpectedOperatorsNonce(nextNonce);
        }
        address[] memory newOperators = new address[](message.new_operators.length);
        for (uint256 i = 0; i < message.new_operators.length; i++) {
            if (message.new_operators[i].length != 20) {
                revert LCPClientClientStateInvalidOperatorAddressLength();
            }
            newOperators[i] = address(bytes20(message.new_operators[i]));
        }
        bytes32 commitment = keccak256(
            LCPOperator.computeEIP712UpdateOperators(
                clientId,
                nextNonce,
                newOperators,
                message.new_operators_threshold_numerator,
                message.new_operators_threshold_denominator
            )
        );
        uint256 success = 0;
        for (uint256 i = 0; i < sigNum; i++) {
            if (message.signatures[i].length > 0) {
                address operator = verifyECDSASignature(commitment, message.signatures[i]);
                if (operator != address(bytes20(clientState.operators[i]))) {
                    revert LCPClientUpdateOperatorsSignatureUnexpectedOperator(
                        operator, address(bytes20(clientState.operators[i]))
                    );
                }
                unchecked {
                    success++;
                }
            }
        }
        ensureSufficientValidSignatures(clientState, success);
        delete clientState.operators;
        // ensure the new operators are sorted(ascending order) and unique
        for (uint256 i = 0; i < newOperators.length; i++) {
            if (i > 0) {
                unchecked {
                    address prev = newOperators[i - 1];
                    if (prev >= newOperators[i]) {
                        revert LCPClientOperatorsInvalidOrder(prev, newOperators[i]);
                    }
                }
            }
            clientState.operators.push(message.new_operators[i]);
        }
        clientState.operators_nonce = nextNonce;
        clientState.operators_threshold_numerator = message.new_operators_threshold_numerator;
        clientState.operators_threshold_denominator = message.new_operators_threshold_denominator;
        return heights;
    }

    function ensureActiveKey(ClientStorage storage clientStorage, address ekAddr, address opAddr) internal view {
        EKInfo storage ekInfo = clientStorage.ekInfos[ekAddr];
        uint256 expiredAt = ekInfo.expiredAt;
        if (expiredAt == 0) {
            revert LCPClientEnclaveKeyNotExist();
        }
        if (expiredAt <= block.timestamp) {
            revert LCPClientEnclaveKeyExpired();
        }
        if (ekInfo.operator != opAddr) {
            revert LCPClientEnclaveKeyUnexpectedOperator(ekInfo.operator, opAddr);
        }
    }

    function ensureActiveKey(ClientStorage storage clientStorage, address ekAddr) internal view {
        EKInfo storage ekInfo = clientStorage.ekInfos[ekAddr];
        uint256 expiredAt = ekInfo.expiredAt;
        if (expiredAt == 0) {
            revert LCPClientEnclaveKeyNotExist();
        }
        if (expiredAt <= block.timestamp) {
            revert LCPClientEnclaveKeyExpired();
        }
    }

    function ensureSufficientValidSignatures(ProtoClientState.Data storage clientState, uint256 success)
        internal
        view
    {
        if (
            success * clientState.operators_threshold_denominator
                < clientState.operators_threshold_numerator * clientState.operators.length
        ) {
            revert LCPClientOperatorSignaturesInsufficient(success);
        }
    }

    function verifyECDSASignature(bytes32 commitment, bytes memory signature) internal pure returns (address) {
        if (uint8(signature[64]) < 27) {
            signature[64] = bytes1(uint8(signature[64]) + 27);
        }
        return ECDSA.recover(commitment, signature);
    }

    function validateProxyMessage(
        ClientStorage storage clientStorage,
        LCPCommitment.VerifyMembershipProxyMessage memory message,
        Height.Data calldata height,
        bytes memory prefix,
        bytes memory path
    ) internal view {
        uint128 messageHeight = message.height.toUint128();
        uint128 heightValue = height.toUint128();
        ConsensusState storage consensusState = clientStorage.consensusStates[messageHeight];
        if (consensusState.stateId == bytes32(0)) {
            revert LCPClientConsensusStateNotFound();
        }
        if (heightValue != messageHeight) {
            revert LCPClientMembershipVerificationInvalidHeight();
        }
        if (keccak256(prefix) != keccak256(message.prefix)) {
            revert LCPClientMembershipVerificationInvalidPrefix();
        }
        if (keccak256(path) != keccak256(message.path)) {
            revert LCPClientMembershipVerificationInvalidPath();
        }
        if (consensusState.stateId != message.stateId) {
            revert LCPClientMembershipVerificationInvalidStateId();
        }
    }

    function verifyCommitmentProofs(
        ClientStorage storage clientStorage,
        LCPCommitment.CommitmentProofs memory commitmentProofs
    ) internal view {
        bytes32 commitment = keccak256(commitmentProofs.message);
        verifySignatures(clientStorage, commitment, commitmentProofs.signatures);
    }

    function verifySignatures(ClientStorage storage clientStorage, bytes32 commitment, bytes[] memory signatures)
        internal
        view
    {
        uint256 sigNum = signatures.length;
        uint256 opNum = clientStorage.clientState.operators.length;
        if (opNum == 0) {
            if (sigNum != 1) {
                revert LCPClientInvalidSignaturesLength();
            }
            ensureActiveKey(clientStorage, verifyECDSASignature(commitment, signatures[0]));
        } else {
            if (sigNum != opNum) {
                revert LCPClientInvalidSignaturesLength();
            }
            uint256 success = 0;
            for (uint256 i = 0; i < sigNum; i++) {
                bytes memory sig = signatures[i];
                if (sig.length != 0) {
                    ensureActiveKey(
                        clientStorage,
                        verifyECDSASignature(commitment, sig),
                        address(bytes20(clientStorage.clientState.operators[i]))
                    );
                    unchecked {
                        success++;
                    }
                }
            }
            ensureSufficientValidSignatures(clientStorage.clientState, success);
        }
    }
}
