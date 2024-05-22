// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {ILightClient} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/ILightClient.sol";
import {IBCHeight} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/IBCHeight.sol";
import {Height} from "@hyperledger-labs/yui-ibc-solidity/contracts/proto/Client.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {
    IbcLightclientsLcpV1ClientState as ProtoClientState,
    IbcLightclientsLcpV1ConsensusState as ProtoConsensusState,
    IbcLightclientsLcpV1RegisterEnclaveKeyMessage as RegisterEnclaveKeyMessage,
    IbcLightclientsLcpV1UpdateClientMessage as UpdateClientMessage,
    IbcLightclientsLcpV1UpdateOperatorsMessage as UpdateOperatorsMessage
} from "./proto/ibc/lightclients/lcp/v1/LCP.sol";
import {LCPCommitment} from "./LCPCommitment.sol";
import {LCPProtoMarshaler} from "./LCPProtoMarshaler.sol";
import {AVRValidator} from "./AVRValidator.sol";
import {ILCPClientErrors} from "./ILCPClientErrors.sol";

abstract contract LCPClientBase is ILightClient, ILCPClientErrors {
    using IBCHeight for Height.Data;

    struct ConsensusState {
        bytes32 stateId;
        uint64 timestamp;
    }

    struct EKOperatorInfo {
        uint256 expiredAt;
        address key;
    }

    event RegisteredEnclaveKey(string clientId, address enclaveKey, uint256 expiredAt);

    address internal immutable ibcHandler;
    // if developmentMode is true, the client allows the remote attestation of IAS in development.
    bool internal immutable developmentMode;

    mapping(string => ProtoClientState.Data) internal clientStates;
    mapping(string => mapping(uint128 => ConsensusState)) internal consensusStates;

    // rootCA's public key parameters
    AVRValidator.RSAParams public verifiedRootCAParams;
    // keccak256(signingCert) => RSAParams of signing public key
    mapping(bytes32 => AVRValidator.RSAParams) public verifiedSigningRSAParams;

    // clientId => enclave key => EKOperatorInfo
    mapping(string => mapping(address => EKOperatorInfo)) internal enclaveKeys;
    // clientId => nonce => operators
    mapping(string => mapping(uint256 => address[])) internal operators;
    // clientId => operator => nonce(revision)
    mapping(string => mapping(address => uint256)) internal activeOperators;

    // clientId => quote status => flag(0: not allowed, 1: allowed)
    mapping(string => mapping(string => uint256)) internal allowedQuoteStatuses;
    // clientId => advisory id => flag(0: not allowed, 1: allowed)
    mapping(string => mapping(string => uint256)) internal allowedAdvisories;

    modifier onlyIBC() {
        require(msg.sender == ibcHandler);
        _;
    }

    constructor(address ibcHandler_, bool developmentMode_) {
        ibcHandler = ibcHandler_;
        developmentMode = developmentMode_;
    }

    /// @dev isDevelopmentMode returns true if the client allows the remote attestation of IAS in development.
    function isDevelopmentMode() public view returns (bool) {
        return developmentMode;
    }

    /// @dev initializeRootCACert initializes the root CA's public key parameters.
    /// All contracts that inherit LCPClientBase should call this in the constructor or initializer.
    function initializeRootCACert(bytes memory rootCACert) internal {
        if (verifiedRootCAParams.notAfter != 0) {
            revert LCPClientRootCACertAlreadyInitialized();
        }
        verifiedRootCAParams = AVRValidator.verifyRootCACert(rootCACert);
    }

    /**
     * @dev initializeClient initializes a new client with the given state.
     *      If succeeded, it returns heights at which the consensus state are stored.
     *      The function must be only called by IBCHandler.
     */
    function initializeClient(
        string calldata clientId,
        bytes calldata protoClientState,
        bytes calldata protoConsensusState
    ) public onlyIBC returns (Height.Data memory height) {
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
        if (clientState.operators.length == 0) {
            revert LCPClientClientStateEmptyOperators();
        }
        if (clientState.operators_nonce == 0) {
            revert LCPClientClientStateInvalidOperatorsNonce();
        }
        if (
            clientState.operators_threshold_numerator == 0 || clientState.operators_threshold_denominator == 0
                || clientState.operators_threshold_numerator > clientState.operators_threshold_denominator
        ) {
            revert LCPClientClientStateInvalidOperatorsThreshold();
        }
        if (consensusState.timestamp != 0) {
            revert LCPClientConsensusStateInvalidTimestamp();
        }
        if (consensusState.state_id.length != 0) {
            revert LCPClientConsensusStateInvalidStateId();
        }

        for (uint256 i = 0; i < clientState.operators.length; i++) {
            address operator = address(bytes20(clientState.operators[i]));
            if (activeOperators[clientId][operator] == clientState.operators_nonce) {
                revert LCPClientOperatorDuplicate(operator, clientState.operators_nonce);
            }
            activeOperators[clientId][operator] = clientState.operators_nonce;
            operators[clientId][clientState.operators_nonce].push(operator);
        }

        clientStates[clientId] = clientState;

        // set allowed quote status and advisories
        for (uint256 i = 0; i < clientState.allowed_quote_statuses.length; i++) {
            allowedQuoteStatuses[clientId][clientState.allowed_quote_statuses[i]] = AVRValidator.FLAG_ALLOWED;
        }
        for (uint256 i = 0; i < clientState.allowed_advisory_ids.length; i++) {
            allowedAdvisories[clientId][clientState.allowed_advisory_ids[i]] = AVRValidator.FLAG_ALLOWED;
        }

        return clientState.latest_height;
    }

    /**
     * @dev getTimestampAtHeight returns the timestamp of the consensus state at the given height.
     */
    function getTimestampAtHeight(string calldata clientId, Height.Data calldata height) public view returns (uint64) {
        ConsensusState storage consensusState = consensusStates[clientId][height.toUint128()];
        if (consensusState.timestamp == 0) {
            revert LCPClientConsensusStateNotFound();
        }
        return consensusState.timestamp;
    }

    /**
     * @dev getLatestHeight returns the latest height of the client state corresponding to `clientId`.
     */
    function getLatestHeight(string calldata clientId) public view returns (Height.Data memory) {
        ProtoClientState.Data storage clientState = clientStates[clientId];
        if (clientState.latest_height.revision_height == 0) {
            revert LCPClientClientStateNotFound();
        }
        return clientState.latest_height;
    }
    /**
     * @dev getStatus returns the status of the client corresponding to `clientId`.
     */

    function getStatus(string calldata clientId) public view returns (ClientStatus) {
        return clientStates[clientId].frozen ? ClientStatus.Frozen : ClientStatus.Active;
    }

    /**
     * @dev getLatestInfo returns the latest height, the latest timestamp, and the status of the client corresponding to `clientId`.
     */
    function getLatestInfo(string calldata clientId)
        public
        view
        returns (Height.Data memory latestHeight, uint64 latestTimestamp, ClientStatus status)
    {
        latestHeight = clientStates[clientId].latest_height;
        latestTimestamp = consensusStates[clientId][latestHeight.toUint128()].timestamp;
        status = clientStates[clientId].frozen ? ClientStatus.Frozen : ClientStatus.Active;
    }

    /**
     * @dev routeUpdateClient returns the calldata to the receiving function of the client message.
     *      Light client contract may encode a client message as other encoding scheme(e.g. ethereum ABI)
     *      Check ADR-001 for details.
     */
    function routeUpdateClient(string calldata clientId, bytes calldata protoClientMessage)
        public
        pure
        returns (bytes4, bytes memory)
    {
        (bytes32 typeUrlHash, bytes memory args) = LCPProtoMarshaler.routeClientMessage(clientId, protoClientMessage);
        if (typeUrlHash == LCPProtoMarshaler.UPDATE_CLIENT_MESSAGE_TYPE_URL_HASH) {
            return (this.updateClient.selector, args);
        } else if (typeUrlHash == LCPProtoMarshaler.REGISTER_ENCLAVE_KEY_MESSAGE_TYPE_URL_HASH) {
            return (this.registerEnclaveKey.selector, args);
        } else if (typeUrlHash == LCPProtoMarshaler.UPDATE_OPERATORS_MESSAGE_TYPE_URL_HASH) {
            return (this.updateOperators.selector, args);
        } else {
            revert LCPClientUnknownProtoTypeUrl();
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
            LCPCommitment.CommitmentProof memory commitmentProof,
            LCPCommitment.VerifyMembershipProxyMessage memory message
        ) = LCPCommitment.parseVerifyMembershipCommitmentProof(proof);
        verifyProxyMessage(clientId, message, height, prefix, path);
        if (keccak256(value) != message.value) {
            revert LCPClientMembershipVerificationInvalidValue();
        }
        verifyCommitmentProof(clientId, commitmentProof);
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
            LCPCommitment.CommitmentProof memory commitmentProof,
            LCPCommitment.VerifyMembershipProxyMessage memory message
        ) = LCPCommitment.parseVerifyMembershipCommitmentProof(proof);
        verifyProxyMessage(clientId, message, height, prefix, path);
        if (message.value != bytes32(0)) {
            revert LCPClientMembershipVerificationInvalidValue();
        }
        verifyCommitmentProof(clientId, commitmentProof);
        return true;
    }

    function verifyProxyMessage(
        string calldata clientId,
        LCPCommitment.VerifyMembershipProxyMessage memory message,
        Height.Data calldata height,
        bytes memory prefix,
        bytes memory path
    ) internal view {
        ConsensusState storage consensusState = consensusStates[clientId][message.height.toUint128()];
        if (consensusState.stateId == bytes32(0)) {
            revert LCPClientConsensusStateNotFound();
        }
        if (!height.eq(message.height)) {
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

    function verifyCommitmentProof(string calldata clientId, LCPCommitment.CommitmentProof memory commitmentProof)
        internal
        view
    {
        ProtoClientState.Data storage clientState = clientStates[clientId];
        address[] storage operators_ = operators[clientId][clientState.operators_nonce];
        require(commitmentProof.signers.length == commitmentProof.signatures.length);
        require(commitmentProof.signers.length == operators_.length);
        bytes32 commitment = keccak256(commitmentProof.message);
        uint256 success = 0;
        for (uint256 i = 0; i < commitmentProof.signatures.length; i++) {
            address ekAddr = commitmentProof.signers[i];
            if (ekAddr != address(0) && verifySignature(commitment, commitmentProof.signatures[i], ekAddr)) {
                ensureActiveKey(clientId, ekAddr, operators_[i]);
                unchecked {
                    success++;
                }
            }
        }
        if (
            success * clientState.operators_threshold_denominator
                < clientState.operators_threshold_numerator * operators_.length
        ) {
            revert LCPClientOperatorSignaturesInsufficient(success);
        }
    }

    /**
     * @dev getClientState returns the clientState corresponding to `clientId`.
     *      If it's not found, the function returns false.
     */
    function getClientState(string calldata clientId) public view returns (bytes memory clientStateBytes, bool) {
        ProtoClientState.Data storage clientState = clientStates[clientId];
        if (clientState.latest_height.revision_height == 0) {
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
        ConsensusState storage consensusState = consensusStates[clientId][height.toUint128()];
        if (consensusState.timestamp == 0 && consensusState.stateId == bytes32(0)) {
            return (consensusStateBytes, false);
        }
        return (LCPProtoMarshaler.marshalConsensusState(consensusState.stateId, consensusState.timestamp), true);
    }

    function updateClient(string calldata clientId, UpdateClientMessage.Data calldata message)
        public
        returns (Height.Data[] memory heights)
    {
        address[] storage operators_ = operators[clientId][clientStates[clientId].operators_nonce];
        require(message.signers.length == operators_.length);
        require(message.signers.length == message.signatures.length);
        bytes32 commitment = keccak256(message.proxy_message);
        uint256 success = 0;
        for (uint256 i = 0; i < message.signers.length; i++) {
            address ekAddr = address(bytes20(message.signers[i]));
            if (ekAddr != address(0) && verifySignature(commitment, message.signatures[i], ekAddr)) {
                ensureActiveKey(clientId, ekAddr, operators_[i]);
                unchecked {
                    success++;
                }
            }
        }
        ProtoClientState.Data storage clientState = clientStates[clientId];
        if (
            success * clientState.operators_threshold_denominator
                < clientState.operators_threshold_numerator * operators_.length
        ) {
            revert LCPClientOperatorSignaturesInsufficient(success);
        }
        LCPCommitment.HeaderedProxyMessage memory hm =
            abi.decode(message.proxy_message, (LCPCommitment.HeaderedProxyMessage));
        if (hm.header == LCPCommitment.LCP_MESSAGE_HEADER_UPDATE_STATE) {
            return updateState(clientId, clientState, abi.decode(hm.message, (LCPCommitment.UpdateStateProxyMessage)));
        } else if (hm.header == LCPCommitment.LCP_MESSAGE_HEADER_MISBEHAVIOUR) {
            return submitMisbehaviour(
                clientId, clientState, abi.decode(hm.message, (LCPCommitment.MisbehaviourProxyMessage))
            );
        } else {
            revert LCPClientUnknownProxyMessageHeader();
        }
    }

    function updateState(
        string calldata clientId,
        ProtoClientState.Data storage clientState,
        LCPCommitment.UpdateStateProxyMessage memory pmsg
    ) internal returns (Height.Data[] memory heights) {
        ConsensusState storage consensusState;

        if (clientState.frozen) {
            revert LCPClientClientStateFrozen();
        }

        if (clientState.latest_height.revision_number == 0 && clientState.latest_height.revision_height == 0) {
            if (pmsg.emittedStates.length == 0) {
                revert LCPClientUpdateStateEmittedStatesMustNotEmpty();
            }
        } else {
            consensusState = consensusStates[clientId][pmsg.prevHeight.toUint128()];
            if (pmsg.prevStateId == bytes32(0)) {
                revert LCPClientUpdateStatePrevStateIdMustNotEmpty();
            }
            if (consensusState.stateId != pmsg.prevStateId) {
                revert LCPClientUpdateStateUnexpectedPrevStateId();
            }
        }

        LCPCommitment.validationContextEval(pmsg.context, block.timestamp * 1e9);

        if (clientState.latest_height.lt(pmsg.postHeight)) {
            clientState.latest_height = pmsg.postHeight;
        }

        consensusState = consensusStates[clientId][pmsg.postHeight.toUint128()];
        consensusState.stateId = pmsg.postStateId;
        consensusState.timestamp = uint64(pmsg.timestamp);

        heights = new Height.Data[](1);
        heights[0] = pmsg.postHeight;
        return heights;
    }

    function submitMisbehaviour(
        string calldata clientId,
        ProtoClientState.Data storage clientState,
        LCPCommitment.MisbehaviourProxyMessage memory pmsg
    ) internal returns (Height.Data[] memory heights) {
        if (clientState.frozen) {
            revert LCPClientClientStateFrozen();
        }
        if (pmsg.prevStates.length == 0) {
            revert LCPClientMisbehaviourPrevStatesMustNotEmpty();
        }

        for (uint256 i = 0; i < pmsg.prevStates.length; i++) {
            ConsensusState storage consensusState = consensusStates[clientId][pmsg.prevStates[i].height.toUint128()];
            if (pmsg.prevStates[i].stateId == bytes32(0)) {
                revert LCPClientUpdateStatePrevStateIdMustNotEmpty();
            }
            if (consensusState.stateId != pmsg.prevStates[i].stateId) {
                revert LCPClientUpdateStateUnexpectedPrevStateId();
            }
        }

        LCPCommitment.validationContextEval(pmsg.context, block.timestamp * 1e9);

        clientState.frozen = true;
        return heights;
    }

    function registerEnclaveKey(string calldata clientId, RegisterEnclaveKeyMessage.Data calldata message)
        public
        returns (Height.Data[] memory heights)
    {
        {
            AVRValidator.RSAParams storage params = verifiedSigningRSAParams[keccak256(message.signing_cert)];
            if (params.notAfter == 0) {
                if (verifiedRootCAParams.notAfter <= block.timestamp) {
                    revert LCPClientIASRootCertExpired();
                }
                AVRValidator.RSAParams memory p = AVRValidator.verifySigningCert(
                    verifiedRootCAParams.modulus, verifiedRootCAParams.exponent, message.signing_cert
                );
                params.modulus = p.modulus;
                params.exponent = p.exponent;
                // NOTE: notAfter is the minimum of rootCACert and signingCert
                if (verifiedRootCAParams.notAfter > p.notAfter) {
                    params.notAfter = p.notAfter;
                } else {
                    params.notAfter = verifiedRootCAParams.notAfter;
                }
            } else if (params.notAfter <= block.timestamp) {
                revert LCPClientIASCertExpired();
            }
            if (
                !AVRValidator.verifySignature(
                    sha256(bytes(message.report)), message.signature, params.exponent, params.modulus
                )
            ) {
                revert LCPClientAVRInvalidSignature();
            }
        }

        ProtoClientState.Data storage clientState = clientStates[clientId];
        (address enclaveKey, uint256 attestationTime, bytes32 mrenclave) = AVRValidator.validateAndExtractElements(
            developmentMode, bytes(message.report), allowedQuoteStatuses[clientId], allowedAdvisories[clientId]
        );
        if (bytes32(clientState.mrenclave) != mrenclave) {
            revert LCPClientClientStateUnexpectedMrenclave();
        }

        uint256 expiredAt = attestationTime + clientState.key_expiration;
        if (expiredAt <= block.timestamp) {
            revert LCPClientAVRAlreadyExpired();
        }

        address operator = verifySignature(keccak256(abi.encodePacked(message.report)), message.operator_signature);
        require(clientState.operators_nonce == activeOperators[clientId][operator]);

        if (enclaveKeys[clientId][enclaveKey].expiredAt != 0) {
            if (enclaveKeys[clientId][enclaveKey].key != operator) {
                revert LCPClientEnclaveKeyUnexpectedOperator();
            }
            if (enclaveKeys[clientId][enclaveKey].expiredAt != expiredAt) {
                revert LCPClientEnclaveKeyUnexpectedExpiredAt();
            }
            // NOTE: if the key already exists, don't update any state
            return heights;
        }

        enclaveKeys[clientId][enclaveKey].key = operator;
        enclaveKeys[clientId][enclaveKey].expiredAt = expiredAt;
        emit RegisteredEnclaveKey(clientId, enclaveKey, expiredAt);

        // Note: client and consensus state are not always updated in registerEnclaveKey
        return heights;
    }

    function updateOperators(string calldata clientId, UpdateOperatorsMessage.Data calldata message)
        public
        returns (Height.Data[] memory heights)
    {
        address[] storage operators_ = operators[clientId][clientStates[clientId].operators_nonce];
        require(message.signatures.length == operators_.length);
        ProtoClientState.Data storage clientState = clientStates[clientId];
        uint64 nonce = clientState.operators_nonce;
        uint64 nextNonce = nonce + 1;
        bytes32 commitment =
            computeUpdateOperatorsCommitment(clientId, nextNonce, computeOperatorsHash(message.new_operators));
        uint256 success = 0;
        for (uint256 i = 0; i < message.signatures.length; i++) {
            if (verifySignature(commitment, message.signatures[i], operators_[i])) {
                unchecked {
                    success++;
                }
            }
        }
        if (
            success * clientState.operators_threshold_denominator
                < clientState.operators_threshold_numerator * operators_.length
        ) {
            revert LCPClientOperatorSignaturesInsufficient(success);
        }
        delete operators[clientId][nonce];
        delete clientState.operators;
        for (uint256 i = 0; i < message.new_operators.length; i++) {
            address opAddr = address(bytes20(message.new_operators[i]));
            activeOperators[clientId][opAddr] = nextNonce;
            operators[clientId][nextNonce].push(opAddr);
            clientState.operators.push(message.new_operators[i]);
        }
        clientState.operators_nonce = nextNonce;
        return heights;
    }

    function computeUpdateOperatorsCommitment(string memory clientId, uint256 nonce, bytes32 operatorsHash)
        internal
        view
        returns (bytes32)
    {
        bytes32 envHash = keccak256(abi.encodePacked(uint16(1), uint16(1), block.chainid, address(this)));
        return keccak256(abi.encodePacked(envHash, clientId, nonce, operatorsHash));
    }

    function computeOperatorsHash(bytes[] calldata _validators) internal pure returns (bytes32) {
        return keccak256(abi.encode(_validators));
    }

    function ensureActiveKey(string calldata clientId, address ekAddr, address opAddr) internal view {
        uint256 expiredAt = enclaveKeys[clientId][ekAddr].expiredAt;
        if (expiredAt == 0) {
            revert LCPClientEnclaveKeyNotExist();
        }
        if (expiredAt <= block.timestamp) {
            revert LCPClientEnclaveKeyExpired();
        }
        if (enclaveKeys[clientId][ekAddr].key != opAddr) {
            revert LCPClientEnclaveKeyUnexpectedOperator();
        }
    }

    function verifySignature(bytes32 commitment, bytes memory signature, address signer) internal pure returns (bool) {
        return verifySignature(commitment, signature) == signer;
    }

    function verifySignature(bytes32 commitment, bytes memory signature) internal pure returns (address) {
        if (uint8(signature[64]) < 27) {
            signature[64] = bytes1(uint8(signature[64]) + 27);
        }
        return ECDSA.recover(commitment, signature);
    }
}
