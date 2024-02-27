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
    IbcLightclientsLcpV1UpdateClientMessage as UpdateClientMessage
} from "./proto/ibc/lightclients/lcp/v1/LCP.sol";
import {LCPCommitment} from "./LCPCommitment.sol";
import {LCPProtoMarshaler} from "./LCPProtoMarshaler.sol";
import {LCPUtils} from "./LCPUtils.sol";
import {AVRValidator} from "./AVRValidator.sol";

contract LCPClient is ILightClient {
    using IBCHeight for Height.Data;

    struct ConsensusState {
        bytes32 stateId;
        uint64 timestamp;
    }

    event RegisteredEnclaveKey(string clientId, address enclaveKey, uint256 expiredAt);

    address immutable ibcHandler;
    // if developmentMode is true, the client allows the remote attestation of IAS in development.
    bool immutable developmentMode;

    mapping(string => ProtoClientState.Data) internal clientStates;
    mapping(string => mapping(uint128 => ConsensusState)) internal consensusStates;

    // rootCA's public key parameters
    AVRValidator.RSAParams public verifiedRootCAParams;
    // keccak256(signingCert) => RSAParams of signing public key
    mapping(bytes32 => AVRValidator.RSAParams) public verifiedSigningRSAParams;
    // clientId => enclave key => expiredAt
    mapping(string => mapping(address => uint256)) internal enclaveKeys;
    // clientId => quote status => flag(0: not allowed, 1: allowed)
    mapping(string => mapping(string => uint256)) internal allowedQuoteStatuses;
    // clientId => advisory id => flag(0: not allowed, 1: allowed)
    mapping(string => mapping(string => uint256)) internal allowedAdvisories;

    modifier onlyIBC() {
        require(msg.sender == ibcHandler);
        _;
    }

    constructor(address ibcHandler_, bytes memory rootCACert, bool developmentMode_) {
        ibcHandler = ibcHandler_;
        developmentMode = developmentMode_;
        verifiedRootCAParams = AVRValidator.verifyRootCACert(rootCACert);
    }

    // @dev isDevelopmentMode returns true if the client allows the remote attestation of IAS in development.
    function isDevelopmentMode() public view returns (bool) {
        return developmentMode;
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
        require(
            clientState.latest_height.revision_number == 0 && clientState.latest_height.revision_height == 0,
            "invalid initial height"
        );
        require(!clientState.frozen, "client state must not be frozen");
        require(clientState.key_expiration != 0, "key_expiration must be non-zero");
        require(clientState.mrenclave.length == 32, "invalid mrenclave length");
        require(consensusState.timestamp == 0 && consensusState.state_id.length == 0, "invalid consensus state");

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
        require(consensusState.timestamp != 0, "consensus state not found");
        return consensusState.timestamp;
    }

    /**
     * @dev getLatestHeight returns the latest height of the client state corresponding to `clientId`.
     */
    function getLatestHeight(string calldata clientId) public view returns (Height.Data memory) {
        ProtoClientState.Data storage clientState = clientStates[clientId];
        require(clientState.latest_height.revision_height != 0, "client state not found");
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
        } else {
            revert("unknown type url");
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
        require(commitmentProof.signature.length == 65, "invalid signature length");

        ConsensusState storage consensusState = consensusStates[clientId][message.height.toUint128()];
        require(consensusState.stateId != bytes32(0), "consensus state not found");

        require(height.eq(message.height), "invalid height");
        require(keccak256(prefix) == keccak256(message.prefix));
        require(keccak256(path) == keccak256(message.path));
        require(keccak256(value) == message.value, "invalid commitment value");
        require(consensusState.stateId == message.stateId, "invalid state_id");
        require(isActiveKey(clientId, commitmentProof.signer), "the key isn't active");
        require(
            verifyCommitmentProof(keccak256(commitmentProof.message), commitmentProof.signature, commitmentProof.signer),
            "failed to verify signature"
        );

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
        require(commitmentProof.signature.length == 65, "invalid signature length");

        ConsensusState storage consensusState = consensusStates[clientId][message.height.toUint128()];
        require(consensusState.stateId != bytes32(0), "consensus state not found");

        require(height.eq(message.height), "invalid height");
        require(keccak256(prefix) == keccak256(message.prefix));
        require(keccak256(path) == keccak256(message.path));
        require(bytes32(0) == message.value, "invalid commitment value");
        require(consensusState.stateId == message.stateId, "invalid state_id");
        require(isActiveKey(clientId, commitmentProof.signer), "the key isn't active");
        require(
            verifyCommitmentProof(keccak256(commitmentProof.message), commitmentProof.signature, commitmentProof.signer),
            "failed to verify signature"
        );

        return true;
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
        return (
            LCPProtoMarshaler.marshal(
                ProtoConsensusState.Data({
                    timestamp: consensusState.timestamp,
                    state_id: abi.encodePacked(consensusState.stateId)
                })
                ),
            true
        );
    }

    function updateClient(string calldata clientId, UpdateClientMessage.Data calldata message)
        public
        returns (Height.Data[] memory heights)
    {
        require(message.signer.length == 20, "invalid signer length");
        require(message.signature.length == 65, "invalid signature length");

        require(isActiveKey(clientId, address(bytes20(message.signer))), "the key isn't active");
        require(
            verifyCommitmentProof(keccak256(message.proxy_message), message.signature, address(bytes20(message.signer))),
            "failed to verify the commitment"
        );

        LCPCommitment.HeaderedProxyMessage memory hm =
            abi.decode(message.proxy_message, (LCPCommitment.HeaderedProxyMessage));
        if (hm.header == LCPCommitment.LCP_MESSAGE_HEADER_UPDATE_STATE) {
            return updateState(clientId, abi.decode(hm.message, (LCPCommitment.UpdateStateProxyMessage)));
        } else if (hm.header == LCPCommitment.LCP_MESSAGE_HEADER_MISBEHAVIOUR) {
            return submitMisbehaviour(clientId, abi.decode(hm.message, (LCPCommitment.MisbehaviourProxyMessage)));
        } else {
            revert("unexpected header");
        }
    }

    function updateState(string calldata clientId, LCPCommitment.UpdateStateProxyMessage memory pmsg)
        internal
        returns (Height.Data[] memory heights)
    {
        ProtoClientState.Data storage clientState = clientStates[clientId];
        ConsensusState storage consensusState;

        require(!clientState.frozen, "client state must not be frozen");

        if (clientState.latest_height.revision_number == 0 && clientState.latest_height.revision_height == 0) {
            require(pmsg.emittedStates.length != 0, "EmittedStates must be non-nil");
        } else {
            consensusState = consensusStates[clientId][pmsg.prevHeight.toUint128()];
            require(pmsg.prevStateId != bytes32(0), "PrevStateID must be non-nil");
            require(consensusState.stateId == pmsg.prevStateId, "unexpected StateID");
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

    function submitMisbehaviour(string calldata clientId, LCPCommitment.MisbehaviourProxyMessage memory pmsg)
        internal
        returns (Height.Data[] memory heights)
    {
        ProtoClientState.Data storage clientState = clientStates[clientId];
        ConsensusState storage consensusState;

        require(!clientState.frozen, "client state must not be frozen");
        require(pmsg.prevStates.length != 0, "PrevStates must be non-nil");

        for (uint256 i = 0; i < pmsg.prevStates.length; i++) {
            consensusState = consensusStates[clientId][pmsg.prevStates[i].height.toUint128()];
            require(pmsg.prevStates[i].stateId != bytes32(0), "stateId must be non-nil");
            require(consensusState.stateId == pmsg.prevStates[i].stateId, "unexpected StateID");
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
                require(verifiedRootCAParams.notAfter > block.timestamp, "root public key is expired");
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
            } else {
                require(params.notAfter > block.timestamp, "certificate is expired");
            }
            require(
                AVRValidator.verifySignature(
                    sha256(bytes(message.report)), message.signature, params.exponent, params.modulus
                ),
                "failed to verify signature"
            );
        }

        ProtoClientState.Data storage clientState = clientStates[clientId];
        (address enclaveKey, bytes memory attestationTimeBytes, bytes32 mrenclave) = AVRValidator
            .validateAndExtractElements(
            developmentMode, bytes(message.report), allowedQuoteStatuses[clientId], allowedAdvisories[clientId]
        );
        require(bytes32(clientState.mrenclave) == mrenclave, "mrenclave mismatch");

        uint256 expiredAt =
            uint64(LCPUtils.attestationTimestampToSeconds(attestationTimeBytes)) + clientState.key_expiration;
        require(expiredAt > block.timestamp, "the report is already expired");

        if (enclaveKeys[clientId][enclaveKey] != 0) {
            require(enclaveKeys[clientId][enclaveKey] == expiredAt, "expiredAt mismatch");
            // NOTE: if the key already exists, don't update any state
            return heights;
        }

        enclaveKeys[clientId][enclaveKey] = expiredAt;
        emit RegisteredEnclaveKey(clientId, enclaveKey, expiredAt);

        // Note: client and consensus state are not always updated in registerEnclaveKey
        return heights;
    }

    function isActiveKey(string calldata clientId, address signer) internal view returns (bool) {
        uint256 expiredAt = enclaveKeys[clientId][signer];
        if (expiredAt == 0) {
            return false;
        }
        return expiredAt > block.timestamp;
    }

    function verifyCommitmentProof(bytes32 commitment, bytes memory signature, address signer)
        internal
        pure
        returns (bool)
    {
        if (uint8(signature[64]) < 27) {
            signature[64] = bytes1(uint8(signature[64]) + 27);
        }
        return ECDSA.recover(commitment, signature) == signer;
    }
}
