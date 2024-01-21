// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/ILightClient.sol";
import "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/IBCHeight.sol";
import "@hyperledger-labs/yui-ibc-solidity/contracts/proto/Client.sol";
import {GoogleProtobufAny as Any} from "@hyperledger-labs/yui-ibc-solidity/contracts/proto/GoogleProtobufAny.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {
    IbcLightclientsLcpV1ClientState as ClientState,
    IbcLightclientsLcpV1ConsensusState as ConsensusState,
    IbcLightclientsLcpV1RegisterEnclaveKeyMessage as RegisterEnclaveKeyMessage,
    IbcLightclientsLcpV1UpdateClientMessage as UpdateClientMessage
} from "./proto/ibc/lightclients/lcp/v1/LCP.sol";
import "./LCPCommitment.sol";
import "./LCPProtoMarshaler.sol";
import "./LCPUtils.sol";
import "./AVRValidator.sol";

contract LCPClient is ILightClient {
    using IBCHeight for Height.Data;

    event RegisteredEnclaveKey(string clientId, address enclaveKey, uint256 expiredAt);

    address immutable ibcHandler;
    // if developmentMode is true, the client allows the remote attestation of IAS in development.
    bool immutable developmentMode;

    mapping(string => ClientState.Data) internal clientStates;
    mapping(string => mapping(uint128 => ConsensusState.Data)) internal consensusStates;

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
    function isDevelopmentMode() external view returns (bool) {
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
    ) external onlyIBC returns (Height.Data memory height) {
        ClientState.Data memory clientState = LCPProtoMarshaler.unmarshalClientState(protoClientState);
        ConsensusState.Data memory consensusState = LCPProtoMarshaler.unmarshalConsensusState(protoConsensusState);

        // validate an initial state
        require(
            clientState.latest_height.revision_number == 0 && clientState.latest_height.revision_height == 0,
            "invalid initial height"
        );
        require(clientState.key_expiration != 0, "key_expiration must be non-zero");
        require(clientState.mrenclave.length == 32, "invalid mrenclave length");
        require(consensusState.timestamp == 0 && consensusState.state_id.length == 0, "invalid consensus state");

        // NOTE should we set only non-default values?
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
    function getTimestampAtHeight(string calldata clientId, Height.Data calldata height)
        external
        view
        returns (uint64)
    {
        ConsensusState.Data storage consensusState = consensusStates[clientId][height.toUint128()];
        require(consensusState.timestamp != 0, "consensus state not found");
        return consensusState.timestamp;
    }

    /**
     * @dev getLatestHeight returns the latest height of the client state corresponding to `clientId`.
     */
    function getLatestHeight(string calldata clientId) external view returns (Height.Data memory) {
        ClientState.Data storage clientState = clientStates[clientId];
        require(clientState.latest_height.revision_height != 0, "client state not found");
        return clientState.latest_height;
    }
    /**
     * @dev getStatus returns the status of the client corresponding to `clientId`.
     */

    function getStatus(string calldata) external view returns (ClientStatus) {
        // TODO: should return the correct status after implementing the misbehavior detection
        return ClientStatus.Active;
    }

    /**
     * @dev routeUpdateClient returns the calldata to the receiving function of the client message.
     *      Light client contract may encode a client message as other encoding scheme(e.g. ethereum ABI)
     *      Check ADR-001 for details.
     */
    function routeUpdateClient(string calldata clientId, bytes calldata protoClientMessage)
        external
        pure
        returns (bytes4 selector, bytes memory args)
    {
        Any.Data memory anyClientMessage = Any.decode(protoClientMessage);
        bytes32 typeUrlHash = keccak256(abi.encodePacked(anyClientMessage.type_url));
        if (typeUrlHash == LCPProtoMarshaler.UPDATE_CLIENT_MESSAGE_TYPE_URL_HASH) {
            return (this.updateState.selector, abi.encode(clientId, UpdateClientMessage.decode(anyClientMessage.value)));
        } else if (typeUrlHash == LCPProtoMarshaler.REGISTER_ENCLAVE_KEY_MESSAGE_TYPE_URL_HASH) {
            return (
                this.registerEnclaveKey.selector,
                abi.encode(clientId, RegisterEnclaveKeyMessage.decode(anyClientMessage.value))
            );
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
        (LCPCommitment.CommitmentProof memory commitmentProof, LCPCommitment.VerifyMembershipMessage memory message) =
            LCPCommitment.parseVerifyMembershipCommitmentProof(proof);
        require(commitmentProof.signature.length == 65, "invalid signature length");

        ConsensusState.Data storage consensusState = consensusStates[clientId][message.height.toUint128()];
        require(consensusState.state_id.length != 0, "consensus state not found");

        require(height.eq(message.height), "invalid height");
        require(keccak256(prefix) == keccak256(message.prefix));
        require(keccak256(path) == keccak256(message.path));
        require(keccak256(value) == message.value, "invalid commitment value");
        require(bytes32(consensusState.state_id) == message.stateId, "invalid state_id");
        require(isActiveKey(clientId, commitmentProof.signer), "the key isn't active");
        require(
            verifyCommitmentProof(
                keccak256(commitmentProof.commitment), commitmentProof.signature, commitmentProof.signer
            ),
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
        (LCPCommitment.CommitmentProof memory commitmentProof, LCPCommitment.VerifyMembershipMessage memory message) =
            LCPCommitment.parseVerifyMembershipCommitmentProof(proof);
        require(commitmentProof.signature.length == 65, "invalid signature length");

        ConsensusState.Data storage consensusState = consensusStates[clientId][message.height.toUint128()];
        require(consensusState.state_id.length != 0, "consensus state not found");

        require(height.eq(message.height), "invalid height");
        require(keccak256(prefix) == keccak256(message.prefix));
        require(keccak256(path) == keccak256(message.path));
        require(bytes32(0) == message.value, "invalid commitment value");
        require(bytes32(consensusState.state_id) == message.stateId, "invalid state_id");
        require(isActiveKey(clientId, commitmentProof.signer), "the key isn't active");
        require(
            verifyCommitmentProof(
                keccak256(commitmentProof.commitment), commitmentProof.signature, commitmentProof.signer
            ),
            "failed to verify signature"
        );

        return true;
    }

    /**
     * @dev getClientState returns the clientState corresponding to `clientId`.
     *      If it's not found, the function returns false.
     */
    function getClientState(string calldata clientId) external view returns (bytes memory clientStateBytes, bool) {
        ClientState.Data storage clientState = clientStates[clientId];
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
        external
        view
        returns (bytes memory consensusStateBytes, bool)
    {
        ConsensusState.Data storage consensusState = consensusStates[clientId][height.toUint128()];
        if (consensusState.timestamp == 0 && consensusState.state_id.length == 0) {
            return (consensusStateBytes, false);
        }
        return (LCPProtoMarshaler.marshal(consensusState), true);
    }

    function updateState(string calldata clientId, UpdateClientMessage.Data calldata message)
        public
        returns (Height.Data[] memory heights)
    {
        require(message.signer.length == 20, "invalid signer length");
        require(message.signature.length == 65, "invalid signature length");

        ClientState.Data storage clientState = clientStates[clientId];
        ConsensusState.Data storage consensusState;

        LCPCommitment.UpdateClientMessage memory commitment = LCPCommitment.parseUpdateClientMessage(message.commitment);
        if (clientState.latest_height.revision_number == 0 && clientState.latest_height.revision_height == 0) {
            require(commitment.emittedStates.length != 0, "the commitment's `EmittedStates` must be non-nil");
        } else {
            consensusState = consensusStates[clientId][commitment.prevHeight.toUint128()];
            require(
                consensusState.timestamp != 0 && bytes32(consensusState.state_id) == commitment.prevStateId,
                "unexpected StateID"
            );
        }

        LCPCommitment.validationContextEval(commitment.context, block.timestamp * 1e9);

        require(isActiveKey(clientId, address(bytes20(message.signer))), "the key isn't active");

        require(
            verifyCommitmentProof(keccak256(message.commitment), message.signature, address(bytes20(message.signer))),
            "failed to verify the commitment"
        );

        if (clientState.latest_height.lt(commitment.postHeight)) {
            clientState.latest_height = commitment.postHeight;
        }

        consensusState = consensusStates[clientId][commitment.postHeight.toUint128()];
        consensusState.state_id = abi.encodePacked(commitment.postStateId);
        consensusState.timestamp = uint64(commitment.timestamp);

        heights = new Height.Data[](1);
        heights[0] = commitment.postHeight;
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

        ClientState.Data storage clientState = clientStates[clientId];
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
