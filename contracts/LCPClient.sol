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

    address immutable ibcHandler;
    // if developmentMode is true, the client allows the remote attestation of IAS in development.
    bool immutable developmentMode;

    mapping(string => ClientState.Data) internal clientStates;
    mapping(string => mapping(uint128 => ConsensusState.Data)) internal consensusStates;

    // rootCA's public key parameters
    AVRValidator.RSAParams public verifiedRootCAParams;
    // keccak256(signingCert) => RSAParams of signing public key
    mapping(bytes32 => AVRValidator.RSAParams) public verifiedSigningRSAParams;
    // enclave key => expiredAt
    mapping(address => uint256) internal enclaveKeys;
    mapping(string => uint256) internal allowedQuoteStatuses;
    mapping(string => uint256) internal allowedAdvisories;

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
     * @dev createClient creates a new client with the given state.
     * If succeeded, it returns a commitment for the initial state.
     */
    function createClient(string calldata clientId, bytes calldata clientStateBytes, bytes calldata consensusStateBytes)
        public
        onlyIBC
        returns (bytes32 clientStateCommitment, ConsensusStateUpdate memory update, bool ok)
    {
        ClientState.Data memory clientState;
        ConsensusState.Data memory consensusState;

        (clientState, ok) = LCPProtoMarshaler.unmarshalClientState(clientStateBytes);
        if (!ok) {
            return (clientStateCommitment, update, false);
        }
        // NOTE consensusState is always default value
        (consensusState, ok) = LCPProtoMarshaler.unmarshalConsensusState(consensusStateBytes);
        if (!ok) {
            return (clientStateCommitment, update, false);
        }

        // Validate an initial state
        if (clientState.latest_height.revision_number != 0 || clientState.latest_height.revision_height != 0) {
            return (clientStateCommitment, update, false);
        }
        if (clientState.key_expiration == 0) {
            return (clientStateCommitment, update, false);
        }
        if (clientState.mrenclave.length != 32) {
            return (clientStateCommitment, update, false);
        }
        if (consensusState.timestamp != 0 || consensusState.state_id.length != 0) {
            return (clientStateCommitment, update, false);
        }
        // NOTE should we set only non-default values?
        clientStates[clientId] = clientState;

        // set allowed quote status and advisories
        for (uint256 i = 0; i < clientState.allowed_quote_statuses.length; i++) {
            allowedQuoteStatuses[clientState.allowed_quote_statuses[i]] = AVRValidator.FLAG_ALLOWED;
        }
        for (uint256 i = 0; i < clientState.allowed_advisory_ids.length; i++) {
            allowedAdvisories[clientState.allowed_advisory_ids[i]] = AVRValidator.FLAG_ALLOWED;
        }

        return (
            keccak256(clientStateBytes),
            ConsensusStateUpdate({
                consensusStateCommitment: keccak256(consensusStateBytes),
                height: clientState.latest_height
            }),
            true
        );
    }

    /**
     * @dev getTimestampAtHeight returns the timestamp of the consensus state at the given height.
     */
    function getTimestampAtHeight(string calldata clientId, Height.Data calldata height)
        public
        view
        returns (uint64, bool)
    {
        ConsensusState.Data storage consensusState = consensusStates[clientId][height.toUint128()];
        return (consensusState.timestamp, consensusState.timestamp != 0);
    }

    /**
     * @dev getLatestHeight returns the latest height of the client state corresponding to `clientId`.
     */
    function getLatestHeight(string calldata clientId) public view returns (Height.Data memory, bool) {
        ClientState.Data storage clientState = clientStates[clientId];
        return (clientState.latest_height, clientState.latest_height.revision_height != 0);
    }
    /**
     * @dev getStatus returns the status of the client corresponding to `clientId`.
     */

    function getStatus(string calldata) external view returns (ClientStatus) {
        // TODO: should return the correct status after implementing the misbehavior detection
        return ClientStatus.Active;
    }

    /**
     * @dev updateClient updates the client corresponding to `clientId`.
     * If succeeded, it returns a commitment for the updated state.
     * If there are no updates for consensus state, this function should returns an empty array as `updates`.
     */
    function updateClient(string calldata clientId, bytes calldata clientMessageBytes)
        public
        onlyIBC
        returns (bytes32 clientStateCommitment, ConsensusStateUpdate[] memory updates, bool ok)
    {
        Any.Data memory anyClientMessage = Any.decode(clientMessageBytes);
        bytes32 typeUrlHash = keccak256(abi.encodePacked(anyClientMessage.type_url));
        if (typeUrlHash == LCPProtoMarshaler.UPDATE_CLIENT_MESSAGE_TYPE_URL_HASH) {
            return updateState(clientId, UpdateClientMessage.decode(anyClientMessage.value));
        } else if (typeUrlHash == LCPProtoMarshaler.REGISTER_ENCLAVE_KEY_MESSAGE_TYPE_URL_HASH) {
            return registerEnclaveKey(clientId, RegisterEnclaveKeyMessage.decode(anyClientMessage.value));
        } else {
            revert("unknown type url");
        }
    }

    /**
     * @dev verifyMembership is a generic proof verification method which verifies a proof of the existence of a value at a given CommitmentPath at the specified height.
     * The caller is expected to construct the full CommitmentPath from a CommitmentPrefix and a standardized path (as defined in ICS 24).
     */
    function verifyMembership(
        string memory clientId,
        Height.Data memory height,
        uint64,
        uint64,
        bytes memory proof,
        bytes memory prefix,
        bytes memory path,
        bytes memory value
    ) public view returns (bool) {
        (LCPCommitment.CommitmentProof memory commitmentProof, LCPCommitment.StateCommitment memory commitment) =
            LCPCommitment.parseStateCommitmentAndProof(proof);
        require(commitmentProof.signature.length == 65, "invalid signature length");

        ConsensusState.Data storage consensusState = consensusStates[clientId][commitment.height.toUint128()];
        require(consensusState.state_id.length != 0, "consensus state not found");

        require(height.eq(commitment.height), "invalid height");
        require(keccak256(prefix) == keccak256(commitment.prefix));
        require(keccak256(path) == keccak256(commitment.path));
        require(keccak256(value) == commitment.value, "invalid commitment value");
        require(bytes32(consensusState.state_id) == commitment.stateId, "invalid state_id");
        require(isActiveKey(commitmentProof.signer), "the key isn't active");
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
        (LCPCommitment.CommitmentProof memory commitmentProof, LCPCommitment.StateCommitment memory commitment) =
            LCPCommitment.parseStateCommitmentAndProof(proof);
        require(commitmentProof.signature.length == 65, "invalid signature length");

        ConsensusState.Data storage consensusState = consensusStates[clientId][commitment.height.toUint128()];
        require(consensusState.state_id.length != 0, "consensus state not found");

        require(height.eq(commitment.height), "invalid height");
        require(keccak256(prefix) == keccak256(commitment.prefix));
        require(keccak256(path) == keccak256(commitment.path));
        require(bytes32(0) == commitment.value, "invalid commitment value");
        require(bytes32(consensusState.state_id) == commitment.stateId, "invalid state_id");
        require(isActiveKey(commitmentProof.signer), "the key isn't active");
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
    function getClientState(string calldata clientId) public view returns (bytes memory clientStateBytes, bool) {
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
        public
        view
        returns (bytes memory consensusStateBytes, bool)
    {
        ConsensusState.Data storage consensusState = consensusStates[clientId][height.toUint128()];
        if (consensusState.timestamp == 0 && consensusState.state_id.length == 0) {
            return (consensusStateBytes, false);
        }
        return (LCPProtoMarshaler.marshal(consensusState), true);
    }

    function updateState(string calldata clientId, UpdateClientMessage.Data memory message)
        internal
        returns (bytes32 clientStateCommitment, ConsensusStateUpdate[] memory updates, bool ok)
    {
        require(message.signer.length == 20, "invalid signer length");
        require(message.signature.length == 65, "invalid signature length");

        ClientState.Data storage clientState = clientStates[clientId];
        ConsensusState.Data storage consensusState;

        LCPCommitment.UpdateClientCommitment memory commitment =
            LCPCommitment.parseUpdateClientCommitment(message.commitment);
        if (clientState.latest_height.revision_number == 0 && clientState.latest_height.revision_height == 0) {
            require(commitment.newState.length != 0, "the commitment's `NewState` must be non-nil");
        } else {
            consensusState = consensusStates[clientId][commitment.prevHeight.toUint128()];
            require(
                consensusState.timestamp != 0 && bytes32(consensusState.state_id) == commitment.prevStateId,
                "unexpected StateID"
            );
        }

        LCPCommitment.validateCommitmentContext(commitment.context, block.timestamp * 1e9);

        require(isActiveKey(address(bytes20(message.signer))), "the key isn't active");

        require(
            verifyCommitmentProof(keccak256(message.commitment), message.signature, address(bytes20(message.signer))),
            "failed to verify the commitment"
        );

        if (clientState.latest_height.lt(commitment.newHeight)) {
            clientState.latest_height = commitment.newHeight;
        }

        consensusState = consensusStates[clientId][commitment.newHeight.toUint128()];
        consensusState.state_id = abi.encodePacked(commitment.newStateId);
        consensusState.timestamp = uint64(commitment.timestamp);

        /* Make updates message */

        updates = new ConsensusStateUpdate[](1);
        updates[0] = ConsensusStateUpdate({
            consensusStateCommitment: keccak256(LCPProtoMarshaler.marshal(consensusState)),
            height: commitment.newHeight
        });

        return (keccak256(LCPProtoMarshaler.marshal(clientState)), updates, true);
    }

    function isActiveKey(address signer) internal view returns (bool) {
        uint256 expiredAt = enclaveKeys[signer];
        if (expiredAt == 0) {
            return false;
        }
        return expiredAt > block.timestamp;
    }

    function registerEnclaveKey(string calldata clientId, RegisterEnclaveKeyMessage.Data memory message)
        internal
        returns (bytes32 clientStateCommitment, ConsensusStateUpdate[] memory updates, bool ok)
    {
        ClientState.Data storage clientState = clientStates[clientId];
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

        (address enclaveKey, bytes memory attestationTimeBytes, bytes32 mrenclave) = AVRValidator
            .validateAndExtractElements(developmentMode, bytes(message.report), allowedQuoteStatuses, allowedAdvisories);
        require(bytes32(clientState.mrenclave) == mrenclave, "mrenclave mismatch");

        uint256 expiredAt =
            uint64(LCPUtils.attestationTimestampToSeconds(attestationTimeBytes)) + clientState.key_expiration;
        require(expiredAt > block.timestamp, "the report is already expired");
        require(enclaveKeys[enclaveKey] == 0, "the key already exists");
        enclaveKeys[enclaveKey] = expiredAt;

        // Note: client and consensus state are not always updated in registerEnclaveKey
        return (bytes32(0), updates, true);
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
