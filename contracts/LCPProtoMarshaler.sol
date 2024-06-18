// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {
    IbcLightclientsLcpV1ClientState as ClientState,
    IbcLightclientsLcpV1ConsensusState as ConsensusState,
    IbcLightclientsLcpV1RegisterEnclaveKeyMessage as RegisterEnclaveKeyMessage,
    IbcLightclientsLcpV1UpdateClientMessage as UpdateClientMessage,
    IbcLightclientsLcpV1UpdateOperatorsMessage as UpdateOperatorsMessage
} from "./proto/ibc/lightclients/lcp/v1/LCP.sol";
import {GoogleProtobufAny as Any} from "@hyperledger-labs/yui-ibc-solidity/contracts/proto/GoogleProtobufAny.sol";

library LCPProtoMarshaler {
    string constant UPDATE_CLIENT_MESSAGE_TYPE_URL = "/ibc.lightclients.lcp.v1.UpdateClientMessage";
    string constant REGISTER_ENCLAVE_KEY_MESSAGE_TYPE_URL = "/ibc.lightclients.lcp.v1.RegisterEnclaveKeyMessage";
    string constant UPDATE_OPERATORS_MESSAGE_TYPE_URL = "/ibc.lightclients.lcp.v1.UpdateOperatorsMessage";
    string constant CLIENT_STATE_TYPE_URL = "/ibc.lightclients.lcp.v1.ClientState";
    string constant CONSENSUS_STATE_TYPE_URL = "/ibc.lightclients.lcp.v1.ConsensusState";

    bytes32 constant UPDATE_CLIENT_MESSAGE_TYPE_URL_HASH = keccak256(abi.encodePacked(UPDATE_CLIENT_MESSAGE_TYPE_URL));
    bytes32 constant REGISTER_ENCLAVE_KEY_MESSAGE_TYPE_URL_HASH =
        keccak256(abi.encodePacked(REGISTER_ENCLAVE_KEY_MESSAGE_TYPE_URL));
    bytes32 constant UPDATE_OPERATORS_MESSAGE_TYPE_URL_HASH =
        keccak256(abi.encodePacked(UPDATE_OPERATORS_MESSAGE_TYPE_URL));
    bytes32 constant CLIENT_STATE_TYPE_URL_HASH = keccak256(abi.encodePacked(CLIENT_STATE_TYPE_URL));
    bytes32 constant CONSENSUS_STATE_TYPE_URL_HASH = keccak256(abi.encodePacked(CONSENSUS_STATE_TYPE_URL));

    function marshal(UpdateClientMessage.Data calldata message) public pure returns (bytes memory) {
        Any.Data memory any;
        any.type_url = UPDATE_CLIENT_MESSAGE_TYPE_URL;
        any.value = UpdateClientMessage.encode(message);
        return Any.encode(any);
    }

    function marshalConsensusState(bytes32 stateId, uint64 timestamp) public pure returns (bytes memory) {
        Any.Data memory anyConsensusState;
        anyConsensusState.type_url = CONSENSUS_STATE_TYPE_URL;
        anyConsensusState.value =
            ConsensusState.encode(ConsensusState.Data({state_id: abi.encodePacked(stateId), timestamp: timestamp}));
        return Any.encode(anyConsensusState);
    }

    function marshal(RegisterEnclaveKeyMessage.Data calldata message) public pure returns (bytes memory) {
        Any.Data memory any;
        any.type_url = REGISTER_ENCLAVE_KEY_MESSAGE_TYPE_URL;
        any.value = RegisterEnclaveKeyMessage.encode(message);
        return Any.encode(any);
    }

    function marshal(ClientState.Data calldata clientState) public pure returns (bytes memory) {
        Any.Data memory anyClientState;
        anyClientState.type_url = CLIENT_STATE_TYPE_URL;
        anyClientState.value = ClientState.encode(clientState);
        return Any.encode(anyClientState);
    }

    function marshal(ConsensusState.Data calldata consensusState) public pure returns (bytes memory) {
        Any.Data memory anyConsensusState;
        anyConsensusState.type_url = CONSENSUS_STATE_TYPE_URL;
        anyConsensusState.value = ConsensusState.encode(consensusState);
        return Any.encode(anyConsensusState);
    }

    function routeClientMessage(string calldata clientId, bytes calldata protoClientMessage)
        public
        pure
        returns (bytes32 typeUrlHash, bytes memory args)
    {
        Any.Data memory anyClientMessage = Any.decode(protoClientMessage);
        typeUrlHash = keccak256(abi.encodePacked(anyClientMessage.type_url));
        if (typeUrlHash == UPDATE_CLIENT_MESSAGE_TYPE_URL_HASH) {
            UpdateClientMessage.Data memory message = UpdateClientMessage.decode(anyClientMessage.value);
            return (typeUrlHash, abi.encode(clientId, message));
        } else if (typeUrlHash == REGISTER_ENCLAVE_KEY_MESSAGE_TYPE_URL_HASH) {
            RegisterEnclaveKeyMessage.Data memory message = RegisterEnclaveKeyMessage.decode(anyClientMessage.value);
            return (typeUrlHash, abi.encode(clientId, message));
        } else if (typeUrlHash == UPDATE_OPERATORS_MESSAGE_TYPE_URL_HASH) {
            UpdateOperatorsMessage.Data memory message = UpdateOperatorsMessage.decode(anyClientMessage.value);
            return (typeUrlHash, abi.encode(clientId, message));
        } else {
            revert("unsupported client message type");
        }
    }

    function unmarshalClientState(bytes calldata bz) public pure returns (ClientState.Data memory clientState) {
        Any.Data memory anyClientState = Any.decode(bz);
        require(
            keccak256(abi.encodePacked(anyClientState.type_url)) == CLIENT_STATE_TYPE_URL_HASH,
            "invalid client state type url"
        );
        return ClientState.decode(anyClientState.value);
    }

    function unmarshalConsensusState(bytes calldata bz)
        public
        pure
        returns (ConsensusState.Data memory consensusState)
    {
        Any.Data memory anyConsensusState = Any.decode(bz);
        require(
            keccak256(abi.encodePacked(anyConsensusState.type_url)) == CONSENSUS_STATE_TYPE_URL_HASH,
            "invalid consensus state type url"
        );
        return ConsensusState.decode(anyConsensusState.value);
    }
}
