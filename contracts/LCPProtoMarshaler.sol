// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {
    IbcLightclientsLcpV1ClientState as ClientState,
    IbcLightclientsLcpV1ConsensusState as ConsensusState,
    IbcLightclientsLcpV1RegisterEnclaveKeyMessage as RegisterEnclaveKeyMessage,
    IbcLightclientsLcpV1UpdateClientMessage as UpdateClientMessage
} from "./proto/ibc/lightclients/lcp/v1/LCP.sol";
import {GoogleProtobufAny as Any} from "@hyperledger-labs/yui-ibc-solidity/contracts/proto/GoogleProtobufAny.sol";

library LCPProtoMarshaler {
    string constant UPDATE_CLIENT_MESSAGE_TYPE_URL = "/ibc.lightclients.lcp.v1.UpdateClientMessage";
    string constant REGISTER_ENCLAVE_KEY_MESSAGE_TYPE_URL = "/ibc.lightclients.lcp.v1.RegisterEnclaveKeyMessage";
    string constant CLIENT_STATE_TYPE_URL = "/ibc.lightclients.lcp.v1.ClientState";
    string constant CONSENSUS_STATE_TYPE_URL = "/ibc.lightclients.lcp.v1.ConsensusState";

    bytes32 constant UPDATE_CLIENT_MESSAGE_TYPE_URL_HASH = keccak256(abi.encodePacked(UPDATE_CLIENT_MESSAGE_TYPE_URL));
    bytes32 constant REGISTER_ENCLAVE_KEY_MESSAGE_TYPE_URL_HASH =
        keccak256(abi.encodePacked(REGISTER_ENCLAVE_KEY_MESSAGE_TYPE_URL));
    bytes32 constant CLIENT_STATE_TYPE_URL_HASH = keccak256(abi.encodePacked(CLIENT_STATE_TYPE_URL));
    bytes32 constant CONSENSUS_STATE_TYPE_URL_HASH = keccak256(abi.encodePacked(CONSENSUS_STATE_TYPE_URL));

    function marshal(UpdateClientMessage.Data calldata message) external pure returns (bytes memory) {
        Any.Data memory any;
        any.type_url = UPDATE_CLIENT_MESSAGE_TYPE_URL;
        any.value = UpdateClientMessage.encode(message);
        return Any.encode(any);
    }

    function marshal(RegisterEnclaveKeyMessage.Data calldata message) external pure returns (bytes memory) {
        Any.Data memory any;
        any.type_url = REGISTER_ENCLAVE_KEY_MESSAGE_TYPE_URL;
        any.value = RegisterEnclaveKeyMessage.encode(message);
        return Any.encode(any);
    }

    function marshal(ClientState.Data calldata clientState) external pure returns (bytes memory) {
        Any.Data memory anyClientState;
        anyClientState.type_url = CLIENT_STATE_TYPE_URL;
        anyClientState.value = ClientState.encode(clientState);
        return Any.encode(anyClientState);
    }

    function marshal(ConsensusState.Data calldata consensusState) external pure returns (bytes memory) {
        Any.Data memory anyConsensusState;
        anyConsensusState.type_url = CONSENSUS_STATE_TYPE_URL;
        anyConsensusState.value = ConsensusState.encode(consensusState);
        return Any.encode(anyConsensusState);
    }

    function unmarshalClientState(bytes calldata bz)
        external
        pure
        returns (ClientState.Data memory clientState, bool ok)
    {
        Any.Data memory anyClientState = Any.decode(bz);
        if (keccak256(abi.encodePacked(anyClientState.type_url)) != CLIENT_STATE_TYPE_URL_HASH) {
            return (clientState, false);
        }
        return (ClientState.decode(anyClientState.value), true);
    }

    function unmarshalConsensusState(bytes calldata bz)
        external
        pure
        returns (ConsensusState.Data memory consensusState, bool ok)
    {
        Any.Data memory anyConsensusState = Any.decode(bz);
        if (keccak256(abi.encodePacked(anyConsensusState.type_url)) != CONSENSUS_STATE_TYPE_URL_HASH) {
            return (consensusState, false);
        }
        return (ConsensusState.decode(anyConsensusState.value), true);
    }
}
