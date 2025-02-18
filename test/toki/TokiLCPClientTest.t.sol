// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import "../TestHelper.t.sol";
import {
    IbcLightclientsLcpV1ClientState,
    IbcLightclientsLcpV1ConsensusState,
    IbcLightclientsLcpV1ZKDCAPRegisterEnclaveKeyMessage,
    IbcLightclientsLcpV1UpdateClientMessage
} from "../../contracts/proto/ibc/lightclients/lcp/v1/LCP.sol";
import {LCPClientZKDCAP} from "../../contracts/LCPClientZKDCAP.sol";
import {LCPClientZKDCAPBase} from "../../contracts/LCPClientZKDCAPBase.sol";
import {LCPProtoMarshaler} from "../../contracts/LCPProtoMarshaler.sol";
import {IRiscZeroVerifier, Receipt} from "risc0-ethereum/contracts/src/test/RiscZeroMockVerifier.sol";
import {DCAPValidator} from "../../contracts/DCAPValidator.sol";
import {BytesLib} from "../BytesLib.sol";
import {ILCPClientErrors} from "../../contracts/ILCPClientErrors.sol";
import {LCPOperator} from "../../contracts/LCPOperator.sol";
import {TokiLCPClientZKDCAP} from "../../contracts/toki/TokiLCPClientZKDCAP.sol";
import {IBCHeight} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/IBCHeight.sol";
import {Test} from "forge-std/Test.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {Options} from "openzeppelin-foundry-upgrades/Options.sol";
import {LCPClientZKDCAPOwnableUpgradeable} from "contracts/LCPClientZKDCAPOwnableUpgradeable.sol";
import {ZKDCAPTestHelper, NopRiscZeroVerifier} from "../LCPClientZKDCAPTest.t.sol";

contract TestTokiLCPClientZKDCAP is TokiLCPClientZKDCAP {
    constructor(
        address ibcHandler_,
        bool developmentMode_,
        bytes memory intelRootCA,
        address riscZeroVerifier,
        uint64 initialTcbEvaluationDataNumber
    )
        TokiLCPClientZKDCAP(ibcHandler_, developmentMode_, intelRootCA, riscZeroVerifier, initialTcbEvaluationDataNumber)
    {}

    function isAdvisoryIdAllowed(string calldata clientId, string calldata advisoryId) public view returns (bool) {
        return clientStorages[clientId].allowedStatuses.allowedAdvisories[advisoryId] == RemoteAttestation.FLAG_ALLOWED;
    }

    function isQuoteStatusAllowed(string calldata clientId, string calldata quoteStatus) public view returns (bool) {
        return
            clientStorages[clientId].allowedStatuses.allowedQuoteStatuses[quoteStatus] == RemoteAttestation.FLAG_ALLOWED;
    }

    function getDecodedClientState(string memory clientId)
        public
        view
        returns (IbcLightclientsLcpV1ClientState.Data memory)
    {
        return clientStorages[clientId].clientState;
    }

    function getDecodedConsensusState(string memory clientId, uint64 revisionNumber, uint64 revisionHeight)
        public
        view
        returns (ConsensusState memory)
    {
        return
            clientStorages[clientId].consensusStates[IBCHeight.toUint128(Height.Data(revisionNumber, revisionHeight))];
    }

    function getEKInfo(string memory clientId, address ekAddr) public view returns (EKInfo memory) {
        return clientStorages[clientId].ekInfos[ekAddr];
    }

    function upgrade2(NewClientState memory newClientState, NewConsensusState memory newConsensusState) public {
        _upgrade(newClientState, newConsensusState);
    }
}

contract TokiLCPClientTest is BasicTest {
    using BytesLib for bytes;

    function testContractUpgrade() public {
        if (!vm.envOr("TEST_UPGRADEABLE", false)) {
            return;
        }
        string memory clientId = "lcp-zkdcap";
        Options memory opts;
        opts.constructorData = abi.encode(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        address proxy = Upgrades.deployUUPSProxy(
            "LCPClientZKDCAPOwnableUpgradeable.sol",
            abi.encodePacked(LCPClientZKDCAPOwnableUpgradeable.initialize.selector),
            opts
        );
        LCPClientZKDCAPOwnableUpgradeable lc = LCPClientZKDCAPOwnableUpgradeable(proxy);
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        clientState.allowed_quote_statuses = new string[](2);
        clientState.allowed_quote_statuses[0] = DCAPValidator.TCB_STATUS_CONFIGURATION_NEEDED_STRING;
        clientState.allowed_quote_statuses[1] = DCAPValidator.TCB_STATUS_OUT_OF_DATE_STRING;
        clientState.allowed_advisory_ids = new string[](2);
        clientState.allowed_advisory_ids[0] = "INTEL-SA-0001";
        clientState.allowed_advisory_ids[1] = "INTEL-SA-0003";
        lc.initializeClient(
            clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
        );
        DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
        output.advisoryIDs = clientState.allowed_advisory_ids;
        Vm.Wallet memory ek0 = vm.createWallet("ek0");
        output.enclaveKey = ek0.addr;
        // warp to the time of `output.validityNotBefore`
        vm.warp(output.validityNotBefore);
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
        {
            LCPCommitment.UpdateStateProxyMessage memory updateStateMessage;
            updateStateMessage.prevHeight = Height.Data(0, 0);
            updateStateMessage.prevStateId = bytes32(0);
            updateStateMessage.postHeight = Height.Data(0, 1);
            updateStateMessage.postStateId = keccak256("state-1");
            updateStateMessage.timestamp = 1;
            LCPCommitment.ValidationContext memory vc;
            updateStateMessage.context = abi.encode(vc);
            updateStateMessage.emittedStates = new LCPCommitment.EmittedState[](1);

            LCPCommitment.HeaderedProxyMessage memory headeredMessage;
            headeredMessage.header = LCPCommitment.LCP_MESSAGE_HEADER_UPDATE_STATE;
            headeredMessage.message = abi.encode(updateStateMessage);

            IbcLightclientsLcpV1UpdateClientMessage.Data memory message;
            message.proxy_message = abi.encode(headeredMessage);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ek0, keccak256(message.proxy_message));
            message.signatures = new bytes[](1);
            message.signatures[0] = abi.encodePacked(r, s, v);
            lc.updateClient(clientId, message);
        }

        TokiLCPClientZKDCAP.NewClientState memory newClientState;
        newClientState.clientId = clientId;
        newClientState.mrenclave = abi.encodePacked(keccak256("new mrenclave"));
        newClientState.keyExpiration = 60 * 60;
        newClientState.allowedQuoteStatuses = new string[](1);
        newClientState.allowedQuoteStatuses[0] = DCAPValidator.TCB_STATUS_SW_HARDENING_NEEDED_STRING;
        newClientState.allowedAdvisoryIds = new string[](1);
        newClientState.allowedAdvisoryIds[0] = "INTEL-SA-0002";
        newClientState.zkdcapVerifierInfos = new bytes[](1);
        newClientState.zkdcapVerifierInfos[0] = abi.encodePacked(
            bytes1(uint8(1)), // zkvmType
            bytes31(0), // reserved
            bytes32(keccak256("new verifier"))
        );
        assertNotEq(newClientState.zkdcapVerifierInfos[0], clientState.zkdcap_verifier_infos[0]);
        assertNotEq(newClientState.allowedQuoteStatuses.length, clientState.allowed_quote_statuses.length);

        TokiLCPClientZKDCAP.NewConsensusState memory newConsensusState;
        newConsensusState.height = Height.Data(0, 2);
        newConsensusState.consensusState.stateId = keccak256("consensus-state-2");
        newConsensusState.consensusState.timestamp = 2;

        Options memory opts2;
        opts2.referenceContract = "LCPClientZKDCAPOwnableUpgradeable.sol";
        opts2.constructorData = abi.encode(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier()), 2
        );
        Upgrades.upgradeProxy(
            proxy,
            "TokiLCPClientZKDCAP.sol",
            abi.encodeCall(TokiLCPClientZKDCAP.upgrade, (newClientState, newConsensusState)),
            opts2
        );

        {
            (bytes memory bz,) = lc.getClientState(clientId);
            IbcLightclientsLcpV1ClientState.Data memory clientState = LCPProtoMarshaler.unmarshalClientState(bz);
            assertEq(clientState.latest_height.revision_number, 0);
            assertEq(clientState.latest_height.revision_height, 2);
            assertEq(clientState.mrenclave, newClientState.mrenclave);
            assertEq(clientState.key_expiration, newClientState.keyExpiration);
            assertEq(clientState.allowed_quote_statuses.length, 1);
            assertEq(clientState.allowed_quote_statuses[0], newClientState.allowedQuoteStatuses[0]);
            assertEq(clientState.allowed_advisory_ids.length, 1);
            assertEq(clientState.allowed_advisory_ids[0], newClientState.allowedAdvisoryIds[0]);
            assertEq(clientState.zkdcap_verifier_infos[0], newClientState.zkdcapVerifierInfos[0]);

            (bz,) = lc.getConsensusState(clientId, newConsensusState.height);
            IbcLightclientsLcpV1ConsensusState.Data memory consensusState =
                LCPProtoMarshaler.unmarshalConsensusState(bz);
            assertEq(consensusState.state_id, abi.encodePacked(newConsensusState.consensusState.stateId));
            assertEq(consensusState.timestamp, newConsensusState.consensusState.timestamp);
        }
    }

    function testRecoveredLCPClientUpgradeable() public {
        string memory clientId = "lcp-zkdcap";
        TestTokiLCPClientZKDCAP lc = new TestTokiLCPClientZKDCAP(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier()), 1
        );
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        clientState.allowed_quote_statuses = new string[](2);
        clientState.allowed_quote_statuses[0] = DCAPValidator.TCB_STATUS_CONFIGURATION_NEEDED_STRING;
        clientState.allowed_quote_statuses[1] = DCAPValidator.TCB_STATUS_OUT_OF_DATE_STRING;
        clientState.allowed_advisory_ids = new string[](2);
        clientState.allowed_advisory_ids[0] = "INTEL-SA-0001";
        clientState.allowed_advisory_ids[1] = "INTEL-SA-0003";
        lc.initializeClient(
            clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
        );
        DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
        output.advisoryIDs = clientState.allowed_advisory_ids;

        Vm.Wallet memory ek0 = vm.createWallet("ek0");
        output.enclaveKey = ek0.addr;
        // warp to the time of `output.validityNotBefore`
        vm.warp(output.validityNotBefore);
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));

        {
            LCPCommitment.UpdateStateProxyMessage memory updateStateMessage;
            updateStateMessage.prevHeight = Height.Data(0, 0);
            updateStateMessage.prevStateId = bytes32(0);
            updateStateMessage.postHeight = Height.Data(0, 1);
            updateStateMessage.postStateId = keccak256("state-1");
            updateStateMessage.timestamp = 1;
            LCPCommitment.ValidationContext memory vc;
            updateStateMessage.context = abi.encode(vc);
            updateStateMessage.emittedStates = new LCPCommitment.EmittedState[](1);

            LCPCommitment.HeaderedProxyMessage memory headeredMessage;
            headeredMessage.header = LCPCommitment.LCP_MESSAGE_HEADER_UPDATE_STATE;
            headeredMessage.message = abi.encode(updateStateMessage);

            IbcLightclientsLcpV1UpdateClientMessage.Data memory message;
            message.proxy_message = abi.encode(headeredMessage);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ek0, keccak256(message.proxy_message));
            message.signatures = new bytes[](1);
            message.signatures[0] = abi.encodePacked(r, s, v);
            lc.updateClient(clientId, message);
        }

        TokiLCPClientZKDCAP.NewClientState memory newClientState;
        newClientState.clientId = clientId;
        newClientState.mrenclave = abi.encodePacked(keccak256("new mrenclave"));
        newClientState.keyExpiration = 60 * 60;
        newClientState.allowedQuoteStatuses = new string[](1);
        newClientState.allowedQuoteStatuses[0] = DCAPValidator.TCB_STATUS_SW_HARDENING_NEEDED_STRING;
        newClientState.allowedAdvisoryIds = new string[](1);
        newClientState.allowedAdvisoryIds[0] = "INTEL-SA-0002";
        newClientState.zkdcapVerifierInfos = new bytes[](1);
        newClientState.zkdcapVerifierInfos[0] = abi.encodePacked(
            bytes1(uint8(1)), // zkvmType
            bytes31(0), // reserved
            bytes32(keccak256("new verifier"))
        );
        assertNotEq(newClientState.zkdcapVerifierInfos[0], clientState.zkdcap_verifier_infos[0]);
        assertNotEq(newClientState.allowedQuoteStatuses.length, clientState.allowed_quote_statuses.length);

        TokiLCPClientZKDCAP.NewConsensusState memory newConsensusState;
        newConsensusState.height = Height.Data(0, 2);
        newConsensusState.consensusState.stateId = keccak256("consensus-state-2");
        newConsensusState.consensusState.timestamp = 2;

        lc.upgrade2(newClientState, newConsensusState);

        clientState = lc.getDecodedClientState(clientId);
        assertEq(clientState.latest_height.revision_number, 0);
        assertEq(clientState.latest_height.revision_height, 2);
        assertEq(clientState.mrenclave, newClientState.mrenclave);
        assertEq(clientState.key_expiration, newClientState.keyExpiration);
        assertEq(clientState.allowed_quote_statuses.length, 1);
        assertEq(clientState.allowed_quote_statuses[0], newClientState.allowedQuoteStatuses[0]);
        assertEq(clientState.allowed_advisory_ids.length, 1);
        assertEq(clientState.allowed_advisory_ids[0], newClientState.allowedAdvisoryIds[0]);
        assertEq(clientState.zkdcap_verifier_infos[0], newClientState.zkdcapVerifierInfos[0]);
        assertFalse(lc.isAdvisoryIdAllowed(clientId, "INTEL-SA-0001"));
        assertTrue(lc.isAdvisoryIdAllowed(clientId, "INTEL-SA-0002"));
        assertFalse(lc.isAdvisoryIdAllowed(clientId, "INTEL-SA-0003"));

        assertFalse(lc.isQuoteStatusAllowed(clientId, DCAPValidator.TCB_STATUS_CONFIGURATION_NEEDED_STRING));
        assertFalse(lc.isQuoteStatusAllowed(clientId, DCAPValidator.TCB_STATUS_OUT_OF_DATE_STRING));
        assertTrue(lc.isQuoteStatusAllowed(clientId, DCAPValidator.TCB_STATUS_SW_HARDENING_NEEDED_STRING));

        TokiLCPClientZKDCAP.ConsensusState memory consensusState = lc.getDecodedConsensusState(clientId, 0, 2);
        assertEq(consensusState.stateId, newConsensusState.consensusState.stateId);
        assertEq(consensusState.timestamp, newConsensusState.consensusState.timestamp);
    }

    // --- helper functions ---

    function registerEnclaveKeyMessage(DCAPValidator.Output memory output)
        internal
        returns (IbcLightclientsLcpV1ZKDCAPRegisterEnclaveKeyMessage.Data memory message)
    {
        message.zkvm_type = 0x01;
        message.quote_verification_output = ZKDCAPTestHelper.toBytes(output);
        message.proof = bytes(hex"00000000").concat(hex"01");
        return message;
    }

    function defaultClientState() internal returns (IbcLightclientsLcpV1ClientState.Data memory clientState) {
        clientState.mrenclave = abi.encodePacked(ZKDCAPTestHelper.TEST_MRENCLAVE);
        clientState.key_expiration = 0;
        clientState.current_tcb_evaluation_data_number = 1;
        clientState.zkdcap_verifier_infos =
            ZKDCAPTestHelper.buildRiscZeroVerifierInfos(ZKDCAPTestHelper.TEST_RISC_ZERO_IMAGE_ID);
        return clientState;
    }

    function defaultConsensusState()
        internal
        pure
        returns (IbcLightclientsLcpV1ConsensusState.Data memory consensusState)
    {
        // The initial consensus state is empty
        return consensusState;
    }

    // Called by the client when registering an enclave key
    function updateClientCommitments(string calldata clientId, Height.Data[] calldata heights) external {}
}
