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

    function upgrade2(NewClientState[] memory newClientStates, NewConsensusState[] memory newConsensusStates) public {
        _upgrade(newClientStates, newConsensusStates);
    }
}

contract TokiLCPClientTest is BasicTest {
    using BytesLib for bytes;

    function testContractUpgrade() public {
        if (!vm.envOr("TEST_UPGRADEABLE", false)) {
            return;
        }
        string memory clientId = "lcp-zkdcap";
        LCPClientZKDCAPOwnableUpgradeable lc = contractUpgradeCommon(clientId, "ek0");

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
        {
            (bytes memory bz,) = lc.getClientState(clientId);
            IbcLightclientsLcpV1ClientState.Data memory clientState = LCPProtoMarshaler.unmarshalClientState(bz);
            assertNotEq(newClientState.zkdcapVerifierInfos[0], clientState.zkdcap_verifier_infos[0]);
            assertNotEq(newClientState.allowedQuoteStatuses.length, clientState.allowed_quote_statuses.length);
        }

        TokiLCPClientZKDCAP.NewConsensusState memory newConsensusState;
        newConsensusState.height = Height.Data(0, 2);
        newConsensusState.consensusState.stateId = keccak256("consensus-state-2");
        newConsensusState.consensusState.timestamp = 2;

        TokiLCPClientZKDCAP.NewClientState[] memory newClientStates = new TokiLCPClientZKDCAP.NewClientState[](1);
        newClientStates[0] = newClientState;
        TokiLCPClientZKDCAP.NewConsensusState[] memory newConsensusStates =
            new TokiLCPClientZKDCAP.NewConsensusState[](1);
        newConsensusStates[0] = newConsensusState;

        Options memory opts2;
        opts2.referenceContract = "LCPClientZKDCAPOwnableUpgradeable.sol";
        opts2.constructorData = abi.encode(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier()), 2
        );
        Upgrades.upgradeProxy(
            address(lc),
            "TokiLCPClientZKDCAP.sol",
            abi.encodeCall(TokiLCPClientZKDCAP.upgrade, (newClientStates, newConsensusStates)),
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

    function testContractUpgradeWithMultipleStates() public {
        if (!vm.envOr("TEST_UPGRADEABLE", false)) {
            return;
        }
        string memory clientId1 = "lcp-zkdcap-1";
        string memory clientId2 = "lcp-zkdcap-2";

        // Deploy proxy and initialize first client with default configuration
        LCPClientZKDCAPOwnableUpgradeable lc = contractUpgradeCommon(clientId1, "ek0");

        // Prepare second client state with different configuration
        IbcLightclientsLcpV1ClientState.Data memory clientState2 = defaultClientState();
        clientState2.allowed_quote_statuses = new string[](1);
        clientState2.allowed_quote_statuses[0] = DCAPValidator.TCB_STATUS_OUT_OF_DATE_STRING;
        clientState2.allowed_advisory_ids = new string[](1);
        clientState2.allowed_advisory_ids[0] = "INTEL-SA-0004";

        // Initialize second client using overloaded function (reuse the already deployed proxy)
        contractUpgradeCommon(clientId2, clientState2, "ek2", lc);

        // Prepare first new client state
        TokiLCPClientZKDCAP.NewClientState memory newClientState1;
        newClientState1.clientId = clientId1;
        newClientState1.mrenclave = abi.encodePacked(keccak256("new mrenclave 1"));
        newClientState1.keyExpiration = 60 * 60 * 2;
        newClientState1.allowedQuoteStatuses = new string[](2);
        newClientState1.allowedQuoteStatuses[0] = DCAPValidator.TCB_STATUS_SW_HARDENING_NEEDED_STRING;
        newClientState1.allowedQuoteStatuses[1] = DCAPValidator.TCB_STATUS_CONFIGURATION_NEEDED_STRING;
        newClientState1.allowedAdvisoryIds = new string[](2);
        newClientState1.allowedAdvisoryIds[0] = "INTEL-SA-0010";
        newClientState1.allowedAdvisoryIds[1] = "INTEL-SA-0011";
        newClientState1.zkdcapVerifierInfos = new bytes[](1);
        newClientState1.zkdcapVerifierInfos[0] = abi.encodePacked(
            bytes1(uint8(1)), // zkvmType
            bytes31(0), // reserved
            bytes32(keccak256("new verifier 1"))
        );

        // Prepare second new client state
        TokiLCPClientZKDCAP.NewClientState memory newClientState2;
        newClientState2.clientId = clientId2;
        newClientState2.mrenclave = abi.encodePacked(keccak256("new mrenclave 2"));
        newClientState2.keyExpiration = 60 * 60 * 3;
        newClientState2.allowedQuoteStatuses = new string[](1);
        newClientState2.allowedQuoteStatuses[0] = DCAPValidator.TCB_STATUS_UP_TO_DATE_STRING;
        newClientState2.allowedAdvisoryIds = new string[](3);
        newClientState2.allowedAdvisoryIds[0] = "INTEL-SA-0020";
        newClientState2.allowedAdvisoryIds[1] = "INTEL-SA-0021";
        newClientState2.allowedAdvisoryIds[2] = "INTEL-SA-0022";
        newClientState2.zkdcapVerifierInfos = new bytes[](1);
        newClientState2.zkdcapVerifierInfos[0] = abi.encodePacked(
            bytes1(uint8(1)), // zkvmType - use 1 instead of 2
            bytes31(0), // reserved
            bytes32(keccak256("new verifier 2"))
        );

        // Verify states before upgrade
        {
            (bytes memory bz1,) = lc.getClientState(clientId1);
            IbcLightclientsLcpV1ClientState.Data memory clientState1 = LCPProtoMarshaler.unmarshalClientState(bz1);
            assertNotEq(newClientState1.zkdcapVerifierInfos[0], clientState1.zkdcap_verifier_infos[0]);
            assertEq(clientState1.allowed_quote_statuses.length, 2); // Initial state has 2 statuses
            assertNotEq(newClientState1.allowedQuoteStatuses[0], clientState1.allowed_quote_statuses[0]);

            (bytes memory bz2,) = lc.getClientState(clientId2);
            IbcLightclientsLcpV1ClientState.Data memory clientState2 = LCPProtoMarshaler.unmarshalClientState(bz2);
            assertNotEq(newClientState2.zkdcapVerifierInfos[0], clientState2.zkdcap_verifier_infos[0]);
            assertEq(clientState2.allowed_quote_statuses.length, 1); // clientState2 was initialized with 1 status
            assertNotEq(newClientState2.allowedQuoteStatuses[0], clientState2.allowed_quote_statuses[0]);
        }

        // Prepare consensus states (matching the order of client states)
        TokiLCPClientZKDCAP.NewConsensusState memory newConsensusState1;
        newConsensusState1.height = Height.Data(0, 2); // Next height after current (1)
        newConsensusState1.consensusState.stateId = keccak256("consensus-state-client1-2");
        newConsensusState1.consensusState.timestamp = 2;

        TokiLCPClientZKDCAP.NewConsensusState memory newConsensusState2;
        newConsensusState2.height = Height.Data(0, 2); // Next height after current (1)
        newConsensusState2.consensusState.stateId = keccak256("consensus-state-client2-2");
        newConsensusState2.consensusState.timestamp = 2;

        // Create arrays for upgrade
        TokiLCPClientZKDCAP.NewClientState[] memory newClientStates = new TokiLCPClientZKDCAP.NewClientState[](2);
        newClientStates[0] = newClientState1;
        newClientStates[1] = newClientState2;

        TokiLCPClientZKDCAP.NewConsensusState[] memory newConsensusStates =
            new TokiLCPClientZKDCAP.NewConsensusState[](2);
        newConsensusStates[0] = newConsensusState1;
        newConsensusStates[1] = newConsensusState2;

        // Perform upgrade
        Options memory opts2;
        opts2.referenceContract = "LCPClientZKDCAPOwnableUpgradeable.sol";
        opts2.constructorData = abi.encode(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier()), 2
        );
        Upgrades.upgradeProxy(
            address(lc),
            "TokiLCPClientZKDCAP.sol",
            abi.encodeCall(TokiLCPClientZKDCAP.upgrade, (newClientStates, newConsensusStates)),
            opts2
        );

        // Verify first client state after upgrade
        {
            (bytes memory bz,) = lc.getClientState(clientId1);
            IbcLightclientsLcpV1ClientState.Data memory clientState = LCPProtoMarshaler.unmarshalClientState(bz);
            assertEq(clientState.latest_height.revision_number, 0);
            assertEq(clientState.latest_height.revision_height, 2); // Updated to height 2
            assertEq(clientState.mrenclave, newClientState1.mrenclave);
            assertEq(clientState.key_expiration, newClientState1.keyExpiration);
            assertEq(clientState.allowed_quote_statuses.length, 2);
            assertEq(clientState.allowed_quote_statuses[0], newClientState1.allowedQuoteStatuses[0]);
            assertEq(clientState.allowed_quote_statuses[1], newClientState1.allowedQuoteStatuses[1]);
            assertEq(clientState.allowed_advisory_ids.length, 2);
            assertEq(clientState.allowed_advisory_ids[0], newClientState1.allowedAdvisoryIds[0]);
            assertEq(clientState.allowed_advisory_ids[1], newClientState1.allowedAdvisoryIds[1]);
            assertEq(clientState.zkdcap_verifier_infos[0], newClientState1.zkdcapVerifierInfos[0]);

            (bz,) = lc.getConsensusState(clientId1, newConsensusState1.height);
            IbcLightclientsLcpV1ConsensusState.Data memory consensusState =
                LCPProtoMarshaler.unmarshalConsensusState(bz);
            assertEq(consensusState.state_id, abi.encodePacked(newConsensusState1.consensusState.stateId));
            assertEq(consensusState.timestamp, newConsensusState1.consensusState.timestamp);
        }

        // Verify second client state after upgrade
        {
            (bytes memory bz,) = lc.getClientState(clientId2);
            IbcLightclientsLcpV1ClientState.Data memory clientState = LCPProtoMarshaler.unmarshalClientState(bz);
            assertEq(clientState.latest_height.revision_number, 0);
            assertEq(clientState.latest_height.revision_height, 2); // Updated to height 2
            assertEq(clientState.mrenclave, newClientState2.mrenclave);
            assertEq(clientState.key_expiration, newClientState2.keyExpiration);
            assertEq(clientState.allowed_quote_statuses.length, 1);
            assertEq(clientState.allowed_quote_statuses[0], newClientState2.allowedQuoteStatuses[0]);
            assertEq(clientState.allowed_advisory_ids.length, 3);
            assertEq(clientState.allowed_advisory_ids[0], newClientState2.allowedAdvisoryIds[0]);
            assertEq(clientState.allowed_advisory_ids[1], newClientState2.allowedAdvisoryIds[1]);
            assertEq(clientState.allowed_advisory_ids[2], newClientState2.allowedAdvisoryIds[2]);
            assertEq(clientState.zkdcap_verifier_infos[0], newClientState2.zkdcapVerifierInfos[0]);

            (bz,) = lc.getConsensusState(clientId2, newConsensusState2.height);
            IbcLightclientsLcpV1ConsensusState.Data memory consensusState =
                LCPProtoMarshaler.unmarshalConsensusState(bz);
            assertEq(consensusState.state_id, abi.encodePacked(newConsensusState2.consensusState.stateId));
            assertEq(consensusState.timestamp, newConsensusState2.consensusState.timestamp);
        }
    }

    function testContractUpgradeWithZeroHeightConsensusState() public {
        if (!vm.envOr("TEST_UPGRADEABLE", false)) {
            return;
        }
        string memory clientId1 = "lcp-zkdcap-1";
        string memory clientId2 = "lcp-zkdcap-2";

        // Deploy proxy and initialize first client with default configuration
        LCPClientZKDCAPOwnableUpgradeable lc = contractUpgradeCommon(clientId1, "ek0");

        {
            // Prepare second client state with different configuration
            IbcLightclientsLcpV1ClientState.Data memory clientState2 = defaultClientState();
            clientState2.allowed_quote_statuses = new string[](1);
            clientState2.allowed_quote_statuses[0] = DCAPValidator.TCB_STATUS_OUT_OF_DATE_STRING;
            clientState2.allowed_advisory_ids = new string[](1);
            clientState2.allowed_advisory_ids[0] = "INTEL-SA-0004";

            // Initialize second client using overloaded function (reuse the already deployed proxy)
            contractUpgradeCommon(clientId2, clientState2, "ek2", lc);
        }

        // Prepare first new client state
        TokiLCPClientZKDCAP.NewClientState memory newClientState1;
        newClientState1.clientId = clientId1;
        newClientState1.mrenclave = abi.encodePacked(keccak256("new mrenclave 1"));
        newClientState1.keyExpiration = 60 * 60 * 2;
        newClientState1.allowedQuoteStatuses = new string[](2);
        newClientState1.allowedQuoteStatuses[0] = DCAPValidator.TCB_STATUS_SW_HARDENING_NEEDED_STRING;
        newClientState1.allowedQuoteStatuses[1] = DCAPValidator.TCB_STATUS_CONFIGURATION_NEEDED_STRING;
        newClientState1.allowedAdvisoryIds = new string[](2);
        newClientState1.allowedAdvisoryIds[0] = "INTEL-SA-0010";
        newClientState1.allowedAdvisoryIds[1] = "INTEL-SA-0011";
        newClientState1.zkdcapVerifierInfos = new bytes[](1);
        newClientState1.zkdcapVerifierInfos[0] = abi.encodePacked(
            bytes1(uint8(1)), // zkvmType
            bytes31(0), // reserved
            bytes32(keccak256("new verifier 1"))
        );

        // Prepare second new client state
        TokiLCPClientZKDCAP.NewClientState memory newClientState2;
        newClientState2.clientId = clientId2;
        newClientState2.mrenclave = abi.encodePacked(keccak256("new mrenclave 2"));
        newClientState2.keyExpiration = 60 * 60 * 3;
        newClientState2.allowedQuoteStatuses = new string[](1);
        newClientState2.allowedQuoteStatuses[0] = DCAPValidator.TCB_STATUS_UP_TO_DATE_STRING;
        newClientState2.allowedAdvisoryIds = new string[](3);
        newClientState2.allowedAdvisoryIds[0] = "INTEL-SA-0020";
        newClientState2.allowedAdvisoryIds[1] = "INTEL-SA-0021";
        newClientState2.allowedAdvisoryIds[2] = "INTEL-SA-0022";
        newClientState2.zkdcapVerifierInfos = new bytes[](1);
        newClientState2.zkdcapVerifierInfos[0] = abi.encodePacked(
            bytes1(uint8(1)), // zkvmType
            bytes31(0), // reserved
            bytes32(keccak256("new verifier 2"))
        );

        // Verify states before upgrade
        {
            (bytes memory bz1,) = lc.getClientState(clientId1);
            IbcLightclientsLcpV1ClientState.Data memory clientState1 = LCPProtoMarshaler.unmarshalClientState(bz1);
            assertNotEq(newClientState1.zkdcapVerifierInfos[0], clientState1.zkdcap_verifier_infos[0]);
            assertEq(clientState1.allowed_quote_statuses.length, 2); // Initial state has 2 statuses
            assertNotEq(newClientState1.allowedQuoteStatuses[0], clientState1.allowed_quote_statuses[0]);

            (bytes memory bz2,) = lc.getClientState(clientId2);
            IbcLightclientsLcpV1ClientState.Data memory clientState2Loaded = LCPProtoMarshaler.unmarshalClientState(bz2);
            assertNotEq(newClientState2.zkdcapVerifierInfos[0], clientState2Loaded.zkdcap_verifier_infos[0]);
            assertEq(clientState2Loaded.allowed_quote_statuses.length, 1); // clientState2 was initialized with 1 status
            assertNotEq(newClientState2.allowedQuoteStatuses[0], clientState2Loaded.allowed_quote_statuses[0]);
        }

        // Prepare consensus states - FIRST ONE WITH HEIGHT ZERO (will be skipped)
        TokiLCPClientZKDCAP.NewConsensusState memory newConsensusState1;
        newConsensusState1.height = Height.Data(0, 0); // Zero height - will skip consensus state update
        newConsensusState1.consensusState.stateId = keccak256("consensus-state-client1-should-not-be-stored");
        newConsensusState1.consensusState.timestamp = 999; // This should not be stored

        TokiLCPClientZKDCAP.NewConsensusState memory newConsensusState2;
        newConsensusState2.height = Height.Data(0, 2); // Next height after current (1)
        newConsensusState2.consensusState.stateId = keccak256("consensus-state-client2-2");
        newConsensusState2.consensusState.timestamp = 2;

        TokiLCPClientZKDCAP.NewClientState[] memory newClientStates = new TokiLCPClientZKDCAP.NewClientState[](2);
        newClientStates[0] = newClientState1;
        newClientStates[1] = newClientState2;

        TokiLCPClientZKDCAP.NewConsensusState[] memory newConsensusStates =
            new TokiLCPClientZKDCAP.NewConsensusState[](2);
        newConsensusStates[0] = newConsensusState1;
        newConsensusStates[1] = newConsensusState2;

        // Perform upgrade
        {
            Options memory opts;
            opts.referenceContract = "LCPClientZKDCAPOwnableUpgradeable.sol";
            opts.constructorData = abi.encode(
                address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier()), 2
            );
            Upgrades.upgradeProxy(
                address(lc),
                "TokiLCPClientZKDCAP.sol",
                abi.encodeCall(TokiLCPClientZKDCAP.upgrade, (newClientStates, newConsensusStates)),
                opts
            );
        }

        // Verify first client state after upgrade
        {
            (bytes memory bz,) = lc.getClientState(clientId1);
            IbcLightclientsLcpV1ClientState.Data memory clientState = LCPProtoMarshaler.unmarshalClientState(bz);
            // Height should remain 1 since consensus state with height 0 is skipped
            assertEq(clientState.latest_height.revision_number, 0);
            assertEq(clientState.latest_height.revision_height, 1); // Remains at height 1
            assertEq(clientState.mrenclave, newClientState1.mrenclave);
            assertEq(clientState.key_expiration, newClientState1.keyExpiration);
            assertEq(clientState.allowed_quote_statuses.length, 2);
            assertEq(clientState.allowed_quote_statuses[0], newClientState1.allowedQuoteStatuses[0]);
            assertEq(clientState.allowed_quote_statuses[1], newClientState1.allowedQuoteStatuses[1]);
            assertEq(clientState.allowed_advisory_ids.length, 2);
            assertEq(clientState.allowed_advisory_ids[0], newClientState1.allowedAdvisoryIds[0]);
            assertEq(clientState.allowed_advisory_ids[1], newClientState1.allowedAdvisoryIds[1]);
            assertEq(clientState.zkdcap_verifier_infos[0], newClientState1.zkdcapVerifierInfos[0]);

            // Verify that consensus state at height 0 was NOT stored
            (bytes memory bzConsensus, bool found) = lc.getConsensusState(clientId1, Height.Data(0, 0));
            assertEq(found, false);
            assertEq(bzConsensus.length, 0);

            // Verify that the previous consensus state at height 1 still exists
            (bzConsensus, found) = lc.getConsensusState(clientId1, Height.Data(0, 1));
            assertEq(found, true);
            IbcLightclientsLcpV1ConsensusState.Data memory consensusState =
                LCPProtoMarshaler.unmarshalConsensusState(bzConsensus);
            // Should still have the old consensus state
            assertEq(consensusState.state_id, abi.encodePacked(keccak256(abi.encodePacked("state-1-", clientId1))));
            assertEq(consensusState.timestamp, 1);
        }

        // Verify second client state after upgrade
        {
            (bytes memory bz,) = lc.getClientState(clientId2);
            IbcLightclientsLcpV1ClientState.Data memory clientState = LCPProtoMarshaler.unmarshalClientState(bz);
            assertEq(clientState.latest_height.revision_number, 0);
            assertEq(clientState.latest_height.revision_height, 2); // Updated to height 2
            assertEq(clientState.mrenclave, newClientState2.mrenclave);
            assertEq(clientState.key_expiration, newClientState2.keyExpiration);
            assertEq(clientState.allowed_quote_statuses.length, 1);
            assertEq(clientState.allowed_quote_statuses[0], newClientState2.allowedQuoteStatuses[0]);
            assertEq(clientState.allowed_advisory_ids.length, 3);
            assertEq(clientState.allowed_advisory_ids[0], newClientState2.allowedAdvisoryIds[0]);
            assertEq(clientState.allowed_advisory_ids[1], newClientState2.allowedAdvisoryIds[1]);
            assertEq(clientState.allowed_advisory_ids[2], newClientState2.allowedAdvisoryIds[2]);
            assertEq(clientState.zkdcap_verifier_infos[0], newClientState2.zkdcapVerifierInfos[0]);

            (bytes memory bzConsensus,) = lc.getConsensusState(clientId2, newConsensusState2.height);
            IbcLightclientsLcpV1ConsensusState.Data memory consensusState =
                LCPProtoMarshaler.unmarshalConsensusState(bzConsensus);
            assertEq(consensusState.state_id, abi.encodePacked(newConsensusState2.consensusState.stateId));
            assertEq(consensusState.timestamp, newConsensusState2.consensusState.timestamp);
        }
    }

    function testContractUpgradeWithEmptyConsensusState() public {
        if (!vm.envOr("TEST_UPGRADEABLE", false)) {
            return;
        }
        string memory clientId = "lcp-zkdcap";
        LCPClientZKDCAPOwnableUpgradeable lc = contractUpgradeCommon(clientId, "ek0");

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

        {
            (bytes memory bz,) = lc.getClientState(clientId);
            IbcLightclientsLcpV1ClientState.Data memory clientState = LCPProtoMarshaler.unmarshalClientState(bz);
            assertNotEq(newClientState.zkdcapVerifierInfos[0], clientState.zkdcap_verifier_infos[0]);
            assertNotEq(newClientState.allowedQuoteStatuses.length, clientState.allowed_quote_statuses.length);
        }

        TokiLCPClientZKDCAP.NewConsensusState memory newConsensusState;
        // NOTE: The new consensus state is empty
        newConsensusState.height = Height.Data(0, 0);

        TokiLCPClientZKDCAP.NewClientState[] memory newClientStates = new TokiLCPClientZKDCAP.NewClientState[](1);
        newClientStates[0] = newClientState;
        TokiLCPClientZKDCAP.NewConsensusState[] memory newConsensusStates =
            new TokiLCPClientZKDCAP.NewConsensusState[](1);
        newConsensusStates[0] = newConsensusState;

        {
            Options memory opts;
            opts.referenceContract = "LCPClientZKDCAPOwnableUpgradeable.sol";
            opts.constructorData = abi.encode(
                address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier()), 2
            );
            Upgrades.upgradeProxy(
                address(lc),
                "TokiLCPClientZKDCAP.sol",
                abi.encodeCall(TokiLCPClientZKDCAP.upgrade, (newClientStates, newConsensusStates)),
                opts
            );
        }

        {
            (bytes memory bz,) = lc.getClientState(clientId);
            IbcLightclientsLcpV1ClientState.Data memory clientState = LCPProtoMarshaler.unmarshalClientState(bz);
            assertEq(clientState.latest_height.revision_number, 0);
            assertEq(clientState.latest_height.revision_height, 1);
            assertEq(clientState.mrenclave, newClientState.mrenclave);
            assertEq(clientState.key_expiration, newClientState.keyExpiration);
            assertEq(clientState.allowed_quote_statuses.length, 1);
            assertEq(clientState.allowed_quote_statuses[0], newClientState.allowedQuoteStatuses[0]);
            assertEq(clientState.allowed_advisory_ids.length, 1);
            assertEq(clientState.allowed_advisory_ids[0], newClientState.allowedAdvisoryIds[0]);
            assertEq(clientState.zkdcap_verifier_infos[0], newClientState.zkdcapVerifierInfos[0]);
        }
    }

    function contractUpgradeCommon(string memory clientId, string memory walletSeed)
        internal
        returns (LCPClientZKDCAPOwnableUpgradeable)
    {
        Options memory opts;
        opts.constructorData = abi.encode(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        LCPClientZKDCAPOwnableUpgradeable lc = LCPClientZKDCAPOwnableUpgradeable(
            Upgrades.deployUUPSProxy(
                "LCPClientZKDCAPOwnableUpgradeable.sol",
                abi.encodePacked(LCPClientZKDCAPOwnableUpgradeable.initialize.selector),
                opts
            )
        );
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        clientState.allowed_quote_statuses = new string[](2);
        clientState.allowed_quote_statuses[0] = DCAPValidator.TCB_STATUS_CONFIGURATION_NEEDED_STRING;
        clientState.allowed_quote_statuses[1] = DCAPValidator.TCB_STATUS_OUT_OF_DATE_STRING;
        clientState.allowed_advisory_ids = new string[](2);
        clientState.allowed_advisory_ids[0] = "INTEL-SA-0001";
        clientState.allowed_advisory_ids[1] = "INTEL-SA-0003";

        contractUpgradeCommon(clientId, clientState, walletSeed, lc);
        return lc;
    }

    function contractUpgradeCommon(
        string memory clientId,
        IbcLightclientsLcpV1ClientState.Data memory clientState,
        string memory walletSeed,
        LCPClientZKDCAPOwnableUpgradeable lc
    ) internal {
        // Initialize client on existing proxy
        lc.initializeClient(
            clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
        );
        DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
        output.advisoryIDs = clientState.allowed_advisory_ids;
        Vm.Wallet memory ek = vm.createWallet(walletSeed);
        output.enclaveKey = ek.addr;
        // warp to the time of `output.validityNotBefore`
        vm.warp(output.validityNotBefore);
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));

        // Update client to have a non-zero latest height
        {
            LCPCommitment.UpdateStateProxyMessage memory updateStateMessage;
            updateStateMessage.prevHeight = Height.Data(0, 0);
            updateStateMessage.prevStateId = bytes32(0);
            updateStateMessage.postHeight = Height.Data(0, 1);
            updateStateMessage.postStateId = keccak256(abi.encodePacked("state-1-", clientId));
            updateStateMessage.timestamp = 1;
            LCPCommitment.ValidationContext memory vc;
            updateStateMessage.context = abi.encode(vc);
            updateStateMessage.emittedStates = new LCPCommitment.EmittedState[](1);

            LCPCommitment.HeaderedProxyMessage memory headeredMessage;
            headeredMessage.header = LCPCommitment.LCP_MESSAGE_HEADER_UPDATE_STATE;
            headeredMessage.message = abi.encode(updateStateMessage);

            IbcLightclientsLcpV1UpdateClientMessage.Data memory message;
            message.proxy_message = abi.encode(headeredMessage);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ek, keccak256(message.proxy_message));
            message.signatures = new bytes[](1);
            message.signatures[0] = abi.encodePacked(r, s, v);

            lc.updateClient(clientId, message);
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

        TokiLCPClientZKDCAP.NewClientState[] memory newClientStates = new TokiLCPClientZKDCAP.NewClientState[](1);
        newClientStates[0] = newClientState;
        TokiLCPClientZKDCAP.NewConsensusState[] memory newConsensusStates =
            new TokiLCPClientZKDCAP.NewConsensusState[](1);
        newConsensusStates[0] = newConsensusState;

        lc.upgrade2(newClientStates, newConsensusStates);

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
