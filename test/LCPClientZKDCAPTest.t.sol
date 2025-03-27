// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import "./TestHelper.t.sol";
import {
    IbcLightclientsLcpV1ClientState,
    IbcLightclientsLcpV1ConsensusState,
    IbcLightclientsLcpV1ZKDCAPRegisterEnclaveKeyMessage
} from "../contracts/proto/ibc/lightclients/lcp/v1/LCP.sol";
import {LCPClientZKDCAP} from "../contracts/LCPClientZKDCAP.sol";
import {LCPClientZKDCAPBase} from "../contracts/LCPClientZKDCAPBase.sol";
import {LCPProtoMarshaler} from "../contracts/LCPProtoMarshaler.sol";
import {IRiscZeroVerifier, Receipt} from "risc0-ethereum/contracts/src/test/RiscZeroMockVerifier.sol";
import {DCAPValidator} from "../contracts/DCAPValidator.sol";
import {BytesLib} from "./BytesLib.sol";
import {ILCPClientErrors} from "../contracts/ILCPClientErrors.sol";
import {LCPOperator} from "../contracts/LCPOperator.sol";

contract TestLCPClientZKDCAPExtended is LCPClientZKDCAP {
    constructor(address ibcHandler_, bool developmentMode_, bytes memory intelRootCA, address riscZeroVerifier)
        LCPClientZKDCAP(ibcHandler_, developmentMode_, intelRootCA, riscZeroVerifier)
    {}

    function getDecodedClientState(string memory clientId)
        public
        view
        returns (IbcLightclientsLcpV1ClientState.Data memory)
    {
        return clientStorages[clientId].clientState;
    }

    function getEKInfo(string memory clientId, address ekAddr) public view returns (EKInfo memory) {
        return clientStorages[clientId].ekInfos[ekAddr];
    }
}

contract LCPClientZKDCAPTest is BasicTest {
    using BytesLib for bytes;

    function testRegisterEnclaveKeyQvOutputValidity() public {
        string memory clientId = "lcp-zkdcap";
        TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        lc.initializeClient(
            clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
        );

        DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
        // warp to the time of `output.validityNotBefore`
        vm.warp(output.validityNotBefore);
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
        assertEq(lc.getEKInfo(clientId, output.enclaveKey).expiredAt, output.validityNotAfter + 1);

        // if `validityNotBefore` is in the future, it should fail
        output = ZKDCAPTestHelper.qvOutput();
        output.validityNotBefore = output.validityNotBefore + 1;
        output.enclaveKey = address(2);
        vm.expectRevert();
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));

        // if `validityNotAfter` is in the past, it should fail
        output = ZKDCAPTestHelper.qvOutput();
        output.validityNotAfter = uint64(block.timestamp) - 1;
        output.enclaveKey = address(2);
        vm.expectRevert();
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));

        // if `validityNotAfter` equals to `block.timestamp`, it should succeed
        output = ZKDCAPTestHelper.qvOutput();
        output.validityNotAfter = uint64(block.timestamp);
        output.enclaveKey = address(2);
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
        assertEq(lc.getEKInfo(clientId, output.enclaveKey).expiredAt, output.validityNotAfter + 1);
    }

    function testRegisterEnclaveKeyNotSetGracePeriod() public {
        string memory clientId = "lcp-zkdcap";
        TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        lc.initializeClient(
            clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
        );

        DCAPValidator.Output memory output;

        // if `minTcbEvaluationDataNumber` equals to `clientState.current_tcb_evaluation_data_number`, it should succeed
        output = ZKDCAPTestHelper.qvOutput();
        output.minTcbEvaluationDataNumber = 1;
        vm.warp(output.validityNotBefore);
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));

        // if `minTcbEvaluationDataNumber` is less than `clientState.current_tcb_evaluation_data_number`, it should fail
        output = ZKDCAPTestHelper.qvOutput();
        output.minTcbEvaluationDataNumber = 1;
        output.enclaveKey = address(2);
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));

        // if `minTcbEvaluationDataNumber` is greater than `clientState.current_tcb_evaluation_data_number`, it should succeed
        output = ZKDCAPTestHelper.qvOutput();
        output.minTcbEvaluationDataNumber = 2;
        output.enclaveKey = address(3);
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));

        // if `minTcbEvaluationDataNumber` is less than `clientState.current_tcb_evaluation_data_number`, it should fail
        output = ZKDCAPTestHelper.qvOutput();
        output.minTcbEvaluationDataNumber = 1;
        output.enclaveKey = address(4);
        vm.expectRevert();
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));

        // if `minTcbEvaluationDataNumber` is greater than `clientState.current_tcb_evaluation_data_number`, it should succeed
        output = ZKDCAPTestHelper.qvOutput();
        output.minTcbEvaluationDataNumber = 5;
        output.enclaveKey = address(4);
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
    }

    function testRegisterEnclaveKeySetGracePeriod() public {
        string memory clientId = "lcp-zkdcap";
        TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        clientState.tcb_evaluation_data_number_update_grace_period = 2;
        lc.initializeClient(
            clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
        );

        {
            // if `minTcbEvaluationDataNumber` equals to `clientState.current_tcb_evaluation_data_number`, it should succeed
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.minTcbEvaluationDataNumber = 1;
            vm.warp(output.validityNotBefore);
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
            assertEq(lc.getDecodedClientState(clientId).current_tcb_evaluation_data_number, 1);
            assertEq(lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number, 0);
            assertEq(lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number_update_time, 0);
        }

        uint64 nextUpdateTime;
        {
            // if `minTcbEvaluationDataNumber` greater than `clientState.current_tcb_evaluation_data_number`, it should succeed
            // and the `current_tcb_evaluation_data_number` should not be updated and the `next_tcb_evaluation_data_number` should be set
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.minTcbEvaluationDataNumber = 2;
            output.enclaveKey = address(2);
            // warp to the time of `output.validityNotBefore`
            vm.warp(output.validityNotBefore);
            // Note: block.timestamp == output.validityNotBefore
            nextUpdateTime = uint64(block.timestamp) + clientState.tcb_evaluation_data_number_update_grace_period;
            vm.expectEmit();
            emit LCPClientZKDCAPBase.LCPClientZKDCAPUpdateNextTcbEvaluationDataNumber(clientId, 2);
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
            assertEq(lc.getDecodedClientState(clientId).current_tcb_evaluation_data_number, 1);
            assertEq(lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number, 2);
            assertEq(lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number_update_time, nextUpdateTime);
        }
        {
            // if current time is within the grace period, it
            // should succeed and the `current_tcb_evaluation_data_number` should be not updated
            vm.warp(nextUpdateTime - 1);
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.minTcbEvaluationDataNumber = 2;
            output.enclaveKey = address(3);
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
            assertEq(lc.getDecodedClientState(clientId).current_tcb_evaluation_data_number, 1);
            assertEq(lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number, 2);
            assertEq(lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number_update_time, nextUpdateTime);
        }
        {
            // warp to the time of `nextUpdateTime`
            vm.warp(nextUpdateTime);
            // if `minTcbEvaluationDataNumber` is equal to `clientState.current_tcb_evaluation_data_number`, it should fail
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.minTcbEvaluationDataNumber = 1;
            output.enclaveKey = address(3);
            vm.expectRevert(
                abi.encodeWithSelector(ILCPClientErrors.LCPClientZKDCAPUnexpectedTcbEvaluationDataNumber.selector, 2)
            );
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
        }
        // save the snapshot that includes the current state (current_tcb_evaluation_data_number = 1, next_tcb_evaluation_data_number = 2)
        uint256 sid = vm.snapshot();
        {
            // warp to the time of `nextUpdateTime`
            vm.warp(nextUpdateTime);
            // if `minTcbEvaluationDataNumber` equals to `clientState.current_tcb_evaluation_data_number`, it should succeed
            // and the `current_tcb_evaluation_data_number` should be updated
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.minTcbEvaluationDataNumber = 2;
            output.enclaveKey = address(3);
            vm.expectEmit();
            emit LCPClientZKDCAPBase.LCPClientZKDCAPUpdateCurrentTcbEvaluationDataNumber(clientId, 2);
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
            assertEq(lc.getDecodedClientState(clientId).current_tcb_evaluation_data_number, 2);
            assertEq(lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number, 0);
            assertEq(lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number_update_time, 0);

            // if `minTcbEvaluationDataNumber` equals to `clientState.current_tcb_evaluation_data_number`, it should succeed
            output = ZKDCAPTestHelper.qvOutput();
            output.minTcbEvaluationDataNumber = 2;
            output.enclaveKey = address(4);
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
            assertEq(lc.getDecodedClientState(clientId).current_tcb_evaluation_data_number, 2);

            // if `minTcbEvaluationDataNumber` is less than `clientState.current_tcb_evaluation_data_number`, it should fail
            output = ZKDCAPTestHelper.qvOutput();
            output.minTcbEvaluationDataNumber = 1;
            output.enclaveKey = address(5);
            vm.expectRevert();
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
        }
        // revert to the state (current_tcb_evaluation_data_number = 1, next_tcb_evaluation_data_number = 2)
        vm.revertTo(sid);
        {
            // Edge case 1 (current < next < newly observed number)
            // warp to the time of `nextUpdateTime`-1
            vm.warp(nextUpdateTime - 1);
            // if `minTcbEvaluationDataNumber` is greater than `clientState.next_tcb_evaluation_data_number`, it should succeed
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.minTcbEvaluationDataNumber = 3;
            output.enclaveKey = address(3);
            vm.expectEmit();
            emit LCPClientZKDCAPBase.LCPClientZKDCAPUpdateCurrentTcbEvaluationDataNumber(clientId, 2);
            emit LCPClientZKDCAPBase.LCPClientZKDCAPUpdateNextTcbEvaluationDataNumber(clientId, 3);
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
            // check if the current and next tcb evaluation data numbers are updated
            assertEq(lc.getDecodedClientState(clientId).current_tcb_evaluation_data_number, 2);
            assertEq(lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number, 3);
            // check if the next update time is rescheduled
            assertNotEq(lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number_update_time, nextUpdateTime);
            assertEq(
                lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number_update_time,
                block.timestamp + clientState.tcb_evaluation_data_number_update_grace_period
            );
        }
        // revert to the state (current_tcb_evaluation_data_number = 1, next_tcb_evaluation_data_number = 2)
        vm.revertTo(sid);
        {
            // warp to the time of `nextUpdateTime`
            vm.warp(nextUpdateTime);
            // if `minTcbEvaluationDataNumber` equals to `clientState.current_tcb_evaluation_data_number`, it should succeed
            // and the `current_tcb_evaluation_data_number` should be updated
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.minTcbEvaluationDataNumber = 2;
            output.enclaveKey = address(3);
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
            assertEq(lc.getDecodedClientState(clientId).current_tcb_evaluation_data_number, 2);
            assertEq(lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number, 0);
            assertEq(lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number_update_time, 0);

            {
                // Edge case 2 (current < newly observed number < next)

                output = ZKDCAPTestHelper.qvOutput();
                output.minTcbEvaluationDataNumber = 4;
                output.enclaveKey = address(4);
                vm.expectEmit();
                emit LCPClientZKDCAPBase.LCPClientZKDCAPUpdateNextTcbEvaluationDataNumber(clientId, 4);
                lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
                uint256 nextUpdateTime2 = block.timestamp + clientState.tcb_evaluation_data_number_update_grace_period;
                assertEq(lc.getDecodedClientState(clientId).current_tcb_evaluation_data_number, 2);
                assertEq(lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number, 4);
                assertEq(
                    lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number_update_time, nextUpdateTime2
                );

                output = ZKDCAPTestHelper.qvOutput();
                output.minTcbEvaluationDataNumber = 3;
                output.enclaveKey = address(5);
                emit LCPClientZKDCAPBase.LCPClientZKDCAPUpdateCurrentTcbEvaluationDataNumber(clientId, 3);
                lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
                // the current tcb evaluation data number should be updated
                assertEq(lc.getDecodedClientState(clientId).current_tcb_evaluation_data_number, 3);
                assertEq(lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number, 4);
                // the next update time should not be updated
                assertEq(
                    lc.getDecodedClientState(clientId).next_tcb_evaluation_data_number_update_time, nextUpdateTime2
                );
            }
        }
    }

    function testRegisterEnclaveKeySetKeyNotSetKeyExpiration() public {
        string memory clientId = "lcp-zkdcap";
        TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        // 1 sec from `output.validityNotBefore`
        clientState.key_expiration = 0;
        lc.initializeClient(
            clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
        );

        DCAPValidator.Output memory output;

        // if `key_expiration` is 0 and the current time is within the validity period, it should succeed
        // and the key expiration should be set to `validityNotAfter` + 1
        output = ZKDCAPTestHelper.qvOutput();
        vm.warp(output.validityNotBefore);
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
        assertEq(lc.getEKInfo(clientId, output.enclaveKey).expiredAt, output.validityNotAfter + 1);
    }

    function testRegisterEnclaveKeySetKeyExpiration() public {
        string memory clientId = "lcp-zkdcap";
        TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        // 1 sec from `output.validityNotBefore`
        clientState.key_expiration = 2;
        lc.initializeClient(
            clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
        );

        DCAPValidator.Output memory output;

        // if `validityNotBefore` + `key_expiration` is in the future, it should succeed
        output = ZKDCAPTestHelper.qvOutput();
        output.enclaveKey = address(1);
        vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP);
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
        assertEq(
            lc.getEKInfo(clientId, output.enclaveKey).expiredAt, output.validityNotBefore + clientState.key_expiration
        );

        // if `validityNotBefore` + `key_expiration` is in the past, it should fail

        // warp to the time of `output.validityNotBefore` + `clientState.key_expiration`
        vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP + clientState.key_expiration);
        output = ZKDCAPTestHelper.qvOutput();
        output.enclaveKey = address(2);
        vm.expectRevert(ILCPClientErrors.LCPClientEnclaveKeyExpired.selector);
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));

        // if `validityNotBefore` + `key_expiration` equals to `validityNotAfter`, it should succeed
        vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP);
        output = ZKDCAPTestHelper.qvOutput();
        output.enclaveKey = address(2);
        output.validityNotAfter = output.validityNotBefore + clientState.key_expiration;
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
        assertEq(
            lc.getEKInfo(clientId, output.enclaveKey).expiredAt, output.validityNotBefore + clientState.key_expiration
        );

        // if `validityNotBefore` + `key_expiration` is greater than `validityNotAfter`, it should succeed
        // and the key expiration should be set to `validityNotAfter`
        vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP);
        output = ZKDCAPTestHelper.qvOutput();
        output.enclaveKey = address(3);
        output.validityNotAfter = output.validityNotBefore + clientState.key_expiration - 1;
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
        assertEq(lc.getEKInfo(clientId, output.enclaveKey).expiredAt, output.validityNotAfter + 1);
    }

    function testRegisterEnclaveKeyInvalidZkvmType() public {
        string memory clientId = "lcp-zkdcap";
        TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        lc.initializeClient(
            clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
        );
        vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP);
        DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
        IbcLightclientsLcpV1ZKDCAPRegisterEnclaveKeyMessage.Data memory msgData = registerEnclaveKeyMessage(output);
        msgData.zkvm_type = 0x02;
        vm.expectRevert(abi.encodeWithSelector(ILCPClientErrors.LCPClientZKDCAPUnsupportedZKVMType.selector));
        lc.zkDCAPRegisterEnclaveKey(clientId, msgData);
    }

    function testRegisterEnclaveKeyInvalidRisc0Header() public {
        string memory clientId = "lcp-zkdcap";
        TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        {
            IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
            clientState.zkdcap_verifier_infos[0][0] = 0x00;
            bytes memory clientStateBytes = LCPProtoMarshaler.marshal(clientState);
            bytes memory consensusStateBytes = LCPProtoMarshaler.marshal(defaultConsensusState());
            vm.expectRevert(
                abi.encodeWithSelector(ILCPClientErrors.LCPClientZKDCAPInvalidVerifierInfoRisc0Header.selector)
            );
            lc.initializeClient(clientId, clientStateBytes, consensusStateBytes);
        }
        {
            IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
            clientState.zkdcap_verifier_infos[0][0] = 0x02;
            bytes memory clientStateBytes = LCPProtoMarshaler.marshal(clientState);
            bytes memory consensusStateBytes = LCPProtoMarshaler.marshal(defaultConsensusState());
            vm.expectRevert(
                abi.encodeWithSelector(ILCPClientErrors.LCPClientZKDCAPInvalidVerifierInfoRisc0Header.selector)
            );
            lc.initializeClient(clientId, clientStateBytes, consensusStateBytes);
        }
        {
            IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
            clientState.zkdcap_verifier_infos[0][1] = 0x01;
            bytes memory clientStateBytes = LCPProtoMarshaler.marshal(clientState);
            bytes memory consensusStateBytes = LCPProtoMarshaler.marshal(defaultConsensusState());
            vm.expectRevert(
                abi.encodeWithSelector(ILCPClientErrors.LCPClientZKDCAPInvalidVerifierInfoRisc0Header.selector)
            );
            lc.initializeClient(clientId, clientStateBytes, consensusStateBytes);
        }
    }

    function testRegisterEnclaveKeyEnclaveDebugMismatch() public {
        string memory clientId = "lcp-zkdcap";
        // developmentMode=false but output.enclaveDebugEnabled is set to true
        TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        lc.initializeClient(
            clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
        );
        DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
        output.enclaveDebugEnabled = true;
        vm.expectRevert(abi.encodeWithSelector(ILCPClientErrors.LCPClientZKDCAPUnexpectedEnclaveDebugMode.selector));
        vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP);
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
    }

    function testRegisterEnclaveKeyMrenclaveMismatch() public {
        string memory clientId = "lcp-zkdcap";
        TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        lc.initializeClient(
            clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
        );
        vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP);
        DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
        output.mrenclave = keccak256(abi.encodePacked("different mrenclave"));
        vm.expectRevert(abi.encodeWithSelector(ILCPClientErrors.LCPClientClientStateUnexpectedMrenclave.selector));
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
    }

    function testRegisterEnclaveKeyIntelRootCAMismatch() public {
        string memory clientId = "lcp-zkdcap";
        TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        lc.initializeClient(
            clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
        );
        vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP);
        DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
        output.sgxIntelRootCAHash = keccak256(abi.encodePacked("different root cert"));
        vm.expectRevert(abi.encodeWithSelector(ILCPClientErrors.LCPClientZKDCAPUnexpectedIntelRootCAHash.selector));
        lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
    }

    function testRegisterEnclaveKeyTCBStatus() public {
        string memory clientId = "lcp-zkdcap";
        TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        clientState.allowed_quote_statuses = new string[](1);
        clientState.allowed_quote_statuses[0] = DCAPValidator.TCB_STATUS_SW_HARDENING_NEEDED_STRING;
        lc.initializeClient(
            clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
        );
        vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP);
        {
            // OutOfDate status is not allowed
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.tcbStatus = DCAPValidator.TCB_STATUS_OUT_OF_DATE_STRING;
            vm.expectRevert(abi.encodeWithSelector(ILCPClientErrors.LCPClientZKDCAPDisallowedTCBStatus.selector));
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
        }
        {
            // SwHardeningNeeded status is allowed
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.enclaveKey = address(1);
            output.tcbStatus = DCAPValidator.TCB_STATUS_SW_HARDENING_NEEDED_STRING;
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
        }
        {
            // UpToDate status is allowed by default
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.enclaveKey = address(2);
            output.tcbStatus = DCAPValidator.TCB_STATUS_UP_TO_DATE_STRING;
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
        }
    }

    function testRegisterEnclaveKeyAllowedAdvisoryID() public {
        string memory clientId = "lcp-zkdcap";
        {
            TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
                address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
            );
            vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP);
            IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
            clientState.allowed_advisory_ids = new string[](0);
            lc.initializeClient(
                clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
            );
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.advisoryIDs = new string[](1);
            output.advisoryIDs[0] = "INTEL-SA-00001";
            vm.expectRevert(abi.encodeWithSelector(ILCPClientErrors.LCPClientZKDCAPDisallowedAdvisoryID.selector));
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
        }
        {
            TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
                address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
            );
            vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP);
            IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
            clientState.allowed_advisory_ids = new string[](1);
            clientState.allowed_advisory_ids[0] = "INTEL-SA-00001";
            lc.initializeClient(
                clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
            );
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.advisoryIDs = new string[](1);
            output.advisoryIDs[0] = "INTEL-SA-00002";
            vm.expectRevert(abi.encodeWithSelector(ILCPClientErrors.LCPClientZKDCAPDisallowedAdvisoryID.selector));
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
        }
        {
            TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
                address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
            );
            vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP);
            IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
            clientState.allowed_advisory_ids = new string[](1);
            clientState.allowed_advisory_ids[0] = "INTEL-SA-00001";
            lc.initializeClient(
                clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
            );
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.advisoryIDs = new string[](1);
            output.advisoryIDs[0] = "INTEL-SA-00001";
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
        }
    }

    function testRegisterEnclaveKeyOperatorsSet() public {
        Vm.Wallet memory op1 = vm.createWallet("op1");
        Vm.Wallet memory op2 = vm.createWallet("op2");
        Vm.Wallet memory op3 = vm.createWallet("op3");

        string memory clientId = "lcp-zkdcap";
        TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        clientState.operators_threshold_denominator = 1;
        clientState.operators_threshold_numerator = 1;
        clientState.operators = new bytes[](2);
        clientState.operators[0] = abi.encodePacked(op3.addr);
        clientState.operators[1] = abi.encodePacked(op1.addr);
        lc.initializeClient(
            clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
        );
        vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP);

        {
            // if the operator is set and operator signature is not set, it should fail
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.operator = op1.addr;
            IbcLightclientsLcpV1ZKDCAPRegisterEnclaveKeyMessage.Data memory message = registerEnclaveKeyMessage(output);
            vm.expectRevert(
                abi.encodeWithSelector(
                    ILCPClientErrors.LCPClientZKDCAPOutputReportUnexpectedOperator.selector, address(0), output.operator
                )
            );
            lc.zkDCAPRegisterEnclaveKey(clientId, message);
        }

        {
            // if the operator signature is set by a different operator, it should fail
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.operator = op1.addr;
            IbcLightclientsLcpV1ZKDCAPRegisterEnclaveKeyMessage.Data memory message = registerEnclaveKeyMessage(output);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                op2,
                keccak256(
                    LCPOperator.computeEIP712ZKDCAPRegisterEnclaveKey(
                        clientState.zkdcap_verifier_infos[0], keccak256(ZKDCAPTestHelper.toBytes(output))
                    )
                )
            );
            message.operator_signature = abi.encodePacked(r, s, v);
            vm.expectRevert(
                abi.encodeWithSelector(
                    ILCPClientErrors.LCPClientZKDCAPOutputReportUnexpectedOperator.selector, op2.addr, op1.addr
                )
            );
            lc.zkDCAPRegisterEnclaveKey(clientId, message);
        }

        {
            // if the operator signature is set by the correct operator, it should succeed
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.enclaveKey = address(1);
            output.operator = op1.addr;
            IbcLightclientsLcpV1ZKDCAPRegisterEnclaveKeyMessage.Data memory message = registerEnclaveKeyMessage(output);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                op1,
                keccak256(
                    LCPOperator.computeEIP712ZKDCAPRegisterEnclaveKey(
                        clientState.zkdcap_verifier_infos[0], keccak256(ZKDCAPTestHelper.toBytes(output))
                    )
                )
            );
            message.operator_signature = abi.encodePacked(r, s, v);
            lc.zkDCAPRegisterEnclaveKey(clientId, message);
            assertEq(lc.getEKInfo(clientId, output.enclaveKey).operator, op1.addr);
        }

        {
            // if both operator and operator signature are not set, it should succeed
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.enclaveKey = address(2);
            IbcLightclientsLcpV1ZKDCAPRegisterEnclaveKeyMessage.Data memory message = registerEnclaveKeyMessage(output);
            lc.zkDCAPRegisterEnclaveKey(clientId, message);
            assertEq(lc.getEKInfo(clientId, output.enclaveKey).operator, address(0));
        }

        {
            // if re-registering the same enclave key with a different operator, it should fail
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.enclaveKey = address(1);
            output.operator = op1.addr;
            IbcLightclientsLcpV1ZKDCAPRegisterEnclaveKeyMessage.Data memory message = registerEnclaveKeyMessage(output);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                op3,
                keccak256(
                    LCPOperator.computeEIP712ZKDCAPRegisterEnclaveKey(
                        clientState.zkdcap_verifier_infos[0], keccak256(ZKDCAPTestHelper.toBytes(output))
                    )
                )
            );
            message.operator_signature = abi.encodePacked(r, s, v);
            vm.expectRevert(
                abi.encodeWithSelector(
                    ILCPClientErrors.LCPClientZKDCAPOutputReportUnexpectedOperator.selector, op3.addr, op1.addr
                )
            );
            lc.zkDCAPRegisterEnclaveKey(clientId, message);
        }
    }

    function testRegisterEnclaveKeyOperatorsNotSet() public {
        Vm.Wallet memory op1 = vm.createWallet("op1");

        string memory clientId = "lcp-zkdcap";
        TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        lc.initializeClient(
            clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(defaultConsensusState())
        );

        {
            // if the operator signature is set, it should succeed
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.enclaveKey = address(1);
            output.operator = op1.addr;
            vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP);

            IbcLightclientsLcpV1ZKDCAPRegisterEnclaveKeyMessage.Data memory message = registerEnclaveKeyMessage(output);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                op1,
                keccak256(
                    LCPOperator.computeEIP712ZKDCAPRegisterEnclaveKey(
                        clientState.zkdcap_verifier_infos[0], keccak256(ZKDCAPTestHelper.toBytes(output))
                    )
                )
            );
            message.operator_signature = abi.encodePacked(r, s, v);
            lc.zkDCAPRegisterEnclaveKey(clientId, message);
            assertEq(lc.getEKInfo(clientId, output.enclaveKey).operator, op1.addr);
        }

        {
            // if the operator signature is not set, it also should succeed
            DCAPValidator.Output memory output = ZKDCAPTestHelper.qvOutput();
            output.enclaveKey = address(2);
            lc.zkDCAPRegisterEnclaveKey(clientId, registerEnclaveKeyMessage(output));
            assertEq(lc.getEKInfo(clientId, output.enclaveKey).operator, address(0));
        }
    }

    function testInitializeClientInvalidVerifierInfos() public {
        string memory clientId = "lcp-zkdcap";
        TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP);
        bytes memory consensusStateBytes = LCPProtoMarshaler.marshal(defaultConsensusState());
        IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
        bytes memory valid_zkdcap_verifier_info = clientState.zkdcap_verifier_infos[0];
        clientState.zkdcap_verifier_infos[0] = new bytes(0);
        bytes memory clientStateBytes = LCPProtoMarshaler.marshal(clientState);
        vm.expectRevert();
        lc.initializeClient(clientId, clientStateBytes, consensusStateBytes);

        clientState.zkdcap_verifier_infos[0] = new bytes(1);
        clientStateBytes = LCPProtoMarshaler.marshal(clientState);
        vm.expectRevert();
        lc.initializeClient(clientId, clientStateBytes, consensusStateBytes);

        clientState.zkdcap_verifier_infos = new bytes[](0);
        clientStateBytes = LCPProtoMarshaler.marshal(clientState);
        vm.expectRevert();
        lc.initializeClient(clientId, clientStateBytes, consensusStateBytes);

        clientState.zkdcap_verifier_infos = new bytes[](2);
        clientStateBytes = LCPProtoMarshaler.marshal(clientState);
        vm.expectRevert();
        lc.initializeClient(clientId, clientStateBytes, consensusStateBytes);

        clientState.zkdcap_verifier_infos = new bytes[](1);
        clientState.zkdcap_verifier_infos[0] = abi.encodePacked(valid_zkdcap_verifier_info, bytes1(0x0));
        clientStateBytes = LCPProtoMarshaler.marshal(clientState);
        vm.expectRevert();
        lc.initializeClient(clientId, clientStateBytes, consensusStateBytes);
    }

    function testInitializeClientInvalidValues() public {
        string memory clientId = "lcp-zkdcap";
        TestLCPClientZKDCAPExtended lc = new TestLCPClientZKDCAPExtended(
            address(this), false, ZKDCAPTestHelper.dummyIntelRootCACert(), address(new NopRiscZeroVerifier())
        );
        vm.warp(ZKDCAPTestHelper.TEST_TIMESTAMP);
        bytes memory consensusStateBytes = LCPProtoMarshaler.marshal(defaultConsensusState());

        {
            // `current_tcb_evaluation_data_number` is not set
            IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
            clientState.current_tcb_evaluation_data_number = 0;
            bytes memory clientStateBytes = LCPProtoMarshaler.marshal(clientState);
            vm.expectRevert(ILCPClientErrors.LCPClientZKDCAPCurrentTcbEvaluationDataNumberNotSet.selector);
            lc.initializeClient(clientId, clientStateBytes, consensusStateBytes);
        }
        {
            // if `next_tcb_evaluation_data_number` is set, `next_tcb_evaluation_data_number_update_time` should be set
            IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
            clientState.next_tcb_evaluation_data_number = 1;
            clientState.next_tcb_evaluation_data_number_update_time = 0;
            bytes memory clientStateBytes = LCPProtoMarshaler.marshal(clientState);
            vm.expectRevert(ILCPClientErrors.LCPClientZKDCAPInvalidNextTcbEvaluationDataNumberInfo.selector);
            lc.initializeClient(clientId, clientStateBytes, consensusStateBytes);
        }
        {
            // if `next_tcb_evaluation_data_number_update_time` is set, `next_tcb_evaluation_data_number` should be set
            IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
            clientState.next_tcb_evaluation_data_number = 0;
            clientState.next_tcb_evaluation_data_number_update_time = uint64(block.timestamp) + 1;
            bytes memory clientStateBytes = LCPProtoMarshaler.marshal(clientState);
            vm.expectRevert(ILCPClientErrors.LCPClientZKDCAPInvalidNextTcbEvaluationDataNumberInfo.selector);
            lc.initializeClient(clientId, clientStateBytes, consensusStateBytes);
        }
        {
            // if `next_tcb_evaluation_data_number` is set, the value should not be equal to `current_tcb_evaluation_data_number`
            IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
            clientState.current_tcb_evaluation_data_number = 1;
            clientState.next_tcb_evaluation_data_number = 1;
            clientState.next_tcb_evaluation_data_number_update_time = uint64(block.timestamp) + 1;
            bytes memory clientStateBytes = LCPProtoMarshaler.marshal(clientState);
            vm.expectRevert(ILCPClientErrors.LCPClientZKDCAPInvalidNextTcbEvaluationDataNumberInfo.selector);
            lc.initializeClient(clientId, clientStateBytes, consensusStateBytes);
        }
        {
            // if `next_tcb_evaluation_data_number` is set, the value should be greater than `current_tcb_evaluation_data_number`
            IbcLightclientsLcpV1ClientState.Data memory clientState = defaultClientState();
            clientState.current_tcb_evaluation_data_number = 2;
            clientState.next_tcb_evaluation_data_number = 1;
            clientState.next_tcb_evaluation_data_number_update_time = uint64(block.timestamp) + 1;
            bytes memory clientStateBytes = LCPProtoMarshaler.marshal(clientState);
            vm.expectRevert(ILCPClientErrors.LCPClientZKDCAPInvalidNextTcbEvaluationDataNumberInfo.selector);
            lc.initializeClient(clientId, clientStateBytes, consensusStateBytes);
        }
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

library ZKDCAPTestHelper {
    bytes32 constant TEST_INTEL_ROOT_CA_HASH = keccak256(abi.encodePacked("sgx intel root ca hash"));
    bytes32 constant TEST_MRENCLAVE = keccak256(abi.encodePacked("mrenclave"));
    bytes32 constant TEST_RISC_ZERO_IMAGE_ID = keccak256(abi.encodePacked("image_id"));

    uint64 constant TEST_TIMESTAMP = 1740842723;

    function qvOutput() internal pure returns (DCAPValidator.Output memory output) {
        output.tcbStatus = DCAPValidator.TCB_STATUS_UP_TO_DATE_STRING;
        output.minTcbEvaluationDataNumber = 1;
        output.sgxIntelRootCAHash = ZKDCAPTestHelper.TEST_INTEL_ROOT_CA_HASH;
        output.validityNotBefore = TEST_TIMESTAMP;
        output.validityNotAfter = output.validityNotBefore + 30 days;
        output.enclaveDebugEnabled = false;
        output.mrenclave = ZKDCAPTestHelper.TEST_MRENCLAVE;
        output.enclaveKey = address(1);
        output.operator = address(0);
        return output;
    }

    function dummyIntelRootCACert() internal pure returns (bytes memory) {
        return abi.encodePacked("sgx intel root ca hash");
    }

    function buildRiscZeroVerifierInfos(bytes32 imageId) internal returns (bytes[] memory infos) {
        // The format is as follows:
        // 0: zkVM type
        // 1-N: arbitrary data for each zkVM type
        //
        // The format of the risc0 zkVM is as follows:
        // | 0 |  1 - 31  |  32 - 64  |
        // |---|----------|-----------|
        // | 1 | reserved | image id  |
        bytes memory verifierInfo = new bytes(64);
        verifierInfo[0] = 0x01;
        assembly {
            mstore(add(add(verifierInfo, 32), 32), imageId)
        }
        infos = new bytes[](1);
        infos[0] = verifierInfo;
        return infos;
    }

    function toBytes(DCAPValidator.Output memory output) internal pure returns (bytes memory) {
        bytes memory result = hex"0000"; // 0..2: version (2 bytes)
        result = BytesLib.concat(result, hex"0003"); // 2..4: quote version (2 bytes)
        result = BytesLib.concat(result, hex"00000000"); // 4..8: tee type (4 bytes)

        // 8: tcb status (1 byte)
        result = BytesLib.concat(result, abi.encodePacked(_tcbStatusFromString(output.tcbStatus)));

        // 9..13: min tcb evaluation data number (4 bytes)
        result = BytesLib.concat(result, abi.encodePacked(output.minTcbEvaluationDataNumber));

        // 13..19: 6 bytes zero padding
        result = BytesLib.concat(result, new bytes(6));

        // 19..51: sgx intel root ca hash (32 bytes)
        result = BytesLib.concat(result, abi.encodePacked(output.sgxIntelRootCAHash));

        // 51..59: validity not before (8 bytes)
        result = BytesLib.concat(result, abi.encodePacked(output.validityNotBefore));

        // 59..67: validity not after (8 bytes)
        result = BytesLib.concat(result, abi.encodePacked(output.validityNotAfter));

        // 67..115: 48 bytes zero padding
        result = BytesLib.concat(result, new bytes(48));

        // 115: attributes (1 byte: 0x00 for enclave debug disabled, 0x02 for enclave debug enabled)
        bytes1 attributesByte = output.enclaveDebugEnabled ? bytes1(0x02) : bytes1(0x00);
        result = BytesLib.concat(result, abi.encodePacked(attributesByte));

        // 116..131: 15 bytes zero padding
        result = BytesLib.concat(result, new bytes(15));

        // 131..163: mrenclave (32 bytes)
        result = BytesLib.concat(result, abi.encodePacked(output.mrenclave));

        // 163..387: 224 bytes zero padding
        result = BytesLib.concat(result, new bytes(224));

        // 387..451: report data (64 bytes)
        // Format: 1 byte report data version (0x01)
        //        20 bytes enclaveKey, 20 bytes operator, 23 bytes zero padding
        result = BytesLib.concat(
            result, abi.encodePacked(uint8(0x01), bytes20(output.enclaveKey), bytes20(output.operator), new bytes(23))
        );

        // 451..end: advisory IDs
        result = BytesLib.concat(result, abi.encode(output.advisoryIDs));

        return result;
    }

    function _tcbStatusFromString(string memory tcbStatus) internal pure returns (uint8) {
        if (keccak256(bytes(tcbStatus)) == keccak256(bytes(DCAPValidator.TCB_STATUS_UP_TO_DATE_STRING))) {
            return DCAPValidator.TCB_STATUS_UP_TO_DATE;
        } else if (keccak256(bytes(tcbStatus)) == keccak256(bytes(DCAPValidator.TCB_STATUS_OUT_OF_DATE_STRING))) {
            return DCAPValidator.TCB_STATUS_OUT_OF_DATE;
        } else if (keccak256(bytes(tcbStatus)) == keccak256(bytes(DCAPValidator.TCB_STATUS_REVOKED_STRING))) {
            return DCAPValidator.TCB_STATUS_REVOKED;
        } else if (
            keccak256(bytes(tcbStatus)) == keccak256(bytes(DCAPValidator.TCB_STATUS_CONFIGURATION_NEEDED_STRING))
        ) {
            return DCAPValidator.TCB_STATUS_CONFIGURATION_NEEDED;
        } else if (
            keccak256(bytes(tcbStatus))
                == keccak256(bytes(DCAPValidator.TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED_STRING))
        ) {
            return DCAPValidator.TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED;
        } else if (keccak256(bytes(tcbStatus)) == keccak256(bytes(DCAPValidator.TCB_STATUS_SW_HARDENING_NEEDED_STRING)))
        {
            return DCAPValidator.TCB_STATUS_SW_HARDENING_NEEDED;
        } else if (
            keccak256(bytes(tcbStatus))
                == keccak256(bytes(DCAPValidator.TCB_STATUS_CONFIGURATION_AND_SW_HARDENING_NEEDED_STRING))
        ) {
            return DCAPValidator.TCB_STATUS_CONFIGURATION_AND_SW_HARDENING_NEEDED;
        } else {
            revert("unexpected TCB status");
        }
    }
}

contract NopRiscZeroVerifier is IRiscZeroVerifier {
    function verify(bytes calldata seal, bytes32 imageId, bytes32) public view override {
        require(seal.length == 5, "unexpected seal length");
        require(imageId == ZKDCAPTestHelper.TEST_RISC_ZERO_IMAGE_ID, "unexpected image id");
    }

    function verifyIntegrity(Receipt calldata) external view {}
}
