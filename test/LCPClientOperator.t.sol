// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {IBCHeight} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/IBCHeight.sol";
import "./TestHelper.t.sol";
import "../contracts/LCPClient.sol";
import {LCPProtoMarshaler} from "../contracts/LCPProtoMarshaler.sol";
import {ILCPClientErrors} from "../contracts/ILCPClientErrors.sol";
import {
    IbcLightclientsLcpV1ClientState as ClientState,
    IbcLightclientsLcpV1ConsensusState as ConsensusState,
    IbcLightclientsLcpV1RegisterEnclaveKeyMessage as RegisterEnclaveKeyMessage,
    IbcLightclientsLcpV1UpdateClientMessage as UpdateClientMessage,
    IbcLightclientsLcpV1UpdateOperatorsMessage as UpdateOperatorsMessage
} from "../contracts/proto/ibc/lightclients/lcp/v1/LCP.sol";

contract LCPClientOperatorTest is BasicTest {
    using IBCHeight for Height.Data;

    string internal constant commandAvrFile = "test/data/client/03/001-avr";
    string internal constant commandResultSuffix = "_result";

    LCPClient lc;

    function setUp() public {
        vm.warp(1717779842);
        lc = new LCPClient(address(this), true, vm.readFileBinary("./test/data/certs/simulation_rootca.der"));
    }

    function avr(string memory filename) internal pure returns (string memory) {
        return string(abi.encodePacked("test/data/client/03/", filename));
    }

    function testRegisterEnclaveKeyOperatorValidation() public {
        Vm.Wallet[] memory wallets = createWallets(2);
        (Vm.Wallet memory validW, Vm.Wallet memory invalidW) = (wallets[0], wallets[1]);
        address[] memory operators = new address[](1);
        operators[0] = validW.addr;
        string memory clientId = generateClientId(1);
        {
            ClientState.Data memory clientState = createInitialState(commandAvrFile, operators, 1, 1);
            ConsensusState.Data memory consensusState;
            Height.Data memory height = lc.initializeClient(
                clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(consensusState)
            );
            require(height.eq(clientState.latest_height));
        }
        // invalid operator but report is valid
        {
            RegisterEnclaveKeyMessage.Data memory message =
                createRegisterEnclaveKeyMessage(commandAvrFile, clientId, 0, invalidW.privateKey);
            vm.expectRevert(
                abi.encodeWithSelector(
                    ILCPClientErrors.LCPClientRegisterEnclaveKeyUnexpectedOperator.selector,
                    0,
                    invalidW.addr,
                    validW.addr
                )
            );
            lc.registerEnclaveKey(clientId, message);
        }
        // both operator and report are valid
        {
            RegisterEnclaveKeyMessage.Data memory message =
                createRegisterEnclaveKeyMessage(commandAvrFile, clientId, 0, validW.privateKey);
            lc.registerEnclaveKey(clientId, message);
        }
    }

    function testRegisterEnclaveKeyMultiOperators() public {
        Vm.Wallet[] memory wallets = createWallets(2);
        address[] memory operators = new address[](wallets.length);
        for (uint256 i = 0; i < wallets.length; i++) {
            operators[i] = wallets[i].addr;
        }
        string memory clientId = generateClientId(1);
        {
            ClientState.Data memory clientState = createInitialState(avr("001-avr"), operators, 1, 1);
            ConsensusState.Data memory consensusState;
            Height.Data memory height = lc.initializeClient(
                clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(consensusState)
            );
            require(height.eq(clientState.latest_height));
        }
        // both operator and report are valid
        {
            RegisterEnclaveKeyMessage.Data memory message =
                createRegisterEnclaveKeyMessage(avr("001-avr"), clientId, 0, wallets[0].privateKey);
            lc.registerEnclaveKey(clientId, message);
        }
        // report is valid but operator is invalid
        {
            RegisterEnclaveKeyMessage.Data memory message =
                createRegisterEnclaveKeyMessage(avr("001-avr"), clientId, 1, wallets[1].privateKey);
            vm.expectRevert(
                abi.encodeWithSelector(
                    ILCPClientErrors.LCPClientEnclaveKeyUnexpectedOperator.selector, operators[0], operators[1]
                )
            );
            lc.registerEnclaveKey(clientId, message);
        }
        // both operator and report are valid
        {
            RegisterEnclaveKeyMessage.Data memory message =
                createRegisterEnclaveKeyMessage(avr("002-avr"), clientId, 1, wallets[1].privateKey);
            lc.registerEnclaveKey(clientId, message);
        }
        // both operator and report are valid
        {
            RegisterEnclaveKeyMessage.Data memory message =
                createRegisterEnclaveKeyMessage(avr("003-avr"), clientId, 0, wallets[0].privateKey);
            lc.registerEnclaveKey(clientId, message);
        }
        // both operator and report are valid
        {
            RegisterEnclaveKeyMessage.Data memory message =
                createRegisterEnclaveKeyMessage(avr("004-avr"), clientId, 1, wallets[1].privateKey);
            lc.registerEnclaveKey(clientId, message);
        }
    }

    function testUpdateClientMultiOperators() public {
        Vm.Wallet[] memory wallets = createWallets(4);
        address[] memory operators = new address[](wallets.length);
        for (uint256 i = 0; i < wallets.length; i++) {
            operators[i] = wallets[i].addr;
        }
        string memory clientId = generateClientId(1);
        {
            ClientState.Data memory clientState = createInitialState(commandAvrFile, operators, 2, 3);
            ConsensusState.Data memory consensusState;
            Height.Data memory height = lc.initializeClient(
                clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(consensusState)
            );
            require(height.eq(clientState.latest_height));
        }

        lc.registerEnclaveKey(
            clientId, createRegisterEnclaveKeyMessage(avr("001-avr"), clientId, 0, wallets[0].privateKey)
        );
        lc.registerEnclaveKey(
            clientId, createRegisterEnclaveKeyMessage(avr("002-avr"), clientId, 1, wallets[1].privateKey)
        );
        lc.registerEnclaveKey(
            clientId, createRegisterEnclaveKeyMessage(avr("003-avr"), clientId, 2, wallets[2].privateKey)
        );
        lc.registerEnclaveKey(
            clientId, createRegisterEnclaveKeyMessage(avr("004-avr"), clientId, 3, wallets[3].privateKey)
        );

        lc.updateClient(
            clientId,
            createUpdateClientMessage(
                "test/data/client/03/",
                [
                    "006-update_client_result",
                    "007-update_client_result",
                    "008-update_client_result",
                    "009-update_client_result"
                ]
            )
        );
        string[4] memory inputs = [
            "010-update_client_result",
            "011-update_client_result",
            "012-update_client_result",
            "013-update_client_result"
        ];
        // OK
        lc.updateClient(clientId, createUpdateClientMessage("test/data/client/03/", inputs));
        // Same update message but OK
        lc.updateClient(clientId, createUpdateClientMessage("test/data/client/03/", inputs));
        // operator index 0 is invalid
        {
            UpdateClientMessage.Data memory message = createUpdateClientMessage("test/data/client/03/", inputs);
            message.signers[0] = new bytes(0);
            message.signatures[0] = new bytes(0);
            lc.updateClient(clientId, message);
        }
        {
            UpdateClientMessage.Data memory message = createUpdateClientMessage("test/data/client/03/", inputs);
            message.signers[0] = new bytes(0);
            message.signatures[0] = new bytes(0);
            message.signers[1] = new bytes(0);
            message.signatures[1] = new bytes(0);
            vm.expectRevert(
                abi.encodeWithSelector(ILCPClientErrors.LCPClientOperatorSignaturesInsufficient.selector, 2)
            );
            lc.updateClient(clientId, message);
        }
        {
            UpdateClientMessage.Data memory message = createUpdateClientMessage("test/data/client/03/", inputs);
            (message.signers[0], message.signatures[0], message.signers[1], message.signatures[1]) =
                (message.signers[1], message.signatures[1], message.signers[0], message.signatures[0]);
            vm.expectRevert(
                abi.encodeWithSelector(
                    ILCPClientErrors.LCPClientEnclaveKeyUnexpectedOperator.selector, operators[1], operators[0]
                )
            );
            lc.updateClient(clientId, message);
        }
    }

    function testUpdateOperators() public {
        Vm.Wallet[] memory wallets = createWallets(4);
        address[] memory operators = new address[](wallets.length);
        for (uint256 i = 0; i < wallets.length; i++) {
            operators[i] = wallets[i].addr;
        }
        string memory clientId = generateClientId(1);
        {
            ClientState.Data memory clientState = createInitialState(commandAvrFile, operators, 2, 3);
            ConsensusState.Data memory consensusState;
            Height.Data memory height = lc.initializeClient(
                clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(consensusState)
            );
            require(height.eq(clientState.latest_height));
        }
        uint64 nextNonce = 2;
        {
            bytes[] memory signatures = generateSignatures(
                wallets,
                keccak256(
                    LCPOperatorTestHelper.computeEIP712UpdateOperators(
                        block.chainid, address(lc), clientId, nextNonce, operators
                    )
                ),
                genValidIndices([true, true, true, true])
            );
            UpdateOperatorsMessage.Data memory message = createUpdateOperators(nextNonce, operators, signatures);
            lc.updateOperators(clientId, message);
            nextNonce++;
        }
        {
            bytes[] memory signatures = generateSignatures(
                wallets,
                keccak256(
                    LCPOperatorTestHelper.computeEIP712UpdateOperators(
                        block.chainid, address(lc), clientId, nextNonce, operators
                    )
                ),
                genValidIndices([false, true, true, true])
            );
            UpdateOperatorsMessage.Data memory message = createUpdateOperators(nextNonce, operators, signatures);
            lc.updateOperators(clientId, message);
            nextNonce++;
        }
        {
            bytes[] memory signatures = generateSignatures(
                wallets,
                keccak256(
                    LCPOperatorTestHelper.computeEIP712UpdateOperators(
                        block.chainid, address(lc), clientId, nextNonce, operators
                    )
                ),
                genValidIndices([false, true, true, false])
            );
            UpdateOperatorsMessage.Data memory message = createUpdateOperators(nextNonce, operators, signatures);
            vm.expectRevert(
                abi.encodeWithSelector(ILCPClientErrors.LCPClientOperatorSignaturesInsufficient.selector, 2)
            );
            lc.updateOperators(clientId, message);
        }
        {
            bytes[] memory signatures = generateSignatures(
                wallets,
                keccak256(
                    LCPOperatorTestHelper.computeEIP712UpdateOperators(
                        block.chainid, address(lc), clientId, nextNonce, operators
                    )
                ),
                genValidIndices([false, false, false, false])
            );
            UpdateOperatorsMessage.Data memory message = createUpdateOperators(nextNonce, operators, signatures);
            vm.expectRevert(
                abi.encodeWithSelector(ILCPClientErrors.LCPClientOperatorSignaturesInsufficient.selector, 0)
            );
            lc.updateOperators(clientId, message);
        }
        {
            bytes[] memory signatures = generateSignatures(
                wallets,
                keccak256(
                    LCPOperatorTestHelper.computeEIP712UpdateOperators(
                        block.chainid, address(lc), clientId, nextNonce, operators
                    )
                ),
                genValidIndices([true, true, true, true])
            );
            // signatures are valid but duplicated
            (signatures[1], signatures[2], signatures[3]) = (signatures[0], signatures[0], signatures[0]);
            UpdateOperatorsMessage.Data memory message = createUpdateOperators(nextNonce, operators, signatures);
            vm.expectRevert(
                abi.encodeWithSelector(ILCPClientErrors.LCPClientOperatorSignaturesInsufficient.selector, 1)
            );
            lc.updateOperators(clientId, message);
        }
    }

    function generateSignature(Vm.Wallet memory wallet, bytes32 commitment, bool valid)
        internal
        pure
        returns (bytes memory)
    {
        Vm.Wallet[] memory wallets = new Vm.Wallet[](1);
        wallets[0] = wallet;
        bool[] memory validIndices = new bool[](1);
        validIndices[0] = valid;
        return generateSignatures(wallets, commitment, validIndices)[0];
    }

    function generateSignatures(Vm.Wallet[] memory wallets, bytes32 commitment, bool[] memory validIndices)
        internal
        pure
        returns (bytes[] memory)
    {
        require(wallets.length == validIndices.length, "invalid length");
        bytes[] memory signatures = new bytes[](wallets.length);
        for (uint256 i = 0; i < wallets.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallets[i].privateKey, commitment);
            if (validIndices[i]) {
                signatures[i] = abi.encodePacked(r, s, v);
            } else {
                signatures[i] = new bytes(0);
            }
        }
        return signatures;
    }

    function genValidIndices(bool[4] memory validIndices) internal pure returns (bool[] memory) {
        bool[] memory res = new bool[](4);
        for (uint256 i = 0; i < 4; i++) {
            res[i] = validIndices[i];
        }
        return res;
    }

    function createInitialState(
        string memory avrFile,
        address[] memory operators,
        uint64 thresholdNumerator,
        uint64 thresholdDenominator
    ) internal returns (ClientState.Data memory clientState) {
        bytes memory mrenclave = readDecodedBytes(avrFile, ".mrenclave");
        require(mrenclave.length == 32, "the length must be 32");

        // Note `latest_height` must be zero height
        clientState.mrenclave = mrenclave;
        clientState.key_expiration = 60 * 60 * 24 * 7;
        clientState.frozen = false;

        clientState.operators = new bytes[](operators.length);
        for (uint256 i = 0; i < operators.length; i++) {
            clientState.operators[i] = abi.encodePacked(operators[i]);
        }
        clientState.operators_nonce = 1;
        clientState.operators_threshold_numerator = thresholdNumerator;
        clientState.operators_threshold_denominator = thresholdDenominator;

        // WARNING: the following configuration is for testing purpose only
        clientState.allowed_quote_statuses = new string[](1);
        clientState.allowed_quote_statuses[0] = readNestedString(avrFile, ".avr", ".isvEnclaveQuoteStatus");
        clientState.allowed_advisory_ids = readNestedStringArray(avrFile, ".avr", ".advisoryIDs");
    }

    function createRegisterEnclaveKeyMessage(
        string memory avrFile,
        string memory clientId,
        uint64 operatorIndex,
        uint256 privateKey
    ) internal returns (RegisterEnclaveKeyMessage.Data memory message) {
        message.report = string(readJSON(avrFile, ".avr"));
        message.signature = readDecodedBytes(avrFile, ".signature");
        message.signing_cert = readDecodedBytes(avrFile, ".signing_cert");
        message.operator_index = operatorIndex;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey,
            keccak256(
                LCPOperatorTestHelper.computeEIP712RegisterEnclaveKey(
                    block.chainid, address(lc), clientId, message.report
                )
            )
        );
        message.operator_signature = abi.encodePacked(r, s, v);
    }

    function createUpdateClientMessage(string memory updateClientFilePrefix)
        internal
        returns (UpdateClientMessage.Data memory message)
    {
        message.proxy_message =
            readDecodedBytes(string(abi.encodePacked(updateClientFilePrefix, commandResultSuffix)), ".message");
        message.signers = new bytes[](1);
        message.signers[0] =
            readDecodedBytes(string(abi.encodePacked(updateClientFilePrefix, commandResultSuffix)), ".signer");
        message.signatures = new bytes[](1);
        message.signatures[0] =
            readDecodedBytes(string(abi.encodePacked(updateClientFilePrefix, commandResultSuffix)), ".signature");
    }

    function createUpdateClientMessage(string memory dir, string[] memory prefixes)
        internal
        returns (UpdateClientMessage.Data memory message)
    {
        message.signers = new bytes[](prefixes.length);
        message.signatures = new bytes[](prefixes.length);
        for (uint256 i = 0; i < prefixes.length; i++) {
            string memory path = string(abi.encodePacked(dir, prefixes[i]));
            message.proxy_message = readDecodedBytes(path, ".message");
            message.signers[i] = readDecodedBytes(path, ".signer");
            message.signatures[i] = readDecodedBytes(path, ".signature");
        }
    }

    function createUpdateClientMessage(string memory dir, string[4] memory prefixes)
        internal
        returns (UpdateClientMessage.Data memory message)
    {
        string[] memory prefixes_ = new string[](4);
        for (uint256 i = 0; i < 4; i++) {
            prefixes_[i] = prefixes[i];
        }
        return createUpdateClientMessage(dir, prefixes_);
    }

    function createUpdateOperators(uint64 nonce, address[] memory newOperators, bytes[] memory signatures)
        internal
        pure
        returns (UpdateOperatorsMessage.Data memory message)
    {
        message.nonce = nonce;
        message.new_operators = new bytes[](newOperators.length);
        for (uint256 i = 0; i < newOperators.length; i++) {
            message.new_operators[i] = abi.encodePacked(newOperators[i]);
        }
        message.signatures = signatures;
    }
}
