// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/utils/Strings.sol";
import "@ensdomains/ens-contracts/contracts/dnssec-oracle/BytesUtils.sol";
import {IBCHeight} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/IBCHeight.sol";
import "../contracts/LCPClientIAS.sol";
import "../contracts/LCPClientIASBase.sol";
import {
    IbcLightclientsLcpV1ClientState as ClientState,
    IbcLightclientsLcpV1ConsensusState as ConsensusState,
    IbcLightclientsLcpV1RegisterEnclaveKeyMessage as RegisterEnclaveKeyMessage,
    IbcLightclientsLcpV1UpdateClientMessage as UpdateClientMessage
} from "../contracts/proto/ibc/lightclients/lcp/v1/LCP.sol";
import "../contracts/LCPCommitment.sol";
import "../contracts/LCPUtils.sol";
import {LCPProtoMarshaler} from "../contracts/LCPProtoMarshaler.sol";
import "./TestHelper.t.sol";

contract LCPClientTest is BasicTest {
    using BytesUtils for bytes;
    using IBCHeight for Height.Data;

    TestContext testContext;
    LCPClientIAS iasLC;
    LCPClientIAS simulationLC;

    string internal constant baseDir = "test/data/client";
    uint256 internal constant commandNumberPrefixLength = 4; // "000-"
    string internal constant commandInputSuffix = "_input"; // e.g. 003_update_client_input
    string internal constant commandResultSuffix = "_result"; // e.g. 003_update_client_result
    uint256 internal constant commandInputSuffixLength = 6; // "_input"

    struct TestContext {
        string dir;
        LCPClientIAS lc;
        Vm.Wallet opWallet;
    }

    function setTestContext(TestContext memory tc) internal {
        testContext = tc;
    }

    function setUp() public {
        vm.warp(1692703263);
        iasLC = new LCPClientIAS(
            address(this), true, vm.readFileBinary("./test/data/certs/Intel_SGX_Attestation_RootCA.der")
        );
        require(iasLC.isDevelopmentMode() == true, "developmentMode must be true");
        simulationLC =
            new LCPClientIAS(address(this), true, vm.readFileBinary("./test/data/certs/simulation_rootca.der"));
    }

    function testIASClientPermissioned() public {
        vm.warp(1718464245);
        setTestContext(TestContext("01", iasLC, vm.createWallet("alice")));
        testLightClient(generateClientId(1), true, "001-avr", 3);
    }

    function testIASClientPermissionless() public {
        vm.warp(1718464245);
        setTestContext(TestContext("01", iasLC, vm.createWallet("alice")));
        testLightClient(generateClientId(1), false, "001-avr", 3);
    }

    function testSimulationClientPermissioned() public {
        vm.warp(1718461269);
        setTestContext(TestContext("02", simulationLC, vm.createWallet("alice")));
        testLightClient(generateClientId(1), true, "001-avr", 3);
    }

    function testSimulationClientPermissionless() public {
        vm.warp(1718461269);
        setTestContext(TestContext("02", simulationLC, vm.createWallet("alice")));
        testLightClient(generateClientId(1), false, "001-avr", 3);
    }

    event RegisteredEnclaveKey(string clientId, address enclaveKey, uint256 expiredAt, address operator);

    function testLightClient(
        string memory clientId,
        bool permissioned,
        string memory commandAvrFile,
        uint256 commandStartNumber
    ) internal {
        LCPClientIAS lc = testContext.lc;
        {
            ClientState.Data memory clientState;
            address[] memory opWallets;
            if (permissioned) {
                opWallets = new address[](1);
                opWallets[0] = testContext.opWallet.addr;
                clientState = createInitialState(commandAvrFile, opWallets);
            } else {
                clientState = createInitialState(commandAvrFile, opWallets, 0, 0);
            }
            ConsensusState.Data memory consensusState;
            Height.Data memory height = lc.initializeClient(
                clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(consensusState)
            );
            require(height.eq(clientState.latest_height));
        }
        {
            RegisterEnclaveKeyMessage.Data memory message =
                createRegisterEnclaveKeyMessage(commandAvrFile, testContext.opWallet);
            vm.expectEmit(false, false, false, false);
            emit RegisteredEnclaveKey(clientId, address(0), 0, address(0));
            Height.Data[] memory heights = lc.registerEnclaveKey(clientId, message);
            require(heights.length == 0);
        }

        {
            RegisterEnclaveKeyMessage.Data memory message =
                createRegisterEnclaveKeyMessage(commandAvrFile, testContext.opWallet);
            // the following staticcall is expected to succeed because registerEnclaveKey does not update the state if the message contains an enclave key already registered
            (bool success,) = address(lc).staticcall(
                abi.encodeWithSelector(LCPClientIASBase.registerEnclaveKey.selector, clientId, message)
            );
            require(success, "failed to register duplicated enclave key");
        }

        TestData[] memory dataList = readTestDataList(commandStartNumber);
        bool firstUpdate = true;
        for (uint256 i = 0; i < dataList.length; i++) {
            if (dataList[i].cmd == Command.UpdateClient) {
                UpdateClientMessage.Data memory message = createUpdateClientMessage(dataList[i].path);
                Height.Data[] memory heights = lc.updateClient(clientId, message);
                require(heights.length == 1, "heights length must be 1");
                console.log("revision_height:");
                console.log(heights[0].revision_height);
                if (firstUpdate) {
                    firstUpdate = false;
                } else {
                    // repeat updateClient to check the state is not changed
                    message = createUpdateClientMessage(dataList[i].path);
                    // staticcall is expected to succeed because updateClient does not update the state if the message is already processed
                    (bool success, bytes memory ret) = address(lc).staticcall(
                        abi.encodeWithSelector(LCPClientBase.updateClient.selector, clientId, message)
                    );
                    require(success, "failed to update duplicated client");
                    heights = abi.decode(ret, (Height.Data[]));
                    require(heights.length == 0, "heights length must be 0");
                }
            } else if (dataList[i].cmd == Command.VerifyMembership) {
                (
                    Height.Data memory height,
                    bytes memory proof,
                    bytes memory prefix,
                    bytes memory path,
                    bytes memory value
                ) = createVerifyMembershipInputs(dataList[i].path);
                console.log("verify_membership: revision_height:");
                console.log(height.revision_height);
                require(
                    lc.verifyMembership(clientId, height, 0, 0, proof, prefix, path, value),
                    "failed to verify membership"
                );
            } else if (dataList[i].cmd == Command.VerifyNonMembership) {
                (Height.Data memory height, bytes memory proof, bytes memory prefix, bytes memory path) =
                    createVerifyNonMembershipInputs(dataList[i].path);
                console.log("verify_non_membership: revision_height:");
                console.log(height.revision_height);
                require(
                    lc.verifyNonMembership(clientId, height, 0, 0, proof, prefix, path),
                    "failed to verify non membership"
                );
            } else {
                require(false);
            }
        }
    }

    function createInitialState(string memory avrFile, address[] memory operators)
        internal
        returns (ClientState.Data memory clientState)
    {
        return createInitialState(avrFile, operators, 1, 1);
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
        clientState.operators_nonce = 0;
        clientState.operators_threshold_numerator = thresholdNumerator;
        clientState.operators_threshold_denominator = thresholdDenominator;

        // WARNING: the following configuration is for testing purpose only
        clientState.allowed_quote_statuses = new string[](1);
        clientState.allowed_quote_statuses[0] = readNestedString(avrFile, ".avr", ".isvEnclaveQuoteStatus");
        clientState.allowed_advisory_ids = readNestedStringArray(avrFile, ".avr", ".advisoryIDs");
    }

    function createRegisterEnclaveKeyMessage(string memory avrFile, Vm.Wallet memory opWallet)
        internal
        returns (RegisterEnclaveKeyMessage.Data memory message)
    {
        message.report = readJSON(avrFile, ".avr");
        message.signature = readDecodedBytes(avrFile, ".signature");
        message.signing_cert = readDecodedBytes(avrFile, ".signing_cert");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            opWallet.privateKey, keccak256(LCPOperatorTestHelper.computeEIP712RegisterEnclaveKey(message.report))
        );
        message.operator_signature = abi.encodePacked(r, s, v);
    }

    function createUpdateClientMessage(string memory updateClientFilePrefix)
        internal
        returns (UpdateClientMessage.Data memory message)
    {
        message.proxy_message =
            readDecodedBytes(string(abi.encodePacked(updateClientFilePrefix, commandResultSuffix)), ".message");
        message.signatures = new bytes[](1);
        message.signatures[0] =
            readDecodedBytes(string(abi.encodePacked(updateClientFilePrefix, commandResultSuffix)), ".signature");
    }

    function createVerifyMembershipInputs(string memory verifyMembershipFilePrefix)
        internal
        returns (
            Height.Data memory height,
            bytes memory proof,
            bytes memory prefix,
            bytes memory path,
            bytes memory value
        )
    {
        value = readDecodedBytes(string(abi.encodePacked(verifyMembershipFilePrefix, commandInputSuffix)), ".value");
        {
            bytes memory messageBytes =
                readDecodedBytes(string(abi.encodePacked(verifyMembershipFilePrefix, commandResultSuffix)), ".message");
            bytes memory signature = readDecodedBytes(
                string(abi.encodePacked(verifyMembershipFilePrefix, commandResultSuffix)), ".signature"
            );
            proof = abi.encode(newCommitmentProofs(messageBytes, signature));
        }
        (, LCPCommitment.VerifyMembershipProxyMessage memory message) =
            LCPCommitmentTestHelper.parseVerifyMembershipCommitmentProofs(proof);
        assert(message.value == keccak256(value));

        height = message.height;
        prefix = readDecodedBytes(string(abi.encodePacked(verifyMembershipFilePrefix, commandInputSuffix)), ".prefix");
        path = message.path;
    }

    function createVerifyNonMembershipInputs(string memory verifyNonMembershipFilePrefix)
        internal
        returns (Height.Data memory height, bytes memory proof, bytes memory prefix, bytes memory path)
    {
        bytes memory messageBytes =
            readDecodedBytes(string(abi.encodePacked(verifyNonMembershipFilePrefix, commandResultSuffix)), ".message");
        bytes memory signature =
            readDecodedBytes(string(abi.encodePacked(verifyNonMembershipFilePrefix, commandResultSuffix)), ".signature");
        proof = abi.encode(newCommitmentProofs(messageBytes, signature));
        (, LCPCommitment.VerifyMembershipProxyMessage memory message) =
            LCPCommitmentTestHelper.parseVerifyMembershipCommitmentProofs(proof);
        assert(message.value == bytes32(0));

        height = message.height;
        prefix =
            readDecodedBytes(string(abi.encodePacked(verifyNonMembershipFilePrefix, commandInputSuffix)), ".prefix");
        path = message.path;
    }

    function tData(string memory name) private view returns (string memory) {
        bytes memory dir = bytes(testContext.dir);
        require(dir.length != 0, "context isn't initialized");
        return string(abi.encodePacked(vm.projectRoot(), "/", baseDir, "/", dir, "/", name));
    }

    function readJSON(string memory path, string memory filter) internal virtual override returns (bytes memory) {
        return super.readJSON(tData(path), filter);
    }

    function readNestedString(string memory path, string memory firstFilter, string memory secondFilter)
        internal
        view
        virtual
        override
        returns (string memory)
    {
        return super.readNestedString(tData(path), firstFilter, secondFilter);
    }

    function readNestedStringArray(string memory path, string memory firstFilter, string memory secondFilter)
        internal
        view
        virtual
        override
        returns (string[] memory)
    {
        return super.readNestedStringArray(tData(path), firstFilter, secondFilter);
    }

    enum Command {
        InitClient,
        UpdateClient,
        VerifyMembership,
        VerifyNonMembership
    }

    struct TestData {
        Command cmd;
        string path;
    }

    /**
     * @dev readTestDataList returns test data list generated by [cgen](https://github.com/datachainlab/lcp/tree/main/tools/cgen).
     */
    function readTestDataList(uint256 commandStartNumber) internal returns (TestData[] memory) {
        string[] memory inputs = new string[](3);
        inputs[0] = "ls";
        inputs[1] = "-1";
        inputs[2] = string(abi.encodePacked(baseDir, "/", testContext.dir));
        string[] memory parts = splitLines(vm.ffi(inputs));
        uint256 n = (parts.length - commandStartNumber) / 2;
        TestData[] memory dataList = new TestData[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes memory fileName = bytes(parts[commandStartNumber + i * 2]);
            bytes32 h = keccak256(
                fileName.substring(
                    commandNumberPrefixLength, fileName.length - commandNumberPrefixLength - commandInputSuffixLength
                )
            );
            string memory path = string(fileName.substring(0, fileName.length - commandInputSuffixLength));
            if (h == keccak256("update_client")) {
                dataList[i] = TestData({cmd: Command.UpdateClient, path: path});
            } else if (
                h == keccak256("verify_connection") || h == keccak256("verify_channel")
                    || h == keccak256("verify_packet")
            ) {
                dataList[i] = TestData({cmd: Command.VerifyMembership, path: path});
            } else if (h == keccak256("verify_packet_receipt_absence")) {
                dataList[i] = TestData({cmd: Command.VerifyNonMembership, path: path});
            } else {
                require(false, string(abi.encodePacked("unknown file name:", fileName)));
            }
        }
        return dataList;
    }

    function splitLines(bytes memory src) internal pure returns (string[] memory) {
        uint256 n = 1;
        for (uint256 i = 0; i < src.length; i++) {
            if (src[i] == hex"0a") {
                n++;
            }
        }
        string[] memory parts = new string[](n);
        uint256 offset = 0;
        bytes memory ret;
        for (uint256 i = 0; i < n; i++) {
            (ret, offset) = extractElementUntil(src, offset, hex"0a");
            parts[i] = string(ret);
            offset += 1;
        }
        return parts;
    }

    function extractElementUntil(bytes memory src, uint256 offset, bytes32 b)
        internal
        pure
        returns (bytes memory, uint256)
    {
        for (uint256 p = offset; p < src.length; p++) {
            if (bytes32(src[p]) == b) {
                return (src.substring(offset, p - offset), p);
            }
        }
        return (src.substring(offset, src.length - offset), src.length);
    }
}
