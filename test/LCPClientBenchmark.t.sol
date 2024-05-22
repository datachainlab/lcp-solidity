// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/utils/Strings.sol";
import "./TestHelper.t.sol";
import "../contracts/LCPClient.sol";
import {
    IbcLightclientsLcpV1ClientState as ClientState,
    IbcLightclientsLcpV1ConsensusState as ConsensusState,
    IbcLightclientsLcpV1RegisterEnclaveKeyMessage as RegisterEnclaveKeyMessage,
    IbcLightclientsLcpV1UpdateClientMessage as UpdateClientMessage
} from "../contracts/proto/ibc/lightclients/lcp/v1/LCP.sol";
import {LCPProtoMarshaler} from "../contracts/LCPProtoMarshaler.sol";
import {IBCHeight} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/IBCHeight.sol";

abstract contract BaseLCPClientBenchmark is BasicTest {
    string internal constant commandAvrFile = "test/data/client/02/001-avr";
    string internal constant rootCAFile = "test/data/certs/simulation_rootca.der";
    string internal constant commandResultSuffix = "_result";

    uint256 internal immutable testOperatorPrivKey;
    address internal immutable testOperator;

    BLCPClient lc;
    string clientId;

    constructor() {
        (testOperator, testOperatorPrivKey) = makeAddrAndKey("alice");
    }

    function createLCContract() internal returns (BLCPClient) {
        return new BLCPClient(address(this), true, vm.readFileBinary(rootCAFile));
    }

    function createClient() internal {
        ClientState.Data memory clientState = createInitialState(commandAvrFile, testOperator);
        ConsensusState.Data memory consensusState;
        lc.initializeClient(clientId, LCPProtoMarshaler.marshal(clientState), LCPProtoMarshaler.marshal(consensusState));
    }

    function generateClientId(uint64 clientCounter) internal pure returns (string memory) {
        return string(abi.encodePacked("lcp-", Strings.toString(clientCounter)));
    }

    function createInitialState(string memory avrFile, address operator)
        internal
        returns (ClientState.Data memory clientState)
    {
        bytes memory mrenclave = readDecodedBytes(avrFile, ".mrenclave");
        require(mrenclave.length == 32, "the length must be 32");

        // Note `latest_height` must be zero height
        clientState.mrenclave = mrenclave;
        clientState.key_expiration = 60 * 60 * 24 * 7;
        clientState.frozen = false;

        clientState.operators = new bytes[](1);
        clientState.operators[0] = abi.encodePacked(operator);
        clientState.operators_nonce = 1;
        clientState.operators_threshold_numerator = 1;
        clientState.operators_threshold_denominator = 1;

        // WARNING: the following configuration is for testing purpose only
        clientState.allowed_quote_statuses = new string[](1);
        clientState.allowed_quote_statuses[0] = readNestedString(avrFile, ".avr", ".isvEnclaveQuoteStatus");
        clientState.allowed_advisory_ids = readNestedStringArray(avrFile, ".avr", ".advisoryIDs");
    }

    function createRegisterEnclaveKeyMessage(string memory avrFile)
        internal
        returns (RegisterEnclaveKeyMessage.Data memory message)
    {
        message.report = string(readJSON(avrFile, ".avr"));
        message.signature = readDecodedBytes(avrFile, ".signature");
        message.signing_cert = readDecodedBytes(avrFile, ".signing_cert");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(testOperatorPrivKey, keccak256(bytes(message.report)));
        message.operator_index = 0;
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
}

contract BLCPClient is LCPClient {
    constructor(address ibcHandler_, bool developmentMode_, bytes memory rootCACert)
        LCPClient(ibcHandler_, developmentMode_, rootCACert)
    {}

    function setSigningRSAParams(bytes32 signingCertHash, AVRValidator.RSAParams calldata params) public {
        verifiedSigningRSAParams[signingCertHash] = params;
    }
}

contract NoCacheEnclaveRegistrationBenchmark is BaseLCPClientBenchmark {
    function setUp() public {
        vm.warp(1703138378);
        lc = createLCContract();
        clientId = generateClientId(1);
        createClient();
    }

    function testRegisterEnclaveKey() public {
        vm.warp(1703138378);
        Height.Data[] memory heights = lc.registerEnclaveKey(clientId, createRegisterEnclaveKeyMessage(commandAvrFile));
        require(heights.length == 0);
    }
}

contract CachedEnclaveRegistrationBenchmark is BaseLCPClientBenchmark {
    function setUp() public {
        vm.warp(1703138378);
        lc = createLCContract();
        clientId = generateClientId(1);
        createClient();
        lc.setSigningRSAParams(
            keccak256(readDecodedBytes(commandAvrFile, ".signing_cert")),
            AVRValidator.RSAParams(
                hex"90D30A012CC4A8F9A1FFF7F3D103D9733F3CD390E9481A99E995B47428814C5CE9DCD814D37C2C0B6DF082A551F4B0167C355B68F88E38B870F7D341422CC7717C2E2A0034D884A9532BBB6D0C0584729633B611BF5E2E29C5ED76B6A564E2FAB8FA3944765709392C9714B2DBDAFF0B283ADF3C6ABD3663B8FA5DE345B54ADDBFC07F02D7F3975BFBA01B7CB86D9304D35AA41E3D672502E361ABFCA07847F770AEE2F9E24B464089F55AFA5F411D18FE8F2ED7F2539315B5144A35E02FAACDD86403E43B6CA397D3C23DAE91599862E99F8DCB6F163D4A27573FDD5C7DDBDD5DF1D98140DC4567E7A579E18E3D92A982B2848FBF56193135A07A80A7104F6F",
                hex"010001",
                2550130947
            )
        );
    }

    function testRegisterEnclaveKey() public {
        vm.warp(1703138378);
        Height.Data[] memory heights = lc.registerEnclaveKey(clientId, createRegisterEnclaveKeyMessage(commandAvrFile));
        require(heights.length == 0);
    }
}

contract CreateClientBenchmark is BaseLCPClientBenchmark {
    function setUp() public {
        vm.warp(1703138378);
        lc = createLCContract();
        clientId = generateClientId(1);
    }

    function testCreateClient() public {
        createClient();
    }
}

contract UpdateClientBenchmark is BaseLCPClientBenchmark {
    function setUp() public {
        vm.warp(1703138378);
        lc = createLCContract();
        clientId = generateClientId(1);
        createClient();

        Height.Data[] memory heights = lc.registerEnclaveKey(clientId, createRegisterEnclaveKeyMessage(commandAvrFile));
        require(heights.length == 0);

        heights = lc.updateClient(clientId, createUpdateClientMessage("test/data/client/02/004-update_client"));
        require(heights.length == 1, "heights length must be 1");
    }

    function testUpdateClient() public {
        Height.Data[] memory heights =
            lc.updateClient(clientId, createUpdateClientMessage("test/data/client/02/007-update_client"));
        require(heights.length == 1, "heights length must be 1");
    }
}
