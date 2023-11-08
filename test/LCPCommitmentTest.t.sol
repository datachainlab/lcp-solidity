// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import "./TestHelper.t.sol";
import "../contracts/LCPCommitment.sol";
import "@hyperledger-labs/yui-ibc-solidity/contracts/proto/Client.sol";

contract LCPCommitmentTest is BasicTest {
    function setUp() public {}

    function testTrustingPeriodContext() public {
        // OK
        LCPCommitmentTestHelper.validateTrustingPeriodContext(
            LCPCommitment.TrustingPeriodContext(1692489600000000000, 1692489600000000000, 1, 1), 1692489600000000000
        );

        vm.expectRevert(bytes("out of trusting period"));
        LCPCommitmentTestHelper.validateTrustingPeriodContext(
            LCPCommitment.TrustingPeriodContext(1692489599999999999, 1692489599999999998, 1, 0), 1692489600000000000
        );

        vm.expectRevert(bytes("out of trusting period"));
        LCPCommitmentTestHelper.validateTrustingPeriodContext(
            LCPCommitment.TrustingPeriodContext(1692489599999999999, 1692489599999999998, 2, 0), 1692489600000000000
        );

        // OK
        LCPCommitmentTestHelper.validateTrustingPeriodContext(
            LCPCommitment.TrustingPeriodContext(1692489599999999999, 1692489599999999998, 3, 0), 1692489600000000000
        );

        vm.expectRevert(bytes("header is from the future"));
        LCPCommitmentTestHelper.validateTrustingPeriodContext(
            LCPCommitment.TrustingPeriodContext(1692489600000000001, 1692489600000000000, 1, 0), 1692489600000000000
        );

        vm.expectRevert(bytes("header is from the future"));
        LCPCommitmentTestHelper.validateTrustingPeriodContext(
            LCPCommitment.TrustingPeriodContext(1692489600000000001, 1692489600000000000, 1, 1), 1692489600000000000
        );

        // OK
        LCPCommitmentTestHelper.validateTrustingPeriodContext(
            LCPCommitment.TrustingPeriodContext(1692489600000000001, 1692489600000000000, 1, 2), 1692489600000000000
        );
    }

    struct UpdateClientCommitmentTestCase {
        bytes commitmentBytes;
        LCPCommitment.UpdateClientCommitment expected;
        LCPCommitment.TrustingPeriodContext expectedContext;
    }

    struct StateCommitmentTestCase {
        bytes commitmentBytes;
        LCPCommitment.StateCommitment expected;
    }

    function testParseUpdateClientCommitment() public {
        UpdateClientCommitmentTestCase[5] memory testCases = [
            UpdateClientCommitmentTestCase({
                commitmentBytes: hex"00000000000000000000000000000000000000000000000000000000000000200001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002e00000000000000000000000000000000000000000000000000000000000000020f29dadb9f61cd620f137030623163dbac8ba2f70fd9de3a69190468b6bd292c10d16d204e6e0c123f05101742caa15ae659d4e4ff1d81f3ec74d61988b9d34f60000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000d7d6fd43906328300000000000000000000000000000000000000000000000008a551c72eef5b2d000000000000000000000000000000000000000000000000070da11a4d4c030710000000000000000000000000000000000000000000000003da50864b78da3ac00000000000000000000000000000000000000000000000c9fc5088901d83bc900000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000000000000000000000000000000000000000009b0a3a2f2ee0b59f2f203fe1a5803a26f09187ac282244f0adb3a76ff09096bcefb9b0cdbbf09f8990f09fa180e0b89beaafb3f096be9cc395efbfbd26125d267f0ac91c355fd52cc2d9b900bd1199f172b2210364757936e0eb25f0022c016c80920e2be330da04ab15e780de11bf468dc925b9dd5840b3c9c94f1183f39d895560d6557a697326d8269b3e71644585c802c82ec537a53cad5cc989000000000000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000020000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000040000000000000000c40953a6e9748ebf100000000000000008fe02db3998abade00000000000000089b822ed1b43e2ebd0000000000000007c2949802ec315edf",
                expected: LCPCommitment.UpdateClientCommitment({
                    prevStateId: hex"f29dadb9f61cd620f137030623163dbac8ba2f70fd9de3a69190468b6bd292c1",
                    newStateId: hex"0d16d204e6e0c123f05101742caa15ae659d4e4ff1d81f3ec74d61988b9d34f6",
                    newState: hex"0a3a2f2ee0b59f2f203fe1a5803a26f09187ac282244f0adb3a76ff09096bcefb9b0cdbbf09f8990f09fa180e0b89beaafb3f096be9cc395efbfbd26125d267f0ac91c355fd52cc2d9b900bd1199f172b2210364757936e0eb25f0022c016c80920e2be330da04ab15e780de11bf468dc925b9dd5840b3c9c94f1183f39d895560d6557a697326d8269b3e71644585c802c82ec537a53cad5cc989",
                    prevHeight: Height.Data({revision_number: 15552896829797640240, revision_height: 9967904630215389904}),
                    newHeight: Height.Data({revision_number: 8131831476812525681, revision_height: 4441965836140127148}),
                    timestamp: 232873546291491650505,
                    context: hex"0000000000000000000000000000000000000000000000000000000000000020000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000040000000000000000c40953a6e9748ebf100000000000000008fe02db3998abade00000000000000089b822ed1b43e2ebd0000000000000007c2949802ec315edf"
                }),
                expectedContext: LCPCommitment.TrustingPeriodContext({
                    untrustedHeaderTimestamp: 226014618921130847217,
                    trustedStateTimestamp: 10367336591605283550,
                    trustingPeriod: 158779522890734644925,
                    clockDrift: 143148207194198073055
                })
            }),
            UpdateClientCommitmentTestCase({
                commitmentBytes: hex"00000000000000000000000000000000000000000000000000000000000000200001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000020581578c48752d5bcb6e40aa395a832f935432b56b5253bbd5e7818899393d72028edf27cc0e0f559d7bf5bc79b7860041a3bf31a244bb7d3fac3207fe51a130a000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000af3213c06e3130d50000000000000000000000000000000000000000000000007d28bb01cb05ebbf00000000000000000000000000000000000000000000000c4ff92c9381e0c90a000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000300a012a122b3d8adfbc0e96a5927e6380dacd3fb64ebefa7b5e0ed2dbf50172c2359e53bb908881bcbc1fe8d76f84a89b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000020000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000040000000000000000292e8955aab58700000000000000000055f79547cbd6929da000000000000000d16cbda1da69aad0700000000000000038bb5ebb2991a7ba4",
                expected: LCPCommitment.UpdateClientCommitment({
                    prevStateId: hex"581578c48752d5bcb6e40aa395a832f935432b56b5253bbd5e7818899393d720",
                    newStateId: hex"28edf27cc0e0f559d7bf5bc79b7860041a3bf31a244bb7d3fac3207fe51a130a",
                    newState: hex"0a012a122b3d8adfbc0e96a5927e6380dacd3fb64ebefa7b5e0ed2dbf50172c2359e53bb908881bcbc1fe8d76f84a89b",
                    prevHeight: Height.Data({revision_number: 0, revision_height: 0}),
                    newHeight: Height.Data({revision_number: 12624174422676287701, revision_height: 9018663870184942527}),
                    timestamp: 227123615094762686730,
                    context: hex"0000000000000000000000000000000000000000000000000000000000000020000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000040000000000000000292e8955aab58700000000000000000055f79547cbd6929da000000000000000d16cbda1da69aad0700000000000000038bb5ebb2991a7ba4"
                }),
                expectedContext: LCPCommitment.TrustingPeriodContext({
                    untrustedHeaderTimestamp: 47479363288207749120,
                    trustedStateTimestamp: 99113343169063365082,
                    trustingPeriod: 241450319268214910215,
                    clockDrift: 65407443915490622372
                })
            }),
            UpdateClientCommitmentTestCase({
                commitmentBytes: hex"00000000000000000000000000000000000000000000000000000000000000200001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002c00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000002f1b9061bfd5c94584adac01631e35c98c12b0350da2016fbe1b3153c9370520000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000073cac1b3a6bb3d10000000000000000000000000000000000000000000000002ff9b639968b348b0000000000000000000000000000000000000000000000006fd8c7171b7d97f100000000000000000000000000000000000000000000000069e0a9e5cf6d9132000000000000000000000000000000000000000000000005031a1a316f272df600000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000000000000000000000000000000000000000006e0a36f090819a3f3d4524e0ba98f09ebab02a7bf091b488f096a9a5efbfbd2fc8baf0909e9622ea9fbc38583cf0909eabc8bae0beb3415c4512348c1dd8191f3c4d4fd229c1178a57aa8896db71704dbaba5e2fab939d5d8d60b90122c5234b2f5786264535ed184057714c7c677000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000002000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000004000000000000000085fe74e82b0d6da260000000000000005ca6d7e098b0bcf0f0000000000000005dc3c63449194a8ad00000000000000078270fde7da6829f2",
                expected: LCPCommitment.UpdateClientCommitment({
                    prevStateId: hex"",
                    newStateId: hex"02f1b9061bfd5c94584adac01631e35c98c12b0350da2016fbe1b3153c937052",
                    newState: hex"0a36f090819a3f3d4524e0ba98f09ebab02a7bf091b488f096a9a5efbfbd2fc8baf0909e9622ea9fbc38583cf0909eabc8bae0beb3415c4512348c1dd8191f3c4d4fd229c1178a57aa8896db71704dbaba5e2fab939d5d8d60b90122c5234b2f5786264535ed184057714c7c6770",
                    prevHeight: Height.Data({revision_number: 521480889812366289, revision_height: 3456994547438662795}),
                    newHeight: Height.Data({revision_number: 8059410435238893553, revision_height: 7629284573258289458}),
                    timestamp: 92457240299676577270,
                    context: hex"000000000000000000000000000000000000000000000000000000000000002000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000004000000000000000085fe74e82b0d6da260000000000000005ca6d7e098b0bcf0f0000000000000005dc3c63449194a8ad00000000000000078270fde7da6829f2"
                }),
                expectedContext: LCPCommitment.TrustingPeriodContext({
                    untrustedHeaderTimestamp: 154484531066119313958,
                    trustedStateTimestamp: 106820173716123275023,
                    trustingPeriod: 108103388701645908141,
                    clockDrift: 138526500110532618738
                })
            }),
            UpdateClientCommitmentTestCase({
                commitmentBytes: hex"000000000000000000000000000000000000000000000000000000000000002000010001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000209a12281da113ec52a69773ceaf62d135a87c3940c086a5fde019fe6ca1c3f2c62fe88a39a2d7659f78d264ea0cbd149396f3c1680bcde867e26414d369b740c00000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000f7ff0b60a7d252050000000000000000000000000000000000000000000000000d2dc9a38dd9a7a4000000000000000000000000000000000000000000000000a0255da711cd68930000000000000000000000000000000000000000000000000c7a2e2bfaeebe93000000000000000000000000000000000000000000000000f359f301c78bfa670000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000020000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000040000000000000000cd662b15cb5865ce7000000000000000892704479a80291aa0000000000000007008a791b7a42fc03000000000000000789834529999e15c0",
                expected: LCPCommitment.UpdateClientCommitment({
                    prevStateId: hex"9a12281da113ec52a69773ceaf62d135a87c3940c086a5fde019fe6ca1c3f2c6",
                    newStateId: hex"2fe88a39a2d7659f78d264ea0cbd149396f3c1680bcde867e26414d369b740c0",
                    newState: hex"",
                    prevHeight: Height.Data({revision_number: 17870014356189762053, revision_height: 949636800741746596}),
                    newHeight: Height.Data({revision_number: 11539732592346359955, revision_height: 899081842042257043}),
                    timestamp: 17535313813112093287,
                    context: hex"0000000000000000000000000000000000000000000000000000000000000020000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000040000000000000000cd662b15cb5865ce7000000000000000892704479a80291aa0000000000000007008a791b7a42fc03000000000000000789834529999e15c0"
                }),
                expectedContext: LCPCommitment.TrustingPeriodContext({
                    untrustedHeaderTimestamp: 236809033568089431271,
                    trustedStateTimestamp: 158125961805905957290,
                    trustingPeriod: 129166185221675219971,
                    clockDrift: 139036048166085334464
                })
            }),
            UpdateClientCommitmentTestCase({
                commitmentBytes: hex"0000000000000000000000000000000000000000000000000000000000000020000100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000240000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000008ca259354bc17a752721218999e14ef1cc5b128900efeafcd0f6ebdadc8aece60000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000880e0f575212c1a60000000000000000000000000000000000000000000000002d907a9bbc8f024c000000000000000000000000000000000000000000000000fe5b1fe20a242370000000000000000000000000000000000000000000000000f7afa21383329991000000000000000000000000000000000000000000000000be8555da4840eb370000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000200001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000400000000000000004e8e966b147608ee2000000000000000b75a21aea2d963a5100000000000000067cb4f7bb14c4bac5000000000000000b1381125d5cb32f3a",
                expected: LCPCommitment.UpdateClientCommitment({
                    prevStateId: hex"",
                    newStateId: hex"8ca259354bc17a752721218999e14ef1cc5b128900efeafcd0f6ebdadc8aece6",
                    newState: hex"",
                    prevHeight: Height.Data({revision_number: 9803790306545680806, revision_height: 3283258937655099980}),
                    newHeight: Height.Data({revision_number: 18328278164207575920, revision_height: 17847662052981774737}),
                    timestamp: 13728473435112270647,
                    context: hex"00000000000000000000000000000000000000000000000000000000000000200001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000400000000000000004e8e966b147608ee2000000000000000b75a21aea2d963a5100000000000000067cb4f7bb14c4bac5000000000000000b1381125d5cb32f3a"
                }),
                expectedContext: LCPCommitment.TrustingPeriodContext({
                    untrustedHeaderTimestamp: 90570034692803825378,
                    trustedStateTimestamp: 211390551852559252049,
                    trustingPeriod: 119666543981647674053,
                    clockDrift: 204319609561717878586
                })
            })
        ];

        for (uint256 i = 0; i < testCases.length; i++) {
            UpdateClientCommitmentTestCase memory testCase = testCases[i];
            LCPCommitment.UpdateClientCommitment memory c =
                LCPCommitment.parseUpdateClientCommitment(testCase.commitmentBytes);
            assertEq(c.prevHeight.revision_number, testCase.expected.prevHeight.revision_number);
            assertEq(c.prevHeight.revision_height, testCase.expected.prevHeight.revision_height);
            assertEq(c.newHeight.revision_number, testCase.expected.newHeight.revision_number);
            assertEq(c.newHeight.revision_height, testCase.expected.newHeight.revision_height);
            assertEq(c.prevStateId, testCase.expected.prevStateId);
            assertEq(c.newStateId, testCase.expected.newStateId);
            assertEq(c.newState, testCase.expected.newState);
            assertEq(c.timestamp, testCase.expected.timestamp);
            assertEq(c.context, testCase.expected.context);
            LCPCommitment.HeaderedCommitmentContext memory hc = LCPCommitment.parseHeaderedCommitmentContext(c.context);
            assertEq(LCPCommitment.extractContextType(hc.header), LCPCommitment.LCPCommitmentContextTypeTrustingPeriod);
            LCPCommitment.TrustingPeriodContext memory tpc = LCPCommitment.parseTrustingPeriodContext(hc.context);
            assertEq(tpc.untrustedHeaderTimestamp, testCase.expectedContext.untrustedHeaderTimestamp);
            assertEq(tpc.trustedStateTimestamp, testCase.expectedContext.trustedStateTimestamp);
            assertEq(tpc.trustingPeriod, testCase.expectedContext.trustingPeriod);
            assertEq(tpc.clockDrift, testCase.expectedContext.clockDrift);
        }
    }

    function testParseStateCommitment() public {
        StateCommitmentTestCase[3] memory testCases = [
            StateCommitmentTestCase({
                commitmentBytes: hex"00000000000000000000000000000000000000000000000000000000000000200001000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000140546b4ac900b71d90630ebd854bf9b4b3081054787817c34edbe248c019d3d5220000000000000000000000000000000000000000000000002a77ef56df161a90000000000000000000000000000000000000000000000000dc8a051df742c6a8ed80bee27e34a0880b2197ab1094fe480d5069a1bd49c0a1edde5f8ac47ae0db000000000000000000000000000000000000000000000000000000000000005bff2001b8eb31136f2313c03bd375ee5a22cf7aa7eb2a8e94f7c32fe2e65300adc61fdb67069228cb78ab9bc66b17e85addc35863ba43738af2b6576491ed523016dbc229b37a5ef5f15de1d6a2d8927c97ddb1a42ba999f5e29e020000000000000000000000000000000000000000000000000000000000000000000000002e68f091b5a43bd1a841f091b590f096ad974fc2a52ff09291b0c2a5e2bfb9427bf3a08492e18dac2fe18ab3c2a53c000000000000000000000000000000000000",
                expected: LCPCommitment.StateCommitment({
                    prefix: hex"ff2001b8eb31136f2313c03bd375ee5a22cf7aa7eb2a8e94f7c32fe2e65300adc61fdb67069228cb78ab9bc66b17e85addc35863ba43738af2b6576491ed523016dbc229b37a5ef5f15de1d6a2d8927c97ddb1a42ba999f5e29e02",
                    path: hex"68f091b5a43bd1a841f091b590f096ad974fc2a52ff09291b0c2a5e2bfb9427bf3a08492e18dac2fe18ab3c2a53c",
                    value: hex"546b4ac900b71d90630ebd854bf9b4b3081054787817c34edbe248c019d3d522",
                    height: Height.Data({revision_number: 3060177628210535056, revision_height: 15891519861390755496}),
                    stateId: hex"ed80bee27e34a0880b2197ab1094fe480d5069a1bd49c0a1edde5f8ac47ae0db"
                })
            }),
            StateCommitmentTestCase({
                commitmentBytes: hex"0000000000000000000000000000000000000000000000000000000000000020000100020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e0598cc53099b2883a28cb4251429d3c7be499d830f9db75a73f6ca51ea98e580f000000000000000000000000000000000000000000000000f25593fbde8b3d9b000000000000000000000000000000000000000000000000001a61bd508161aa1237a766505d2856fc583afbf4e516a56a8d938e28a3ad80a48bdb2b0ff0fba30000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000de0a1aaf09f95b45c61333d6c5300000000000000000000000000000000000000",
                expected: LCPCommitment.StateCommitment({
                    prefix: hex"",
                    path: hex"e0a1aaf09f95b45c61333d6c53",
                    value: hex"598cc53099b2883a28cb4251429d3c7be499d830f9db75a73f6ca51ea98e580f",
                    height: Height.Data({revision_number: 17462025840178707867, revision_height: 7425815121846698}),
                    stateId: hex"1237a766505d2856fc583afbf4e516a56a8d938e28a3ad80a48bdb2b0ff0fba3"
                })
            }),
            StateCommitmentTestCase({
                commitmentBytes: hex"0000000000000000000000000000000000000000000000000000000000000020000100020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000daa00bf6ff409e11000000000000000000000000000000000000000000000000d10de8755bbb966f872b34191770690dfab12766f81a675542e235e601fade02aaafef223f8c91320000000000000000000000000000000000000000000000000000000000000025af9969689d3af0ee38a30a1370d0006fd5eddf471a701a27bee843d2ecf6d88adf6f2f064f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000017f091b6942fc381f09e8b9f272e4d5ed1a825603cc2a54b000000000000000000",
                expected: LCPCommitment.StateCommitment({
                    prefix: hex"af9969689d3af0ee38a30a1370d0006fd5eddf471a701a27bee843d2ecf6d88adf6f2f064f",
                    path: hex"f091b6942fc381f09e8b9f272e4d5ed1a825603cc2a54b",
                    value: hex"0000000000000000000000000000000000000000000000000000000000000000",
                    height: Height.Data({revision_number: 15753604652014280209, revision_height: 15063951919372015215}),
                    stateId: hex"872b34191770690dfab12766f81a675542e235e601fade02aaafef223f8c9132"
                })
            })
        ];
        for (uint256 i = 0; i < testCases.length; i++) {
            StateCommitmentTestCase memory testCase = testCases[i];
            LCPCommitment.StateCommitment memory c = LCPCommitment.parseStateCommitment(testCase.commitmentBytes);
            assertEq(c.prefix, testCase.expected.prefix);
            assertEq(c.path, testCase.expected.path);
            assertEq(c.value, testCase.expected.value);
            assertEq(c.height.revision_number, testCase.expected.height.revision_number);
            assertEq(c.height.revision_height, testCase.expected.height.revision_height);
            assertEq(c.stateId, testCase.expected.stateId);
        }
    }
}
