// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/utils/Strings.sol";
import "../contracts/LCPUtils.sol";
import "./TestHelper.t.sol";

contract LCPUtilsTest is BasicTest {
    function setUp() public {}

    function testAttestationTimestampToSeconds(uint40 secs, string memory nonce) public {
        // assume the timestamp is less than or equal to 253402300799 (9999-12-31T23:59:59Z)
        vm.assume(secs <= 253402300799);
        (uint256 year, uint256 month, uint256 day, uint256 hour, uint256 minute, uint256 second) =
            DateTime.timestampToDateTime(secs);

        uint256 timestamp = TestLCPUtils.attestationTimestampToSeconds(
            abi.encodePacked(
                Strings.toString(year),
                "-",
                toStringPadLeft2(month),
                "-",
                toStringPadLeft2(day),
                "T",
                toStringPadLeft2(hour),
                ":",
                toStringPadLeft2(minute),
                ":",
                toStringPadLeft2(second),
                nonce
            )
        );
        assertEq(timestamp, secs, "timestamp should be equal to secs");
    }

    function testRfc5280TimeToSecondsGeneralizedTime(uint40 secs) public {
        // assume the timestamp is less than or equal to 253402300799 (9999-12-31T23:59:59Z)
        vm.assume(secs <= 253402300799);
        (uint256 year, uint256 month, uint256 day, uint256 hour, uint256 minute, uint256 second) =
            DateTime.timestampToDateTime(secs);
        uint256 timestamp = TestLCPUtils.rfc5280TimeToSeconds(
            abi.encodePacked(
                Strings.toString(year),
                toStringPadLeft2(month),
                toStringPadLeft2(day),
                toStringPadLeft2(hour),
                toStringPadLeft2(minute),
                toStringPadLeft2(second),
                "Z"
            )
        );
        assertEq(timestamp, secs, "timestamp should be equal to secs");
    }

    function testRfc5280TimeToSecondsUTCTime(uint40 secs) public {
        // assume the timestamp is less than or equal to 2524607999 (2049-12-31T23:59:59Z)
        vm.assume(secs <= 2524607999);
        (uint256 year, uint256 month, uint256 day, uint256 hour, uint256 minute, uint256 second) =
            DateTime.timestampToDateTime(secs);
        if (year >= 2000) {
            year -= 2000;
        } else {
            year -= 1900;
        }
        uint256 timestamp = TestLCPUtils.rfc5280TimeToSeconds(
            abi.encodePacked(
                toStringPadLeft2(year),
                toStringPadLeft2(month),
                toStringPadLeft2(day),
                toStringPadLeft2(hour),
                toStringPadLeft2(minute),
                toStringPadLeft2(second),
                "Z"
            )
        );
        assertEq(timestamp, secs, "timestamp should be equal to secs");
    }

    function toStringPadLeft2(uint256 n) private pure returns (string memory) {
        if (n < 10) {
            return string(abi.encodePacked("0", Strings.toString(n)));
        } else {
            return Strings.toString(n);
        }
    }
}
