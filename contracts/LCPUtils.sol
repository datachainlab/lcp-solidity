// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import "@ensdomains/ens-contracts/contracts/dnssec-oracle/BytesUtils.sol";
import "solidity-datetime/contracts/DateTime.sol";

library LCPUtils {
    /**
     * @dev readBytesUntil reads bytes until the needle is found.
     */
    function readBytesUntil(bytes memory src, uint256 offset, bytes1 needle)
        internal
        pure
        returns (bytes memory bz, uint256 pos)
    {
        pos = BytesUtils.find(src, offset, src.length, needle);
        require(pos != type(uint256).max, "not found");
        return (BytesUtils.substring(src, offset, pos - offset), pos);
    }

    /**
     * @dev attestationTimestampToSeconds parses ISO 8601 date time string to unix timestamp in seconds
     *      The parse assumes the format YYYY-MM-DDTHH:mm:ss.ssssss and its timezone is UTC.
     *      The timestamp spec is described in "4.2.1 Report Data" section of the following document:
     *      https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf
     *      > The time shall be in UTC and the encoding shall be compliant to ISO 8601 standard.
     *      NOTE The parser rounds timestamp to the nearest second.
     * @param timestamp included in Report Data. e.g. 2022-12-01T09:49:53.473230
     */
    function attestationTimestampToSeconds(bytes memory timestamp) internal pure returns (uint256) {
        // ensure the timestamp[10] is 'T'
        require(timestamp.length >= 19 && timestamp[10] == bytes1(uint8(84)));
        return timestampFromDateTime(
            uint256(uint8(timestamp[0]) - 48) * 1000 + uint256(uint8(timestamp[1]) - 48) * 100
                + uint256(uint8(timestamp[2]) - 48) * 10 + uint8(timestamp[3]) - 48, // year
            uint256(uint8(timestamp[5]) - 48) * 10 + uint8(timestamp[6]) - 48, // month
            uint256(uint8(timestamp[8]) - 48) * 10 + uint8(timestamp[9]) - 48, // day
            uint256(uint8(timestamp[11]) - 48) * 10 + uint8(timestamp[12]) - 48, // hour
            uint256(uint8(timestamp[14]) - 48) * 10 + uint8(timestamp[15]) - 48, // minute
            uint256(uint8(timestamp[17]) - 48) * 10 + uint8(timestamp[18]) - 48 // second
        );
    }

    /**
     * @dev parseValidityTime parses X.509 validity time string to unix timestamp in seconds
     *      Its format is YYMMDDHHMMSSZ(UTCTime) or YYYYMMDDHHMMSSZ(GeneralizedTime)
     *      More details:
     *        - https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.1
     *        - https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.2
     * @param timestamp e.g. 221201094953Z(UTCTime) or 20221201094953Z(GeneralizedTime)
     */
    function rfc5280TimeToSeconds(bytes memory timestamp) internal pure returns (uint256) {
        uint256 year = 0;
        uint8 offset = 0;
        if (timestamp.length == 13) {
            // UTCTime
            if (uint8(timestamp[0]) - 48 < 5) {
                year += 2000;
            } else {
                year += 1900;
            }
        } else if (timestamp.length == 15) {
            // GeneralizedTime
            year += uint256(uint8(timestamp[0]) - 48) * 1000 + uint256(uint8(timestamp[1]) - 48) * 100;
            offset = 2;
        } else {
            revert("unknown time format");
        }
        year += uint256(uint8(timestamp[offset]) - 48) * 10 + uint8(timestamp[offset + 1]) - 48;
        // ensure the last char is 'Z'
        require(timestamp[timestamp.length - 1] == bytes1(uint8(90)));
        return timestampFromDateTime(
            year,
            uint256(uint8(timestamp[offset + 2]) - 48) * 10 + uint8(timestamp[offset + 3]) - 48, // month
            uint256(uint8(timestamp[offset + 4]) - 48) * 10 + uint8(timestamp[offset + 5]) - 48, // day
            uint256(uint8(timestamp[offset + 6]) - 48) * 10 + uint8(timestamp[offset + 7]) - 48, // hour
            uint256(uint8(timestamp[offset + 8]) - 48) * 10 + uint8(timestamp[offset + 9]) - 48, // minute
            uint256(uint8(timestamp[offset + 10]) - 48) * 10 + uint8(timestamp[offset + 11]) - 48 // second
        );
    }

    function timestampFromDateTime(
        uint256 year,
        uint256 month,
        uint256 day,
        uint256 hour,
        uint256 minute,
        uint256 second
    ) private pure returns (uint256) {
        require(DateTime.isValidDateTime(year, month, day, hour, minute, second), "invalid date time");
        return DateTime.timestampFromDateTime(year, month, day, hour, minute, second);
    }
}
