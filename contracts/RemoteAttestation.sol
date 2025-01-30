// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

library RemoteAttestation {
    // FLAG_DISALLOWED indicates that the advisory or quote status is not allowed.
    uint256 internal constant FLAG_DISALLOWED = 0;
    // FLAG_ALLOWED indicates that the advisory or quote status is allowed.
    uint256 internal constant FLAG_ALLOWED = 1;

    struct ReportAllowedStatus {
        // quote status => flag(0: not allowed, 1: allowed)
        mapping(string => uint256) allowedQuoteStatuses;
        // advisory id => flag(0: not allowed, 1: allowed)
        mapping(string => uint256) allowedAdvisories;
    }
}
