// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.28;

import {LCPClientZKDCAPOwnableUpgradeable} from "../LCPClientZKDCAPOwnableUpgradeable.sol";
import {IbcLightclientsLcpV1ClientState} from "../proto/ibc/lightclients/lcp/v1/LCP.sol";
import {RemoteAttestation} from "../RemoteAttestation.sol";
import {Height} from "@hyperledger-labs/yui-ibc-solidity/contracts/proto/Client.sol";
import {IBCHeight} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/IBCHeight.sol";
import {IIBCClient} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/IIBCClient.sol";

/// @notice TokiLCPClientZKDCAP is LCPClientZKDCAPOwnableUpgradeable with state recovery functionality for TOKI operations.
/// @custom:oz-upgrades-unsafe-allow external-library-linking
contract TokiLCPClientZKDCAP is LCPClientZKDCAPOwnableUpgradeable {
    struct NewClientState {
        string clientId;
        bytes mrenclave;
        uint64 keyExpiration;
        string[] allowedQuoteStatuses;
        string[] allowedAdvisoryIds;
        bytes[] zkdcapVerifierInfos;
    }

    struct NewConsensusState {
        Height.Data height;
        ConsensusState consensusState;
    }

    // A unique version is assigned to the implementation contract.
    // To ensure the initialization process is only allowed once, it is checked by the reinitializer modifier.
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint64 public immutable RECOVERED_VERSION;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        address ibcHandler,
        bool developmentMode,
        bytes memory intelRootCA,
        address riscZeroVerifier,
        uint64 recoveredVersion
    ) LCPClientZKDCAPOwnableUpgradeable(ibcHandler, developmentMode, intelRootCA, riscZeroVerifier) {
        _disableInitializers();
        RECOVERED_VERSION = recoveredVersion;
    }

    /**
    * @dev `upgrade` should only be called once through UUPSUpgradeable.upgradeToAndCall.
    *      This function is used in the following situations:
    *      - When a critical security vulnerability is discovered in the LCP enclave or zkDCAP quote verifier, requiring an urgent upgrade.
    *      - When a newly issued security advisory of SGX, which is not critical to LCP security or operations, needs to be permitted.
    *      - When an ELC corresponding to the client state's `mrenclave` needs to be upgraded due to a hard fork.
    * @param newClientState New client state to upgrade.
    * @param newConsensusState New consensus state to upgrade.
    */
    function upgrade(NewClientState memory newClientState, NewConsensusState memory newConsensusState)
        external
        reinitializer(RECOVERED_VERSION)
        onlyOwner
    {
        return _upgrade(newClientState, newConsensusState);
    }

    function _upgrade(NewClientState memory newClientState, NewConsensusState memory newConsensusState) internal {
        ClientStorage storage clientStorage = clientStorages[newClientState.clientId];
        IbcLightclientsLcpV1ClientState.Data storage clientState = clientStorage.clientState;

        if (clientState.frozen) {
            revert LCPClientClientStateFrozen();
        }

        Height.Data memory latestHeight =
            Height.Data(clientState.latest_height.revision_number, clientState.latest_height.revision_height);
        if (IBCHeight.isZero(latestHeight) || IBCHeight.gte(latestHeight, newConsensusState.height)) {
            revert LCPClientClientStateInvalidLatestHeight();
        }

        // Validate ClientState
        if (newClientState.mrenclave.length != 32) {
            revert LCPClientClientStateInvalidMrenclaveLength();
        }

        // Validate ConsensusState
        if (newConsensusState.consensusState.timestamp == 0) {
            revert LCPClientConsensusStateInvalidTimestamp();
        }

        // A stateId with zero length or zero value is invalid.
        if (newConsensusState.consensusState.stateId == bytes32(0)) {
            revert LCPClientConsensusStateInvalidStateId();
        }

        // Upgrade ClientState
        clientState.mrenclave = newClientState.mrenclave;
        clientState.key_expiration = newClientState.keyExpiration;

        // Clear old statuses and advisories
        for (uint256 i = 0; i < clientState.allowed_quote_statuses.length; i++) {
            delete clientStorage.allowedStatuses.allowedQuoteStatuses[
                clientState.allowed_quote_statuses[i]
            ];
        }
        for (uint256 i = 0; i < clientState.allowed_advisory_ids.length; i++) {
            delete clientStorage.allowedStatuses.allowedAdvisories[
                clientState.allowed_advisory_ids[i]
            ];
        }

        // Set new statuses and advisories
        clientState.allowed_quote_statuses = newClientState.allowedQuoteStatuses;
        clientState.allowed_advisory_ids = newClientState.allowedAdvisoryIds;
        for (uint256 i = 0; i < clientState.allowed_quote_statuses.length; i++) {
            clientStorage.allowedStatuses.allowedQuoteStatuses[clientState.allowed_quote_statuses[i]] =
                RemoteAttestation.FLAG_ALLOWED;
        }
        for (uint256 i = 0; i < clientState.allowed_advisory_ids.length; i++) {
            clientStorage.allowedStatuses.allowedAdvisories[clientState.allowed_advisory_ids[i]] =
                RemoteAttestation.FLAG_ALLOWED;
        }

        // Upgrade zkDCAP verifier info in clientState and clientStorage
        clientState.zkdcap_verifier_infos[0] = newClientState.zkdcapVerifierInfos[0];
        clientStorage.zkDCAPRisc0ImageId = parseRiscZeroVerifierInfo(newClientState.zkdcapVerifierInfos[0]);

        // Upgrade ConsensusState and latestHeight of ClientState
        clientState.latest_height.revision_number = newConsensusState.height.revision_number;
        clientState.latest_height.revision_height = newConsensusState.height.revision_height;
        uint128 height = IBCHeight.toUint128(newConsensusState.height);
        clientStorage.consensusStates[height] = newConsensusState.consensusState;

        // Update commitments
        Height.Data[] memory heights = new Height.Data[](1);
        heights[0] = newConsensusState.height;
        IIBCClient(ibcHandler).updateClientCommitments(newClientState.clientId, heights);
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}
}
