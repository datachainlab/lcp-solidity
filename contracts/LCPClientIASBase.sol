// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {IBCHeight} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/IBCHeight.sol";
import {Height} from "@hyperledger-labs/yui-ibc-solidity/contracts/proto/Client.sol";
import {
    IbcLightclientsLcpV1ClientState as ProtoClientState,
    IbcLightclientsLcpV1RegisterEnclaveKeyMessage as RegisterEnclaveKeyMessage
} from "./proto/ibc/lightclients/lcp/v1/LCP.sol";
import {LCPOperator} from "./LCPOperator.sol";
import {LCPProtoMarshaler} from "./LCPProtoMarshaler.sol";
import {LCPClientBase} from "./LCPClientBase.sol";
import {AVRValidator} from "./AVRValidator.sol";

abstract contract LCPClientIASBase is LCPClientBase {
    using IBCHeight for Height.Data;

    /// @dev if developmentMode is true, the client allows the target enclave which is debug mode enabled.
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    bool internal immutable developmentMode;

    // --------------------- Constructor ---------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    /// @param ibcHandler_ the address of the IBC handler contract
    /// @param developmentMode_ if true, the client allows the enclave debug mode
    constructor(address ibcHandler_, bool developmentMode_) LCPClientBase(ibcHandler_) {
        developmentMode = developmentMode_;
    }

    // --------------------- Events ---------------------

    /// @dev Emitted when an enclave key from IAS report is registered.
    event RegisteredEnclaveKey(string clientId, address enclaveKey, uint256 expiredAt, address operator);

    // --------------------- Storage fields ---------------------

    /// @dev RootCA's public key parameters
    AVRValidator.RSAParams internal verifiedRootCAParams;
    /// @dev keccak256(signingCert) => RSAParams of signing public key
    mapping(bytes32 => AVRValidator.RSAParams) internal verifiedSigningRSAParams;

    /// @dev Reserved storage space to allow for layout changes in the future
    uint256[50] private __gap;

    // --------------------- Public methods ---------------------

    /// @dev isDevelopmentMode returns true if the client allows the enclave debug mode.
    function isDevelopmentMode() public view returns (bool) {
        return developmentMode;
    }

    /**
     * @dev initializeClient initializes a new client with the given state.
     *      If succeeded, it returns heights at which the consensus state are stored.
     *      This function is guaranteed by the IBC contract to be called only once for each `clientId`.
     * @param clientId the client identifier which is unique within the IBC handler
     */
    function initializeClient(
        string calldata clientId,
        bytes calldata protoClientState,
        bytes calldata protoConsensusState
    ) public override onlyIBC returns (Height.Data memory height) {
        (ProtoClientState.Data memory clientState,) =
            _initializeClient(clientStorages[clientId], protoClientState, protoConsensusState);
        if (clientState.key_expiration == 0) {
            revert LCPClientClientStateInvalidKeyExpiration();
        }
        return clientState.latest_height;
    }

    /**
     * @dev routeUpdateClient returns the calldata to the receiving function of the client message.
     *      Light client contract may encode a client message as other encoding scheme(e.g. ethereum ABI)
     *      Check ADR-001 for details.
     */
    function routeUpdateClient(string calldata clientId, bytes calldata protoClientMessage)
        public
        pure
        override
        returns (bytes4, bytes memory)
    {
        (bytes32 typeUrlHash, bytes memory args) = LCPProtoMarshaler.routeClientMessage(clientId, protoClientMessage);
        if (typeUrlHash == LCPProtoMarshaler.UPDATE_CLIENT_MESSAGE_TYPE_URL_HASH) {
            return (this.updateClient.selector, args);
        } else if (typeUrlHash == LCPProtoMarshaler.REGISTER_ENCLAVE_KEY_MESSAGE_TYPE_URL_HASH) {
            return (this.registerEnclaveKey.selector, args);
        } else if (typeUrlHash == LCPProtoMarshaler.UPDATE_OPERATORS_MESSAGE_TYPE_URL_HASH) {
            return (this.updateOperators.selector, args);
        } else {
            revert LCPClientUnknownProtoTypeUrl();
        }
    }

    /**
     * @dev registerEnclaveKey validates the IAS report and registers the enclave key from the report data.
     */
    function registerEnclaveKey(string calldata clientId, RegisterEnclaveKeyMessage.Data calldata message)
        public
        returns (Height.Data[] memory heights)
    {
        ClientStorage storage clientStorage = clientStorages[clientId];
        AVRValidator.ReportExtractedElements memory reElems = AVRValidator.verifyReport(
            developmentMode,
            verifiedRootCAParams,
            verifiedSigningRSAParams,
            clientStorage.allowedStatuses,
            message.report,
            message.signing_cert,
            message.signature
        );

        if (bytes32(clientStorage.clientState.mrenclave) != reElems.mrenclave) {
            revert LCPClientClientStateUnexpectedMrenclave();
        }

        // if `operator_signature` is empty, the operator address is zero
        address operator;
        if (message.operator_signature.length != 0) {
            operator = verifyECDSASignature(
                keccak256(LCPOperator.computeEIP712RegisterEnclaveKey(message.report)), message.operator_signature
            );
        }
        if (reElems.operator != address(0) && reElems.operator != operator) {
            revert LCPClientAVRUnexpectedOperator(operator, reElems.operator);
        }
        uint64 expiredAt = reElems.attestationTime + clientStorage.clientState.key_expiration;
        if (expiredAt <= block.timestamp) {
            revert LCPClientAVRAlreadyExpired();
        }
        EKInfo storage ekInfo = clientStorage.ekInfos[reElems.enclaveKey];
        if (ekInfo.expiredAt != 0) {
            if (ekInfo.operator != operator) {
                revert LCPClientEnclaveKeyUnexpectedOperator(ekInfo.operator, operator);
            }
            if (ekInfo.expiredAt != expiredAt) {
                revert LCPClientEnclaveKeyUnexpectedExpiredAt();
            }
            // NOTE: if the key already exists, don't update any state
            return heights;
        }
        ekInfo.expiredAt = expiredAt;
        ekInfo.operator = operator;

        emit RegisteredEnclaveKey(clientId, reElems.enclaveKey, expiredAt, operator);

        // Note: client and consensus state are not always updated in registerEnclaveKey
        return heights;
    }

    // --------------------- Internal methods ---------------------

    /// @dev initializeRootCACert initializes the root CA's public key parameters.
    /// All contracts that inherit LCPClientIASBase should call this in the constructor or initializer.
    function initializeRootCACert(bytes memory rootCACert) internal {
        if (verifiedRootCAParams.notAfter != 0) {
            revert LCPClientRootCACertAlreadyInitialized();
        }
        verifiedRootCAParams = AVRValidator.verifyRootCACert(rootCACert);
    }
}
