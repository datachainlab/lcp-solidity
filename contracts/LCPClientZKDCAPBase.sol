// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {IBCHeight} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/IBCHeight.sol";
import {Height} from "@hyperledger-labs/yui-ibc-solidity/contracts/proto/Client.sol";
import {IRiscZeroVerifier} from "risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";
import {
    IbcLightclientsLcpV1ClientState as ProtoClientState,
    IbcLightclientsLcpV1ZKDCAPRegisterEnclaveKeyMessage as ZKDCAPRegisterEnclaveKeyMessage
} from "./proto/ibc/lightclients/lcp/v1/LCP.sol";
import {LCPProtoMarshaler} from "./LCPProtoMarshaler.sol";
import {LCPClientBase} from "./LCPClientBase.sol";
import {LCPOperator} from "./LCPOperator.sol";
import {RemoteAttestation} from "./RemoteAttestation.sol";
import {DCAPValidator} from "./DCAPValidator.sol";

abstract contract LCPClientZKDCAPBase is LCPClientBase {
    using IBCHeight for Height.Data;
    // --------------------- Constants ---------------------

    uint8 internal constant ZKVM_TYPE_RISC_ZERO = 0x01;

    // --------------------- Events ---------------------

    event ZKDCAPRegisteredEnclaveKey(string clientId, address enclaveKey, uint256 expiredAt, address operator);

    // --------------------- Immutable fields ---------------------

    /// @dev if developmentMode is true, the client allows the target enclave which is debug mode enabled.
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    bool internal immutable developmentMode;

    /// @notice The hash of the root CA's public key certificate.
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    bytes32 public immutable intelRootCAHash;

    /// @notice RISC Zero verifier contract address.
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IRiscZeroVerifier public immutable riscZeroVerifier;

    // --------------------- Storage fields ---------------------

    /// @dev Reserved storage space to allow for layout changes in the future
    uint256[50] private __gap;

    // --------------------- Constructor ---------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    /// @param ibcHandler_ the address of the IBC handler contract
    constructor(address ibcHandler_, bool developmentMode_, bytes memory intelRootCA, address riscZeroVerifier_)
        LCPClientBase(ibcHandler_)
    {
        if (intelRootCA.length == 0 || riscZeroVerifier_ == address(0)) {
            revert LCPClientZKDCAPInvalidConstructorParams();
        }
        intelRootCAHash = keccak256(intelRootCA);
        riscZeroVerifier = IRiscZeroVerifier(riscZeroVerifier_);
        developmentMode = developmentMode_;
    }

    // --------------------- Public methods ---------------------

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
        ClientStorage storage clientStorage = clientStorages[clientId];
        (ProtoClientState.Data memory clientState,) =
            _initializeClient(clientStorage, protoClientState, protoConsensusState);
        if (clientState.zkdcap_verifier_infos.length != 1) {
            revert LCPClientZKDCAPInvalidVerifierInfos();
        }
        bytes memory verifierInfo = clientState.zkdcap_verifier_infos[0];
        if (verifierInfo.length != 64) {
            revert LCPClientZKDCAPInvalidVerifierInfoLength();
        }
        if (uint8(verifierInfo[0]) != ZKVM_TYPE_RISC_ZERO) {
            revert LCPClientZKDCAPInvalidVerifierInfoZKVMType();
        }
        // 32..64 bytes: image ID
        bytes32 imageId;
        assembly {
            imageId := mload(add(add(verifierInfo, 32), 32))
        }
        clientStorage.zkDCAPRisc0ImageId = imageId;
        return clientState.latest_height;
    }

    /**
     * @dev routeUpdateClient returns the calldata to the receiving function of the client message.
     *      Light client contract may encode a client message as other encoding scheme(e.g. ethereum ABI)
     *      Check ibc-solidity's ADR-001 for details.
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
        } else if (typeUrlHash == LCPProtoMarshaler.ZKDCAP_REGISTER_ENCLAVE_KEY_MESSAGE_TYPE_URL_HASH) {
            return (this.zkDCAPRegisterEnclaveKey.selector, args);
        } else if (typeUrlHash == LCPProtoMarshaler.UPDATE_OPERATORS_MESSAGE_TYPE_URL_HASH) {
            return (this.updateOperators.selector, args);
        } else {
            revert LCPClientUnknownProtoTypeUrl();
        }
    }

    /**
     * @dev zkDCAPRegisterEnclaveKey validates the zkDCAP proof and registers the enclave key from the commit.
     */
    function zkDCAPRegisterEnclaveKey(string calldata clientId, ZKDCAPRegisterEnclaveKeyMessage.Data calldata message)
        public
        returns (Height.Data[] memory heights)
    {
        // Currently, the client only supports RISC Zero zkVM
        if (message.zkvm_type != ZKVM_TYPE_RISC_ZERO) {
            revert LCPClientZKDCAPUnsupportedZKVMType();
        }
        ClientStorage storage clientStorage = clientStorages[clientId];
        if (clientStorage.zkDCAPRisc0ImageId == bytes32(0)) {
            revert LCPClientZKDCAPRisc0ImageIdNotSet();
        }
        // NOTE: the client must revert if the proof is invalid
        riscZeroVerifier.verify(
            message.proof, clientStorage.zkDCAPRisc0ImageId, sha256(message.quote_verification_output)
        );
        DCAPValidator.Output memory output = DCAPValidator.parseOutput(message.quote_verification_output);
        if (output.sgxIntelRootCAHash != intelRootCAHash) {
            revert LCPClientZKDCAPUnexpectedIntelRootCAHash();
        }
        if (output.mrenclave != bytes32(clientStorage.clientState.mrenclave)) {
            revert LCPClientClientStateUnexpectedMrenclave();
        }

        // Check if the TCB status and advisory IDs are allowed

        // if the TCB status is not up-to-date, the client should check if the status is allowed
        if (
            keccak256(bytes(output.tcbStatus)) != DCAPValidator.TCB_STATUS_UP_TO_DATE_KECCAK256_HASH
                && clientStorage.allowedStatuses.allowedQuoteStatuses[output.tcbStatus] != RemoteAttestation.FLAG_ALLOWED
        ) {
            revert LCPClientZKDCAPDisallowedTCBStatus();
        }

        // if the advisory IDs are not empty, the client should check if the advisories are allowed
        for (uint256 i = 0; i < output.advisoryIDs.length; i++) {
            if (
                clientStorage.allowedStatuses.allowedAdvisories[output.advisoryIDs[i]] != RemoteAttestation.FLAG_ALLOWED
            ) {
                revert LCPClientZKDCAPDisallowedAdvisoryID();
            }
        }

        // check if the `output.enclaveDebugEnabled` and `developmentMode` are consistent
        if (output.enclaveDebugEnabled != developmentMode) {
            revert LCPClientZKDCAPUnexpectedEnclaveDebugMode();
        }

        // check if the validity period of the output is valid at the current block timestamp
        if (block.timestamp < output.validityNotBeforeMax || block.timestamp > output.validityNotAfterMin) {
            revert LCPClientZKDCAPOutputNotValid();
        }

        // if `operator_signature` is empty, the operator address is zero
        address operator;
        if (message.operator_signature.length != 0) {
            operator = verifyECDSASignature(
                keccak256(
                    LCPOperator.computeEIP712ZKDCAPRegisterEnclaveKey(
                        clientStorage.clientState.zkdcap_verifier_infos[0], keccak256(message.quote_verification_output)
                    )
                ),
                message.operator_signature
            );
        }
        if (output.operator != address(0) && output.operator != operator) {
            revert LCPClientAVRUnexpectedOperator(operator, output.operator);
        }

        uint64 expiredAt = output.validityNotAfterMin;
        EKInfo storage ekInfo = clientStorage.ekInfos[output.enclaveKey];
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

        emit ZKDCAPRegisteredEnclaveKey(clientId, output.enclaveKey, expiredAt, operator);

        // Note: client and consensus state are not always updated in registerEnclaveKey
        return heights;
    }
}
