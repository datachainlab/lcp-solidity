// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {IBCHeight} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/IBCHeight.sol";
import {Height} from "@hyperledger-labs/yui-ibc-solidity/contracts/proto/Client.sol";
import {IIBCHandler} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/25-handler/IIBCHandler.sol";
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

    /// @dev Emitted when an enclave key from zkDCAP quote is registered.
    event LCPClientZKDCAPRegisteredEnclaveKey(string clientId, address enclaveKey, uint256 expiredAt, address operator);

    /// @dev Emitted when the current TCB evaluation data number is updated.
    event LCPClientZKDCAPUpdateCurrentTcbEvaluationDataNumber(string clientId, uint32 tcbEvaluationDataNumber);
    /// @dev Emitted when the next TCB evaluation data number is updated.
    ///      This event is emitted only when the new next TCB evaluation data number is set.
    event LCPClientZKDCAPUpdateNextTcbEvaluationDataNumber(string clientId, uint32 tcbEvaluationDataNumber);

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
        if (clientState.current_tcb_evaluation_data_number == 0) {
            revert LCPClientZKDCAPCurrentTcbEvaluationDataNumberNotSet();
        }
        // check if both next_tcb_evaluation_data_number and next_tcb_evaluation_data_number_update_time are zero or non-zero
        if (
            (clientState.next_tcb_evaluation_data_number == 0)
                != (clientState.next_tcb_evaluation_data_number_update_time == 0)
        ) {
            revert LCPClientZKDCAPInvalidNextTcbEvaluationDataNumberInfo();
        }
        if (
            clientState.next_tcb_evaluation_data_number != 0
                && clientState.current_tcb_evaluation_data_number >= clientState.next_tcb_evaluation_data_number
        ) {
            revert LCPClientZKDCAPInvalidNextTcbEvaluationDataNumberInfo();
        }
        if (clientState.zkdcap_verifier_infos.length != 1) {
            revert LCPClientZKDCAPInvalidVerifierInfos();
        }
        // Currently, the client only supports RISC Zero zkVM
        clientStorage.zkDCAPRisc0ImageId = parseRiscZeroVerifierInfo(clientState.zkdcap_verifier_infos[0]);
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
     * @notice The client only supports RISC Zero zkVM currently.
     * @param clientId the client identifier
     * @param message the message to register the enclave key with the zkDCAP proof
     * @return heights the heights at which the new consensus states are stored. It is always empty because the consensus state is never updated in this function.
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
        ProtoClientState.Data storage clientState = clientStorage.clientState;
        // NOTE: the client must revert if the proof is invalid
        riscZeroVerifier.verify(
            message.proof, clientStorage.zkDCAPRisc0ImageId, sha256(message.quote_verification_output)
        );
        DCAPValidator.Output memory output = DCAPValidator.parseOutput(message.quote_verification_output);
        if (output.sgxIntelRootCAHash != intelRootCAHash) {
            revert LCPClientZKDCAPUnexpectedIntelRootCAHash();
        }
        if (output.mrenclave != bytes32(clientState.mrenclave)) {
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

        // check if the validity period of the output is valid at the current block timestamp
        if (block.timestamp < output.validityNotBefore || block.timestamp > output.validityNotAfter) {
            revert LCPClientZKDCAPOutputNotValid();
        }

        // check if the `output.enclaveDebugEnabled` and `developmentMode` are consistent
        if (output.enclaveDebugEnabled != developmentMode) {
            revert LCPClientZKDCAPUnexpectedEnclaveDebugMode();
        }

        // calculate the expiration time of the enclave key
        uint64 expiredAt;
        if (clientState.key_expiration == 0) {
            // If the value is 0, the validity period of the EK is `qv_output.validity.not_after`.
            expiredAt = output.validityNotAfter;
        } else {
            // If the value is greater than 0, the validity period of the EK is min(`output.validty.not_before + key_expiration`, `output.validity.not_after`).
            expiredAt = output.validityNotBefore + clientState.key_expiration;
            if (expiredAt > output.validityNotAfter) {
                expiredAt = output.validityNotAfter;
            }
        }

        // check if the TCB evaluation data number is updated
        (bool currentUpdated, bool nextUpdated) =
            checkAndUpdateTcbEvaluationDataNumber(clientId, output.minTcbEvaluationDataNumber);
        if (currentUpdated) {
            emit LCPClientZKDCAPUpdateCurrentTcbEvaluationDataNumber(
                clientId, clientState.current_tcb_evaluation_data_number
            );
        }
        if (nextUpdated) {
            emit LCPClientZKDCAPUpdateNextTcbEvaluationDataNumber(clientId, clientState.next_tcb_evaluation_data_number);
        }
        if (currentUpdated || nextUpdated) {
            // update the commitment of the client state in the IBC handler
            // `heights` is always empty because the consensus state is never updated in this function
            IIBCHandler(ibcHandler).updateClientCommitments(clientId, heights);
        }

        // if `operator_signature` is empty, the operator address is zero
        address operator;
        if (message.operator_signature.length != 0) {
            operator = verifyECDSASignature(
                keccak256(
                    LCPOperator.computeEIP712ZKDCAPRegisterEnclaveKey(
                        clientState.zkdcap_verifier_infos[0], keccak256(message.quote_verification_output)
                    )
                ),
                message.operator_signature
            );
        }
        if (output.operator != address(0) && output.operator != operator) {
            revert LCPClientAVRUnexpectedOperator(operator, output.operator);
        }

        EKInfo storage ekInfo = clientStorage.ekInfos[output.enclaveKey];
        if (ekInfo.expiredAt != 0) {
            if (ekInfo.operator != operator) {
                revert LCPClientEnclaveKeyUnexpectedOperator(ekInfo.operator, operator);
            }
            if (ekInfo.expiredAt != expiredAt) {
                revert LCPClientEnclaveKeyUnexpectedExpiredAt();
            }
            return heights;
        }
        ekInfo.expiredAt = expiredAt;
        ekInfo.operator = operator;

        emit LCPClientZKDCAPRegisteredEnclaveKey(clientId, output.enclaveKey, expiredAt, operator);

        return heights;
    }

    // --------------------- Internal methods --------------------- //

    function parseRiscZeroVerifierInfo(bytes memory verifierInfo) internal pure returns (bytes32) {
        // The format is as follows:
        // 0: zkVM type
        // 1-N: arbitrary data for each zkVM type
        //
        // The format of the risc0 zkVM is as follows:
        // | 0 |  1 - 31  |  32 - 64  |
        // |---|----------|-----------|
        // | 1 | reserved | image id  |
        uint256 vlen = verifierInfo.length;
        if (vlen == 0) {
            revert LCPClientZKDCAPInvalidVerifierInfoLength();
        }
        // Currently, the client only supports RISC Zero zkVM
        if (uint8(verifierInfo[0]) != ZKVM_TYPE_RISC_ZERO) {
            revert LCPClientZKDCAPInvalidVerifierInfoZKVMType();
        }
        if (vlen < 64) {
            revert LCPClientZKDCAPInvalidVerifierInfoLength();
        }
        // 32..64 bytes: image ID
        bytes32 imageId;
        assembly {
            imageId := mload(add(add(verifierInfo, 32), 32))
        }
        return imageId;
    }

    /// @dev Checks and updates the current and next TCB evaluation data numbers based on the observed `outputTcbEvaluationDataNumber`.
    ///
    /// The update logic aligns strictly with the proto definition in `LCP.proto`:
    /// - If the reserved next number's update time has arrived, it immediately replaces the current number.
    /// - Observing a number greater than the current number triggers updates depending on the configured grace period:
    ///   - Zero grace period: Immediate update; no next number reserved.
    ///   - Non-zero grace period:
    ///     - If no next number reserved yet, reserve the observed number.
    ///     - If a next number is already reserved:
    ///       - General case: No action required if the observed number matches the reserved number.
    ///       - Edge case 1 (current < next < observed): Immediate update of current number to reserved number; reserve newly observed number.
    ///       - Edge case 2 (current < observed < next): Immediate update of current number to observed number; reserved number unchanged.
    ///
    /// @param clientId Client identifier
    /// @param outputTcbEvaluationDataNumber Observed TCB evaluation data number
    /// @return currentUpdated True if current number is updated
    /// @return nextUpdated True if next number is updated or reserved
    function checkAndUpdateTcbEvaluationDataNumber(string calldata clientId, uint32 outputTcbEvaluationDataNumber)
        internal
        returns (bool currentUpdated, bool nextUpdated)
    {
        ProtoClientState.Data storage clientState = clientStorages[clientId].clientState;

        // Check if the reserved next TCB number is due for update.
        if (
            clientState.next_tcb_evaluation_data_number != 0
                && block.timestamp >= clientState.next_tcb_evaluation_data_number_update_time
        ) {
            clientState.current_tcb_evaluation_data_number = clientState.next_tcb_evaluation_data_number;
            clientState.next_tcb_evaluation_data_number = 0;
            clientState.next_tcb_evaluation_data_number_update_time = 0;
            currentUpdated = true;
            // No new next number reservation here.
        }

        if (outputTcbEvaluationDataNumber > clientState.current_tcb_evaluation_data_number) {
            if (clientState.tcb_evaluation_data_number_update_grace_period == 0) {
                // Immediate update due to zero grace period.
                clientState.current_tcb_evaluation_data_number = outputTcbEvaluationDataNumber;
                // Sanity check: No next number should be reserved if grace period is zero.
                require(
                    clientState.next_tcb_evaluation_data_number == 0
                        && clientState.next_tcb_evaluation_data_number_update_time == 0
                );
                return (true, false);
            } else {
                uint64 nextUpdateTime =
                    uint64(block.timestamp) + clientState.tcb_evaluation_data_number_update_grace_period;

                if (clientState.next_tcb_evaluation_data_number == 0) {
                    // No reserved number yet; reserve now.
                    clientState.next_tcb_evaluation_data_number = outputTcbEvaluationDataNumber;
                    clientState.next_tcb_evaluation_data_number_update_time = nextUpdateTime;
                    return (currentUpdated, true);
                }

                if (outputTcbEvaluationDataNumber > clientState.next_tcb_evaluation_data_number) {
                    // Edge case 1: Immediate update to previously reserved next number.
                    clientState.current_tcb_evaluation_data_number = clientState.next_tcb_evaluation_data_number;
                    clientState.next_tcb_evaluation_data_number = outputTcbEvaluationDataNumber;
                    clientState.next_tcb_evaluation_data_number_update_time = nextUpdateTime;
                    return (true, true);
                } else if (outputTcbEvaluationDataNumber < clientState.next_tcb_evaluation_data_number) {
                    // Edge case 2: Immediate update to the newly observed number, keep existing reservation.
                    clientState.current_tcb_evaluation_data_number = outputTcbEvaluationDataNumber;
                    return (true, false);
                } else {
                    // General case: The observed number is already reserved; no action required.
                    return (currentUpdated, false);
                }
            }
        } else if (outputTcbEvaluationDataNumber < clientState.current_tcb_evaluation_data_number) {
            // Reverting due to invalid backward update.
            revert LCPClientZKDCAPUnexpectedTcbEvaluationDataNumber(clientState.current_tcb_evaluation_data_number);
        } else {
            // Observed number matches current; no updates necessary.
            return (currentUpdated, false);
        }
    }
}
