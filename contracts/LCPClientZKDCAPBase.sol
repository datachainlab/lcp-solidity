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
import {LCPClientCommon} from "./LCPClientBase.sol";
import {LCPOperator} from "./LCPOperator.sol";
import {AVRValidator} from "./AVRValidator.sol";
import {DCAPValidator} from "./DCAPValidator.sol";

abstract contract LCPClientZKDCAPBase is LCPClientCommon {
    using IBCHeight for Height.Data;

    // --------------------- Events ---------------------

    event ZKDCAPRegisteredEnclaveKey(string clientId, address enclaveKey, uint256 expiredAt, address operator);

    // --------------------- Immutable fields ---------------------

    /// @notice The hash of the root CA's public key certificate.
    bytes32 public immutable intelRootCAHash;
    /// @notice RISC Zero verifier contract address.
    IRiscZeroVerifier public immutable riscZeroVerifier;

    // --------------------- Storage fields ---------------------

    /// @dev Reserved storage space to allow for layout changes in the future
    uint256[50] private __gap;

    // --------------------- Constructor ---------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    /// @param ibcHandler_ the address of the IBC handler contract
    constructor(address ibcHandler_, bytes memory intelRootCA, address riscZeroVerifier_)
        LCPClientCommon(ibcHandler_)
    {
        require(intelRootCA.length != 0 && riscZeroVerifier_ != address(0), "invalid parameters");
        intelRootCAHash = keccak256(intelRootCA);
        riscZeroVerifier = IRiscZeroVerifier(riscZeroVerifier_);
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
        require(clientState.zkdcap_verifier_info.length == 64, "invalid verifier info length");
        require(clientState.zkdcap_verifier_info[0] == 0x01, "invalid verifier info version");
        bytes memory verifierInfo = clientState.zkdcap_verifier_info;
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
        } else if (typeUrlHash == LCPProtoMarshaler.ZKDCAP_REGISTER_ENCLAVE_KEY_MESSAGE_TYPE_URL_HASH) {
            return (this.zkdcapRegisterEnclaveKey.selector, args);
        } else if (typeUrlHash == LCPProtoMarshaler.UPDATE_OPERATORS_MESSAGE_TYPE_URL_HASH) {
            return (this.updateOperators.selector, args);
        } else {
            revert LCPClientUnknownProtoTypeUrl();
        }
    }

    function zkdcapRegisterEnclaveKey(string calldata clientId, ZKDCAPRegisterEnclaveKeyMessage.Data calldata message)
        public
        returns (Height.Data[] memory heights)
    {
        ClientStorage storage clientStorage = clientStorages[clientId];
        require(clientStorage.zkDCAPRisc0ImageId != bytes32(0), "image ID not set");
        riscZeroVerifier.verify(message.proof, clientStorage.zkDCAPRisc0ImageId, sha256(message.commit));
        DCAPValidator.Output memory output = DCAPValidator.parseCommit(message.commit);
        require(output.sgxIntelRootCAHash == intelRootCAHash, "unexpected root CA hash");

        if (bytes32(clientStorage.clientState.mrenclave) != output.mrenclave) {
            revert LCPClientClientStateUnexpectedMrenclave();
        }

        require(
            clientStorage.allowedStatuses.allowedQuoteStatuses[DCAPValidator.tcbStatusToString(output.tcbStatus)]
                == AVRValidator.FLAG_ALLOWED,
            "disallowed TCB status"
        );
        for (uint256 i = 0; i < output.advisoryIDs.length; i++) {
            require(
                clientStorage.allowedStatuses.allowedAdvisories[output.advisoryIDs[i]] == AVRValidator.FLAG_ALLOWED,
                "disallowed advisory ID"
            );
        }

        // if `operator_signature` is empty, the operator address is zero
        address operator;
        if (message.operator_signature.length != 0) {
            operator = verifyECDSASignature(
                keccak256(
                    LCPOperator.computeEIP712ZKDCAPRegisterEnclaveKey(
                        clientStorage.clientState.zkdcap_verifier_info, keccak256(message.commit)
                    )
                ),
                message.operator_signature
            );
        }
        if (output.operator != address(0) && output.operator != operator) {
            revert LCPClientAVRUnexpectedOperator(operator, output.operator);
        }
        if (block.timestamp < output.validityNotBeforeMax || block.timestamp > output.validityNotAfterMin) {
            revert LCPClientZKDCAPBaseOutputNotValid();
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
