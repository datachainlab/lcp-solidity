// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {ILightClient} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/ILightClient.sol";
import {IBCHeight} from "@hyperledger-labs/yui-ibc-solidity/contracts/core/02-client/IBCHeight.sol";
import {Height} from "@hyperledger-labs/yui-ibc-solidity/contracts/proto/Client.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IbcLightclientsLcpV1ZKDCAPRegisterEnclaveKeyMessage as ZKDCAPRegisterEnclaveKeyMessage} from
    "./proto/ibc/lightclients/lcp/v1/LCP.sol";
import {LCPProtoMarshaler} from "./LCPProtoMarshaler.sol";
import {LCPClientV2Base} from "./LCPClientBase.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";

contract LCPClientZKDCAP is LCPClientV2Base {
    using IBCHeight for Height.Data;

    // --------------------- Events ---------------------

    event ZKDCAPRegisteredEnclaveKey(string clientId, address enclaveKey, uint256 expiredAt, address operator);

    // --------------------- Immutable fields ---------------------

    // /// @notice RISC Zero verifier contract address.
    // IRiscZeroVerifier public immutable verifier;

    // --------------------- Storage fields ---------------------

    /// @dev Reserved storage space to allow for layout changes in the future
    uint256[50] private __gap;

    // --------------------- Constructor ---------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    /// @param ibcHandler_ the address of the IBC handler contract
    constructor(address ibcHandler_) LCPClientV2Base(ibcHandler_) {}

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
        revert("not implemented");
        return heights;
    }
}
