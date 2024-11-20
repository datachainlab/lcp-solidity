// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

library LCPOperator {
    type ChainType is uint16;

    bytes32 internal constant TYPEHASH_DOMAIN_SEPARATOR =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    bytes32 internal constant TYPEHASH_REGISTER_ENCLAVE_KEY = keccak256("RegisterEnclaveKey(string avr)");
    bytes32 internal constant TYPEHASH_UPDATE_OPERATORS = keccak256(
        "UpdateOperators(string clientId,uint64 nonce,address[] newOperators,uint64 thresholdNumerator,uint64 thresholdDenominator)"
    );

    bytes32 internal constant DOMAIN_SEPARATOR_NAME = keccak256("LCPClient");
    bytes32 internal constant DOMAIN_SEPARATOR_VERSION = keccak256("1");

    // domainSeparatorUniversal()
    bytes32 internal constant DOMAIN_SEPARATOR_REGISTER_ENCLAVE_KEY =
        0x7fd21c2453e80741907e7ff11fd62ae1daa34c6fc0c2eced821f1c1d3fe88a4c;
    ChainType internal constant CHAIN_TYPE_EVM = ChainType.wrap(1);
    // chainTypeSalt(CHAIN_TYPE_EVM, hex"")
    bytes32 internal constant CHAIN_TYPE_EVM_SALT = keccak256(abi.encodePacked(CHAIN_TYPE_EVM, hex""));

    // slither-disable-next-line dead-code
    function chainTypeSalt(ChainType chainType, bytes memory args) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(chainType, args));
    }

    // slither-disable-next-line dead-code
    function domainSeparatorUniversal() internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                TYPEHASH_DOMAIN_SEPARATOR, DOMAIN_SEPARATOR_NAME, DOMAIN_SEPARATOR_VERSION, 0, address(0), bytes32(0)
            )
        );
    }

    function domainSeparatorEVM(uint256 chainId, address verifyingContract) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                TYPEHASH_DOMAIN_SEPARATOR,
                DOMAIN_SEPARATOR_NAME,
                DOMAIN_SEPARATOR_VERSION,
                chainId,
                verifyingContract,
                CHAIN_TYPE_EVM_SALT
            )
        );
    }

    function computeEIP712RegisterEnclaveKey(bytes calldata avr) internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"1901",
            DOMAIN_SEPARATOR_REGISTER_ENCLAVE_KEY,
            keccak256(abi.encode(TYPEHASH_REGISTER_ENCLAVE_KEY, keccak256(avr)))
        );
    }

    function computeEIP712UpdateOperators(
        string calldata clientId,
        uint64 nonce,
        address[] memory newOperators,
        uint64 thresholdNumerator,
        uint64 thresholdDenominator
    ) internal view returns (bytes memory) {
        return computeEIP712UpdateOperators(
            block.chainid, address(this), clientId, nonce, newOperators, thresholdNumerator, thresholdDenominator
        );
    }

    function computeEIP712UpdateOperators(
        uint256 chainId,
        address verifyingContract,
        string calldata clientId,
        uint64 nonce,
        address[] memory newOperators,
        uint64 thresholdNumerator,
        uint64 thresholdDenominator
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"1901",
            domainSeparatorEVM(chainId, verifyingContract),
            keccak256(
                abi.encode(
                    TYPEHASH_UPDATE_OPERATORS,
                    keccak256(bytes(clientId)),
                    nonce,
                    keccak256(abi.encodePacked(newOperators)),
                    thresholdNumerator,
                    thresholdDenominator
                )
            )
        );
    }
}
