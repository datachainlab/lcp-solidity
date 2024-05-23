// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

interface ILCPClientErrors {
    error LCPClientRootCACertAlreadyInitialized();
    error LCPClientClientStateInvalidLatestHeight();
    error LCPClientClientStateFrozen();
    error LCPClientClientStateInvalidKeyExpiration();
    error LCPClientClientStateInvalidMrenclaveLength();
    error LCPClientClientStateUnexpectedMrenclave();
    error LCPClientClientStateEmptyOperators();
    error LCPClientClientStateInvalidOperatorAddressLength();
    error LCPClientClientStateInvalidOperatorsNonce();
    error LCPClientClientStateUnexpectedOperatorsNonce(uint64 expectedNonce);

    error LCPClientOperatorsInvalidOrder(address prevOperator, address nextOperator);
    error LCPClientClientStateInvalidOperatorsThreshold();

    error LCPClientConsensusStateInvalidTimestamp();
    error LCPClientConsensusStateInvalidStateId();

    error LCPClientClientStateNotFound();
    error LCPClientConsensusStateNotFound();
    error LCPClientUnknownProxyMessageHeader();
    error LCPClientUnknownProtoTypeUrl();

    error LCPClientMembershipVerificationInvalidHeight();
    error LCPClientMembershipVerificationInvalidPrefix();
    error LCPClientMembershipVerificationInvalidPath();
    error LCPClientMembershipVerificationInvalidValue();
    error LCPClientMembershipVerificationInvalidStateId();

    error LCPClientUpdateStateEmittedStatesMustNotEmpty();
    error LCPClientUpdateStatePrevStateIdMustNotEmpty();
    error LCPClientUpdateStateUnexpectedPrevStateId();

    error LCPClientMisbehaviourPrevStatesMustNotEmpty();

    error LCPClientEnclaveKeyNotExist();
    error LCPClientEnclaveKeyExpired();
    error LCPClientEnclaveKeyUnexpectedOperator(address expected, address actual);
    error LCPClientEnclaveKeyUnexpectedExpiredAt();

    error LCPClientOperatorSignaturesInsufficient(uint256 success);

    error LCPClientIASRootCertExpired();
    error LCPClientIASCertExpired();

    error LCPClientAVRInvalidSignature();
    error LCPClientAVRAlreadyExpired();

    error LCPClientInvalidSignersLength();
    error LCPClientInvalidSignaturesLength();

    error LCPClientRegisterEnclaveKeyUnexpectedOperator(uint64 index, address gotOperator, address actualOperator);
}
