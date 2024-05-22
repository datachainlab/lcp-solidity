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
    error LCPClientClientStateInvalidOperatorsNonce();
    error LCPClientOperatorDuplicate(address operator, uint64 nonce);
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
    error LCPClientEnclaveKeyUnexpectedOperator();
    error LCPClientEnclaveKeyUnexpectedExpiredAt();

    error LCPClientOperatorSignaturesInsufficient(uint256 success);

    error LCPClientIASRootCertExpired();
    error LCPClientIASCertExpired();

    error LCPClientAVRInvalidSignature();
    error LCPClientAVRAlreadyExpired();
}
