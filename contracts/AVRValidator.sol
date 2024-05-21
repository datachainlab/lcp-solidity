// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import {RSAVerify} from "@ensdomains/ens-contracts/contracts/dnssec-oracle/algorithms/RSAVerify.sol";
import {BytesUtils} from "@ensdomains/ens-contracts/contracts/dnssec-oracle/BytesUtils.sol";
import {Base64} from "base64/base64.sol";
import {Asn1Decode, NodePtr} from "./Asn1Decode.sol";
import {LCPUtils} from "./LCPUtils.sol";

/**
 * @dev AVRValidator provides the validation functions of Intel's Attestation Verification Report(AVR)
 *      An AVR is signed with Intel's signing key, and the signing key is certified by Intel's Root CA.
 */
library AVRValidator {
    using Asn1Decode for bytes;
    using BytesUtils for bytes;

    // OID_SHA256_WITH_RSA_ENCRYPTION is the OID of sha256WithRSAEncryption(1.2.840.113549.1.1.11)
    bytes32 internal constant OID_SHA256_WITH_RSA_ENCRYPTION =
        0x2a864886f70d01010b0000000000000000000000000000000000000000000000;
    // OID_RSA_ENCRYPTION is the OID of rsaEncryption(1.2.840.113549.1.1.1)
    bytes32 internal constant OID_RSA_ENCRYPTION = 0x2a864886f70d0101010000000000000000000000000000000000000000000000;
    // FLAG_DISALLOWED indicates that the advisory or quote status is not allowed.
    uint256 internal constant FLAG_DISALLOWED = 0;
    // FLAG_ALLOWED indicates that the advisory or quote status is allowed.
    uint256 internal constant FLAG_ALLOWED = 1;
    // '"'
    bytes32 internal constant CHAR_DOUBLE_QUOTE = bytes32(hex"22");
    // ','
    bytes32 internal constant CHAR_COMMA = bytes32(hex"2c");
    // '['
    bytes32 internal constant CHAR_LIST_START = bytes32(hex"5b");
    // ']'
    bytes32 internal constant CHAR_LIST_END = bytes32(hex"5d");

    uint256 internal constant OFFSET_JSON_NUMBER_VALUE = 1;
    uint256 internal constant OFFSET_JSON_STRING_VALUE = 2;
    uint256 internal constant OFFSET_JSON_LIST_VALUE = 1;

    bytes32 internal constant HASHED_GROUP_OUT_OF_DATE = keccak256("GROUP_OUT_OF_DATE");
    bytes32 internal constant HASHED_CONFIGURATION_NEEDED = keccak256("CONFIGURATION_NEEDED");
    bytes32 internal constant HASHED_SW_HARDENING_NEEDED = keccak256("SW_HARDENING_NEEDED");
    bytes32 internal constant HASHED_CONFIGURATION_AND_SW_HARDENING_NEEDED =
        keccak256("CONFIGURATION_AND_SW_HARDENING_NEEDED");

    struct RSAParams {
        bytes modulus;
        bytes exponent;
        uint256 notAfter; // seconds since epoch
    }

    /**
     * @dev verifySignature verifies the RSA signature of the report.
     * @param reportSha256 is sha256(AVR)
     * @param signature is the RSA signature of the AVR
     * @param exponent is the exponent of the signing public key
     * @param modulus is the modulus of the signing public key
     */
    function verifySignature(
        bytes32 reportSha256,
        bytes calldata signature,
        bytes calldata exponent,
        bytes calldata modulus
    ) public view returns (bool) {
        (bool ok, bytes memory result) = RSAVerify.rsarecover(modulus, exponent, signature);
        // Verify it ends with the hash of our data
        return ok && reportSha256 == result.readBytes32(result.length - 32);
    }

    /**
     * @dev verifyRootCACert verifies the root CA certificate.
     *      Please read the comments of parseCertificate for the expected structure of the certificate.
     */
    function verifyRootCACert(bytes calldata rootCACert) public view returns (RSAParams memory) {
        (bytes memory modulus, bytes memory exponent, bytes32 signedData, bytes memory signature, uint256 notAfter) =
            parseCertificate(rootCACert);
        (bool ok, bytes memory result) = RSAVerify.rsarecover(modulus, exponent, signature);
        // Verify it ends with the hash of our data
        require(ok && signedData == result.readBytes32(result.length - 32), "signature verification failed");
        return RSAParams(modulus, exponent, notAfter);
    }

    /**
     * @dev verifySigningCert verifies the signing certificate with the public key of the root CA certificate.
     *      Please read the comments of parseCertificate for the expected structure of the certificate.
     */
    function verifySigningCert(
        bytes calldata rootCAPublicKeyModulus,
        bytes calldata rootCAPublicKeyExponent,
        bytes calldata signingCert
    ) public view returns (RSAParams memory) {
        (bytes memory modulus, bytes memory exponent, bytes32 signedData, bytes memory signature, uint256 notAfter) =
            parseCertificate(signingCert);
        (bool ok, bytes memory result) =
            RSAVerify.rsarecover(rootCAPublicKeyModulus, rootCAPublicKeyExponent, signature);
        // Verify it ends with the hash of our data
        require(ok && signedData == result.readBytes32(result.length - 32), "signature verification failed");
        return RSAParams(modulus, exponent, notAfter);
    }

    /**
     * @dev parseCertificate parses a given certificate.
     *      The parser expects the following structure:
     *      - `Certificate.signatureAlgorithm` must be sha256WithRSAEncryption(1.2.840.113549.1.1.11)
     *      - `Certificate.tbsCertificate.signature` must be sha256WithRSAEncryption(1.2.840.113549.1.1.11)
     *      - `Certificate.tbsCertificate.subjectPublicKeyInfo.algorithm` must be rsaEncryption(1.2.840.113549.1.1.1)
     *
     *     https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
     *     Certificate  ::=  SEQUENCE  {
     *         tbsCertificate       TBSCertificate,
     *         signatureAlgorithm   AlgorithmIdentifier,
     *         signatureValue       BIT STRING  }
     *
     *     TBSCertificate  ::=  SEQUENCE  {
     *         version         [0]  EXPLICIT Version DEFAULT v1,
     *         serialNumber         CertificateSerialNumber,
     *         signature            AlgorithmIdentifier,
     *         issuer               Name,
     *         validity             Validity,
     *         subject              Name,
     *         subjectPublicKeyInfo SubjectPublicKeyInfo,
     *         issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                                 -- If present, version MUST be v2 or v3
     *         subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                                 -- If present, version MUST be v2 or v3
     *         extensions      [3]  EXPLICIT Extensions OPTIONAL
     *                                 -- If present, version MUST be v3
     *     }
     * @param cert The der-encoded ASN1 certificate
     * @return modulus of public key
     * @return exponent of public key
     * @return signedData is sha256(tbsCertificate)
     * @return signature of certificate
     * @return notAfter is the timestamp when the certificate is expired
     */
    function parseCertificate(bytes memory cert)
        internal
        view
        returns (bytes memory, bytes memory, bytes32 signedData, bytes memory signature, uint256 notAfter)
    {
        // node: tbsCertificate
        uint256 node = cert.firstChildOf(cert.root());
        {
            // n: signatureAlgorithm
            uint256 n = cert.nextSiblingOf(node);
            // ensure that the signature algorithm is sha256WithRSAEncryption
            require(
                cert.bytes32At(cert.firstChildOf(n)) == OID_SHA256_WITH_RSA_ENCRYPTION,
                "signature algorithm is not sha256WithRSAEncryption"
            );
            // n: signatureValue
            n = cert.nextSiblingOf(n);
            signature = cert.bytesAt(n);
            // signedData is sha256(tbsCertificate)
            signedData = sha256(cert.allBytesAt(node));
        }
        // node: version or serial number
        node = cert.firstChildOf(node);
        // version is optional
        // 0xa0(10 1 00000) represents CONTXET_SPECIFIC and CONSTRUCTED and tag 0
        if (cert[NodePtr.ixs(node)] == 0xa0) {
            node = cert.nextSiblingOf(node);
        }
        // node: serial number

        // Signature algorithm
        node = cert.nextSiblingOf(node);
        // ensure that the signature algorithm is sha256WithRSAEncryption
        require(
            cert.bytes32At(cert.firstChildOf(node)) == OID_SHA256_WITH_RSA_ENCRYPTION,
            "signature algorithm is not sha256WithRSAEncryption"
        );

        // Issuer (no need to validate)
        node = cert.nextSiblingOf(node);
        // Validity
        node = cert.nextSiblingOf(node);
        {
            /*
            Validity ::= SEQUENCE {
                notBefore      Time,
                notAfter       Time
            }
            */
            // n: notBefore
            uint256 n = cert.firstChildOf(node);
            require(LCPUtils.rfc5280TimeToSeconds(cert.bytesAt(n)) <= block.timestamp, "certificate is not valid yet");
            notAfter = LCPUtils.rfc5280TimeToSeconds(cert.bytesAt(cert.nextSiblingOf(n)));
            require(block.timestamp <= notAfter, "certificate is expired");
        }
        // Subject (no need to validate)
        node = cert.nextSiblingOf(node);

        /**
         * SubjectPublicKeyInfo ::= SEQUENCE
         *     {
         *     algorithm           AlgorithmIdentifier,
         *     subjectPublicKey    BITSTRING
         *     }
         */
        // subjectPublicKeyInfo
        node = cert.nextSiblingOf(node);
        // algorithm (AlgorithmIdentifier)
        node = cert.firstChildOf(node);
        // https://datatracker.ietf.org/doc/html/rfc5912
        // AlgorithmIdentifier{ALGORITHM-TYPE, ALGORITHM-TYPE:AlgorithmSet} ::=
        //     SEQUENCE {
        //         algorithm   ALGORITHM-TYPE.&id({AlgorithmSet}),
        //         parameters  ALGORITHM-TYPE.
        //                &Params({AlgorithmSet}{@algorithm}) OPTIONAL
        //     }
        // ensure that oid matches rsaEncryption
        require(
            cert.bytes32At(cert.firstChildOf(node)) == OID_RSA_ENCRYPTION, "signature algorithm is not rsaEncryption"
        );

        // subjectPublicKey
        node = cert.nextSiblingOf(node);

        // https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.1
        // RSAPublicKey ::= SEQUENCE {
        //     modulus           INTEGER,  -- n
        //     publicExponent    INTEGER   -- e
        // }
        node = cert.firstChildOf(cert.rootOfBitStringAt(node));
        // prefix '00' that represents a positive integer
        require(cert[NodePtr.ixf(node)] == 0, "exponent must be positive");

        return (
            // modulus
            cert.substring(NodePtr.ixf(node) + 1, NodePtr.ixl(node) - NodePtr.ixf(node)),
            // exponent
            cert.bytesAt(cert.nextSiblingOf(node)),
            signedData,
            signature,
            notAfter
        );
    }

    /**
     * @dev validateAndExtractElements try to parse a given report.
     * The parser expects the following structure(pretty printed):
     * {
     *   "id": "120273546145229684841731255506776325150",
     *   "timestamp": "2022-12-01T09:49:53.473230",
     *   "version": 4,
     *   "advisoryURL": "https://security-center.intel.com", // optional
     *   "advisoryIDs": [ // optional
     *      "INTEL-SA-00219",
     *      "INTEL-SA-00289",
     *      "INTEL-SA-00614",
     *      "INTEL-SA-00617",
     *      "INTEL-SA-00477",
     *      "INTEL-SA-00615",
     *      "INTEL-SA-00334"
     *   ],
     *   "isvEnclaveQuoteStatus": "GROUP_OUT_OF_DATE",
     *   // optional
     *   "platformInfoBlob": "1502006504000F00000F0F020202800E0000000000000000000D00000C000000020000000000000BF1FF71C73902CC168C67B32BABE311C8DCD69AA9A065D5DA1F575FA5939FD06B43FC187CDBDF97C972CA863F96A6EA5E6BB7313B5A38E28C2D117C990CEAA9CF3A",
     *   "isvEnclaveQuoteBody": "AgAAAPELAAALAAoAAAAAALCbZcb+Fr6JI5sV5pIlYVt2GdTw6l8Ea6v+ySKOFbzvDQ3//wKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAADRdEEo/Gd2j3BUnuFH3PJYMIqpCpDr30GLCEPnHnp+kAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABNFlyxvu2l+vFxOlwhIAe+KlPZewAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
     * }
     *
     * @return address of EnclaveKey
     * @return timestamp when report was attested
     * @return mrenclave of the attested enclave
     */
    function validateAndExtractElements(
        bool developmentMode,
        bytes calldata report,
        mapping(string => uint256) storage allowedQuoteStatuses,
        mapping(string => uint256) storage allowedAdvisories
    ) public view returns (address, uint256, bytes32) {
        // find 'timestamp' key
        (uint256 i, bytes memory timestamp) = consumeTimestampReportJSON(report, 0);
        uint256 checkpoint;

        // find 'version' key
        i = consumeVersionReportJSON(report, i);
        checkpoint = i;

        // find 'isvEnclaveQuoteStatus' key
        bytes memory status;
        (i, status) = consumeIsvEnclaveQuoteStatusReportJSON(report, i);
        // skip the validation for quote status and advisories if status is "OK"
        if (!(status.length == 2 && status[0] == 0x4f && status[1] == 0x4b)) {
            require(allowedQuoteStatuses[string(status)] == FLAG_ALLOWED, "the quote status is not allowed");
            bytes32 h = keccak256(status);
            if (
                h == HASHED_GROUP_OUT_OF_DATE || h == HASHED_CONFIGURATION_NEEDED || h == HASHED_SW_HARDENING_NEEDED
                    || h == HASHED_CONFIGURATION_AND_SW_HARDENING_NEEDED
            ) {
                // find 'advisoryIDs' key and validate them
                validateAdvisories(report, consumeAdvisoryIdsReportJSON(report, checkpoint), allowedAdvisories);
            }
        }

        // find 'platformInfoBlob' key(optional)
        i = consumePlatformInfoBlobReportJSONIfExists(report, i);

        // find 'isvEnclaveQuoteBody' key
        i = consumeIsvEnclaveQuoteBodyReportJSON(report, i);

        // decode isvEnclaveQuoteBody
        // 576 bytes is the length of the quote
        bytes memory quoteDecoded = Base64.decode(string(report[i:i + 576]));

        /**
         * parse the quote fields as follows:
         * https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf (p.26-27)
         */
        uint8 attributesFlags = quoteDecoded.readUint8(96);
        // check debug flag(0b0000_0010)
        if (developmentMode) {
            require(attributesFlags & uint8(2) != uint8(0), "disallowed production enclave");
        } else {
            require(attributesFlags & uint8(2) == uint8(0), "disallowed debug enclave");
        }

        return (
            address(quoteDecoded.readBytes20(368)),
            LCPUtils.attestationTimestampToSeconds(timestamp),
            quoteDecoded.readBytes32(112)
        );
    }

    function validateAdvisories(
        bytes calldata report,
        uint256 offset,
        mapping(string => uint256) storage allowedAdvisories
    ) internal view returns (uint256) {
        require(offset < report.length && report[offset] == CHAR_LIST_START);
        offset++;

        uint256 lastStart = offset;
        bool itemStart = false;
        bytes32 chr;

        for (; offset < report.length; offset++) {
            chr = report[offset];
            if (chr == CHAR_DOUBLE_QUOTE) {
                itemStart = !itemStart;
                if (itemStart) {
                    lastStart = offset + 1;
                }
            } else if (chr == CHAR_COMMA) {
                require(
                    allowedAdvisories[string(report[lastStart:lastStart + offset - lastStart - 1])] == FLAG_ALLOWED,
                    "disallowed advisory is included"
                );
            } else if (chr == CHAR_LIST_END) {
                if (offset - lastStart > 0) {
                    require(
                        allowedAdvisories[string(report[lastStart:lastStart + offset - lastStart - 1])] == FLAG_ALLOWED,
                        "disallowed advisory is included"
                    );
                }
                require(!itemStart, "insufficient doubleQuotes number");
                return offset + 1;
            }
        }
        revert("missing listEnd");
    }

    function consumeJSONKey(bytes calldata report, uint256 i, string memory keyStr) internal pure returns (uint256) {
        uint256 len = bytes(keyStr).length;
        assert(len > 0 && len <= 32);
        bytes32 key = bytes32(bytes(keyStr));
        uint256 limit = report.length - len - 2;
        unchecked {
            while (
                i < limit
                    && !(
                        bytes32(report[i]) == CHAR_DOUBLE_QUOTE && bytes32(report[i + 1 + len]) == CHAR_DOUBLE_QUOTE
                            && bytes32(report[i + 1:i + 1 + len]) == key
                    )
            ) {
                i++;
            }
        }
        require(i < limit, "key not found");
        // advance the index to the value
        return i + len + 2;
    }

    function consumeTimestampReportJSON(bytes calldata report, uint256 i)
        internal
        pure
        returns (uint256, bytes memory)
    {
        i = consumeJSONKey(report, i, "timestamp") + OFFSET_JSON_STRING_VALUE;
        return (i + 26, report[i:i + 26]);
    }

    function consumeVersionReportJSON(bytes calldata report, uint256 i) internal pure returns (uint256) {
        i = consumeJSONKey(report, i, "version") + OFFSET_JSON_NUMBER_VALUE;
        // check if the version matches "4,"(0x34, 0x2c)
        require(bytes2(report[i:i + 2]) == bytes2(hex"342c"), "version mismatch");
        return i + 2;
    }

    function consumeAdvisoryIdsReportJSON(bytes calldata report, uint256 i) internal pure returns (uint256) {
        return consumeJSONKey(report, i, "advisoryIDs") + OFFSET_JSON_LIST_VALUE;
    }

    function consumeIsvEnclaveQuoteStatusReportJSON(bytes calldata report, uint256 i)
        internal
        pure
        returns (uint256, bytes memory)
    {
        i = consumeJSONKey(report, i, "isvEnclaveQuoteStatus") + OFFSET_JSON_STRING_VALUE;
        (bytes memory status, uint256 offset) = LCPUtils.readBytesUntil(report, i, bytes1(CHAR_DOUBLE_QUOTE));
        return (offset + 2, status);
    }

    function consumePlatformInfoBlobReportJSONIfExists(bytes calldata report, uint256 i)
        internal
        pure
        returns (uint256)
    {
        if (bytes32(report[i:i + 18]) != bytes32("\"platformInfoBlob\"")) {
            return i;
        } else if (bytes32(report[i + 18 + 1]) != CHAR_DOUBLE_QUOTE) {
            // TODO remove this check after the AVR of the RA simulation is fixed
            return i;
        }
        // "platformInfoBlob":"
        i = i + 18 + 2;
        // TLV Header as hex string
        // 0-2: Type
        // 2-4: Version
        // 4-8: Size
        return i + 8 + hexBytesToUint(bytes4(report[i + 4:i + 8])) * 2;
    }

    function consumeIsvEnclaveQuoteBodyReportJSON(bytes calldata report, uint256 i) internal pure returns (uint256) {
        return consumeJSONKey(report, i, "isvEnclaveQuoteBody") + OFFSET_JSON_STRING_VALUE;
    }

    function hexBytesToUint(bytes4 ss) internal pure returns (uint256) {
        uint256 val = 0;
        uint8 zero = uint8(48); //0
        uint8 nine = uint8(57); //9
        // solhint-disable-next-line var-name-mixedcase
        uint8 A = uint8(65); //A
        uint8 a = uint8(97); // a
        // solhint-disable-next-line var-name-mixedcase
        uint8 F = uint8(70); //F
        uint8 f = uint8(102); //f
        for (uint256 i = 0; i < 4; ++i) {
            uint8 byt = uint8(ss[i]);
            if (byt >= zero && byt <= nine) byt = byt - zero;
            else if (byt >= a && byt <= f) byt = byt - a + 10;
            else if (byt >= A && byt <= F) byt = byt - A + 10;
            val = (val << 4) | (byt & 0xF);
        }
        return val;
    }
}
