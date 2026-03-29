<?php

declare(strict_types=1);

namespace CA\Cms\Asn1\Maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\AlgorithmIdentifier;
use phpseclib3\File\ASN1\Maps\Name;

/**
 * SignerInfo ::= SEQUENCE {
 *   version CMSVersion,
 *   sid SignerIdentifier,
 *   digestAlgorithm DigestAlgorithmIdentifier,
 *   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
 *   signatureAlgorithm SignatureAlgorithmIdentifier,
 *   signature SignatureValue,
 *   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
 *
 * SignerIdentifier ::= CHOICE {
 *   issuerAndSerialNumber IssuerAndSerialNumber,
 *   subjectKeyIdentifier [0] SubjectKeyIdentifier }
 *
 * SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 * UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 * Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }
 *
 * RFC 5652 Section 5.3
 */
final class SignerInfo
{
    public static function getMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'version' => [
                    'type' => ASN1::TYPE_INTEGER,
                ],
                'sid' => [
                    'type' => ASN1::TYPE_CHOICE,
                    'children' => [
                        'issuerAndSerialNumber' => IssuerAndSerialNumber::getMap(),
                        'subjectKeyIdentifier' => [
                            'type' => ASN1::TYPE_OCTET_STRING,
                            'constant' => 0,
                            'implicit' => true,
                        ],
                    ],
                ],
                'digestAlgorithm' => AlgorithmIdentifier::MAP,
                'signedAttrs' => [
                    'type' => ASN1::TYPE_SET,
                    'constant' => 0,
                    'implicit' => true,
                    'optional' => true,
                    'min' => 1,
                    'max' => -1,
                    'children' => self::attributeMap(),
                ],
                'signatureAlgorithm' => AlgorithmIdentifier::MAP,
                'signature' => [
                    'type' => ASN1::TYPE_OCTET_STRING,
                ],
                'unsignedAttrs' => [
                    'type' => ASN1::TYPE_SET,
                    'constant' => 1,
                    'implicit' => true,
                    'optional' => true,
                    'min' => 1,
                    'max' => -1,
                    'children' => self::attributeMap(),
                ],
            ],
        ];
    }

    public static function attributeMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'attrType' => [
                    'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                ],
                'attrValues' => [
                    'type' => ASN1::TYPE_SET,
                    'min' => 1,
                    'max' => -1,
                    'children' => [
                        'type' => ASN1::TYPE_ANY,
                    ],
                ],
            ],
        ];
    }
}
