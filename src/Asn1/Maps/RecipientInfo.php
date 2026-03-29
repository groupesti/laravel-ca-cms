<?php

declare(strict_types=1);

namespace CA\Cms\Asn1\Maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\AlgorithmIdentifier;
use phpseclib3\File\ASN1\Maps\Name;

/**
 * RecipientInfo ::= CHOICE {
 *   ktri KeyTransRecipientInfo,
 *   ... }
 *
 * KeyTransRecipientInfo ::= SEQUENCE {
 *   version CMSVersion,
 *   rid RecipientIdentifier,
 *   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *   encryptedKey EncryptedKey }
 *
 * RecipientIdentifier ::= CHOICE {
 *   issuerAndSerialNumber IssuerAndSerialNumber,
 *   subjectKeyIdentifier [0] SubjectKeyIdentifier }
 *
 * EncryptedKey ::= OCTET STRING
 *
 * RFC 5652 Section 6.2.1
 */
final class RecipientInfo
{
    public static function getMap(): array
    {
        return self::getKeyTransRecipientInfoMap();
    }

    public static function getKeyTransRecipientInfoMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'version' => [
                    'type' => ASN1::TYPE_INTEGER,
                ],
                'rid' => [
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
                'keyEncryptionAlgorithm' => AlgorithmIdentifier::MAP,
                'encryptedKey' => [
                    'type' => ASN1::TYPE_OCTET_STRING,
                ],
            ],
        ];
    }
}
