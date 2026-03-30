<?php

declare(strict_types=1);

namespace CA\Cms\Asn1\Maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\AlgorithmIdentifier;

/**
 * EncryptedContentInfo ::= SEQUENCE {
 *   contentType ContentType,
 *   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *   encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL }
 *
 * RFC 5652 Section 6.1
 */
final class EncryptedContentInfo
{
    public static function getMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'contentType' => [
                    'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                ],
                'contentEncryptionAlgorithm' => AlgorithmIdentifier::MAP,
                'encryptedContent' => [
                    'type' => ASN1::TYPE_OCTET_STRING,
                    'constant' => 0,
                    'implicit' => true,
                    'optional' => true,
                ],
            ],
        ];
    }
}
