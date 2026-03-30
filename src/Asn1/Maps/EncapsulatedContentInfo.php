<?php

declare(strict_types=1);

namespace CA\Cms\Asn1\Maps;

use phpseclib3\File\ASN1;

/**
 * EncapsulatedContentInfo ::= SEQUENCE {
 *   eContentType ContentType,
 *   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
 *
 * RFC 5652 Section 5.2
 */
final class EncapsulatedContentInfo
{
    public static function getMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'eContentType' => [
                    'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                ],
                'eContent' => [
                    'type' => ASN1::TYPE_OCTET_STRING,
                    'constant' => 0,
                    'explicit' => true,
                    'optional' => true,
                ],
            ],
        ];
    }
}
