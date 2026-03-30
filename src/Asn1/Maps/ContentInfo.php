<?php

declare(strict_types=1);

namespace CA\Cms\Asn1\Maps;

use phpseclib3\File\ASN1;

/**
 * ContentInfo ::= SEQUENCE {
 *   contentType ContentType,
 *   content [0] EXPLICIT ANY DEFINED BY contentType }
 *
 * ContentType ::= OBJECT IDENTIFIER
 *
 * RFC 5652 Section 3
 */
final class ContentInfo
{
    public static function getMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'contentType' => [
                    'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                ],
                'content' => [
                    'type' => ASN1::TYPE_ANY,
                    'constant' => 0,
                    'explicit' => true,
                    'optional' => false,
                ],
            ],
        ];
    }
}
