<?php

declare(strict_types=1);

namespace CA\Cms\Asn1\Maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\Name;

/**
 * IssuerAndSerialNumber ::= SEQUENCE {
 *   issuer Name,
 *   serialNumber CertificateSerialNumber }
 *
 * CertificateSerialNumber ::= INTEGER
 *
 * RFC 5652 Section 10.2.4
 */
final class IssuerAndSerialNumber
{
    public static function getMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'issuer' => Name::MAP,
                'serialNumber' => [
                    'type' => ASN1::TYPE_INTEGER,
                ],
            ],
        ];
    }
}
