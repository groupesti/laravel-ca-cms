<?php

declare(strict_types=1);

namespace CA\Cms\Asn1\Maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\AlgorithmIdentifier;

/**
 * SignedData ::= SEQUENCE {
 *   version CMSVersion,
 *   digestAlgorithms DigestAlgorithmIdentifiers,
 *   encapContentInfo EncapsulatedContentInfo,
 *   certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
 *   signerInfos SignerInfos }
 *
 * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 * SignerInfos ::= SET OF SignerInfo
 * CertificateSet ::= SET OF CertificateChoices
 *
 * RFC 5652 Section 5.1
 */
final class SignedData
{
    public static function getMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'version' => [
                    'type' => ASN1::TYPE_INTEGER,
                ],
                'digestAlgorithms' => [
                    'type' => ASN1::TYPE_SET,
                    'min' => 0,
                    'max' => -1,
                    'children' => AlgorithmIdentifier::MAP,
                ],
                'encapContentInfo' => EncapsulatedContentInfo::getMap(),
                'certificates' => [
                    'type' => ASN1::TYPE_SET,
                    'constant' => 0,
                    'implicit' => true,
                    'optional' => true,
                    'min' => 0,
                    'max' => -1,
                    'children' => [
                        'type' => ASN1::TYPE_ANY,
                    ],
                ],
                'crls' => [
                    'type' => ASN1::TYPE_SET,
                    'constant' => 1,
                    'implicit' => true,
                    'optional' => true,
                    'min' => 0,
                    'max' => -1,
                    'children' => [
                        'type' => ASN1::TYPE_ANY,
                    ],
                ],
                'signerInfos' => [
                    'type' => ASN1::TYPE_SET,
                    'min' => 0,
                    'max' => -1,
                    'children' => SignerInfo::getMap(),
                ],
            ],
        ];
    }
}
