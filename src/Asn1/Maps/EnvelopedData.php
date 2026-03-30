<?php

declare(strict_types=1);

namespace CA\Cms\Asn1\Maps;

use phpseclib3\File\ASN1;

/**
 * EnvelopedData ::= SEQUENCE {
 *   version CMSVersion,
 *   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *   recipientInfos RecipientInfos,
 *   encryptedContentInfo EncryptedContentInfo,
 *   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
 *
 * RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
 *
 * RFC 5652 Section 6.1
 */
final class EnvelopedData
{
    public static function getMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'version' => [
                    'type' => ASN1::TYPE_INTEGER,
                ],
                'originatorInfo' => [
                    'type' => ASN1::TYPE_SEQUENCE,
                    'constant' => 0,
                    'implicit' => true,
                    'optional' => true,
                    'children' => [
                        'certs' => [
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
                    ],
                ],
                'recipientInfos' => [
                    'type' => ASN1::TYPE_SET,
                    'min' => 1,
                    'max' => -1,
                    'children' => RecipientInfo::getMap(),
                ],
                'encryptedContentInfo' => EncryptedContentInfo::getMap(),
                'unprotectedAttrs' => [
                    'type' => ASN1::TYPE_SET,
                    'constant' => 1,
                    'implicit' => true,
                    'optional' => true,
                    'min' => 1,
                    'max' => -1,
                    'children' => SignerInfo::attributeMap(),
                ],
            ],
        ];
    }
}
