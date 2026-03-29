<?php

declare(strict_types=1);

namespace CA\Cms\Services;

use CA\Cms\Contracts\CmsSignerInterface;
use CA\Cms\Events\CmsMessageSigned;
use CA\Cms\Events\CmsMessageVerified;
use CA\Cms\Models\CmsMessage;
use CA\Crt\Models\Certificate;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Element;
use phpseclib3\File\X509;
use phpseclib3\Math\BigInteger;
use RuntimeException;

class CmsSigner implements CmsSignerInterface
{
    // CMS OIDs
    private const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
    private const OID_DATA = '1.2.840.113549.1.7.1';
    private const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
    private const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
    private const OID_SIGNING_TIME = '1.2.840.113549.1.9.5';
    private const OID_COUNTER_SIGNATURE = '1.2.840.113549.1.9.6';

    // Digest algorithm OIDs
    private const DIGEST_OIDS = [
        'sha1' => '1.3.14.3.2.26',
        'sha256' => '2.16.840.1.101.3.4.2.1',
        'sha384' => '2.16.840.1.101.3.4.2.2',
        'sha512' => '2.16.840.1.101.3.4.2.3',
    ];

    // Signature algorithm OIDs
    private const RSA_SIGNATURE_OIDS = [
        'sha1' => '1.2.840.113549.1.1.5',
        'sha256' => '1.2.840.113549.1.1.11',
        'sha384' => '1.2.840.113549.1.1.12',
        'sha512' => '1.2.840.113549.1.1.13',
    ];

    private const EC_SIGNATURE_OIDS = [
        'sha256' => '1.2.840.10045.4.3.2',
        'sha384' => '1.2.840.10045.4.3.3',
        'sha512' => '1.2.840.10045.4.3.4',
    ];

    public function sign(string $data, Certificate $cert, PrivateKey $key, array $options = []): string
    {
        $hashAlgo = $options['hash'] ?? config('ca-cms.default_hash', 'sha256');
        $includeCerts = $options['include_certs'] ?? config('ca-cms.include_certs', true);
        $includeChain = $options['include_chain'] ?? config('ca-cms.include_chain', false);

        $der = $this->buildSignedData($data, $cert, $key, $hashAlgo, $includeCerts, $includeChain, detached: false);

        $this->persistMessage($cert, $der, $hashAlgo, detached: false);

        return $der;
    }

    public function signDetached(string $data, Certificate $cert, PrivateKey $key, array $options = []): string
    {
        $hashAlgo = $options['hash'] ?? config('ca-cms.default_hash', 'sha256');
        $includeCerts = $options['include_certs'] ?? config('ca-cms.include_certs', true);
        $includeChain = $options['include_chain'] ?? config('ca-cms.include_chain', false);

        $der = $this->buildSignedData($data, $cert, $key, $hashAlgo, $includeCerts, $includeChain, detached: true);

        $this->persistMessage($cert, $der, $hashAlgo, detached: true);

        return $der;
    }

    public function addCounterSignature(string $signedDataDer, Certificate $cert, PrivateKey $key): string
    {
        // Parse the existing ContentInfo
        $parsed = $this->parseContentInfo($signedDataDer);
        $hashAlgo = config('ca-cms.default_hash', 'sha256');

        // Get the first signer's signature value
        $signerInfosRaw = $parsed['signerInfos'];
        if (empty($signerInfosRaw)) {
            throw new RuntimeException('No SignerInfo found in SignedData.');
        }

        $firstSignerInfo = $signerInfosRaw[0];

        // The counter-signature is a signature over the existing signature value
        $existingSignature = $firstSignerInfo['signature'];

        // Hash the existing signature
        $digest = hash($hashAlgo, $existingSignature, binary: true);

        // Build signed attributes for counter-signature
        $signedAttrs = $this->buildSignedAttributes(self::OID_DATA, $digest, $hashAlgo);
        $signedAttrsDer = $this->encodeSignedAttributesForSigning($signedAttrs);

        // Sign
        $signature = $this->computeSignature($key, $signedAttrsDer, $hashAlgo);

        // Build counter-signature SignerInfo
        $certDer = $this->getCertificateDer($cert);
        $x509 = new X509();
        $x509->loadX509($certDer);
        $issuerDn = $x509->getIssuerDN(X509::DN_ASN1);
        $serial = $x509->currentCert['tbsCertificate']['serialNumber'];

        $counterSignerInfo = $this->buildSignerInfoDer(
            $issuerDn,
            $serial,
            $hashAlgo,
            $signedAttrs,
            $signature,
            $key,
        );

        // Build the counter-signature attribute
        $counterSigAttr = $this->buildAttribute(self::OID_COUNTER_SIGNATURE, $counterSignerInfo);

        // Now we need to rebuild: add the counter-signature as an unsigned attribute
        // on the first SignerInfo. We rebuild from raw DER manipulation.
        return $this->injectCounterSignature($signedDataDer, $counterSigAttr);
    }

    public function verify(string $signedDataDer, ?string $content = null): bool
    {
        try {
            $result = $this->doVerify($signedDataDer, $content);
        } catch (\Throwable) {
            $result = false;
        }

        CmsMessageVerified::dispatch($result, $signedDataDer);

        return $result;
    }

    // ========================================================================
    // Private implementation
    // ========================================================================

    private function buildSignedData(
        string $data,
        Certificate $cert,
        PrivateKey $key,
        string $hashAlgo,
        bool $includeCerts,
        bool $includeChain,
        bool $detached,
    ): string {
        $certDer = $this->getCertificateDer($cert);

        // Parse the certificate to extract issuer and serial
        $x509 = new X509();
        $x509->loadX509($certDer);
        $issuerDnDer = $x509->getIssuerDN(X509::DN_ASN1);
        $serial = $x509->currentCert['tbsCertificate']['serialNumber'];

        // 1. Compute message digest
        $digest = hash($hashAlgo, $data, binary: true);

        // 2. Build SignedAttributes
        $signedAttrs = $this->buildSignedAttributes(self::OID_DATA, $digest, $hashAlgo);

        // 3. DER-encode SignedAttributes for signing (as SET OF, not IMPLICIT [0])
        $signedAttrsDer = $this->encodeSignedAttributesForSigning($signedAttrs);

        // 4. Sign the DER-encoded SignedAttributes
        $signature = $this->computeSignature($key, $signedAttrsDer, $hashAlgo);

        // 5. Build SignerInfo
        $signerInfoDer = $this->buildSignerInfoDer(
            $issuerDnDer,
            $serial,
            $hashAlgo,
            $signedAttrs,
            $signature,
            $key,
        );

        // 6. Build digest algorithm identifier
        $digestAlgDer = $this->encodeAlgorithmIdentifier($this->getDigestOid($hashAlgo));

        // 7. Build EncapsulatedContentInfo
        if ($detached) {
            $encapContentInfoDer = $this->encodeTlv(0x30, // SEQUENCE
                $this->encodeOid(self::OID_DATA)
            );
        } else {
            $eContentOctet = $this->encodeTlv(0x04, $data); // OCTET STRING
            $eContentExplicit = $this->encodeTlv(0xA0, $eContentOctet); // [0] EXPLICIT
            $encapContentInfoDer = $this->encodeTlv(0x30, // SEQUENCE
                $this->encodeOid(self::OID_DATA) . $eContentExplicit
            );
        }

        // 8. Build certificates [0] IMPLICIT if requested
        $certSetDer = '';
        if ($includeCerts) {
            $certsContent = $certDer;
            if ($includeChain) {
                $certsContent .= $this->getChainCertsDer($cert);
            }
            $certSetDer = $this->encodeTlv(0xA0, $certsContent); // [0] IMPLICIT constructed
        }

        // 9. Build SignerInfos SET OF
        $signerInfosSetDer = $this->encodeTlv(0x31, $signerInfoDer); // SET OF

        // 10. Build digestAlgorithms SET OF
        $digestAlgsSetDer = $this->encodeTlv(0x31, $digestAlgDer); // SET OF

        // 11. Assemble SignedData SEQUENCE
        $versionDer = $this->encodeInteger(1); // version 1

        $signedDataContent = $versionDer
            . $digestAlgsSetDer
            . $encapContentInfoDer
            . $certSetDer
            . $signerInfosSetDer;

        $signedDataDer = $this->encodeTlv(0x30, $signedDataContent); // SEQUENCE

        // 12. Wrap in ContentInfo
        $contentInfoDer = $this->encodeTlv(0x30,
            $this->encodeOid(self::OID_SIGNED_DATA)
            . $this->encodeTlv(0xA0, $signedDataDer) // [0] EXPLICIT
        );

        return $contentInfoDer;
    }

    /**
     * Build the SignedAttributes as an array of DER-encoded Attribute SEQUENCEs.
     *
     * @return array<int, string> Array of DER-encoded Attribute SEQUENCEs
     */
    private function buildSignedAttributes(string $contentTypeOid, string $digest, string $hashAlgo): array
    {
        $attrs = [];

        // contentType attribute
        $attrs[] = $this->buildAttribute(
            self::OID_CONTENT_TYPE,
            $this->encodeOid($contentTypeOid),
        );

        // signingTime attribute
        $attrs[] = $this->buildAttribute(
            self::OID_SIGNING_TIME,
            $this->encodeUtcTime(new \DateTimeImmutable()),
        );

        // messageDigest attribute
        $attrs[] = $this->buildAttribute(
            self::OID_MESSAGE_DIGEST,
            $this->encodeTlv(0x04, $digest), // OCTET STRING
        );

        return $attrs;
    }

    /**
     * Build a single Attribute SEQUENCE: { OID, SET OF { value } }.
     */
    private function buildAttribute(string $oid, string $valueDer): string
    {
        return $this->encodeTlv(0x30, // SEQUENCE
            $this->encodeOid($oid)
            . $this->encodeTlv(0x31, $valueDer) // SET OF
        );
    }

    /**
     * Encode signed attributes as a SET OF for signing.
     * Per RFC 5652 Section 5.4: the DER encoding of the SET OF must be computed
     * using an explicit SET OF tag (0x31), not the IMPLICIT [0] tag.
     *
     * The individual attributes must be DER-sorted per X.690 Section 11.6.
     *
     * @param  array<int, string>  $attrs  DER-encoded Attribute SEQUENCEs
     */
    private function encodeSignedAttributesForSigning(array $attrs): string
    {
        // Sort the DER-encoded attributes lexicographically per DER SET OF rules
        sort($attrs, SORT_STRING);

        return $this->encodeTlv(0x31, implode('', $attrs)); // SET OF
    }

    /**
     * Encode signed attributes with IMPLICIT [0] tag for embedding in SignerInfo.
     *
     * @param  array<int, string>  $attrs  DER-encoded Attribute SEQUENCEs
     */
    private function encodeSignedAttributesImplicit(array $attrs): string
    {
        // Sort per DER SET OF rules
        sort($attrs, SORT_STRING);

        return $this->encodeTlv(0xA0, implode('', $attrs)); // [0] IMPLICIT constructed
    }

    private function buildSignerInfoDer(
        string $issuerDnDer,
        BigInteger $serial,
        string $hashAlgo,
        array $signedAttrs,
        string $signature,
        PrivateKey $key,
    ): string {
        // version
        $versionDer = $this->encodeInteger(1);

        // sid: IssuerAndSerialNumber
        $serialDer = $this->encodeBigInteger($serial);
        $sidDer = $this->encodeTlv(0x30, $issuerDnDer . $serialDer); // SEQUENCE

        // digestAlgorithm
        $digestAlgDer = $this->encodeAlgorithmIdentifier($this->getDigestOid($hashAlgo));

        // signedAttrs [0] IMPLICIT
        $signedAttrsDer = $this->encodeSignedAttributesImplicit($signedAttrs);

        // signatureAlgorithm
        $sigAlgDer = $this->encodeAlgorithmIdentifier($this->getSignatureOid($key, $hashAlgo));

        // signature OCTET STRING
        $sigDer = $this->encodeTlv(0x04, $signature);

        return $this->encodeTlv(0x30,
            $versionDer
            . $sidDer
            . $digestAlgDer
            . $signedAttrsDer
            . $sigAlgDer
            . $sigDer
        );
    }

    private function computeSignature(PrivateKey $key, string $data, string $hashAlgo): string
    {
        if ($key instanceof RSA\PrivateKey) {
            $rsaKey = $key->withPadding(RSA::SIGNATURE_PKCS1);
            $rsaKey = $rsaKey->withHash($hashAlgo);

            return $rsaKey->sign($data);
        }

        if ($key instanceof EC\PrivateKey) {
            $ecKey = $key->withHash($hashAlgo);

            return $ecKey->sign($data);
        }

        throw new RuntimeException('Unsupported key type for CMS signature.');
    }

    private function doVerify(string $signedDataDer, ?string $content): bool
    {
        // Parse the ContentInfo
        $parsed = $this->parseContentInfo($signedDataDer);

        if (empty($parsed['signerInfos'])) {
            return false;
        }

        $signerInfo = $parsed['signerInfos'][0];

        // Extract the certificate from the SignedData
        $certDer = null;
        if (!empty($parsed['certificates'])) {
            $certDer = $parsed['certificates'][0];
        }

        if ($certDer === null) {
            return false;
        }

        // Determine content: from encapContentInfo or provided externally (detached)
        $data = $content;
        if ($data === null && isset($parsed['encapContent'])) {
            $data = $parsed['encapContent'];
        }

        if ($data === null) {
            return false;
        }

        // Get digest algorithm from signerInfo
        $hashAlgo = $this->resolveHashAlgoFromOid($signerInfo['digestAlgorithmOid']);
        if ($hashAlgo === null) {
            return false;
        }

        // Verify messageDigest attribute
        $computedDigest = hash($hashAlgo, $data, binary: true);
        $claimedDigest = $signerInfo['messageDigest'] ?? null;
        if ($claimedDigest === null || !hash_equals($computedDigest, $claimedDigest)) {
            return false;
        }

        // Verify signature over signed attributes
        $signedAttrsDer = $signerInfo['signedAttrsDer'] ?? null;
        $signature = $signerInfo['signature'] ?? null;
        if ($signedAttrsDer === null || $signature === null) {
            return false;
        }

        // Load the public key from the certificate
        $x509 = new X509();
        $certData = $x509->loadX509($certDer);
        $publicKey = $x509->getPublicKey();

        if ($publicKey instanceof RSA\PublicKey) {
            $publicKey = $publicKey->withPadding(RSA::SIGNATURE_PKCS1);
            $publicKey = $publicKey->withHash($hashAlgo);

            return $publicKey->verify($signedAttrsDer, $signature);
        }

        if ($publicKey instanceof EC\PublicKey) {
            $publicKey = $publicKey->withHash($hashAlgo);

            return $publicKey->verify($signedAttrsDer, $signature);
        }

        return false;
    }

    /**
     * Parse a DER-encoded ContentInfo wrapping SignedData.
     * Uses low-level DER parsing for maximum compatibility.
     *
     * @return array{signerInfos: array, certificates: array, encapContent: ?string}
     */
    private function parseContentInfo(string $der): array
    {
        $offset = 0;

        // ContentInfo SEQUENCE
        $contentInfo = $this->readTlv($der, $offset);
        $ciOffset = 0;

        // contentType OID
        $contentTypeRaw = $this->readTlv($contentInfo['value'], $ciOffset);
        // content [0] EXPLICIT
        $contentWrapper = $this->readTlv($contentInfo['value'], $ciOffset);
        $sdOffset = 0;

        // SignedData SEQUENCE
        $signedData = $this->readTlv($contentWrapper['value'], $sdOffset);
        $sdInner = 0;

        // version INTEGER
        $version = $this->readTlv($signedData['value'], $sdInner);

        // digestAlgorithms SET OF
        $digestAlgs = $this->readTlv($signedData['value'], $sdInner);

        // encapContentInfo SEQUENCE
        $encapCI = $this->readTlv($signedData['value'], $sdInner);
        $encapContent = $this->extractEncapContent($encapCI['value']);

        // Optional certificates [0] IMPLICIT and crls [1] IMPLICIT
        $certificates = [];
        $remaining = substr($signedData['value'], $sdInner);

        // Check for [0] certificates
        if (strlen($remaining) > 0 && (ord($remaining[0]) & 0xFF) === 0xA0) {
            $certSet = $this->readTlv($signedData['value'], $sdInner);
            $certificates = $this->extractCertificates($certSet['value']);
            $remaining = substr($signedData['value'], $sdInner);
        }

        // Check for [1] crls
        if (strlen($remaining) > 0 && (ord($remaining[0]) & 0xFF) === 0xA1) {
            $this->readTlv($signedData['value'], $sdInner); // skip crls
        }

        // signerInfos SET OF
        $signerInfosRaw = $this->readTlv($signedData['value'], $sdInner);
        $signerInfos = $this->parseSignerInfos($signerInfosRaw['value']);

        return [
            'signerInfos' => $signerInfos,
            'certificates' => $certificates,
            'encapContent' => $encapContent,
        ];
    }

    /**
     * Extract eContent from EncapsulatedContentInfo value bytes.
     */
    private function extractEncapContent(string $encapCiValue): ?string
    {
        $offset = 0;
        // eContentType OID
        $this->readTlv($encapCiValue, $offset);

        if ($offset >= strlen($encapCiValue)) {
            return null; // detached
        }

        // eContent [0] EXPLICIT
        $eContentWrapper = $this->readTlv($encapCiValue, $offset);
        $innerOffset = 0;
        // OCTET STRING
        $octetString = $this->readTlv($eContentWrapper['value'], $innerOffset);

        return $octetString['value'];
    }

    /**
     * Extract individual certificate DER blobs from the certificates [0] SET.
     *
     * @return array<int, string>
     */
    private function extractCertificates(string $certSetValue): array
    {
        $certs = [];
        $offset = 0;

        while ($offset < strlen($certSetValue)) {
            $tlv = $this->readTlv($certSetValue, $offset);
            // Each cert is a full SEQUENCE - rebuild with tag+length+value
            $certs[] = $this->encodeTlv($tlv['tag'], $tlv['value']);
        }

        return $certs;
    }

    /**
     * Parse SignerInfos from the SET OF value bytes.
     *
     * @return array<int, array>
     */
    private function parseSignerInfos(string $setOfValue): array
    {
        $infos = [];
        $offset = 0;

        while ($offset < strlen($setOfValue)) {
            $siTlv = $this->readTlv($setOfValue, $offset);
            $infos[] = $this->parseOneSignerInfo($siTlv['value']);
        }

        return $infos;
    }

    /**
     * Parse a single SignerInfo SEQUENCE value.
     */
    private function parseOneSignerInfo(string $value): array
    {
        $offset = 0;
        $result = [];

        // version
        $this->readTlv($value, $offset);

        // sid (IssuerAndSerialNumber SEQUENCE)
        $this->readTlv($value, $offset);

        // digestAlgorithm
        $digestAlg = $this->readTlv($value, $offset);
        $algOffset = 0;
        $algOidTlv = $this->readTlv($digestAlg['value'], $algOffset);
        $result['digestAlgorithmOid'] = $this->decodeOidValue($algOidTlv['value']);

        // signedAttrs [0] IMPLICIT (optional)
        $signedAttrsDer = null;
        $messageDigest = null;
        if ($offset < strlen($value) && (ord($value[$offset]) & 0xFF) === 0xA0) {
            $signedAttrsTlv = $this->readTlv($value, $offset);
            // Re-encode as SET OF (0x31) for signature verification
            $signedAttrsDer = $this->encodeTlv(0x31, $signedAttrsTlv['value']);
            // Extract messageDigest attribute
            $messageDigest = $this->extractMessageDigest($signedAttrsTlv['value']);
        }
        $result['signedAttrsDer'] = $signedAttrsDer;
        $result['messageDigest'] = $messageDigest;

        // signatureAlgorithm
        $this->readTlv($value, $offset);

        // signature OCTET STRING
        $sigTlv = $this->readTlv($value, $offset);
        $result['signature'] = $sigTlv['value'];

        // unsignedAttrs [1] IMPLICIT (optional) - skip
        return $result;
    }

    /**
     * Extract the messageDigest value from signed attributes bytes.
     */
    private function extractMessageDigest(string $attrsValue): ?string
    {
        $offset = 0;

        while ($offset < strlen($attrsValue)) {
            $attr = $this->readTlv($attrsValue, $offset);
            $attrOffset = 0;
            $oidTlv = $this->readTlv($attr['value'], $attrOffset);
            $oid = $this->decodeOidValue($oidTlv['value']);

            if ($oid === self::OID_MESSAGE_DIGEST) {
                $valuesSet = $this->readTlv($attr['value'], $attrOffset);
                $valOffset = 0;
                $octetString = $this->readTlv($valuesSet['value'], $valOffset);

                return $octetString['value'];
            }
        }

        return null;
    }

    /**
     * Inject a counter-signature attribute into the first SignerInfo's unsignedAttrs.
     * This rebuilds the DER by locating and appending the unsigned attribute.
     */
    private function injectCounterSignature(string $originalDer, string $counterSigAttr): string
    {
        // This is a simplified approach: we rebuild the entire structure.
        // Parse the original structure
        $offset = 0;
        $contentInfo = $this->readTlv($originalDer, $offset);
        $ciOffset = 0;
        $contentTypeRaw = $this->readTlv($contentInfo['value'], $ciOffset);
        $contentWrapper = $this->readTlv($contentInfo['value'], $ciOffset);
        $sdOffset = 0;
        $signedData = $this->readTlv($contentWrapper['value'], $sdOffset);

        // Walk through the SignedData to find the SignerInfos
        $sdInner = 0;
        $version = $this->readTlvRaw($signedData['value'], $sdInner);
        $digestAlgs = $this->readTlvRaw($signedData['value'], $sdInner);
        $encapCI = $this->readTlvRaw($signedData['value'], $sdInner);

        $certSetRaw = '';
        $remaining = substr($signedData['value'], $sdInner);
        if (strlen($remaining) > 0 && (ord($remaining[0]) & 0xFF) === 0xA0) {
            $certSetRaw = $this->readTlvRaw($signedData['value'], $sdInner);
        }

        $crlsRaw = '';
        $remaining = substr($signedData['value'], $sdInner);
        if (strlen($remaining) > 0 && (ord($remaining[0]) & 0xFF) === 0xA1) {
            $crlsRaw = $this->readTlvRaw($signedData['value'], $sdInner);
        }

        $signerInfosSetTlv = $this->readTlv($signedData['value'], $sdInner);

        // Parse the first SignerInfo and append unsigned attr
        $siOffset = 0;
        $firstSignerInfoTlv = $this->readTlv($signerInfosSetTlv['value'], $siOffset);

        // Rebuild the SignerInfo with the counter-signature as unsigned attribute
        $newUnsignedAttrs = $this->encodeTlv(0xA1, $counterSigAttr); // [1] IMPLICIT

        // If existing unsigned attrs exist, we need to merge. Simplified: just append.
        $newSignerInfo = $this->encodeTlv(0x30,
            $firstSignerInfoTlv['value'] . $newUnsignedAttrs
        );

        // Remaining signer infos
        $remainingSignerInfos = substr($signerInfosSetTlv['value'], $siOffset);

        $newSignerInfosSet = $this->encodeTlv(0x31, $newSignerInfo . $remainingSignerInfos);

        // Reassemble SignedData
        $newSignedData = $this->encodeTlv(0x30,
            $version . $digestAlgs . $encapCI . $certSetRaw . $crlsRaw . $newSignerInfosSet
        );

        // Reassemble ContentInfo
        return $this->encodeTlv(0x30,
            $this->encodeTlv($contentTypeRaw[0], substr($contentTypeRaw, $this->tagLenSize($contentTypeRaw)))
                . $this->encodeTlv(0xA0, $newSignedData)
        );
    }

    // ========================================================================
    // DER encoding helpers
    // ========================================================================

    /**
     * Encode a TLV (Tag-Length-Value) structure.
     */
    private function encodeTlv(int $tag, string $value): string
    {
        $length = strlen($value);

        return chr($tag) . $this->encodeLength($length) . $value;
    }

    /**
     * Encode a DER length.
     */
    private function encodeLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';
        $temp = $length;
        while ($temp > 0) {
            $bytes = chr($temp & 0xFF) . $bytes;
            $temp >>= 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * Encode an OID as a DER OBJECT IDENTIFIER.
     */
    private function encodeOid(string $oid): string
    {
        $parts = array_map('intval', explode('.', $oid));

        if (count($parts) < 2) {
            throw new RuntimeException("Invalid OID: {$oid}");
        }

        // First two components combined
        $encoded = chr($parts[0] * 40 + $parts[1]);

        for ($i = 2; $i < count($parts); $i++) {
            $value = $parts[$i];
            if ($value < 128) {
                $encoded .= chr($value);
            } else {
                $bytes = '';
                $temp = $value;
                while ($temp > 0) {
                    $bytes = chr(($temp & 0x7F) | ($bytes === '' ? 0x00 : 0x80)) . $bytes;
                    $temp >>= 7;
                }
                // Set high bit on all bytes except the last
                $result = '';
                for ($j = 0; $j < strlen($bytes); $j++) {
                    if ($j < strlen($bytes) - 1) {
                        $result .= chr(ord($bytes[$j]) | 0x80);
                    } else {
                        $result .= $bytes[$j];
                    }
                }
                $encoded .= $result;
            }
        }

        return $this->encodeTlv(0x06, $encoded);
    }

    /**
     * Encode an INTEGER (small values).
     */
    private function encodeInteger(int $value): string
    {
        if ($value >= 0 && $value <= 127) {
            return $this->encodeTlv(0x02, chr($value));
        }

        $bytes = '';
        $temp = $value;
        while ($temp > 0) {
            $bytes = chr($temp & 0xFF) . $bytes;
            $temp >>= 8;
        }

        // Add leading zero if high bit set
        if (ord($bytes[0]) & 0x80) {
            $bytes = "\x00" . $bytes;
        }

        return $this->encodeTlv(0x02, $bytes);
    }

    /**
     * Encode a BigInteger as DER INTEGER.
     */
    private function encodeBigInteger(BigInteger $value): string
    {
        $bytes = $value->toBytes();

        // Ensure positive encoding (add leading zero if high bit set)
        if (strlen($bytes) > 0 && (ord($bytes[0]) & 0x80)) {
            $bytes = "\x00" . $bytes;
        }

        if ($bytes === '') {
            $bytes = "\x00";
        }

        return $this->encodeTlv(0x02, $bytes);
    }

    /**
     * Encode a UTCTime.
     */
    private function encodeUtcTime(\DateTimeInterface $dt): string
    {
        $formatted = $dt->format('ymdHis') . 'Z';

        return $this->encodeTlv(0x17, $formatted);
    }

    /**
     * Encode an AlgorithmIdentifier SEQUENCE with NULL parameters.
     */
    private function encodeAlgorithmIdentifier(string $oid): string
    {
        return $this->encodeTlv(0x30,
            $this->encodeOid($oid) . "\x05\x00" // NULL parameters
        );
    }

    /**
     * Read a TLV from DER bytes at the given offset, advancing the offset.
     *
     * @return array{tag: int, value: string}
     */
    private function readTlv(string $data, int &$offset): array
    {
        if ($offset >= strlen($data)) {
            throw new RuntimeException('Unexpected end of DER data.');
        }

        $tag = ord($data[$offset]);
        $offset++;

        // Read length
        $length = ord($data[$offset]);
        $offset++;

        if ($length & 0x80) {
            $numBytes = $length & 0x7F;
            $length = 0;
            for ($i = 0; $i < $numBytes; $i++) {
                $length = ($length << 8) | ord($data[$offset]);
                $offset++;
            }
        }

        $value = substr($data, $offset, $length);
        $offset += $length;

        return ['tag' => $tag, 'value' => $value];
    }

    /**
     * Read a raw TLV (returns the complete DER bytes including tag and length).
     */
    private function readTlvRaw(string $data, int &$offset): string
    {
        $start = $offset;
        $this->readTlv($data, $offset);

        return substr($data, $start, $offset - $start);
    }

    /**
     * Get the size of the tag+length prefix of a raw TLV.
     */
    private function tagLenSize(string $rawTlv): int
    {
        $offset = 1; // skip tag
        $lenByte = ord($rawTlv[$offset]);
        $offset++;

        if ($lenByte & 0x80) {
            $offset += ($lenByte & 0x7F);
        }

        return $offset;
    }

    /**
     * Decode an OID value (without tag+length).
     */
    private function decodeOidValue(string $value): string
    {
        if (strlen($value) === 0) {
            return '';
        }

        $first = ord($value[0]);
        $components = [intdiv($first, 40), $first % 40];

        $current = 0;
        for ($i = 1; $i < strlen($value); $i++) {
            $byte = ord($value[$i]);
            $current = ($current << 7) | ($byte & 0x7F);
            if (!($byte & 0x80)) {
                $components[] = $current;
                $current = 0;
            }
        }

        return implode('.', $components);
    }

    private function getDigestOid(string $hashAlgo): string
    {
        return self::DIGEST_OIDS[strtolower($hashAlgo)]
            ?? throw new RuntimeException("Unsupported hash algorithm: {$hashAlgo}");
    }

    private function getSignatureOid(PrivateKey $key, string $hashAlgo): string
    {
        $algo = strtolower($hashAlgo);

        if ($key instanceof RSA\PrivateKey) {
            return self::RSA_SIGNATURE_OIDS[$algo]
                ?? throw new RuntimeException("Unsupported RSA hash: {$hashAlgo}");
        }

        if ($key instanceof EC\PrivateKey) {
            return self::EC_SIGNATURE_OIDS[$algo]
                ?? throw new RuntimeException("Unsupported EC hash: {$hashAlgo}");
        }

        throw new RuntimeException('Unsupported key type.');
    }

    private function resolveHashAlgoFromOid(string $oid): ?string
    {
        $map = array_flip(self::DIGEST_OIDS);

        return $map[$oid] ?? null;
    }

    private function getCertificateDer(Certificate $cert): string
    {
        if (!empty($cert->certificate_der)) {
            return $cert->certificate_der;
        }

        if (!empty($cert->certificate_pem)) {
            $pem = $cert->certificate_pem;
            $pem = preg_replace('/-----BEGIN CERTIFICATE-----/', '', $pem);
            $pem = preg_replace('/-----END CERTIFICATE-----/', '', $pem);

            return base64_decode(preg_replace('/\s+/', '', $pem));
        }

        throw new RuntimeException('Certificate has no DER or PEM data.');
    }

    /**
     * Get chain certificates DER (excluding the leaf).
     */
    private function getChainCertsDer(Certificate $cert): string
    {
        $chainDer = '';
        $issuer = $cert->issuerCertificate;

        while ($issuer !== null) {
            $chainDer .= $this->getCertificateDer($issuer);
            $issuer = $issuer->issuerCertificate;
        }

        return $chainDer;
    }

    private function persistMessage(Certificate $cert, string $der, string $hashAlgo, bool $detached): void
    {
        try {
            $message = CmsMessage::create([
                'tenant_id' => $cert->tenant_id,
                'type' => 'signed',
                'signer_certificate_id' => $cert->id,
                'content_type' => 'application/pkcs7-mime',
                'is_detached' => $detached,
                'hash_algorithm' => $hashAlgo,
                'encryption_algorithm' => null,
                'message_der' => $der,
                'metadata' => [
                    'signer_fingerprint' => $cert->fingerprint_sha256,
                ],
            ]);

            CmsMessageSigned::dispatch($message);
        } catch (\Throwable) {
            // Persistence is best-effort; do not fail the signing operation
        }
    }
}
