<?php

declare(strict_types=1);

namespace CA\Cms\Services;

use CA\Cms\Contracts\CmsEncryptorInterface;
use CA\Cms\Events\CmsMessageDecrypted;
use CA\Cms\Events\CmsMessageEncrypted;
use CA\Cms\Models\CmsMessage;
use CA\Crt\Models\Certificate;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use phpseclib3\File\X509;
use phpseclib3\Math\BigInteger;
use RuntimeException;

class CmsEncryptor implements CmsEncryptorInterface
{
    private const OID_ENVELOPED_DATA = '1.2.840.113549.1.7.3';
    private const OID_DATA = '1.2.840.113549.1.7.1';
    private const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';

    // AES-CBC OIDs
    private const ENCRYPTION_OIDS = [
        'aes-128-cbc' => '2.16.840.1.101.3.4.1.2',
        'aes-192-cbc' => '2.16.840.1.101.3.4.1.22',
        'aes-256-cbc' => '2.16.840.1.101.3.4.1.42',
    ];

    // Key sizes in bytes
    private const KEY_SIZES = [
        'aes-128-cbc' => 16,
        'aes-192-cbc' => 24,
        'aes-256-cbc' => 32,
    ];

    private const IV_SIZE = 16; // AES block size

    public function encrypt(string $data, array $recipientCerts, array $options = []): string
    {
        if (empty($recipientCerts)) {
            throw new RuntimeException('At least one recipient certificate is required.');
        }

        $algorithm = $options['encryption'] ?? config('ca-cms.default_encryption', 'aes-256-cbc');
        $keySize = self::KEY_SIZES[$algorithm]
            ?? throw new RuntimeException("Unsupported encryption algorithm: {$algorithm}");

        $encryptionOid = self::ENCRYPTION_OIDS[$algorithm];

        // 1. Generate random content encryption key (CEK) and IV
        $cek = random_bytes($keySize);
        $iv = random_bytes(self::IV_SIZE);

        // 2. Encrypt the content using AES-CBC with PKCS#7 padding
        $encryptedContent = $this->aesEncrypt($data, $cek, $iv);

        // 3. For each recipient, encrypt the CEK with their public key
        $recipientInfosDer = '';
        foreach ($recipientCerts as $recipientCert) {
            $recipientInfosDer .= $this->buildKeyTransRecipientInfo($recipientCert, $cek);
        }

        // 4. Build EncryptedContentInfo
        $encryptedContentInfoDer = $this->buildEncryptedContentInfo(
            $encryptionOid,
            $iv,
            $encryptedContent,
        );

        // 5. Build RecipientInfos SET
        $recipientInfosSetDer = $this->encodeTlv(0x31, $recipientInfosDer);

        // 6. Build EnvelopedData
        $versionDer = $this->encodeInteger(0); // version 0 for ktri with issuerAndSerialNumber

        $envelopedDataDer = $this->encodeTlv(0x30,
            $versionDer
            . $recipientInfosSetDer
            . $encryptedContentInfoDer
        );

        // 7. Wrap in ContentInfo
        $contentInfoDer = $this->encodeTlv(0x30,
            $this->encodeOid(self::OID_ENVELOPED_DATA)
            . $this->encodeTlv(0xA0, $envelopedDataDer) // [0] EXPLICIT
        );

        // Persist
        $this->persistMessage($recipientCerts, $contentInfoDer, $algorithm);

        return $contentInfoDer;
    }

    public function decrypt(string $envelopedDataDer, Certificate $cert, PrivateKey $key): string
    {
        $parsed = $this->parseEnvelopedData($envelopedDataDer);

        // Find the matching RecipientInfo for this certificate
        $certDer = $this->getCertificateDer($cert);
        $x509 = new X509();
        $x509->loadX509($certDer);
        $certSerial = $x509->currentCert['tbsCertificate']['serialNumber'];

        $encryptedKey = null;
        foreach ($parsed['recipientInfos'] as $ri) {
            if ($ri['serial']->equals($certSerial)) {
                $encryptedKey = $ri['encryptedKey'];
                break;
            }
        }

        if ($encryptedKey === null) {
            throw new RuntimeException('No matching RecipientInfo found for the provided certificate.');
        }

        // Decrypt the CEK
        if ($key instanceof RSA\PrivateKey) {
            $rsaKey = $key->withPadding(RSA::ENCRYPTION_PKCS1);
            $cek = $rsaKey->decrypt($encryptedKey);
        } else {
            throw new RuntimeException('Only RSA key transport is supported for CMS decryption.');
        }

        if ($cek === false || $cek === null) {
            throw new RuntimeException('Failed to decrypt content encryption key.');
        }

        // Decrypt the content
        $plaintext = $this->aesDecrypt(
            $parsed['encryptedContent'],
            $cek,
            $parsed['iv'],
        );

        CmsMessageDecrypted::dispatch($cert, $envelopedDataDer);

        return $plaintext;
    }

    // ========================================================================
    // Private implementation
    // ========================================================================

    /**
     * Build a KeyTransRecipientInfo for a single recipient.
     */
    private function buildKeyTransRecipientInfo(Certificate $cert, string $cek): string
    {
        $certDer = $this->getCertificateDer($cert);
        $x509 = new X509();
        $x509->loadX509($certDer);

        $issuerDnDer = $x509->getIssuerDN(X509::DN_ASN1);
        $serial = $x509->currentCert['tbsCertificate']['serialNumber'];
        $publicKey = $x509->getPublicKey();

        if (!($publicKey instanceof RSA\PublicKey)) {
            throw new RuntimeException('Only RSA recipient certificates are supported for key transport.');
        }

        // Encrypt the CEK with RSA PKCS#1 v1.5
        $rsaPubKey = $publicKey->withPadding(RSA::ENCRYPTION_PKCS1);
        $encryptedKey = $rsaPubKey->encrypt($cek);

        // version: 0 for issuerAndSerialNumber
        $versionDer = $this->encodeInteger(0);

        // rid: IssuerAndSerialNumber
        $serialDer = $this->encodeBigInteger($serial);
        $ridDer = $this->encodeTlv(0x30, $issuerDnDer . $serialDer);

        // keyEncryptionAlgorithm: rsaEncryption
        $keyEncAlgDer = $this->encodeAlgorithmIdentifier(self::OID_RSA_ENCRYPTION);

        // encryptedKey OCTET STRING
        $encKeyDer = $this->encodeTlv(0x04, $encryptedKey);

        return $this->encodeTlv(0x30,
            $versionDer . $ridDer . $keyEncAlgDer . $encKeyDer
        );
    }

    /**
     * Build the EncryptedContentInfo SEQUENCE.
     */
    private function buildEncryptedContentInfo(string $encryptionOid, string $iv, string $encryptedContent): string
    {
        // contentType: id-data
        $contentTypeDer = $this->encodeOid(self::OID_DATA);

        // contentEncryptionAlgorithm with IV as parameter
        $ivOctetString = $this->encodeTlv(0x04, $iv); // OCTET STRING
        $algDer = $this->encodeTlv(0x30,
            $this->encodeOid($encryptionOid) . $ivOctetString
        );

        // encryptedContent [0] IMPLICIT OCTET STRING
        $encContentDer = $this->encodeTlv(0x80, $encryptedContent); // [0] IMPLICIT primitive

        return $this->encodeTlv(0x30,
            $contentTypeDer . $algDer . $encContentDer
        );
    }

    /**
     * Parse a DER-encoded ContentInfo wrapping EnvelopedData.
     *
     * @return array{recipientInfos: array, encryptedContent: string, iv: string, encryptionOid: string}
     */
    private function parseEnvelopedData(string $der): array
    {
        $offset = 0;

        // ContentInfo SEQUENCE
        $contentInfo = $this->readTlv($der, $offset);
        $ciOffset = 0;

        // contentType OID
        $this->readTlv($contentInfo['value'], $ciOffset);

        // content [0] EXPLICIT
        $contentWrapper = $this->readTlv($contentInfo['value'], $ciOffset);
        $edOffset = 0;

        // EnvelopedData SEQUENCE
        $envelopedData = $this->readTlv($contentWrapper['value'], $edOffset);
        $edInner = 0;

        // version
        $this->readTlv($envelopedData['value'], $edInner);

        // Check for originatorInfo [0] IMPLICIT (optional)
        $remaining = substr($envelopedData['value'], $edInner);
        if (strlen($remaining) > 0 && (ord($remaining[0]) & 0xFF) === 0xA0) {
            $this->readTlv($envelopedData['value'], $edInner);
        }

        // recipientInfos SET OF
        $recipientInfosSet = $this->readTlv($envelopedData['value'], $edInner);
        $recipientInfos = $this->parseRecipientInfos($recipientInfosSet['value']);

        // encryptedContentInfo SEQUENCE
        $encContentInfo = $this->readTlv($envelopedData['value'], $edInner);
        $eciOffset = 0;

        // contentType OID
        $this->readTlv($encContentInfo['value'], $eciOffset);

        // contentEncryptionAlgorithm AlgorithmIdentifier
        $algId = $this->readTlv($encContentInfo['value'], $eciOffset);
        $algOffset = 0;
        $algOidTlv = $this->readTlv($algId['value'], $algOffset);
        $encryptionOid = $this->decodeOidValue($algOidTlv['value']);

        // IV from algorithm parameters
        $ivTlv = $this->readTlv($algId['value'], $algOffset);
        $iv = $ivTlv['value'];

        // encryptedContent [0] IMPLICIT OCTET STRING
        $encContentTlv = $this->readTlv($encContentInfo['value'], $eciOffset);
        $encryptedContent = $encContentTlv['value'];

        return [
            'recipientInfos' => $recipientInfos,
            'encryptedContent' => $encryptedContent,
            'iv' => $iv,
            'encryptionOid' => $encryptionOid,
        ];
    }

    /**
     * Parse RecipientInfos SET OF value.
     *
     * @return array<int, array{serial: BigInteger, encryptedKey: string}>
     */
    private function parseRecipientInfos(string $setOfValue): array
    {
        $infos = [];
        $offset = 0;

        while ($offset < strlen($setOfValue)) {
            $riTlv = $this->readTlv($setOfValue, $offset);
            $riOffset = 0;

            // version
            $this->readTlv($riTlv['value'], $riOffset);

            // rid: IssuerAndSerialNumber SEQUENCE
            $ridTlv = $this->readTlv($riTlv['value'], $riOffset);
            $ridOffset = 0;

            // issuer Name (skip)
            $this->readTlv($ridTlv['value'], $ridOffset);

            // serialNumber INTEGER
            $serialTlv = $this->readTlv($ridTlv['value'], $ridOffset);
            $serial = new BigInteger($serialTlv['value'], 256);

            // keyEncryptionAlgorithm (skip)
            $this->readTlv($riTlv['value'], $riOffset);

            // encryptedKey OCTET STRING
            $encKeyTlv = $this->readTlv($riTlv['value'], $riOffset);

            $infos[] = [
                'serial' => $serial,
                'encryptedKey' => $encKeyTlv['value'],
            ];
        }

        return $infos;
    }

    /**
     * AES-CBC encrypt with PKCS#7 padding using phpseclib.
     */
    private function aesEncrypt(string $data, string $key, string $iv): string
    {
        $keyLen = strlen($key);
        $cipher = match ($keyLen) {
            16 => new \phpseclib3\Crypt\AES('cbc'),
            24 => new \phpseclib3\Crypt\AES('cbc'),
            32 => new \phpseclib3\Crypt\AES('cbc'),
            default => throw new RuntimeException("Invalid AES key length: {$keyLen}"),
        };

        $cipher->setKey($key);
        $cipher->setIV($iv);
        $cipher->enablePadding(); // PKCS#7 padding

        return $cipher->encrypt($data);
    }

    /**
     * AES-CBC decrypt with PKCS#7 padding removal using phpseclib.
     */
    private function aesDecrypt(string $data, string $key, string $iv): string
    {
        $cipher = new \phpseclib3\Crypt\AES('cbc');
        $cipher->setKey($key);
        $cipher->setIV($iv);
        $cipher->enablePadding(); // PKCS#7 padding removal

        $result = $cipher->decrypt($data);

        if ($result === false) {
            throw new RuntimeException('AES decryption failed.');
        }

        return $result;
    }

    // ========================================================================
    // DER encoding helpers (shared with CmsSigner)
    // ========================================================================

    private function encodeTlv(int $tag, string $value): string
    {
        return chr($tag) . $this->encodeLength(strlen($value)) . $value;
    }

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

    private function encodeOid(string $oid): string
    {
        $parts = array_map('intval', explode('.', $oid));

        if (count($parts) < 2) {
            throw new RuntimeException("Invalid OID: {$oid}");
        }

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

        if (ord($bytes[0]) & 0x80) {
            $bytes = "\x00" . $bytes;
        }

        return $this->encodeTlv(0x02, $bytes);
    }

    private function encodeBigInteger(BigInteger $value): string
    {
        $bytes = $value->toBytes();

        if (strlen($bytes) > 0 && (ord($bytes[0]) & 0x80)) {
            $bytes = "\x00" . $bytes;
        }

        if ($bytes === '') {
            $bytes = "\x00";
        }

        return $this->encodeTlv(0x02, $bytes);
    }

    private function encodeAlgorithmIdentifier(string $oid): string
    {
        return $this->encodeTlv(0x30,
            $this->encodeOid($oid) . "\x05\x00"
        );
    }

    /**
     * @return array{tag: int, value: string}
     */
    private function readTlv(string $data, int &$offset): array
    {
        if ($offset >= strlen($data)) {
            throw new RuntimeException('Unexpected end of DER data.');
        }

        $tag = ord($data[$offset]);
        $offset++;

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

    private function persistMessage(array $recipientCerts, string $der, string $algorithm): void
    {
        try {
            $firstCert = $recipientCerts[0] ?? null;
            $message = CmsMessage::create([
                'tenant_id' => $firstCert?->tenant_id,
                'type' => 'enveloped',
                'signer_certificate_id' => null,
                'content_type' => 'application/pkcs7-mime',
                'is_detached' => false,
                'hash_algorithm' => null,
                'encryption_algorithm' => $algorithm,
                'message_der' => $der,
                'metadata' => [
                    'recipient_count' => count($recipientCerts),
                ],
            ]);

            CmsMessageEncrypted::dispatch($message);
        } catch (\Throwable) {
            // Persistence is best-effort
        }
    }
}
