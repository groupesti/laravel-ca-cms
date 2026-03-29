<?php

declare(strict_types=1);

namespace CA\Cms\Services;

use CA\Cms\Contracts\CmsEncryptorInterface;
use CA\Cms\Contracts\CmsSignerInterface;
use CA\Crt\Models\Certificate;
use phpseclib3\Crypt\Common\PrivateKey;
use RuntimeException;

class SmimeHandler
{
    public function __construct(
        private readonly CmsSignerInterface $signer,
        private readonly CmsEncryptorInterface $encryptor,
    ) {}

    /**
     * Sign a MIME message body, producing an S/MIME signed message.
     *
     * Options:
     *  - 'detached' (bool, default true): produce a clear-signed multipart/signed message
     *  - 'hash' (string, default from config): digest algorithm
     *  - 'include_certs' (bool, default true)
     *  - 'include_chain' (bool, default false)
     *
     * @param  array<string, mixed>  $options
     */
    public function signMessage(string $mimeBody, Certificate $cert, PrivateKey $key, array $options = []): string
    {
        $detached = $options['detached'] ?? true;
        $hashAlgo = $options['hash'] ?? config('ca-cms.default_hash', 'sha256');

        $signOptions = [
            'hash' => $hashAlgo,
            'include_certs' => $options['include_certs'] ?? config('ca-cms.include_certs', true),
            'include_chain' => $options['include_chain'] ?? config('ca-cms.include_chain', false),
        ];

        if ($detached) {
            $signatureDer = $this->signer->signDetached($mimeBody, $cert, $key, $signOptions);

            return $this->buildClearSignedMessage($mimeBody, $signatureDer, $hashAlgo);
        }

        $signedDer = $this->signer->sign($mimeBody, $cert, $key, $signOptions);
        $signedBase64 = $this->wrapBase64($signedDer);

        return $this->buildOpaqueSignedMessage($signedBase64);
    }

    /**
     * Encrypt a MIME message body for the given recipients.
     *
     * Options:
     *  - 'encryption' (string, default from config): content encryption algorithm
     *
     * @param  array<int, Certificate>  $recipientCerts
     * @param  array<string, mixed>     $options
     */
    public function encryptMessage(string $mimeBody, array $recipientCerts, array $options = []): string
    {
        $encryptionAlgo = $options['encryption'] ?? config('ca-cms.default_encryption', 'aes-256-cbc');

        $envelopedDer = $this->encryptor->encrypt($mimeBody, $recipientCerts, [
            'encryption' => $encryptionAlgo,
        ]);

        $envelopedBase64 = $this->wrapBase64($envelopedDer);

        return $this->buildEnvelopedMessage($envelopedBase64);
    }

    /**
     * Sign then encrypt a MIME message body.
     *
     * @param  array<int, Certificate>  $recipientCerts
     */
    public function signAndEncrypt(string $mimeBody, Certificate $cert, PrivateKey $key, array $recipientCerts): string
    {
        $hashAlgo = config('ca-cms.default_hash', 'sha256');

        $signedDer = $this->signer->sign($mimeBody, $cert, $key, [
            'hash' => $hashAlgo,
            'include_certs' => config('ca-cms.include_certs', true),
            'include_chain' => config('ca-cms.include_chain', false),
        ]);

        $envelopedDer = $this->encryptor->encrypt($signedDer, $recipientCerts, [
            'encryption' => config('ca-cms.default_encryption', 'aes-256-cbc'),
        ]);

        $envelopedBase64 = $this->wrapBase64($envelopedDer);

        return $this->buildEnvelopedMessage($envelopedBase64);
    }

    /**
     * Verify an S/MIME signed message.
     *
     * Supports both clear-signed (multipart/signed) and opaque (application/pkcs7-mime) formats.
     */
    public function verifyMessage(string $smimeMessage): bool
    {
        $contentType = $this->extractContentType($smimeMessage);

        if (str_contains($contentType, 'multipart/signed')) {
            return $this->verifyClearSigned($smimeMessage, $contentType);
        }

        if (str_contains($contentType, 'application/pkcs7-mime')) {
            return $this->verifyOpaque($smimeMessage);
        }

        return false;
    }

    /**
     * Decrypt an S/MIME enveloped message.
     */
    public function decryptMessage(string $smimeMessage, Certificate $cert, PrivateKey $key): string
    {
        $body = $this->extractSmimeBody($smimeMessage);
        $der = base64_decode($body, strict: true);

        if ($der === false) {
            throw new RuntimeException('Failed to decode S/MIME enveloped data from base64.');
        }

        return $this->encryptor->decrypt($der, $cert, $key);
    }

    // ========================================================================
    // Clear-signed message (multipart/signed)
    // ========================================================================

    private function buildClearSignedMessage(string $mimeBody, string $signatureDer, string $hashAlgo): string
    {
        $boundary = $this->generateBoundary();
        $signatureBase64 = $this->wrapBase64($signatureDer);
        $micAlg = $this->mapMicAlgorithm($hashAlgo);

        $headers = "MIME-Version: 1.0\r\n"
            . "Content-Type: multipart/signed;\r\n"
            . " protocol=\"application/pkcs7-signature\";\r\n"
            . " micalg={$micAlg};\r\n"
            . " boundary=\"{$boundary}\"\r\n";

        $body = "\r\n"
            . "--{$boundary}\r\n"
            . $mimeBody . "\r\n"
            . "--{$boundary}\r\n"
            . "Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n"
            . "Content-Transfer-Encoding: base64\r\n"
            . "Content-Disposition: attachment; filename=\"smime.p7s\"\r\n"
            . "\r\n"
            . $signatureBase64 . "\r\n"
            . "--{$boundary}--\r\n";

        return $headers . $body;
    }

    // ========================================================================
    // Opaque signed message (application/pkcs7-mime; smime-type=signed-data)
    // ========================================================================

    private function buildOpaqueSignedMessage(string $signedBase64): string
    {
        $headers = "MIME-Version: 1.0\r\n"
            . "Content-Type: application/pkcs7-mime; smime-type=signed-data; name=\"smime.p7m\"\r\n"
            . "Content-Transfer-Encoding: base64\r\n"
            . "Content-Disposition: attachment; filename=\"smime.p7m\"\r\n";

        return $headers . "\r\n" . $signedBase64 . "\r\n";
    }

    // ========================================================================
    // Enveloped message (application/pkcs7-mime; smime-type=enveloped-data)
    // ========================================================================

    private function buildEnvelopedMessage(string $envelopedBase64): string
    {
        $headers = "MIME-Version: 1.0\r\n"
            . "Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\n"
            . "Content-Transfer-Encoding: base64\r\n"
            . "Content-Disposition: attachment; filename=\"smime.p7m\"\r\n";

        return $headers . "\r\n" . $envelopedBase64 . "\r\n";
    }

    // ========================================================================
    // Verification helpers
    // ========================================================================

    private function verifyClearSigned(string $smimeMessage, string $contentType): bool
    {
        $boundary = $this->extractBoundary($contentType);
        if ($boundary === null) {
            return false;
        }

        $parts = $this->splitMultipart($smimeMessage, $boundary);
        if (count($parts) < 2) {
            return false;
        }

        $originalContent = $parts[0];
        $signaturePart = $parts[1];

        // Extract the base64-encoded signature from the signature part
        $signatureBase64 = $this->extractPartBody($signaturePart);
        $signatureDer = base64_decode($signatureBase64, strict: true);

        if ($signatureDer === false) {
            return false;
        }

        return $this->signer->verify($signatureDer, $originalContent);
    }

    private function verifyOpaque(string $smimeMessage): bool
    {
        $body = $this->extractSmimeBody($smimeMessage);
        $der = base64_decode($body, strict: true);

        if ($der === false) {
            return false;
        }

        return $this->signer->verify($der);
    }

    // ========================================================================
    // MIME parsing helpers
    // ========================================================================

    private function extractContentType(string $message): string
    {
        // Extract Content-Type header, handling folded headers
        if (preg_match('/^Content-Type:\s*(.+?)(?=\r?\n[^\s]|\r?\n\r?\n)/si', $message, $matches)) {
            return preg_replace('/\r?\n\s+/', ' ', trim($matches[1]));
        }

        return '';
    }

    private function extractBoundary(string $contentType): ?string
    {
        if (preg_match('/boundary="?([^";]+)"?/i', $contentType, $matches)) {
            return $matches[1];
        }

        return null;
    }

    /**
     * Split a MIME multipart message into its parts by boundary.
     *
     * @return array<int, string>
     */
    private function splitMultipart(string $message, string $boundary): array
    {
        // Separate headers from body
        $headerBodySplit = preg_split('/\r?\n\r?\n/', $message, 2);
        if (count($headerBodySplit) < 2) {
            return [];
        }

        $body = $headerBodySplit[1];

        // Split by boundary
        $parts = explode("--{$boundary}", $body);

        // Remove the preamble (before first boundary) and the epilogue (after closing boundary --)
        $result = [];
        foreach ($parts as $part) {
            $trimmed = trim($part);
            if ($trimmed === '' || $trimmed === '--') {
                continue;
            }
            // Remove leading CRLF
            $result[] = ltrim($part, "\r\n");
        }

        return $result;
    }

    /**
     * Extract the body content from a MIME part (after the part headers).
     */
    private function extractPartBody(string $part): string
    {
        $split = preg_split('/\r?\n\r?\n/', $part, 2);

        return isset($split[1]) ? trim($split[1]) : trim($part);
    }

    /**
     * Extract the base64 body from an S/MIME message (after MIME headers).
     */
    private function extractSmimeBody(string $smimeMessage): string
    {
        $split = preg_split('/\r?\n\r?\n/', $smimeMessage, 2);
        if (count($split) < 2) {
            throw new RuntimeException('Invalid S/MIME message: could not separate headers from body.');
        }

        return preg_replace('/\s+/', '', $split[1]);
    }

    // ========================================================================
    // Utility helpers
    // ========================================================================

    private function generateBoundary(): string
    {
        return '----=_Part_' . bin2hex(random_bytes(16));
    }

    private function wrapBase64(string $binaryData): string
    {
        return chunk_split(base64_encode($binaryData), 76, "\r\n");
    }

    private function mapMicAlgorithm(string $hashAlgo): string
    {
        return match (strtolower($hashAlgo)) {
            'sha1' => 'sha-1',
            'sha256' => 'sha-256',
            'sha384' => 'sha-384',
            'sha512' => 'sha-512',
            default => strtolower($hashAlgo),
        };
    }
}
