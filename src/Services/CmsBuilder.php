<?php

declare(strict_types=1);

namespace CA\Cms\Services;

use CA\Cms\Contracts\CmsBuilderInterface;
use CA\Cms\Contracts\CmsEncryptorInterface;
use CA\Cms\Contracts\CmsSignerInterface;
use CA\Crt\Models\Certificate;
use phpseclib3\Crypt\Common\PrivateKey;
use RuntimeException;

class CmsBuilder implements CmsBuilderInterface
{
    private ?string $data = null;

    private ?Certificate $signerCert = null;

    private ?PrivateKey $signerKey = null;

    /** @var array<int, Certificate> */
    private array $recipients = [];

    private bool $isDetached = false;

    private string $hashAlgorithm;

    private string $encryptionAlgorithm;

    private bool $includeCertsFlag;

    private bool $includeChainFlag;

    public function __construct(
        private readonly CmsSignerInterface $signer,
        private readonly CmsEncryptorInterface $encryptor,
    ) {
        $this->hashAlgorithm = config('ca-cms.default_hash', 'sha256');
        $this->encryptionAlgorithm = config('ca-cms.default_encryption', 'aes-256-cbc');
        $this->includeCertsFlag = config('ca-cms.include_certs', true);
        $this->includeChainFlag = config('ca-cms.include_chain', false);
    }

    public function data(string $data): static
    {
        $this->data = $data;

        return $this;
    }

    public function signer(Certificate $cert, PrivateKey $key): static
    {
        $this->signerCert = $cert;
        $this->signerKey = $key;

        return $this;
    }

    public function recipient(Certificate $cert): static
    {
        $this->recipients[] = $cert;

        return $this;
    }

    public function detached(bool $detached = true): static
    {
        $this->isDetached = $detached;

        return $this;
    }

    public function hash(string $algorithm): static
    {
        $this->hashAlgorithm = $algorithm;

        return $this;
    }

    public function encryption(string $algorithm): static
    {
        $this->encryptionAlgorithm = $algorithm;

        return $this;
    }

    public function includeCerts(bool $include = true): static
    {
        $this->includeCertsFlag = $include;

        return $this;
    }

    public function includeChain(bool $include = true): static
    {
        $this->includeChainFlag = $include;

        return $this;
    }

    public function sign(): string
    {
        $this->validateForSigning();

        $options = $this->buildSignOptions();

        if ($this->isDetached) {
            return $this->signer->signDetached($this->data, $this->signerCert, $this->signerKey, $options);
        }

        return $this->signer->sign($this->data, $this->signerCert, $this->signerKey, $options);
    }

    public function encrypt(): string
    {
        $this->validateForEncryption();

        return $this->encryptor->encrypt($this->data, $this->recipients, [
            'encryption' => $this->encryptionAlgorithm,
        ]);
    }

    public function signAndEncrypt(): string
    {
        $this->validateForSigning();
        $this->validateForEncryption();

        // Sign first
        $signedData = $this->signer->sign($this->data, $this->signerCert, $this->signerKey, $this->buildSignOptions());

        // Then encrypt the signed data
        return $this->encryptor->encrypt($signedData, $this->recipients, [
            'encryption' => $this->encryptionAlgorithm,
        ]);
    }

    private function validateForSigning(): void
    {
        if ($this->data === null) {
            throw new RuntimeException('No data provided. Call data() before signing.');
        }

        if ($this->signerCert === null || $this->signerKey === null) {
            throw new RuntimeException('No signer provided. Call signer() before signing.');
        }
    }

    private function validateForEncryption(): void
    {
        if ($this->data === null) {
            throw new RuntimeException('No data provided. Call data() before encrypting.');
        }

        if (empty($this->recipients)) {
            throw new RuntimeException('No recipients provided. Call recipient() before encrypting.');
        }

        // Validate that each recipient certificate is suitable for encryption.
        // Encryption operations require the recipient's certificate (not the signer's)
        // to have key encipherment capabilities.
        foreach ($this->recipients as $recipient) {
            if (isset($recipient->key_usage) && is_array($recipient->key_usage)) {
                if (!in_array('keyEncipherment', $recipient->key_usage, true)
                    && !in_array('keyAgreement', $recipient->key_usage, true)) {
                    throw new RuntimeException(
                        'Recipient certificate does not have keyEncipherment or keyAgreement usage. '
                        . 'Encryption requires a recipient certificate with appropriate key usage.'
                    );
                }
            }
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function buildSignOptions(): array
    {
        return [
            'hash' => $this->hashAlgorithm,
            'include_certs' => $this->includeCertsFlag,
            'include_chain' => $this->includeChainFlag,
        ];
    }
}
