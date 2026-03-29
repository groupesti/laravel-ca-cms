<?php

declare(strict_types=1);

namespace CA\Cms\Contracts;

use CA\Crt\Models\Certificate;
use phpseclib3\Crypt\Common\PrivateKey;

interface CmsBuilderInterface
{
    /**
     * Set the data to be signed or encrypted.
     */
    public function data(string $data): static;

    /**
     * Set the signer certificate and private key.
     */
    public function signer(Certificate $cert, PrivateKey $key): static;

    /**
     * Add a recipient certificate for encryption.
     */
    public function recipient(Certificate $cert): static;

    /**
     * Set whether the signature should be detached.
     */
    public function detached(bool $detached = true): static;

    /**
     * Set the hash algorithm.
     */
    public function hash(string $algorithm): static;

    /**
     * Set the content encryption algorithm.
     */
    public function encryption(string $algorithm): static;

    /**
     * Set whether to include signer certificates.
     */
    public function includeCerts(bool $include = true): static;

    /**
     * Set whether to include the full certificate chain.
     */
    public function includeChain(bool $include = true): static;

    /**
     * Sign the data and return DER-encoded CMS SignedData.
     */
    public function sign(): string;

    /**
     * Encrypt the data and return DER-encoded CMS EnvelopedData.
     */
    public function encrypt(): string;

    /**
     * Sign then encrypt: produce EnvelopedData wrapping SignedData.
     */
    public function signAndEncrypt(): string;
}
