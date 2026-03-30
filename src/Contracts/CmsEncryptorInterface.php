<?php

declare(strict_types=1);

namespace CA\Cms\Contracts;

use CA\Crt\Models\Certificate;
use phpseclib3\Crypt\Common\PrivateKey;

interface CmsEncryptorInterface
{
    /**
     * Encrypt data for the given recipients producing CMS EnvelopedData.
     *
     * @param  array<int, Certificate>  $recipientCerts
     * @param  array<string, mixed>     $options
     */
    public function encrypt(string $data, array $recipientCerts, array $options = []): string;

    /**
     * Decrypt a CMS EnvelopedData structure.
     */
    public function decrypt(string $envelopedDataDer, Certificate $cert, PrivateKey $key): string;
}
