<?php

declare(strict_types=1);

namespace CA\Cms\Contracts;

use CA\Crt\Models\Certificate;
use phpseclib3\Crypt\Common\PrivateKey;

interface CmsSignerInterface
{
    /**
     * Sign data and produce a CMS SignedData DER-encoded structure.
     *
     * @param  array<string, mixed>  $options
     */
    public function sign(string $data, Certificate $cert, PrivateKey $key, array $options = []): string;

    /**
     * Produce a detached CMS SignedData (no encapsulated content).
     *
     * @param  array<string, mixed>  $options
     */
    public function signDetached(string $data, Certificate $cert, PrivateKey $key, array $options = []): string;

    /**
     * Add a counter-signature to an existing SignedData.
     */
    public function addCounterSignature(string $signedDataDer, Certificate $cert, PrivateKey $key): string;

    /**
     * Verify a CMS SignedData structure.
     *
     * @param  string       $signedDataDer  DER-encoded ContentInfo wrapping SignedData
     * @param  string|null  $content        Original content for detached signatures
     */
    public function verify(string $signedDataDer, ?string $content = null): bool;
}
