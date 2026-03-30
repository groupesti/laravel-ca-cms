<?php

declare(strict_types=1);

namespace CA\Cms\Facades;

use CA\Cms\Contracts\CmsBuilderInterface;
use Illuminate\Support\Facades\Facade;

/**
 * @method static self data(string $data)
 * @method static self signer(\CA\Crt\Models\Certificate $cert, \phpseclib3\Crypt\Common\PrivateKey $key)
 * @method static self recipient(\CA\Crt\Models\Certificate $cert)
 * @method static self detached(bool $detached = true)
 * @method static self hash(string $algorithm)
 * @method static self encryption(string $algorithm)
 * @method static string sign()
 * @method static string encrypt()
 * @method static string signAndEncrypt()
 */
class CaCms extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return CmsBuilderInterface::class;
    }
}
