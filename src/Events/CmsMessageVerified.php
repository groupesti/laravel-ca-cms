<?php

declare(strict_types=1);

namespace CA\Cms\Events;

use Illuminate\Foundation\Events\Dispatchable;

class CmsMessageVerified
{
    use Dispatchable;

    public function __construct(
        public readonly bool $valid,
        public readonly string $signedDataDer,
    ) {}
}
