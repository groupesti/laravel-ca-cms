<?php

declare(strict_types=1);

namespace CA\Cms\Events;

use CA\Crt\Models\Certificate;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class CmsMessageDecrypted
{
    use Dispatchable;
    use SerializesModels;

    public function __construct(
        public readonly Certificate $certificate,
        public readonly string $envelopedDataDer,
    ) {}
}
