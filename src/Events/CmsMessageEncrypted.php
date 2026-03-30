<?php

declare(strict_types=1);

namespace CA\Cms\Events;

use CA\Cms\Models\CmsMessage;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class CmsMessageEncrypted
{
    use Dispatchable;
    use SerializesModels;

    public function __construct(
        public readonly CmsMessage $message,
    ) {}
}
