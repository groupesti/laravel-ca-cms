<?php

declare(strict_types=1);

namespace CA\Cms\Models;

use CA\Crt\Models\Certificate;
use CA\Traits\Auditable;
use CA\Traits\BelongsToTenant;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class CmsMessage extends Model
{
    use HasUuids;
    use BelongsToTenant;
    use Auditable;

    protected $table = 'ca_cms_messages';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = [
        'tenant_id',
        'type',
        'signer_certificate_id',
        'content_type',
        'is_detached',
        'hash_algorithm',
        'encryption_algorithm',
        'message_der',
        'metadata',
    ];

    protected $hidden = [
        'message_der',
    ];

    protected function casts(): array
    {
        return [
            'is_detached' => 'boolean',
            'metadata' => 'array',
            'message_der' => 'binary',
        ];
    }

    // ---- Relationships ----

    public function signerCertificate(): BelongsTo
    {
        return $this->belongsTo(Certificate::class, 'signer_certificate_id');
    }
}
