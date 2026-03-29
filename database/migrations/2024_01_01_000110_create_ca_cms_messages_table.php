<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('ca_cms_messages', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('tenant_id')->nullable()->index();
            $table->string('type')->index()->comment('signed, enveloped, signed_enveloped');
            $table->uuid('signer_certificate_id')->nullable();
            $table->string('content_type')->default('application/octet-stream');
            $table->boolean('is_detached')->default(false);
            $table->string('hash_algorithm')->nullable();
            $table->string('encryption_algorithm')->nullable();
            $table->binary('message_der');
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->foreign('signer_certificate_id')
                ->references('id')
                ->on('ca_certificates')
                ->nullOnDelete();
        });

        // Extend message_der to LONGBLOB on MySQL/MariaDB
        if (in_array(Schema::getConnection()->getDriverName(), ['mysql', 'mariadb'])) {
            Schema::getConnection()->statement(
                'ALTER TABLE ca_cms_messages MODIFY message_der LONGBLOB NOT NULL'
            );
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('ca_cms_messages');
    }
};
