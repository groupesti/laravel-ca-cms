<?php

declare(strict_types=1);

namespace CA\Cms\Console\Commands;

use CA\Cms\Contracts\CmsEncryptorInterface;
use CA\Crt\Models\Certificate;
use Illuminate\Console\Command;
use Throwable;

class CmsEncryptCommand extends Command
{
    protected $signature = 'ca:cms:encrypt {file : Path to the file to encrypt}
                            {--recipient=* : Recipient certificate UUID (repeatable)}
                            {--output= : Output file path}
                            {--algorithm=aes-256-cbc : Encryption algorithm (aes-256-cbc, aes-128-cbc)}';

    protected $description = 'Encrypt a file using CMS/PKCS#7 EnvelopedData';

    public function handle(CmsEncryptorInterface $encryptor): int
    {
        $filePath = $this->argument('file');
        if (!file_exists($filePath) || !is_readable($filePath)) {
            $this->error("File not found or not readable: {$filePath}");

            return self::FAILURE;
        }

        $recipientUuids = $this->option('recipient');
        if (empty($recipientUuids)) {
            $this->error('At least one --recipient is required.');

            return self::FAILURE;
        }

        try {
            $recipientCerts = Certificate::whereIn('uuid', $recipientUuids)->get()->all();

            if (empty($recipientCerts)) {
                $this->error('No valid recipient certificates found for the given UUIDs.');

                return self::FAILURE;
            }

            if (count($recipientCerts) !== count($recipientUuids)) {
                $this->warn('Some recipient UUIDs did not match any certificates.');
            }

            $data = file_get_contents($filePath);
            $algorithm = $this->option('algorithm') ?? 'aes-256-cbc';

            $this->info('Encrypting file...');

            $cms = $encryptor->encrypt($data, $recipientCerts, [
                'encryption' => $algorithm,
            ]);

            $outputPath = $this->option('output') ?? $filePath . '.p7m';
            file_put_contents($outputPath, $cms);

            $this->info("CMS enveloped data written to: {$outputPath}");
            $this->info('Algorithm: ' . $algorithm);
            $this->info('Recipients: ' . count($recipientCerts));
            $this->info('Size: ' . strlen($cms) . ' bytes');

            return self::SUCCESS;
        } catch (Throwable $e) {
            $this->error("Encryption failed: {$e->getMessage()}");

            return self::FAILURE;
        }
    }
}
