<?php

declare(strict_types=1);

namespace CA\Cms\Console\Commands;

use CA\Cms\Contracts\CmsEncryptorInterface;
use CA\Crt\Models\Certificate;
use CA\Key\Contracts\KeyManagerInterface;
use CA\Key\Models\Key;
use Illuminate\Console\Command;
use Throwable;

class CmsDecryptCommand extends Command
{
    protected $signature = 'ca:cms:decrypt {file : Path to the CMS enveloped file}
                            {--cert= : Certificate UUID}
                            {--key= : Key UUID (if different from certificate key)}
                            {--output= : Output file path}';

    protected $description = 'Decrypt a CMS/PKCS#7 enveloped file';

    public function handle(CmsEncryptorInterface $encryptor, KeyManagerInterface $keyManager): int
    {
        $filePath = $this->argument('file');
        if (!file_exists($filePath) || !is_readable($filePath)) {
            $this->error("File not found or not readable: {$filePath}");

            return self::FAILURE;
        }

        $certUuid = $this->option('cert');
        if ($certUuid === null) {
            $this->error('The --cert option is required.');

            return self::FAILURE;
        }

        try {
            $cert = Certificate::where('uuid', $certUuid)->firstOrFail();

            if ($this->option('key')) {
                $keyModel = Key::where('uuid', $this->option('key'))->firstOrFail();
                $privateKey = $keyManager->decryptPrivateKey($keyModel);
            } else {
                $privateKey = $keyManager->decryptPrivateKey($cert->key);
            }

            $envelopedDer = file_get_contents($filePath);

            $this->info('Decrypting file...');

            $plaintext = $encryptor->decrypt($envelopedDer, $cert, $privateKey);

            $outputPath = $this->option('output');
            if ($outputPath) {
                file_put_contents($outputPath, $plaintext);
                $this->info("Decrypted content written to: {$outputPath}");
            } else {
                // Write to stdout by stripping extension
                $baseName = preg_replace('/\.p7m$/i', '', $filePath);
                $outputPath = $baseName === $filePath ? $filePath . '.dec' : $baseName;
                file_put_contents($outputPath, $plaintext);
                $this->info("Decrypted content written to: {$outputPath}");
            }

            $this->info('Decrypted size: ' . strlen($plaintext) . ' bytes');

            return self::SUCCESS;
        } catch (Throwable $e) {
            $this->error("Decryption failed: {$e->getMessage()}");

            return self::FAILURE;
        }
    }
}
