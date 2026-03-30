<?php

declare(strict_types=1);

namespace CA\Cms\Console\Commands;

use CA\Cms\Contracts\CmsSignerInterface;
use CA\Crt\Models\Certificate;
use CA\Key\Contracts\KeyManagerInterface;
use CA\Key\Models\Key;
use Illuminate\Console\Command;
use Throwable;

class CmsSignCommand extends Command
{
    protected $signature = 'ca:cms:sign {file : Path to the file to sign}
                            {--cert= : Certificate UUID}
                            {--key= : Key UUID (if different from certificate key)}
                            {--detached : Produce a detached signature}
                            {--output= : Output file path}
                            {--hash=sha256 : Hash algorithm (sha256, sha384, sha512)}';

    protected $description = 'Sign a file using CMS/PKCS#7';

    public function handle(CmsSignerInterface $signer, KeyManagerInterface $keyManager): int
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

            $data = file_get_contents($filePath);
            $hashAlgo = $this->option('hash') ?? 'sha256';
            $detached = $this->option('detached');

            $options = [
                'hash' => $hashAlgo,
                'include_certs' => config('ca-cms.include_certs', true),
                'include_chain' => config('ca-cms.include_chain', false),
            ];

            $this->info('Signing file...');

            $cms = $detached
                ? $signer->signDetached($data, $cert, $privateKey, $options)
                : $signer->sign($data, $cert, $privateKey, $options);

            $outputPath = $this->option('output') ?? $filePath . ($detached ? '.p7s' : '.p7m');
            file_put_contents($outputPath, $cms);

            $this->info("CMS signed data written to: {$outputPath}");
            $this->info('Hash algorithm: ' . $hashAlgo);
            $this->info('Detached: ' . ($detached ? 'yes' : 'no'));
            $this->info('Size: ' . strlen($cms) . ' bytes');

            return self::SUCCESS;
        } catch (Throwable $e) {
            $this->error("Signing failed: {$e->getMessage()}");

            return self::FAILURE;
        }
    }
}
