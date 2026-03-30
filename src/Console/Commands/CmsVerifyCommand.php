<?php

declare(strict_types=1);

namespace CA\Cms\Console\Commands;

use CA\Cms\Contracts\CmsSignerInterface;
use Illuminate\Console\Command;
use Throwable;

class CmsVerifyCommand extends Command
{
    protected $signature = 'ca:cms:verify {file : Path to the CMS signed file}
                            {--content= : Path to the original content file (for detached signatures)}';

    protected $description = 'Verify a CMS/PKCS#7 signed file';

    public function handle(CmsSignerInterface $signer): int
    {
        $filePath = $this->argument('file');
        if (!file_exists($filePath) || !is_readable($filePath)) {
            $this->error("File not found or not readable: {$filePath}");

            return self::FAILURE;
        }

        try {
            $signedDataDer = file_get_contents($filePath);

            $content = null;
            if ($this->option('content')) {
                $contentPath = $this->option('content');
                if (!file_exists($contentPath) || !is_readable($contentPath)) {
                    $this->error("Content file not found or not readable: {$contentPath}");

                    return self::FAILURE;
                }
                $content = file_get_contents($contentPath);
            }

            $this->info('Verifying CMS signature...');

            $valid = $signer->verify($signedDataDer, $content);

            if ($valid) {
                $this->info('Signature verification: VALID');

                return self::SUCCESS;
            }

            $this->error('Signature verification: INVALID');

            return self::FAILURE;
        } catch (Throwable $e) {
            $this->error("Verification failed: {$e->getMessage()}");

            return self::FAILURE;
        }
    }
}
