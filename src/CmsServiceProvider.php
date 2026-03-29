<?php

declare(strict_types=1);

namespace CA\Cms;

use CA\Cms\Console\Commands\CmsDecryptCommand;
use CA\Cms\Console\Commands\CmsEncryptCommand;
use CA\Cms\Console\Commands\CmsSignCommand;
use CA\Cms\Console\Commands\CmsVerifyCommand;
use CA\Cms\Contracts\CmsBuilderInterface;
use CA\Cms\Contracts\CmsEncryptorInterface;
use CA\Cms\Contracts\CmsSignerInterface;
use CA\Cms\Services\CmsBuilder;
use CA\Cms\Services\CmsEncryptor;
use CA\Cms\Services\CmsSigner;
use CA\Cms\Services\SmimeHandler;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

class CmsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/ca-cms.php',
            'ca-cms',
        );

        $this->app->singleton(CmsSignerInterface::class, CmsSigner::class);

        $this->app->singleton(CmsEncryptorInterface::class, CmsEncryptor::class);

        $this->app->bind(CmsBuilderInterface::class, function ($app): CmsBuilder {
            return new CmsBuilder(
                signer: $app->make(CmsSignerInterface::class),
                encryptor: $app->make(CmsEncryptorInterface::class),
            );
        });

        $this->app->singleton(SmimeHandler::class, function ($app): SmimeHandler {
            return new SmimeHandler(
                signer: $app->make(CmsSignerInterface::class),
                encryptor: $app->make(CmsEncryptorInterface::class),
            );
        });

        $this->app->alias(CmsBuilderInterface::class, 'ca-cms');
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/ca-cms.php' => config_path('ca-cms.php'),
            ], 'ca-cms-config');

            $this->publishes([
                __DIR__ . '/../database/migrations/' => database_path('migrations'),
            ], 'ca-cms-migrations');

            $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

            $this->commands([
                CmsSignCommand::class,
                CmsVerifyCommand::class,
                CmsEncryptCommand::class,
                CmsDecryptCommand::class,
            ]);
        }

        $this->registerRoutes();
    }

    private function registerRoutes(): void
    {
        if (!config('ca-cms.routes.enabled', true)) {
            return;
        }

        Route::prefix(config('ca-cms.routes.prefix', 'api/ca/cms'))
            ->middleware(config('ca-cms.routes.middleware', ['api']))
            ->group(__DIR__ . '/../routes/api.php');
    }
}
