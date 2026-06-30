<?php

namespace App\Providers;

use App\Fingerprinting\Support\PluginLoader;
use App\Fingerprinting\Support\PluginRegistry;
use App\Scanners\Contracts\ScannerProcessRunnerInterface;
use App\Scanners\Support\SymfonyScannerProcessRunner;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->app->singleton(PluginRegistry::class, function ($app): PluginRegistry {
            return new PluginRegistry($app->make(PluginLoader::class)->load());
        });

        $this->app->bind(ScannerProcessRunnerInterface::class, SymfonyScannerProcessRunner::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //
    }
}
