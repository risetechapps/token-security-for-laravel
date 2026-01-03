<?php

namespace RiseTechApps\TokenSecurity;

use Illuminate\Support\ServiceProvider;

class TokenSecurityServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     */
    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/config.php' => config_path('token-security.php'),
            ], 'config');
        }
    }

    /**
     * Register the application services.
     */
    public function register(): void
    {
        // Register the main class to use with the facade
        $this->app->singleton(TokenSecurity::class, function () {
            return new TokenSecurity;
        });

        $this->mergeConfigFrom(__DIR__ . '/../config/config.php', 'token-security');
    }
}
