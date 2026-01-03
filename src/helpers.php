<?php

declare(strict_types=1);

if (!function_exists('tokenSecurity')) {
    function tokenSecurity(): \RiseTechApps\TokenSecurity\TokenSecurity
    {
        return app(\RiseTechApps\TokenSecurity\TokenSecurity::class);
    }
}
