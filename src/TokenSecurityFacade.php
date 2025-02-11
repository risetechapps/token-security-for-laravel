<?php

namespace RiseTechApps\TokenSecurity;

use Illuminate\Support\Facades\Facade;

/**
 * @see \RiseTechApps\TokenSecurity\Skeleton\SkeletonClass
 */
class TokenSecurityFacade extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'tokenSecurity';
    }
}
