<?php

/*
 * You can place your custom package configuration in here.
 */
return [
    'notifications' => [
        'sms' => \RiseTechApps\TokenSecurity\Notifications\TokenSmsNotification::class,
        'email' => \RiseTechApps\TokenSecurity\Notifications\TokenEmailNotification::class
    ]
];
