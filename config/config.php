<?php

/*
 * You can place your custom package configuration in here.
 */
return [
    'notifications' => [
        'sms' => \RiseTechApps\TokenSecurity\Notifications\TokenSmsNotification::class,
        'email' => \RiseTechApps\TokenSecurity\Notifications\TokenEmailNotification::class
    ],

    // Tentativas de código erradas (e-mail, SMS e TOTP). Atingido um dos
    // limites, todo código é recusado até a janela passar.
    'limits' => [
        // Por destinatário + IP.
        'per_ip' => (int) env('TOKEN_SECURITY_LIMIT_PER_IP', 5),
        'per_ip_decay_seconds' => (int) env('TOKEN_SECURITY_LIMIT_PER_IP_DECAY', 60),
        // Por destinatário, de qualquer IP (chute distribuído).
        'per_target' => (int) env('TOKEN_SECURITY_LIMIT_PER_TARGET', 10),
        'per_target_decay_seconds' => (int) env('TOKEN_SECURITY_LIMIT_PER_TARGET_DECAY', 900),
    ],
];
