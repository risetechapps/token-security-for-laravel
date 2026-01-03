<?php

namespace RiseTechApps\TokenSecurity\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class TokenEmailNotification extends Notification
{
    use Queueable;
    private $token;

    public function __construct($token)
    {
        $this->token = $token;
    }

    public function via($notifiable)
    {
        return ['mail'];
    }

    public function toMail($notifiable)
    {
        return (new MailMessage)
            ->subject('Your Security Code')
            ->greeting('Hello, ' . $notifiable->name)
            ->line('You have requested an operation that requires additional authentication.')
            ->line('Your verification code is:')
            ->line($this->token) // Destaca o código em um quadro
            ->line('This code expires in 10 minutes.')
            ->line("If you didn't request it, ignore this email.");
    }
}
