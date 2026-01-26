<?php

namespace RiseTechApps\TokenSecurity;

use Carbon\Carbon;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use PragmaRX\Google2FALaravel\Google2FA;

class TokenSecurity
{
    private static string $headerOperation = 'X-OTP-Operation';
    private static string $headerCode = 'X-OTP-Code';

    protected bool $isVerified = false;
    protected bool $shouldAbort = true;
    protected bool $ignorePath = false;

    protected ?Authenticatable $authenticatable = null;
    protected ?string $manualContact = null;
    protected ?string $manualId = null;

    protected ?Google2FA $google2FA = null;
    protected string $secret = "";

    /**
     * Define o usuário para autenticação
     */
    public function auth(Authenticatable $authenticatable): static
    {
        $this->authenticatable = $authenticatable;
        return $this;
    }

    /**
     * Define um destinatário manual (email ou celular)
     */
    public function to(string $contact, ?string $identifier = null): static
    {
        $this->manualContact = $contact;

        $namespace = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
        $this->manualId = $identifier ?? \Ramsey\Uuid\Uuid::uuid5($namespace, $contact)->toString();

        return $this;
    }

    public function setShouldAbort(bool $status): static
    {
        $this->shouldAbort = $status;
        return $this;
    }

    public function ignorePath(bool $status = true): static
    {
        $this->ignorePath = $status;
        return $this;
    }

    public function setSecret(string $secret): static
    {
        $this->secret = $secret;
        return $this;
    }

    protected function getTargetId()
    {
        return $this->authenticatable ? $this->authenticatable->getKey() : $this->manualId;
    }

    private function handleResponse(array $data, int $status = 428): array
    {
        if ($this->shouldAbort) {
            abort(response()->json($data, $status));
        }
        return $data;
    }

    /**
     * Roteador principal
     * @throws \Throwable
     */
    public function generateToken($type = null)
    {
        if (request()->hasHeader(static::$headerOperation) && request()->hasHeader(static::$headerCode)) {
            if ($this->isValid()) {
                return true;
            }

            return $this->handleResponse([
                'type' => Str::lower(request()->header(static::$headerOperation)),
                'error' => 'Invalid or expired token'
            ]);
        }

        $type = $type ?? ($this->authenticatable ? $this->authenticatable->routeNotificationPreference() : 'email');
        return $this->generate($type);
    }

    // Métodos de atalho corrigidos
    public function generateTokenSms() { return $this->generateToken('sms'); }
    public function generateTokenEmail() { return $this->generateToken('email'); }
    public function generateTokenTotp() { return $this->generateToken('totp'); }

    /**
     * @throws \Throwable
     */
    protected function generate(string $type)
    {
        if ($type === 'totp') {
            return $this->handleResponse(['uuid' => 'totp', 'type' => 'totp']);
        }

        $targetId = $this->getTargetId();
        if (!$targetId) {
            throw new \Exception("Destinatário não definido. Use ->auth() ou ->to().");
        }

        $result = DB::transaction(function () use ($type, $targetId) {
            $path = request()->path();

            $query = DB::table('tokens')
                ->where('authenticatable_id', $targetId)
                ->where('type', $type)
                ->when(!$this->ignorePath, fn($q) => $q->where('path', $path))
                ->whereNull('used')
                ->where('expires_at', '>', now())
                ->lockForUpdate()
                ->first();

            if ($query) {
                return ['uuid' => $query->uuid, 'type' => $query->type, 'is_new' => false];
            }

            $token = mt_rand(100000, 999999);
            $uuid = Str::uuid()->toString();

            DB::table('tokens')->insert([
                'authenticatable_id' => $targetId,
                'type' => $type,
                'path' => $path,
                'uuid' => $uuid,
                'token' => $token,
                'expires_at' => Carbon::now()->addMinutes(10),
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            $this->sendNotification($type, $token);

            return ['uuid' => $uuid, 'type' => $type, 'is_new' => true];
        });

        return $this->handleResponse(['uuid' => $result['uuid'], 'type' => $result['type']]);
    }

    protected function sendNotification(string $type, int|string $token): void
    {
        $notificationClass = config("token-security.notifications.{$type}");
        if (!$notificationClass || !class_exists($notificationClass)) return;

        $notification = (new $notificationClass($token))->locale(app()->getLocale());

        if ($this->authenticatable) {
            $this->authenticatable->notify($notification);
        } elseif ($this->manualContact) {
            $driver = ($type === 'sms') ? 'vonage' : 'mail';
            Notification::route($driver, $this->manualContact)->notify($notification);
        }
    }

    public function isValid(): bool
    {
        $code = request()->header(static::$headerCode);
        $operation = Str::lower(request()->header(static::$headerOperation));
        $targetId = $this->getTargetId();

        $key = 'otp_limit:'.$targetId.request()->ip();
        if (RateLimiter::tooManyAttempts($key, 5)) {
            return false;
        }

        if ($operation === 'totp' || $operation === 'google2fa') {
            return $this->isValidTotp($code);
        }

        $isValid = DB::transaction(function () use ($code, $targetId) {
            $tokenRecord = DB::table('tokens')
                ->where('authenticatable_id', $targetId)
                ->when(!$this->ignorePath, fn($q) => $q->where('path', request()->path()))
                ->where('token', $code)
                ->whereNull('used')
                ->where('expires_at', '>', now())
                ->lockForUpdate()
                ->first();

            if (!$tokenRecord) {
                return false;
            }

            DB::table('tokens')->where('id', $tokenRecord->id)->update([
                'used' => now(),
                'updated_at' => now(),
            ]);

            return true;
        });

        if (!$isValid) {
            RateLimiter::hit($key, 60);
        } else {
            RateLimiter::clear($key);
        }

        return $isValid;
    }

    public function isValidTotp($code, $secret = null): bool
    {
        $this->google2FA ??= new Google2FA(request());
        $secret = $secret ?? ($this->secret ?: ($this->authenticatable ? $this->authenticatable->twoFactorSecret() : null));
        return $secret ? $this->google2FA->verifyGoogle2FA($secret, $code) : false;
    }

    public function generateSecretGoogle2FA(): string
    {
        return (new Google2FA(request()))->generateSecretKey();
    }

    public function getQrCodeUrl(string $app, string $email, string $secret)
    {
        return (new Google2FA(request()))->getQrCodeUrl($app, $email, $secret);
    }
}
