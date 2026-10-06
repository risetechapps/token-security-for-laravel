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

        $type ??= $this->authenticatable ? $this->authenticatable->routeNotificationPreference() : 'email';
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
        // App autenticador: o código vem do app, não há o que gerar nem enviar.
        // 'google2fa' é o nome usado pelo AuthFlow; antes caía no caminho de
        // e-mail/SMS e gravava um código de 6 dígitos que ninguém recebia.
        if ($type === 'totp' || $type === 'google2fa') {
            return $this->handleResponse(['uuid' => 'totp', 'type' => $type]);
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

            // random_int: gerador criptográfico (mt_rand é previsível).
            $token = random_int(100000, 999999);
            $uuid = Str::uuid()->toString();

            DB::table('tokens')->insert([
                'authenticatable_id' => $targetId,
                'type' => $type,
                'path' => $path,
                'uuid' => $uuid,
                // Só o hash: o código em texto puro dava acesso (por 10 min) a
                // quem lesse a tabela. O valor enviado vai só na notificação.
                'token' => static::hashCode($targetId, $token),
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

        $notification = new $notificationClass($token)->locale(app()->getLocale());

        if ($this->authenticatable) {
            $this->authenticatable->notify($notification);
        } elseif ($this->manualContact) {
            $driver = ($type === 'sms') ? 'vonage' : 'mail';
            Notification::route($driver, $this->manualContact)->notify($notification);
        }
    }

    /**
     * Valida o código enviado nos headers X-OTP-*.
     *
     * Dois limites de tentativas erradas, valendo para TODOS os tipos de código
     * (e-mail, SMS e TOTP):
     *  - por destinatário + IP (curto): freia o chute em sequência;
     *  - por destinatário, de qualquer IP (longo): freia o chute distribuído.
     *
     * Antes só o código de e-mail/SMS contava tentativa: o TOTP voltava direto
     * do isValidTotp() sem registrar o erro, e o código de 6 dígitos do app
     * autenticador podia ser chutado sem limite.
     */
    public function isValid(): bool
    {
        $code = (string) request()->header(static::$headerCode);
        $operation = Str::lower((string) request()->header(static::$headerOperation));
        $targetId = $this->getTargetId();

        $ipKey = 'otp_limit:' . $targetId . ':' . request()->ip();
        $targetKey = 'otp_limit_target:' . $targetId;

        if (RateLimiter::tooManyAttempts($ipKey, (int) config('token-security.limits.per_ip', 5))
            || RateLimiter::tooManyAttempts($targetKey, (int) config('token-security.limits.per_target', 10))) {
            return false;
        }

        $isValid = ($operation === 'totp' || $operation === 'google2fa')
            ? $this->isValidTotp($code)
            : $this->isValidStoredCode($code, $targetId);

        if ($isValid) {
            RateLimiter::clear($ipKey);
            RateLimiter::clear($targetKey);
        } else {
            RateLimiter::hit($ipKey, (int) config('token-security.limits.per_ip_decay_seconds', 60));
            RateLimiter::hit($targetKey, (int) config('token-security.limits.per_target_decay_seconds', 900));
        }

        return $isValid;
    }

    /**
     * Hash do código, amarrado ao destinatário. Com a chave da aplicação
     * (HMAC): sem ela, 6 dígitos se descobrem por força bruta no hash.
     */
    protected static function hashCode($targetId, int|string $code): string
    {
        return hash_hmac('sha256', $targetId . '|' . trim((string) $code), (string) config('app.key'));
    }

    /** Código de e-mail/SMS gravado na tabela `tokens`: de uso único. */
    protected function isValidStoredCode(string $code, $targetId): bool
    {
        return DB::transaction(function () use ($code, $targetId) {
            $tokenRecord = DB::table('tokens')
                ->where('authenticatable_id', $targetId)
                ->when(!$this->ignorePath, fn($q) => $q->where('path', request()->path()))
                ->where('token', static::hashCode($targetId, $code))
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
    }

    public function isValidTotp($code, $secret = null): bool
    {
        $this->google2FA ??= new Google2FA(request());
        $secret ??= $this->secret ?: ($this->authenticatable ? $this->authenticatable->twoFactorSecret() : null);
        return $secret ? $this->google2FA->verifyGoogle2FA($secret, $code) : false;
    }

    public function generateSecretGoogle2FA(): string
    {
        return new Google2FA(request())->generateSecretKey();
    }

    public function getQrCodeUrl(string $app, string $email, string $secret)
    {
        return new Google2FA(request())->getQrCodeUrl($app, $email, $secret);
    }
}
