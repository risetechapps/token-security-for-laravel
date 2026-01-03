<?php

namespace RiseTechApps\TokenSecurity;

use Carbon\Carbon;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PragmaRX\Google2FALaravel\Google2FA;

class TokenSecurity
{
    private static string $headerOperation = 'X-OTP-Operation';
    private static string $headerCode = 'X-OTP-Code';

    protected bool $isVerified = false;
    protected bool $shouldAbort = true;

    protected bool $ignorePath = false;

    protected Authenticatable $authenticatable;
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
     * Define se a classe deve disparar abort() ou retornar dados
     */
    public function setShouldAbort(bool $status): static
    {
        $this->shouldAbort = $status;
        return $this;
    }

    /**
     * Define se a validação deve ignorar o path da requisição
     */
    public function ignorePath(bool $status = true): static
    {
        $this->ignorePath = $status;
        return $this;
    }

    /**
     * Define o segredo manualmente (usado para validação temporária/setup)
     */
    public function setSecret(string $secret): static
    {
        $this->secret = $secret;
        return $this;
    }

    /**
     * Centraliza a lógica de resposta/interrupção
     */
    private function handleResponse(array $data, int $status = 418)
    {
        if ($this->shouldAbort) {
            abort(response()->json($data, $status));
        }
        return $data;
    }

    /**
     * Tenta validar se houver headers, caso contrário gera um novo token
     */
    public function generateToken($type = null)
    {
        if (request()->hasHeader(static::$headerOperation) && request()->hasHeader(static::$headerCode)) {
            $status = $this->isValid();
            if ($status === true) {
                return true;
            }
        }

        $type = $type ?? $this->authenticatable->routeNotificationPreference();
        return $this->generate($type);
    }

    public function generateTokenSms()
    {
        if (request()->hasHeader(static::$headerOperation) && request()->hasHeader(static::$headerCode)) {
            return $this->isValid();
        }
        return $this->generate('sms');
    }

    public function generateTokenEmail()
    {
        if (request()->hasHeader(static::$headerOperation) && request()->hasHeader(static::$headerCode)) {
            return $this->isValid();
        }
        return $this->generate('email');
    }

    public function generateTokenTotp()
    {
        if (request()->hasHeader(static::$headerOperation) && request()->hasHeader(static::$headerCode)) {
            return $this->isValid();
        }
        return $this->generate('totp');
    }

    /**
     * Lógica principal de geração e armazenamento do token
     */
    protected function generate(string $type)
    {
        if ($type === 'totp') {
            return $this->handleResponse(['uuid' => $type, 'type' => $type]);
        }

        $result = DB::transaction(function () use ($type) {
            $path = request()->path();
            $authId = $this->authenticatable->getKey();

            // Busca token ativo com Lock de linha
            $query = DB::table('tokens')
                ->where([
                    'authenticatable_id' => $authId,
                    'type' => $type,
                ])
                ->when(!$this->ignorePath, function ($q) {
                    return $q->where('path', request()->path());
                })
                ->whereNull('used')
                ->where(function ($q) {
                    $q->whereNull('expires_at')->orWhere('expires_at', '>', now());
                })
                ->lockForUpdate()
                ->first();

            if ($query) {
                return ['uuid' => $query->uuid, 'type' => $query->type, 'is_new' => false];
            }

            $token = mt_rand(100000, 999999);
            $uuid = Str::uuid()->toString();

            DB::table('tokens')->insert([
                'authenticatable_id' => $authId,
                'type' => $type,
                'path' => $path,
                'uuid' => $uuid,
                'token' => $token,
                'expires_at' => Carbon::now()->addMinutes(10),
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            // Envia notificação dentro da transação para garantir rollback se falhar
            $this->sendNotification($type, $token);

            return ['uuid' => $uuid, 'type' => $type, 'is_new' => true];
        });

        $responseData = ['uuid' => $result['uuid'], 'type' => $result['type']];

        if (!$result['is_new'] && $this->isVerified) {
            $responseData['message'] = "Invalid Token";
        }

        return $this->handleResponse($responseData);
    }

    protected function sendNotification(string $type, int|string $token): void
    {
        $notification = match ($type) {
            'sms' => config('token-security.notifications.sms'),
            'email' => config('token-security.notifications.email'),
            default => null
        };

        if ($notification && class_exists($notification)) {
            $this->authenticatable->notify((new $notification($token))->locale(app()->getLocale()));
        }
    }

    /**
     * Valida o token recebido via Header
     */
    private function isValid(): bool
    {
        $code = request()->header(static::$headerCode);
        $operation = Str::lower(request()->header(static::$headerOperation));

        if ($operation === 'totp') {
            return $this->isValidTotp($code);
        }

        return DB::transaction(function () use ($code) {
            $path = request()->path();

            $tokenRecord = DB::table('tokens')
                ->where('authenticatable_id', $this->authenticatable->getKey())
                ->when(!$this->ignorePath, function ($q) {
                    return $q->where('path', request()->path());
                })
                ->where('token', $code)
                ->whereNull('used')
                ->whereNull('deleted_at')
                ->lockForUpdate()
                ->first();

            if (!$tokenRecord || Carbon::now()->greaterThan($tokenRecord->expires_at)) {
                $this->isVerified = true;
                return false;
            }

            DB::table('tokens')->where('id', $tokenRecord->id)->update([
                'used' => now(),
                'deleted_at' => now(),
                'updated_at' => now(),
            ]);

            return true;
        });
    }

    /* --- Google 2FA / TOTP Methods --- */

    public function generateSecretGoogle2FA(): string
    {
        $this->google2FA ??= new Google2FA(request());
        return $this->google2FA->generateSecretKey();
    }

    public function getQrCodeUrl(string $app, string $email, string $secret)
    {
        $this->google2FA ??= new Google2FA(request());
        return $this->google2FA->getQrCodeUrl($app, $email, $secret);
    }

    public function isValidTotp($code, $secret = null): bool
    {
        $this->google2FA ??= new Google2FA(request());

        $secret = $secret ?? ($this->secret !== "" ? $this->secret : $this->authenticatable->google2fa_secret);

        return $this->google2FA->verifyGoogle2FA($secret, $code);
    }
}
