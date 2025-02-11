<?php

namespace RiseTechApps\TokenSecurity;

use Carbon\Carbon;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class TokenSecurity
{
    private static string $headerOperation = 'X-OTP-Operation';
    private static string $headerCode = 'X-OTP-Code';
    protected bool $isVerified = false;

    protected Authenticatable $authenticatable;

    public function auth(Authenticatable $authenticatable): static
    {
        $this->authenticatable = $authenticatable;
        return $this;
    }

    public function generateToken(): bool|string|null
    {
        if (request()->hasHeader(static::$headerOperation) && request()->hasHeader(static::$headerCode)) {
            $status = $this->isValid();
            if ($status === true) {
                return true;
            }
        }

        return $this->generate($this->authenticatable->routeNotificationPreference());
    }

    public function generateTokenSms(): array|bool|null
    {
        if (request()->hasHeader(static::$headerOperation) && request()->hasHeader(static::$headerCode)) {
            $status = $this->isValid();
            if ($status === true) {
                return true;
            }
        }

        return $this->generate('sms');
    }

    public function generateTokenEmail(): array|bool|null
    {
        if (request()->hasHeader(static::$headerOperation) && request()->hasHeader(static::$headerCode)) {
            $status = $this->isValid();
            if ($status === true) {
                return true;
            }
        }

        return $this->generate('email');
    }

    protected function generate(string $type): string|bool|null
    {
        $token = mt_rand(100000, 999999);
        $expiresAt = Carbon::now()->addMinutes(10);
        $uuid = Str::uuid()->toString();

        $path = request()->path();
        $auth = $this->authenticatable->getKey();

        $query = DB::table('tokens')->where(
            [
                'authenticatable_id' => $auth,
                'path' => $path,
                'type' => $type,
            ]
        )->whereNull('used')
            ->where(function ($query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })->first();

        if (!is_null($query)) {

            $data = ['uuid' => $query->uuid, 'type' => $query->type];
            if ($this->isVerified) {
                $data['message'] = "Invalid Token";
            }
            abort(response()->json($data, 418));

        }

        DB::table('tokens')->insertGetId([
            'authenticatable_id' => $auth,
            'type' => $type,
            'path' => $path,
            'uuid' => $uuid,
            'token' => $token,
            'expires_at' => $expiresAt,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::commit();

        $this->sendNotification($type, $token);

        abort(response()->json(['uuid' => $uuid, 'type' => $type], 418));

    }

    protected function sendNotification(string $type, int|string $token): void
    {
        $notification = match ($type) {
            'sms' => config('token-security.notifications.sms'),
            'email' => config('token-security.notifications.email'),
            default => null
        };

        if (!is_null($notification)) {

            $this->authenticatable->notify(new $notification($token));
        }
    }

    private function isValid(): ?bool
    {
        $path = request()->path();

        $tokenRecord = DB::table('tokens')
            ->where('authenticatable_id', $this->authenticatable->getKey())
            ->where('path', $path)
            ->where('token', request()->header(self::$headerCode))
            ->where('used', null)
            ->where('deleted_at', null)
            ->first();

        if (!$tokenRecord || Carbon::now()->greaterThan($tokenRecord->expires_at)) {
            $this->isVerified = true;
            return false;
        }

        DB::table('tokens')->where('id', $tokenRecord->id)->update([
            'used' => now(),
            'deleted_at' => now(),
        ]);

        return true;
    }
}
