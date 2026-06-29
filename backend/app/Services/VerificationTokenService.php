<?php

namespace App\Services;

use App\Models\Website;

class VerificationTokenService
{
    public function plainToken(Website $website): string
    {
        $material = implode('|', [
            'scanforge-domain-verification',
            (string) $website->id,
            (string) $website->normalized_host,
        ]);

        return 'sf_'.$this->base64Url(hash_hmac('sha256', $material, $this->signingKey(), true), 42);
    }

    public function hashToken(string $token): string
    {
        return hash_hmac('sha256', $token, $this->signingKey());
    }

    public function ensureHash(Website $website): string
    {
        $token = $this->plainToken($website);
        $hash = $this->hashToken($token);

        if ($website->verification_token_hash !== $hash) {
            $website->forceFill([
                'verification_token_hash' => $hash,
            ])->save();
        }

        return $token;
    }

    private function signingKey(): string
    {
        return (string) (config('app.key') ?: config('app.name') ?: 'scanforge-local-key');
    }

    private function base64Url(string $binary, int $length): string
    {
        $encoded = rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');

        return substr($encoded, 0, $length);
    }
}
