<?php

namespace App\Services;

use App\Models\HttpObservation;
use App\Models\SslCertificate;
use App\Models\Website;

class DiscoveryScoreService
{
    /**
     * @param array<string, array{present: bool, value: string|null, recommendation: string}> $securityHeaders
     * @param list<array<string, mixed>> $cookies
     */
    public function score(Website $website, ?HttpObservation $observation, ?SslCertificate $certificate, array $securityHeaders, array $cookies): int
    {
        $score = 100;

        if ($website->scheme !== 'https') {
            $score -= 20;
        }

        if ($certificate?->days_remaining !== null) {
            if ($certificate->days_remaining < 0) {
                $score -= 30;
            } elseif ($certificate->days_remaining <= 14) {
                $score -= 10;
            }
        }

        foreach (['hsts' => 10, 'csp' => 8, 'x_frame_options' => 6, 'x_content_type_options' => 4] as $header => $penalty) {
            if (! ($securityHeaders[$header]['present'] ?? false)) {
                $score -= $penalty;
            }
        }

        $badCookieCount = count(array_filter($cookies, fn (array $cookie): bool => ! $cookie['secure'] || ! $cookie['http_only'] || ! $cookie['same_site']));
        $score -= min(15, $badCookieCount * 5);

        if ($observation?->server_header && preg_match('/\/\d+(?:\.\d+)+/', $observation->server_header) === 1) {
            $score -= 5;
        }

        if ($observation?->powered_by_header) {
            $score -= 5;
        }

        return max(0, min(100, $score));
    }
}
