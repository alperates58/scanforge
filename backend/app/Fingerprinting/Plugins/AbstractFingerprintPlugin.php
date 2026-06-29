<?php

namespace App\Fingerprinting\Plugins;

use App\Fingerprinting\Contracts\FingerprintPluginInterface;
use App\Fingerprinting\Support\FingerprintContext;
use App\Fingerprinting\Support\FingerprintRule;
use Closure;

abstract class AbstractFingerprintPlugin implements FingerprintPluginInterface
{
    protected function rule(
        string $key,
        string $sourceType,
        ?string $sourceKey,
        int $confidence,
        string $description,
        Closure $matcher,
    ): FingerprintRule {
        return new FingerprintRule($key, $sourceType, $sourceKey, $confidence, $description, $matcher);
    }

    /**
     * @return array<string, mixed>|null
     */
    protected function contains(string $value, string $needle, ?string $versionPattern = null): ?array
    {
        if (! str_contains(strtolower($value), strtolower($needle))) {
            return null;
        }

        return [
            'source_value' => $value,
            'version' => $versionPattern ? $this->version($value, $versionPattern) : null,
        ];
    }

    protected function version(string $value, string $pattern): ?string
    {
        if (preg_match($pattern, $value, $matches) !== 1) {
            return null;
        }

        return $matches[1] ?? null;
    }

    /**
     * @return array<string, mixed>|null
     */
    protected function header(FingerprintContext $context, string $header, ?string $needle = null, ?string $versionPattern = null): ?array
    {
        $value = $context->header($header);

        if ($value === null) {
            return null;
        }

        if ($needle !== null && ! str_contains(strtolower($value), strtolower($needle))) {
            return null;
        }

        return [
            'source_key' => $header,
            'source_value' => $value,
            'version' => $versionPattern ? $this->version($value, $versionPattern) : null,
        ];
    }
}
