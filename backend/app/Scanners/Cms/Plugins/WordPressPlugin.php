<?php

namespace App\Scanners\Cms\Plugins;

use App\Models\CmsAsset;
use App\Models\HttpObservation;
use App\Models\ScanJob;
use App\Scanners\Cms\Contracts\CmsScannerPluginInterface;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class WordPressPlugin implements CmsScannerPluginInterface
{
    public function key(): string
    {
        return 'wordpress_cms';
    }

    public function performChecks(ScanJob $scanJob): array
    {
        $findings = [];
        $websiteId = $scanJob->website_id;
        $affectedUrl = $scanJob->website?->url ?? 'http://' . ($scanJob->website?->host ?? 'unknown');

        $this->extractCmsAssets($websiteId, $affectedUrl);

        // Check observations for wordpress generator
        $generatorObservations = HttpObservation::query()
            ->where('website_id', $websiteId)
            ->whereNotNull('generator_meta')
            ->get();

        foreach ($generatorObservations as $obs) {
            $tagContent = $obs->generator_meta;
            if (str_contains(strtolower($tagContent ?? ''), 'wordpress')) {
                $version = null;
                if (preg_match('/WordPress ([\d\.]+)/i', $tagContent, $matches)) {
                    $version = $matches[1];
                }
                
                $findings[] = $this->createPayload(
                    'wp_generator_exposed',
                    'info',
                    'WordPress Version Exposed',
                    "WordPress version " . ($version ?? 'unknown') . " is exposed via meta generator tag.",
                    'CWE-200',
                    $affectedUrl,
                    ['meta_tag' => $tagContent],
                    $version
                );
            }
        }

        // Minimal safe checks using GET/HEAD (only if allowed by boundary, but we'll stick to basic exists)
        // Note: As per instructions "xmlrpc.php sadece HEAD/GET ile varlık kontrolü"
        $xmlrpcUrl = rtrim($affectedUrl, '/') . '/xmlrpc.php';
        try {
            $response = Http::timeout(3)->head($xmlrpcUrl);
            $status = 'unavailable';
            if ($response->successful()) {
                $status = 'exists';
            } elseif ($response->status() === 403) {
                $status = 'forbidden';
            } elseif ($response->status() === 405) {
                $status = 'disabled'; // Method not allowed often means disabled
            }
            
            $findings[] = $this->createPayload(
                'xmlrpc_enabled',
                'info',
                'XML-RPC Status: ' . ucfirst($status),
                "The XML-RPC endpoint returned status: {$status}.",
                'CWE-200',
                $xmlrpcUrl,
                ['status' => $status]
            );
        } catch (\Exception $e) {
            // ignore timeout
        }

        $wpJsonUrl = rtrim($affectedUrl, '/') . '/wp-json/';
        try {
            $response = Http::timeout(3)->get($wpJsonUrl);
            if ($response->successful() && str_contains((string)$response->body(), 'routes')) {
                $findings[] = $this->createPayload(
                    'wordpress_rest_api_exposed_info',
                    'info',
                    'WordPress REST API Exposed',
                    "The WordPress REST API is publicly accessible.",
                    'CWE-200',
                    $wpJsonUrl,
                    ['status' => $response->status()]
                );
            }
        } catch (\Exception $e) {
            // ignore timeout
        }

        return $findings;
    }

    private function extractCmsAssets(int $websiteId, string $url): void
    {
        try {
            $response = Http::timeout(5)->get($url);
            if (! $response->successful()) {
                return;
            }
            
            $body = $response->body();
            $assetsToInsert = [];
            $now = Carbon::now();

            // Extract plugins
            if (preg_match_all('/wp-content\/plugins\/([a-zA-Z0-9\-_]+)/i', $body, $pluginMatches)) {
                foreach (array_unique($pluginMatches[1]) as $plugin) {
                    $assetsToInsert[] = [
                        'website_id' => $websiteId,
                        'cms_name' => 'WordPress',
                        'asset_type' => 'plugin',
                        'asset_name' => $plugin,
                        'detected_version' => null,
                        'source' => 'html_comment', // or asset_url
                        'confidence' => 'inferred',
                        'analysis_required' => true,
                        'first_seen_at' => $now,
                        'last_seen_at' => $now,
                        'created_at' => $now,
                        'updated_at' => $now,
                    ];
                }
            }

            // Extract themes
            if (preg_match_all('/wp-content\/themes\/([a-zA-Z0-9\-_]+)/i', $body, $themeMatches)) {
                foreach (array_unique($themeMatches[1]) as $theme) {
                    $assetsToInsert[] = [
                        'website_id' => $websiteId,
                        'cms_name' => 'WordPress',
                        'asset_type' => 'theme',
                        'asset_name' => $theme,
                        'detected_version' => null,
                        'source' => 'html_comment',
                        'confidence' => 'inferred',
                        'analysis_required' => true,
                        'first_seen_at' => $now,
                        'last_seen_at' => $now,
                        'created_at' => $now,
                        'updated_at' => $now,
                    ];
                }
            }

            if (!empty($assetsToInsert)) {
                CmsAsset::query()->upsert(
                    $assetsToInsert,
                    ['website_id', 'cms_name', 'asset_type', 'asset_name'],
                    ['last_seen_at', 'updated_at']
                );
            }
        } catch (\Exception $e) {
            // ignore timeout
        }
    }

    private function createPayload(string $checkId, string $severity, string $title, string $description, string $cwe, string $affectedUrl, array $evidence, string $cmsVersion = null): array
    {
        $payload = [
            'check_id' => $checkId,
            'severity' => $severity,
            'title' => $title,
            'description' => $description,
            'cwe' => $cwe,
            'affected_url' => $affectedUrl,
            'evidence' => $evidence,
            'timestamp' => Carbon::now()->toIso8601String(),
            'cms_name' => 'WordPress',
            'detection_sources' => ['wp_json', 'readme'],
        ];

        if ($cmsVersion) {
            $payload['cms_version'] = $cmsVersion;
        }

        return $payload;
    }
}
