<?php

namespace App\Fingerprinting\Plugins;

use App\Fingerprinting\Support\FingerprintContext;
use App\Fingerprinting\Support\FingerprintRule;
use App\Fingerprinting\Support\RuleGroup;

class CommonTechnologyPlugin extends AbstractFingerprintPlugin
{
    public function key(): string
    {
        return 'common-web-technologies';
    }

    public function label(): string
    {
        return 'Common Web Technologies';
    }

    public function ruleGroups(): array
    {
        return [
            $this->server('apache', 'Apache', 'apache', '/apache\/([0-9][0-9.]+)/', ['nginx', 'caddy', 'litespeed', 'iis']),
            $this->server('caddy', 'Caddy', 'caddy', '/caddy\/([0-9][0-9.]+)/', ['apache', 'nginx', 'litespeed', 'iis']),
            $this->server('litespeed', 'LiteSpeed', 'litespeed', '/litespeed\/([0-9][0-9.]+)/', ['apache', 'nginx', 'caddy', 'iis']),
            $this->server('openresty', 'OpenResty', 'openresty', '/openresty\/([0-9][0-9.]+)/', ['apache', 'caddy', 'litespeed', 'iis']),
            $this->server('iis', 'IIS', 'microsoft-iis', '/microsoft-iis\/([0-9][0-9.]+)/', ['apache', 'nginx', 'caddy', 'litespeed']),
            $this->cdn('fastly', 'Fastly', ['fastly', 'x-served-by', 'varnish']),
            $this->cdn('cloudfront', 'CloudFront', ['cloudfront', 'x-amz-cf-id']),
            $this->cdn('akamai', 'Akamai', ['akamai', 'x-akamai-transformed', 'akamai-cache-status']),
            $this->cdn('bunny', 'Bunny', ['bunny', 'cdn-pullzone', 'x-bunny-cache']),
            $this->cdn('vercel', 'Vercel', ['vercel', 'x-vercel-id', 'x-vercel-cache']),
            $this->cdn('netlify', 'Netlify', ['netlify', 'x-nf-request-id']),
            $this->cdn('azure_front_door', 'Azure Front Door', ['azurefd', 'x-azure-ref', 'x-fd-healthprobe']),
            $this->cdn('google_cloud_cdn', 'Google Cloud CDN', ['google', 'x-goog-generation', 'x-goog-hash']),
            $this->framework('symfony', 'Symfony', 'framework', [
                $this->rule('symfony-header', 'header', 'x-symfony-cache', 60, 'Symfony cache header is present.', fn (FingerprintContext $context) => $this->header($context, 'x-symfony-cache')),
                $this->rule('symfony-cookie', 'cookie', 'sf', 46, 'Symfony style cookie is present.', fn (FingerprintContext $context) => $context->hasCookieContaining('sf') ? ['source_value' => 'sf cookie'] : null),
            ], ['php']),
            $this->framework('codeigniter', 'CodeIgniter', 'framework', [
                $this->rule('codeigniter-cookie', 'cookie', 'ci_session', 58, 'CodeIgniter session cookie is present.', fn (FingerprintContext $context) => $context->hasCookie('ci_session') ? ['source_value' => 'ci_session'] : null),
            ], ['php']),
            $this->framework('drupal', 'Drupal', 'cms', [
                $this->rule('drupal-generator', 'generator_meta', 'generator', 76, 'Generator meta references Drupal.', fn (FingerprintContext $context) => $this->contains($context->generator(), 'drupal', '/drupal\s+([0-9][0-9.]+)/i')),
                $this->rule('drupal-settings', 'html', 'drupal-settings-json', 62, 'HTML references Drupal settings JSON.', fn (FingerprintContext $context) => $context->bodyContains('drupal-settings-json') ? ['source_value' => 'drupal-settings-json'] : null),
            ], ['php']),
            $this->framework('joomla', 'Joomla', 'cms', [
                $this->rule('joomla-generator', 'generator_meta', 'generator', 74, 'Generator meta references Joomla.', fn (FingerprintContext $context) => $this->contains($context->generator(), 'joomla', '/joomla!\s*([0-9][0-9.]+)/i')),
                $this->rule('joomla-html', 'html', 'joomla', 58, 'HTML references Joomla.', fn (FingerprintContext $context) => $context->bodyContains('content="joomla') ? ['source_value' => 'content="joomla'] : null),
            ], ['php']),
            $this->framework('nuxt', 'Nuxt', 'framework', [
                $this->rule('nuxt-html', 'html', '__nuxt__', 64, 'HTML contains Nuxt marker.', fn (FingerprintContext $context) => $context->bodyContains('__nuxt__') ? ['source_value' => '__nuxt__'] : null),
            ], ['vue']),
            $this->framework('vue', 'Vue', 'frontend', [
                $this->rule('vue-html', 'html', 'vue', 50, 'HTML contains Vue markers.', fn (FingerprintContext $context) => $context->bodyContains('__vue__') || $context->bodyContains('data-v-') || $context->bodyContains('id="app"') ? ['source_value' => 'vue html marker'] : null),
            ]),
            $this->framework('angular', 'Angular', 'frontend', [
                $this->rule('angular-html', 'html', 'angular', 58, 'HTML contains Angular markers.', fn (FingerprintContext $context) => $context->bodyContains('ng-version') || $context->bodyContains('ng-app') ? ['source_value' => 'angular html marker'] : null),
            ]),
            $this->framework('aspnet', 'ASP.NET', 'framework', [
                $this->rule('aspnet-powered-by', 'header', 'x-powered-by', 74, 'X-Powered-By references ASP.NET.', fn (FingerprintContext $context) => $this->header($context, 'x-powered-by', 'asp.net')),
                $this->rule('aspnet-cookie', 'cookie', 'asp.net_sessionid', 72, 'ASP.NET session cookie is present.', fn (FingerprintContext $context) => $context->hasCookie('asp.net_sessionid') ? ['source_value' => 'ASP.NET_SessionId'] : null),
                $this->rule('aspnet-iis', 'server', 'server', 55, 'IIS server header hints ASP.NET.', fn (FingerprintContext $context) => str_contains($context->server(), 'microsoft-iis') ? ['source_value' => $context->server()] : null),
            ], ['iis']),
            $this->framework('spring_boot', 'Spring Boot', 'framework', [
                $this->rule('spring-context-header', 'header', 'x-application-context', 60, 'Spring application context header is present.', fn (FingerprintContext $context) => $this->header($context, 'x-application-context')),
                $this->rule('spring-jsessionid', 'cookie', 'jsessionid', 45, 'JSESSIONID cookie hints Java/Spring.', fn (FingerprintContext $context) => $context->hasCookie('jsessionid') ? ['source_value' => 'JSESSIONID'] : null),
            ]),
            $this->framework('express', 'Express', 'framework', [
                $this->rule('express-powered-by', 'header', 'x-powered-by', 78, 'X-Powered-By references Express.', fn (FingerprintContext $context) => $this->header($context, 'x-powered-by', 'express')),
                $this->rule('express-cookie', 'cookie', 'connect.sid', 58, 'Express session cookie is present.', fn (FingerprintContext $context) => $context->hasCookie('connect.sid') ? ['source_value' => 'connect.sid'] : null),
            ]),
            $this->framework('django', 'Django', 'framework', [
                $this->rule('django-csrftoken', 'cookie', 'csrftoken', 56, 'Django CSRF cookie is present.', fn (FingerprintContext $context) => $context->hasCookie('csrftoken') ? ['source_value' => 'csrftoken'] : null),
                $this->rule('django-csrf-body', 'html', 'csrfmiddlewaretoken', 50, 'HTML contains Django CSRF marker.', fn (FingerprintContext $context) => $context->bodyContains('csrfmiddlewaretoken') ? ['source_value' => 'csrfmiddlewaretoken'] : null),
            ]),
            $this->framework('flask', 'Flask', 'framework', [
                $this->rule('flask-werkzeug', 'server', 'server', 52, 'Werkzeug server header hints Flask.', fn (FingerprintContext $context) => $this->contains($context->server(), 'werkzeug')),
                $this->rule('flask-session', 'cookie', 'session', 35, 'Generic session cookie weakly hints Flask.', fn (FingerprintContext $context) => $context->hasCookie('session') ? ['source_value' => 'session'] : null),
            ]),
        ];
    }

    /**
     * @param list<string> $conflictsWith
     */
    private function server(string $key, string $name, string $needle, ?string $versionPattern, array $conflictsWith): RuleGroup
    {
        return new RuleGroup(
            technologyKey: $key,
            technologyName: $name,
            category: 'server',
            rules: [
                $this->rule($key.'-server-header', 'server', 'server', 78, $name.' appears in the Server header.', fn (FingerprintContext $context) => $this->contains($context->server(), $needle, $versionPattern)),
            ],
            parents: ['cloudflare', 'fastly', 'cloudfront', 'akamai', 'bunny'],
            conflictsWith: $conflictsWith,
            coverageCategory: 'server',
            cpeVendor: $key === 'iis' ? 'microsoft' : $key,
            cpeProduct: $key,
            conflictGroup: 'http_server',
        );
    }

    /**
     * @param list<string> $signals
     */
    private function cdn(string $key, string $name, array $signals): RuleGroup
    {
        $rules = [];

        foreach ($signals as $signal) {
            $rules[] = $this->rule(
                $key.'-'.$signal,
                str_starts_with($signal, 'x-') ? 'header' : 'response',
                $signal,
                65,
                $name.' edge signal is present.',
                fn (FingerprintContext $context) => $context->header($signal) !== null || str_contains($context->server(), $signal) || $context->headerContains('via', $signal) ? ['source_value' => $signal] : null,
            );
        }

        return new RuleGroup($key, $name, 'cdn', $rules, coverageCategory: 'cdn');
    }

    /**
     * @param list<FingerprintRule> $rules
     * @param list<string> $parents
     */
    private function framework(string $key, string $name, string $category, array $rules, array $parents = []): RuleGroup
    {
        return new RuleGroup($key, $name, $category, $rules, parents: $parents, coverageCategory: $category);
    }
}
