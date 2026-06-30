<?php

return [
    'analysis_version' => env('SCANFORGE_FINDING_ANALYSIS_VERSION', 'finding-v1'),

    'rules' => [
        'exact_template_url' => [
            'label' => 'Exact template and affected URL',
            'score' => 100,
            'fields' => ['template_id', 'affected_url'],
        ],
        'same_cve_host' => [
            'label' => 'Same CVE on same host',
            'score' => 92,
            'fields' => ['cve', 'host'],
        ],
        'same_cwe_path_parameter' => [
            'label' => 'Same CWE, path and parameter',
            'score' => 84,
            'fields' => ['cwe', 'affected_component', 'affected_parameter'],
        ],
        'same_title_component' => [
            'label' => 'Same normalized title and affected component',
            'score' => 72,
            'fields' => ['normalized_title', 'affected_component'],
        ],
        'header_cookie_name' => [
            'label' => 'Header or cookie finding grouped by name',
            'score' => 78,
            'fields' => ['asset_type', 'asset_identifier'],
        ],
        'ssl_certificate_host_fingerprint' => [
            'label' => 'SSL certificate finding grouped by host and fingerprint',
            'score' => 86,
            'fields' => ['host', 'asset_identifier'],
        ],
    ],

    'risk' => [
        'sla_days' => [
            'critical' => 2,
            'high' => 7,
            'medium' => 30,
            'low' => 90,
            'info' => null,
        ],
    ],
];
