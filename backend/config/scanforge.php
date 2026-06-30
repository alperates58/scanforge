<?php

return [
    'version' => env('SCANFORGE_VERSION', '0.7.0-phase07'),

    'scanner' => [
        'allow_unverified_domains' => env('ALLOW_UNVERIFIED_DOMAINS', false),
        'safe_mode' => env('SCAN_SAFE_MODE', true),
        'default_timeout_seconds' => env('SCAN_DEFAULT_TIMEOUT_SECONDS', 900),
        'mock_worker_enabled' => env('SCANNER_MOCK_WORKER_ENABLED', true),
        'enable_deep_scan' => env('SCANFORGE_ENABLE_DEEP_SCAN', false),
        'worker_id' => env('SCANFORGE_WORKER_ID'),
        'worker_max_jobs' => env('SCANFORGE_WORKER_MAX_JOBS', 1),
        'worker_heartbeat_seconds' => env('SCANFORGE_WORKER_HEARTBEAT_SECONDS', 30),
    ],

    'rate_limits' => [
        'workspace_concurrent_scans' => env('SCAN_MAX_CONCURRENT_JOBS', 2),
        'same_target_cooldown_minutes' => env('SCAN_SAME_TARGET_COOLDOWN_MINUTES', 15),
        'passive_requests_per_second' => env('SCAN_PASSIVE_RPS', 1),
        'standard_requests_per_second' => env('SCAN_STANDARD_RPS', 3),
        'deep_requests_per_second' => env('SCAN_DEEP_RPS', 5),
    ],

    'orchestration' => [
        'lock_ttl_seconds' => env('SCANFORGE_SCAN_LOCK_TTL_SECONDS', 900),
        'default_job_timeout_seconds' => env('SCANFORGE_JOB_TIMEOUT_SECONDS', 300),
        'default_job_max_requests' => env('SCANFORGE_JOB_MAX_REQUESTS', 50),
        'default_job_max_runtime' => env('SCANFORGE_JOB_MAX_RUNTIME', 300),
        'default_job_max_memory' => env('SCANFORGE_JOB_MAX_MEMORY_MB', 256),
        'mock_progress_steps' => [10, 35, 65, 100],
    ],

    'queues' => [
        'scan_high' => env('SCANFORGE_QUEUE_SCAN_HIGH', 'scan-high'),
        'scan_normal' => env('SCANFORGE_QUEUE_SCAN_NORMAL', 'scan-normal'),
        'scan_low' => env('SCANFORGE_QUEUE_SCAN_LOW', 'scan-low'),
        'maintenance' => env('SCANFORGE_QUEUE_MAINTENANCE', 'maintenance'),
        'ai' => env('SCANFORGE_QUEUE_AI', 'ai'),
        'notification' => env('SCANFORGE_QUEUE_NOTIFICATION', 'notification'),
    ],

    'retry' => [
        'default' => [
            'max_attempts' => env('SCANFORGE_RETRY_DEFAULT_MAX_ATTEMPTS', 2),
            'backoff_seconds' => env('SCANFORGE_RETRY_DEFAULT_BACKOFF_SECONDS', 30),
        ],
        'scanners' => [
            'nuclei' => [
                'max_attempts' => env('SCANFORGE_RETRY_NUCLEI_MAX_ATTEMPTS', 3),
                'backoff_seconds' => env('SCANFORGE_RETRY_NUCLEI_BACKOFF_SECONDS', 30),
            ],
            'zap' => [
                'max_attempts' => env('SCANFORGE_RETRY_ZAP_MAX_ATTEMPTS', 1),
                'backoff_seconds' => env('SCANFORGE_RETRY_ZAP_BACKOFF_SECONDS', 60),
            ],
        ],
    ],

    'verification' => [
        'timeout_seconds' => env('DOMAIN_VERIFICATION_TIMEOUT_SECONDS', 5),
        'max_redirects' => env('DOMAIN_VERIFICATION_MAX_REDIRECTS', 3),
    ],

    'discovery' => [
        'timeout_seconds' => env('DISCOVERY_TIMEOUT_SECONDS', 5),
        'max_redirects' => env('DISCOVERY_MAX_REDIRECTS', 5),
        'max_body_bytes' => env('DISCOVERY_MAX_BODY_BYTES', 262144),
        'whois_enabled' => env('DISCOVERY_WHOIS_ENABLED', false),
        'reverse_dns_enabled' => env('DISCOVERY_REVERSE_DNS_ENABLED', false),
    ],

    'ai' => [
        'provider' => env('AI_PROVIDER', 'deepseek'),
        'model' => env('DEEPSEEK_MODEL', 'deepseek-v4-flash'),
        'api_key' => env('DEEPSEEK_API_KEY'),
    ],
];
