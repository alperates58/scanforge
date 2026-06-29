<?php

$frontendUrl = env('FRONTEND_URL', 'http://localhost:3000');
$allowedOrigins = array_filter(array_map('trim', explode(',', env('CORS_ALLOWED_ORIGINS', $frontendUrl))));

return [
    'paths' => ['api/*', 'sanctum/csrf-cookie'],
    'allowed_methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    'allowed_origins' => $allowedOrigins,
    'allowed_origins_patterns' => [],
    'allowed_headers' => ['Content-Type', 'X-Requested-With', 'Accept', 'Authorization', 'X-Workspace-Id'],
    'exposed_headers' => [],
    'max_age' => 0,
    'supports_credentials' => false,
];
