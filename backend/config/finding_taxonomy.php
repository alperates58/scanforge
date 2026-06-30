<?php

return [
    'defaults' => [
        'category' => 'Security Misconfiguration',
        'subcategory' => 'General Finding',
        'owasp_category' => 'OWASP A05',
        'asvs_control' => null,
        'cwe' => null,
        'capec' => null,
    ],

    'cwe' => [
        'CWE-79' => [
            'category' => 'Injection',
            'subcategory' => 'Cross-Site Scripting',
            'owasp_category' => 'OWASP A03',
            'asvs_control' => 'ASVS 5.3',
            'capec' => 'CAPEC-63',
        ],
        'CWE-89' => [
            'category' => 'Injection',
            'subcategory' => 'SQL Injection',
            'owasp_category' => 'OWASP A03',
            'asvs_control' => 'ASVS 5.3',
            'capec' => 'CAPEC-66',
        ],
        'CWE-200' => [
            'category' => 'Sensitive Data Exposure',
            'subcategory' => 'Information Disclosure',
            'owasp_category' => 'OWASP A01',
            'asvs_control' => 'ASVS 14.3',
            'capec' => 'CAPEC-118',
        ],
        'CWE-287' => [
            'category' => 'Identification and Authentication Failures',
            'subcategory' => 'Improper Authentication',
            'owasp_category' => 'OWASP A07',
            'asvs_control' => 'ASVS 2.1',
            'capec' => 'CAPEC-115',
        ],
        'CWE-352' => [
            'category' => 'Broken Access Control',
            'subcategory' => 'Cross-Site Request Forgery',
            'owasp_category' => 'OWASP A01',
            'asvs_control' => 'ASVS 4.2',
            'capec' => 'CAPEC-62',
        ],
        'CWE-693' => [
            'category' => 'Security Misconfiguration',
            'subcategory' => 'Protection Mechanism Failure',
            'owasp_category' => 'OWASP A05',
            'asvs_control' => 'ASVS 14.4',
            'capec' => 'CAPEC-676',
        ],
    ],

    'passive_categories' => [
        'security_headers' => [
            'category' => 'Security Misconfiguration',
            'subcategory' => 'Missing Security Header',
            'owasp_category' => 'OWASP A05',
            'asvs_control' => 'ASVS 14.4',
            'cwe' => 'CWE-693',
            'capec' => 'CAPEC-676',
        ],
        'cookies' => [
            'category' => 'Security Misconfiguration',
            'subcategory' => 'Cookie Security Attribute',
            'owasp_category' => 'OWASP A05',
            'asvs_control' => 'ASVS 3.4',
            'cwe' => 'CWE-614',
            'capec' => 'CAPEC-31',
        ],
        'ssl' => [
            'category' => 'Cryptographic Failures',
            'subcategory' => 'TLS Certificate',
            'owasp_category' => 'OWASP A02',
            'asvs_control' => 'ASVS 9.1',
            'cwe' => 'CWE-295',
            'capec' => 'CAPEC-217',
        ],
        'target_safety' => [
            'category' => 'Security Misconfiguration',
            'subcategory' => 'Unsafe Target Resolution',
            'owasp_category' => 'OWASP A05',
            'asvs_control' => 'ASVS 14.5',
            'cwe' => 'CWE-200',
            'capec' => 'CAPEC-118',
        ],
    ],
];
