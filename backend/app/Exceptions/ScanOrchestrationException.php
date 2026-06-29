<?php

namespace App\Exceptions;

use RuntimeException;

class ScanOrchestrationException extends RuntimeException
{
    /**
     * @param list<string> $reasons
     */
    public function __construct(
        public readonly string $errorCode,
        public readonly int $statusCode,
        public readonly array $reasons,
        string $message = 'Scan request blocked by ScanForge safety gate.',
    ) {
        parent::__construct($message);
    }
}
