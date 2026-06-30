<?php

namespace App\Scanners\Support;

class ScannerSandbox
{
    public function __construct(
        public readonly string $root,
        public readonly string $workingDirectory,
        public readonly string $tempDirectory,
        public readonly string $outputDirectory,
    ) {
    }

    public function outputPath(string $filename): string
    {
        return $this->outputDirectory.DIRECTORY_SEPARATOR.$filename;
    }
}
