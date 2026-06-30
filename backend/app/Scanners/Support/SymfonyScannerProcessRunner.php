<?php

namespace App\Scanners\Support;

use App\Scanners\Contracts\ScannerProcessRunnerInterface;
use Illuminate\Support\Carbon;
use Symfony\Component\Process\Process;
use Throwable;

class SymfonyScannerProcessRunner implements ScannerProcessRunnerInterface
{
    /**
     * @param list<string> $command
     * @param callable(): bool|null $shouldCancel
     */
    public function run(array $command, int $timeoutSeconds, string $workingDirectory, ?callable $shouldCancel = null): ScannerProcessResult
    {
        $startedAt = Carbon::now();
        $process = new Process($command, $workingDirectory);
        $process->setTimeout($timeoutSeconds);
        $timedOut = false;
        $cancelled = false;

        try {
            $process->start();

            while ($process->isRunning()) {
                if ($shouldCancel !== null && $shouldCancel()) {
                    $cancelled = true;
                    $process->stop(3, defined('SIGTERM') ? SIGTERM : 15);
                    break;
                }

                usleep(250000);
            }
        } catch (Throwable $throwable) {
            $message = $throwable->getMessage();
            $timedOut = str_contains(strtolower($message), 'timeout') || str_contains(strtolower($message), 'timed out');

            if ($process->isRunning()) {
                $process->stop(1, defined('SIGKILL') ? SIGKILL : 9);
            }

            return new ScannerProcessResult(
                exitCode: $process->getExitCode() ?? 1,
                stdout: $process->getOutput(),
                stderr: trim($process->getErrorOutput().PHP_EOL.$message),
                timedOut: $timedOut,
                cancelled: $cancelled,
                durationMs: (int) round($startedAt->diffInMilliseconds(Carbon::now())),
            );
        }

        return new ScannerProcessResult(
            exitCode: $process->getExitCode() ?? ($cancelled ? 130 : 1),
            stdout: $process->getOutput(),
            stderr: $process->getErrorOutput(),
            timedOut: $timedOut,
            cancelled: $cancelled,
            durationMs: (int) round($startedAt->diffInMilliseconds(Carbon::now())),
        );
    }
}
