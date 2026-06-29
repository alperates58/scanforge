<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Redis;
use Throwable;

class HealthController extends Controller
{
    public function __invoke(Application $app): JsonResponse
    {
        $database = $this->checkDatabase();
        $redis = $this->checkRedis();

        $healthy = $database['ok'] && $redis['ok'];

        return response()->json([
            'status' => $healthy ? 'ok' : 'degraded',
            'service' => 'scanforge-api',
            'environment' => $app->environment(),
            'version' => config('scanforge.version'),
            'dependencies' => [
                'database' => $database,
                'redis' => $redis,
            ],
        ], $healthy ? 200 : 503);
    }

    /**
     * @return array<string, mixed>
     */
    private function checkDatabase(): array
    {
        try {
            DB::select('select 1');

            return [
                'ok' => true,
                'connection' => config('database.default'),
            ];
        } catch (Throwable $exception) {
            return [
                'ok' => false,
                'connection' => config('database.default'),
                'error' => class_basename($exception),
            ];
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function checkRedis(): array
    {
        try {
            $pong = Redis::ping();

            return [
                'ok' => true,
                'client' => config('database.redis.client'),
                'response' => is_scalar($pong) ? (string) $pong : 'PONG',
            ];
        } catch (Throwable $exception) {
            return [
                'ok' => false,
                'client' => config('database.redis.client'),
                'error' => class_basename($exception),
            ];
        }
    }
}
