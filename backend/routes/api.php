<?php

use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\AssetDiscoveryController;
use App\Http\Controllers\Api\AssetSummaryController;
use App\Http\Controllers\Api\DashboardSummaryController;
use App\Http\Controllers\Api\DomainVerificationController;
use App\Http\Controllers\Api\HealthController;
use App\Http\Controllers\Api\ScanPlanController;
use App\Http\Controllers\Api\TechnologyFingerprintController;
use App\Http\Controllers\Api\WebsiteController;
use App\Http\Controllers\Api\WebsiteScanController;
use Illuminate\Support\Facades\Route;

Route::get('/health', HealthController::class);

Route::post('/auth/register', [AuthController::class, 'register']);
Route::post('/auth/login', [AuthController::class, 'login']);

Route::middleware('auth:sanctum')->group(function (): void {
    Route::post('/auth/logout', [AuthController::class, 'logout']);
    Route::get('/me', [AuthController::class, 'me']);

    Route::get('/dashboard/summary', DashboardSummaryController::class);

    Route::get('/websites', [WebsiteController::class, 'index']);
    Route::post('/websites', [WebsiteController::class, 'store']);
    Route::get('/websites/{website}', [WebsiteController::class, 'show']);
    Route::delete('/websites/{website}', [WebsiteController::class, 'destroy']);

    Route::get('/websites/{website}/verification', [DomainVerificationController::class, 'show']);
    Route::post('/websites/{website}/verification/check', [DomainVerificationController::class, 'check']);
    Route::get('/websites/{website}/scans', [WebsiteScanController::class, 'index']);
    Route::post('/websites/{website}/scans', [WebsiteScanController::class, 'store']);
    Route::get('/websites/{website}/scans/{scan}', [WebsiteScanController::class, 'show']);
    Route::post('/websites/{website}/scans/{scan}/cancel', [WebsiteScanController::class, 'cancel']);
    Route::post('/websites/{website}/scans/{scan}/retry-failed', [WebsiteScanController::class, 'retryFailed']);
    Route::get('/websites/{website}/scans/{scan}/jobs', [WebsiteScanController::class, 'jobs']);

    Route::post('/websites/{website}/discoveries', [AssetDiscoveryController::class, 'store']);
    Route::get('/websites/{website}/discoveries', [AssetDiscoveryController::class, 'index']);
    Route::get('/websites/{website}/discoveries/{discovery}', [AssetDiscoveryController::class, 'show']);
    Route::get('/websites/{website}/assets/summary', AssetSummaryController::class);

    Route::post('/websites/{website}/fingerprint', [TechnologyFingerprintController::class, 'store']);
    Route::get('/websites/{website}/technologies', [TechnologyFingerprintController::class, 'index']);
    Route::get('/websites/{website}/technology-coverage', [TechnologyFingerprintController::class, 'coverage']);
    Route::get('/websites/{website}/technology-relationships', [TechnologyFingerprintController::class, 'relationships']);
    Route::get('/websites/{website}/technology-conflicts', [TechnologyFingerprintController::class, 'conflicts']);
    Route::get('/websites/{website}/technology-graph', [TechnologyFingerprintController::class, 'graph']);

    Route::post('/websites/{website}/scan-plans', [ScanPlanController::class, 'store']);
    Route::get('/websites/{website}/scan-plans', [ScanPlanController::class, 'index']);
    Route::get('/websites/{website}/scan-plans/{scanPlan}', [ScanPlanController::class, 'show']);
});
