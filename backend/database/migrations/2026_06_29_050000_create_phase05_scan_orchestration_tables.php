<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('scans', function (Blueprint $table) {
            if (! Schema::hasColumn('scans', 'workspace_id')) {
                $table->foreignId('workspace_id')->nullable()->after('id')->constrained()->nullOnDelete();
            }

            if (! Schema::hasColumn('scans', 'scan_plan_id')) {
                $table->foreignId('scan_plan_id')->nullable()->after('website_id')->constrained()->nullOnDelete();
            }

            if (! Schema::hasColumn('scans', 'completed_at')) {
                $table->timestamp('completed_at')->nullable()->after('finished_at');
            }

            if (! Schema::hasColumn('scans', 'cancelled_at')) {
                $table->timestamp('cancelled_at')->nullable()->after('completed_at');
            }

            if (! Schema::hasColumn('scans', 'duration_ms')) {
                $table->unsignedBigInteger('duration_ms')->nullable()->after('cancelled_at');
            }

            if (! Schema::hasColumn('scans', 'progress_percent')) {
                $table->unsignedTinyInteger('progress_percent')->default(0)->after('duration_ms');
            }

            if (! Schema::hasColumn('scans', 'total_jobs')) {
                $table->unsignedInteger('total_jobs')->default(0)->after('progress_percent');
            }

            if (! Schema::hasColumn('scans', 'completed_jobs')) {
                $table->unsignedInteger('completed_jobs')->default(0)->after('total_jobs');
            }

            if (! Schema::hasColumn('scans', 'failed_jobs')) {
                $table->unsignedInteger('failed_jobs')->default(0)->after('completed_jobs');
            }

            if (! Schema::hasColumn('scans', 'skipped_jobs')) {
                $table->unsignedInteger('skipped_jobs')->default(0)->after('failed_jobs');
            }

            if (! Schema::hasColumn('scans', 'safety_mode')) {
                $table->string('safety_mode')->default('safe')->after('skipped_jobs');
            }

            if (! Schema::hasColumn('scans', 'request_budget')) {
                $table->unsignedInteger('request_budget')->nullable()->after('safety_mode');
            }

            if (! Schema::hasColumn('scans', 'timeout_seconds')) {
                $table->unsignedInteger('timeout_seconds')->nullable()->after('request_budget');
            }

            if (! Schema::hasColumn('scans', 'metadata')) {
                $table->json('metadata')->nullable()->after('timeout_seconds');
            }
        });

        Schema::table('scans', function (Blueprint $table) {
            $table->index(['workspace_id', 'status', 'created_at'], 'scans_workspace_status_created_idx');
            $table->index(['website_id', 'scan_plan_id', 'status'], 'scans_website_plan_status_idx');
        });

        Schema::table('scan_jobs', function (Blueprint $table) {
            if (! Schema::hasColumn('scan_jobs', 'workspace_id')) {
                $table->foreignId('workspace_id')->nullable()->after('id')->constrained()->nullOnDelete();
            }

            if (! Schema::hasColumn('scan_jobs', 'website_id')) {
                $table->foreignId('website_id')->nullable()->after('workspace_id')->constrained()->nullOnDelete();
            }

            if (! Schema::hasColumn('scan_jobs', 'scan_plan_item_id')) {
                $table->foreignId('scan_plan_item_id')->nullable()->after('scan_id')->constrained()->nullOnDelete();
            }

            if (! Schema::hasColumn('scan_jobs', 'scanner_key')) {
                $table->string('scanner_key')->nullable()->after('job_type');
            }

            if (! Schema::hasColumn('scan_jobs', 'scan_module')) {
                $table->string('scan_module')->nullable()->after('scanner_key');
            }

            if (! Schema::hasColumn('scan_jobs', 'template_group')) {
                $table->string('template_group')->nullable()->after('scan_module');
            }

            if (! Schema::hasColumn('scan_jobs', 'priority')) {
                $table->unsignedTinyInteger('priority')->default(50)->after('template_group');
            }

            if (! Schema::hasColumn('scan_jobs', 'recommendation_score')) {
                $table->unsignedTinyInteger('recommendation_score')->default(0)->after('priority');
            }

            if (! Schema::hasColumn('scan_jobs', 'safe_default')) {
                $table->boolean('safe_default')->default(true)->after('recommendation_score');
            }

            if (! Schema::hasColumn('scan_jobs', 'attempt_count')) {
                $table->unsignedSmallInteger('attempt_count')->default(0)->after('safe_default');
            }

            if (! Schema::hasColumn('scan_jobs', 'max_attempts')) {
                $table->unsignedSmallInteger('max_attempts')->default(1)->after('attempt_count');
            }

            if (! Schema::hasColumn('scan_jobs', 'timeout_seconds')) {
                $table->unsignedInteger('timeout_seconds')->nullable()->after('max_attempts');
            }

            if (! Schema::hasColumn('scan_jobs', 'completed_at')) {
                $table->timestamp('completed_at')->nullable()->after('finished_at');
            }

            if (! Schema::hasColumn('scan_jobs', 'duration_ms')) {
                $table->unsignedBigInteger('duration_ms')->nullable()->after('completed_at');
            }

            if (! Schema::hasColumn('scan_jobs', 'progress_percent')) {
                $table->unsignedTinyInteger('progress_percent')->default(0)->after('duration_ms');
            }

            if (! Schema::hasColumn('scan_jobs', 'request_count')) {
                $table->unsignedInteger('request_count')->default(0)->after('progress_percent');
            }

            if (! Schema::hasColumn('scan_jobs', 'result_summary')) {
                $table->json('result_summary')->nullable()->after('request_count');
            }

            if (! Schema::hasColumn('scan_jobs', 'worker_id')) {
                $table->string('worker_id')->nullable()->after('result_summary');
            }

            if (! Schema::hasColumn('scan_jobs', 'lock_key')) {
                $table->string('lock_key')->nullable()->after('worker_id');
            }

            if (! Schema::hasColumn('scan_jobs', 'queue_name')) {
                $table->string('queue_name')->default('scan-normal')->after('lock_key');
            }

            if (! Schema::hasColumn('scan_jobs', 'max_requests')) {
                $table->unsignedInteger('max_requests')->nullable()->after('queue_name');
            }

            if (! Schema::hasColumn('scan_jobs', 'max_runtime')) {
                $table->unsignedInteger('max_runtime')->nullable()->after('max_requests');
            }

            if (! Schema::hasColumn('scan_jobs', 'max_memory')) {
                $table->unsignedInteger('max_memory')->nullable()->after('max_runtime');
            }

            if (! Schema::hasColumn('scan_jobs', 'cancellation_token')) {
                $table->string('cancellation_token', 128)->nullable()->after('max_memory');
            }

            if (! Schema::hasColumn('scan_jobs', 'cancel_requested_at')) {
                $table->timestamp('cancel_requested_at')->nullable()->after('cancellation_token');
            }

            if (! Schema::hasColumn('scan_jobs', 'last_heartbeat_at')) {
                $table->timestamp('last_heartbeat_at')->nullable()->after('cancel_requested_at');
            }
        });

        Schema::table('scan_jobs', function (Blueprint $table) {
            $table->index(['workspace_id', 'status', 'queue_name'], 'scan_jobs_workspace_status_queue_idx');
            $table->index(['scan_id', 'status'], 'scan_jobs_scan_status_idx');
            $table->index(['worker_id', 'status'], 'scan_jobs_worker_status_idx');
            $table->index(['website_id', 'scan_plan_item_id'], 'scan_jobs_website_plan_item_idx');
        });

        Schema::table('raw_artifacts', function (Blueprint $table) {
            if (! Schema::hasColumn('raw_artifacts', 'scanner_key')) {
                $table->string('scanner_key')->nullable()->after('tool_name');
            }

            if (! Schema::hasColumn('raw_artifacts', 'artifact_type')) {
                $table->string('artifact_type')->nullable()->after('scanner_key');
            }

            if (! Schema::hasColumn('raw_artifacts', 'content')) {
                $table->json('content')->nullable()->after('json_payload');
            }

            if (! Schema::hasColumn('raw_artifacts', 'sha256')) {
                $table->string('sha256', 64)->nullable()->after('content');
            }
        });

        Schema::create('scan_workers', function (Blueprint $table) {
            $table->id();
            $table->string('worker_id')->unique();
            $table->string('hostname')->nullable();
            $table->string('version')->nullable();
            $table->json('supported_scanners')->nullable();
            $table->string('status')->default('online');
            $table->unsignedInteger('current_jobs')->default(0);
            $table->unsignedInteger('max_jobs')->default(1);
            $table->timestamp('last_heartbeat')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->index(['status', 'last_heartbeat']);
        });

        Schema::create('scan_job_timelines', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_job_id')->constrained()->cascadeOnDelete();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
            $table->foreignId('workspace_id')->nullable()->constrained()->nullOnDelete();
            $table->string('from_status')->nullable();
            $table->string('to_status');
            $table->string('reason')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('occurred_at');
            $table->timestamps();

            $table->index(['scan_job_id', 'occurred_at']);
            $table->index(['scan_id', 'to_status']);
        });

        Schema::create('scan_job_logs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_job_id')->constrained()->cascadeOnDelete();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
            $table->foreignId('workspace_id')->nullable()->constrained()->nullOnDelete();
            $table->timestamp('timestamp');
            $table->string('level')->default('info');
            $table->text('message');
            $table->json('context')->nullable();
            $table->timestamps();

            $table->index(['scan_job_id', 'timestamp']);
            $table->index(['scan_id', 'level']);
        });

        Schema::create('scan_schedules', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('scan_plan_id')->nullable()->constrained()->nullOnDelete();
            $table->string('scan_type')->default('standard');
            $table->string('safety_mode')->default('standard');
            $table->string('cron');
            $table->string('timezone')->default('UTC');
            $table->boolean('enabled')->default(false);
            $table->timestamp('last_run')->nullable();
            $table->timestamp('next_run')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->index(['workspace_id', 'enabled', 'next_run']);
            $table->index(['website_id', 'enabled']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('scan_schedules');
        Schema::dropIfExists('scan_job_logs');
        Schema::dropIfExists('scan_job_timelines');
        Schema::dropIfExists('scan_workers');

        Schema::table('raw_artifacts', function (Blueprint $table) {
            $table->dropColumn(['scanner_key', 'artifact_type', 'content', 'sha256']);
        });

        Schema::table('scan_jobs', function (Blueprint $table) {
            $table->dropIndex('scan_jobs_workspace_status_queue_idx');
            $table->dropIndex('scan_jobs_scan_status_idx');
            $table->dropIndex('scan_jobs_worker_status_idx');
            $table->dropIndex('scan_jobs_website_plan_item_idx');
            $table->dropConstrainedForeignId('workspace_id');
            $table->dropConstrainedForeignId('website_id');
            $table->dropConstrainedForeignId('scan_plan_item_id');
            $table->dropColumn([
                'scanner_key',
                'scan_module',
                'template_group',
                'priority',
                'recommendation_score',
                'safe_default',
                'attempt_count',
                'max_attempts',
                'timeout_seconds',
                'completed_at',
                'duration_ms',
                'progress_percent',
                'request_count',
                'result_summary',
                'worker_id',
                'lock_key',
                'queue_name',
                'max_requests',
                'max_runtime',
                'max_memory',
                'cancellation_token',
                'cancel_requested_at',
                'last_heartbeat_at',
            ]);
        });

        Schema::table('scans', function (Blueprint $table) {
            $table->dropIndex('scans_workspace_status_created_idx');
            $table->dropIndex('scans_website_plan_status_idx');
            $table->dropConstrainedForeignId('workspace_id');
            $table->dropConstrainedForeignId('scan_plan_id');
            $table->dropColumn([
                'completed_at',
                'cancelled_at',
                'duration_ms',
                'progress_percent',
                'total_jobs',
                'completed_jobs',
                'failed_jobs',
                'skipped_jobs',
                'safety_mode',
                'request_budget',
                'timeout_seconds',
                'metadata',
            ]);
        });
    }
};
