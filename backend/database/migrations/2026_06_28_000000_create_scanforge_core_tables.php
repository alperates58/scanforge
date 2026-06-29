<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('workspaces', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->foreignId('owner_user_id')->constrained('users')->cascadeOnDelete();
            $table->timestamps();
        });

        Schema::create('workspace_members', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('role')->default('owner');
            $table->timestamps();

            $table->unique(['workspace_id', 'user_id']);
        });

        Schema::create('websites', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->nullable()->constrained()->nullOnDelete();
            $table->string('url', 2048);
            $table->string('normalized_host');
            $table->string('status')->default('pending_verification');
            $table->string('verification_method')->nullable();
            $table->string('verification_token', 128)->nullable();
            $table->timestamp('verified_at')->nullable();
            $table->timestamp('last_scan_at')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->unique(['workspace_id', 'normalized_host']);
            $table->index(['normalized_host', 'status']);
        });

        Schema::create('domain_verifications', function (Blueprint $table) {
            $table->id();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->string('method');
            $table->string('token', 128);
            $table->string('status')->default('pending');
            $table->timestamp('checked_at')->nullable();
            $table->timestamp('verified_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->text('last_error')->nullable();
            $table->json('evidence')->nullable();
            $table->timestamps();

            $table->index(['website_id', 'method', 'status']);
        });

        Schema::create('scans', function (Blueprint $table) {
            $table->id();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->string('scan_type');
            $table->string('status')->default('queued');
            $table->unsignedTinyInteger('score')->nullable();
            $table->boolean('safe_mode')->default(true);
            $table->timestamp('consent_accepted_at')->nullable();
            $table->foreignId('requested_by_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->json('request_options')->nullable();
            $table->timestamp('started_at')->nullable();
            $table->timestamp('finished_at')->nullable();
            $table->text('error_message')->nullable();
            $table->timestamps();

            $table->index(['website_id', 'scan_type', 'status']);
            $table->index(['created_at', 'status']);
        });

        Schema::create('scan_jobs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
            $table->string('job_type');
            $table->string('status')->default('queued');
            $table->unsignedTinyInteger('progress')->default(0);
            $table->unsignedSmallInteger('attempts')->default(0);
            $table->timestamp('started_at')->nullable();
            $table->timestamp('finished_at')->nullable();
            $table->json('logs')->nullable();
            $table->text('error_message')->nullable();
            $table->timestamps();

            $table->index(['scan_id', 'job_type', 'status']);
        });

        Schema::create('raw_artifacts', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
            $table->foreignId('scan_job_id')->nullable()->constrained()->nullOnDelete();
            $table->string('tool_name');
            $table->string('file_path', 2048)->nullable();
            $table->json('json_payload')->nullable();
            $table->timestamps();

            $table->index(['scan_id', 'tool_name']);
        });

        Schema::create('findings', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('raw_artifact_id')->nullable()->constrained('raw_artifacts')->nullOnDelete();
            $table->string('title');
            $table->string('severity')->default('info');
            $table->decimal('confidence', 4, 3)->default(0);
            $table->string('affected_url', 2048);
            $table->string('source_tool');
            $table->string('cwe')->nullable();
            $table->string('cve')->nullable();
            $table->decimal('cvss', 3, 1)->nullable();
            $table->string('owasp_category')->nullable();
            $table->text('evidence');
            $table->text('remediation')->nullable();
            $table->string('fingerprint_hash', 128)->nullable();
            $table->string('status')->default('open');
            $table->json('false_positive_notes')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->index(['website_id', 'severity', 'status']);
            $table->index(['scan_id', 'severity']);
            $table->unique(['scan_id', 'fingerprint_hash']);
        });

        Schema::create('technology_fingerprints', function (Blueprint $table) {
            $table->id();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('scan_id')->nullable()->constrained()->nullOnDelete();
            $table->string('name');
            $table->string('category')->nullable();
            $table->string('version')->nullable();
            $table->decimal('confidence', 4, 3)->default(0);
            $table->string('source')->nullable();
            $table->json('evidence')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->index(['website_id', 'name']);
            $table->index(['category', 'confidence']);
        });

        Schema::create('ai_analyses', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
            $table->string('model');
            $table->string('risk_level')->default('low');
            $table->text('executive_summary');
            $table->text('business_impact')->nullable();
            $table->json('priority_fixes')->nullable();
            $table->json('false_positive_notes')->nullable();
            $table->json('technology_specific_recommendations')->nullable();
            $table->text('next_scan_recommendation')->nullable();
            $table->json('raw_json')->nullable();
            $table->timestamps();

            $table->unique('scan_id');
        });

        Schema::create('audit_logs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignId('user_id')->nullable()->constrained()->nullOnDelete();
            $table->string('action');
            $table->string('target_type')->nullable();
            $table->unsignedBigInteger('target_id')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('created_at')->useCurrent();

            $table->index(['workspace_id', 'action']);
            $table->index(['target_type', 'target_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('audit_logs');
        Schema::dropIfExists('ai_analyses');
        Schema::dropIfExists('technology_fingerprints');
        Schema::dropIfExists('findings');
        Schema::dropIfExists('raw_artifacts');
        Schema::dropIfExists('scan_jobs');
        Schema::dropIfExists('scans');
        Schema::dropIfExists('domain_verifications');
        Schema::dropIfExists('websites');
        Schema::dropIfExists('workspace_members');
        Schema::dropIfExists('workspaces');
    }
};
