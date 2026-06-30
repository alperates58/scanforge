<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('scanner_template_policies', function (Blueprint $table) {
            $table->id();
            $table->string('scanner_key');
            $table->string('template_group');
            $table->boolean('allowed')->default(false);
            $table->string('safety_level')->default('safe');
            $table->json('blocked_tags')->nullable();
            $table->json('allowed_tags')->nullable();
            $table->text('reason')->nullable();
            $table->timestamps();

            $table->unique(['scanner_key', 'template_group'], 'scanner_template_policy_unique');
            $table->index(['scanner_key', 'allowed']);
        });

        Schema::create('scanner_versions', function (Blueprint $table) {
            $table->id();
            $table->string('scanner_key')->unique();
            $table->string('binary_version')->nullable();
            $table->string('templates_version')->nullable();
            $table->timestamp('last_checked_at')->nullable();
            $table->string('status')->default('unknown');
            $table->json('metadata')->nullable();
            $table->timestamps();
        });

        Schema::create('template_manifests', function (Blueprint $table) {
            $table->id();
            $table->string('scanner_key')->default('nuclei');
            $table->string('template_id');
            $table->string('group')->nullable();
            $table->string('severity')->default('info');
            $table->json('tags')->nullable();
            $table->string('author')->nullable();
            $table->boolean('signed')->default(false);
            $table->timestamp('last_updated')->nullable();
            $table->boolean('deprecated')->default(false);
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->unique(['scanner_key', 'template_id'], 'template_manifest_unique');
            $table->index(['scanner_key', 'group']);
            $table->index(['severity', 'deprecated']);
        });

        Schema::create('finding_histories', function (Blueprint $table) {
            $table->id();
            $table->foreignId('finding_id')->constrained()->cascadeOnDelete();
            $table->foreignId('scan_id')->nullable()->constrained()->nullOnDelete();
            $table->string('from_status')->nullable();
            $table->string('to_status');
            $table->text('reason')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('changed_at');
            $table->timestamps();

            $table->index(['finding_id', 'changed_at']);
            $table->index(['to_status', 'changed_at']);
        });

        Schema::create('cve_references', function (Blueprint $table) {
            $table->id();
            $table->string('cve')->unique();
            $table->decimal('cvss', 3, 1)->nullable();
            $table->decimal('epss', 7, 6)->nullable();
            $table->boolean('kev')->nullable();
            $table->string('vendor')->nullable();
            $table->string('product')->nullable();
            $table->string('version')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->index(['vendor', 'product']);
        });

        Schema::create('scanner_metrics', function (Blueprint $table) {
            $table->id();
            $table->string('scanner_key')->unique();
            $table->unsignedBigInteger('runs')->default(0);
            $table->unsignedBigInteger('success')->default(0);
            $table->unsignedBigInteger('failed')->default(0);
            $table->unsignedBigInteger('timeout')->default(0);
            $table->decimal('avg_runtime', 12, 2)->default(0);
            $table->decimal('avg_findings', 10, 2)->default(0);
            $table->timestamp('last_run_at')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();
        });

        Schema::create('artifact_manifests', function (Blueprint $table) {
            $table->id();
            $table->foreignId('raw_artifact_id')->constrained()->cascadeOnDelete();
            $table->string('checksum', 64);
            $table->unsignedBigInteger('size')->default(0);
            $table->string('mime')->default('application/octet-stream');
            $table->boolean('compressed')->default(false);
            $table->string('retention_policy')->default('scan_raw_default');
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->unique('raw_artifact_id');
            $table->index(['checksum']);
        });

        Schema::table('scan_jobs', function (Blueprint $table) {
            if (! Schema::hasColumn('scan_jobs', 'job_uuid')) {
                $table->uuid('job_uuid')->nullable()->after('id')->unique();
            }
        });

        Schema::table('findings', function (Blueprint $table) {
            if (! Schema::hasColumn('findings', 'scanner_key')) {
                $table->string('scanner_key')->nullable()->after('source_tool');
            }

            if (! Schema::hasColumn('findings', 'template_id')) {
                $table->string('template_id')->nullable()->after('scanner_key');
            }

            if (! Schema::hasColumn('findings', 'parameter')) {
                $table->string('parameter')->nullable()->after('affected_url');
            }

            if (! Schema::hasColumn('findings', 'dedupe_hash')) {
                $table->string('dedupe_hash', 128)->nullable()->after('fingerprint_hash');
            }

            if (! Schema::hasColumn('findings', 'first_seen_at')) {
                $table->timestamp('first_seen_at')->nullable()->after('dedupe_hash');
            }

            if (! Schema::hasColumn('findings', 'last_seen_at')) {
                $table->timestamp('last_seen_at')->nullable()->after('first_seen_at');
            }

            if (! Schema::hasColumn('findings', 'occurrence_count')) {
                $table->unsignedInteger('occurrence_count')->default(1)->after('last_seen_at');
            }

            if (! Schema::hasColumn('findings', 'matched_at')) {
                $table->timestamp('matched_at')->nullable()->after('occurrence_count');
            }

            if (! Schema::hasColumn('findings', 'description')) {
                $table->text('description')->nullable()->after('matched_at');
            }

            if (! Schema::hasColumn('findings', 'references')) {
                $table->json('references')->nullable()->after('description');
            }

            if (! Schema::hasColumn('findings', 'evidence_json')) {
                $table->json('evidence_json')->nullable()->after('evidence');
            }

            if (! Schema::hasColumn('findings', 'confidence_score')) {
                $table->unsignedTinyInteger('confidence_score')->default(0)->after('confidence');
            }

            if (! Schema::hasColumn('findings', 'false_positive_risk')) {
                $table->string('false_positive_risk')->default('medium')->after('confidence_score');
            }

            if (! Schema::hasColumn('findings', 'analysis_required')) {
                $table->boolean('analysis_required')->default(true)->after('false_positive_notes');
            }
        });

        Schema::table('findings', function (Blueprint $table) {
            $table->unique(['website_id', 'dedupe_hash'], 'findings_website_dedupe_unique');
            $table->index(['scanner_key', 'template_id']);
            $table->index(['status', 'analysis_required']);
        });
    }

    public function down(): void
    {
        Schema::table('findings', function (Blueprint $table) {
            $table->dropUnique('findings_website_dedupe_unique');
            $table->dropIndex(['scanner_key', 'template_id']);
            $table->dropIndex(['status', 'analysis_required']);
            $table->dropColumn([
                'scanner_key',
                'template_id',
                'parameter',
                'dedupe_hash',
                'first_seen_at',
                'last_seen_at',
                'occurrence_count',
                'matched_at',
                'description',
                'references',
                'evidence_json',
                'confidence_score',
                'false_positive_risk',
                'analysis_required',
            ]);
        });

        Schema::table('scan_jobs', function (Blueprint $table) {
            $table->dropUnique(['job_uuid']);
            $table->dropColumn('job_uuid');
        });

        Schema::dropIfExists('artifact_manifests');
        Schema::dropIfExists('scanner_metrics');
        Schema::dropIfExists('cve_references');
        Schema::dropIfExists('finding_histories');
        Schema::dropIfExists('template_manifests');
        Schema::dropIfExists('scanner_versions');
        Schema::dropIfExists('scanner_template_policies');
    }
};
