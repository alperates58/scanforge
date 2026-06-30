<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('finding_taxonomies', function (Blueprint $table) {
            $table->id();
            $table->string('category');
            $table->string('subcategory')->nullable();
            $table->string('owasp_category')->nullable();
            $table->string('asvs_control')->nullable();
            $table->string('cwe')->nullable();
            $table->string('capec')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->index(['category', 'subcategory']);
            $table->index(['owasp_category', 'cwe']);
        });

        Schema::create('canonical_findings', function (Blueprint $table) {
            $table->id();
            $table->foreignId('finding_taxonomy_id')->nullable()->constrained('finding_taxonomies')->nullOnDelete();
            $table->string('normalized_key')->unique();
            $table->string('default_title');
            $table->text('default_description')->nullable();
            $table->text('default_remediation')->nullable();
            $table->json('default_references')->nullable();
            $table->text('ai_summary_template')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->index(['finding_taxonomy_id']);
        });

        Schema::table('websites', function (Blueprint $table) {
            if (! Schema::hasColumn('websites', 'critical_count')) {
                $table->unsignedInteger('critical_count')->default(0)->after('risk_score');
            }

            if (! Schema::hasColumn('websites', 'high_count')) {
                $table->unsignedInteger('high_count')->default(0)->after('critical_count');
            }

            if (! Schema::hasColumn('websites', 'risk_trend')) {
                $table->string('risk_trend')->default('flat')->after('high_count');
            }
        });

        Schema::table('findings', function (Blueprint $table) {
            if (! Schema::hasColumn('findings', 'workspace_id')) {
                $table->foreignId('workspace_id')->nullable()->after('id')->constrained()->nullOnDelete();
            }

            if (! Schema::hasColumn('findings', 'canonical_finding_id')) {
                $table->foreignId('canonical_finding_id')->nullable()->after('raw_artifact_id')->constrained('canonical_findings')->nullOnDelete();
            }

            if (! Schema::hasColumn('findings', 'finding_taxonomy_id')) {
                $table->foreignId('finding_taxonomy_id')->nullable()->after('canonical_finding_id')->constrained('finding_taxonomies')->nullOnDelete();
            }

            if (! Schema::hasColumn('findings', 'normalized_title')) {
                $table->string('normalized_title')->nullable()->after('title');
            }

            if (! Schema::hasColumn('findings', 'normalized_description')) {
                $table->text('normalized_description')->nullable()->after('description');
            }

            if (! Schema::hasColumn('findings', 'risk_score')) {
                $table->unsignedTinyInteger('risk_score')->default(0)->after('false_positive_risk');
            }

            if (! Schema::hasColumn('findings', 'priority')) {
                $table->string('priority')->default('info')->after('risk_score');
            }

            if (! Schema::hasColumn('findings', 'resolved_at')) {
                $table->timestamp('resolved_at')->nullable()->after('last_seen_at');
            }

            if (! Schema::hasColumn('findings', 'reopened_at')) {
                $table->timestamp('reopened_at')->nullable()->after('resolved_at');
            }

            if (! Schema::hasColumn('findings', 'correlation_key')) {
                $table->string('correlation_key', 128)->nullable()->after('dedupe_hash');
            }

            if (! Schema::hasColumn('findings', 'correlation_score')) {
                $table->unsignedTinyInteger('correlation_score')->default(0)->after('correlation_key');
            }

            if (! Schema::hasColumn('findings', 'related_finding_id')) {
                $table->foreignId('related_finding_id')->nullable()->after('correlation_score')->constrained('findings')->nullOnDelete();
            }

            if (! Schema::hasColumn('findings', 'asset_type')) {
                $table->string('asset_type')->nullable()->after('website_id');
            }

            if (! Schema::hasColumn('findings', 'asset_id')) {
                $table->unsignedBigInteger('asset_id')->nullable()->after('asset_type');
            }

            if (! Schema::hasColumn('findings', 'asset_identifier')) {
                $table->string('asset_identifier', 2048)->nullable()->after('asset_id');
            }

            if (! Schema::hasColumn('findings', 'affected_component')) {
                $table->string('affected_component', 2048)->nullable()->after('affected_url');
            }

            if (! Schema::hasColumn('findings', 'affected_parameter')) {
                $table->string('affected_parameter')->nullable()->after('affected_component');
            }

            if (! Schema::hasColumn('findings', 'cve_json')) {
                $table->json('cve_json')->nullable()->after('cve');
            }

            if (! Schema::hasColumn('findings', 'cwe_json')) {
                $table->json('cwe_json')->nullable()->after('cwe');
            }

            if (! Schema::hasColumn('findings', 'cvss_score')) {
                $table->decimal('cvss_score', 3, 1)->nullable()->after('cvss');
            }

            if (! Schema::hasColumn('findings', 'ai_summary')) {
                $table->text('ai_summary')->nullable()->after('references');
            }

            if (! Schema::hasColumn('findings', 'analysis_version')) {
                $table->string('analysis_version')->default('finding-v1')->after('analysis_required');
            }

            if (! Schema::hasColumn('findings', 'analysis_status')) {
                $table->string('analysis_status')->default('pending')->after('analysis_version');
            }

            if (! Schema::hasColumn('findings', 'sla_due_at')) {
                $table->timestamp('sla_due_at')->nullable()->after('analysis_status');
            }
        });

        $this->backfillFindingWorkspaceIds();

        Schema::table('findings', function (Blueprint $table) {
            $table->index(['workspace_id', 'website_id', 'status', 'risk_score', 'last_seen_at'], 'findings_ws_site_status_risk_seen_idx');
            $table->index(['workspace_id', 'scanner_key', 'last_seen_at'], 'findings_ws_scanner_seen_idx');
            $table->index(['website_id', 'priority', 'status'], 'findings_site_priority_status_idx');
            $table->index(['website_id', 'correlation_key'], 'findings_site_correlation_idx');
            $table->index(['canonical_finding_id', 'website_id'], 'findings_canonical_site_idx');
            $table->index(['asset_type', 'asset_id'], 'findings_asset_idx');
        });

        Schema::create('finding_sources', function (Blueprint $table) {
            $table->id();
            $table->foreignId('finding_id')->constrained()->cascadeOnDelete();
            $table->foreignId('workspace_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->string('scanner_key');
            $table->foreignId('scan_job_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignId('raw_artifact_id')->nullable()->constrained('raw_artifacts')->nullOnDelete();
            $table->string('template_id')->nullable();
            $table->string('source_severity')->nullable();
            $table->unsignedTinyInteger('source_confidence')->nullable();
            $table->json('source_payload')->nullable();
            $table->timestamp('observed_at');
            $table->timestamps();

            $table->index(['finding_id', 'observed_at']);
            $table->index(['website_id', 'scanner_key', 'template_id']);
            $table->index(['workspace_id', 'scanner_key', 'observed_at'], 'finding_sources_ws_scanner_seen_idx');
        });

        Schema::create('finding_events', function (Blueprint $table) {
            $table->id();
            $table->foreignId('finding_id')->constrained()->cascadeOnDelete();
            $table->foreignId('workspace_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('scan_id')->nullable()->constrained()->nullOnDelete();
            $table->string('old_status')->nullable();
            $table->string('new_status');
            $table->text('reason')->nullable();
            $table->foreignId('changed_by_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->json('metadata')->nullable();
            $table->timestamp('changed_at');
            $table->timestamps();

            $table->index(['finding_id', 'changed_at']);
            $table->index(['website_id', 'new_status', 'changed_at']);
        });

        Schema::create('risk_score_histories', function (Blueprint $table) {
            $table->id();
            $table->foreignId('finding_id')->constrained()->cascadeOnDelete();
            $table->foreignId('workspace_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->unsignedTinyInteger('old_score')->nullable();
            $table->unsignedTinyInteger('new_score');
            $table->text('reason')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('calculated_at');
            $table->timestamps();

            $table->index(['finding_id', 'calculated_at']);
            $table->index(['website_id', 'new_score']);
        });

        Schema::create('finding_evidences', function (Blueprint $table) {
            $table->id();
            $table->foreignId('finding_id')->constrained()->cascadeOnDelete();
            $table->foreignId('workspace_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->string('type');
            $table->string('mime')->default('application/json');
            $table->string('sha256', 64);
            $table->foreignId('artifact_id')->nullable()->constrained('raw_artifacts')->nullOnDelete();
            $table->text('thumbnail')->nullable();
            $table->text('preview')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('observed_at')->nullable();
            $table->timestamps();

            $table->index(['finding_id', 'type']);
            $table->index(['website_id', 'sha256']);
        });

        Schema::create('suppression_rules', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignId('website_id')->nullable()->constrained()->cascadeOnDelete();
            $table->string('scanner_key')->nullable();
            $table->string('template_id')->nullable();
            $table->string('host')->nullable();
            $table->string('action')->default('ignored');
            $table->timestamp('expires_at')->nullable();
            $table->text('reason')->nullable();
            $table->foreignId('created_by_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->boolean('enabled')->default(true);
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->index(['workspace_id', 'website_id', 'enabled']);
            $table->index(['scanner_key', 'template_id', 'host']);
            $table->index(['expires_at']);
        });

        Schema::create('confidence_histories', function (Blueprint $table) {
            $table->id();
            $table->foreignId('finding_id')->constrained()->cascadeOnDelete();
            $table->foreignId('workspace_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->unsignedTinyInteger('confidence');
            $table->text('reason')->nullable();
            $table->string('scanner')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('calculated_at');
            $table->timestamps();

            $table->index(['finding_id', 'calculated_at']);
            $table->index(['website_id', 'scanner']);
        });

        Schema::create('finding_deltas', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('scan_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignId('previous_scan_id')->nullable()->constrained('scans')->nullOnDelete();
            $table->foreignId('finding_id')->nullable()->constrained()->nullOnDelete();
            $table->string('delta_type');
            $table->string('old_status')->nullable();
            $table->string('new_status')->nullable();
            $table->unsignedTinyInteger('old_score')->nullable();
            $table->unsignedTinyInteger('new_score')->nullable();
            $table->string('old_severity')->nullable();
            $table->string('new_severity')->nullable();
            $table->text('reason')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('calculated_at');
            $table->timestamps();

            $table->index(['website_id', 'scan_id', 'delta_type']);
            $table->index(['finding_id', 'calculated_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('finding_deltas');
        Schema::dropIfExists('confidence_histories');
        Schema::dropIfExists('suppression_rules');
        Schema::dropIfExists('finding_evidences');
        Schema::dropIfExists('risk_score_histories');
        Schema::dropIfExists('finding_events');
        Schema::dropIfExists('finding_sources');

        Schema::table('findings', function (Blueprint $table) {
            $table->dropIndex('findings_ws_site_status_risk_seen_idx');
            $table->dropIndex('findings_ws_scanner_seen_idx');
            $table->dropIndex('findings_site_priority_status_idx');
            $table->dropIndex('findings_site_correlation_idx');
            $table->dropIndex('findings_canonical_site_idx');
            $table->dropIndex('findings_asset_idx');
            $table->dropConstrainedForeignId('workspace_id');
            $table->dropConstrainedForeignId('canonical_finding_id');
            $table->dropConstrainedForeignId('finding_taxonomy_id');
            $table->dropConstrainedForeignId('related_finding_id');
            $table->dropColumn([
                'normalized_title',
                'normalized_description',
                'risk_score',
                'priority',
                'resolved_at',
                'reopened_at',
                'correlation_key',
                'correlation_score',
                'asset_type',
                'asset_id',
                'asset_identifier',
                'affected_component',
                'affected_parameter',
                'cve_json',
                'cwe_json',
                'cvss_score',
                'ai_summary',
                'analysis_version',
                'analysis_status',
                'sla_due_at',
            ]);
        });

        Schema::table('websites', function (Blueprint $table) {
            $table->dropColumn(['critical_count', 'high_count', 'risk_trend']);
        });

        Schema::dropIfExists('canonical_findings');
        Schema::dropIfExists('finding_taxonomies');
    }

    private function backfillFindingWorkspaceIds(): void
    {
        DB::table('findings')
            ->whereNull('workspace_id')
            ->orderBy('id')
            ->chunkById(250, function ($findings): void {
                foreach ($findings as $finding) {
                    $workspaceId = DB::table('websites')
                        ->where('id', $finding->website_id)
                        ->value('workspace_id');

                    if ($workspaceId !== null) {
                        DB::table('findings')
                            ->where('id', $finding->id)
                            ->update(['workspace_id' => $workspaceId]);
                    }
                }
            });
    }
};
