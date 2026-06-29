<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('workspaces', function (Blueprint $table) {
            $table->string('plan_name')->default('personal');
            $table->unsignedInteger('monthly_scan_limit')->default(100);
            $table->unsignedInteger('concurrent_scan_limit')->default(1);
            $table->unsignedInteger('scans_used_this_month')->default(0);
        });

        Schema::table('websites', function (Blueprint $table) {
            $table->foreignId('created_by_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('scheme', 10)->nullable();
            $table->string('host')->nullable();
            $table->string('root_domain')->nullable();
            $table->unsignedSmallInteger('port')->nullable();
            $table->string('environment')->default('production');
            $table->string('importance')->default('normal');
            $table->string('verification_status')->default('pending');
            $table->string('verification_token_hash', 128)->nullable();
            $table->timestamp('verification_last_checked_at')->nullable();
            $table->timestamp('ownership_verified_at')->nullable();
            $table->unsignedTinyInteger('security_score')->nullable();
            $table->decimal('risk_score', 5, 2)->nullable();
            $table->unsignedTinyInteger('last_scan_score')->nullable();
            $table->text('notes')->nullable();
            $table->json('tags')->nullable();

            $table->index(['workspace_id', 'verification_status']);
            $table->index(['root_domain', 'environment']);
            $table->index(['importance', 'security_score']);
        });

        if (Schema::hasColumn('websites', 'verification_token')) {
            Schema::table('websites', function (Blueprint $table) {
                $table->dropColumn('verification_token');
            });
        }

        Schema::table('domain_verifications', function (Blueprint $table) {
            $table->string('verification_token_hash', 128)->nullable();
            $table->index(['method', 'status']);
        });

        DB::table('domain_verifications')->update([
            'verification_token_hash' => DB::raw("coalesce(verification_token_hash, '')"),
        ]);

        if (Schema::hasColumn('domain_verifications', 'token')) {
            Schema::table('domain_verifications', function (Blueprint $table) {
                $table->dropColumn('token');
            });
        }

        Schema::table('scans', function (Blueprint $table) {
            $table->timestamp('discovery_completed_at')->nullable();
            $table->timestamp('fingerprint_completed_at')->nullable();
            $table->timestamp('passive_scan_completed_at')->nullable();
            $table->timestamp('deep_scan_completed_at')->nullable();
            $table->timestamp('ai_analysis_completed_at')->nullable();
        });

        Schema::table('technology_fingerprints', function (Blueprint $table) {
            $table->unsignedTinyInteger('confidence_score')->default(0);
            $table->string('detection_source')->nullable();
            $table->string('cpe')->nullable();

            $table->index(['website_id', 'confidence_score']);
            $table->index(['detection_source', 'name']);
        });

        Schema::table('ai_analyses', function (Blueprint $table) {
            $table->string('prompt_version')->nullable();
            $table->string('model_provider')->nullable();
            $table->string('model_name')->nullable();
            $table->unsignedInteger('input_tokens')->nullable();
            $table->unsignedInteger('output_tokens')->nullable();
            $table->decimal('cost_usd', 10, 6)->nullable();
            $table->unsignedInteger('duration_ms')->nullable();
        });

        Schema::create('scan_profiles', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->string('name');
            $table->string('scan_type');
            $table->json('enabled_modules')->nullable();
            $table->json('rate_limit')->nullable();
            $table->unsignedInteger('timeout_seconds')->default(900);
            $table->boolean('is_default')->default(false);
            $table->boolean('authenticated')->default(false);
            $table->foreignId('created_by_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();

            $table->unique(['website_id', 'name']);
            $table->index(['workspace_id', 'scan_type', 'is_default']);
        });

        Schema::create('website_credentials', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->string('name');
            $table->string('type');
            $table->text('encrypted_payload');
            $table->foreignId('created_by_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamps();

            $table->index(['workspace_id', 'type']);
            $table->index(['website_id', 'expires_at']);
        });

        Schema::create('scanner_capabilities', function (Blueprint $table) {
            $table->id();
            $table->string('technology_key');
            $table->string('scanner_key');
            $table->string('template_group');
            $table->string('scan_module');
            $table->unsignedTinyInteger('min_confidence')->default(70);
            $table->boolean('enabled')->default(true);
            $table->boolean('safe_default')->default(true);
            $table->text('description')->nullable();
            $table->timestamps();

            $table->unique(['technology_key', 'scanner_key', 'template_group', 'scan_module'], 'scanner_capability_unique');
            $table->index(['technology_key', 'enabled']);
            $table->index(['scanner_key', 'safe_default']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('scanner_capabilities');
        Schema::dropIfExists('website_credentials');
        Schema::dropIfExists('scan_profiles');

        Schema::table('ai_analyses', function (Blueprint $table) {
            $table->dropColumn([
                'prompt_version',
                'model_provider',
                'model_name',
                'input_tokens',
                'output_tokens',
                'cost_usd',
                'duration_ms',
            ]);
        });

        Schema::table('technology_fingerprints', function (Blueprint $table) {
            $table->dropIndex(['website_id', 'confidence_score']);
            $table->dropIndex(['detection_source', 'name']);
            $table->dropColumn(['confidence_score', 'detection_source', 'cpe']);
        });

        Schema::table('scans', function (Blueprint $table) {
            $table->dropColumn([
                'discovery_completed_at',
                'fingerprint_completed_at',
                'passive_scan_completed_at',
                'deep_scan_completed_at',
                'ai_analysis_completed_at',
            ]);
        });

        Schema::table('domain_verifications', function (Blueprint $table) {
            $table->dropIndex(['method', 'status']);
            $table->string('token', 128)->nullable();
            $table->dropColumn('verification_token_hash');
        });

        Schema::table('websites', function (Blueprint $table) {
            $table->dropIndex(['workspace_id', 'verification_status']);
            $table->dropIndex(['root_domain', 'environment']);
            $table->dropIndex(['importance', 'security_score']);
            $table->string('verification_token', 128)->nullable();
            $table->dropConstrainedForeignId('created_by_user_id');
            $table->dropColumn([
                'scheme',
                'host',
                'root_domain',
                'port',
                'environment',
                'importance',
                'verification_status',
                'verification_token_hash',
                'verification_last_checked_at',
                'ownership_verified_at',
                'security_score',
                'risk_score',
                'last_scan_score',
                'notes',
                'tags',
            ]);
        });

        Schema::table('workspaces', function (Blueprint $table) {
            $table->dropColumn([
                'plan_name',
                'monthly_scan_limit',
                'concurrent_scan_limit',
                'scans_used_this_month',
            ]);
        });
    }
};
