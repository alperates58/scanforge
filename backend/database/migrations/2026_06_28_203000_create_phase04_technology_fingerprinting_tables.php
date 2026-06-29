<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('technology_fingerprints', function (Blueprint $table) {
            $table->foreignId('workspace_id')->nullable()->after('id')->constrained()->nullOnDelete();
            $table->foreignId('asset_discovery_id')->nullable()->after('scan_id')->constrained()->nullOnDelete();
            $table->string('technology_key')->nullable()->after('asset_discovery_id');
            $table->string('technology_name')->nullable()->after('technology_key');
            $table->unsignedTinyInteger('quality_score')->default(0)->after('confidence_score');
            $table->json('cpe_candidates')->nullable()->after('cpe');
            $table->json('scanner_recommendations')->nullable()->after('metadata');
            $table->boolean('analysis_required')->default(true)->after('scanner_recommendations');
            $table->string('analysis_version')->default('fingerprint-v1')->after('analysis_required');
            $table->boolean('is_active')->default(true)->after('analysis_version');
            $table->timestamp('first_detected_at')->nullable()->after('is_active');
            $table->timestamp('last_detected_at')->nullable()->after('first_detected_at');
            $table->string('fingerprint_hash', 128)->nullable()->after('last_detected_at');

            $table->index(['workspace_id', 'technology_key']);
            $table->index(['asset_discovery_id', 'confidence_score']);
            $table->unique(['website_id', 'technology_key'], 'technology_fingerprints_website_key_unique');
        });

        Schema::table('scanner_capabilities', function (Blueprint $table) {
            $table->string('min_version')->nullable()->after('min_confidence');
            $table->string('max_version')->nullable()->after('min_version');
            $table->json('supported_versions')->nullable()->after('max_version');
            $table->unsignedTinyInteger('priority')->default(50)->after('safe_default');
            $table->unsignedInteger('estimated_duration_seconds')->default(60)->after('priority');
            $table->unsignedInteger('estimated_requests')->default(20)->after('estimated_duration_seconds');
            $table->decimal('estimated_cpu', 5, 2)->default(0.10)->after('estimated_requests');
            $table->unsignedInteger('estimated_memory_mb')->default(128)->after('estimated_cpu');
            $table->boolean('safe_mode')->default(true)->after('estimated_memory_mb');

            $table->index(['technology_key', 'min_version', 'max_version']);
        });

        Schema::create('technology_evidences', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('fingerprint_id')->constrained('technology_fingerprints')->cascadeOnDelete();
            $table->foreignId('asset_discovery_id')->nullable()->constrained()->nullOnDelete();
            $table->string('source_type');
            $table->string('source_key')->nullable();
            $table->text('source_value')->nullable();
            $table->unsignedTinyInteger('confidence')->default(0);
            $table->json('raw_data')->nullable();
            $table->timestamp('detected_at');
            $table->timestamps();

            $table->index(['website_id', 'source_type']);
            $table->index(['fingerprint_id', 'detected_at']);
            $table->index(['asset_discovery_id', 'source_type']);
        });

        Schema::create('fingerprint_histories', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('fingerprint_id')->constrained('technology_fingerprints')->cascadeOnDelete();
            $table->string('technology_key');
            $table->string('old_version')->nullable();
            $table->string('new_version')->nullable();
            $table->unsignedTinyInteger('confidence_old')->nullable();
            $table->unsignedTinyInteger('confidence_new')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('detected_at');
            $table->timestamps();

            $table->index(['website_id', 'technology_key', 'detected_at']);
        });

        Schema::create('technology_relationships', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('parent_fingerprint_id')->constrained('technology_fingerprints')->cascadeOnDelete();
            $table->foreignId('child_fingerprint_id')->constrained('technology_fingerprints')->cascadeOnDelete();
            $table->string('parent_technology_key');
            $table->string('child_technology_key');
            $table->string('relationship_type')->default('supports');
            $table->unsignedTinyInteger('confidence')->default(0);
            $table->json('metadata')->nullable();
            $table->timestamp('detected_at');
            $table->timestamps();

            $table->unique(['website_id', 'parent_technology_key', 'child_technology_key'], 'technology_relationship_unique');
            $table->index(['website_id', 'relationship_type']);
        });

        Schema::create('technology_conflicts', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('left_fingerprint_id')->constrained('technology_fingerprints')->cascadeOnDelete();
            $table->foreignId('right_fingerprint_id')->constrained('technology_fingerprints')->cascadeOnDelete();
            $table->string('category');
            $table->string('severity')->default('medium');
            $table->text('reason');
            $table->string('status')->default('open');
            $table->timestamp('detected_at');
            $table->timestamps();

            $table->index(['website_id', 'category', 'status']);
        });

        Schema::create('scan_plans', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('asset_discovery_id')->nullable()->constrained()->nullOnDelete();
            $table->string('status')->default('generated');
            $table->unsignedTinyInteger('coverage_prediction')->default(0);
            $table->unsignedInteger('estimated_runtime_seconds')->default(0);
            $table->unsignedInteger('estimated_requests')->default(0);
            $table->decimal('estimated_cpu', 6, 2)->default(0);
            $table->unsignedInteger('estimated_memory_mb')->default(0);
            $table->boolean('safe_mode')->default(true);
            $table->boolean('analysis_required')->default(true);
            $table->string('generated_from')->default('technology_fingerprinting');
            $table->json('summary')->nullable();
            $table->timestamp('generated_at');
            $table->timestamps();

            $table->index(['website_id', 'generated_at']);
            $table->index(['workspace_id', 'status']);
        });

        Schema::create('scan_plan_items', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_plan_id')->constrained()->cascadeOnDelete();
            $table->foreignId('technology_fingerprint_id')->nullable()->constrained('technology_fingerprints')->nullOnDelete();
            $table->string('technology_key');
            $table->string('scanner_key');
            $table->string('template_group');
            $table->string('scan_module');
            $table->unsignedTinyInteger('priority')->default(50);
            $table->unsignedTinyInteger('recommendation_score')->default(0);
            $table->unsignedInteger('estimated_duration_seconds')->default(0);
            $table->unsignedInteger('estimated_requests')->default(0);
            $table->decimal('estimated_cpu', 5, 2)->default(0);
            $table->unsignedInteger('estimated_memory_mb')->default(0);
            $table->boolean('safe_mode')->default(true);
            $table->text('reason')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->index(['scan_plan_id', 'priority']);
            $table->index(['technology_key', 'scanner_key']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('scan_plan_items');
        Schema::dropIfExists('scan_plans');
        Schema::dropIfExists('technology_conflicts');
        Schema::dropIfExists('technology_relationships');
        Schema::dropIfExists('fingerprint_histories');
        Schema::dropIfExists('technology_evidences');

        Schema::table('scanner_capabilities', function (Blueprint $table) {
            $table->dropIndex(['technology_key', 'min_version', 'max_version']);
            $table->dropColumn([
                'min_version',
                'max_version',
                'supported_versions',
                'priority',
                'estimated_duration_seconds',
                'estimated_requests',
                'estimated_cpu',
                'estimated_memory_mb',
                'safe_mode',
            ]);
        });

        Schema::table('technology_fingerprints', function (Blueprint $table) {
            $table->dropUnique('technology_fingerprints_website_key_unique');
            $table->dropIndex(['workspace_id', 'technology_key']);
            $table->dropIndex(['asset_discovery_id', 'confidence_score']);
            $table->dropConstrainedForeignId('workspace_id');
            $table->dropConstrainedForeignId('asset_discovery_id');
            $table->dropColumn([
                'technology_key',
                'technology_name',
                'quality_score',
                'cpe_candidates',
                'scanner_recommendations',
                'analysis_required',
                'analysis_version',
                'is_active',
                'first_detected_at',
                'last_detected_at',
                'fingerprint_hash',
            ]);
        });
    }
};
