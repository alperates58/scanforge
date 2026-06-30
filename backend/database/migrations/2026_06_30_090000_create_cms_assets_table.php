<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('cms_assets', function (Blueprint $table) {
            $table->id();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->string('cms_name')->index();
            $table->string('asset_type')->index(); // core, plugin, theme
            $table->string('asset_name');
            $table->string('detected_version')->nullable();
            $table->string('source')->nullable(); // e.g. generator_meta, readme, wp_json
            $table->string('confidence')->default('inferred'); // exact, probable, inferred
            $table->boolean('analysis_required')->default(true);
            $table->timestamp('first_seen_at')->nullable();
            $table->timestamp('last_seen_at')->nullable();
            $table->timestamps();

            $table->unique(['website_id', 'cms_name', 'asset_type', 'asset_name'], 'cms_assets_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('cms_assets');
    }
};
