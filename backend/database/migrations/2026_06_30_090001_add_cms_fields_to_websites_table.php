<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('websites', function (Blueprint $table) {
            $table->boolean('cms_detected')->default(false);
            $table->string('cms_name')->nullable();
            $table->string('cms_version')->nullable();
            $table->integer('cms_confidence')->default(0);
        });
    }

    public function down(): void
    {
        Schema::table('websites', function (Blueprint $table) {
            $table->dropColumn(['cms_detected', 'cms_name', 'cms_version', 'cms_confidence']);
        });
    }
};
