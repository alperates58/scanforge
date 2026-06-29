<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('websites', function (Blueprint $table) {
            $table->timestamp('discovery_completed_at')->nullable();
            $table->timestamp('last_observed_at')->nullable();

            $table->index(['workspace_id', 'discovery_completed_at']);
        });

        Schema::create('asset_discoveries', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('scan_id')->nullable()->constrained()->nullOnDelete();
            $table->string('status')->default('pending');
            $table->timestamp('started_at')->nullable();
            $table->timestamp('dns_completed_at')->nullable();
            $table->timestamp('http_completed_at')->nullable();
            $table->timestamp('ssl_completed_at')->nullable();
            $table->timestamp('whois_completed_at')->nullable();
            $table->timestamp('completed_at')->nullable();
            $table->unsignedInteger('duration_ms')->nullable();
            $table->json('summary')->nullable();
            $table->text('error_message')->nullable();
            $table->unsignedInteger('total_dns_records')->default(0);
            $table->unsignedInteger('total_ips')->default(0);
            $table->unsignedInteger('total_headers')->default(0);
            $table->unsignedInteger('total_cookies')->default(0);
            $table->unsignedInteger('total_findings')->default(0);
            $table->unsignedInteger('technologies_detected')->default(0);
            $table->boolean('analysis_required')->default(false);
            $table->unsignedTinyInteger('discovery_score')->nullable();
            $table->timestamps();

            $table->index(['workspace_id', 'status', 'created_at']);
            $table->index(['website_id', 'completed_at']);
        });

        Schema::create('dns_records', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('asset_discovery_id')->nullable()->constrained()->nullOnDelete();
            $table->string('type', 16);
            $table->string('name');
            $table->text('value');
            $table->unsignedInteger('ttl')->nullable();
            $table->unsignedSmallInteger('priority')->nullable();
            $table->string('source')->default('dns_get_record');
            $table->timestamp('first_seen_at');
            $table->timestamp('last_seen_at');
            $table->timestamps();

            $table->index(['website_id', 'type']);
            $table->index(['asset_discovery_id', 'type']);
        });

        Schema::create('ip_addresses', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('asset_discovery_id')->nullable()->constrained()->nullOnDelete();
            $table->string('ip', 45);
            $table->unsignedTinyInteger('ip_version');
            $table->boolean('is_public')->default(false);
            $table->string('reverse_dns')->nullable();
            $table->unsignedInteger('asn')->nullable();
            $table->string('asn_org')->nullable();
            $table->string('country_code', 2)->nullable();
            $table->string('region')->nullable();
            $table->string('city')->nullable();
            $table->string('provider')->nullable();
            $table->string('source')->default('dns');
            $table->timestamp('first_seen_at');
            $table->timestamp('last_seen_at');
            $table->timestamps();

            $table->index(['website_id', 'is_public']);
            $table->index(['asset_discovery_id', 'ip']);
        });

        Schema::create('http_observations', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('asset_discovery_id')->nullable()->constrained()->nullOnDelete();
            $table->string('url', 2048);
            $table->string('final_url', 2048)->nullable();
            $table->unsignedSmallInteger('status_code')->nullable();
            $table->string('title')->nullable();
            $table->string('server_header')->nullable();
            $table->string('powered_by_header')->nullable();
            $table->json('headers')->nullable();
            $table->json('response_headers_raw')->nullable();
            $table->json('cookies')->nullable();
            $table->json('redirect_chain')->nullable();
            $table->unsignedInteger('response_time_ms')->nullable();
            $table->string('body_sha256', 64)->nullable();
            $table->string('body_hash_sha256', 64)->nullable();
            $table->string('favicon_hash', 128)->nullable();
            $table->string('html_lang')->nullable();
            $table->string('html_doctype')->nullable();
            $table->unsignedInteger('html_size_bytes')->nullable();
            $table->string('body_title')->nullable();
            $table->text('body_description')->nullable();
            $table->string('generator_meta')->nullable();
            $table->timestamp('observed_at');
            $table->timestamps();

            $table->index(['website_id', 'observed_at']);
            $table->index(['asset_discovery_id', 'status_code']);
        });

        Schema::create('security_header_observations', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('asset_discovery_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignId('http_observation_id')->nullable()->constrained()->nullOnDelete();
            $table->string('header_key');
            $table->boolean('present')->default(false);
            $table->text('value')->nullable();
            $table->text('recommendation')->nullable();
            $table->timestamp('observed_at');
            $table->timestamps();

            $table->index(['asset_discovery_id', 'header_key']);
        });

        Schema::create('cookie_observations', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('asset_discovery_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignId('http_observation_id')->nullable()->constrained()->nullOnDelete();
            $table->string('name');
            $table->string('domain')->nullable();
            $table->string('path')->nullable();
            $table->boolean('secure')->default(false);
            $table->boolean('http_only')->default(false);
            $table->string('same_site')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->boolean('persistent')->default(false);
            $table->boolean('host_only')->default(true);
            $table->timestamp('observed_at');
            $table->timestamps();

            $table->index(['website_id', 'name']);
            $table->index(['asset_discovery_id', 'secure', 'http_only']);
        });

        Schema::create('redirect_observations', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('asset_discovery_id')->nullable()->constrained()->nullOnDelete();
            $table->foreignId('http_observation_id')->nullable()->constrained()->nullOnDelete();
            $table->unsignedTinyInteger('order');
            $table->string('from_url', 2048);
            $table->string('to_url', 2048);
            $table->unsignedSmallInteger('status_code');
            $table->timestamp('observed_at');
            $table->timestamps();

            $table->index(['asset_discovery_id', 'order']);
        });

        Schema::create('ssl_certificates', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('asset_discovery_id')->nullable()->constrained()->nullOnDelete();
            $table->string('host');
            $table->text('issuer')->nullable();
            $table->text('subject')->nullable();
            $table->timestamp('valid_from')->nullable();
            $table->timestamp('valid_to')->nullable();
            $table->integer('days_remaining')->nullable();
            $table->json('san')->nullable();
            $table->string('fingerprint_sha256', 128)->nullable();
            $table->json('tls_summary')->nullable();
            $table->timestamp('observed_at');
            $table->timestamps();

            $table->index(['website_id', 'host']);
            $table->index(['asset_discovery_id', 'days_remaining']);
        });

        Schema::create('subdomains', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('asset_discovery_id')->nullable()->constrained()->nullOnDelete();
            $table->string('host');
            $table->string('source');
            $table->boolean('resolved')->default(false);
            $table->timestamp('first_seen_at');
            $table->timestamp('last_seen_at');
            $table->timestamps();

            $table->unique(['website_id', 'host', 'source']);
            $table->index(['asset_discovery_id', 'resolved']);
        });

        Schema::create('domain_whois_snapshots', function (Blueprint $table) {
            $table->id();
            $table->foreignId('workspace_id')->constrained()->cascadeOnDelete();
            $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->foreignId('asset_discovery_id')->nullable()->constrained()->nullOnDelete();
            $table->string('registrar')->nullable();
            $table->timestamp('created_at_remote')->nullable();
            $table->timestamp('expires_at_remote')->nullable();
            $table->timestamp('updated_at_remote')->nullable();
            $table->unsignedInteger('age_days')->nullable();
            $table->json('raw_summary')->nullable();
            $table->timestamp('observed_at');
            $table->timestamps();

            $table->index(['website_id', 'observed_at']);
        });

        Schema::table('findings', function (Blueprint $table) {
            $table->dropForeign(['scan_id']);
        });

        Schema::table('findings', function (Blueprint $table) {
            $table->foreignId('scan_id')->nullable()->change();
            $table->foreignId('asset_discovery_id')->nullable()->after('website_id')->constrained()->nullOnDelete();
            $table->foreign('scan_id')->references('id')->on('scans')->cascadeOnDelete();
            $table->index(['asset_discovery_id', 'severity']);
        });
    }

    public function down(): void
    {
        Schema::table('findings', function (Blueprint $table) {
            $table->dropIndex(['asset_discovery_id', 'severity']);
            $table->dropConstrainedForeignId('asset_discovery_id');
            $table->dropForeign(['scan_id']);
        });

        Schema::table('findings', function (Blueprint $table) {
            $table->foreignId('scan_id')->nullable(false)->change();
            $table->foreign('scan_id')->references('id')->on('scans')->cascadeOnDelete();
        });

        Schema::dropIfExists('domain_whois_snapshots');
        Schema::dropIfExists('subdomains');
        Schema::dropIfExists('ssl_certificates');
        Schema::dropIfExists('redirect_observations');
        Schema::dropIfExists('cookie_observations');
        Schema::dropIfExists('security_header_observations');
        Schema::dropIfExists('http_observations');
        Schema::dropIfExists('ip_addresses');
        Schema::dropIfExists('dns_records');
        Schema::dropIfExists('asset_discoveries');

        Schema::table('websites', function (Blueprint $table) {
            $table->dropIndex(['workspace_id', 'discovery_completed_at']);
            $table->dropColumn(['discovery_completed_at', 'last_observed_at']);
        });
    }
};
