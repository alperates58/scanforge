<?php

namespace Database\Seeders;

use App\Models\Workspace;
use App\Models\User;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    use WithoutModelEvents;

    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        $this->call(ScannerCapabilitySeeder::class);

        $user = User::factory()->create([
            'name' => 'Test User',
            'email' => 'test@example.com',
        ]);

        $workspace = Workspace::query()->firstOrCreate(
            ['owner_user_id' => $user->id],
            [
                'name' => 'Personal Workspace',
                'plan_name' => 'personal',
                'monthly_scan_limit' => 100,
                'concurrent_scan_limit' => 1,
                'scans_used_this_month' => 0,
            ]
        );

        $workspace->members()->syncWithoutDetaching([
            $user->id => ['role' => 'owner'],
        ]);
    }
}
