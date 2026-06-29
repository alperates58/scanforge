<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Concerns\RespondsWithJson;
use App\Http\Controllers\Controller;
use App\Http\Requests\Api\LoginRequest;
use App\Http\Requests\Api\RegisterRequest;
use App\Models\User;
use App\Models\Workspace;
use App\Services\AuditLogService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    use RespondsWithJson;

    public function __construct(private readonly AuditLogService $auditLogService)
    {
    }

    public function register(RegisterRequest $request): JsonResponse
    {
        $user = null;
        $workspace = null;

        DB::transaction(function () use ($request, &$user, &$workspace): void {
            $user = User::query()->create([
                'name' => $request->string('name')->toString(),
                'email' => strtolower($request->string('email')->toString()),
                'password' => $request->string('password')->toString(),
            ]);

            $workspace = Workspace::query()->create([
                'name' => 'Personal Workspace',
                'owner_user_id' => $user->id,
                'plan_name' => 'personal',
                'monthly_scan_limit' => 100,
                'concurrent_scan_limit' => 1,
                'scans_used_this_month' => 0,
            ]);

            $workspace->members()->attach($user->id, ['role' => 'owner']);
        });

        $token = $user->createToken('scanforge-web')->plainTextToken;

        $this->auditLogService->record(
            'auth.registered',
            $user,
            $workspace->id,
            'user',
            $user->id,
            $request->ip(),
        );

        return $this->ok([
            'user' => $this->userData($user),
            'workspace' => $this->workspaceData($workspace),
            'token' => $token,
        ], 201);
    }

    public function login(LoginRequest $request): JsonResponse
    {
        $user = User::query()->where('email', strtolower($request->string('email')->toString()))->first();

        if (! $user || ! Hash::check($request->string('password')->toString(), $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are invalid.'],
            ]);
        }

        $workspace = $user->workspaces()->orderBy('workspaces.id')->first();
        $token = $user->createToken('scanforge-web')->plainTextToken;

        $this->auditLogService->record(
            'auth.logged_in',
            $user,
            $workspace?->id,
            'user',
            $user->id,
            $request->ip(),
        );

        return $this->ok([
            'user' => $this->userData($user),
            'workspace' => $workspace ? $this->workspaceData($workspace) : null,
            'token' => $token,
        ]);
    }

    public function me(Request $request): JsonResponse
    {
        $user = $request->user();

        return $this->ok([
            'user' => $this->userData($user),
            'workspaces' => $user->workspaces()->orderBy('workspaces.id')->get()->map(fn (Workspace $workspace): array => $this->workspaceData($workspace))->values(),
        ]);
    }

    public function logout(Request $request): JsonResponse
    {
        $user = $request->user();
        $workspace = $user->workspaces()->orderBy('workspaces.id')->first();

        $request->user()->currentAccessToken()?->delete();

        $this->auditLogService->record(
            'auth.logged_out',
            $user,
            $workspace?->id,
            'user',
            $user->id,
            $request->ip(),
        );

        return $this->ok([
            'logged_out' => true,
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function userData(User $user): array
    {
        return [
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function workspaceData(Workspace $workspace): array
    {
        return [
            'id' => $workspace->id,
            'name' => $workspace->name,
            'plan_name' => $workspace->plan_name,
            'monthly_scan_limit' => $workspace->monthly_scan_limit,
            'concurrent_scan_limit' => $workspace->concurrent_scan_limit,
            'scans_used_this_month' => $workspace->scans_used_this_month,
            'role' => $workspace->pivot?->role,
        ];
    }
}
