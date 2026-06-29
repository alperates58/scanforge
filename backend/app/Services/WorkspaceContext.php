<?php

namespace App\Services;

use App\Models\User;
use App\Models\Workspace;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class WorkspaceContext
{
    public function resolve(User $user, Request $request): Workspace
    {
        $requestedWorkspaceId = $request->header('X-Workspace-Id');

        $query = $user->workspaces()->withPivot('role');

        if ($requestedWorkspaceId !== null && $requestedWorkspaceId !== '') {
            $workspace = $query->where('workspaces.id', (int) $requestedWorkspaceId)->first();

            if ($workspace === null) {
                throw ValidationException::withMessages([
                    'workspace_id' => ['Workspace is not available for this user.'],
                ]);
            }

            return $workspace;
        }

        $workspace = $query->orderBy('workspaces.id')->first();

        if ($workspace === null) {
            throw ValidationException::withMessages([
                'workspace_id' => ['User does not belong to a workspace.'],
            ]);
        }

        return $workspace;
    }
}
