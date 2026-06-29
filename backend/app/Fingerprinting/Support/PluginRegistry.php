<?php

namespace App\Fingerprinting\Support;

use App\Fingerprinting\Contracts\FingerprintPluginInterface;

class PluginRegistry
{
    /**
     * @param list<FingerprintPluginInterface> $plugins
     */
    public function __construct(private readonly array $plugins)
    {
    }

    /**
     * @return list<FingerprintPluginInterface>
     */
    public function plugins(): array
    {
        return $this->plugins;
    }

    /**
     * @return list<RuleGroup>
     */
    public function ruleGroups(): array
    {
        $groups = [];

        foreach ($this->plugins as $plugin) {
            array_push($groups, ...$plugin->ruleGroups());
        }

        return $groups;
    }
}
