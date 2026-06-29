<?php

namespace App\Fingerprinting\Support;

use App\Fingerprinting\Contracts\FingerprintPluginInterface;
use Illuminate\Contracts\Container\Container;
use InvalidArgumentException;

class PluginLoader
{
    public function __construct(private readonly Container $container)
    {
    }

    /**
     * @return list<FingerprintPluginInterface>
     */
    public function load(): array
    {
        $plugins = [];

        foreach (config('fingerprinting.plugins', []) as $pluginClass) {
            $plugin = $this->container->make($pluginClass);

            if (! $plugin instanceof FingerprintPluginInterface) {
                throw new InvalidArgumentException(sprintf('%s must implement FingerprintPluginInterface.', $pluginClass));
            }

            $plugins[] = $plugin;
        }

        return $plugins;
    }
}
