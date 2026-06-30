<?php

namespace App\Scanners\Cms;

use App\Scanners\Cms\Contracts\CmsScannerPluginInterface;
use App\Scanners\Cms\Plugins\GenericCmsPlugin;
use App\Scanners\Cms\Plugins\WordPressPlugin;

class CmsPluginRegistry
{
    /** @var array<string, CmsScannerPluginInterface> */
    private array $plugins = [];

    public function __construct(
        WordPressPlugin $wordPressPlugin,
        GenericCmsPlugin $genericCmsPlugin
    ) {
        $this->plugins[$wordPressPlugin->key()] = $wordPressPlugin;
        $this->plugins[$genericCmsPlugin->key()] = $genericCmsPlugin;
    }

    /**
     * @return array<string, CmsScannerPluginInterface>
     */
    public function all(): array
    {
        return $this->plugins;
    }

    public function get(string $key): ?CmsScannerPluginInterface
    {
        return $this->plugins[$key] ?? null;
    }
}
