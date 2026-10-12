<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Modules;

/**
 * One module as the shop has it.
 */
final readonly class ModuleInfo
{
    public function __construct(
        public string $name,
        public string $version,
        public string $author = '',
        public bool $installed = true,
        public bool $active = true,
    ) {
    }

    /**
     * Whether PrestaShop SA ships it, and so it is a Composer package on Packagist
     * (prestashop/ps_facetedsearch): its author says so, or it carries the ps_ prefix.
     */
    public function isNative(): bool
    {
        return str_starts_with($this->name, 'ps_') || preg_match('/^prestashop(\s+sa)?$/i', trim($this->author)) === 1;
    }
}
