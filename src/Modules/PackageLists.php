<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Modules;

use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\Packages\ExtensionList;
use Ruvelo\SecurityAdvisories\Packages\PackageSource;

/**
 * What goes to the scanner:
 *
 *  - Composer: PrestaShop itself (prestashop/prestashop) and the modules PrestaShop SA
 *    ships (prestashop/ps_facetedsearch), which Packagist has advisories for.
 *  - Extension: every module by technical name, which the Friends of Presta source reads.
 *
 * Only the Composer names leave the server, and only for modules that are PrestaShop's own.
 */
final class PackageLists
{
    /**
     * @param list<ModuleInfo> $modules
     *
     * @return list<PackageSource>
     */
    public static function build(string $prestashopVersion, array $modules): array
    {
        $composer = [new InstalledPackage(Ecosystem::Composer, 'prestashop/prestashop', $prestashopVersion)];
        $extensions = [];

        foreach ($modules as $module) {
            if ($module->version === '') {
                continue;
            }

            // What the shop knows about the module rides along on every finding for it.
            $metadata = ['installed' => $module->installed, 'active' => $module->active];
            $extensions[] = new InstalledPackage(Ecosystem::Extension, $module->name, $module->version, false, $metadata);

            if ($module->isNative() && preg_match('/^[a-z0-9_]+$/', $module->name) === 1) {
                $composer[] = new InstalledPackage(Ecosystem::Composer, 'prestashop/' . $module->name, $module->version, false, $metadata);
            }
        }

        return [
            new ExtensionList($composer, Ecosystem::Composer, 'PrestaShop and its own modules'),
            new ExtensionList($extensions, Ecosystem::Extension, 'the installed modules'),
        ];
    }
}
