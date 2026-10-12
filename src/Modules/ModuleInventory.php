<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Modules;

/**
 * The modules a shop has: those in the `module` table, and those whose folder is
 * in modules/ without being installed. An uninstalled module's files are still
 * reachable by URL, and many PrestaShop module flaws are exactly that, so a
 * disabled or uninstalled module with a known flaw still matters.
 *
 * The version is the one in the `module` table, which is what PrestaShop last
 * installed or upgraded; for a module that isn't installed, it is config.xml's.
 */
final class ModuleInventory
{
    /**
     * @param list<array{name: string, version?: string|null, active?: int|string|bool|null}> $installedRows Rows of the `module` table
     *
     * @return list<ModuleInfo> Sorted by name
     */
    public function modules(string $modulesDirectory, array $installedRows): array
    {
        $found = [];

        foreach (glob(rtrim($modulesDirectory, '/\\') . '/*/config.xml') ?: [] as $file) {
            $info = $this->readConfig($file);
            if ($info !== null) {
                $found[$info['name']] = $info;
            }
        }

        $modules = [];
        $seen = [];

        foreach ($installedRows as $row) {
            $name = strtolower(trim($row['name']));
            if ($name === '' || isset($seen[$name])) {
                continue;
            }
            $seen[$name] = true;
            $disk = $found[$name] ?? null;
            $version = trim((string) ($row['version'] ?? ''));
            $modules[] = new ModuleInfo(
                $name,
                $version !== '' ? $version : ($disk['version'] ?? ''),
                $disk['author'] ?? '',
                true,
                (bool) (int) ($row['active'] ?? 1),
            );
        }

        foreach ($found as $name => $disk) {
            if (!isset($seen[$name])) {
                $modules[] = new ModuleInfo($name, $disk['version'], $disk['author'], false, false);
            }
        }

        usort($modules, static fn (ModuleInfo $a, ModuleInfo $b): int => $a->name <=> $b->name);

        return $modules;
    }

    /**
     * @return array{name: string, version: string, author: string}|null
     */
    private function readConfig(string $file): ?array
    {
        $previous = libxml_use_internal_errors(true);
        $xml = simplexml_load_file($file, \SimpleXMLElement::class, LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        if ($xml === false) {
            return null;
        }

        // The folder is the technical name; config.xml repeats it.
        $name = strtolower(basename(\dirname($file)));
        $version = trim((string) $xml->version);

        return $version === '' ? null : ['name' => $name, 'version' => $version, 'author' => trim((string) $xml->author)];
    }
}
