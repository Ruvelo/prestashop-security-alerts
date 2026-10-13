<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts;

use Ruvelo\PrestaShop\SecurityAlerts\Modules\ModuleInfo;
use Ruvelo\PrestaShop\SecurityAlerts\Modules\PackageLists;
use Ruvelo\PrestaShop\SecurityAlerts\Sources\FriendsOfPrestaSource;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAdvisories\Sources\FallbackAdvisorySource;
use Ruvelo\SecurityAdvisories\Sources\KevCatalogue;
use Ruvelo\SecurityAdvisories\Sources\PackagistAdvisorySource;
use Ruvelo\SecurityAdvisories\Valtry\ValtryAdvisorySource;

/**
 * The scanner for a shop: the same chain the core's Scanner::forProject() builds
 * (Valtry first, the public feeds when Valtry can't answer) for the Composer
 * packages, plus Friends of Presta for every module. Written out because the
 * package lists come from the shop, not from a lockfile.
 */
final class ScannerBuilder
{
    /**
     * @param JsonClient $json The client for the public feeds
     * @param JsonClient $valtryJson The client for Valtry, with its short timeout
     * @param string|null $source "valtry" or "public" (the setting); RUVELO_ADVISORIES_SOURCE=public in the environment wins
     * @param array<string, string>|null $keys Valtry's pinned keys; only tests say otherwise
     * @param list<ModuleInfo> $modules
     */
    public static function build(
        JsonClient $json,
        JsonClient $valtryJson,
        ResponseCache $cache,
        ?string $source,
        string $prestashopVersion,
        array $modules,
        string $valtryUrl = ValtryAdvisorySource::URL,
        ?array $keys = null,
    ): Scanner {
        $packagist = new PackagistAdvisorySource($json, $cache);
        $composer = Scanner::source($source) === Scanner::SOURCE_PUBLIC
            ? $packagist
            : new FallbackAdvisorySource(new ValtryAdvisorySource($valtryJson, $cache, $valtryUrl, $keys), [$packagist]);

        return new Scanner(
            PackageLists::build($prestashopVersion, $modules),
            [$composer, new FriendsOfPrestaSource($json, $cache)],
            new KevCatalogue($json, $cache),
        );
    }
}
