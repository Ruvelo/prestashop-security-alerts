<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\PrestaShop;

use Nyholm\Psr7\Factory\Psr17Factory;
use Ruvelo\PrestaShop\SecurityAlerts\Cache\FileCache;
use Ruvelo\PrestaShop\SecurityAlerts\Checker;
use Ruvelo\PrestaShop\SecurityAlerts\Checkup;
use Ruvelo\PrestaShop\SecurityAlerts\Http\CurlHttpClient;
use Ruvelo\PrestaShop\SecurityAlerts\Modules\ModuleInventory;
use Ruvelo\PrestaShop\SecurityAlerts\Modules\PackageLists;
use Ruvelo\PrestaShop\SecurityAlerts\Sources\FriendsOfPrestaSource;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Cache\Ttls;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAdvisories\Sources\KevCatalogue;
use Ruvelo\SecurityAdvisories\Sources\PackagistAdvisorySource;

/**
 * Builds the pieces from the running shop. Used by the back office, the cron URL
 * and the console command alike.
 */
final class ServiceFactory
{
    public static function checker(): Checker
    {
        return new Checker(self::checkup(), new DbStorage(), new ConfigurationSettings(), new MailNotifier(self::moduleDirectory()));
    }

    public static function checkup(): Checkup
    {
        $psr17 = new Psr17Factory();
        $client = new CurlHttpClient($psr17);
        $json = new JsonClient($client, $psr17, $psr17);
        $cache = new ResponseCache(new FileCache(_PS_CACHE_DIR_ . 'ruvelo_securityalerts'), new Ttls());

        $friends = new FriendsOfPrestaSource($json, $client, $psr17, $cache);
        $scanner = new Scanner(
            PackageLists::build(_PS_VERSION_, self::modules()),
            [new PackagistAdvisorySource($json, $cache), $friends],
            new KevCatalogue($json, $cache),
        );

        return new Checkup($scanner, $friends);
    }

    /**
     * @return list<\Ruvelo\PrestaShop\SecurityAlerts\Modules\ModuleInfo>
     */
    public static function modules(): array
    {
        $rows = \Db::getInstance()->executeS('SELECT `name`, `version`, `active` FROM `' . _DB_PREFIX_ . 'module`');

        return (new ModuleInventory())->modules(_PS_MODULE_DIR_, \is_array($rows) ? array_values($rows) : []);
    }

    public static function moduleDirectory(): string
    {
        return rtrim(_PS_MODULE_DIR_, '/') . '/ruvelo_securityalerts';
    }
}
