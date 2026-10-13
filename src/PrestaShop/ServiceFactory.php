<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\PrestaShop;

use Nyholm\Psr7\Factory\Psr17Factory;
use Ruvelo\PrestaShop\SecurityAlerts\Cache\FileCache;
use Ruvelo\PrestaShop\SecurityAlerts\Checker;
use Ruvelo\PrestaShop\SecurityAlerts\Checkup;
use Ruvelo\PrestaShop\SecurityAlerts\Modules\ModuleInventory;
use Ruvelo\PrestaShop\SecurityAlerts\ScannerBuilder;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Cache\Ttls;
use Ruvelo\SecurityAdvisories\Http\CurlClient;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\Valtry\ValtryAdvisorySource;

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
        // The core's PSR-18 client on ext-curl, which every PrestaShop has: no second HTTP stack in the shop.
        $json = new JsonClient(new CurlClient($psr17, $psr17, 20.0, 10.0), $psr17, $psr17);
        // Valtry gets 5 seconds to answer before the public feeds are asked instead.
        $valtry = new JsonClient(new CurlClient($psr17, $psr17, ValtryAdvisorySource::DEADLINE, 3.0), $psr17, $psr17, tries: 1);
        $cache = new ResponseCache(new FileCache(_PS_CACHE_DIR_ . 'ruvelo_securityalerts'), new Ttls());

        return new Checkup(ScannerBuilder::build($json, $valtry, $cache, ConfigurationSettings::source(), _PS_VERSION_, self::modules()));
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
