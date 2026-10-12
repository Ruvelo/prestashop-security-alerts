<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\PrestaShop\SecurityAlerts\Modules\ModuleInfo;
use Ruvelo\PrestaShop\SecurityAlerts\Modules\ModuleInventory;
use Ruvelo\PrestaShop\SecurityAlerts\Modules\PackageLists;
use Ruvelo\SecurityAdvisories\Ecosystem;

final class ModulesTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/ruvelo-sa-' . bin2hex(random_bytes(4));
        mkdir($this->dir . '/modules', 0775, true);
        $this->config('ps_facetedsearch', '3.0.0', 'PrestaShop');
        $this->config('upsshipping', '2.4.0', 'Agence Web 360');
        $this->config('ondisk', '1.0.0', 'Someone');
        mkdir($this->dir . '/modules/broken');
        file_put_contents($this->dir . '/modules/broken/config.xml', '<module><');
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/modules/*/config.xml') ?: [] as $file) {
            unlink($file);
        }
        foreach (glob($this->dir . '/modules/*') ?: [] as $d) {
            rmdir($d);
        }
        rmdir($this->dir . '/modules');
        rmdir($this->dir);
    }

    private function config(string $name, string $version, string $author): void
    {
        mkdir($this->dir . '/modules/' . $name);
        file_put_contents($this->dir . '/modules/' . $name . '/config.xml', "<?xml version=\"1.0\"?><module><name><![CDATA[{$name}]]></name><version><![CDATA[{$version}]]></version><author><![CDATA[{$author}]]></author></module>");
    }

    public function testInventoryMergesTheTableAndTheDisk(): void
    {
        $modules = (new ModuleInventory())->modules($this->dir . '/modules', [
            ['name' => 'ps_facetedsearch', 'version' => '3.1.0', 'active' => '1'],
            ['name' => 'upsshipping', 'version' => '', 'active' => '0'],
            ['name' => 'gone', 'version' => '1.0', 'active' => '1'],
        ]);
        $byName = array_column(array_map(static fn (ModuleInfo $m): array => [$m->name, $m], $modules), 1, 0);

        self::assertSame(['gone', 'ondisk', 'ps_facetedsearch', 'upsshipping'], array_keys($byName));
        self::assertSame('3.1.0', $byName['ps_facetedsearch']->version, 'the table wins over config.xml');
        self::assertSame('2.4.0', $byName['upsshipping']->version, 'an empty table version falls back to config.xml');
        self::assertFalse($byName['upsshipping']->active);
        self::assertTrue($byName['upsshipping']->installed);
        self::assertFalse($byName['ondisk']->installed, 'a folder that is not installed is still listed');
        self::assertSame('PrestaShop', $byName['ps_facetedsearch']->author);
    }

    public function testNativeModulesAreRecognised(): void
    {
        self::assertTrue((new ModuleInfo('ps_checkout', '1', 'whoever'))->isNative());
        self::assertTrue((new ModuleInfo('blockwishlist', '1', 'PrestaShop'))->isNative());
        self::assertTrue((new ModuleInfo('paypal', '1', 'PrestaShop SA'))->isNative());
        self::assertFalse((new ModuleInfo('upsshipping', '1', 'Agence Web 360'))->isNative());
        self::assertFalse((new ModuleInfo('fake', '1', 'PrestaShop Partner Ltd'))->isNative());
    }

    public function testOnlyPrestaShopsOwnNamesGoToPackagist(): void
    {
        $lists = PackageLists::build('8.1.7', [
            new ModuleInfo('ps_facetedsearch', '3.0.0', 'PrestaShop'),
            new ModuleInfo('upsshipping', '2.4.0', 'Agence Web 360'),
            new ModuleInfo('noversion', '', 'x'),
        ]);

        [$composer, $extension] = $lists;
        self::assertSame(Ecosystem::Composer, $composer->ecosystem());
        self::assertSame(['prestashop/prestashop', 'prestashop/ps_facetedsearch'], array_map(static fn ($p) => $p->name, $composer->packages() ?? []));
        self::assertSame(['ps_facetedsearch', 'upsshipping'], array_map(static fn ($p) => $p->name, $extension->packages() ?? []));
        self::assertSame('8.1.7', $composer->packages()[0]->version);
    }
}
