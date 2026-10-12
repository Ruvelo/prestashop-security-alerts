<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Tests\Unit;

use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use Ruvelo\PrestaShop\SecurityAlerts\Sources\FriendsOfPrestaSource;
use Ruvelo\PrestaShop\SecurityAlerts\Tests\Support\ArrayCache;
use Ruvelo\PrestaShop\SecurityAlerts\Tests\Support\MockClient;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\Severity;

final class FriendsOfPrestaSourceTest extends TestCase
{
    private const POSTS = [
        '2026-05-21-upsshipping-cve-2026-39079',
        '2026-02-16-advancedpopupcreator-cve-2025-69633',
        '2025-10-23-ps_checkout',
        '2024-07-26-paypal',
        '2025-05-22-appagebuilder',
    ];

    private MockClient $client;

    private function source(bool $withPosts = true, ?ArrayCache $cache = null): FriendsOfPrestaSource
    {
        $bodies = ['search.json' => (string) file_get_contents(__DIR__ . '/../fixtures/fop-index.json')];
        foreach ($withPosts ? self::POSTS : [] as $slug) {
            $bodies[$slug . '.md'] = (string) file_get_contents(__DIR__ . '/../fixtures/posts/' . $slug . '.md');
        }
        $this->client = new MockClient($bodies);
        $factory = new Psr17Factory();

        return new FriendsOfPrestaSource(new JsonClient($this->client, $factory, $factory, tries: 1), $this->client, $factory, new ResponseCache($cache));
    }

    private static function module(string $name, string $version): InstalledPackage
    {
        return new InstalledPackage(Ecosystem::Extension, $name, $version);
    }

    public function testSupportsOnlyExtensions(): void
    {
        $source = $this->source();

        self::assertTrue($source->supports(Ecosystem::Extension));
        self::assertFalse($source->supports(Ecosystem::Composer));
    }

    public function testMatchesAnAffectedModuleAndLinksTheAdvisory(): void
    {
        $matches = $this->source()->find([self::module('advancedpopupcreator', '1.2.0')]);

        self::assertCount(1, $matches);
        $advisory = $matches[0]->advisory;
        self::assertSame('FOP-2026-02-16-advancedpopupcreator-cve-2025-69633', $advisory->id);
        self::assertSame('CVE-2025-69633', $advisory->cve);
        self::assertSame(Severity::Critical, $advisory->severity);
        self::assertSame('https://security.friendsofpresta.org/modules/2026/02/16/advancedpopupcreator-cve-2025-69633.html', $advisory->link);
        self::assertSame('1.2.7', $matches[0]->fixedIn);
        self::assertStringStartsWith('Improper neutralization', $advisory->title);
    }

    public function testAFixedVersionIsNotAFinding(): void
    {
        self::assertSame([], $this->source()->find([self::module('advancedpopupcreator', '1.2.7')]));
    }

    public function testAllVersionsAdvisoryHasNoFix(): void
    {
        $matches = $this->source()->find([self::module('upsshipping', '2.4.0')]);

        self::assertCount(1, $matches);
        self::assertNull($matches[0]->fixedIn);
        self::assertSame(Severity::High, $matches[0]->advisory->severity);
    }

    public function testModuleNamesAreMatchedCaseInsensitively(): void
    {
        self::assertCount(1, $this->source()->find([self::module('UpsShipping', '1.0.0')]));
    }

    public function testUnrelatedModulesCostNoRequestForAdvisoryText(): void
    {
        $source = $this->source();
        $source->find([self::module('ps_emailsubscription', '2.0.0')]);

        self::assertSame(['GET https://security.friendsofpresta.org/search.json'], $this->client->requested);
    }

    public function testUnreadableVersionsAreReportedNotGuessed(): void
    {
        $source = $this->source();
        // ps_checkout's ">= 1.3.0, < 4.4.1, < 5.0.5" is ambiguous.
        $matches = $source->find([self::module('ps_checkout', '4.0.0')]);

        self::assertSame([], $matches);
        self::assertCount(1, $source->unreadable());
        self::assertStringStartsWith('ps_checkout: ', $source->unreadable()[0]);
    }

    public function testFetchesEachAdvisoryOnceThenReadsTheCache(): void
    {
        $cache = new ArrayCache();
        $this->source(true, $cache)->find([self::module('upsshipping', '2.4.0')]);
        $first = \count($this->client->requested);
        $this->source(true, $cache)->find([self::module('upsshipping', '2.4.0')]);

        self::assertSame(2, $first);
        self::assertSame([], $this->client->requested);
    }

    public function testAnUnreadableFeedIsAnErrorNotAnEmptyAnswer(): void
    {
        $this->expectException(SourceUnavailable::class);
        $this->source(false)->find([self::module('upsshipping', '2.4.0')]);
    }

    public function testParsePostReadsTheFields(): void
    {
        $post = FriendsOfPrestaSource::parsePost('2026-05-21-x', (string) file_get_contents(__DIR__ . '/../fixtures/posts/2026-05-21-upsshipping-cve-2026-39079.md'));

        self::assertSame('FOP-2026-05-21-x', $post['id']);
        self::assertSame('CVE-2026-39079', $post['cve']);
        self::assertSame('2026-05-18', $post['date']);
        self::assertSame('*', $post['constraint']);
    }
}
