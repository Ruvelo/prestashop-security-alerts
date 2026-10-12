<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\PrestaShop\SecurityAlerts\Cache\FileCache;
use Ruvelo\PrestaShop\SecurityAlerts\FindingCodec;
use Ruvelo\PrestaShop\SecurityAlerts\Mail\MessageBuilder;
use Ruvelo\PrestaShop\SecurityAlerts\PrestaShop\ConfigurationSettings;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\KevEntry;
use Ruvelo\SecurityAdvisories\Severity;

final class SmallPartsTest extends TestCase
{
    private function finding(bool $exploited): Finding
    {
        return new Finding(Ecosystem::Extension, 'm<b>', '1.0', 'FOP-1', 'Bad <script>', Severity::Critical, 'https://x.test/a?b=1&c=2', 'CVE-2026-1', '1.1', '<1.1', '2026-01-01',
            $exploited ? new KevEntry('CVE-2026-1', 'n', new \DateTimeImmutable('2026-01-02')) : null);
    }

    public function testFindingSurvivesTheTable(): void
    {
        foreach ([true, false] as $exploited) {
            $finding = $this->finding($exploited);
            $back = FindingCodec::decode(json_decode((string) json_encode($finding->toArray()), true));

            self::assertNotNull($back);
            self::assertSame($finding->toArray(), $back->toArray());
        }
        self::assertNull(FindingCodec::decode(['ecosystem' => 'nope']));
    }

    public function testEmailEscapesEverythingAndPutsTheBadgeOnExploited(): void
    {
        $html = MessageBuilder::html([$this->finding(true)]);

        self::assertStringNotContainsString('<script>', $html);
        self::assertStringContainsString('m&lt;b&gt;', $html);
        self::assertStringContainsString('href="https://x.test/a?b=1&amp;c=2"', $html);
        self::assertStringContainsString('EXPLOITED', $html);
        self::assertStringContainsString('EXPLOITED', MessageBuilder::text([$this->finding(true)]));
        self::assertStringNotContainsString('EXPLOITED', MessageBuilder::text([$this->finding(false)]));
    }

    public function testSubjectsAndNoBrandingInTheMail(): void
    {
        self::assertStringContainsString('patch now', MessageBuilder::subject([$this->finding(true)], 'Shop'));
        self::assertStringContainsString('1 new security advisory', MessageBuilder::subject([$this->finding(false)], 'Shop'));
        self::assertStringNotContainsString('valtry', strtolower(MessageBuilder::html([$this->finding(true)]) . MessageBuilder::text([$this->finding(true)])));
    }

    public function testMailLinksMustBeHttps(): void
    {
        $f = new Finding(Ecosystem::Extension, 'm', '1', 'A', 'T', link: 'javascript:alert(1)');

        self::assertStringNotContainsString('href', MessageBuilder::html([$f]));
    }

    public function testEmailsAreSplitValidatedAndDeduplicated(): void
    {
        self::assertSame(['a@x.test', 'B@y.test'], ConfigurationSettings::parseEmails("a@x.test, B@y.test;\nnot-an-email  b@y.test"));
        self::assertSame([], ConfigurationSettings::parseEmails(''));
    }

    public function testSeverityDefaultsToMedium(): void
    {
        self::assertSame(Severity::High, ConfigurationSettings::parseSeverity('high'));
        self::assertSame(Severity::Medium, ConfigurationSettings::parseSeverity('whatever'));
        self::assertSame(Severity::Medium, ConfigurationSettings::parseSeverity('not_rated'));
    }

    public function testFileCacheKeepsAndExpires(): void
    {
        $dir = sys_get_temp_dir() . '/ruvelo-cache-' . bin2hex(random_bytes(4));
        $cache = new FileCache($dir);

        self::assertNull($cache->get('k'));
        self::assertTrue($cache->set('k', ['a' => 1], 60));
        self::assertSame(['a' => 1], $cache->get('k'));
        self::assertTrue($cache->has('k'));
        self::assertTrue($cache->set('old', 'x', -5));
        self::assertSame('fallback', $cache->get('old', 'fallback'));
        $cache->delete('k');
        self::assertFalse($cache->has('k'));
        $cache->set('z', 1, 60);
        $cache->clear();
        self::assertFalse($cache->has('z'));
        @rmdir($dir);
    }
}
