<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Tests\Unit;

use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use Ruvelo\PrestaShop\SecurityAlerts\Checker;
use Ruvelo\PrestaShop\SecurityAlerts\Checkup;
use Ruvelo\PrestaShop\SecurityAlerts\Dedupe;
use Ruvelo\PrestaShop\SecurityAlerts\Modules\ModuleInfo;
use Ruvelo\PrestaShop\SecurityAlerts\Modules\PackageLists;
use Ruvelo\PrestaShop\SecurityAlerts\Notifier;
use Ruvelo\PrestaShop\SecurityAlerts\Settings;
use Ruvelo\PrestaShop\SecurityAlerts\Sources\FriendsOfPrestaSource;
use Ruvelo\PrestaShop\SecurityAlerts\Storage;
use Ruvelo\PrestaShop\SecurityAlerts\Tests\Support\MockClient;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Changes;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\KevEntry;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAdvisories\Sources\KevCatalogue;
use Ruvelo\SecurityAdvisories\Sources\PackagistAdvisorySource;

final class CheckerTest extends TestCase
{
    private function finding(string $package, string $id, Severity $severity = Severity::High, bool $exploited = false, ?string $cve = null, Ecosystem $eco = Ecosystem::Extension): Finding
    {
        return new Finding($eco, $package, '1.0.0', $id, 'Title ' . $id, $severity, 'https://example.test/' . $id, $cve, '1.0.1', null, null,
            $exploited ? new KevEntry($cve ?? 'CVE-2026-0001', 'x', new \DateTimeImmutable('2026-01-01')) : null);
    }

    /**
     * A checker whose "network" answers Packagist, the Friends of Presta and CISA from canned bodies.
     *
     * @return array{Checker, FakeStorage, FakeNotifier, FakeSettings}
     */
    private function build(bool $kevExploits, FakeStorage $storage = new FakeStorage(), ?FakeSettings $settings = null): array
    {
        $kev = json_encode(['vulnerabilities' => $kevExploits ? [['cveID' => 'CVE-2025-69633', 'vulnerabilityName' => 'APC SQLi', 'dateAdded' => '2026-03-01', 'dueDate' => '2026-03-22', 'knownRansomwareCampaignUse' => 'Unknown']] : []]);
        $client = new MockClient([
            'packagist.org' => json_encode(['advisories' => []]),
            'search.json' => (string) file_get_contents(__DIR__ . '/../fixtures/fop-index.json'),
            'advancedpopupcreator-cve-2025-69633.md' => (string) file_get_contents(__DIR__ . '/../fixtures/posts/2026-02-16-advancedpopupcreator-cve-2025-69633.md'),
            'cisa.gov' => $kev,
        ]);
        $factory = new Psr17Factory();
        $json = new JsonClient($client, $factory, $factory, tries: 1);
        $cache = new ResponseCache();
        $friends = new FriendsOfPrestaSource($json, $client, $factory, $cache);
        $scanner = new Scanner(
            PackageLists::build('8.1.7', [new ModuleInfo('advancedpopupcreator', '1.2.0', 'Idnovate')]),
            [new PackagistAdvisorySource($json, $cache), $friends],
            new KevCatalogue($json, $cache),
        );
        $notifier = new FakeNotifier();
        $settings ??= new FakeSettings();

        return [new Checker(new Checkup($scanner, $friends), $storage, $settings, $notifier), $storage, $notifier, $settings];
    }

    public function testFindsStoresAndEmailsAnExploitedFindingFirst(): void
    {
        [$checker, $storage, $notifier] = $this->build(true);

        $outcome = $checker->run();

        self::assertTrue($outcome->report->isComplete(), implode('; ', $outcome->report->problems));
        self::assertCount(1, $outcome->report->findings);
        self::assertTrue($outcome->report->findings[0]->isExploited());
        self::assertCount(1, $storage->rows);
        self::assertSame(1, $outcome->emailed);
        self::assertCount(1, $notifier->sent);
        self::assertSame([], $storage->pending(), 'a mailed finding is not mailed again');
    }

    public function testASecondCheckSendsNothing(): void
    {
        [$checker, , $notifier] = $this->build(true);

        $checker->run();
        $second = $checker->run();

        self::assertSame(0, $second->emailed);
        self::assertCount(1, $notifier->sent);
    }

    public function testAFindingThatBecomesExploitedIsMailedAgain(): void
    {
        $storage = new FakeStorage();
        [$first] = $this->build(false, $storage);
        $first->run();
        self::assertFalse($storage->known()['extension:advancedpopupcreator:FOP-2026-02-16-advancedpopupcreator-cve-2025-69633']);

        [$second, , $notifier] = $this->build(true, $storage);
        $outcome = $second->run();

        self::assertCount(1, $outcome->changes->exploited);
        self::assertSame(1, $outcome->emailed);
        self::assertTrue($notifier->sent[0][0]->isExploited());
    }

    public function testDryRunStoresAndSendsNothing(): void
    {
        [$checker, $storage, $notifier] = $this->build(true);

        $outcome = $checker->run(true);

        self::assertTrue($outcome->dryRun);
        self::assertCount(1, $outcome->report->findings);
        self::assertSame([], $storage->rows);
        self::assertSame([], $notifier->sent);
    }

    public function testNoRecipientsMeansNoMailButItIsNotQueuedForLater(): void
    {
        [$checker, $storage, $notifier] = $this->build(true, new FakeStorage(), new FakeSettings(recipients: []));

        $checker->run();

        self::assertSame([], $notifier->sent);
        self::assertSame([], $storage->pending());
    }

    public function testBelowTheMinimumSeverityNothingIsMailedUnlessExploited(): void
    {
        [$checker, , $notifier] = $this->build(false, new FakeStorage(), new FakeSettings(minimum: Severity::Critical));
        // advancedpopupcreator is critical; use a stricter bar via a high-rated one below.
        $checker->run();
        self::assertCount(1, $notifier->sent, 'critical meets a critical minimum');

        $settings = new FakeSettings(minimum: Severity::Critical);
        $storage = new FakeStorage();
        $storage->rows['k'] = ['finding' => $this->finding('m', 'A', Severity::High), 'exploited' => false, 'notified' => false];
        $notifier = new FakeNotifier();
        $checkup = $this->emptyCheckup();
        (new Checker($checkup, $storage, $settings, $notifier))->run();
        self::assertSame([], $notifier->sent);
    }

    public function testAFailedMailIsRetriedNextTime(): void
    {
        [$checker, $storage, $notifier] = $this->build(true);
        $notifier->ok = false;

        $checker->run();
        self::assertCount(1, $storage->pending());

        $notifier->ok = true;
        $checker->run();
        self::assertSame([], $storage->pending());
    }

    public function testDisabledChecksStillStoreButDoNotMail(): void
    {
        [$checker, $storage, $notifier] = $this->build(true, new FakeStorage(), new FakeSettings(enabled: false));

        $checker->run();

        self::assertCount(1, $storage->rows);
        self::assertSame([], $notifier->sent);
    }

    public function testPackagistWinsOverFriendsOfPrestaForTheSameCve(): void
    {
        $report = new Report([
            $this->finding('prestashop/ps_checkout', 'PKSA-1', Severity::Critical, false, 'CVE-2025-61922', Ecosystem::Composer),
            $this->finding('ps_checkout', 'FOP-x', Severity::Critical, false, 'CVE-2025-61922'),
            $this->finding('ps_checkout', 'FOP-y', Severity::High, false, 'CVE-2025-99999'),
            $this->finding('other', 'FOP-z', Severity::High, false, 'CVE-2025-61922'),
        ]);

        $ids = array_map(static fn (Finding $f): string => $f->advisoryId, Dedupe::report($report)->findings);
        sort($ids);

        self::assertSame(['FOP-y', 'FOP-z', 'PKSA-1'], $ids);
    }

    private function emptyCheckup(): Checkup
    {
        $client = new MockClient(['search.json' => '[{"url":"/x/2026/01/01/none.html","tags":"none"}]']);
        $factory = new Psr17Factory();
        $json = new JsonClient($client, $factory, $factory, tries: 1);
        $friends = new FriendsOfPrestaSource($json, $client, $factory, new ResponseCache());

        return new Checkup(new Scanner([], [$friends]), $friends);
    }
}

final class FakeSettings implements Settings
{
    /**
     * @param list<string> $recipients
     */
    public function __construct(
        private readonly bool $enabled = true,
        private readonly array $recipients = ['owner@example.test'],
        private readonly Severity $minimum = Severity::Medium,
    ) {
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function recipients(): array
    {
        return $this->recipients;
    }

    public function minimumSeverity(): Severity
    {
        return $this->minimum;
    }
}

final class FakeNotifier implements Notifier
{
    /** @var list<list<Finding>> */
    public array $sent = [];
    public bool $ok = true;

    public function send(array $recipients, array $findings): bool
    {
        if ($this->ok) {
            $this->sent[] = $findings;
        }

        return $this->ok;
    }
}

final class FakeStorage implements Storage
{
    /** @var array<string, array{finding: Finding, exploited: bool, notified: bool}> */
    public array $rows = [];
    /** @var array<string, mixed>|null */
    public ?array $meta = null;

    public function known(): array
    {
        return array_map(static fn (array $r): bool => $r['exploited'], $this->rows);
    }

    public function apply(Report $report, Changes $changes): void
    {
        $flipped = array_map(static fn (Finding $f): string => $f->key(), $changes->exploited);
        foreach ($report->findings as $f) {
            $old = $this->rows[$f->key()] ?? null;
            $this->rows[$f->key()] = [
                'finding' => $f,
                'exploited' => $f->isExploited() || ($old['exploited'] ?? false),
                'notified' => $old !== null && !\in_array($f->key(), $flipped, true) && $old['notified'],
            ];
        }
        foreach ($changes->resolved as $key) {
            unset($this->rows[$key]);
        }
    }

    public function pending(): array
    {
        return array_values(array_map(static fn (array $r): Finding => $r['finding'], array_filter($this->rows, static fn (array $r): bool => !$r['notified'])));
    }

    public function markNotified(array $keys): void
    {
        foreach ($keys as $key) {
            $this->rows[$key]['notified'] = true;
        }
    }

    public function all(): array
    {
        return array_values(array_map(static fn (array $r): Finding => $r['finding'], $this->rows));
    }

    public function lastCheck(): ?array
    {
        return $this->meta;
    }

    public function saveLastCheck(array $meta): void
    {
        $this->meta = $meta;
    }
}
