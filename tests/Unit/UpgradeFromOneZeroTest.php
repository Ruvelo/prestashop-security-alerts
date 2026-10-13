<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Tests\Unit;

use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use Ruvelo\PrestaShop\SecurityAlerts\Checker;
use Ruvelo\PrestaShop\SecurityAlerts\Checkup;
use Ruvelo\PrestaShop\SecurityAlerts\Modules\ModuleInfo;
use Ruvelo\PrestaShop\SecurityAlerts\ScannerBuilder;
use Ruvelo\PrestaShop\SecurityAlerts\Tests\Support\FakeNetwork;
use Ruvelo\PrestaShop\SecurityAlerts\Tests\Support\FakeNotifier;
use Ruvelo\PrestaShop\SecurityAlerts\Tests\Support\FakeSettings;
use Ruvelo\PrestaShop\SecurityAlerts\Tests\Support\FakeStorage;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\Scanner;

/**
 * A shop that ran 1.0 has findings stored, and their alerts sent. The first 1.1 check
 * must recognise them, whichever source answers, and tell nobody again.
 */
final class UpgradeFromOneZeroTest extends TestCase
{
    private const CHECKOUT = 'composer:prestashop/ps_checkout:PKSA-pscheckout';
    private const POPUP = 'extension:advancedpopupcreator:FOP-2026-02-16-advancedpopupcreator-cve-2025-69633';

    protected function tearDown(): void
    {
        putenv(Scanner::ENV);
    }

    /**
     * The table as 1.0 left it: the shape 1.0 wrote (no shape version, aliases, key or
     * metadata), everything already mailed, the popup creator already flagged exploited.
     */
    private function storedByOneZero(): FakeStorage
    {
        $storage = new FakeStorage();
        $storage->seed([
            'ecosystem' => 'composer', 'package' => 'prestashop/ps_checkout', 'installed' => '4.0.0', 'advisory_id' => 'PKSA-pscheckout',
            'title' => 'ps_checkout: improper access control', 'severity' => 'critical', 'link' => 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
            'cve' => FakeNetwork::CVE, 'fixed_in' => '4.4.1', 'affected_versions' => '<4.4.1', 'reported_at' => '2025-10-23 10:00:00', 'exploited' => false, 'kev' => null,
        ], false, true, self::CHECKOUT);
        $storage->seed([
            'ecosystem' => 'extension', 'package' => 'advancedpopupcreator', 'installed' => '1.2.0', 'advisory_id' => 'FOP-2026-02-16-advancedpopupcreator-cve-2025-69633',
            'title' => 'Improper neutralization of SQL parameters', 'severity' => 'critical', 'link' => 'https://security.friendsofpresta.org/modules/2026/02/16/advancedpopupcreator-cve-2025-69633.html',
            'cve' => 'CVE-2025-69633', 'fixed_in' => '1.2.7', 'affected_versions' => '<=1.2.6', 'reported_at' => '2026-02-16', 'exploited' => true,
            'kev' => ['cve' => 'CVE-2025-69633', 'name' => 'APC SQLi', 'date_added' => '2026-03-01', 'due_date' => '2026-03-22', 'ransomware' => false],
        ], true, true, self::POPUP);

        return $storage;
    }

    /**
     * @return array{Checker, FakeNotifier}
     */
    private function checker(FakeNetwork $net, FakeStorage $storage, string $source): array
    {
        $factory = new Psr17Factory();
        $scanner = ScannerBuilder::build(
            new JsonClient($net, $factory, $factory, tries: 1),
            new JsonClient($net, $factory, $factory, tries: 1),
            new ResponseCache(),
            $source,
            '8.1.7',
            [new ModuleInfo('ps_checkout', '4.0.0', 'PrestaShop'), new ModuleInfo('advancedpopupcreator', '1.2.0', 'Idnovate', true, false)],
            FakeNetwork::VALTRY,
            $net->keys(),
        );
        $notifier = new FakeNotifier();

        return [new Checker(new Checkup($scanner), $storage, new FakeSettings(), $notifier), $notifier];
    }

    private function assertNothingNew(Checker $checker, FakeNotifier $notifier, FakeStorage $storage): \Ruvelo\SecurityAdvisories\Report
    {
        $outcome = $checker->run();

        self::assertTrue($outcome->report->isComplete(), implode('; ', $outcome->report->problems));
        self::assertCount(2, $outcome->report->findings);
        self::assertSame([], $outcome->changes->new);
        self::assertSame([], $outcome->changes->exploited);
        self::assertSame([], $outcome->changes->resolved);
        self::assertSame(0, $outcome->emailed);
        self::assertSame([], $notifier->sent);
        self::assertSame([], $storage->pending());
        self::assertSame([self::CHECKOUT, self::POPUP], array_keys($storage->rows));
        self::assertSame([self::CHECKOUT => false, self::POPUP => true], $storage->known());

        return $outcome->report;
    }

    public function testStoredOneZeroFindingsAreKnownToThePublicPath(): void
    {
        $net = new FakeNetwork();
        $storage = $this->storedByOneZero();
        [$checker, $notifier] = $this->checker($net, $storage, 'public');

        $report = $this->assertNothingNew($checker, $notifier, $storage);

        self::assertSame('public', $report->source);
        self::assertSame([], $net->to('valtry.test'), 'the public path never contacts Valtry');
    }

    public function testStoredOneZeroFindingsAreKnownToTheValtryPath(): void
    {
        $net = new FakeNetwork();
        $storage = $this->storedByOneZero();
        [$checker, $notifier] = $this->checker($net, $storage, 'valtry');

        $report = $this->assertNothingNew($checker, $notifier, $storage);

        self::assertSame('valtry', $report->source);
        self::assertCount(1, $net->to('valtry.test'));
        self::assertSame([], $net->to('packagist.org'), 'Valtry answered, so Packagist is not asked');
    }

    public function testAnAdvisoryValtryNamesDifferentlyIsStillTheStoredOne(): void
    {
        $net = new FakeNetwork();
        $net->valtryId = 'GHSA-aaaa-bbbb-cccc';
        $storage = $this->storedByOneZero();
        [$checker, $notifier] = $this->checker($net, $storage, 'valtry');

        $this->assertNothingNew($checker, $notifier, $storage);

        self::assertSame('GHSA-aaaa-bbbb-cccc', $storage->rows[self::CHECKOUT]['data']['advisory_id'], 'the row shows the advisory as it is named now');

        // And the next check, now that the row carries the new name and its aliases, still tells nobody.
        $this->assertNothingNew($checker, $notifier, $storage);
    }

    public function testWhenValtryIsDownThePublicFeedsAnswerAndNothingIsNew(): void
    {
        $net = new FakeNetwork();
        $net->valtryDown = true;
        $storage = $this->storedByOneZero();
        [$checker, $notifier] = $this->checker($net, $storage, 'valtry');

        $report = $this->assertNothingNew($checker, $notifier, $storage);

        self::assertSame('public', $report->source);
        self::assertCount(1, $net->to('packagist.org'));
    }

    public function testTheEnvironmentOptsOutWhateverTheSettingSays(): void
    {
        putenv(Scanner::ENV . '=public');
        $net = new FakeNetwork();
        $storage = $this->storedByOneZero();
        [$checker, $notifier] = $this->checker($net, $storage, 'valtry');

        $report = $this->assertNothingNew($checker, $notifier, $storage);

        self::assertSame('public', $report->source);
        self::assertSame([], $net->to('valtry.test'));
    }

    public function testValtryIsSentPackageNamesOnly(): void
    {
        $net = new FakeNetwork();
        [$checker] = $this->checker($net, new FakeStorage(), 'valtry');

        $checker->run();

        self::assertCount(1, $net->sentToValtry);
        $names = array_map(static fn (array $p): string => $p['name'], $net->sentToValtry[0]['packages']);
        self::assertSame(['prestashop/prestashop', 'prestashop/ps_checkout'], $names);
        $raw = (string) json_encode($net->sentToValtry);
        self::assertStringNotContainsString('4.0.0', $raw);
        self::assertStringNotContainsString('8.1.7', $raw);
        self::assertStringNotContainsString('advancedpopupcreator', $raw, 'third-party module names go nowhere near Valtry');
    }

    public function testAFreshInstallOnEitherPathAnnouncesTheSameThings(): void
    {
        $found = [];
        foreach (['public', 'valtry'] as $source) {
            $storage = new FakeStorage();
            [$checker, $notifier] = $this->checker(new FakeNetwork(), $storage, $source);
            $outcome = $checker->run();
            $found[$source] = array_map(static fn ($f): string => $f->package . ' ' . ($f->isExploited() ? 'exploited' : 'open'), $outcome->changes->new);
            self::assertCount(1, $notifier->sent);
        }

        self::assertEquals($found['public'], $found['valtry']);
        self::assertSame(['advancedpopupcreator exploited', 'prestashop/ps_checkout open'], $found['valtry']);
    }

    public function testNotesAndModuleFlagsComeThroughTheCore(): void
    {
        [$checker] = $this->checker(new FakeNetwork(), new FakeStorage(), 'valtry');

        $report = $checker->run(true)->report;

        $popup = array_values(array_filter($report->findings, static fn ($f): bool => $f->ecosystem === Ecosystem::Extension))[0];
        self::assertFalse($popup->metadata['active'], 'a disabled module says so');
        self::assertTrue($popup->metadata['installed']);
        self::assertCount(1, $report->notes, 'the ps_checkout advisory whose versions are ambiguous is a note, not a finding');
        self::assertSame('ps_checkout', $report->notes[0]->package);
        self::assertSame(['ps_checkout: ' . $report->notes[0]->message], Checker::noteLines($report));
    }
}
