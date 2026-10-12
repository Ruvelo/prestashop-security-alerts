<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts;

use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Reconciler;
use Ruvelo\SecurityAdvisories\Severity;

/**
 * One full check: scan, store what changed, tell the people who asked to be told.
 */
final class Checker
{
    public function __construct(
        private readonly Checkup $checkup,
        private readonly Storage $storage,
        private readonly Settings $settings,
        private readonly Notifier $notifier,
        private readonly Reconciler $reconciler = new Reconciler(),
    ) {
    }

    /**
     * @param bool $dryRun Only report: store nothing, send nothing
     * @param bool $fresh Skip the response cache
     */
    public function run(bool $dryRun = false, bool $fresh = false): CheckOutcome
    {
        ['report' => $report, 'notes' => $notes] = $this->checkup->run($fresh);
        $changes = $this->reconciler->reconcile($this->storage->known(), $report);

        if ($dryRun) {
            return new CheckOutcome($report, $changes, 0, $notes, true);
        }

        $this->storage->apply($report, $changes);
        $this->storage->saveLastCheck([
            'at' => gmdate('Y-m-d H:i:s'),
            'packages' => $report->packages,
            'problems' => $report->problems,
            'notes' => $notes,
            'kev_checked' => $report->kevChecked,
            'counts' => $report->counts(),
        ]);

        return new CheckOutcome($report, $changes, $this->settings->isEnabled() ? $this->notify() : 0, $notes);
    }

    /**
     * Mails what nobody was told about yet. Exploited findings always go; the rest
     * only when they reach the minimum severity (a finding with no rating counts as
     * high: it is mostly an old advisory from before ratings). A mail that fails
     * leaves the findings pending for the next check.
     */
    private function notify(): int
    {
        $pending = $this->storage->pending();
        if ($pending === []) {
            return 0;
        }

        $recipients = $this->settings->recipients();
        $minimum = $this->settings->minimumSeverity();
        $worthIt = array_values(array_filter(
            $pending,
            static fn (Finding $f): bool => $f->isExploited() || ($f->severity === Severity::NotRated ? Severity::High : $f->severity)->atLeast($minimum),
        ));

        if ($recipients !== [] && $worthIt !== [] && !$this->notifier->send($recipients, $worthIt)) {
            return 0;
        }

        $this->storage->markNotified(array_map(static fn (Finding $f): string => $f->key(), $pending));

        return $recipients === [] ? 0 : \count($worthIt);
    }
}
