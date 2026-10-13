<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts;

use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Note;
use Ruvelo\SecurityAdvisories\Reconciler;
use Ruvelo\SecurityAdvisories\Report;
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
        $report = $this->checkup->run($fresh);
        $known = $this->storage->known();
        $lastSeen = $this->storage->lastSeen();

        // The core decides what is news, whichever source named the advisory this time.
        $changes = $this->reconciler->reconcile($known, $report, $lastSeen);

        if ($dryRun) {
            return new CheckOutcome($report, $changes, 0, true);
        }

        $next = $this->reconciler->next($known, $report, [], $lastSeen);
        $this->storage->apply($report, $changes, $next, $this->reconciler->lastSeen($lastSeen, $report, $next));
        $this->storage->saveLastCheck([
            'at' => gmdate('Y-m-d H:i:s'),
            'packages' => $report->packages,
            'problems' => $report->problems,
            'notes' => self::noteLines($report),
            'source' => $report->source,
            'sources' => $report->sources,
            'kev_checked' => $report->kevChecked,
            'counts' => $report->counts(),
        ]);

        return new CheckOutcome($report, $changes, $this->settings->isEnabled() ? $this->notify() : 0);
    }

    /**
     * The report's notes as the plain lines the page, the console and the JSON show
     * ("module: advisory title"), the shape 1.0 stored.
     *
     * @return list<string>
     */
    public static function noteLines(Report $report): array
    {
        return array_map(
            static fn (Note $note): string => ($note->package !== null ? $note->package . ': ' : '') . $note->message,
            $report->notes,
        );
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

        $this->storage->markNotified(array_keys($pending));

        return $recipients === [] ? 0 : \count($worthIt);
    }
}
