<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts;

use Ruvelo\SecurityAdvisories\Changes;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Report;

/**
 * Where seen findings live between checks (a table in PrestaShop).
 */
interface Storage
{
    /**
     * @return array<string, bool> Finding key => whether it was exploited when last seen
     */
    public function known(): array;

    /**
     * The findings as last seen, by the key each was first stored under: what
     * Reconciler::lastSeen() gave, so a finding is still recognised when a
     * different source names its advisory differently.
     *
     * @return array<string, array<string, mixed>>
     */
    public function lastSeen(): array;

    /**
     * Stores the report under the keys Reconciler::next() chose ($next, key =>
     * exploited; $seen is Reconciler::lastSeen()): new findings are added as not yet
     * notified, a finding that just became exploited is flagged and not yet notified
     * again, and every stored key that is no longer in $next is dropped.
     *
     * @param array<string, bool> $next
     * @param array<string, array<string, mixed>> $seen
     */
    public function apply(Report $report, Changes $changes, array $next, array $seen): void;

    /**
     * @return array<string, Finding> Findings nobody was told about yet, by their stored key
     */
    public function pending(): array;

    /**
     * @param list<string> $keys
     */
    public function markNotified(array $keys): void;

    /**
     * @return list<Finding> Everything open, worst first
     */
    public function all(): array;

    /**
     * @return array<string, mixed>|null What the last check recorded
     */
    public function lastCheck(): ?array;

    /**
     * @param array<string, mixed> $meta
     */
    public function saveLastCheck(array $meta): void;
}
