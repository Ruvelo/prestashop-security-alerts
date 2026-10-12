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
     * Stores the report: new findings are added as not yet notified, a finding that
     * just became exploited is flagged and not yet notified again, the resolved ones
     * are dropped.
     */
    public function apply(Report $report, Changes $changes): void;

    /**
     * @return list<Finding> Findings nobody was told about yet
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
