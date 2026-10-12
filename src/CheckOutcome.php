<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts;

use Ruvelo\SecurityAdvisories\Changes;
use Ruvelo\SecurityAdvisories\Report;

final readonly class CheckOutcome
{
    /**
     * @param list<string> $notes Advisories about installed modules whose affected versions couldn't be read
     */
    public function __construct(
        public Report $report,
        public Changes $changes,
        public int $emailed,
        public array $notes = [],
        public bool $dryRun = false,
    ) {
    }
}
