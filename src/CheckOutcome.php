<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts;

use Ruvelo\SecurityAdvisories\Changes;
use Ruvelo\SecurityAdvisories\Report;

final readonly class CheckOutcome
{
    public function __construct(
        public Report $report,
        public Changes $changes,
        public int $emailed,
        public bool $dryRun = false,
    ) {
    }
}
