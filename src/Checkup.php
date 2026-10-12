<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts;

use Ruvelo\PrestaShop\SecurityAlerts\Sources\FriendsOfPrestaSource;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Scanner;

/**
 * The scanner, plus the one thing it can't carry: the notes the Friends of Presta
 * source leaves about advisories it couldn't read.
 */
final class Checkup
{
    public function __construct(
        private readonly Scanner $scanner,
        private readonly FriendsOfPrestaSource $friends,
    ) {
    }

    /**
     * @return array{report: Report, notes: list<string>}
     */
    public function run(bool $fresh = false): array
    {
        $report = $this->scanner->scan($fresh);

        return ['report' => Dedupe::report($report), 'notes' => $this->friends->unreadable()];
    }
}
