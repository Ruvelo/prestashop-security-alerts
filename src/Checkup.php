<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts;

use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Scanner;

/**
 * The scanner, plus the one thing it can't know: that a module PrestaShop ships
 * can be in two sources under two names.
 */
final class Checkup
{
    public function __construct(private readonly Scanner $scanner)
    {
    }

    public function run(bool $fresh = false): Report
    {
        return Dedupe::report($this->scanner->scan($fresh));
    }
}
