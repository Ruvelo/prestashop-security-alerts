<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts;

use Ruvelo\SecurityAdvisories\Finding;

interface Notifier
{
    /**
     * @param list<string> $recipients
     * @param list<Finding> $findings Exploited first
     *
     * @return bool Whether the mail was handed over
     */
    public function send(array $recipients, array $findings): bool;
}
