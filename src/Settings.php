<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts;

use Ruvelo\SecurityAdvisories\Severity;

/**
 * What the shop owner configured. The PrestaShop implementation reads Configuration.
 */
interface Settings
{
    public function isEnabled(): bool;

    /**
     * @return list<string> Valid addresses only
     */
    public function recipients(): array;

    public function minimumSeverity(): Severity;
}
