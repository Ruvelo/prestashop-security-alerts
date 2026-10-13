<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Tests\Support;

use Ruvelo\PrestaShop\SecurityAlerts\Settings;
use Ruvelo\SecurityAdvisories\Severity;

final class FakeSettings implements Settings
{
    /**
     * @param list<string> $recipients
     */
    public function __construct(
        private readonly bool $enabled = true,
        private readonly array $recipients = ['owner@example.test'],
        private readonly Severity $minimum = Severity::Medium,
    ) {
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function recipients(): array
    {
        return $this->recipients;
    }

    public function minimumSeverity(): Severity
    {
        return $this->minimum;
    }
}
