<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Tests\Support;

use Ruvelo\PrestaShop\SecurityAlerts\Notifier;
use Ruvelo\SecurityAdvisories\Finding;

final class FakeNotifier implements Notifier
{
    /** @var list<list<Finding>> */
    public array $sent = [];
    public bool $ok = true;

    public function send(array $recipients, array $findings): bool
    {
        if ($this->ok) {
            $this->sent[] = $findings;
        }

        return $this->ok;
    }
}

/*
 * Keeps what DbStorage keeps: per stored key, the finding as its toArray() JSON
 * (so a test can seed the shape 1.0 wrote), whether it is exploited, whether
 * somebody was told.
 */
