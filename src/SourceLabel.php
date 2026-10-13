<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts;

/**
 * Where the advisories for PrestaShop and its own modules came from, in words.
 * (Third-party modules always come from Friends of Presta, whatever this says.)
 */
final class SourceLabel
{
    public static function of(string $source): string
    {
        return match ($source) {
            'valtry' => 'Valtry (signed answers)',
            'mixed' => 'Valtry and the public feeds',
            default => 'public feeds (Packagist, CISA)',
        };
    }
}
