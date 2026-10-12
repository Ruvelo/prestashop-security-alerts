<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts;

use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\KevEntry;
use Ruvelo\SecurityAdvisories\Severity;

/**
 * Finding <-> the array stored in the table (Finding::toArray()).
 */
final class FindingCodec
{
    /**
     * @param array<mixed> $data
     */
    public static function decode(array $data): ?Finding
    {
        $ecosystem = Ecosystem::tryFrom((string) ($data['ecosystem'] ?? ''));
        $package = $data['package'] ?? null;
        $installed = $data['installed'] ?? null;
        $id = $data['advisory_id'] ?? null;

        if ($ecosystem === null || !\is_string($package) || !\is_string($installed) || !\is_string($id)) {
            return null;
        }

        $str = static fn (string $key): ?string => isset($data[$key]) && \is_string($data[$key]) ? $data[$key] : null;

        return new Finding(
            ecosystem: $ecosystem,
            package: $package,
            installed: $installed,
            advisoryId: $id,
            title: $str('title') ?? $id,
            severity: Severity::tryFrom((string) ($data['severity'] ?? '')) ?? Severity::NotRated,
            link: $str('link'),
            cve: $str('cve'),
            fixedIn: $str('fixed_in'),
            affectedVersions: $str('affected_versions'),
            reportedAt: $str('reported_at'),
            exploited: \is_array($data['kev'] ?? null) ? KevEntry::fromArray($data['kev']) : null,
        );
    }
}
