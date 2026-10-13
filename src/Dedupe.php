<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts;

use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Report;

/**
 * A module PrestaShop ships can be in two sources: Packagist (as prestashop/ps_checkout)
 * and Friends of Presta (as ps_checkout). Where both name the same CVE, Packagist's
 * is kept: its version ranges are exact and the FoP text is free-form.
 */
final class Dedupe
{
    public static function report(Report $report): Report
    {
        $viaPackagist = [];
        foreach ($report->findings as $finding) {
            if ($finding->ecosystem === Ecosystem::Composer && $finding->cve !== null && str_starts_with($finding->package, 'prestashop/')) {
                $viaPackagist[substr($finding->package, 11) . '|' . $finding->cve] = true;
            }
        }

        $kept = array_values(array_filter(
            $report->findings,
            static fn (Finding $f): bool => !($f->ecosystem === Ecosystem::Extension && $f->cve !== null && isset($viaPackagist[$f->package . '|' . $f->cve])),
        ));

        return new Report($kept, $report->packages, $report->checked, $report->problems, $report->kevChecked, $report->checkedAt, $report->sources, $report->unchecked, $report->notes);
    }
}
