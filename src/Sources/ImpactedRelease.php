<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Sources;

/**
 * Reads the "Impacted release" line of a Friends of Presta advisory into a
 * Composer constraint. The line is free text written by people ("<= 4.0.1 (4.0.2
 * fixed the vulnerability)", "All versions", "PS 1.6 : < 1.8.12, PS 1.7 : < 2.0.3"),
 * so this accepts only what it can read with certainty and says "unreadable"
 * (null) for the rest. A wrong guess would be a false alarm or a missed flaw.
 */
final class ImpactedRelease
{
    private const CLAUSE = '/(<=|>=|<|>|=)\s*v?(\d+(?:\.\d+)*(?:[-.]?(?:p|rc|beta|alpha)\d*)?)/i';

    /**
     * @return array{constraint: string, fixed: string|null}|null
     */
    public static function parse(string $line): ?array
    {
        $text = trim(str_replace(['*', '`'], '', $line));
        $fixed = self::fixedVersion($text);

        if (preg_match('/^all\s+versions?\b/i', $text) === 1) {
            return ['constraint' => '*', 'fixed' => $fixed];
        }

        $head = trim(preg_replace('/\([^)]*\)/', ' ', $text) ?? $text);

        if (preg_match_all(self::CLAUSE, $head, $found, PREG_SET_ORDER) < 1) {
            return null;
        }

        $remainder = preg_replace(self::CLAUSE, ' ', $head) ?? $head;
        $remainder = preg_replace('/\b(and|or)\b|[&,\/\s]+/i', '', $remainder) ?? $remainder;
        if ($remainder !== '') {
            return null;
        }

        $ranges = [];
        $current = [];
        $hasUpper = false;
        $hasLower = false;
        foreach ($found as [, $operator, $version]) {
            $isUpper = $operator === '<' || $operator === '<=';
            $isEqual = $operator === '=';

            // A new range starts when this clause can't belong to the one being built.
            if ($current !== [] && ($isEqual || $hasUpper)) {
                // ">= 1.3.0, < 4.4.1, < 5.0.5" could be two lines of releases or one sloppy range: don't guess.
                if ($isUpper && $hasLower) {
                    return null;
                }
                $ranges[] = implode(',', $current);
                $current = [];
                $hasUpper = false;
                $hasLower = false;
            }

            $current[] = $operator . $version;
            $hasUpper = $hasUpper || $isUpper;
            $hasLower = $hasLower || (!$isUpper && !$isEqual);
            if ($isEqual) {
                $ranges[] = implode(',', $current);
                $current = [];
                $hasUpper = false;
                $hasLower = false;
            }
        }
        if ($current !== []) {
            $ranges[] = implode(',', $current);
        }

        // With several ranges, one named fix doesn't say which line it belongs to.
        return ['constraint' => implode('|', $ranges), 'fixed' => \count($ranges) === 1 ? $fixed : null];
    }

    private static function fixedVersion(string $text): ?string
    {
        if (preg_match('/patched versions?\s+v?(\d+(?:\.\d+)*)/i', $text, $m) === 1
            || preg_match('/\(\s*v?(\d+(?:\.\d+)*)\s+(?:fix|fixed|fixes|patched)\b/i', $text, $m) === 1
            || preg_match('/,\s*v?(\d+(?:\.\d+)*)\s+(?:fix|fixed|fixes|patched)\b/i', $text, $m) === 1
        ) {
            return $m[1];
        }

        return null;
    }
}
