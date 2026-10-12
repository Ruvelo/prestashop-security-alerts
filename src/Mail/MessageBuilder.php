<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Mail;

use Ruvelo\SecurityAdvisories\Finding;

/**
 * The words of the alert, as a subject, an HTML list and a plain list.
 * The mail names the shop's own findings and links to the advisories; nothing else.
 */
final class MessageBuilder
{
    /**
     * @param list<Finding> $findings Exploited first
     */
    public static function subject(array $findings, string $shop): string
    {
        $exploited = \count(array_filter($findings, static fn (Finding $f): bool => $f->isExploited()));

        return $exploited > 0
            ? sprintf('[%s] Exploited security flaw in your shop: patch now (%d exploited, %d in all)', $shop, $exploited, \count($findings))
            : sprintf('[%s] %d new security %s in your shop', $shop, \count($findings), \count($findings) === 1 ? 'advisory' : 'advisories');
    }

    /**
     * @param list<Finding> $findings
     */
    public static function html(array $findings): string
    {
        $rows = '';
        foreach ($findings as $f) {
            $title = self::e($f->title);
            $title = $f->link !== null && preg_match('#^https://#', $f->link) === 1
                ? '<a href="' . self::e($f->link) . '">' . $title . '</a>'
                : $title;
            $badge = $f->isExploited() ? '<strong style="color:#b3261e">EXPLOITED, patch now</strong> &middot; ' : '';
            $rows .= '<li style="margin:0 0 14px">'
                . $badge . '<strong>' . self::e($f->package) . '</strong> ' . self::e($f->installed)
                . '<br>' . $title
                . '<br><span style="color:#666">' . self::e(self::meta($f)) . '</span></li>';
        }

        return '<ul style="padding-left:18px">' . $rows . '</ul>';
    }

    /**
     * @param list<Finding> $findings
     */
    public static function text(array $findings): string
    {
        $lines = [];
        foreach ($findings as $f) {
            $lines[] = ($f->isExploited() ? '[EXPLOITED, PATCH NOW] ' : '') . "{$f->package} {$f->installed}: {$f->title}\n    " . self::meta($f) . ($f->link !== null ? "\n    {$f->link}" : '');
        }

        return implode("\n\n", $lines);
    }

    public static function meta(Finding $f): string
    {
        return implode(' | ', array_filter([
            $f->severity->label(),
            $f->cve,
            $f->fixedIn !== null ? 'Fixed in ' . ltrim($f->fixedIn, '>') . ($f->fixedIn[0] === '>' ? ' or later' : '') : 'No fixed version known',
        ]));
    }

    private static function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
