<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\PrestaShop;

use Ruvelo\PrestaShop\SecurityAlerts\Settings;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAdvisories\Severity;

final class ConfigurationSettings implements Settings
{
    public const ENABLED = 'RUVELO_SA_ENABLED';
    public const EMAILS = 'RUVELO_SA_EMAILS';
    public const MIN_SEVERITY = 'RUVELO_SA_MIN_SEVERITY';
    public const SOURCE = 'RUVELO_SA_SOURCE';
    public const CRON_TOKEN = 'RUVELO_SA_CRON_TOKEN';
    public const LAST_CHECK = 'RUVELO_SA_LAST_CHECK';

    public function isEnabled(): bool
    {
        return (bool) \Configuration::get(self::ENABLED);
    }

    public function recipients(): array
    {
        return self::parseEmails((string) \Configuration::get(self::EMAILS));
    }

    public function minimumSeverity(): Severity
    {
        return self::parseSeverity((string) \Configuration::get(self::MIN_SEVERITY));
    }

    /**
     * @return list<string>
     */
    public static function parseEmails(string $raw): array
    {
        $emails = [];
        foreach (preg_split('/[\s,;]+/', $raw) ?: [] as $candidate) {
            if ($candidate !== '' && filter_var($candidate, FILTER_VALIDATE_EMAIL) !== false) {
                $emails[strtolower($candidate)] ??= $candidate;
            }
        }

        return array_values($emails);
    }

    public static function parseSeverity(string $raw): Severity
    {
        $severity = Severity::tryFrom($raw);

        return $severity === null || $severity === Severity::NotRated ? Severity::Medium : $severity;
    }

    /**
     * The advisory source setting: "valtry" (the default, also when nothing is saved,
     * as on a shop upgraded from 1.0) or "public". RUVELO_ADVISORIES_SOURCE=public in
     * the server's environment overrides it; Scanner::source() applies that.
     */
    public static function source(): string
    {
        return self::parseSource((string) \Configuration::get(self::SOURCE));
    }

    public static function parseSource(string $raw): string
    {
        return strtolower(trim($raw)) === Scanner::SOURCE_PUBLIC ? Scanner::SOURCE_PUBLIC : Scanner::SOURCE_VALTRY;
    }

    public static function token(): string
    {
        $token = (string) \Configuration::get(self::CRON_TOKEN);
        if ($token === '') {
            $token = bin2hex(random_bytes(16));
            \Configuration::updateGlobalValue(self::CRON_TOKEN, $token);
        }

        return $token;
    }
}
