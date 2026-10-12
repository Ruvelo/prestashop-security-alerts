<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\PrestaShop;

use Ruvelo\PrestaShop\SecurityAlerts\FindingCodec;
use Ruvelo\PrestaShop\SecurityAlerts\Storage;
use Ruvelo\SecurityAdvisories\Changes;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Report;

/**
 * Seen findings in the `ruvelo_securityalerts_finding` table.
 */
final class DbStorage implements Storage
{
    public const TABLE = 'ruvelo_securityalerts_finding';

    public function known(): array
    {
        $known = [];
        foreach ($this->rows('SELECT finding_key, exploited FROM `' . $this->table() . '`') as $row) {
            $known[(string) $row['finding_key']] = (bool) (int) $row['exploited'];
        }

        return $known;
    }

    public function apply(Report $report, Changes $changes): void
    {
        $db = \Db::getInstance();
        $flipped = array_fill_keys(array_map(static fn (Finding $f): string => $f->key(), $changes->exploited), true);
        $known = $this->known();

        foreach ($report->findings as $finding) {
            $key = $finding->key();
            $data = json_encode($finding->toArray(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $exploited = $finding->isExploited() || ($known[$key] ?? false);

            if (\array_key_exists($key, $known)) {
                // A finding stays "exploited" once it was: if CISA's feed was down this time, keep the stored details.
                $fields = ($known[$key] && !$finding->isExploited()) ? [] : ['data' => pSQL((string) $data, true)];
                $db->update(self::TABLE, $fields + [
                    'exploited' => (int) $exploited,
                ] + (isset($flipped[$key]) ? ['notified' => 0] : []), "finding_key = '" . pSQL($key) . "'");
            } else {
                $db->insert(self::TABLE, [
                    'finding_key' => pSQL($key),
                    'data' => pSQL((string) $data, true),
                    'exploited' => (int) $exploited,
                    'notified' => 0,
                    'date_add' => date('Y-m-d H:i:s'),
                ]);
            }
        }

        foreach ($changes->resolved as $key) {
            $db->delete(self::TABLE, "finding_key = '" . pSQL($key) . "'");
        }
    }

    public function pending(): array
    {
        return $this->decode($this->rows('SELECT data, exploited FROM `' . $this->table() . '` WHERE notified = 0'));
    }

    public function markNotified(array $keys): void
    {
        foreach ($keys as $key) {
            \Db::getInstance()->update(self::TABLE, ['notified' => 1], "finding_key = '" . pSQL($key) . "'");
        }
    }

    public function all(): array
    {
        return $this->decode($this->rows('SELECT data, exploited FROM `' . $this->table() . '`'));
    }

    public function lastCheck(): ?array
    {
        $raw = \Configuration::get(ConfigurationSettings::LAST_CHECK);
        $meta = \is_string($raw) ? json_decode($raw, true) : null;

        return \is_array($meta) ? $meta : null;
    }

    public function saveLastCheck(array $meta): void
    {
        \Configuration::updateGlobalValue(ConfigurationSettings::LAST_CHECK, json_encode($meta));
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function rows(string $sql): array
    {
        $rows = \Db::getInstance()->executeS($sql);

        return \is_array($rows) ? array_values($rows) : [];
    }

    /**
     * @param list<array<string, mixed>> $rows
     *
     * @return list<Finding>
     */
    private function decode(array $rows): array
    {
        $findings = [];
        foreach ($rows as $row) {
            $data = json_decode((string) $row['data'], true);
            $finding = \is_array($data) ? FindingCodec::decode($data) : null;
            if ($finding === null) {
                continue;
            }
            $findings[] = $finding;
        }
        usort($findings, Finding::compare(...));

        return $findings;
    }

    private function table(): string
    {
        return _DB_PREFIX_ . self::TABLE;
    }
}
