<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Tests\Support;

use Ruvelo\PrestaShop\SecurityAlerts\Storage;
use Ruvelo\SecurityAdvisories\Changes;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Report;

final class FakeStorage implements Storage
{
    /** @var array<string, array{data: array<string, mixed>, exploited: bool, notified: bool}> */
    public array $rows = [];
    /** @var array<string, mixed>|null */
    public ?array $meta = null;

    /**
     * @param array<string, mixed> $data A finding's toArray(), of any shape version
     */
    public function seed(array $data, bool $exploited, bool $notified, ?string $key = null): void
    {
        $finding = Finding::fromArray($data);
        $this->rows[$key ?? ($finding?->key() ?? 'invalid')] = ['data' => $data, 'exploited' => $exploited, 'notified' => $notified];
    }

    public function known(): array
    {
        return array_map(static fn (array $r): bool => $r['exploited'], $this->rows);
    }

    public function lastSeen(): array
    {
        return array_map(static fn (array $r): array => $r['data'], $this->rows);
    }

    public function apply(Report $report, Changes $changes, array $next, array $seen): void
    {
        $current = [];
        foreach ($report->findings as $f) {
            $current[$f->key()] = $f;
        }
        $flipped = array_map(static fn (Finding $f): string => $f->key(), $changes->exploited);
        foreach ($next as $key => $exploited) {
            $f = $current[(string) ($seen[$key]['key'] ?? '')] ?? null;
            if ($f === null) {
                continue;
            }
            $old = $this->rows[$key] ?? null;
            $this->rows[$key] = [
                'data' => $f->toArray(),
                'exploited' => $exploited,
                'notified' => $old !== null && !\in_array($f->key(), $flipped, true) && $old['notified'],
            ];
        }
        foreach (array_keys($this->rows) as $key) {
            if (!\array_key_exists($key, $next)) {
                unset($this->rows[$key]);
            }
        }
    }

    public function pending(): array
    {
        return $this->findings(false);
    }

    public function markNotified(array $keys): void
    {
        foreach ($keys as $key) {
            $this->rows[$key]['notified'] = true;
        }
    }

    public function all(): array
    {
        return array_values($this->findings(null));
    }

    public function lastCheck(): ?array
    {
        return $this->meta;
    }

    public function saveLastCheck(array $meta): void
    {
        $this->meta = $meta;
    }

    /**
     * @return array<string, Finding>
     */
    private function findings(?bool $notified): array
    {
        $out = [];
        foreach ($this->rows as $key => $row) {
            $finding = Finding::fromArray($row['data']);
            if ($finding !== null && ($notified === null || $row['notified'] === $notified)) {
                $out[$key] = $finding;
            }
        }

        return $out;
    }
}
