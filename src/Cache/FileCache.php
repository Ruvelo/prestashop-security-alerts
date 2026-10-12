<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Cache;

use Psr\SimpleCache\CacheInterface;

/**
 * A PSR-16 cache in a directory (PrestaShop's var/cache), cleared by "Clear cache".
 *
 * Parameters are deliberately untyped: PrestaShop's own Symfony may load an older
 * psr/simple-cache (1.x, untyped) than the one this module was built against (3.x),
 * and an untyped parameter is valid against both.
 */
final class FileCache implements CacheInterface
{
    public function __construct(private readonly string $directory)
    {
    }

    public function get($key, $default = null): mixed
    {
        $entry = $this->read((string) $key);

        return $entry === null ? $default : $entry['value'];
    }

    public function set($key, $value, $ttl = null): bool
    {
        if (!is_dir($this->directory) && !@mkdir($this->directory, 0775, true) && !is_dir($this->directory)) {
            return false;
        }

        $seconds = $ttl instanceof \DateInterval
            ? (new \DateTimeImmutable())->add($ttl)->getTimestamp() - time()
            : (\is_int($ttl) ? $ttl : 3600);
        $json = json_encode(['expires' => time() + $seconds, 'value' => $value]);

        return $json !== false && @file_put_contents($this->path((string) $key), $json, LOCK_EX) !== false;
    }

    public function delete($key): bool
    {
        @unlink($this->path((string) $key));

        return true;
    }

    public function clear(): bool
    {
        foreach (glob($this->directory . '/*.json') ?: [] as $file) {
            @unlink($file);
        }

        return true;
    }

    public function getMultiple($keys, $default = null): iterable
    {
        $values = [];
        foreach ($keys as $key) {
            $values[$key] = $this->get($key, $default);
        }

        return $values;
    }

    /**
     * @param iterable<string, mixed> $values
     */
    public function setMultiple($values, $ttl = null): bool
    {
        $ok = true;
        foreach ($values as $key => $value) {
            $ok = $this->set((string) $key, $value, $ttl) && $ok;
        }

        return $ok;
    }

    public function deleteMultiple($keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has($key): bool
    {
        return $this->read((string) $key) !== null;
    }

    private function path(string $key): string
    {
        return $this->directory . '/' . sha1($key) . '.json';
    }

    /**
     * @return array{value: mixed}|null
     */
    private function read(string $key): ?array
    {
        $raw = @file_get_contents($this->path($key));
        $entry = \is_string($raw) ? json_decode($raw, true) : null;

        if (!\is_array($entry) || !\array_key_exists('value', $entry) || (int) ($entry['expires'] ?? 0) < time()) {
            return null;
        }

        return ['value' => $entry['value']];
    }
}
