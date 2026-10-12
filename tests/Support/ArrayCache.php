<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Tests\Support;

use Psr\SimpleCache\CacheInterface;

final class ArrayCache implements CacheInterface
{
    /** @var array<string, mixed> */
    public array $items = [];

    public function get($key, $default = null): mixed
    {
        return $this->items[$key] ?? $default;
    }

    public function set($key, $value, $ttl = null): bool
    {
        $this->items[$key] = $value;

        return true;
    }

    public function delete($key): bool
    {
        unset($this->items[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    public function getMultiple($keys, $default = null): iterable
    {
        return [];
    }

    /**
     * @param iterable<string, mixed> $values
     */
    public function setMultiple($values, $ttl = null): bool
    {
        return true;
    }

    public function deleteMultiple($keys): bool
    {
        return true;
    }

    public function has($key): bool
    {
        return isset($this->items[$key]);
    }
}
