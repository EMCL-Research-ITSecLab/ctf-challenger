<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class Cookie implements ICookie
{
    public function offsetExists(mixed $offset): bool
    {
        return isset($_COOKIE[$offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $_COOKIE[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $_COOKIE[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($_COOKIE[$offset]);
    }

    public function getIterator(): Traversable
    {
        return new ArrayIterator($_COOKIE);
    }

    public function count(): int
    {
        return count($_COOKIE);
    }

    public function all(): array
    {
        return $_COOKIE;
    }

    public function clear(): void
    {
        $_COOKIE = [];
    }
}