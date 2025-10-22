<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class Server implements IServer
{
    public function offsetExists(mixed $offset): bool
    {
        return isset($_SERVER[$offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $_SERVER[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $_SERVER[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($_SERVER[$offset]);
    }

    public function getIterator(): Traversable
    {
        return new ArrayIterator($_SERVER);
    }

    public function count(): int
    {
        return count($_SERVER);
    }

    public function all(): array
    {
        return $_SERVER;
    }

    public function clear(): void
    {
        $_SERVER = [];
    }
}
