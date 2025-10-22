<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class Get implements IGet
{
    public function offsetExists(mixed $offset): bool
    {
        return isset($_GET[$offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $_GET[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $_GET[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($_GET[$offset]);
    }

    public function getIterator(): Traversable
    {
        return new ArrayIterator($_GET);
    }

    public function count(): int
    {
        return count($_GET);
    }

    public function all(): array
    {
        return $_GET;
    }

    public function clear(): void
    {
        $_GET = [];
    }
}