<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';


class Files implements IFiles
{
    public function offsetExists(mixed $offset): bool
    {
        return isset($_FILES[$offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $_FILES[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $_FILES[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($_FILES[$offset]);
    }

    public function getIterator(): Traversable
    {
        return new ArrayIterator($_FILES);
    }

    public function count(): int
    {
        return count($_FILES);
    }

    public function all(): array
    {
        return $_FILES;
    }

    public function clear(): void
    {
        $_FILES = [];
    }
}