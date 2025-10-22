<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class Post implements IPost
{
    public function offsetExists(mixed $offset): bool
    {
        return isset($_POST[$offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $_POST[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $_POST[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($_POST[$offset]);
    }

    public function getIterator(): Traversable
    {
        return new ArrayIterator($_POST);
    }

    public function count(): int
    {
        return count($_POST);
    }

    public function all(): array
    {
        return $_POST;
    }

    public function clear(): void
    {
        $_POST = [];
    }
}