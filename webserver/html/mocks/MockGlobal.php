<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

abstract class MockGlobal implements IGlobal
{
    private array $data;

    public function __construct(
        array $data = []
    )
    {
        $this->data = $data;
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->data[$offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $this->data[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->data[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->data[$offset]);
    }

    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->data);
    }

    public function count(): int
    {
        return count($this->data);
    }

    public function all(): array
    {
        return $this->data;
    }

    public function clear(): void
    {
        $this->data = [];
    }
}