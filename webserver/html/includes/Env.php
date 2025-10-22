<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class Env implements IEnv
{
    public function __construct(
        $path = '/var/www',
    )
    {
        $dotenv = Dotenv\Dotenv::createImmutable($path);
        $dotenv->load();
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($_ENV[$offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $_ENV[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $_ENV[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($_ENV[$offset]);
    }

    public function getIterator(): Traversable
    {
        return new ArrayIterator($_ENV);
    }

    public function count(): int
    {
        return count($_ENV);
    }

    public function all(): array
    {
        return $_ENV;
    }

    public function clear(): void
    {
        $_ENV = [];
    }
}
