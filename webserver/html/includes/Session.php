<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class Session implements ISession
{
    public function offsetExists(mixed $offset): bool
    {
        return isset($_SESSION[$offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $_SESSION[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $_SESSION[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($_SESSION[$offset]);
    }

    public function getIterator(): Traversable
    {
        return new ArrayIterator($_SESSION);
    }

    public function count(): int
    {
        return count($_SESSION);
    }

    public function all(): array
    {
        return $_SESSION;
    }

    public function clear(): void
    {
        $_SESSION = [];
    }

    public function abort(): bool
    {
        return session_abort();
    }

    public function cache_expire(?int $value = null): int|false
    {
        return $value === null ? session_cache_expire() : session_cache_expire($value);
    }

    public function cache_limiter(?string $value = null): string|false
    {
        return $value === null ? session_cache_limiter() : session_cache_limiter($value);
    }

    public function commit(): bool
    {
        return session_commit();
    }

    public function create_id(string $prefix = ''): string|false
    {
        return session_create_id($prefix);
    }

    public function decode(string $data): bool
    {
        return session_decode($data);
    }

    public function destroy(): bool
    {
        return session_destroy();
    }

    public function encode(): string|false
    {
        return session_encode();
    }

    public function gc(): int|false
    {
        return session_gc();
    }

    public function get_cookie_params(): array
    {
        return session_get_cookie_params();
    }

    public function id(?string $id = null): false|string
    {
        return $id === null ? session_id() : session_id($id);
    }

    public function module_name(?string $module = null): string|false
    {
        return $module === null ? session_module_name() : session_module_name($module);
    }

    public function name(?string $name = null): false|string
    {
        return $name === null ? session_name() : session_name($name);
    }

    public function regenerate_id(bool $deleteOldSession = true): bool
    {
        return session_regenerate_id($deleteOldSession);
    }

    public function register_shutdown(): void
    {
        session_register_shutdown();
    }

    public function reset(): bool
    {
        return session_reset();
    }

    public function save_path(?string $path = null): string|false
    {
        return $path === null ? session_save_path() : session_save_path($path);
    }

    public function set_cookie_params(array|int $lifetime_or_options, ?string $path = null, ?string $domain = null, ?bool $secure = null, ?bool $httponly = null): bool
    {
        return session_set_cookie_params($lifetime_or_options, $path, $domain, $secure, $httponly);
    }

    public function set_save_handler(SessionHandlerInterface $handler, bool $register_shutdown = true): bool
    {
        return session_set_save_handler($handler, $register_shutdown);
    }

    public function start(array $options = []): bool
    {
        return session_start($options);
    }

    public function status(): int
    {
        return session_status();
    }

    public function unset(): bool
    {
        return session_unset();
    }

    public function write_close(): bool
    {
        return session_write_close();
    }
}