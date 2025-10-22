<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class MockSession implements ISession
{
    private array $attributes = [];
    private string $sessionId = '';
    private string $sessionName = 'MOCKSESSID';
    private string $moduleName = 'files';
    private bool $started = false;

    private array $cookieParams = [
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => false,
        'httponly' => true,
    ];

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->attributes[$offset]);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $this->attributes[$offset] ?? null;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->attributes[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->attributes[$offset]);
    }

    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->attributes);
    }

    public function count(): int
    {
        return count($this->attributes);
    }

    public function all(): array
    {
        return $this->attributes;
    }

    public function clear(): void
    {
        $this->attributes = [];
    }

    public function abort(): bool
    {
        $this->started = false;
        return true;
    }

    public function cache_expire(?int $value = null): int|false
    {
        return 180;
    }

    public function cache_limiter(?string $value = null): string|false
    {
        return 'nocache';
    }

    public function commit(): bool
    {
        return true;
    }

    public function create_id(string $prefix = ''): string|false
    {
        return $prefix . bin2hex(random_bytes(8));
    }

    public function decode(string $data): bool
    {
        $this->attributes = unserialize($data) ?: [];
        return true;
    }

    public function destroy(): bool
    {
        $this->attributes = [];
        $this->sessionId = '';
        $this->started = false;
        return true;
    }

    public function encode(): string|false
    {
        return serialize($this->attributes);
    }

    public function gc(): int|false
    {
        return 0;
    }

    public function get_cookie_params(): array
    {
        return $this->cookieParams;
    }

    public function id(?string $id = null): false|string
    {
        if ($id !== null) {
            $this->sessionId = $id;
        }
        return $this->sessionId;
    }

    public function module_name(?string $module = null): string|false
    {
        if ($module !== null) {
            $this->moduleName = $module;
        }
        return $this->moduleName;
    }

    public function name(?string $name = null): false|string
    {
        if ($name !== null) {
            $this->sessionName = $name;
        }
        return $this->sessionName;
    }

    public function regenerate_id(bool $deleteOldSession = true): bool
    {
        $this->sessionId = bin2hex(random_bytes(16));
        return true;
    }

    public function register_shutdown(): void
    { /* noop in mock */
    }

    public function reset(): bool
    {
        $this->attributes = [];
        return true;
    }

    public function save_path(?string $path = null): string|false
    {
        return '/tmp';
    }

    public function set_cookie_params(array|int $lifetime_or_options, ?string $path = null, ?string $domain = null, ?bool $secure = null, ?bool $httponly = null): bool
    {
        if (is_array($lifetime_or_options)) {
            // PHP 7.3+ style with options array
            $this->cookieParams = array_merge($this->cookieParams, $lifetime_or_options);
        } else {
            // Legacy style with individual args
            $this->cookieParams['lifetime'] = $lifetime_or_options;
            if ($path !== null) $this->cookieParams['path'] = $path;
            if ($domain !== null) $this->cookieParams['domain'] = $domain;
            if ($secure !== null) $this->cookieParams['secure'] = $secure;
            if ($httponly !== null) $this->cookieParams['httponly'] = $httponly;
        }

        return true;
    }

    public function set_save_handler(SessionHandlerInterface $handler, bool $register_shutdown = true): bool
    {
        return true;
    }

    public function start(array $options = []): bool
    {
        $this->started = true;
        if (!$this->sessionId) {
            $this->sessionId = bin2hex(random_bytes(16));
        }
        return true;
    }

    public function status(): int
    {
        return $this->started ? PHP_SESSION_ACTIVE : PHP_SESSION_NONE;
    }

    public function unset(): bool
    {
        $this->attributes = [];
        return true;
    }

    public function write_close(): bool
    {
        $this->started = false;
        return true;
    }
}