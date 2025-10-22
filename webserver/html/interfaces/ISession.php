<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

interface ISession extends IGlobal
{
    public function abort(): bool;
    public function cache_expire(?int $value = null): int|false;
    public function cache_limiter(?string $value = null): string|false;
    public function commit(): bool;
    public function create_id(string $prefix = ''): string|false;
    public function decode(string $data): bool;
    public function destroy(): bool;
    public function encode(): string|false;
    public function gc(): int|false;
    public function get_cookie_params(): array;
    public function id(?string $id = null): false|string;
    public function module_name(?string $module = null): string|false;
    public function name(?string $name = null): false|string;
    public function regenerate_id(bool $deleteOldSession = true): bool;
    public function register_shutdown(): void;
    public function reset(): bool;
    public function save_path(?string $path = null): string|false;
    public function set_cookie_params(array|int $lifetime_or_options, ?string $path = null, ?string $domain = null, ?bool $secure = null, ?bool $httponly = null): bool;
    public function set_save_handler(SessionHandlerInterface $handler, bool $register_shutdown = true): bool;
    public function start(array $options = []): bool;
    public function status(): int;
    public function unset(): bool;
    public function write_close(): bool;
}
