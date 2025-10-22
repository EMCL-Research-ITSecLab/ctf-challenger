<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

interface ISystem
{
    public function file_exists(string $filename): bool;

    public function mkdir(string $pathname, int $mode = 0777, bool $recursive = false, $context = null): bool;

    public function file_put_contents(string $filename, mixed $data, int $flags = 0, $context = null): int|false;

    public function file_get_contents(string $filename, bool $use_include_path = false, $context = null, int $offset = 0, ?int $length = null): string|false;

    public function pathinfo(string $path, int $flags = PATHINFO_DIRNAME | PATHINFO_BASENAME | PATHINFO_EXTENSION | PATHINFO_FILENAME): array|string;

    public function chmod(string $filename, int $permissions): bool;

    public function unlink(string $filename): bool;

    public function is_dir(string $filename): bool;

    public function is_readable(string $filename): bool;

    public function fopen(string $filename, string $mode, bool $use_include_path = false, $context = null);

    public function fseek($stream, int $offset, int $whence = SEEK_SET): int;

    public function fclose($stream): bool;

    public function fwrite($stream, string $data, ?int $length = null): int|false;

    public function glob(string $pattern, int $flags = 0): array|false;

    public function sys_get_temp_dir(): string;

    public function time(): int;

    public function date(string $format, ?int $timestamp = null): string;

    public function system(string $command, &$return_code = null): false|string;

    public function setcookie(string $name, string $value = "", int|array $expires_or_options = 0, string $path = "", string $domain = "", bool $secure = false, bool $httponly = false): bool;

    public function ignore_user_abort(?bool $value): int;

    public function move_uploaded_file(string $from, string $to): bool;

    public function connection_aborted(): int;

}
