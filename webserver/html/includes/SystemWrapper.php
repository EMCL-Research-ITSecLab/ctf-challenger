<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class SystemWrapper implements ISystem
{
    public function file_exists(string $filename): bool
    {
        return file_exists($filename);
    }

    public function mkdir(string $pathname, int $mode = 0777, bool $recursive = false, $context = null): bool
    {
        if ($context === null) {
            return mkdir($pathname, $mode, $recursive);
        } else {
            return mkdir($pathname, $mode, $recursive, $context);
        }
    }

    public function file_put_contents(string $filename, mixed $data, int $flags = 0, $context = null): int|false
    {
        if ($context === null) {
            return file_put_contents($filename, $data, $flags);
        } else {
            return file_put_contents($filename, $data, $flags, $context);
        }
    }

    public function file_get_contents(string $filename, bool $use_include_path = false, $context = null, int $offset = 0, ?int $length = null): string|false
    {
        if ($context === null) {
            return $length === null
                ? file_get_contents($filename, $use_include_path, null, $offset)
                : file_get_contents($filename, $use_include_path, null, $offset, $length);
        } else {
            return $length === null
                ? file_get_contents($filename, $use_include_path, $context, $offset)
                : file_get_contents($filename, $use_include_path, $context, $offset, $length);
        }
    }

    public function pathinfo(string $path, int $flags = PATHINFO_DIRNAME | PATHINFO_BASENAME | PATHINFO_EXTENSION | PATHINFO_FILENAME): array|string
    {
        return pathinfo($path, $flags);
    }

    public function chmod(string $filename, int $permissions): bool
    {
        return chmod($filename, $permissions);
    }

    public function unlink(string $filename): bool
    {
        return unlink($filename);
    }

    public function is_dir(string $filename): bool
    {
        return is_dir($filename);
    }

    public function is_readable(string $filename): bool
    {
        return is_readable($filename);
    }

    public function fopen(string $filename, string $mode, bool $use_include_path = false, $context = null)
    {
        if ($context === null) {
            return fopen($filename, $mode, $use_include_path);
        } else {
            return fopen($filename, $mode, $use_include_path, $context);
        }
    }

    public function fseek($stream, int $offset, int $whence = SEEK_SET): int
    {
        return fseek($stream, $offset, $whence);
    }

    public function fclose($stream): bool
    {
        return fclose($stream);
    }

    public function fwrite($stream, string $data, ?int $length = null): int|false
    {
        if ($length === null) {
            return fwrite($stream, $data);
        } else {
            return fwrite($stream, $data, $length);
        }
    }

    public function glob(string $pattern, int $flags = 0): array|false
    {
        return glob($pattern, $flags);
    }

    public function sys_get_temp_dir(): string
    {
        return sys_get_temp_dir();
    }

    public function time(): int
    {
        return time();
    }

    public function date(string $format, ?int $timestamp = null): string
    {
        if ($timestamp === null) {
            return date($format);
        } else {
            return date($format, $timestamp);
        }
    }

    public function system(string $command, &$return_code = null): false|string
    {
        if ($return_code === null) {
            return system($command);
        }

        return system($command, $return_code);
    }

    public function setcookie(string $name, string $value = "", int|array $expires_or_options = 0, string $path = "", string $domain = "", bool $secure = false, bool $httponly = false): bool
    {
        if(is_array($expires_or_options)) {
            return setcookie($name, $value, $expires_or_options);
        } else {
            return setcookie($name, $value, $expires_or_options, $path, $domain, $secure, $httponly);
        }
    }

    public function ignore_user_abort(?bool $value): int
    {
        if ($value === null) {
            return ignore_user_abort();
        } else {
            return ignore_user_abort($value);
        }
    }

    public function move_uploaded_file(string $from, string $to): bool
    {
        return move_uploaded_file($from, $to);
    }

    public function connection_aborted(): int
    {
        return connection_aborted();
    }
}
