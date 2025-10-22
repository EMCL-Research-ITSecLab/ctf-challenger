<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class MockSystem implements ISystem
{
    private array $files = [];         // filename => content
    private array $directories = [];   // list of directories
    private array $cookies = [];       // name => value
    private int $currentTime;          // mock time

    public function __construct()
    {
        $this->directories['/'] = true; // root dir
        $this->currentTime = time();
    }

    public function file_exists(string $filename): bool
    {
        return isset($this->files[$filename]) || isset($this->directories[$filename]);
    }

    public function mkdir(string $pathname, int $mode = 0777, bool $recursive = false, $context = null): bool
    {
        if ($this->file_exists($pathname)) {
            return false;
        }
        $this->directories[$pathname] = true;
        return true;
    }

    public function file_put_contents(string $filename, mixed $data, int $flags = 0, $context = null): int|false
    {
        $this->files[$filename] = (string) $data;
        return strlen((string) $data);
    }

    public function file_get_contents(
        string $filename,
        bool $use_include_path = false,
               $context = null,
        int $offset = 0,
        ?int $length = null
    ): string|false {
        if (!isset($this->files[$filename])) {
            return false;
        }
        $content = substr($this->files[$filename], $offset, $length ?? null);
        return $content == false ? '' : $content;
    }

    public function pathinfo(
        string $path,
        int $flags = PATHINFO_DIRNAME | PATHINFO_BASENAME | PATHINFO_EXTENSION | PATHINFO_FILENAME
    ): array|string {
        return pathinfo($path, $flags);
    }

    public function chmod(string $filename, int $permissions): bool
    {
        return $this->file_exists($filename);
    }

    public function unlink(string $filename): bool
    {
        if (isset($this->files[$filename])) {
            unset($this->files[$filename]);
            return true;
        }
        return false;
    }

    public function is_dir(string $filename): bool
    {
        return isset($this->directories[$filename]);
    }

    public function is_readable(string $filename): bool
    {
        return $this->file_exists($filename);
    }

    public function fopen(string $filename, string $mode, bool $use_include_path = false, $context = null)
    {
        if ($mode[0] === 'r' && !isset($this->files[$filename])) {
            return false;
        }
        if (!isset($this->files[$filename])) {
            $this->files[$filename] = '';
        }
        return fopen('php://memory', $mode);
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
        return fwrite($stream, $data, $length ?? strlen($data));
    }

    public function glob(string $pattern, int $flags = 0): array|false
    {
        $matches = preg_grep('/^' . str_replace('\*', '.*', preg_quote($pattern, '/')) . '$/', array_keys($this->files));
        return $matches ? array_values($matches) : false;
    }

    public function sys_get_temp_dir(): string
    {
        return '/tmp';
    }

    public function time(): int
    {
        return $this->currentTime;
    }

    public function date(string $format, ?int $timestamp = null): string
    {
        return date($format, $timestamp ?? $this->currentTime);
    }

    public function system(string $command, &$return_code = null): false|string
    {
        $return_code = 0;
        return "mocked: $command";
    }

    public function setcookie(
        string $name,
        string $value = "",
        int|array $expires_or_options = 0,
        string $path = "",
        string $domain = "",
        bool $secure = false,
        bool $httponly = false
    ): bool {
        $this->cookies[$name] = [
            'value' => $value,
            'expires' => is_int($expires_or_options) ? $expires_or_options : 0,
            'path' => $path,
            'domain' => $domain,
            'secure' => $secure,
            'httponly' => $httponly,
        ];
        return true;
    }

    // Helper for tests
    public function getCookies(): array
    {
        return $this->cookies;
    }

    public function getFiles(): array
    {
        return $this->files;
    }

    public function getDirectories(): array
    {
        return array_keys($this->directories);
    }

    public function setTime(int $timestamp): void
    {
        $this->currentTime = $timestamp;
    }

    public function ignore_user_abort(?bool $value): int
    {
        return 0;
    }

    public function move_uploaded_file(string $from, string $to, bool $simulateSuccess = true): bool
    {
        return $simulateSuccess;
    }

    public function connection_aborted(): int
    {
        return 0;
    }
}
