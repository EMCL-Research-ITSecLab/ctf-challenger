<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class MockLogger implements ILogger
{
    public function logInfo($message): void
    {
        fwrite(STDERR, print_r($message, true) . "\n");
    }

    public function logError($message): void
    {
        fwrite(STDERR, print_r($message, true) . "\n");
    }

    public function logDebug($message): void
    {
        fwrite(STDERR, print_r($message, true) . "\n");
    }

    public function logWarning($message): void
    {
        fwrite(STDERR, print_r($message, true) . "\n");
    }

    public function anonymizeIp(string $ip): string
    {
        return $ip;
    }
}