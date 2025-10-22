<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

interface ILogger
{
    public function logError($message): void;
    public function logInfo($message): void;
    public function logDebug($message): void;
    public function logWarning($message): void;
    public function anonymizeIp(string $ip): string;
}