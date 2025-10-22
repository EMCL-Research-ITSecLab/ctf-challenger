<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

interface ISecurityHelper
{
    public function __construct(ILogger $logger = null);
    public function initSecureSession(): void;
    public function addSecurityHeaders(): void;
    public function generateCsrfToken(): string;
    public function validateCsrfToken(string $token): bool;
    public function validateSession(): bool;
    public function validateAdminAccess(PDO $pdo): bool;
}