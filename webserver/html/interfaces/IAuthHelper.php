<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

interface IAuthHelper
{
    public function __construct(ILogger $logger = null);
    public function getAuthHeaders($contentType = null);
    public function getBackendHeaders($contentType = 'application/json');
}