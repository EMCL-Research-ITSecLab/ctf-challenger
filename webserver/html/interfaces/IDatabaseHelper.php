<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

interface IDatabaseHelper
{
    public function __construct(ILogger $logger = null);
    public function getPDO(): PDO;
}