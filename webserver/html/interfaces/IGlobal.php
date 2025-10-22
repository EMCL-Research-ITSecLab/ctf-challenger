<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

interface IGlobal extends ArrayAccess, IteratorAggregate, Countable
{
    public function all(): array;
    public function clear(): void;
}
