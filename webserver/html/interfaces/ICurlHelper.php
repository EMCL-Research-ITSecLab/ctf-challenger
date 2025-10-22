<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

interface ICurlHelper
{
    public function makeCurlRequest($endpoint, $method = 'GET', $headers = [], $postFields = null);
    public function makeBackendRequest($endpoint, $method = 'GET', $headers = [], $postFields = null);
}