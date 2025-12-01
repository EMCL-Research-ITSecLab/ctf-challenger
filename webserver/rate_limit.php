<?php
require_once __DIR__ . '/html/includes/logger.php';

$rateLimitConfig = [
    'signup.php' => ['limit' => 20, 'window' => 1800], // 20 requests per half hour
    'login.php' => ['limit' => 10, 'window' => 900],   // 10 requests per 15 min
    'challenge.php' => ['limit' => 10, 'window' => 300], // 10 requests per 5 min
    'profile.php' => ['limit' => 8, 'window' => 60], // 8 requests per minute
];

$logger = new Logger('rate-limit');
$scriptPath = $_SERVER['SCRIPT_FILENAME'];
$scriptName = basename($scriptPath);
$scriptDir = basename(dirname($scriptPath));
$requestMethod = $_SERVER['REQUEST_METHOD'];
$logger->logDebug("Initialize RateLimiter for: " . $scriptName . ", " . $scriptDir);

$shouldLimit = false;
$config = null;

if ($scriptDir === 'backend' && isset($rateLimitConfig[$scriptName])) {
    if ($requestMethod !== 'GET') {
        $shouldLimit = true;
        $config = $rateLimitConfig[$scriptName];
    }
}

if ($shouldLimit && $config) {

    try {
        $redis = new Redis();
        $redis->connect('/var/run/redis/redis-server.sock');

        $identifier = $_SERVER['REMOTE_ADDR'];
        $key = "rate_limit:{$scriptName}:{$identifier}";

        $current = $redis->get($key);

        if ($current === false) {
            $redis->setex($key, $config['window'], 1);
        } else {
            if ((int)$current >= $config['limit']) {
                $ttl = $redis->ttl($key);

                $logger->logWarning("Rate limit exceeded for {$scriptName} - IP: {$identifier}");

                header('HTTP/1.1 429 Too Many Requests');
                header('Content-Type: application/json');
                header("Retry-After: $ttl");

                echo json_encode([
                    'success' => false,
                    'error' => 'Rate limit exceeded',
                    'message' => "Too many requests. Please try again in " . ceil($ttl / 60) . " minute(s).",
                    'retry_after' => $ttl
                ]);

                $redis->close();
                exit;
            } else {
                $redis->incr($key);
            }
        }

        $remaining = max(0, $config['limit'] - ((int)$current + 1));
        header("X-RateLimit-Limit: {$config['limit']}");
        header("X-RateLimit-Remaining: $remaining");
        header("X-RateLimit-Reset: " . (time() + $redis->ttl($key)));

        $redis->close();

    } catch (Exception $e) {
        $logger->logError("Rate limiting error: " . $e->getMessage());
    }
}
?>