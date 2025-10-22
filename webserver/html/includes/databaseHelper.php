<?php
declare(strict_types=1);

use JetBrains\PhpStorm\NoReturn;

require_once __DIR__ . '/../vendor/autoload.php';

class DatabaseHelper implements IDatabaseHelper
{
    private ?PDO $pdoInstance;

    private ILogger $logger;
    private IEnv $env;

    private string $route;

    public function __construct(
        ILogger $logger = null,
        ISystem $system = new SystemWrapper(),
        IEnv $env = new Env()
    )
    {
        $this->route = "/databaseHelper";

        $this->logger = $logger ?? new Logger(route: $this->route, system: $system);
        $this->pdoInstance = null;
        $this->env = $env;
    }
    
    public function getPDO(): PDO
    {
        try {
            if ($this->pdoInstance === null) {
                $this->pdoInstance = $this->createConnection();
                $this->logger->logInfo("Database connection established successfully");
            }
            return $this->pdoInstance;

        } catch (PDOException $e) {
            $this->logger->logError("Database connection failed: " . $e->getMessage());
            $this->sendErrorResponse();
        } catch (CustomException $e) {
            $this->logger->logError("Unexpected error during database connection: " . $e->getMessage());
            $this->sendErrorResponse();
        } catch (Exception $e) {
            $this->logger->logError("General error during database connection: " . $e->getMessage());
            $this->sendErrorResponse();
        }
    }

    private function createConnection(): PDO
    {
        $host = $this->env['DB_HOST'] ?? '';
        $db = $this->env['DB_NAME'] ?? '';
        $user = $this->env['DB_USER'] ?? '';
        $pass = $this->env['DB_PASSWORD'] ?? '';
        $port = $this->env['DB_PORT'] ?? '';

        if (empty($host) || empty($db) || empty($user) || empty($port)) {
            $this->logger->logError("Missing required database configuration parameters");
            throw new CustomException('Incomplete database configuration');
        }

        $dsn = "pgsql:host=$host;port=$port;dbname=$db";
        return new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]);
    }

    #[NoReturn] private function sendErrorResponse(): void
    {
        header('Content-Type: application/json');
        http_response_code(500);
        die(json_encode([
            'success' => false,
            'message' => 'Database service unavailable'
        ]));
    }
}