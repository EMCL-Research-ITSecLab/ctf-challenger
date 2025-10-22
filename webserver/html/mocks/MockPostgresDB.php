<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Testcontainers\Container\GenericContainer;
use Testcontainers\Container\StartedGenericContainer;
use Testcontainers\Modules\PostgresContainer;
use Testcontainers\Wait\WaitForLog;

class MockPostgresDB
{
    private StartedGenericContainer $postgresContainer;
    private GenericContainer $container;
    private PDO $pdo;
    private string $dbInitScript;
    private array $dbFunctionsScripts;
    private string $dbPermissionsScript;
    private ISystem $system;

    private string $dbName;
    private string $dbUser;
    private string $dbPassword;

    public function __construct(
        string $dbName = 'ctf-challenger',
        string $dbUser = 'testuser',
        string $dbPassword = 'testpass',
        string $dbScriptsPath = __DIR__ . '/../../../database',
        ISystem $system = new SystemWrapper()
    )
    {
        $this->dbName = $dbName;
        $this->dbUser = $dbUser;
        $this->dbPassword = $dbPassword;

        $this->system = $system;
        $dbScriptsPath = rtrim($dbScriptsPath, '/');
        $this->dbInitScript = $dbScriptsPath . '/init.sql';
        $dbFunctionsDir = $dbScriptsPath . '/functions';
        $this->dbFunctionsScripts = glob($dbFunctionsDir . '/*.sql');
        $this->dbPermissionsScript = $dbScriptsPath . '/permissions.sql';

        if (PHP_OS_FAMILY === 'Windows') {
            putenv("DOCKER_HOST=tcp://192.168.227.3:2375");
        } else {
            putenv("DOCKER_HOST=unix:///var/run/docker.sock");
        }

        $maxTries = 5;
        $attempt = 0;
        while ($attempt < $maxTries) {
            try {

                $this->container = (new PostgresContainer("15"))
                    ->withPostgresUser($dbUser)
                    ->withPostgresPassword($dbPassword)
                    ->withPostgresDatabase($dbName)
                    ->withWait(new WaitForLog("database system is ready to accept connections", false, 20000));

                $this->postgresContainer = $this->container->start();

                sleep(1);

                $this->pdo = new PDO(
                    sprintf(
                        'pgsql:host=%s;port=%d;dbname=%s',
                        $this->postgresContainer->getHost(),
                        $this->postgresContainer->getMappedPort(5432),
                        $dbName
                    ),
                    $dbUser,
                    $dbPassword
                );
                $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                $this->initializeDatabase();

                break;
            } catch (Exception $e) {
                $attempt++;
                if ($attempt >= $maxTries) {
                    throw new CustomException("Failed to start Postgres container after $maxTries attempts: " . $e->getMessage());
                }
                sleep(2); // wait before retrying
            }
        }
    }

    public function getPDO(): PDO
    {
        return $this->pdo;
    }

    private function initializeDatabase(): void
    {
        if ($this->system->file_exists($this->dbInitScript)) {
            $initSql = $this->system->file_get_contents($this->dbInitScript);
            $this->pdo->exec($initSql);
            foreach ($this->dbFunctionsScripts as $functionScript) {
                if ($this->system->file_exists($functionScript)) {
                    $functionSql = $this->system->file_get_contents($functionScript);
                    $this->pdo->exec($functionSql);
                }
            }
            if ($this->system->file_exists($this->dbPermissionsScript)) {
                $permissionsSql = $this->system->file_get_contents($this->dbPermissionsScript);
                $this->pdo->exec($permissionsSql);
            }

            $this->insertTestData();
        } else {
            throw new CustomException("Initialization script not found: " . $this->dbInitScript);
        }
    }

    private function insertTestData(): void
    {
        $salt = 'testsalt';
        $adminHash = hash('sha512', $salt . 'adminpass');
        $userHash = hash('sha512', $salt . 'testpass');

        $this->pdo->exec("
            INSERT INTO users (username, email, password_hash, password_salt, is_admin)
            VALUES ('admin', 'admin@localhost.local', '$adminHash', '$salt', true),
                   ('testuser', 'test@test.test', '$userHash', '$salt', false);
        ");

        $this->pdo->exec("
            INSERT INTO vpn_static_ips (vpn_static_ip, user_id) VALUES 
                ('10.64.0.2', 1),
                ('10.64.0.3', NULL),
                ('10.64.0.4', NULL),
                ('10.64.0.5', NULL),
                ('10.64.0.6', NULL),
                ('10.64.0.7', NULL),
                ('10.64.0.8', NULL),
                ('10.64.0.9', NULL),
                ('10.64.0.0', NULL),
                ('10.64.0.10', NULL),
                ('10.64.0.11', NULL);
        ");

        $this->pdo->exec("
            UPDATE users SET vpn_static_ip = '10.64.0.2' WHERE id = 1;
        ");

        $this->pdo->exec("
            INSERT INTO challenge_subnets (subnet, available) VALUES 
                ('10.128.0.0/24', true), 
                ('10.128.0.1/24', true), 
                ('10.128.0.2/24', true), 
                ('10.128.0.3/24', true), 
                ('10.128.0.4/24', true), 
                ('10.128.0.5/24', true), 
                ('10.128.0.6/24', true), 
                ('10.128.0.7/24', true), 
                ('10.128.0.8/24', true), 
                ('10.128.0.9/24', true);
        ");
    }

    public function installLintingTools(): void
    {
        $this->postgresContainer->exec(['apt-get', 'update']);
        $this->postgresContainer->exec(['apt-get','install', '-y', 'postgresql-15-plpgsql-check']);
    }

    public function __destruct()
    {
        if (isset($this->postgresContainer)) {
            $this->postgresContainer->stop();
        }
    }
}
