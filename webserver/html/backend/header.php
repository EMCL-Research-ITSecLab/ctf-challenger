<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class ProfileStatusHandler
{
    private PDO $pdo;
    private ?int $userId;
    private bool $isLoggedIn;
    private string $route;

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ILogger $logger;

    private ISession $session;
    private IServer $server;

    public function __construct(
        IDatabaseHelper $databaseHelper = null,
        ISecurityHelper $securityHelper = null,
        ILogger $logger = null,

        ISession $session = new Session(),
        IServer $server = new Server(),

        ISystem $system = new SystemWrapper()
    )
    {
        $this->session = $session;
        $this->server = $server;
        $this->route = "/header";

        $this->databaseHelper = $databaseHelper ?? new DatabaseHelper($logger, $system);
        $this->securityHelper = $securityHelper ?? new SecurityHelper($logger, $session, $system);
        $this->logger = $logger ?? new Logger(route: $this->route, system: $system);

        header('Content-Type: application/json');
        $this->initSession();
        $this->validateRequestMethod();
        $this->pdo = $this->databaseHelper->getPDO();
        $this->isLoggedIn = $this->securityHelper->validateSession();
        $this->userId = $this->session['user_id'] ?? null;

        $this->logger->logDebug("Initialized ProfileStatusHandler for " . ($this->isLoggedIn ? "user ID: $this->userId" : "guest"));
    }

    private function initSession(): void
    {
        try {
            $this->securityHelper->initSecureSession();
        } catch (CustomException $e) {
            $this->logger->logError("Session initialization failed: " . $e->getMessage());
            throw new CustomException('Session initialization error', 500);
        } // @codeCoverageIgnoreStart
        catch (Exception $e) {
            // most likely not reachable, gonna leave it here for safety
            $this->logger->logError("Unexpected error during session initialization: " . $e->getMessage());
            throw new Exception('Internal Server Error', 500);
        }
        // @codeCoverageIgnoreEnd
    }

    private function validateRequestMethod(): void
    {
        if ($this->server['REQUEST_METHOD'] !== 'GET') {
            $this->logger->logWarning("Invalid request method: " . $this->server['REQUEST_METHOD']);
            throw new CustomException('Method not allowed', 405);
        }
    }

    public function handleRequest(): void
    {
        try {
            $response = $this->buildResponse();
            $this->sendSuccessResponse($response);
        } catch (CustomException $e) {
            $this->handleError($e);
        } catch (Exception $e) {
            // most likely not reachable, gonna leave it here for safety
            $this->logger->logError("Unexpected error in handleRequest: " . $e->getMessage());
            $this->handleError(new Exception('Internal Server Error', 500));
        }
    }

    private function buildResponse(): array
    {
        $response = ['is_logged_in' => $this->isLoggedIn];

        if ($this->isLoggedIn && $this->userId) {
            $userData = $this->getUserProfileData();
            $response = array_merge($response, $userData);
        }

        return $response;
    }

    private function getUserProfileData(): array
    {
        try {
            $stmt = $this->pdo->prepare("SELECT avatar_url, is_admin FROM get_header_data(:user_id)");
            $stmt->execute(['user_id' => $this->userId]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$result) {
                $this->logger->logError("User not found in database: $this->userId");
                throw new CustomException('User not found', 400);
            }

            return [
                'avatar_url' => $result['avatar_url'] ?? '/assets/avatars/default-avatar.png',
                'is_admin' => (bool)$result['is_admin']
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error for user $this->userId: " . $e->getMessage());
            throw new CustomException('Failed to retrieve profile data', 500);
        }
    }

    private function sendSuccessResponse(array $data): void
    {
        echo json_encode([
            'success' => true,
            'data' => $data
        ]);
    }

    private function handleError(Exception $e): void
    {
        $errorCode = $e->getCode() ?: 500;
        $errorMessage = $errorCode >= 500 ? 'An internal server error occurred' : $e->getMessage();

        // @codeCoverageIgnoreStart
        // most likely not reachable, gonna leave it here for safety
        if ($errorCode === 401) {
            $this->session->unset();
            $this->session->destroy();
            $this->logger->logWarning("Session destroyed due to unauthorized access");
        }
        // @codeCoverageIgnoreEnd

        if ($errorCode >= 500) {
            $this->logger->logError("Internal error: " . $e->getMessage() . "\n" . $e->getTraceAsString());
        } else {
            $this->logger->logWarning("Profile status error: " . $e->getMessage());
        }

        http_response_code($errorCode);
        echo json_encode([
            'success' => false,
            'message' => $errorMessage,
            'redirect' => $errorCode === 401 ? '/login' : null
        ]);
    }
}


// @codeCoverageIgnoreStart

if(defined('PHPUNIT_RUNNING'))
    return;

try {
    $handler = new ProfileStatusHandler();
    $handler->handleRequest();
} catch (CustomException $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    $logger = new Logger(route: $this->route);
    $logger->logError("Error in header endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
} catch (Exception $e) {
    http_response_code(500);
    $logger = new Logger(route: $this->route);
    $logger->logError("Unexpected error in header endpoint: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'message' => 'An unexpected error occurred'
    ]);
}

// @codeCoverageIgnoreEnd