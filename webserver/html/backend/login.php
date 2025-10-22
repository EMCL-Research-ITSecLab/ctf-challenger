<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class LoginHandler
{
    private PDO $pdo;
    private bool $isPost;
    private string $username;
    private string $password;
    private string $csrfToken;
    private string $route;

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ILogger $logger;

    private ISession $session;
    private IServer $server;
    private IPost $post;
    private ICookie $cookie;
    
    private ISystem $system;

    public function __construct(
        IDatabaseHelper $databaseHelper = null,
        ISecurityHelper $securityHelper = null,
        ILogger $logger = null,

        ISession $session = new Session(),
        IServer $server = new Server(),
        IPost $post = new Post(),
        ISystem $system = new SystemWrapper(),
        ICookie $cookie = new Cookie()
    )
    {
        $this->session = $session;
        $this->server = $server;
        $this->post = $post;
        $this->cookie = $cookie;
        $this->route = "/login";

        $this->databaseHelper = $databaseHelper ?? new DatabaseHelper($logger, $system);
        $this->securityHelper = $securityHelper ?? new SecurityHelper($logger, $session, $system);
        $this->logger = $logger ?? new Logger(route: $this->route, system: $system);
        
        $this->system = $system;

        $this->initSession();
        $this->validateRequestMethod();
        $this->checkAlreadyAuthenticated();
        $this->logger->logDebug("Initialized LoginHandler with Session ID: " . $this->session->id() ? hash('sha256', $this->session->id()) : 'no-session');
    }

    private function initSession(): void
    {
        $this->securityHelper->initSecureSession();
    }

    private function validateRequestMethod(): void
    {
        $this->isPost = $this->server['REQUEST_METHOD'] === 'POST';
    }

    private function checkAlreadyAuthenticated(): void
    {
        if ($this->securityHelper->validateSession(false) && !empty($this->session['authenticated'])) {
            $this->handleAlreadyAuthenticated();
        }
    }

    private function handleAlreadyAuthenticated(): void
    {
        $redirectUrl = '/dashboard';
        $userId = $this->session['user_id'];
        $username = $this->session['username'];
        $ip = $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown');

        $this->logger->logWarning("User already authenticated - User ID: $userId, Username: $username, IP: $ip");

        if (!isset($this->session['csrf_token'])) {
            $this->securityHelper->generateCsrfToken();
            $this->logger->logDebug("Generated new CSRF token for user ID: $userId");
        }

        $csrf = $this->session['csrf_token'];

        $this->setCsrfCookie($csrf);

        echo json_encode([
            'success' => true,
            'redirect' => $redirectUrl,
            'csrf_token' => $csrf
        ]);
        defined('PHPUNIT_RUNNING') || exit;
    }

    public function handleRequest(): void
    {
        try {
            if ($this->isPost) {
                $this->processLogin();
            }
        } catch (PDOException $e) {
            $this->logger->logError("Database error during login: " . $e->getMessage());
            $this->respondWithError('Database error occurred', 500, 'server');
        } catch (CustomException $e) {
            $this->logger->logError("Login error: " . $e->getMessage());
            $this->respondWithError($e->getMessage(), $e->getCode(), 'auth');
        } catch (Exception $e) {
            $this->logger->logError("Unexpected error during login: " . $e->getMessage());
            $this->respondWithError('Internal Server Error', 500, 'server');
        }
    }

    /**
     * @throws Exception
     */
    private function processLogin(): void
    {
        $this->parseInput();
        $this->validateInput();
        $this->authenticateUser();
    }

    private function parseInput(): void
    {
        $this->csrfToken = $this->post['csrf_token'] ?? '';
        $this->username = trim($this->post['username'] ?? '');
        $this->password = $this->post['password'] ?? '';
    }

    /**
     * @throws Exception
     */
    private function validateInput(): void
    {
        if (empty($this->csrfToken)) {
            $this->logger->logError("Empty CSRF token - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new CustomException('Invalid request token.', 403);
        }

        if (!$this->securityHelper->validateCsrfToken($this->csrfToken)) {
            $this->logger->logError("Invalid CSRF token - Received: $this->csrfToken, IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown') .", Username: $this->username");
            throw new CustomException('Invalid CSRF token', 403);
        }

        if (empty($this->username)) {
            $this->logger->logError("Empty username provided - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new CustomException('Username is required.', 400);
        }

        if (empty($this->password)) {
            $this->logger->logError("Empty password provided - Username: $this->username, IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new CustomException('Password is required.', 400);
        }
    }

    /**
     * @throws Exception
     */
    private function authenticateUser(): void
    {
        $this->pdo = $this->databaseHelper->getPDO();

        $passwordSalt = $this->getUserPasswordSalt();
        $userId = $this->verifyPassword($passwordSalt);
        $this->updateLastLogin($userId);
        $this->initializeUserSession($userId, $this->username);
        $this->sendSuccessResponse();
    }

    /**
     * @throws Exception
     */
    private function getUserPasswordSalt()
    {
        $stmt = $this->pdo->prepare("SELECT get_user_password_salt(:username) AS password_salt");
        $stmt->execute(['username' => $this->username]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        $passwordSalt = $result['password_salt'] ?? null;

        if ($passwordSalt === null) {
            $this->logger->logError("User not found - Username: $this->username, IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new CustomException('Invalid username or password.', 401);
        }

        return $passwordSalt;
    }

    /**
     * @throws Exception
     */
    private function verifyPassword(string $passwordSalt): int
    {
        $passwordHash = hash('sha512', $passwordSalt . $this->password);

        $stmt = $this->pdo->prepare("SELECT authenticate_user(:username, :password_hash) AS user_id");
        $stmt->execute([
            'username' => $this->username,
            'password_hash' => $passwordHash
        ]);
        $user_id = $stmt->fetchColumn();

        if (!$user_id) {
            $this->logger->logError("Invalid password attempt - Username: $this->username, IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new CustomException('Invalid username or password.', 401);
        }

        return (int)$user_id;
    }

    private function updateLastLogin(int $userId): void
    {
        $update = $this->pdo->prepare("SELECT update_last_login(:id)");
        $update->execute(['id' => $userId]);
    }

    private function initializeUserSession(int $user_id, string $username): void
    {
        $this->session->regenerate_id(true);
        $this->logger->logDebug("Session regenerated - User ID: {$user_id}, New Session ID: " . $this->session->id() ? hash('sha256', $this->session->id()) : 'no-session');

        $this->session['user_id'] = $user_id;
        $this->session['authenticated'] = true;
        $this->session['ip'] = $this->server['REMOTE_ADDR'] ?? '';
        $this->session['user_agent'] = $this->server['HTTP_USER_AGENT'] ?? '';
        $this->session['last_activity'] = $this->system->time();
        $this->session['username'] = $username;
    }

    private function sendSuccessResponse(): void
    {
        $newCsrf = $this->securityHelper->generateCsrfToken();
        $this->setCsrfCookie($newCsrf);

        echo json_encode([
            'success' => true,
            'message' => 'Login successful.',
            'redirect' => '/dashboard',
            'csrf_token' => $newCsrf
        ]);
        defined('PHPUNIT_RUNNING') || exit;
    }

    private function setCsrfCookie(string $token): void
    {
        $this->system->setcookie(
            'csrf_token',
            $token,
            [
                'expires' => $this->system->time() + 3600,
                'path' => '/',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Strict'
            ]
        );
    }

    private function respondWithError(string $message, int $statusCode, string $type = 'general'): void
    {
        http_response_code($statusCode);
        echo json_encode([
            'success' => false,
            'type' => $type,
            'message' => $message
        ]);
        defined('PHPUNIT_RUNNING') || exit;
    }
}


// @codeCoverageIgnoreStart

if(defined('PHPUNIT_RUNNING'))
    return;

try {
    header('Content-Type: application/json');

    $handler = new LoginHandler();
    $handler->handleRequest();
} catch (CustomException $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    $logger = new Logger(route: $this->route);
    $logger->logError("Error in login endpoint: " . $e->getMessage() . " (Code: $errorCode)");
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
    $logger->logError("Unexpected error in login endpoint: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'message' => 'An unexpected error occurred'
    ]);
}

// @codeCoverageIgnoreEnd