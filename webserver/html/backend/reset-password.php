<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class ChangePasswordHandler
{
    private PDO $pdo;
    private ILogger $logger;
    private ISecurityHelper $securityHelper;
    private ISession $session;
    private IServer $server;
    private IPost $post;
    private ICookie $cookie;
    private ISystem $system;
    private IDatabaseHelper $databaseHelper;
    private string $currentPassword;
    private string $newPassword;
    private string $confirmPassword;
    private ?int $userId;

    private array $generalConfig;

    public function __construct(
        array $generalConfig,
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
        $this->system = $system;
        $this->cookie = $cookie;

        $this->databaseHelper = $databaseHelper ?? new DatabaseHelper($logger, $system);
        $this->securityHelper = $securityHelper ?? new SecurityHelper($logger, $session, $system);
        $this->logger = $logger ?? new Logger(route: '/change-password', system: $system);
        $this->pdo = $this->databaseHelper->getPDO();
        $this->generalConfig = $generalConfig;

        $this->initSession();
        $this->validateAuthentication();
        $this->userId = (int)$this->session['user_id'];
    }

    private function initSession(): void
    {
        $this->securityHelper->initSecureSession();
    }

    private function validateAuthentication(): void
    {
        if (!$this->securityHelper->validateSession(true, false)) {
            header('Location: /login');
            defined('PHPUNIT_RUNNING') || exit;
        }
        if (!$this->securityHelper->requiresPasswordChange()) {
            header('Location: /dashboard');
            defined('PHPUNIT_RUNNING') || exit;
        }
    }

    public function handleRequest(): void
    {
        try {
            if ($this->server['REQUEST_METHOD'] === 'POST') {
                $this->processPasswordChange();
            }
        } catch (CustomException $e) {
            $this->handleError($e);
        } catch (Exception $e) {
            $this->handleError(new Exception('Internal Server Error', 500));
        }
    }

    private function processPasswordChange(): void
    {
        $this->parseInput();
        $this->validateRequest();
        $this->changePassword();
    }

    private function parseInput(): void
    {
        $this->currentPassword = $this->post['current_password'] ?? '';
        $this->newPassword = $this->post['new_password'] ?? '';
        $this->confirmPassword = $this->post['confirm_password'] ?? '';
    }

    private function validateRequest(): void
    {
        $csrfToken = $this->cookie['csrf_token'] ?? '';
        if (!$this->securityHelper->validateCsrfToken($csrfToken)) {
            $this->logger->logWarning("Invalid CSRF token in reset-password - User ID: $this->userId, Token: $csrfToken");
            throw new CustomException('Invalid CSRF token', 403);
        }
    }

    private function changePassword(): void
    {
        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare("SELECT get_password_reset_valid(:user_id) AS valid");
            $stmt->execute(['user_id' => $this->userId]);
            $resetValid = $stmt->fetchColumn();
            if(!$resetValid) {
                throw new CustomException('Password Reset Window Expired', 400);
            }

            if (empty($this->currentPassword) || empty($this->newPassword)) {
                throw new CustomException('Both current and new password are required', 400);
            }

            if (strlen($this->newPassword) < $this->generalConfig['user']['MIN_PASSWORD_LENGTH']) {
                throw new CustomException('New password must be at least 8 characters', 400);
            }

            if (strlen($this->newPassword) > $this->generalConfig['user']['MAX_PASSWORD_LENGTH']) {
                throw new CustomException('Password is too long', 400);
            }

            $stmt = $this->pdo->prepare("SELECT get_user_password_salt(:username) AS salt");
            $stmt->execute(['username' => $this->session['username']]);
            $passwordSalt = $stmt->fetch(PDO::FETCH_ASSOC)['salt'];

            if (!$passwordSalt) {
                $this->logger->logError("User not found during password change - User ID: $this->userId");
                throw new CustomException('User not found', 404);
            }

            $oldPasswordHash = hash('sha512', $passwordSalt . $this->currentPassword);
            $userStmt = $this->pdo->prepare("SELECT authenticate_user(:username, :password_hash) AS user_id");
            $userStmt->execute([
                'username' => $this->session['username'],
                'password_hash' => $oldPasswordHash
            ]);
            $user_id = $userStmt->fetch(PDO::FETCH_ASSOC)['user_id'];


            if (!$user_id) {
                $this->logger->logWarning("Incorrect current password attempt - User ID: $this->userId");
                throw new CustomException('Current password is incorrect', 400);
            }

            if (hash('sha512', $passwordSalt . $this->newPassword) === $oldPasswordHash) {
                throw new CustomException('New password must be different from current password', 400);
            }

            $newSalt = bin2hex(random_bytes(16));
            $newPasswordHash = hash('sha512', $newSalt . $this->newPassword);
            if (!$newPasswordHash) {
                throw new CustomException('Error hashing password', 500);
            }

            $updateStmt = $this->pdo->prepare("SELECT change_user_password(:user_id, :old_password_hash, :new_password_hash, :new_password_salt)");
            $updateStmt->execute([
                'user_id' => $this->userId,
                'old_password_hash' => $oldPasswordHash,
                'new_password_hash' => $newPasswordHash,
                'new_password_salt' => $newSalt
            ]);

            $this->pdo->commit();
            unset($this->session['password_change_check']);
            unset($this->session['password_change_check_time']);

            $this->logger->logDebug("Password changed successfully - User ID: $this->userId");

            $this->sendSuccessResponse();

        } catch (PDOException $e) {
            $this->pdo->rollBack();
            $this->logger->logError("Database error during password change - User ID: $this->userId - " . $e->getMessage());
            throw new CustomException('Failed to change password', 400);
        }
    }

    private function sendSuccessResponse(): void
    {
        echo json_encode([
            'success' => true,
            'message' => 'Password changed successfully',
            'redirect' => '/dashboard'
        ]);
        defined('PHPUNIT_RUNNING') || exit;
    }

    private function handleError(Exception $e): void
    {
        $code = $e->getCode() >= 400 && $e->getCode() < 600 ? $e->getCode() : 400;
        http_response_code($code);

        $this->logger->logError("Password change error: " . $e->getMessage() . " [Code: $code]");

        echo json_encode([
            'success' => false,
            'message' => $e->getMessage(),
            'error_code' => $code
        ]);
        defined('PHPUNIT_RUNNING') || exit;
    }
}

// @codeCoverageIgnoreStart
if (defined('PHPUNIT_RUNNING')) {
    return;
}

try {
    header('Content-Type: application/json');
    $system = new SystemWrapper();
    $generalConfig = json_decode($system->file_get_contents(__DIR__ . '/../config/general.config.json'), true);
    $handler = new ChangePasswordHandler(generalConfig: $generalConfig);
    $handler->handleRequest();
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'An unexpected error occurred'
    ]);
}
// @codeCoverageIgnoreEnd