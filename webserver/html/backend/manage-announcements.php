<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class AdminAnnouncementsHandler
{
    private PDO $pdo;
    private ?int $userId;
    private string $username;
    private string $action;
    private array $config;
    private array $generalConfig;
    private string $route;

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ILogger $logger;

    private ISession $session;
    private IServer $server;
    private IGet $get;
    private ICookie $cookie;
    
    private ISystem $system;

    /**
     * @throws Exception
     */
    public function __construct(
        array $config,
        array $generalConfig,

        IDatabaseHelper $databaseHelper = null,
        ISecurityHelper $securityHelper = null,
        ILogger $logger = null,

        ISession $session = new Session(),
        IServer $server = new Server(),
        IGet $get = new Get(),

        ISystem $system = new SystemWrapper(),
        ICookie $cookie = new Cookie()
    )
    {
        $this->session = $session;
        $this->server = $server;
        $this->get = $get;
        $this->cookie = $cookie;
        $this->route = "/manage-announcements";

        $this->databaseHelper = $databaseHelper ?? new DatabaseHelper($logger, $system);
        $this->securityHelper = $securityHelper ?? new SecurityHelper($logger, $session, $system);
        $this->logger = $logger ?? new Logger(route: $this->route, system: $system);
        
        $this->system = $system;

        $this->config = $config;
        $this->generalConfig = $generalConfig;
        $this->pdo = $this->databaseHelper->getPDO();
        $this->initSession();
        $this->validateRequest();
        $this->userId = $this->session['user_id'];
        $this->username = $this->session['username'];
        $this->action = $this->get['action'] ?? '';
        $this->logger->logDebug("Initialized AdminAnnouncementsHandler for user ID: $this->userId, Action: $this->action");
    }

    /**
     * @throws Exception
     */
    private function initSession(): void
    {
        $this->securityHelper->initSecureSession();

        if (!$this->securityHelper->validateSession()) {
            $this->logger->logWarning("Unauthorized access attempt to admin announcements - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new CustomException('Unauthorized', 401);
        }
    }

    /**
     * @throws Exception
     */
    private function validateRequest(): void
    {
        $csrfToken = $this->cookie['csrf_token'] ?? '';
        if (!$this->securityHelper->validateCsrfToken($csrfToken)) {
            $this->logger->logWarning("Invalid CSRF token in admin announcements - User ID: " . ($this->session['user_id'] ?? 'unknown') . ", Token: $csrfToken");
            throw new CustomException('Invalid CSRF token', 403);
        }

        if (!$this->securityHelper->validateAdminAccess($this->pdo)) {
            $this->logger->logWarning("Non-admin access attempt to admin announcements - User ID: " . ($this->session['user_id'] ?? 'unknown'));
            throw new CustomException('Unauthorized - Admin access only', 403);
        }
    }

    /**
     * @throws Exception
     */
    public function handleRequest(): void
    {
        try {
            switch ($this->action) {
                case 'list':
                    $response = $this->handleListAction();
                    break;
                case 'create':
                case 'update':
                    $response = $this->handleCreateUpdateAction();
                    break;
                case 'delete':
                    $response = $this->handleDeleteAction();
                    break;
                default:
                    $this->logger->logError("Invalid action in admin announcements - Action: $this->action, User: $this->username");
                    throw new CustomException('Invalid action', 400);
            }

            $this->sendResponse($response);
        } catch (PDOException $e) {
            $this->logger->logError("Database error in admin announcements - " . $e->getMessage() . " - User ID: $this->userId");
            throw new CustomException('Database error occurred', 500);
        }
    }

    private function handleListAction(): array
    {
        $page = max(1, intval($this->get['page'] ?? 1));
        $perPage = 10;
        $offset = ($page - 1) * $perPage;

        $total = $this->getTotalAnnouncements();
        $announcements = $this->getPaginatedAnnouncements($perPage, $offset);

        return [
            'success' => true,
            'data' => [
                'announcements' => $announcements,
                'total' => $total
            ]
        ];
    }

    private function getTotalAnnouncements()
    {
        $stmt = $this->pdo->prepare("SELECT get_total_announcement_count() AS total");
        $stmt->execute();
        return $stmt->fetchColumn();
    }

    private function getPaginatedAnnouncements(int $perPage, int $offset): array
    {
        $stmt = $this->pdo->prepare("
            SELECT
                id,
                title,
                content,
                short_description,
                importance,
                category,
                author,
                created_at,
                updated_at
            FROM get_announcements(:limit, :offset)
        ");
        $stmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * @throws Exception
     */
    private function handleCreateUpdateAction(): array
    {
        $data = $this->getJsonInput();
        $earlyResponse = $this->validateAnnouncementData($data);

        if ($earlyResponse)
            return $earlyResponse;

        if ($this->action === 'create') {
            return $this->createAnnouncement($data);
        } else {
            return $this->updateAnnouncement($data);
        }
    }

    /**
     * @throws Exception
     */
    private function getJsonInput()
    {
        $data = json_decode($this->system->file_get_contents('php://input'), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->logger->logError("Invalid JSON in announcement $this->action - User: $this->username");
            throw new CustomException('Invalid JSON data', 400);
        }
        return $data;
    }

    private function validateAnnouncementData(array $data): ?array
    {
        $errors = [];
        $errorFields = [];

        $title = trim($data['title'] ?? '');
        if (empty($title)) {
            $errors[] = 'Title is required';
            $errorFields[] = 'announcement-title';
        } elseif (strlen($title) > $this->generalConfig['announcement']['MAX_ANNOUNCEMENT_NAME_LENGTH']) {
            $errors[] = 'Title cannot exceed ' . $this->generalConfig['announcement']['MAX_ANNOUNCEMENT_NAME_LENGTH'] . ' characters';
            $errorFields[] = 'announcement-title';
        }

        $shortDesc = trim($data['short_description'] ?? '');
        if (strlen($shortDesc) > $this->generalConfig['announcement']['MAX_ANNOUNCEMENT_SHORT_DESCRIPTION_LENGTH']) {
            $errors[] = 'Short description cannot exceed ' . $this->generalConfig['announcement']['MAX_ANNOUNCEMENT_SHORT_DESCRIPTION_LENGTH'] . ' characters';
            $errorFields[] = 'announcement-short-desc';
        }

        $content = trim($data['content'] ?? '');
        if (empty($content)) {
            $errors[] = 'Content is required';
            $errorFields[] = 'announcement-content';
        } elseif (strlen($content) > $this->generalConfig['announcement']['MAX_ANNOUNCEMENT_DESCRIPTION_LENGTH']) {
            $errors[] = 'Content cannot exceed ' . $this->generalConfig['announcement']['MAX_ANNOUNCEMENT_DESCRIPTION_LENGTH'] . ' characters';
            $errorFields[] = 'announcement-content';
        }

        $category = strtolower(trim($data['category'] ?? ''));
        if (!in_array($category, $this->config['announcement']['VALID_CATEGORIES'])) {
            $errors[] = 'Please select a valid category';
            $errorFields[] = 'announcement-category';
        }

        $importance = strtolower(trim($data['importance'] ?? ''));
        if (!in_array($importance, $this->config['announcement']['IMPORTANCE_LEVELS'])) {
            $errors[] = 'Please select a valid importance level';
            $errorFields[] = 'announcement-importance';
        }

        if (!empty($errors)) {
            $this->logger->logError("Validation failed in announcement $this->action - User: $this->username, Errors: " . implode(', ', $errors));
            http_response_code(400);

            $errorResponse = [
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $errors,
                'fields' => array_unique($errorFields)
            ];
            if(defined('PHPUNIT_RUNNING'))
                return $errorResponse;
            // @codeCoverageIgnoreStart
            else
                echo json_encode($errorResponse);
            exit;
            // @codeCoverageIgnoreEnd
        }
        return null;
    }

    private function createAnnouncement(array $data): array
    {
        $title = trim($data['title']  ?? '');
        $content = trim($data['content'] ?? '');
        $shortDesc = trim($data['short_description'] ?? '');
        $importance = strtolower(trim($data['importance'] ?? ''));
        $category = strtolower(trim($data['category'] ?? ''));

        $stmt = $this->pdo->prepare("
            SELECT create_announcement(
                :title,
                :content,
                :short_desc,
                :importance,
                :category,
                :author
            ) AS announcement_id
        ");

        $stmt->execute([
            'title' => $title,
            'content' => $content,
            'short_desc' => $shortDesc,
            'importance' => $importance,
            'category' => $category,
            'author' => $this->username
        ]);

        $announcementId = $stmt->fetchColumn();
        $this->logger->logInfo("Announcement created - ID: $announcementId, Title: $title, Author: $this->username");

        return [
            'success' => true,
            'message' => 'Announcement created successfully',
            'id' => $announcementId
        ];
    }

    /**
     * @throws Exception
     */
    private function updateAnnouncement(array $data): array
    {
        if (empty($data['id'])) {
            $this->logger->logError("Missing announcement ID in update - User: $this->username");
            throw new CustomException('Missing announcement ID', 400);
        }

        $id = intval($data['id']);
        $this->verifyAnnouncementExists($id);

        $title = trim($data['title'] ?? '');
        $content = trim($data['content'] ?? '');
        $shortDesc = trim($data['short_description'] ?? '');
        $importance = strtolower(trim($data['importance'] ?? ''));
        $category = strtolower(trim($data['category'] ?? ''));

        $stmt = $this->pdo->prepare("
            SELECT update_announcement(
                :id,
                :title,
                :content,
                :short_desc,
                :importance,
                :category
            )
        ");

        $stmt->execute([
            'id' => $id,
            'title' => $title,
            'content' => $content,
            'short_desc' => $shortDesc,
            'importance' => $importance,
            'category' => $category
        ]);

        $this->logger->logInfo("Announcement updated - ID: $id, Title: $title, User: $this->username");

        return [
            'success' => true,
            'message' => 'Announcement updated successfully'
        ];
    }

    /**
     * @throws Exception
     */
    private function verifyAnnouncementExists(int $id): void
    {
        $stmt = $this->pdo->prepare("SELECT announcement_exists(:id) AS exists");
        $stmt->execute(['id' => $id]);
        if ($stmt->fetchColumn() == 0) {
            $this->logger->logError("Announcement not found for update - ID: $id, User: $this->username");
            throw new CustomException('Announcement not found', 404);
        }
    }

    /**
     * @throws Exception
     */
    private function handleDeleteAction(): array
    {
        $data = $this->getJsonInput();

        if (empty($data['id'])) {
            throw new CustomException('Missing announcement ID', 400);
        }

        $stmt = $this->pdo->prepare("SELECT delete_announcement(:id)");
        $stmt->execute(['id' => $data['id']]);

        return [
            'success' => true,
            'message' => 'Announcement deleted successfully'
        ];
    }

    private function sendResponse(array $response): void
    {
        echo json_encode($response);
    }
}

// @codeCoverageIgnoreStart

if(defined('PHPUNIT_RUNNING'))
    return;

try {
    header('Content-Type: application/json');
    $config = require __DIR__ . '/../config/backend.config.php';
    $system = new SystemWrapper();
    $generalConfig = json_decode($system->file_get_contents(__DIR__ . '/../config/general.config.json'), true);

    $handler = new AdminAnnouncementsHandler(config: $config, generalConfig: $generalConfig);
    $handler->handleRequest();
} catch (CustomException $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    $logger = new Logger(route: $this->route);
    $logger->logError("Error in manage-announcements endpoint: " . $e->getMessage() . " (Code: $errorCode)");
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
    $logger->logError("Unexpected error in manage-announcements endpoint: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'message' => 'An unexpected error occurred'
    ]);
}

// @codeCoverageIgnoreEnd
