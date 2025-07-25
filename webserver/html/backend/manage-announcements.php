<?php
declare(strict_types=1);

header('Content-Type: application/json');

require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/security.php';
$config = require __DIR__ . '/../config/backend.config.php';
$generalConfig = json_decode(file_get_contents(__DIR__ . '/../config/general.config.json'), true);

class AdminAnnouncementsHandler
{
    private PDO $pdo;
    private ?int $userId;
    private string $username;
    private string $action;
    private array $config;
    private array $generalConfig;

    public function __construct(array $config, array $generalConfig)
    {
        $this->config = $config;
        $this->generalConfig = $generalConfig;
        $this->pdo = getPDO();
        $this->initSession();
        $this->validateRequest();
        $this->userId = $_SESSION['user_id'];
        $this->username = $this->getUsername();
        $this->action = $_GET['action'] ?? '';
        logDebug("Initialized AdminAnnouncementsHandler for user ID: {$this->userId}, Action: {$this->action}");
    }

    private function initSession()
    {
        init_secure_session();

        if (!validate_session()) {
            logWarning("Unauthorized access attempt to admin announcements - IP: " . anonymizeIp($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Unauthorized', 401);
        }
    }

    private function validateRequest()
    {
        $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!validate_csrf_token($csrfToken)) {
            logWarning("Invalid CSRF token in admin announcements - User ID: " . ($_SESSION['user_id'] ?? 'unknown') . ", Token: {$csrfToken}");
            throw new Exception('Invalid CSRF token', 403);
        }

        if (!validate_admin_access($this->pdo)) {
            logWarning("Non-admin access attempt to admin announcements - User ID: " . ($_SESSION['user_id'] ?? 'unknown'));
            throw new Exception('Unauthorized - Admin access only', 403);
        }
    }

    private function getUsername()
    {
        $stmt = $this->pdo->prepare("SELECT username FROM users WHERE id = :user_id");
        $stmt->execute(['user_id' => $this->userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            logError("User not found during admin announcement access - User ID: {$this->userId}");
            throw new Exception('User not found', 404);
        }

        return $user['username'];
    }

    public function handleRequest()
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
                    logError("Invalid action in admin announcements - Action: {$this->action}, User: {$this->username}");
                    throw new Exception('Invalid action', 400);
            }

            $this->sendResponse($response);
        } catch (PDOException $e) {
            logError("Database error in admin announcements - " . $e->getMessage() . " - User ID: {$this->userId}");
            throw new Exception('Database error occurred', 500);
        }
    }

    private function handleListAction()
    {
        $page = max(1, intval($_GET['page'] ?? 1));
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
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM announcements");
        $stmt->execute();
        return $stmt->fetchColumn();
    }

    private function getPaginatedAnnouncements(int $perPage, int $offset)
    {
        $stmt = $this->pdo->prepare("
            SELECT * FROM announcements 
            ORDER BY created_at DESC 
            LIMIT :limit OFFSET :offset
        ");
        $stmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    private function handleCreateUpdateAction()
    {
        $data = $this->getJsonInput();
        $this->validateAnnouncementData($data);

        if ($this->action === 'create') {
            return $this->createAnnouncement($data);
        } else {
            return $this->updateAnnouncement($data);
        }
    }

    private function getJsonInput()
    {
        $data = json_decode(file_get_contents('php://input'), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            logError("Invalid JSON in announcement {$this->action} - User: {$this->username}");
            throw new Exception('Invalid JSON data', 400);
        }
        return $data;
    }

    private function validateAnnouncementData(array $data)
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
            logError("Validation failed in announcement {$this->action} - User: {$this->username}, Errors: " . implode(', ', $errors));
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $errors,
                'fields' => array_unique($errorFields)
            ]);
            exit;
        }
    }

    private function createAnnouncement(array $data)
    {
        $title = trim($data['title']);
        $content = trim($data['content']);
        $shortDesc = !empty($data['short_description']) ? trim($data['short_description']) : null;
        $importance = strtolower(trim($data['importance']));
        $category = strtolower(trim($data['category']));

        $stmt = $this->pdo->prepare("
            INSERT INTO announcements (
                title, 
                content, 
                short_description, 
                importance, 
                category, 
                author,
                created_at,
                updated_at
            ) VALUES (
                :title, 
                :content, 
                :short_desc, 
                :importance, 
                :category, 
                :author,
                NOW(),
                NOW()
            )
        ");

        $stmt->execute([
            'title' => $title,
            'content' => $content,
            'short_desc' => $shortDesc,
            'importance' => $importance,
            'category' => $category,
            'author' => $this->username
        ]);

        $announcementId = $this->pdo->lastInsertId();
        logInfo("Announcement created - ID: {$announcementId}, Title: {$title}, Author: {$this->username}");

        return [
            'success' => true,
            'message' => 'Announcement created successfully',
            'id' => $announcementId
        ];
    }

    private function updateAnnouncement(array $data)
    {
        if (empty($data['id'])) {
            logError("Missing announcement ID in update - User: {$this->username}");
            throw new Exception('Missing announcement ID', 400);
        }

        $id = intval($data['id']);
        $this->verifyAnnouncementExists($id);

        $title = trim($data['title']);
        $content = trim($data['content']);
        $shortDesc = !empty($data['short_description']) ? trim($data['short_description']) : null;
        $importance = strtolower(trim($data['importance']));
        $category = strtolower(trim($data['category']));

        $stmt = $this->pdo->prepare("
            UPDATE announcements SET
                title = :title,
                content = :content,
                short_description = :short_desc,
                importance = :importance,
                category = :category,
                updated_at = NOW()
            WHERE id = :id
        ");

        $stmt->execute([
            'id' => $id,
            'title' => $title,
            'content' => $content,
            'short_desc' => $shortDesc,
            'importance' => $importance,
            'category' => $category
        ]);

        logInfo("Announcement updated - ID: {$id}, Title: {$title}, User: {$this->username}");

        return [
            'success' => true,
            'message' => 'Announcement updated successfully'
        ];
    }

    private function verifyAnnouncementExists(int $id)
    {
        $stmt = $this->pdo->prepare("SELECT id FROM announcements WHERE id = :id");
        $stmt->execute(['id' => $id]);
        if (!$stmt->fetch()) {
            logError("Announcement not found for update - ID: {$id}, User: {$this->username}");
            throw new Exception('Announcement not found', 404);
        }
    }

    private function handleDeleteAction()
    {
        $data = $this->getJsonInput();

        if (empty($data['id'])) {
            throw new Exception('Missing announcement ID', 400);
        }

        $stmt = $this->pdo->prepare("DELETE FROM announcements WHERE id = :id");
        $stmt->execute(['id' => $data['id']]);

        return [
            'success' => true,
            'message' => 'Announcement deleted successfully'
        ];
    }

    private function sendResponse(array $response)
    {
        echo json_encode($response);
    }
}

try {
    $handler = new AdminAnnouncementsHandler($config, $generalConfig);
    $handler->handleRequest();
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    logError("Error in manage-announcements endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}