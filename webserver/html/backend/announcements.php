<?php
declare(strict_types=1);

header('Content-Type: application/json');

require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/security.php';
$config = require __DIR__ . '/../config/backend.config.php';

class AnnouncementsHandler
{
    private PDO $pdo;
    private int $page;
    private int $perPage = 10;
    private string $importanceFilter;
    private string $rangeFilter;
    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->initSession();
        $this->validateRequest();
        $this->pdo = getPDO();
        $this->parseInputParameters();
        logDebug("Initialized AnnouncementsHandler");
    }

    private function initSession()
    {
        init_secure_session();

        if (!validate_session()) {
            logWarning('Unauthorized access attempt to announcements route');
            throw new Exception('Unauthorized', 401);
        }
    }

    private function validateRequest()
    {
        $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!validate_csrf_token($csrfToken)) {
            logWarning('Invalid CSRF token attempt from user ID: ' . ($_SESSION['user_id'] ?? 'unknown'));
            throw new Exception('Invalid CSRF token', 403);
        }
    }

    private function parseInputParameters()
    {
        $this->page = filter_input(INPUT_GET, 'page', FILTER_VALIDATE_INT, [
            'options' => ['default' => 1, 'min_range' => 1]
        ]);

        $this->importanceFilter = $_GET['importance'] ?? 'all';
        if (!in_array($this->importanceFilter, $this->config['filters']['IMPORTANCE_LEVELS'])) {
            logWarning('Invalid importance filter provided: ' . $this->importanceFilter);
            throw new Exception('Invalid importance value', 400);
        }

        $this->rangeFilter = $_GET['range'] ?? 'all';
        if (!in_array($this->rangeFilter, $this->config['filters']['ACTIVITY_RANGES'])) {
            logWarning('Invalid range filter provided: ' . $this->rangeFilter);
            throw new Exception('Invalid date range value', 400);
        }
    }

    public function handleRequest()
    {
        try {
            $dateRange = $this->getDateRange();
            $params = [];
            $whereConditions = $this->buildWhereConditions($dateRange, $params);

            $baseQuery = "SELECT * FROM announcements";
            $countQuery = "SELECT COUNT(*) FROM announcements";

            if (!empty($whereConditions)) {
                $whereClause = " WHERE " . implode(" AND ", $whereConditions);
                $baseQuery .= $whereClause;
                $countQuery .= $whereClause;
            }

            $total = $this->getTotalCount($countQuery, $params);
            $announcements = $this->getPaginatedResults($baseQuery, $params, $total);

            $this->sendResponse($announcements, $total);
        } catch (PDOException $e) {
            logError("Database error in announcements route: " . $e->getMessage());
            throw new Exception('Database error occurred', 500);
        }
    }

    private function getDateRange()
    {
        if ($this->rangeFilter === 'all') {
            return null;
        }

        $date = new DateTime();
        switch ($this->rangeFilter) {
            case 'today':
                $date->setTime(0, 0, 0);
                break;
            case 'week':
                $date->modify('-1 week');
                break;
            case 'month':
                $date->modify('-1 month');
                break;
            case 'year':
                $date->modify('-1 year');
                break;
        }
        return $date->format('Y-m-d H:i:s');
    }

    private function buildWhereConditions($dateRange, &$params)
    {
        $conditions = [];

        if ($this->importanceFilter !== 'all') {
            $conditions[] = "importance = :importance";
            $params['importance'] = $this->importanceFilter;
        }

        if ($dateRange) {
            $conditions[] = "created_at >= :date_range";
            $params['date_range'] = $dateRange;
        }

        return $conditions;
    }

    private function getTotalCount($query, $params)
    {
        $stmt = $this->pdo->prepare($query);

        foreach ($params as $key => $val) {
            $stmt->bindValue($key, $val);
        }

        $stmt->execute();
        return $stmt->fetchColumn();
    }

    private function getPaginatedResults($query, $params, $total)
    {
        $offset = ($this->page - 1) * $this->perPage;
        $query .= " ORDER BY created_at DESC LIMIT :limit OFFSET :offset";

        $stmt = $this->pdo->prepare($query);

        foreach ($params as $key => $val) {
            $stmt->bindValue($key, $val);
        }

        $stmt->bindValue(':limit', $this->perPage, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        $announcements = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $announcements[] = $this->formatAnnouncement($row);
        }
        return $announcements;
    }

    private function formatAnnouncement($row)
    {
        return [
            'id' => $row['id'],
            'title' => htmlspecialchars($row['title'], ENT_QUOTES, 'UTF-8'),
            'content' => htmlspecialchars($row['content'], ENT_QUOTES, 'UTF-8'),
            'importance' => $row['importance'],
            'category' => htmlspecialchars($row['category'] ?? '', ENT_QUOTES, 'UTF-8'),
            'author' => htmlspecialchars($row['author'], ENT_QUOTES, 'UTF-8'),
            'date' => $row['created_at']
        ];
    }

    private function sendResponse($announcements, $total)
    {
        echo json_encode([
            'success' => true,
            'data' => [
                'announcements' => $announcements,
                'total' => (int)$total,
                'page' => $this->page,
                'per_page' => $this->perPage,
                'total_pages' => ceil($total / $this->perPage)
            ]
        ]);
    }
}

try {
    $handler = new AnnouncementsHandler($config);
    $handler->handleRequest();
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    logError("Error in announcements endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}