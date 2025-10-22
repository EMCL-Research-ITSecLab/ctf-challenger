<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class BadgesHandler
{
    private PDO $pdo;
    private ?int $userId;
    private array $config;
    private string $route;

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ILogger $logger;

    private ISession $session;
    private IServer $server;
    private ICookie $cookie;

    /**
     * @throws Exception
     */
    public function __construct(
        array $config,

        IDatabaseHelper $databaseHelper = null,
        ISecurityHelper $securityHelper = null,
        ILogger $logger = null,

        ISession $session = new Session(),
        IServer $server = new Server(),

        ISystem $system = new SystemWrapper(),
        ICookie $cookie = new Cookie()
    )
    {
        $this->session = $session;
        $this->server = $server;
        $this->cookie = $cookie;
        $this->route = "/badges";

        $this->databaseHelper = $databaseHelper ?? new DatabaseHelper($logger, $system);
        $this->securityHelper = $securityHelper ?? new SecurityHelper($logger, $session, $system);
        $this->logger = $logger ?? new Logger(route: $this->route, system: $system);

        $this->config = $config;
        $this->initSession();
        $this->validateRequest();
        $this->pdo = $this->databaseHelper->getPDO();
        $this->userId = $this->session['user_id'];
        $this->logger->logDebug("Initialized BadgesHandler for user ID: $this->userId");
    }

    /**
     * @throws Exception
     */
    private function initSession(): void
    {
        $this->securityHelper->initSecureSession();

        if (!$this->securityHelper->validateSession()) {
            $this->logger->logWarning("Unauthorized access attempt to badges route");
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
            $this->logger->logWarning("Invalid CSRF token attempt from user ID: " . ($this->session['user_id'] ?? 'unknown'));
            throw new CustomException('Invalid CSRF token', 403);
        }

        if (!isset($this->session['user_id'])) {
            $this->logger->logError("Session user_id not set after validation");
            throw new CustomException('User identification failed', 500);
        }
    }

    /**
     * @throws Exception
     */
    public function handleRequest(): void
    {
        try {
            $badges = $this->fetchBadges();
            $stats = $this->fetchBadgeStats();

            $this->sendResponse($badges, $stats);
        } catch (PDOException $e) {
            $this->logger->logError("Database error in badges route: " . $e->getMessage());
            throw new CustomException('Database error occurred', 500);
        }
    }

    /**
     * @throws Exception
     */
    private function fetchBadges(): array
    {
        $stmt = $this->pdo->prepare("
            SELECT
                id,
                name,
                description,
                icon,
                rarity,
                requirements,
                earned_at,
                earned
            FROM get_user_badges_data(:user_id)
        ");
        $stmt->bindValue(':user_id', $this->userId, PDO::PARAM_INT);

        if (!$stmt->execute()) {
            $this->logger->logError("Failed to execute badges query for user ID: $this->userId");
            throw new CustomException('Failed to fetch badges', 500);
        }

        $badges = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            if (!$this->validateBadgeFields($row)) {
                continue;
            }

            $badges[] = $this->formatBadge($row);
        }

        return $badges;
    }

    private function validateBadgeFields($row): bool
    {
        foreach ($this->config['badge']['REQUIRED_FIELDS'] as $field) {
            if (!array_key_exists($field, $row)) {
                $this->logger->logWarning("Missing badge field '$field' in result for user ID: $this->userId");
                return false;
            }
        }
        return true;
    }

    private function formatBadge($row): array
    {
        return [
            'id' => (int)$row['id'],
            'name' => htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8'),
            'description' => htmlspecialchars($row['description'], ENT_QUOTES, 'UTF-8'),
            'icon' => htmlspecialchars($row['icon'], ENT_QUOTES, 'UTF-8'),
            'rarity' => htmlspecialchars($row['rarity'], ENT_QUOTES, 'UTF-8'),
            'requirements' => htmlspecialchars($row['requirements'], ENT_QUOTES, 'UTF-8'),
            'earned' => (bool)$row['earned'],
            'earned_at' => $row['earned_at'],
            'progress' => $this->calculateProgress($row)
        ];
    }

    private function calculateProgress($badge): ?array
    {
        $requirements = $badge['requirements'];

        if (preg_match('/complete (\d+) challenges?/i', $requirements, $matches)) {
            return $this->calculateChallengeProgress((int)$matches[1]);
        }

        if (preg_match('/solve (\d+) (\w+) challenges?/i', $requirements, $matches)) {
            return $this->calculateCategoryProgress((int)$matches[1], $matches[2]);
        }

        if (preg_match('/earn (\d+) points?/i', $requirements, $matches)) {
            return $this->calculatePointsProgress((int)$matches[1]);
        }

        if (preg_match('/earn all available badges/i', $requirements)) {
            return $this->calculateAllBadgesProgress($badge['id']);
        }

        return null;
    }

    private function calculateChallengeProgress($required): array
    {
        $stmt = $this->pdo->prepare("
            SELECT get_user_solved_challenge_count(:user_id)
        ");
        $stmt->execute(['user_id' => $this->userId]);
        $current = $stmt->fetchColumn();

        return ['current' => (int)$current, 'max' => $required];
    }

    private function calculateCategoryProgress($required, $category): array
    {
        $stmt = $this->pdo->prepare("
            SELECT get_user_solved_challenge_count_in_category(:user_id, :category) AS count
        ");

        $stmt->execute(['user_id' => $this->userId, 'category' => $category]);
        $current = $stmt->fetchColumn();

        return ['current' => (int)$current, 'max' => $required];
    }

    private function calculatePointsProgress($required): array
    {
        $stmt = $this->pdo->prepare("
            SELECT get_user_total_points(:user_id)
        ");
        $stmt->execute(['user_id' => $this->userId]);
        $current = $stmt->fetchColumn();

        return ['current' => (int)$current, 'max' => $required];
    }

    private function calculateAllBadgesProgress($badgeId): array
    {
        $totalStmt = $this->pdo->prepare("
            SELECT get_total_badge_count_exclude_one(:badge_id)
        ");
        $totalStmt->execute(['badge_id' => $badgeId]);
        $total = $totalStmt->fetchColumn();

        $earnedStmt = $this->pdo->prepare("
            SELECT get_user_earned_badges_count_exclude_one(:user_id, :badge_id) AS count
        ");
        $earnedStmt->execute(['user_id' => $this->userId, 'badge_id' => $badgeId]);
        $earned = $earnedStmt->fetchColumn();

        return ['current' => (int)$earned, 'max' => (int)$total];
    }

    /**
     * @throws Exception
     */
    private function fetchBadgeStats(): array
    {
        $stmt = $this->pdo->prepare("
            SELECT
                total_badges,
                earned_badges
            FROM get_total_badge_count_and_user_earned_count(:user_id)
        ");
        $stmt->execute([$this->userId]);
        $stats = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$stats || !isset($stats['total_badges'])) {
            $this->logger->logError("Failed to fetch badge stats for user ID: $this->userId");
            throw new CustomException('Failed to fetch badge statistics', 500);
        }

        $stats['completion_rate'] = $stats['total_badges'] > 0 ?
            round(($stats['earned_badges'] / $stats['total_badges']) * 100) : 0;

        return [
            'total' => (int)$stats['total_badges'],
            'earned' => (int)$stats['earned_badges'],
            'completion_rate' => $stats['completion_rate']
        ];
    }

    private function sendResponse($badges, $stats): void
    {
        $response = [
            'success' => true,
            'data' => [
                'badges' => $badges,
                'stats' => $stats
            ]
        ];
        echo json_encode($response);
    }
}

// @codeCoverageIgnoreStart

if(defined('PHPUNIT_RUNNING'))
    return;

try {
    header('Content-Type: application/json');
    $config = require __DIR__ . '/../config/backend.config.php';

    $handler = new BadgesHandler(config: $config);
    $handler->handleRequest();
} catch (CustomException $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    $logger = new Logger(route: $this->route);
    $logger->logError("Error in badges endpoint: " . $e->getMessage() . " (Code: $errorCode)");
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
    $logger->logError("Unexpected error in badges endpoint: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'message' => 'An unexpected error occurred'
    ]);
}

// @codeCoverageIgnoreEnd