<?php
declare(strict_types=1);

header('Content-Type: application/json');

require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/security.php';
$config = require __DIR__ . '/../config/backend.config.php';

class BadgesHandler
{
    private PDO $pdo;
    private ?int $userId;
    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->initSession();
        $this->validateRequest();
        $this->pdo = getPDO();
        $this->userId = $_SESSION['user_id'];
        logDebug("Initialized BadgesHandler for user ID: {$this->userId}");
    }

    private function initSession()
    {
        init_secure_session();

        if (!validate_session()) {
            logWarning("Unauthorized access attempt to badges route");
            throw new Exception('Unauthorized', 401);
        }
    }

    private function validateRequest()
    {
        $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!validate_csrf_token($csrfToken)) {
            logWarning("Invalid CSRF token attempt from user ID: " . ($_SESSION['user_id'] ?? 'unknown'));
            throw new Exception('Invalid CSRF token', 403);
        }

        if (!isset($_SESSION['user_id'])) {
            logError("Session user_id not set after validation");
            throw new Exception('User identification failed', 500);
        }
    }

    public function handleRequest()
    {
        try {
            $badges = $this->fetchBadges();
            $stats = $this->fetchBadgeStats();

            $this->sendResponse($badges, $stats);
        } catch (PDOException $e) {
            logError("Database error in badges route: " . $e->getMessage());
            throw new Exception('Database error occurred', 500);
        }
    }

    private function fetchBadges()
    {
        $query = "SELECT 
            b.id,
            b.name,
            b.description,
            b.icon,
            b.rarity,
            b.requirements,
            ub.earned_at,
            CASE WHEN ub.user_id IS NULL THEN false ELSE true END as earned
        FROM badges b
        LEFT JOIN user_badges ub ON ub.badge_id = b.id AND ub.user_id = :user_id
        ORDER BY b.rarity DESC, b.name ASC";

        $stmt = $this->pdo->prepare($query);
        $stmt->bindValue(':user_id', $this->userId, PDO::PARAM_INT);

        if (!$stmt->execute()) {
            logError("Failed to execute badges query for user ID: {$this->userId}");
            throw new Exception('Failed to fetch badges', 500);
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

    private function validateBadgeFields($row)
    {
        foreach ($this->config['badge']['REQUIRED_FIELDS'] as $field) {
            if (!array_key_exists($field, $row)) {
                logWarning("Missing badge field '$field' in result for user ID: {$this->userId}");
                return false;
            }
        }
        return true;
    }

    private function formatBadge($row)
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

    private function calculateProgress($badge)
    {
        try {
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
        } catch (Exception $e) {
            logError("Error calculating progress for badge ID {$badge['id']}: " . $e->getMessage());
            return null;
        }
    }

    private function calculateChallengeProgress($required)
    {
        $query = "
            WITH user_completed_flags AS (
                SELECT 
                    user_id,
                    challenge_template_id,
                    flag_id
                FROM completed_challenges
                WHERE user_id = ?
            ),
            challenge_total_flags AS (
                SELECT 
                    challenge_template_id, 
                    COUNT(*) as total_flags
                FROM challenge_flags
                GROUP BY challenge_template_id
            ),
            user_solved_challenges AS (
                SELECT 
                    ucf.user_id,
                    ucf.challenge_template_id
                FROM user_completed_flags ucf
                JOIN challenge_total_flags ctf ON ucf.challenge_template_id = ctf.challenge_template_id
                GROUP BY ucf.user_id, ucf.challenge_template_id
                HAVING COUNT(DISTINCT ucf.flag_id) = MAX(ctf.total_flags)
            )
            SELECT COUNT(*) 
            FROM user_solved_challenges
            WHERE user_id = ?";

        $stmt = $this->pdo->prepare($query);
        $stmt->execute([$this->userId, $this->userId]);
        $current = $stmt->fetchColumn();

        return ['current' => (int)$current, 'max' => $required];
    }

    private function calculateCategoryProgress($required, $category)
    {
        $query = "
            WITH user_completed_flags AS (
                SELECT 
                    cc.user_id,
                    cc.challenge_template_id,
                    cc.flag_id
                FROM completed_challenges cc
                WHERE cc.user_id = ?
            ),
            challenge_total_flags AS (
                SELECT 
                    cf.challenge_template_id, 
                    COUNT(*) as total_flags
                FROM challenge_flags cf
                JOIN challenge_templates ct ON ct.id = cf.challenge_template_id
                WHERE ct.category = ?::challenge_category
                GROUP BY cf.challenge_template_id
            ),
            user_solved_challenges AS (
                SELECT 
                    ucf.user_id,
                    ucf.challenge_template_id
                FROM user_completed_flags ucf
                JOIN challenge_total_flags ctf ON ucf.challenge_template_id = ctf.challenge_template_id
                GROUP BY ucf.user_id, ucf.challenge_template_id
                HAVING COUNT(DISTINCT ucf.flag_id) = MAX(ctf.total_flags)
            )
            SELECT COUNT(*) 
            FROM user_solved_challenges
            WHERE user_id = ?";

        $stmt = $this->pdo->prepare($query);
        $stmt->execute([$this->userId, $category, $this->userId]);
        $current = $stmt->fetchColumn();

        return ['current' => (int)$current, 'max' => $required];
    }

    private function calculatePointsProgress($required)
    {
        $query = "
            SELECT COALESCE(SUM(cf.points), 0) 
            FROM completed_challenges cc
            JOIN challenge_flags cf ON cf.id = cc.flag_id
            WHERE cc.user_id = ?";

        $stmt = $this->pdo->prepare($query);
        $stmt->execute([$this->userId]);
        $current = $stmt->fetchColumn();

        return ['current' => (int)$current, 'max' => $required];
    }

    private function calculateAllBadgesProgress($badgeId)
    {
        $totalQuery = "SELECT COUNT(*) FROM badges WHERE id != ?";
        $totalStmt = $this->pdo->prepare($totalQuery);
        $totalStmt->execute([$badgeId]);
        $total = $totalStmt->fetchColumn();

        $earnedQuery = "
            SELECT COUNT(*) 
            FROM user_badges ub
            JOIN badges b ON b.id = ub.badge_id
            WHERE ub.user_id = ? AND b.id != ?";

        $earnedStmt = $this->pdo->prepare($earnedQuery);
        $earnedStmt->execute([$this->userId, $badgeId]);
        $earned = $earnedStmt->fetchColumn();

        return ['current' => (int)$earned, 'max' => (int)$total];
    }

    private function fetchBadgeStats()
    {
        $query = "
            SELECT 
                (SELECT COUNT(*) FROM badges) as total_badges,
                (SELECT COUNT(*) FROM user_badges WHERE user_id = ?) as earned_badges";

        $stmt = $this->pdo->prepare($query);
        $stmt->execute([$this->userId]);
        $stats = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$stats || !isset($stats['total_badges'])) {
            logError("Failed to fetch badge stats for user ID: {$this->userId}");
            throw new Exception('Failed to fetch badge statistics', 500);
        }

        $stats['completion_rate'] = $stats['total_badges'] > 0 ?
            round(($stats['earned_badges'] / $stats['total_badges']) * 100) : 0;

        return [
            'total' => (int)$stats['total_badges'],
            'earned' => (int)$stats['earned_badges'],
            'completion_rate' => $stats['completion_rate']
        ];
    }

    private function sendResponse($badges, $stats)
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

try {
    $handler = new BadgesHandler($config);
    $handler->handleRequest();
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    logError("Error in badges endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}