<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class ProfileHandlerPublic
{
    private PDO $pdo;
    private ?int $userId;
    private string $requestedUsername;
    private array $generalConfig;
    private string $route;

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ILogger $logger;

    private ISession $session;
    private IServer $server;
    private IGet $get;
    private ICookie $cookie;

    /**
     * @throws Exception
     */
    public function __construct(
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
        $this->route = "/profile_view";

        $this->databaseHelper = $databaseHelper ?? new DatabaseHelper($logger, $system);
        $this->securityHelper = $securityHelper ?? new SecurityHelper($logger, $session, $system);
        $this->logger = $logger ?? new Logger(route: $this->route, system: $system);

        $this->generalConfig = $generalConfig;
        $this->pdo = $this->databaseHelper->getPDO();
        $this->requestedUsername = trim($this->get['username'] ?? '');
        $this->initSession();
        $this->validateRequest();
        $this->initializeUserData();
        $this->logger->logDebug("Initialized ProfileHandlerPublic for username: $this->requestedUsername");
    }

    /**
     * @throws Exception
     */
    private function initSession(): void
    {
        $this->securityHelper->initSecureSession();

        if (!$this->securityHelper->validateSession()) {
            $this->logger->logWarning("Unauthorized access attempt to profile - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new CustomException('Unauthorized', 401);
        }
    }

    /**
     * @throws Exception
     */
    private function validateRequest(): void
    {
        if (empty($this->requestedUsername)) {
            $this->logger->logError("Empty username requested - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new CustomException('Username is required', 400);
        }

        if (strlen($this->requestedUsername) > $this->generalConfig['user']['MAX_USERNAME_LENGTH'] ||
            strlen($this->requestedUsername) < $this->generalConfig['user']['MIN_USERNAME_LENGTH'] ||
            !preg_match('/' . $this->generalConfig['user']['USERNAME_REGEX'] . '/', $this->requestedUsername)) {
            $this->logger->logError("Invalid username format requested: $this->requestedUsername");
            throw new CustomException('Invalid username format', 400);
        }

        if (in_array($this->server['REQUEST_METHOD'], ['POST', 'PUT', 'DELETE', 'PATCH'])) {
            $csrfToken = $this->cookie['csrf_token'] ?? '';
            if (!$this->securityHelper->validateCsrfToken($csrfToken)) {
                $this->logger->logWarning("Invalid CSRF token in profile request - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
                throw new CustomException('Invalid CSRF token', 403);
            }
        }
    }

    /**
     * @throws Exception
     */
    private function initializeUserData(): void
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT get_id_by_username(:username) AS id
            ");
            $stmt->execute(['username' => $this->requestedUsername]);
            $user = $stmt->fetchColumn();

            if (!$user) {
                $this->logger->logError("User not found in profile view: $this->requestedUsername");
                throw new CustomException('Profile not found', 404);
            }

            $this->userId = (int)$user;
        } catch (PDOException $e) {
            $this->logger->logError("Database error during profile initialization: " . $e->getMessage());
            throw new CustomException('Database error occurred', 500);
        }
    }

    public function handleRequest(): void
    {
        try {
            $profileData = $this->getBasicProfileData();
            $stats = $this->getProfileStats();
            $badges = $this->getProfileBadges();

            $response = [
                'success' => true,
                'data' => [
                    'profile' => $this->sanitizeProfileData($profileData),
                    'stats' => $stats,
                    'badges' => $badges
                ]
            ];

            $this->sendResponse($response);
        } catch (CustomException $e) {
            $this->handleError($e);
        } // @codeCoverageIgnoreStart
        catch (Exception $e) {
            // most likely not reachable, gonna leave it here for safety
            $this->handleError(new Exception('Internal Server Error', 500));
        }
        // @codeCoverageIgnoreEnd
    }

    private function getBasicProfileData(): array
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT 
                    username,
                    created_at,
                    avatar_url,
                    bio,
                    github_url,
                    twitter_url,
                    website_url,
                    solved_count,
                    total_points
                FROM get_public_profile_data(:user_id)
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $profileData = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$profileData) {
                $this->logger->logError("Profile data not found for user ID: $this->userId");
                throw new CustomException('Profile data not found', 404);
            }

            $rankStmt = $this->pdo->prepare("
                SELECT get_user_rank(:user_id, :user_points) AS user_rank
            ");
            $rankStmt->execute([
                'user_points' => $profileData['total_points'],
                'user_id' => $this->userId
            ]);
            $rankData = $rankStmt->fetch(PDO::FETCH_ASSOC);

            return [
                'username' => $profileData['username'],
                'join_date' => $profileData['created_at'],
                'avatar_url' => $profileData['avatar_url'] ?? '/assets/avatars/default-avatar.png',
                'bio' => $profileData['bio'] ?? '',
                'social_links' => [
                    'github' => $profileData['github_url'] ?? '',
                    'twitter' => $profileData['twitter_url'] ?? '',
                    'website' => $profileData['website_url'] ?? ''
                ],
                'rank' => (int)($rankData['user_rank'] ?? 1),
                'points' => (int)$profileData['total_points'],
                'solved_count' => (int)$profileData['solved_count']
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getBasicProfileData: " . $e->getMessage());
            throw new CustomException('Could not load profile data', 500);
        }
    }

    private function getProfileStats(): array
    {
        try {
            $successStmt = $this->pdo->prepare("
                SELECT 
                    solved,
                    total_points,
                    attempts
                FROM get_profile_stats(:user_id)
            ");
            $successStmt->execute(['user_id' => $this->userId]);
            $successData = $successStmt->fetch(PDO::FETCH_ASSOC);

            if (!$successData) {
                $this->logger->logError("Failed to retrieve stats for user ID: $this->userId");
                throw new CustomException('Failed to retrieve profile statistics', 500);
            }

            $successRate = 0;
            if ($successData['attempts'] > 0) {
                $successRate = round(($successData['solved'] / $successData['attempts']) * 100);
            }

            $categoryData = $this->getCategoryData();

            return [
                'categories' => array_map('htmlspecialchars', $categoryData['categories']),
                'percentages' => array_map('intval', $categoryData['percentages']),
                'solved_counts' => array_map('intval', $categoryData['solved_counts']),
                'success_rate' => $successRate,
                'total_solved' => (int)$successData['solved'],
                'total_points' => (int)$successData['total_points'],
                'total_attempts' => (int)$successData['attempts']
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getProfileStats: " . $e->getMessage());
            throw new CustomException('Failed to retrieve profile statistics', 500);
        }
    }

    private function getCategoryData(): array
    {
        try {
            $stmt = $this->pdo->query("
                SELECT category FROM get_all_challenge_categories()
            ");
            $allCategories = $stmt->fetchAll(PDO::FETCH_COLUMN);

            if (empty($allCategories)) {
                $this->logger->logError("No challenge categories found in database");
                throw new CustomException('No challenge categories found', 500);
            }

            $totals = [];
            $stmt = $this->pdo->query("
                SELECT category, total FROM get_active_challenge_templates_by_category()
            ");
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $totals[$row['category']] = (int)$row['total'];
            }

            $stmt = $this->pdo->prepare("
                SELECT category, solved FROM get_user_solved_challenge_count_by_categories(:user_id)
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $solved = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);

            $percentages = [];
            foreach ($allCategories as $category) {
                $total = $totals[$category] ?? 0;
                $solvedCount = $solved[$category] ?? 0;
                $percentages[$category] = $total > 0 ? round(($solvedCount / $total) * 100) : 0;
            }

            return [
                'categories' => $allCategories,
                'percentages' => $percentages,
                'solved_counts' => array_replace(array_fill_keys($allCategories, 0), $solved)
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getCategoryData: " . $e->getMessage());
            throw new CustomException('Failed to retrieve category data', 500);
        }
    }

    private function getProfileBadges(): array
    {
        try {
            $badgeStmt = $this->pdo->prepare("
                SELECT
                    id,
                    name,
                    description,
                    icon,
                    color
                FROM get_user_earned_badges_data(:user_id)
            ");
            $badgeStmt->execute(['user_id' => $this->userId]);
            $badges = $badgeStmt->fetchAll(PDO::FETCH_ASSOC);

            $sanitizedBadges = array_map(function ($badge) {
                return [
                    'id' => (int)$badge['id'],
                    'name' => htmlspecialchars($badge['name']),
                    'description' => htmlspecialchars($badge['description']),
                    'icon' => $badge['icon'],
                    'color' => $badge['color']
                ];
            }, $badges);

            $totalStmt = $this->pdo->query("
                SELECT get_total_badges_count() AS total
            ");
            $totalBadges = (int)$totalStmt->fetch(PDO::FETCH_ASSOC)['total'];

            $earnedCount = count($sanitizedBadges);

            return [
                'badges' => $sanitizedBadges,
                'earned_count' => $earnedCount,
                'total_badges' => $totalBadges
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getProfileBadges: " . $e->getMessage());
            throw new CustomException('Failed to retrieve badge information', 500);
        }
    }

    private function sanitizeProfileData(array $data): array
    {
        return [
            'username' => htmlspecialchars($data['username']),
            'join_date' => $data['join_date'],
            'avatar_url' => filter_var($data['avatar_url'], FILTER_SANITIZE_URL),
            'bio' => htmlspecialchars($data['bio'] ?? ''),
            'social_links' => [
                'github' => filter_var($data['social_links']['github'] ?? '', FILTER_SANITIZE_URL),
                'twitter' => filter_var($data['social_links']['twitter'] ?? '', FILTER_SANITIZE_URL),
                'website' => filter_var($data['social_links']['website'] ?? '', FILTER_SANITIZE_URL)
            ],
            'rank' => (int)$data['rank'],
            'points' => (int)$data['points'],
            'solved_count' => (int)$data['solved_count']
        ];
    }

    private function sendResponse(array $response): void
    {
        echo json_encode($response);
    }

    private function handleError(Exception $e): void
    {
        $errorCode = $e->getCode() ?: 500;
        $errorMessage = $e->getMessage();

        if ($errorCode === 401) {
            // @codeCoverageIgnoreStart
            // This block is probably not reachable since authentication is required to reach this point
            // Wont be deleted for security reasons
            $this->session->unset();
            $this->session->destroy();
            $this->logger->logWarning("Session destroyed due to unauthorized access");
            // @codeCoverageIgnoreEnd
        }

        if ($errorCode >= 500) {
            $errorMessage = 'An internal server error occurred';
            $this->logger->logError("Internal error : " . $e->getMessage());
        } else {
            $this->logger->logError("Profile error: " . $e->getMessage());
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
    header('Content-Type: application/json');
    $system = new SystemWrapper();
    $generalConfig = json_decode($system->file_get_contents(__DIR__ . '/../config/general.config.json'), true);

    $handler = new ProfileHandlerPublic(generalConfig: $generalConfig);
    $handler->handleRequest();
} catch (CustomException $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    $logger = new Logger("/profile_view");
    $logger->logError("Error in profile_view endpoint: " . $e->getMessage() . " (Code: $errorCode)");
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
    $logger = new Logger("/profile_view");
    $logger->logError("Unexpected error in profile_view endpoint: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'message' => 'An unexpected error occurred'
    ]);
}

// @codeCoverageIgnoreEnd
