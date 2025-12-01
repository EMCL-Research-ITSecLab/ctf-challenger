<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class DashboardHandler
{
    private PDO $pdo;
    private ?int $userId;
    private string $dataType;
    private ?string $range;
    private ?string $view;
    private array $config;
    private string $route;

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ILogger $logger;
    private IChallengeHelper $challengeHelper;

    private ISession $session;
    private IServer $server;
    private IGet $get;
    private ICookie $cookie;

    /**
     * @throws Exception
     */
    public function __construct(
        array $config,

        IDatabaseHelper $databaseHelper = null,
        ISecurityHelper $securityHelper = null,
        ILogger $logger = null,
        IChallengeHelper $challengeHelper = null,

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
        $this->route = "/dashboard";

        $this->databaseHelper = $databaseHelper ?? new DatabaseHelper($logger, $system);
        $this->securityHelper = $securityHelper ?? new SecurityHelper($logger, $session, $system);
        $this->logger = $logger ?? new Logger(route: $this->route, system: $system);
        $this->challengeHelper = $challengeHelper ?? new ChallengeHelper();

        $this->config = $config;
        $this->pdo = $this->databaseHelper->getPDO();
        $this->dataType = $this->get['type'] ?? 'all';
        $this->range = $this->get['range'] ?? null;
        $this->view = $this->get['view'] ?? null;
        $this->initSession();
        $this->userId = $this->session['user_id'];
        $this->validateRequest();
        $this->logger->logDebug("Initialized DashboardHandler for user ID: $this->userId, Data type: $this->dataType");
    }

    /**
     * @throws Exception
     */
    private function initSession(): void
    {
        $this->securityHelper->initSecureSession();

        if (!$this->securityHelper->validateSession()) {
            $this->logger->logWarning("Unauthorized access attempt to dashboard - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new CustomException('Unauthorized - Please login', 401);
        }
    }

    /**
     * @throws Exception
     */
    private function validateRequest(): void
    {
        $csrfToken = $this->cookie['csrf_token'] ?? '';
        if (!$this->securityHelper->validateCsrfToken($csrfToken)) {
            $this->logger->logWarning("Invalid CSRF token in dashboard - User ID: $this->userId, Token: $csrfToken");
            throw new CustomException('Invalid CSRF token', 403);
        }

        if (!in_array($this->dataType, $this->config['dashboard']['VALID_DATA_TYPES'])) {
            $this->logger->logWarning("Invalid data type requested - User ID: $this->userId, Type: $this->dataType");
            throw new CustomException('Invalid data type requested', 400);
        }
    }

    public function handleRequest(): void
    {
        try {
            $response = $this->getDashboardData();
            $this->sendResponse($response);
        } catch (CustomException $e) {
            $this->handleError($e);
        } catch (Exception $e) {
            $this->handleError(new Exception('Internal Server Error', 500));
        }
    }

    /**
     * @throws Exception
     */
    private function getDashboardData(): array
    {
        switch ($this->dataType) {
            case 'user':
                $data = $this->getUserData();
                $this->logger->logDebug("Retrieved user data for user $this->userId");
                break;

            case 'progress':
                $data = $this->getProgressData();
                $this->logger->logDebug("Retrieved progress data for user $this->userId");
                break;

            case 'category':
                $data = $this->getCategoryData();
                $this->logger->logDebug("Retrieved category data for user $this->userId");
                break;

            case 'activity':
                $data = $this->getActivityData();
                $this->logger->logDebug("Retrieved activity data for user $this->userId");
                break;

            case 'badges':
                $data = $this->getBadgesData();
                $this->logger->logDebug("Retrieved badges data for user $this->userId");
                break;

            case 'active_challenge':
                $data = $this->getActiveChallengeData();
                $this->logger->logDebug("Retrieved active challenge data for user $this->userId");
                break;

            case 'challenges':
                $data = $this->getChallengesData();
                $this->logger->logDebug("Retrieved challenges data for user $this->userId");
                break;

            case 'timeline':
                $data = $this->getTimelineData($this->range, $this->view);
                $this->logger->logDebug("Retrieved timeline data for user $this->userId");
                break;

            case 'news':
                $data = $this->getLatestNews();
                $this->logger->logDebug("Retrieved latest news");
                break;

            default:
                $data = [
                    'user' => $this->getUserData(),
                    'progress' => $this->getProgressData(),
                    'category' => $this->getCategoryData(),
                    'activity' => $this->getActivityData(5),
                    'badges' => $this->getBadgesData(),
                    'active_challenge' => $this->getActiveChallengeData(),
                    'challenges' => $this->getChallengesData(),
                    'timeline' => $this->getTimelineData('week', 'daily'),
                    'news' => $this->getLatestNews()
                ];
                $this->logger->logDebug("Retrieved complete dashboard data for user $this->userId");
        }

        return ['success' => true, 'data' => $data];
    }

    /**
     * @throws Exception
     */
    private function getUserData(): array
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT
                    username,
                    total_points,
                    solved_count,
                    user_rank
                FROM get_user_data_dashboard(:user_id)
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $userData = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$userData) {
                $this->logger->logError("User not found in getUserData: $this->userId");
                throw new CustomException('User not found', 404);
            }

            return [
                'username' => htmlspecialchars($userData['username']),
                'rank' => (int)$userData['user_rank'],
                'points' => (int)$userData['total_points']
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getUserData: " . $e->getMessage());
            throw new CustomException('Failed to retrieve user data', 500);
        }
    }

    /**
     * @throws Exception
     */
    private function getProgressData(): array
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT
                    solved_count,
                    failed_count,
                    total_attempts,
                    avg_time_seconds
                FROM get_progress_data_dashboard(:user_id)
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $progress = $stmt->fetch(PDO::FETCH_ASSOC);

            $stmt = $this->pdo->prepare("SELECT get_total_active_challenges_count_dashboard() AS total_challenges");
            $stmt->execute();
            $total = $stmt->fetch(PDO::FETCH_ASSOC);

            $solved = (int)($progress['solved_count'] ?? 0);
            $failed = (int)($progress['failed_count'] ?? 0);
            $unsolved = max(0, (int)($total['total_challenges'] ?? 0) - $solved);

            $avgTimeSeconds = isset($progress['avg_time_seconds'])
                ? max(0, (float)$progress['avg_time_seconds'])
                : 0;

            $successRate = isset($progress['total_attempts']) && $progress['total_attempts'] > 0
                ? round(($solved / $progress['total_attempts']) * 100)
                : 0;

            return [
                'solved' => $solved,
                'failed' => $failed,
                'unsolved' => $unsolved,
                'success_rate' => $successRate,
                'avg_time' => $this->formatTime($avgTimeSeconds)
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getProgressData: " . $e->getMessage());
            throw new CustomException('Failed to retrieve progress data', 500);
        }
    }

    private function formatTime(float $seconds): string
    {
        if ($seconds < 60) {
            return round($seconds) . 's';
        } elseif ($seconds < 3600) {
            return round($seconds / 60) . 'm';
        } elseif ($seconds < 86400) {
            return round($seconds / 3600, 1) . 'h';
        }
        return round($seconds / 86400, 1) . 'd';
    }

    /**
     * @throws Exception
     */
    private function getCategoryData(): array
    {
        try {
            $stmt = $this->pdo->query("
                SELECT category FROM get_all_challenge_categories()
            ");
            $allCategories = $stmt->fetchAll(PDO::FETCH_COLUMN);

            $totals = [];
            $stmt = $this->pdo->query("
                SELECT category, total FROM get_challenge_count_by_categories()
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

            return ['percentages' => $percentages];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getCategoryData: " . $e->getMessage());
            throw new CustomException('Failed to retrieve category data', 500);
        }
    }

    /**
     * @throws Exception
     */
    private function getActivityData(int $limit = 5): array
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT
                    challenge_id,
                    challenge_name,
                    category,
                    solved_points,
                    current_points,
                    solved,
                    attempts,
                    started_at,
                    completed_at,
                    status,
                    time_ago
                FROM get_user_activity_dashboard(:user_id, :limit)
            ");

            $stmt->bindValue(':user_id', $this->userId, PDO::PARAM_INT);
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->execute();

            $activities = [];
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $points = $row['solved']
                    ? (int)$row['solved_points']
                    : (int)$row['current_points'];

                $activities[] = [
                    'challenge_id' => (int)$row['challenge_id'],
                    'challenge' => htmlspecialchars($row['challenge_name']),
                    'category' => htmlspecialchars($row['category']),
                    'points' => $points,
                    'status' => $row['status'],
                    'attempts' => (int)$row['attempts'],
                    'time_ago' => $row['time_ago'],
                    'started_at' => $row['started_at']
                ];
            }

            return $activities;
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getActivityData: " . $e->getMessage());
            throw new CustomException('Failed to retrieve activity data', 500);
        }
    }

    /**
     * @throws Exception
     */
    private function getBadgesData(): array
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT 
                    id,
                    name,
                    description,
                    icon,
                    color
                FROM get_user_badges_data_dashboard(:user_id) b
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $badges = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $sanitizedBadges = [];
            foreach ($badges as $badge) {
                $sanitizedBadges[] = [
                    'id' => (int)$badge['id'],
                    'name' => htmlspecialchars($badge['name']),
                    'description' => htmlspecialchars($badge['description']),
                    'icon' => htmlspecialchars($badge['icon']),
                    'color' => htmlspecialchars($badge['color'])
                ];
            }

            $stmt = $this->pdo->prepare("
                SELECT
                    solved_count,
                    total_badges,
                    earned_badges
                FROM get_user_progress_data_dashboard(:user_id)                
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $progress = $stmt->fetch(PDO::FETCH_ASSOC);

            $nextBadgeProgress = isset($progress['total_badges']) && $progress['total_badges'] > 0
                ? round(
                    ($progress['earned_badges'] /
                        ($progress['earned_badges'] == $progress['total_badges']
                            ? $progress['total_badges']
                            : max(1, $progress['total_badges'] - 1)
                        )
                    ) * 100
                )
                : 0;

            return [
                'earned' => $sanitizedBadges,
                'next_badge' => [
                    'name' => 'Master Hacker',
                    'progress' => $nextBadgeProgress,
                    'requirements' => 'Earn all badges',
                    'solved_count' => (int)($progress['solved_count'] ?? 0)
                ]
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getBadgesData: " . $e->getMessage());
            throw new CustomException('Failed to retrieve badges data', 500);
        }
    }

    /**
     * @throws Exception
     */
    private function getChallengesData(): array
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT
                    id,
                    name,
                    category,
                    points,
                    difficulty,
                    solved_count,
                    attempted_count
                FROM get_challenges_data_dashboard(:user_id)
            ");

            $stmt->execute(['user_id' => $this->userId]);

            $challenges = [];
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $attempted = (int)($row['attempted_count'] ?? 0);
                $solved = (int)($row['solved_count'] ?? 0);
                $successRate = $attempted > 0 ? round(($solved / $attempted) * 100) : 0;

                $challenges[] = [
                    'id' => (int)$row['id'],
                    'name' => htmlspecialchars($row['name']),
                    'category' => htmlspecialchars($row['category']),
                    'points' => (int)$row['points'],
                    'difficulty' => htmlspecialchars($row['difficulty']),
                    'success_rate' => $successRate . '%'
                ];
            }

            return $challenges;
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getChallengesData: " . $e->getMessage());
            throw new CustomException('Failed to retrieve challenges data', 500);
        }
    }

    /**
     * @throws Exception
     */
    private function getTimelineData(string $range = 'week', string $viewType = 'daily'): array
    {
        try {
            $endDate = new DateTime();
            $startDate = clone $endDate;

            switch ($range) {
                case 'week':
                    $dateFormat = 'YYYY-MM-DD';
                    $startDate->modify('-6 days');
                    $labelFormat = 'D';
                    break;
                case 'month':
                    $dateFormat = 'YYYY-MM-DD';
                    $startDate->modify('-29 days');
                    $labelFormat = 'j M';
                    break;
                case 'year':
                    $dateFormat = 'YYYY-MM';
                    $startDate->modify('-11 months');
                    $labelFormat = 'M';
                    break;
                default:
                    throw new CustomException('Invalid time range specified', 400);
            }

            if (!in_array($viewType, ['daily', 'cumulative'])) {
                throw new CustomException('Invalid timeline view type specified', 400);
            }

            $stmt = $this->pdo->prepare("
                SELECT
                    date_group,
                    points_sum,
                    challenge_count,
                    challenge_details
                FROM get_timeline_data_dashboard(:user_id, :start_date, :end_date, :range, :date_format)
            
            ");
            $stmt->execute([
                'user_id' => $this->userId,
                'start_date' => $startDate->format('Y-m-d'),
                'end_date' => $endDate->format('Y-m-d'),
                'range' => $range,
                'date_format' => $dateFormat
            ]);

            $labels = [];
            $points = [];
            $challenges = [];
            $details = [];

            $currentDate = clone $startDate;
            while ($currentDate <= $endDate) {
                $formattedDate = $currentDate->format($range === 'year' ? 'Y-m' : 'Y-m-d');
                $labels[] = $currentDate->format($labelFormat);
                $points[$formattedDate] = 0;
                $challenges[$formattedDate] = 0;
                $details[$formattedDate] = [];

                if ($range === 'week' || $range === 'month') {
                    $currentDate->modify('+1 day');
                } else {
                    $currentDate->modify('+1 month');
                }
            }

            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                if (isset($points[$row['date_group']])) {
                    $points[$row['date_group']] = (int)$row['points_sum'];
                    $challenges[$row['date_group']] = (int)$row['challenge_count'];

                    if ($row['challenge_details']) {
                        foreach (explode(',', $row['challenge_details']) as $detail) {
                            if (!empty($detail)) {
                                list($name, $category, $pointsVal) = explode('|', $detail);
                                $details[$row['date_group']][] = [
                                    'name' => htmlspecialchars($name),
                                    'category' => htmlspecialchars($category),
                                    'points' => (int)$pointsVal
                                ];
                            }
                        }
                    }
                }
            }

            if ($viewType === 'cumulative') {
                $points = $this->accumulateArray(array_values($points));
                $challenges = $this->accumulateArray(array_values($challenges));
            } else {
                $points = array_values($points);
                $challenges = array_values($challenges);
            }

            return [
                'labels' => $labels,
                'points' => $points,
                'challenges' => $challenges,
                'details' => array_values($details)
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getTimelineData: " . $e->getMessage());
            throw new CustomException('Failed to retrieve timeline data', 500);
        }
    }

    /**
     * @throws Exception
     */
    private function getLatestNews(): array
    {
        try {
            $stmt = $this->pdo->query("
                SELECT 
                    id,
                    title,
                    short_description,
                    importance,
                    category,
                    author,
                    created_at
                FROM get_announcements_data_dashboard()
            ");
            $news = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $sanitizedNews = [];
            foreach ($news as $item) {
                $sanitizedNews[] = [
                    'id' => (int)$item['id'],
                    'title' => htmlspecialchars($item['title']),
                    'short_description' => htmlspecialchars($item['short_description']),
                    'importance' => htmlspecialchars($item['importance']),
                    'category' => htmlspecialchars($item['category']),
                    'author' => htmlspecialchars($item['author']),
                    'created_at' => $item['created_at']
                ];
            }

            return $sanitizedNews;
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getLatestNews: " . $e->getMessage());
            throw new CustomException('Failed to retrieve latest news', 500);
        }
    }

    /**
     * @throws Exception
     */
    private function getActiveChallengeData(): ?array
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT get_user_running_challenge(:user_id) AS running_challenge
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$result || !$result['running_challenge']) {
                return null;
            }

            $runningChallengeId = $result['running_challenge'];

            $stmt = $this->pdo->prepare("
                SELECT get_challenge_template_id_from_challenge_id(:running_challenge_id) AS challenge_template_id
            ");
            $stmt->execute(['running_challenge_id' => $runningChallengeId]);
            $challenge_template_id = (int)$stmt->fetchColumn();

            $elapsedSeconds = $this->challengeHelper->getElapsedSecondsForChallenge($this->pdo,$this->userId,$challenge_template_id);

            $stmt = $this->pdo->prepare("
                SELECT 
                    id,
                    name,
                    category,
                    difficulty,
                    points,
                    current_attempt_started_at,
                    completed_challenge_id
                FROM get_running_challenge_data_dashboard(:user_id, :challenge_template_id)
            ");
            $stmt->execute([
                'challenge_template_id' => $challenge_template_id,
                'user_id' => $this->userId
            ]);

            $challenge = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$challenge) {
                $this->logger->logError("Challenge details not found for running challenge ID: $runningChallengeId");
                return null;
            }

            return [
                'id' => (int)$challenge['id'],
                'name' => htmlspecialchars($challenge['name']),
                'category' => htmlspecialchars($challenge['category']),
                'difficulty' => htmlspecialchars($challenge['difficulty']),
                'points' => (int)$challenge['points'],
                'started_at' => $challenge['current_attempt_started_at'],
                'elapsedSeconds' => $elapsedSeconds,
                'isSolved' => $this->challengeHelper->isChallengeSolved($this->pdo, $this->userId, $challenge['id']),
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getActiveChallengeData: " . $e->getMessage());
            throw new CustomException('Failed to retrieve active challenge data', 500);
        }
    }

    private function accumulateArray(array $input): array
    {
        $output = [];
        $sum = 0;
        foreach ($input as $value) {
            $sum += $value;
            $output[] = $sum;
        }
        return $output;
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
            $this->session->unset();
            $this->session->destroy();
            $this->logger->logWarning("Session destroyed due to unauthorized access");
        }

        if ($errorCode >= 500) {
            $errorMessage = 'An internal server error occurred';
            $this->logger->logError("Internal error : " . $e->getMessage());
        } else {
            $this->logger->logError("Dashboard error: " . $e->getMessage());
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
    $config = require __DIR__ . '/../config/backend.config.php';

    $handler = new DashboardHandler(config: $config);
    $handler->handleRequest();
} catch (CustomException $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    $logger = new Logger("/dashboard");
    $logger->logError("Error in dashboard endpoint: " . $e->getMessage() . " (Code: $errorCode)");
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
    $logger = new Logger("/dashboard");
    $logger->logError("Unexpected error in dashboard endpoint: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'message' => 'An unexpected error occurred'
    ]);
}

// @codeCoverageIgnoreEnd