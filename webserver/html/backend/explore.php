<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class ExploreHandler
{
    private PDO $pdo;
    private ?int $userId;
    private bool $isPublic = true;
    private array $config;
    private int $perPage = 12;
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
        array $config,

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
        $this->route = "/explore";

        $this->databaseHelper = $databaseHelper ?? new DatabaseHelper($logger, $system);
        $this->securityHelper = $securityHelper ?? new SecurityHelper($logger, $session, $system);
        $this->logger = $logger ?? new Logger(route: $this->route, system: $system);

        $this->config = $config;
        $this->initSession();
        $this->validateRequest();
        $this->pdo = $this->databaseHelper->getPDO();
        $this->userId = $this->session['user_id'] ?? null;
        $this->logger->logDebug("Initialized ExploreHandler for user ID: " . ($this->userId ?? 'guest'));
    }

    /**
     * @throws Exception
     */
    private function initSession(): void
    {
        $this->securityHelper->initSecureSession();

        if (!$this->isPublic && !$this->securityHelper->validateSession()) {
            // @codeCoverageIgnoreStart
            // This branch cananot be tested when isPublic is set to true by default
            $this->logger->logWarning('Unauthorized access attempt to explore route');
            throw new CustomException('Unauthorized - Please login', 401);
            // @codeCoverageIgnoreEnd
        }
    }

    /**
     * @throws Exception
     */
    private function validateRequest(): void
    {
        if (!$this->isPublic) {
            // @codeCoverageIgnoreStart
            // This branch cananot be tested when isPublic is set to true by default
            $csrfToken = $this->cookie['csrf_token'] ?? '';
            if (!$this->securityHelper->validateCsrfToken($csrfToken)) {
                $this->logger->logWarning('Invalid CSRF token attempt from user: ' . ($this->session['user_id'] ?? 'unknown'));
                throw new CustomException('Invalid CSRF token.', 403);
            }
            // @codeCoverageIgnoreEnd
        }
    }

    /**
     * @throws Exception
     */
    public function handleRequest(): void
    {
        try {
            $params = $this->parseInputParameters();
            $challenges = $this->fetchChallenges($params);
            $response = $this->buildResponse($challenges, $params);

            $this->sendResponse($response);
        } catch (PDOException $e) {
            $this->logger->logError("Database error in explore route: " . $e->getMessage());
            throw new CustomException('Failed to retrieve challenges', 500);
        }
    }

    private function parseInputParameters(): array
    {
        $search = $this->get['search'] ?? '';
        $category = $this->get['category'] ?? 'all';
        $difficulty = $this->get['difficulty'] ?? 'all';
        $sort = $this->get['sort'] ?? 'popularity';
        $page = isset($this->get['page']) ? (int)$this->get['page'] : 1;

        if (!in_array($category, $this->config['filters']['CHALLENGE_CATEGORIES'])) {
            $this->logger->logDebug("Invalid category requested: $category - Defaulting to 'all'");
            $category = 'all';
        }

        if (!in_array($difficulty, $this->config['filters']['CHALLENGE_DIFFICULTIES'])) {
            $this->logger->logDebug("Invalid difficulty requested: $difficulty - Defaulting to 'all'");
            $difficulty = 'all';
        }

        if (!in_array($sort, $this->config['sorts']['VALID'])) {
            $this->logger->logDebug("Invalid sort requested: $sort - Defaulting to 'popularity'");
            $sort = 'popularity';
        }

        if ($page < 1) {
            $this->logger->logDebug("Invalid page number requested: $page - Defaulting to 1");
            $page = 1;
        }

        $search_param = !empty($search) ? "%$search%" : '';

        return [
            'search' => $search,
            'search_param' => $search_param,
            'category' => $category,
            'difficulty' => $difficulty,
            'sort' => $sort,
            'page' => $page
        ];
    }

    private function fetchChallenges($params): array
    {
        $offset = ($params['page'] - 1) * $this->perPage;

        $countStmt = $this->pdo->prepare("
            SELECT explore_challenges_count(:category, :difficulty, :search) AS total
        ");
        $countStmt->execute([
            ':category' => $params['category'] === 'all' ? null : $params['category'],
            ':difficulty' => $params['difficulty'] === 'all' ? null : $params['difficulty'],
            ':search' => $params['search_param'] === '' ? null : $params['search_param']
        ]);
        $totalItems = (int)$countStmt->fetchColumn();

        $stmt = $this->pdo->prepare("
            SELECT 
                id,
                name,
                description,
                category,
                difficulty,
                created_at,
                image_path,
                is_active,
                solved_count,
                attempted_count
            FROM explore_challenges(:category, :difficulty, :search, :order_by, :limit, :offset)
        ");
        $stmt->execute([
            ':category' => $params['category'] === 'all' ? null : $params['category'],
            ':difficulty' => $params['difficulty'] === 'all' ? null : $params['difficulty'],
            ':search' => $params['search_param'] === '' ? null : $params['search_param'],
            ':order_by' => $params['sort'],
            ':limit' => $this->perPage,
            ':offset' => $offset
        ]);
        $challenges = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return [
            'data' => $challenges,
            'total_items' => $totalItems,
            'current_page' => $params['page'],
            'total_pages' => ceil($totalItems / $this->perPage)
        ];
    }

    private function buildResponse($challenges, $params): array
    {
        $formattedChallenges = array_map([$this, 'formatChallenge'], $challenges['data']);

        return [
            'challenges' => $formattedChallenges,
            'pagination' => [
                'current_page' => $challenges['current_page'],
                'total_pages' => $challenges['total_pages'],
                'total_items' => $challenges['total_items'],
                'per_page' => $this->perPage
            ],
            'filters' => [
                'search' => htmlspecialchars($params['search'], ENT_QUOTES, 'UTF-8'),
                'category' => htmlspecialchars($params['category'], ENT_QUOTES, 'UTF-8'),
                'difficulty' => htmlspecialchars($params['difficulty'], ENT_QUOTES, 'UTF-8'),
                'sort' => htmlspecialchars($params['sort'], ENT_QUOTES, 'UTF-8')
            ]
        ];
    }

    private function formatChallenge($challenge): array
    {
        $solvedStatus = $this->userId ? $this->getUserChallengeData($challenge['id']) : null;

        return [
            'id' => (int)$challenge['id'],
            'title' => htmlspecialchars($challenge['name'], ENT_QUOTES, 'UTF-8'),
            'description' => htmlspecialchars($challenge['description'], ENT_QUOTES, 'UTF-8'),
            'category' => htmlspecialchars($challenge['category'], ENT_QUOTES, 'UTF-8'),
            'difficulty' => htmlspecialchars($challenge['difficulty'], ENT_QUOTES, 'UTF-8'),
            'image' => htmlspecialchars($challenge['image_path'] ?? '../assets/images/ctf-default.png', ENT_QUOTES, 'UTF-8'),
            'created_at' => $challenge['created_at'],
            'is_active' => $challenge['is_active'],
            'solved' => $solvedStatus
        ];
    }

    private function getUserChallengeData($challengeId)
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT get_user_solved_challenge(:user_id, :challenge_template_id) AS solved
            ");
            $stmt->execute([
                ':user_id' => $this->userId,
                ':challenge_template_id' => $challengeId
            ]);
            $data = $stmt->fetchColumn();

            return $data;
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getUserChallengeData for user $this->userId and challenge $challengeId: " . $e->getMessage());
            return null;
        }
    }

    private function sendResponse($response): void
    {
        echo json_encode(['success' => true, 'data' => $response]);
    }
}

// @codeCoverageIgnoreStart

if(defined('PHPUNIT_RUNNING'))
    return;

try {
    header('Content-Type: application/json');
    $config = require __DIR__ . '/../config/backend.config.php';

    $handler = new ExploreHandler(config: $config);
    $handler->handleRequest();
} catch (CustomException $e) {
    $errorCode = $e->getCode() ?: 500;
    $errorMessage = $e->getMessage();
    $logger = new Logger("/explore");

    if ($errorCode === 401) {
        $this->session->unset();
        $this->session->destroy();
        $logger->logWarning("Session destroyed due to unauthorized access");
    }

    if ($errorCode >= 500) {
        $errorMessage = 'An internal server error occurred';
        $logger->logError("Internal error: " . $e->getMessage() . "\n" . $e->getTraceAsString());
    } else {
        $logger->logError("Explore endpoint error: " . $e->getMessage());
    }

    http_response_code($errorCode);
    echo json_encode([
        'success' => false,
        'message' => $errorMessage,
        'redirect' => $errorCode === 401 ? '/login' : null
    ]);
} catch (Exception $e) {
    http_response_code(500);
    $logger = new Logger("/explore");
    $logger->logError("Unexpected error in explore endpoint: " . $e->getMessage() . "\n" . $e->getTraceAsString());
    echo json_encode([
        'success' => false,
        'message' => 'An unexpected error occurred'
    ]);
}

// @codeCoverageIgnoreEnd