<?php

// @codeCoverageIgnoreStart
if (defined('PHPUNIT_RUNNING')) 
    require_once __DIR__ . '/../../vendor/autoload.php';
else
    require_once '/var/www/html/vendor/autoload.php';
// @codeCoverageIgnoreEnd


class ChallengeWorker
{
    private PDO $pdo;
    private IDatabaseHelper $databaseHelper;
    private ICurlHelper $curlHelper;
    private IAuthHelper $authHelper;
    private bool $logErrors;
    private ISystem $system;

    public function __construct(
        IDatabaseHelper $databaseHelper = null,
        ICurlHelper $curlHelper = null,
        IAuthHelper $authHelper = null,
        
        bool $logErrors = true,
        ISystem $system = new SystemWrapper(),
        IEnv $env = new Env(),
        ILogger $logger = null
        
    ) {        
        $this->logErrors = $logErrors;
        $this->databaseHelper = $databaseHelper ?? new DatabaseHelper($logger, $system);
        $this->curlHelper = $curlHelper ?? new CurlHelper($env);
        $this->authHelper = $authHelper ?? new AuthHelper($logger, $system, $env);

        $this->pdo = $this->databaseHelper->getPDO();
        $this->system = $system;
    }

    public function run(): void
    {
        try {
            $expiredChallenges = $this->getExpiredChallenges();

            if (empty($expiredChallenges)) {
                $this->logMessage("No expired challenges found.");
                return;
            }

            foreach ($expiredChallenges as $challenge) {
                $this->processExpiredChallenge($challenge);
            }

            $this->logMessage("Successfully processed " . count($expiredChallenges) . " expired challenges.");

        } catch (CustomException $e) {
            $this->logError("ChallengeWorker error: " . $e->getMessage());
            $this->logMessage("Error processing challenges: " . $e->getMessage());
        } catch (Exception $e) {
            $this->logError("Unexpected error: " . $e->getMessage());
            $this->logMessage("Unexpected error: " . $e->getMessage());
        }
    }

    private function getExpiredChallenges(): array
    {
        $stmt = $this->pdo->prepare("
            SELECT
                user_id,
                username,
                challenge_id,
                challenge_template_id,
                expires_at
            FROM get_expired_challenge_data()
        ");

        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * @throws Exception
     */
    private function processExpiredChallenge($challenge): void
    {
        $this->pdo->beginTransaction();

        try {
            $this->stopChallenge($challenge['user_id']);
            $this->markAttemptAsCompleted($challenge['user_id'], $challenge['challenge_template_id']);
            $this->logUserNetworkTraceStop($challenge['user_id'], $challenge['challenge_template_id']);
            if ($this->shouldDeleteChallengeTemplate($challenge['challenge_template_id'])) {
                $this->deleteChallengeTemplate($challenge['challenge_template_id']);
            }

            $this->pdo->commit();

            $this->logError("Successfully processed expired challenge for user {$challenge['username']} (ID: {$challenge['user_id']})");

        } catch (CustomException $e) {
            $this->pdo->rollBack();
            $this->logError("Failed to process expired challenge for user {$challenge['username']}: " . $e->getMessage());
            throw $e;
        } catch (Exception $e) {
            $this->pdo->rollBack();
            $this->logError("Unexpected error: " . $e->getMessage());
            $this->logMessage("Unexpected error: " . $e->getMessage());
            throw $e;
        }
    }

    /**
     * @throws Exception
     */
    private function stopChallenge($userId): void
    {
        $result = $this->curlHelper->makeBackendRequest(
            '/stop-challenge',
            'POST',
            $this->authHelper->getBackendHeaders(),
            ['user_id' => $userId]
        );

        if (!$result['success'] || $result['http_code'] !== 200) {
            throw new CustomException("Failed to stop challenge: " . ($result['error'] ?? "HTTP {$result['http_code']}"));
        }
    }

    private function markAttemptAsCompleted($userId, $challengeTemplateId): void
    {
        $stmt = $this->pdo->prepare("
            SELECT * FROM mark_attempt_completed(:user_id, :challenge_id)
        ");
        $stmt->execute([
            'user_id' => $userId,
            'challenge_id' => $challengeTemplateId
        ]);
    }

    private function logUserNetworkTraceStop($userId, $challengeTemplateId): void
    {
        $stmt = $this->pdo->prepare("
            SELECT stop_user_network_trace(:userid, :challenge_template_id)
        ");
        $stmt->execute([
            'userid' => $userId,
            'challenge_template_id' => $challengeTemplateId
        ]);
    }

    private function shouldDeleteChallengeTemplate($challengeTemplateId): bool
    {
        $stmt = $this->pdo->prepare("
            SELECT challenge_template_should_be_deleted(:template_id) AS remaining_instances
        ");
        $stmt->execute(['template_id' => $challengeTemplateId]);
        return $stmt->fetchColumn() == 1;
    }

    /**
     * @throws Exception
     */
    private function deleteChallengeTemplate($challengeTemplateId): void
    {
        $result = $this->curlHelper->makeBackendRequest(
            '/delete-machine-templates',
            'POST',
            $this->authHelper->getBackendHeaders(),
            ['challenge_id' => $challengeTemplateId]
        );

        if (!$result['success'] || $result['http_code'] !== 200) {
            throw new CustomException("Failed to delete VM templates: " . ($result['error'] ?? "HTTP {$result['http_code']}"));
        }

        $stmt = $this->pdo->prepare("
            SELECT delete_challenge_template(:challenge_id)
        ");
        $stmt->execute(['challenge_id' => $challengeTemplateId]);

        $this->logMessage("Successfully deleted challenge template ID $challengeTemplateId");
    }

    private function logMessage($message): void
    {
        echo "[" . $this->system->date('Y-m-d H:i:s') . "] $message\n";
    }
    
    private function logError($message): void
    {
        if(!$this->logErrors)
            return;

        // @codeCoverageIgnoreStart
        error_log($message);
        // @codeCoverageIgnoreEnd
    }
}

// @codeCoverageIgnoreStart

if(defined('PHPUNIT_RUNNING'))
    return;

$worker = new ChallengeWorker();
$worker->run();

// @codeCoverageIgnoreEnd