<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class ChallengeHelper implements IChallengeHelper
{
    public function isChallengeSolved(PDO $pdo, int $userId, int $challengeId): bool
    {
        $stmt = $pdo->prepare("
            SELECT
                total_flags,
                flags_completed,
                is_solved
            FROM get_solve_progress_data(:user_id, :challenge_id)
        ");
        $stmt->execute([
            'user_id' => $userId,
            'challenge_id' => $challengeId
        ]);
        $solvedData = $stmt->fetch(PDO::FETCH_ASSOC);
        return (bool)($solvedData['is_solved'] ?? false);
    }

    public function getElapsedSecondsForChallenge(PDO $pdo, int $userId, int $challengeId): int
    {
        $stmt = $pdo->prepare("
            SELECT get_elapsed_seconds_for_challenge(:user_id, :challenge_template_id) AS total_seconds
        ");
        $stmt->execute([
            'user_id' => $userId,
            'challenge_template_id' => $challengeId
        ]);

        return (int)$stmt->fetchColumn();
    }

    public function getSolvedLeaderboard(PDO $pdo, int $challengeTemplateId): array
    {
        $stmt = $pdo->prepare("
            SELECT
                username,
                avatar_url,
                total_seconds,
                rank
            FROM get_solved_leaderboard(:challenge_template_id)
        ");
        $stmt->execute(['challenge_template_id' => $challengeTemplateId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getChallengeLeaderboard(PDO $pdo, int $challengeTemplateId, int $limit = 10, int $offset = 0): array
    {
        $stmt = $pdo->prepare("
            SELECT
                username,
                avatar_url,
                total_points,
                total_seconds,
                rank
            FROM get_challenge_leaderboard(:challenge_template_id, :limit, :offset)
        ");

        $stmt->bindValue(':challenge_template_id', $challengeTemplateId, PDO::PARAM_INT);
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);

    }
}
