<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

interface IChallengeHelper
{
    public function isChallengeSolved(PDO $pdo, int $userId, int $challengeId): bool;

    public function getElapsedSecondsForChallenge(PDO $pdo, int $userId, int $challengeId): int;

    public function getSolvedLeaderboard(PDO $pdo, int $challengeTemplateId): array;

    public function getChallengeLeaderboard(PDO $pdo, int $challengeTemplateId, int $limit = 10, int $offset = 0): array;
}
