<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';

$securityHelper = new SecurityHelper();
$securityHelper->initSecureSession();

if (!$securityHelper->validateSession()) {
    header('Location: /404');
    exit();
}
?>

<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Badges & Achievements - CTF Dashboard</title>
    <link rel="stylesheet" href="../assets/css/base.css">
    <link rel="stylesheet" href="../assets/css/badges.css">
</head>
<body>
<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/header.html'); ?>

<main class="badges-container">
    <div class="back-button-container">
        <a href="/profile" class="back-button">
            <span class="arrow">←</span> Back to Dashboard
        </a>
    </div>

    <div id="global-error" class="error-message" style="display: none;"></div>

    <section class="badges-header">
        <h1>Badges & Achievements</h1>
        <div class="progress-summary">
            <div class="progress-card">
                <div class="progress-icon">🏆</div>
                <div class="progress-info">
                    <span class="progress-count" id="earned-badges">0</span>
                    <span class="progress-label">Earned Badges</span>
                </div>
            </div>
            <div class="progress-card">
                <div class="progress-icon">📊</div>
                <div class="progress-info">
                    <span class="progress-count" id="total-badges">0</span>
                    <span class="progress-label">Total Badges</span>
                </div>
            </div>
            <div class="progress-card">
                <div class="progress-icon">🌟</div>
                <div class="progress-info">
                    <span class="progress-count" id="completion-rate">0%</span>
                    <span class="progress-label">Completion</span>
                </div>
            </div>
        </div>
    </section>

    <section class="badges-grid">
        <div class="grid-container">
            <!-- This will be populated by JavaScript -->
            <div class="empty-state">
                <div class="empty-icon">🏆</div>
                <h3>No badges found</h3>
                <p>Complete challenges to earn badges!</p>
                <a href="/explore" class="button button-primary">Explore Challenges</a>
            </div>
        </div>
    </section>
</main>

<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/footer.html'); ?>

<script type="module" src="../assets/js/theme-toggle.js"></script>
<script type="module" src="../assets/js/badges.js"></script>
</body>
</html>