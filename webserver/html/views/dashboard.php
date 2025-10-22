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
    <title>CTF Dashboard</title>
    <link rel="stylesheet" href="../assets/css/base.css">
    <link rel="stylesheet" href="../assets/css/dashboard.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js" defer></script>
    <script src="https://cdn.jsdelivr.net/npm/apexcharts@3.44.0/dist/apexcharts.min.js" defer></script>
</head>
<body>
<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/header.html'); ?>
<main class="dashboard-container">
    <section class="welcome-banner">
        <h1>Welcome back, <span id="username"></span>! 👋</h1>
        <p>Your current rank: <span id="user-rank"></span> | Points: <span id="user-points"></span></p>
    </section>

    <div class="dashboard-grid">
        <section class="card progress-section">
            <h2>Your Progress</h2>
            <div class="progress-container">
                <div class="progress-chart">
                    <canvas id="progressChart"></canvas>
                </div>
                <div class="progress-stats">
                    <div class="stat-item">
                        <div class="stat-value" id="solved-count"></div>
                        <div class="stat-label">Challenges Solved</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="success-rate"></div>
                        <div class="stat-label">Success Rate</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="avg-time"></div>
                        <div class="stat-label">Avg. Time</div>
                    </div>
                </div>
            </div>
        </section>
        <section class="card category-section">
            <h2>Skills Breakdown</h2>
            <div id="categoryChart"></div>
        </section>

        <section class="card news-section">
            <h2>CTF News & Updates</h2>
            <div class="news-list">
            </div>
            <a href="/announcements" class="view-all">View all announcements →</a>
        </section>

        <section class="card progress-timeline">
            <h2>Your Progress Over Time</h2>
            <div class="graph-controls">
                <div class="time-filters">
                    <button class="time-filter active" data-range="week">Week</button>
                    <button class="time-filter" data-range="month">Month</button>
                    <button class="time-filter" data-range="year">Year</button>
                </div>
                <div class="view-toggle">
                    <span>View:</span>
                    <button class="view-option active" data-type="daily">Daily</button>
                    <button class="view-option" data-type="cumulative">Cumulative</button>
                </div>
            </div>
            <canvas id="timelineChart"></canvas>
            <div id="challengeDetailsPopup" class="popup">
                <div class="popup-content">
                    <h3>Challenges solved on <span id="popupDate"></span></h3>
                    <ul id="challengeList"></ul>
                    <button class="close-popup">&times;</button>
                </div>
            </div>
        </section>

        <section class="card activity-section">
            <h2>Recent Activity</h2>
            <div class="activity-list">
            </div>
            <a href="/activity" class="view-all">View all activity →</a>
        </section>

        <section class="card badges-section">
            <h2>Your Badges</h2>
            <div class="badges-grid">
            </div>
            <div class="badges-progress">
                <div class="progress-bar">
                    <div class="progress-fill" style="width: 0%"></div>
                </div>
                <div class="progress-text">0% to next badge</div>
            </div>
        </section>

        <section class="card challenges-section">
            <h2>Recommended Challenges</h2>
            <div class="challenges-list">
            </div>
        </section>

        <section class="card active-challenge-section">
            <h2>Active Challenge</h2>
            <div id="active-challenge-container">
                <div class="no-challenge" id="no-active-challenge">
                    <p>You don't have any active challenge</p>
                    <button class="button button-primary" onclick="window.location.href='/explore'">Start a Challenge
                    </button>
                </div>
                <div class="active-challenge-details" id="active-challenge-details" style="display: none;">
                    <div class="challenge-info">
                        <h3 id="active-challenge-name">Challenge Name</h3>
                        <div class="challenge-meta">
                            <span id="active-challenge-category">Category</span> •
                            <span id="active-challenge-difficulty">Difficulty</span> •
                            <span id="active-challenge-points">0</span> points
                        </div>
                        <div class="time-info">
                            <div class="time-stat">
                                <span class="time-label">Started:</span>
                                <span id="active-challenge-started">-</span>
                            </div>
                            <div class="time-stat">
                                <span class="time-label">Time spent:</span>
                                <span id="active-challenge-time-spent">-</span>
                            </div>
                        </div>
                    </div>
                    <div class="challenge-actions">
                        <button class="button button-secondary" id="view-challenge-btn">View Challenge</button>
                        <button class="button button-danger" id="cancel-challenge-btn">Cancel</button>
                    </div>
                </div>
            </div>
        </section>
    </div>
</main>
<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/footer.html'); ?>
<script type="module" src="../assets/js/theme-toggle.js"></script>
<script type="module" src="../assets/js/dashboard.js"></script>
</body>
</html>
