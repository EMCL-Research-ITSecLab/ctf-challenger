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
    <title>Activity History - CTF Dashboard</title>
    <link rel="stylesheet" href="../assets/css/base.css">
    <link rel="stylesheet" href="../assets/css/activity.css">
</head>
<body>
<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/header.html'); ?>
<div class="main-wrapper">
    <main class="activity-container">
        <div class="back-button-container">
            <a href="/dashboard" class="back-button">
                <span class="arrow">←</span> Back to Dashboard
            </a>
        </div>

        <div id="global-error" class="error-message" style="display: none;"></div>

        <section class="activity-header">
            <h1>Your Activity History</h1>
            <div class="activity-filters">
                <div class="filter-group dropdown">
                    <label for="activity-type">Filter by:</label>
                    <select id="activity-type">
                        <option value="all">All Activity</option>
                        <option value="solved">Solved Challenges</option>
                        <option value="failed">Failed Attempts</option>
                        <option value="active">Active Attempts</option>
                        <option value="badges">Badges Earned</option>
                    </select>
                </div>
                <div class="filter-group dropdown">
                    <label for="time-range">Time Range:</label>
                    <select id="time-range">
                        <option value="all">All Time</option>
                        <option value="today">Today</option>
                        <option value="week">Last 7 Days</option>
                        <option value="month">Last 30 Days</option>
                        <option value="year">Last Year</option>
                    </select>
                </div>
                <div class="filter-group dropdown">
                    <label for="category-filter">Category:</label>
                    <select id="category-filter">
                        <option value="all">All Categories</option>
                        <option value="web">Web</option>
                        <option value="crypto">Crypto</option>
                        <option value="reverse">Reverse</option>
                        <option value="pwn">Pwn</option>
                        <option value="forensics">Forensics</option>
                        <option value="misc">Misc</option>
                    </select>
                </div>
                <button id="reset-filters" class="button button-secondary">Reset Filters</button>
            </div>
        </section>

        <section class="activity-timeline">
            <div class="timeline-container">
                <!-- This will be populated by JavaScript -->
                <div class="empty-state">
                    <div class="empty-icon">📊</div>
                    <h3>No activity found</h3>
                    <p>Try adjusting your filters or complete some challenges!</p>
                    <a href="/explore" class="button button-primary">Explore Challenges</a>
                </div>
            </div>
            <div class="pagination">
                <button id="prev-page" class="pagination-button button button-secondary" disabled>
                    <span class="text-button">← Previous</span>
                    <i class="fa-solid fa-chevron-left icon-button"></i>
                </button>
                <span class="page-info">Page 1 of 1</span>
                <button id="next-page" class="pagination-button button button-secondary" disabled>
                    <span class="text-button">Next →</span>
                    <i class="fa-solid fa-chevron-right icon-button"></i>
                </button>
            </div>
        </section>
    </main>
</div>

<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/footer.html'); ?>

<script type="module" src="../assets/js/theme-toggle.js"></script>
<script type="module" src="../assets/js/activity.js"></script>