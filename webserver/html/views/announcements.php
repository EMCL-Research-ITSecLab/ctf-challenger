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
    <title>Announcements - CTF Dashboard</title>
    <link rel="stylesheet" href="../assets/css/base.css">
    <link rel="stylesheet" href="../assets/css/announcements.css">
</head>
<body>
<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/header.html'); ?>
<div class="main-wrapper">
    <main class="announcements-container">
        <div class="back-button-container">
            <a href="/dashboard" class="back-button">
                <span class="arrow">←</span> Back to Dashboard
            </a>
        </div>

        <div id="global-error" class="error-message" style="display: none;"></div>

        <section class="announcements-header">
            <h1>CTF Announcements</h1>
            <div class="announcements-filters">
                <div class="filter-group dropdown">
                    <label for="importance-filter">Filter by:</label>
                    <select id="importance-filter">
                        <option value="all">All Announcements</option>
                        <option value="critical">Critical Updates</option>
                        <option value="important">Important</option>
                        <option value="normal">Regular Updates</option>
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
                <button id="reset-filters" class="button button-secondary">Reset Filters</button>
            </div>
        </section>

        <section class="announcements-list">
            <div class="list-container">
                <!-- This will be populated by JavaScript -->
                <div class="empty-state">
                    <div class="empty-icon">📢</div>
                    <h3>No announcements found</h3>
                    <p>Try adjusting your filters</p>
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
<script type="module" src="../assets/js/announcements.js"></script>
</body>
</html>