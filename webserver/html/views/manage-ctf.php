<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';

$securityHelper = new SecurityHelper();
$securityHelper->initSecureSession();

$databaseHelper = new DatabaseHelper();
$pdo = $databaseHelper->getPDO();

if (!$securityHelper->validateSession() || !$securityHelper->validateAdminAccess($pdo)) {
    header('Location: /404');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage CTF Challenges - CTF Challenger</title>
    <link rel="stylesheet" href="../assets/css/base.css">
    <link rel="stylesheet" href="../assets/css/manage-ctf.css">
</head>
<body>
<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/header.html'); ?>
<div class="main-wrapper">
    <main class="manage-ctf-container">
        <div class="dashboard-header">
            <h1>Your CTF Challenges</h1>
            <div class="header-actions">
                <button id="create-new-ctf" class="button button-primary">
                    <i class="fa-solid fa-plus"></i> Create New Challenge
                </button>
                <div class="search-filter dropdown">
                    <input type="text" id="challenge-search" placeholder="Search challenges...">
                    <select id="category-filter">
                        <option value="">All Categories</option>
                        <option value="web">Web</option>
                        <option value="crypto">Crypto</option>
                        <option value="forensics">Forensics</option>
                        <option value="reverse">Reverse Engineering</option>
                        <option value="pwn">Pwn</option>
                        <option value="misc">Miscellaneous</option>
                    </select>
                    <select id="status-filter">
                        <option value="">All Statuses</option>
                        <option value="active">Active</option>
                        <option value="inactive">Inactive</option>
                    </select>
                </div>
            </div>
        </div>

        <div class="stats-summary">
            <div class="stat-card">
                <div class="stat-value" id="total-challenges">0</div>
                <div class="stat-label">Total Challenges</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="active-deployments">0</div>
                <div class="stat-label">Active Deployments</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="total-deployments">0</div>
                <div class="stat-label">Total Deployments</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="avg-completion">0m</div>
                <div class="stat-label">Avg. Completion Time</div>
            </div>
        </div>

        <div class="challenges-table-container">
            <table class="challenges-table">
                <thead>
                <tr>
                    <th>Challenge</th>
                    <th>Category</th>
                    <th>Difficulty</th>
                    <th>Status</th>
                    <th>Deployments</th>
                    <th>Active Now</th>
                    <th>Avg. Time</th>
                    <th>Actions</th>
                </tr>
                </thead>
                <tbody id="challenges-list">
                <!-- This will be populated by JavaScript -->
                </tbody>
            </table>
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
        <div id="edit-modal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h2>Edit Challenge</h2>
                    <button class="close-modal">&times;</button>
                </div>
                <div class="modal-body">
                    <form id="edit-challenge-form">
                        <input type="hidden" id="edit-challenge-id">

                        <div class="form-group">
                            <label for="edit-name">Challenge Name</label>
                            <input type="text" id="edit-name" required>
                        </div>

                        <div class="form-group">
                            <label for="edit-description">Description</label>
                            <textarea id="edit-description" rows="3" required></textarea>
                        </div>

                        <div class="form-row">
                            <div class="form-group dropdown">
                                <label for="edit-category">Category</label>
                                <select id="edit-category" required>
                                    <option value="web">Web</option>
                                    <option value="crypto">Crypto</option>
                                    <option value="forensics">Forensics</option>
                                    <option value="reverse">Reverse Engineering</option>
                                    <option value="pwn">Pwn</option>
                                    <option value="misc">Miscellaneous</option>
                                </select>
                            </div>

                            <div class="form-group dropdown">
                                <label for="edit-difficulty">Difficulty</label>
                                <select id="edit-difficulty" required>
                                    <option value="easy">Easy</option>
                                    <option value="medium">Medium</option>
                                    <option value="hard">Hard</option>
                                </select>
                            </div>
                        </div>

                        <div class="form-group">
                            <label for="edit-hint">Hint</label>
                            <textarea id="edit-hint" rows="2"></textarea>
                        </div>

                        <div class="form-group">
                            <label for="edit-solution">Solution</label>
                            <textarea id="edit-solution" rows="4"></textarea>
                        </div>

                        <div class="form-group">
                            <label>Status</label>
                            <div class="toggle-switch">
                                <input type="checkbox" id="edit-active">
                                <label for="edit-active" class="toggle-slider"></label>
                                <span id="toggle-label">Inactive</span>
                            </div>
                        </div>

                        <div class="form-actions">
                            <button type="submit" class="button button-primary">Save Changes</button>
                            <button type="button" class="button button-secondary close-modal">Cancel</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <div id="delete-modal" class="modal">
            <div class="modal-content medium">
                <div class="modal-header">
                    <h2>Delete Challenge</h2>
                    <button class="close-modal">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="delete-options-tabs">
                        <button class="tab-button active" data-tab="soft-delete">Standard Delete</button>
                        <button class="tab-button" data-tab="hard-delete">Force Delete</button>
                        <div class="tab-indicator"></div>
                    </div>

                    <div class="tab-content active" id="soft-delete-tab">
                        <div class="warning-message warning">
                            <i class="fa-solid fa-info-circle"></i>
                            <div>
                                <h4>Standard (Safe) Deletion</h4>
                                <p>The challenge will be marked for deletion and automatically removed when all active
                                    instances are terminated.</p>
                                <ul>
                                    <li>Active instances can finish their sessions</li>
                                    <li>Challenge remains available until last instance closes</li>
                                    <li>Can be undone while instances are running</li>
                                </ul>
                            </div>
                        </div>

                        <div class="form-actions">
                            <button id="confirm-soft-delete" class="button button-warning no-border">
                                <i class="fa-solid fa-trash-alt"></i> Mark for Deletion
                            </button>
                            <button type="button" class="button button-secondary no-border close-modal">Cancel</button>
                        </div>
                    </div>

                    <div class="tab-content" id="hard-delete-tab">
                        <div class="warning-message danger">
                            <i class="fa-solid fa-exclamation-triangle"></i>
                            <div>
                                <h4>Force (Immediate) Deletion</h4>
                                <p>The challenge and all active instances will be terminated immediately. Use only in
                                    emergencies.</p>
                                <ul>
                                    <li>All active instances will be forcibly terminated</li>
                                    <li>Challenge will be permanently deleted</li>
                                    <li>Cannot be undone</li>
                                </ul>
                            </div>
                        </div>

                        <div class="form-actions">
                            <button id="confirm-hard-delete" class="button button-danger no-border">
                                <i class="fa-solid fa-skull-crossbones"></i> Force Delete Now
                            </button>
                            <button type="button" class="button button-secondary no-border close-modal">Cancel</button>
                        </div>
                    </div>

                    <input type="hidden" id="delete-challenge-id">
                </div>
            </div>
        </div>
        <div id="leaderboard-modal" class="modal">
            <div class="modal-content large">
                <div class="modal-header">
                    <h2>Challenge Leaderboard</h2>
                    <button class="close-modal">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="leaderboard-header">
                        <div class="leaderboard-info">
                            <img id="leaderboard-challenge-image" src="" alt="Challenge Image" class="challenge-image">
                            <div>
                                <h3 id="leaderboard-challenge-name"></h3>
                                <div class="leaderboard-stats">
                                    <span id="leaderboard-challenge-category"></span>
                                    <span id="leaderboard-challenge-difficulty"></span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="leaderboard-table-container">
                        <table class="leaderboard-table">
                            <thead>
                            <tr>
                                <th>Rank</th>
                                <th>User</th>
                                <th>Points</th>
                                <th>Time</th>
                            </tr>
                            </thead>
                            <tbody id="leaderboard-entries">
                            <!-- This will be populated by JavaScript -->
                            </tbody>
                        </table>
                    </div>

                    <div class="leaderboard-pagination">
                        <button id="leaderboard-prev" class="pagination-button button button-secondary" disabled>
                            <i class="fa-solid fa-chevron-left"></i>
                        </button>
                        <span id="leaderboard-page-info">Page 1</span>
                        <button id="leaderboard-next" class="pagination-button button button-secondary" disabled>
                            <i class="fa-solid fa-chevron-right"></i>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </main>
</div>
<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/footer.html'); ?>
<div id="toast-notification" class="toast" style="display: none;"></div>

<script type="module" src="../assets/js/theme-toggle.js"></script>
<script type="module" src="../assets/js/manage-ctf.js"></script>
</body>
</html>