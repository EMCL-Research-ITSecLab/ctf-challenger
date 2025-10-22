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
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Announcements - CTF Dashboard</title>
    <link rel="stylesheet" href="../assets/css/base.css">
    <link rel="stylesheet" href="../assets/css/manage-announcements.css">
</head>
<body>
<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/header.html'); ?>
<div class="main-wrapper">
    <main class="manage-announcements-container">
        <div class="management-header">
            <h1>Manage Announcements</h1>
            <button id="create-announcement" class="button button-primary">
                <i class="fa-solid fa-plus"></i> Create New
            </button>
        </div>

        <div class="announcements-table-container">
            <table class="announcements-table">
                <thead>
                <tr>
                    <th>Title</th>
                    <th>Category</th>
                    <th>Importance</th>
                    <th>Created</th>
                    <th>Last Updated</th>
                    <th>Actions</th>
                </tr>
                </thead>
                <tbody id="announcements-list">
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
        <div id="editor-modal" class="modal">
            <div class="modal-content editor-modal">
                <div class="modal-header">
                    <h2 id="modal-title">Create New Announcement</h2>
                    <button class="close-modal">&times;</button>
                </div>
                <div class="modal-body">
                    <form id="announcement-form">
                        <input type="hidden" id="announcement-id">

                        <div class="form-group">
                            <label for="announcement-title">Title*</label>
                            <input type="text" id="announcement-title" required>
                        </div>

                        <div class="form-group">
                            <label for="announcement-short-desc">Short Description</label>
                            <input type="text" id="announcement-short-desc">
                        </div>

                        <div class="form-group">
                            <label for="announcement-content">Content*</label>
                            <textarea id="announcement-content" rows="8" required></textarea>
                        </div>

                        <div class="form-row">
                            <div class="form-group dropdown">
                                <label for="announcement-category">Category*</label>
                                <select id="announcement-category" required>
                                    <option value="general">General</option>
                                    <option value="updates">Updates</option>
                                    <option value="maintenance">Maintenance</option>
                                    <option value="events">Events</option>
                                    <option value="security">Security</option>
                                </select>
                            </div>

                            <div class="form-group dropdown">
                                <label for="announcement-importance">Importance*</label>
                                <select id="announcement-importance" required>
                                    <option value="normal">Normal</option>
                                    <option value="important">Important</option>
                                    <option value="critical">Critical</option>
                                </select>
                            </div>
                        </div>

                        <div class="form-actions">
                            <button type="submit" class="button button-primary">Save Announcement</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <div id="delete-modal" class="modal">
            <div class="modal-content small">
                <div class="modal-header">
                    <h2>Delete Announcement</h2>
                    <button class="close-modal">&times;</button>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to delete this announcement?</p>
                    <p class="warning-text"><i class="fa-solid fa-exclamation-triangle"></i> This action cannot be
                        undone.</p>
                    <input type="hidden" id="delete-announcement-id">
                    <div class="form-actions">
                        <button id="confirm-delete" class="button button-danger">Delete</button>
                        <button type="button" class="button button-secondary close-modal">Cancel</button>
                    </div>
                </div>
            </div>
        </div>
    </main>
</div>
<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/footer.html'); ?>

<script type="module" src="../assets/js/theme-toggle.js"></script>
<script type="module" src="../assets/js/manage-announcements.js"></script>
</body>
</html>