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
    <title>Upload OVA - CTF Challenger</title>
    <link rel="stylesheet" href="../assets/css/base.css">
    <link rel="stylesheet" href="../assets/css/upload-diskfile.css">
</head>
<body>
<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/header.html'); ?>
<div class="main-wrapper">
    <main class="upload-ova-container">
        <div class="upload-section">
            <h1><i class="fa-solid fa-upload"></i> Upload OVA File</h1>

            <div class="upload-card">
                <div class="upload-area" id="upload-dropzone">
                    <i class="fa-solid fa-cloud-upload-alt"></i>
                    <h3>Drag & Drop your OVA file here</h3>
                    <p>or</p>
                    <button id="browse-btn" class="button button-primary">Browse Files</button>
                    <input type="file" id="file-input" accept=".ova,.ovf" style="display: none;">
                    <p class="file-cloud">Warning: only cloud-init compatible OVAs will work!<br>Make sure that all SCSI disks have the appropriate VirtIO drivers installed!</p>
                    <div class="file-info" id="file-info">
                        <span id="file-name">No file selected</span>
                        <span id="file-size"></span>
                    </div>
                    <div class="upload-progress-container" id="upload-progress-container">
                        <div class="upload-progress-bar" id="upload-progress-bar"></div>
                        <span class="upload-progress-text" id="upload-progress-text"></span>
                    </div>
                </div>

                <div class="upload-form">
                    <div class="form-actions">
                        <button id="cancel-btn" class="button button-secondary">Cancel</button>
                        <button id="upload-btn" class="button button-primary" disabled>Upload OVA</button>
                    </div>
                </div>
            </div>
        </div>

        <div class="existing-ovas">
            <h2>Your Existing OVAs</h2>
            <div class="search-filter">
                <div class="search-box">
                    <i class="fa-solid fa-search"></i>
                    <input type="text" id="search-ovas" placeholder="Search OVAs...">
                </div>
            </div>

            <div class="ova-list" id="ova-list">
                <!-- This will be populated by JavaScript -->
                <div class="empty-state">
                    <i class="fa-solid fa-box-open"></i>
                    <p>You haven't uploaded any OVAs yet</p>
                </div>
            </div>
        </div>
    </main>
</div>
<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/footer.html'); ?>

<script type="module" src="../assets/js/theme-toggle.js"></script>
<script type="module" src="../assets/js/upload-diskfile.js"></script>
</body>
</html>