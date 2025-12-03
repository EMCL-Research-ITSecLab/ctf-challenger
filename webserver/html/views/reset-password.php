<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';

$securityHelper = new SecurityHelper();
$securityHelper->initSecureSession();

if (!$securityHelper->validateSession()) {
    header('Location: /404');
    exit();
}

if (!$securityHelper->requiresPasswordChange()) {
    header('Location: /dashboard');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - CTF Challenger</title>
    <link rel="stylesheet" href="../assets/css/base.css">
    <link rel="stylesheet" href="../assets/css/reset-password.css">
</head>
<body>
<div class="theme-switch">
    <label class="switch">
        <input type="checkbox" id="theme-toggle">
        <span class="slider">
            <img class="icon moon" src="/assets/icons/moon.svg"/>
            <img class="icon sun" src="/assets/icons/sun.svg"/>
        </span>
    </label>
</div>
<div class="reset-password-logo">
    <a href="/landing">CTF Challenger</a>
</div>
<div class="reset-password-container">
    <form class="reset-password-form" id="resetPasswordForm" method="POST">
        <h2>Reset Password</h2>

        <!-- Current Password -->
        <div class="input-group password-container has-icon">
            <label for="current_password">Current Password</label>
            <div class="input-wrapper">
                <input type="password" id="current_password" name="current_password"
                       placeholder="Enter your current password" required>
                <button type="button" class="password-toggle" aria-label="Toggle password visibility">
                    <i class="fa-solid fa-eye"></i>
                </button>
                <i class="fa-solid fa-circle-exclamation input-error-icon" id="current-password-icon"></i>
            </div>
            <small class="error-message" id="current-password-error"></small>
        </div>

        <!-- New Password -->
        <div class="input-group password-container has-icon">
            <label for="new_password">New Password</label>
            <div class="input-wrapper">
                <input type="password" id="new_password" name="new_password"
                       placeholder="Enter your new password" required>
                <button type="button" class="password-toggle" aria-label="Toggle password visibility">
                    <i class="fa-solid fa-eye"></i>
                </button>
                <i class="fa-solid fa-circle-exclamation input-error-icon" id="new-password-icon"></i>
            </div>
            <small class="error-message" id="new-password-error"></small>
        </div>

        <!-- Confirm New Password -->
        <div class="input-group password-container has-icon">
            <label for="confirm_password">Confirm New Password</label>
            <div class="input-wrapper">
                <input type="password" id="confirm_password" name="confirm_password"
                       placeholder="Confirm your new password" required>
                <button type="button" class="password-toggle" aria-label="Toggle password visibility">
                    <i class="fa-solid fa-eye"></i>
                </button>
                <i class="fa-solid fa-circle-exclamation input-error-icon" id="confirm-password-icon"></i>
            </div>
            <small class="error-message" id="confirm-password-error"></small>
        </div>

        <!-- Form Feedback Area -->
        <div class="form-feedback" id="form-feedback"></div>

        <button type="submit" class="button button-primary">Update Password</button>
    </form>
</div>
<script type="module" src="../assets/js/theme-toggle.js"></script>
<script type="module" src="../assets/js/reset-password.js"></script>
</body>
</html>