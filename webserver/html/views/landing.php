<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CTF VM Deployment</title>
    <link rel="stylesheet" href="../assets/css/base.css">
    <link rel="stylesheet" href="../assets/css/landing.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
</head>
<body class="dark-mode">
<header>
    <div class="header-container">
        <div class="logo">
            <a href="/landing">CTF-Challenger</a>
        </div>
        <nav>
            <ul>
                <li><a href="/profile">Profile</a></li>
                <li><a href="/explore">Explore Challenges</a></li>
                <li><a href="/dashboard">Dashboard</a></li>
            </ul>
        </nav>
        <div class="button-group">
            <a href="/login" class="button button-secondary">Login</a>
            <a href="/signup" class="button button-primary">Get Started</a>
        </div>
        <div class="theme-switch">
            <label class="switch">
                <input type="checkbox" id="theme-toggle">
                <span class="slider">
                        <img class="icon moon" src="/assets/icons/moon.svg"/>
                        <img class="icon sun" src="/assets/icons/sun.svg"/>
                    </span>
            </label>
        </div>
    </div>
</header>

<section class="hero">
    <div class="container">
        <h2>Start your own <span class="terminal-text">CTF environment</span> now</h2>
        <p>Create and manage your virtual machines with ease.</p>
        <div class="cta-buttons">
            <a href="/signup" class="button button-primary cta-button">Get Started</a>
        </div>
    </div>
</section>

<section class="features">
    <div class="container">
        <div class="feature">
            <h3 class="terminal-text">Easy Management</h3>
            <p>Maintain control over your VMs with an intuitive dashboard.</p>
        </div>
        <div class="feature">
            <h3 class="terminal-text">Scalable & Secure</h3>
            <p>Our platform uses Proxmox for a secure and reliable environment.</p>
        </div>
        <div class="feature">
            <h3 class="terminal-text">Perfect for CTF</h3>
            <p>Designed for training, competitions, and testing environments.</p>
        </div>
    </div>
</section>

<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/footer.html'); ?>
<script type="module" src="../assets/js/theme-toggle.js"></script>
</body>
</html>