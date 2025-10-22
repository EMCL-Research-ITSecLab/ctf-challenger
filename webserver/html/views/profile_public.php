<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><span id="username-display">User</span> | CTF-Challenger</title>
    <link rel="stylesheet" href="../assets/css/base.css">
    <link rel="stylesheet" href="../assets/css/profile.css">
    <link rel="stylesheet" href="../assets/css/profile_public.css">
    <script src="https://cdn.jsdelivr.net/npm/apexcharts@3.44.0/dist/apexcharts.min.js" defer></script>
</head>
<body>
<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/header.html'); ?>
<main class="profile-container">
    <div class="profile-grid">
        <section class="account-info-card">
            <div class="account-info-content">
                <div class="info-section active">
                    <div class="avatar-section">
                        <div class="avatar-public">
                            <img id="user-avatar" src="../assets/avatars/default-avatar.png" alt="User Avatar">
                        </div>
                        <div class="avatar-info">
                            <div class="user-member-group">
                                <div class="user-field">
                                    <div class="username-display-container">
                                        <h1 id="username-display">Loading...</h1>
                                    </div>
                                </div>
                                <div class="info-field member-since">
                                    <span class="field-label">Member Since</span>
                                    <span class="field-value" id="member-since">Loading...</span>
                                </div>
                            </div>
                            <div class="user-rank">
                                <span class="rank-badge" id="rank-badge">Loading rank</span>
                                <span class="points" id="points">0 points</span>
                            </div>
                        </div>
                    </div>
                    <div class="info-content-wrapper">
                        <div class="info-field bio-field">
                            <span class="field-label">Bio</span>
                            <div class="bio-container">
                                <p class="bio-text" id="bio-text">Loading bio...</p>
                            </div>
                        </div>
                    </div>
                    <div class="social-links-container">
                        <div class="info-field">
                            <span class="field-label">Social Links</span>
                            <div class="social-links" id="social-links">
                                <!-- This will be populated by JavaScript -->
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        <section class="profile-card stats-overview">
            <h2>Stats</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value" id="total-solved">0</div>
                    <div class="stat-label">Challenges Solved</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="success-rate">0%</div>
                    <div class="stat-label">Success Rate</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="total-points">0</div>
                    <div class="stat-label">Total Points</div>
                </div>
            </div>
            <div class="stat-chart">
                <div id="categoryChart"></div>
            </div>
        </section>
        <section class="profile-card achievements">
            <div class="card-header">
                <h2>Badges & Achievements</h2>
                <span class="badge-count" id="badge-count">0/0 unlocked</span>
            </div>
            <div class="badges-grid" id="badges-grid">
                <div class="badge-item loading">
                    <div class="badge-icon">⌛</div>
                    <div class="badge-title">Loading...</div>
                </div>
            </div>
            <div class="view-all-container">
                <a href="/badges" class="view-all">View all achievements →</a>
            </div>
        </section>
    </div>
</main>
<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/footer.html'); ?>

<script type="module" src="../assets/js/profile_public.js"></script>
</body>
</html>