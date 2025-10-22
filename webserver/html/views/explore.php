<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CTF Dashboard - CTF Challenger</title>
    <link rel="stylesheet" href="../assets/css/base.css">
    <link rel="stylesheet" href="../assets/css/explore.css">
</head>
<body>
<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/header.html'); ?>
<main class="dashboard-container">
    <section class="search-bar">
        <input type="text" placeholder="Search CTFs..." class="search-input">
    </section>

    <section class="filters">
        <div class="filter-group dropdown">
            <label for="category">Category:</label>
            <select id="category" class="filter-select">
                <option value="all">All</option>
                <option value="web">Web</option>
                <option value="crypto">Crypto</option>
                <option value="forensics">Forensics</option>
                <option value="reverse">Reverse Engineering</option>
                <option value="pwn">Pwn</option>
                <option value="misc">Misc</option>
            </select>
        </div>
        <div class="filter-group dropdown">
            <label for="difficulty">Difficulty:</label>
            <select id="difficulty" class="filter-select">
                <option value="all">All</option>
                <option value="easy">Easy</option>
                <option value="medium">Medium</option>
                <option value="hard">Hard</option>
            </select>
        </div>
        <div class="filter-group dropdown">
            <label for="sort">Sort By:</label>
            <select id="sort" class="filter-select">
                <option value="popularity">Popularity</option>
                <option value="date">Date</option>
                <option value="difficulty">Difficulty</option>
            </select>
        </div>
        <button class="view-toggle-button">
            <span class="stripe"></span>
            <span class="stripe"></span>
            <span class="stripe"></span>
        </button>
    </section>

    <section class="ctf-list">
        <div class="ctf-card" data-category="web" data-difficulty="easy">
            <div class="ctf-image-container">
                <img src="../assets/images/web-challenge-1.jpg" alt="Web Challenge 1" class="ctf-image">
                <div class="ctf-image-overlay"></div>
            </div>
            <div class="ctf-content">
                <h3 class="ctf-title">Web Challenge 1</h3>
                <p class="ctf-description">Find and exploit a vulnerability in a web application.</p>
                <div class="ctf-labels">
                    <span class="ctf-difficulty easy">Easy</span>
                    <span class="ctf-category">🌐 Web</span>
                </div>
            </div>
        </div>
        <div class="ctf-card" data-category="web" data-difficulty="easy">
            <img src="../assets/images/web-challenge-1.jpg" alt="Web Challenge 1" class="ctf-image">
            <div class="ctf-content">
                <h3 class="ctf-title">Web Challenge 1</h3>
                <p class="ctf-description">Find and exploit a vulnerability in a web application.</p>
                <div class="ctf-labels">
                    <span class="ctf-difficulty easy">Easy</span>
                    <span class="ctf-category">🌐 Web</span>
                </div>
            </div>
        </div>
        <div class="ctf-card" data-category="web" data-difficulty="easy">
            <img src="../assets/images/web-challenge-1.jpg" alt="Web Challenge 1" class="ctf-image">
            <div class="ctf-content">
                <h3 class="ctf-title">Web Challenge 1</h3>
                <p class="ctf-description">Find and exploit a vulnerability in a web application.</p>
                <div class="ctf-labels">
                    <span class="ctf-difficulty easy">Easy</span>
                    <span class="ctf-category">🌐 Web</span>
                </div>
            </div>
        </div>
        <div class="ctf-card" data-category="web" data-difficulty="easy">
            <img src="../assets/images/web-challenge-1.jpg" alt="Web Challenge 1" class="ctf-image">
            <div class="ctf-content">
                <h3 class="ctf-title">Web Challenge 1</h3>
                <p class="ctf-description">Find and exploit a vulnerability in a web application.</p>
                <div class="ctf-labels">
                    <span class="ctf-difficulty easy">Easy</span>
                    <span class="ctf-category">🌐 Web</span>
                </div>
            </div>
        </div>
        <div class="ctf-card" data-category="web" data-difficulty="easy">
            <img src="../assets/images/web-challenge-1.jpg" alt="Web Challenge 1" class="ctf-image">
            <div class="ctf-content">
                <h3 class="ctf-title">Web Challenge 1</h3>
                <p class="ctf-description">Find and exploit a vulnerability in a web application.</p>
                <div class="ctf-labels">
                    <span class="ctf-difficulty easy">Easy</span>
                    <span class="ctf-category">🌐 Web</span>
                </div>
            </div>
        </div>
        <div class="ctf-card" data-category="web" data-difficulty="easy">
            <h3 class="ctf-title">Web Challenge 1</h3>
            <p class="ctf-description">Find and exploit a vulnerability in a web application.</p>
            <div class="ctf-labels">
                <span class="ctf-difficulty easy">Easy</span>
                <span class="ctf-category">🌐 Web</span>
            </div>
        </div>
        <div class="ctf-card" data-category="crypto" data-difficulty="medium">
            <h3 class="ctf-title">Crypto Challenge 1</h3>
            <p class="ctf-description">Decrypt a message using a classic cipher.</p>
            <div class="ctf-labels">
                <span class="ctf-difficulty medium">Medium</span>
                <span class="ctf-category">🔒 Crypto</span>
            </div>
        </div>
        <div class="ctf-card" data-category="forensics" data-difficulty="hard">
            <h3 class="ctf-title">Forensics Challenge 1</h3>
            <p class="ctf-description">Analyze a disk image to recover hidden data.</p>
            <div class="ctf-labels">
                <span class="ctf-difficulty hard">Hard</span>
                <span class="ctf-category">🔍 Forensics</span>
            </div>
        </div>
        <div class="ctf-card" data-category="web" data-difficulty="easy">
            <div class="ctf-icon">🌐</div>
            <h3 class="ctf-title">Web Challenge 1</h3>
            <p class="ctf-description">Find and exploit a vulnerability in a web application.</p>
            <div class="ctf-labels">
                <span class="ctf-category">Web</span>
                <span class="ctf-difficulty easy">Easy</span>
            </div>
        </div>
        <div class="ctf-card" data-category="crypto" data-difficulty="medium">
            <div class="ctf-icon">🔒</div>
            <h3 class="ctf-title">Crypto Challenge 1</h3>
            <p class="ctf-description">Decrypt a message using a classic cipher.</p>
            <div class="ctf-labels">
                <span class="ctf-category">Crypto</span>
                <span class="ctf-difficulty medium">Medium</span>
            </div>
        </div>
        <div class="ctf-card" data-category="forensics" data-difficulty="hard">
            <div class="ctf-icon">🔍</div>
            <h3 class="ctf-title">Forensics Challenge 1</h3>
            <p class="ctf-description">Analyze a disk image to recover hidden data.</p>
            <div class="ctf-labels">
                <span class="ctf-category">Forensics</span>
                <span class="ctf-difficulty hard">Hard</span>
            </div>
        </div>
        <div class="ctf-card" data-category="reverse" data-difficulty="medium">
            <div class="ctf-icon">🛠️</div>
            <h3 class="ctf-title">Reverse Engineering Challenge 1</h3>
            <p class="ctf-description">Reverse engineer a binary to find the flag.</p>
            <div class="ctf-labels">
                <span class="ctf-category">Reverse Engineering</span>
                <span class="ctf-difficulty medium">Medium</span>
            </div>
        </div>
        <div class="ctf-card" data-category="pwn" data-difficulty="hard">
            <div class="ctf-icon">💥</div>
            <h3 class="ctf-title">Pwn Challenge 1</h3>
            <p class="ctf-description">Exploit a buffer overflow to gain shell access.</p>
            <div class="ctf-labels">
                <span class="ctf-category">Pwn</span>
                <span class="ctf-difficulty hard">Hard</span>
            </div>
        </div>

        <div class="ctf-card" data-category="web" data-difficulty="easy">
            <h3 class="ctf-title">Web Challenge 1</h3>
            <p class="ctf-category">Web</p>
            <p class="ctf-difficulty">Easy</p>
        </div>
        <div class="ctf-card" data-category="crypto" data-difficulty="medium">
            <h3 class="ctf-title">Crypto Challenge 1</h3>
            <p class="ctf-category">Crypto</p>
            <p class="ctf-difficulty">Medium</p>
        </div>
        <div class="ctf-card" data-category="forensics" data-difficulty="hard">
            <h3 class="ctf-title">Forensics Challenge 1</h3>
            <p class="ctf-category">Forensics</p>
            <p class="ctf-difficulty">Hard</p>
        </div>
        <div class="ctf-card" data-category="web" data-difficulty="medium">
            <h3 class="ctf-title">Web Challenge 2</h3>
            <p class="ctf-category">Web</p>
            <p class="ctf-difficulty">Medium</p>
        </div>
        <div class="ctf-card" data-category="crypto" data-difficulty="hard">
            <h3 class="ctf-title">Crypto Challenge 2</h3>
            <p class="ctf-category">Crypto</p>
            <p class="ctf-difficulty">Hard</p>
        </div>
        <div class="ctf-card" data-category="forensics" data-difficulty="easy">
            <h3 class="ctf-title">Forensics Challenge 2</h3>
            <p class="ctf-category">Forensics</p>
            <p class="ctf-difficulty">Easy</p>
        </div>
        <div class="ctf-card" data-category="reverse" data-difficulty="medium">
            <h3 class="ctf-title">Reverse Engineering Challenge 1</h3>
            <p class="ctf-category">Reverse Engineering</p>
            <p class="ctf-difficulty">Medium</p>
        </div>
        <div class="ctf-card" data-category="pwn" data-difficulty="hard">
            <h3 class="ctf-title">Pwn Challenge 1</h3>
            <p class="ctf-category">Pwn</p>
            <p class="ctf-difficulty">Hard</p>
        </div>
        <div class="ctf-card" data-category="web" data-difficulty="hard">
            <h3 class="ctf-title">Web Challenge 3</h3>
            <p class="ctf-category">Web</p>
            <p class="ctf-difficulty">Hard</p>
        </div>
        <div class="ctf-card" data-category="crypto" data-difficulty="easy">
            <h3 class="ctf-title">Crypto Challenge 3</h3>
            <p class="ctf-category">Crypto</p>
            <p class="ctf-difficulty">Easy</p>
        </div>
        <div class="ctf-card" data-category="forensics" data-difficulty="medium">
            <h3 class="ctf-title">Forensics Challenge 3</h3>
            <p class="ctf-category">Forensics</p>
            <p class="ctf-difficulty">Medium</p>
        </div>
        <div class="ctf-card" data-category="reverse" data-difficulty="easy">
            <h3 class="ctf-title">Reverse Engineering Challenge 2</h3>
            <p class="ctf-category">Reverse Engineering</p>
            <p class="ctf-difficulty">Easy</p>
        </div>
    </section>

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
</main>

<?php include($_SERVER['DOCUMENT_ROOT'] . '/partials/footer.html'); ?>

<script type="module" src="../assets/js/explore.js"></script>
<script type="module" src="../assets/js/theme-toggle.js"></script>
</body>
</html>
