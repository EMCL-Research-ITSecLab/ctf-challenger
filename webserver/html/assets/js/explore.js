import {apiClient, messageManager} from './utils.js';

class CTFExplorer {
    constructor() {
        this.categoryFilter = document.getElementById('category');
        this.difficultyFilter = document.getElementById('difficulty');
        this.sortFilter = document.getElementById('sort');
        this.searchInput = document.querySelector('.search-input');
        this.ctfList = document.querySelector('.ctf-list');
        this.paginationContainer = document.querySelector('.pagination');
        this.viewToggleButton = document.querySelector('.view-toggle-button');

        this.currentPage = 1;
        this.totalPages = 1;
        this.isMinimalisticView = false;
        this.searchTimeout = null;

        this.categoryIcons = {
            'web': '🌐',
            'crypto': '🔒',
            'forensics': '🔍',
            'reverse': '🛠️',
            'pwn': '💥',
            'default': '🎯'
        };

        this.init();
    }

    async init() {
        await this.filterCTFs();
        this.setupEventListeners();
    }

    async filterCTFs(page = 1) {
        this.currentPage = page;
        this.showLoadingState();

        const params = new URLSearchParams({
            search: this.searchInput.value.trim(),
            category: this.categoryFilter.value,
            difficulty: this.difficultyFilter.value,
            sort: this.sortFilter.value,
            page: page
        });

        try {
            const data = await apiClient.get(`../backend/explore.php?${params.toString()}`);
            this.handleResponse(data);
        } catch (error) {
            this.handleError();
        }
    }

    showLoadingState() {
        this.ctfList.innerHTML = '<div class="loading">Loading challenges...</div>';
    }

    handleResponse(data) {
        if (data?.success) {
            this.renderCTFs(data.data.challenges);
            this.updatePagination(data.data.pagination);
        } else {
            this.handleError();
        }
    }

    handleError() {
        messageManager.showError('Failed to load challenges');
        this.ctfList.innerHTML = '<div class="no-results">No challenges available.</div>';
    }

    renderCTFs(challenges) {
        if (!challenges?.length) {
            this.ctfList.innerHTML = '<div class="no-results">No challenges found matching your criteria.</div>';
            return;
        }

        this.ctfList.innerHTML = '';
        challenges.forEach(challenge => this.createCTFCard(challenge));
    }

    createCTFCard(challenge) {
        const card = document.createElement('div');
        card.className = `ctf-card ${this.isMinimalisticView ? 'minimalistic' : ''}`;
        card.dataset.category = challenge.category;
        card.dataset.difficulty = challenge.difficulty;

        card.innerHTML = this.getCardHTML(challenge);
        card.addEventListener('click', () => {
            window.location.href = `/challenge?id=${challenge.id}`;
        });

        this.ctfList.appendChild(card);
    }

    getCardHTML(challenge) {
        const inactiveRibbon = !challenge.is_active ? '<div class="inactive-ribbon">Inactive</div>' : '';

        return `
            <div class="ctf-image-container">
                ${inactiveRibbon}
                <img src="${challenge.image}" alt="${challenge.title}" class="ctf-image" onerror="this.src='../assets/images/ctf-default.png'">
                <div class="ctf-image-overlay"></div>
            </div>
            <div class="ctf-content">
                <h3 class="ctf-title">${challenge.title}</h3>
                <p class="ctf-description">${challenge.description}</p>
                <div class="ctf-labels">
                    <span class="ctf-difficulty ${challenge.difficulty}">
                        ${this.capitalizeFirstLetter(challenge.difficulty)}
                    </span>
                    <span class="ctf-category">
                        ${this.getCategoryIcon(challenge.category)} ${challenge.category}
                    </span>
                </div>
                ${challenge.user_data?.solved ? '<span class="solved-badge">✓ Solved</span>' : ''}
            </div>
        `;
    }

    updatePagination(pagination) {
        this.totalPages = pagination.total_pages;
        this.paginationContainer.style.display = this.totalPages <= 1 ? 'none' : 'flex';

        if (this.totalPages > 1) {
            document.querySelector('.page-info').textContent = `Page ${this.currentPage} of ${this.totalPages}`;
        }
    }

    getCategoryIcon(category) {
        return this.categoryIcons[category.toLowerCase()] || this.categoryIcons.default;
    }

    capitalizeFirstLetter(string) {
        return string.charAt(0).toUpperCase() + string.slice(1);
    }

    setupEventListeners() {
        this.setupFilterListeners();
        this.setupSearchListener();
        this.setupPaginationListener();
        this.setupViewToggleListener();
    }

    setupFilterListeners() {
        [this.categoryFilter, this.difficultyFilter, this.sortFilter].forEach(filter => {
            filter.addEventListener('change', () => this.filterCTFs(1));
        });
    }

    setupSearchListener() {
        this.searchInput.addEventListener('input', () => {
            clearTimeout(this.searchTimeout);
            this.searchTimeout = setTimeout(() => this.filterCTFs(1), 300);
        });
    }

    setupPaginationListener() {
        this.paginationContainer.addEventListener('click', (e) => {
            if (!e.target.classList.contains('button')) return;

            if (e.target.textContent.includes('Previous') && this.currentPage > 1) {
                this.filterCTFs(this.currentPage - 1);
            } else if (e.target.textContent.includes('Next') && this.currentPage < this.totalPages) {
                this.filterCTFs(this.currentPage + 1);
            }
        });
    }

    setupViewToggleListener() {
        if (!this.viewToggleButton) return;

        this.viewToggleButton.addEventListener('click', () => {
            this.isMinimalisticView = !this.isMinimalisticView;
            this.toggleViewStyles();
            this.updateCardViews();
        });
    }

    toggleViewStyles() {
        this.ctfList.classList.toggle('minimalistic-view');
        this.viewToggleButton.classList.toggle('active');
    }

    updateCardViews() {
        this.ctfList.querySelectorAll('.ctf-card').forEach(card => {
            card.classList.toggle('minimalistic', this.isMinimalisticView);
        });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new CTFExplorer();
});