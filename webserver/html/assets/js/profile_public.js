import {apiClient, messageManager} from './utils.js';
import themeToggle from './theme-toggle.js';
class PublicProfile {
    constructor() {
        this.config = null;
        this.chart = null;
        this.domElements = {
            usernameDisplay: document.getElementById('username-display'),
            memberSince: document.getElementById('member-since'),
            points: document.getElementById('points'),
            rankBadge: document.getElementById('rank-badge'),
            userAvatar: document.getElementById('user-avatar'),
            bioText: document.getElementById('bio-text'),
            totalSolved: document.getElementById('total-solved'),
            successRate: document.getElementById('success-rate'),
            totalPoints: document.getElementById('total-points'),
            badgesGrid: document.getElementById('badges-grid'),
            badgeCount: document.getElementById('badge-count'),
            socialLinks: document.getElementById('social-links'),
            categoryChart: document.getElementById('categoryChart')
        };

        this.unsubscribeTheme = themeToggle.subscribe(() => this.updateChartColors());

        this.loadConfig().then(() => {
            this.username = this.extractUsernameFromPath();
            this.init();
        });
    }

    init() {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
        this.initRadarChart(currentTheme);
        this.loadProfileData();
    }

    async loadConfig() {
        try {
            const response = await fetch('/config/general.config.json');
            const config = await response.json();
            this.config = config.user;

            this.config.USERNAME_REGEX = new RegExp(this.config.USERNAME_REGEX);
        } catch (error) {
            console.error('Failed to load config:', error);
        }
    }

    extractUsernameFromPath() {
        const pathParts = window.location.pathname.split('/');
        const username = pathParts[2];

        return this.validateUsername(username);
    }

    validateUsername(username) {
        if (!this.config.USERNAME_REGEX.test(username)) {
            messageManager.showError('Invalid username format');
            window.location.href = '/';
            throw new Error('Invalid username format');
        }
        return username;
    }

    initRadarChart() {
        if (!this.domElements.categoryChart) return;

        // Get current theme (default to dark if not set)
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
        const isLightTheme = currentTheme === 'light';

        const chartOptions = {
            series: [{
                name: 'Completion',
                data: []
            }],
            chart: {
                type: 'radar',
                height: 300,
                toolbar: {show: false},
                background: 'transparent'
            },
            theme: {
                mode: currentTheme
            },
            colors: ['#00adb5'],
            xaxis: {
                categories: []
            },
            yaxis: {
                show: false,
                max: 100,
                min: 0
            },
            markers: {
                size: 5,
                hover: {size: 7}
            },
            tooltip: {
                y: {
                    formatter: function (val) {
                        return val + '% completed';
                    }
                }
            },
            plotOptions: {
                radar: {
                    size: 120,
                    polygons: {
                        strokeColors: isLightTheme
                            ? 'rgba(0, 0, 0, 0.1)'
                            : 'rgba(255, 255, 255, 0.1)',
                        fill: {
                            colors: [isLightTheme
                                ? 'rgba(0, 0, 0, 0.03)'
                                : 'rgba(255, 255, 255, 0.05)']
                        }
                    }
                }
            }
        };

        this.chart = new ApexCharts(this.domElements.categoryChart, chartOptions);
        this.chart.render();
    }

    async loadProfileData() {
        try {
            const response = await apiClient.get(`/backend/profile_view.php?username=${this.username}`);
            this.handleProfileResponse(response);
        } catch (error) {
            this.handleProfileError(error);
        }
    }

    handleProfileResponse(response) {
        if (!response) {
            window.location.href = '/';
            return;
        }

        if (response.success) {
            this.updateProfile(response.data);
        } else {
            this.handleProfileFailure(response);
        }
    }

    updateProfile(data) {
        const {profile, stats, badges} = data;
        this.updateBasicInfo(profile);
        this.updateStats(stats);
        this.updateBadges(badges);
        this.updateSocialLinks(profile.social_links);
    }

    updateStats(stats) {
        this.domElements.totalSolved.textContent = stats.total_solved;
        this.domElements.successRate.textContent = `${stats.success_rate}%`;
        this.domElements.totalPoints.textContent = stats.total_points;

        if (this.chart) {

            const percentagesArray = stats.categories.map(category => stats.percentages[category] || 0);

            this.chart.updateOptions({
                series: [{
                    name: 'Completion',
                    data: percentagesArray
                }],
                xaxis: {
                    categories: stats.categories
                }
            });
        }
    }

    updateBasicInfo(profile) {
        document.title = `${profile.username} | heiST`;
        this.domElements.usernameDisplay.textContent = profile.username;
        this.domElements.memberSince.textContent = new Date(profile.join_date).toLocaleDateString();
        this.domElements.points.textContent = `${profile.points} points`;
        this.domElements.rankBadge.textContent = this.getRankTitle(profile.points);

        if (profile.avatar_url && this.domElements.userAvatar) {
            this.domElements.userAvatar.src = profile.avatar_url;
        }

        this.domElements.bioText.textContent = profile.bio || 'No bio yet';
    }

    updateBadges(badgeData) {
        const {badges, earned_count, total_badges} = badgeData;

        if (this.domElements.badgesGrid) {

            this.domElements.badgesGrid.innerHTML = badges.map(badge => this.createBadgeElement(badge, true)).join('');


            if (badges.length < total_badges) {
                this.domElements.badgesGrid.innerHTML += this.createLockedBadgesPlaceholder(total_badges - badges.length);
            }
        }

        if (this.domElements.badgeCount) {
            this.domElements.badgeCount.textContent = `${earned_count}/${total_badges} unlocked`;
        }
    }

    createBadgeElement(badge, isUnlocked) {
        return `
            <div class="badge-item ${isUnlocked ? '' : 'locked'}"
                data-tooltip="${isUnlocked ? (badge.description || 'No description available') : 'Locked Badge'}">
                <div class="badge-icon ${badge.color || 'gold'}">
                    ${isUnlocked ? (badge.icon || '🏆') : '🔒'}
                </div>
                <div class="badge-title">${badge.name}</div>
            </div>
        `;
    }

    createLockedBadgesPlaceholder(count) {
        let html = '';
        for (let i = 0; i < count; i++) {
            html += this.createBadgeElement({
                name: 'Locked',
                color: 'gray'
            }, false);
        }
        return html;
    }

    updateChartColors() {
        if (!this.chart) return;

        const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
        const isLightTheme = currentTheme === 'light';

        this.chart.updateOptions({
            theme: {
                mode: currentTheme
            },
            plotOptions: {
                radar: {
                    polygons: {
                        strokeColors: isLightTheme
                            ? 'rgba(0, 0, 0, 0.1)'
                            : 'rgba(255, 255, 255, 0.1)',
                        fill: {
                            colors: [isLightTheme
                                ? 'rgba(0, 0, 0, 0.03)'
                                : 'rgba(255, 255, 255, 0.05)']
                        }
                    }
                }
            }
        }, false, true);
    }

    updateSocialLinks(socialLinks) {
        if (!this.domElements.socialLinks) return;

        this.domElements.socialLinks.innerHTML = Object.entries(socialLinks)
            .filter(([_, url]) => url && url !== '#')
            .map(([type, url]) => this.createSocialLink(type, url))
            .join('');
    }

    createSocialLink(type, url) {
        return `
            <a href="${url}" class="social-link" target="_blank" rel="noopener noreferrer">
                <svg class="social-icon" viewBox="0 0 24 24">
                    ${this.getSocialIcon(type)}
                </svg>
                ${type.charAt(0).toUpperCase() + type.slice(1)}
            </a>
        `;
    }

    getSocialIcon(type) {
        const icons = {
            github: '<path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>',
            twitter: '<path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z"/>',
            website: '<path d="M12 0C8.688 0 6 2.688 6 6s2.688 6 6 6 6-2.688 6-6-2.688-6-6-6zm0 10c-2.206 0-4-1.794-4-4s1.794-4 4-4 4 1.794 4 4-1.794 4-4 4zm7.5-1.5c-.828 0-1.5.672-1.5 1.5s.672 1.5 1.5 1.5 1.5-.672 1.5-1.5-.672-1.5-1.5-1.5zM23.994 22v-.002c0-.438-.095-.864-.275-1.262-.545-1.229-1.756-2.062-3.219-2.062h-16c-1.463 0-2.674.833-3.219 2.062-.18.398-.275.824-.275 1.262v.002h23.988zM22 12v10h-5v-6c0-1.104-.896-2-2-2s-2 .896-2 2v6h-5V12h-2v10h-1.994c.004-.063.012-.125.012-.188 0-1.656 1.344-3 3-3h16c1.656 0 3 1.344 3 3 0 .063.008.125.012.188h-2.012V12h-2z"/>'
        };
        return icons[type] || '';
    }

    getRankTitle(points) {
        if (points >= 5000) return 'Elite Hacker';
        if (points >= 2000) return 'Advanced Hacker';
        if (points >= 1000) return 'Intermediate Hacker';
        if (points >= 500) return 'Novice Hacker';
        return 'Beginner';
    }

    handleProfileFailure(response) {
        messageManager.showError(response.message || 'Failed to load profile');
        if (response.status === 404) {
            window.location.href = '/';
        }
    }

    handleProfileError(error) {
        console.error('Error loading profile:', error);
        messageManager.showError('Error loading profile data');
    }
}


if (typeof window !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
        new PublicProfile();
    });
}

export default PublicProfile;