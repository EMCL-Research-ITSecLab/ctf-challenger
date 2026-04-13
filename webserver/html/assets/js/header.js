import { apiClient, messageManager } from './utils.js';
import themeToggleInstance from './theme-toggle.js';

class UserHeader {
    constructor() {
        this.logoImg = document.getElementById('logo-img');
        this.init();
    }

    init() {
        document.addEventListener('DOMContentLoaded', () => {
            this.setupLogout();
            this.loadUserAvatar();
            this.setupLogoToggle();
        });
    }

    setupLogoToggle() {
        if (!this.logoImg) return;

        this.updateLogo();
        themeToggleInstance.subscribe(() => this.updateLogo());
    }

    updateLogo() {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        this.logoImg.src = isDark
            ? '/assets/icons/heiST_dark.svg'
            : '/assets/icons/heiST.svg';
    }

    setupLogout() {
        const logoutLink = document.getElementById('logout-link');
        if (logoutLink) {
            logoutLink.addEventListener('click', async (e) => {
                e.preventDefault();
                await this.handleLogout();
            });
        }
    }

    async loadUserAvatar() {
        const result = await apiClient.get('/backend/header.php');
        if (!result) return;

        if (result.success) {
            const {is_logged_in: isLoggedIn, avatar_url: avatarUrl, is_admin: isAdmin} = result.data;
            const loginBtn = document.getElementById('login-btn');
            const signupBtn = document.getElementById('signup-btn');
            const mainNav = document.getElementById('main-nav');
            const avatarContainer = document.getElementById('avatar-container');
            const avatarImg = document.getElementById('avatar-img');

            if (isLoggedIn) {
                this.showLoggedInState(loginBtn, signupBtn, mainNav, avatarContainer, avatarImg, avatarUrl);
                if (isAdmin) this.addAdminLinks();
            } else {
                this.showLoggedOutState(loginBtn, signupBtn, mainNav, avatarContainer);
            }
        }
    }

    showLoggedInState(loginBtn, signupBtn, mainNav, avatarContainer, avatarImg, avatarUrl) {
        loginBtn.style.display = 'none';
        signupBtn.style.display = 'none';
        mainNav.style.display = 'block';
        avatarContainer.style.display = 'flex';

        if (avatarImg) {
            avatarImg.src = avatarUrl;
            avatarImg.alt = 'User Avatar';
        }
    }

    showLoggedOutState(loginBtn, signupBtn, mainNav, avatarContainer) {
        loginBtn.style.display = 'block';
        signupBtn.style.display = 'block';
        mainNav.style.display = 'none';
        avatarContainer.style.display = 'none';
    }

    addAdminLinks() {
        const menu = document.querySelector('.dropdown-menu');
        if (!menu) return;

        const adminLinks = [
            {
                href: '/create-ctf',
                label: 'Create CTF',
                icon: '<svg class="dropdown-icon" viewBox="0 0 24 24"><path d="M19 11h-6V5h-2v6H5v2h6v6h2v-6h6z"/></svg>'
            },
            {
                href: '/manage-ctf',
                label: 'Manage CTFs',
                icon: '<svg class="dropdown-icon" viewBox="0 0 24 24"><path d="M3 13h2v-2H3v2zm4 0h14v-2H7v2zm0 6h14v-2H7v2zM3 19h2v-2H3v2zm0-12h2V5H3v2zm4 0h14V5H7v2z"/></svg>'
            },
            {
                href: '/manage-announcements',
                label: 'Announcements',
                icon: '<svg class="dropdown-icon" viewBox="0 0 489.803 489.803"><path d="M11.701,244.606h10.6v13.5c0,19.3,15.7,35,35,35h8.7l35.1,117c2.8,9.2,12.2,14.6,21.5,12.4c9-2.1,14.9-10.7,13.7-19.8l-13.9-109.6h17.5c8.1,0,14.6-6.5,14.6-14.6v-0.4c34.1,4.9,91.6,17.4,140.9,48.6c8.4,16.5,18.5,26.3,29.6,26.3c28.3,0,51.3-64.1,51.3-143.1c0-79.1-23-143.1-51.3-143.1c-10.2,0-19.8,8.5-27.8,22.9c-49.8,32.1-108.4,44.8-142.9,49.7c-0.9-7.2-7-12.7-14.4-12.7h-82.6c-19.3,0-35,15.7-35,35v15.6h-10.6c-6.5,0-11.7,5.3-11.7,11.7v43.8C-0.099,239.306,5.201,244.606,11.701,244.606z M310.401,175.406c2.8-29,8.9-50.9,14.7-64.1c7.8,18,16.3,52.3,16.3,98.6s-8.5,80.5-16.3,98.6c-5.8-13.2-11.8-35.2-14.7-64.1c11.4-3.7,19.9-17.7,19.9-34.4C330.301,193.106,321.801,179.106,310.401,175.406z"/><path d="M475.501,195.506h-57.6c-7.9,0-14.3,6.4-14.3,14.3c0,7.9,6.4,14.3,14.3,14.3h57.6c7.9,0,14.3-6.4,14.3-14.3C489.901,201.906,483.401,195.506,475.501,195.506z"/><path d="M478.401,284.606c2.3-7.1-1.3-14.7-8.3-17.5l-55-21.8c-7.6-3-16.2,1-18.7,8.8c-2.3,7.1,1.3,14.7,8.3,17.5l55,21.8C467.301,296.506,475.901,292.406,478.401,284.606z"/><path d="M415.201,174.306l55-21.8c6.9-2.7,10.5-10.4,8.3-17.5c-2.5-7.8-11.1-11.9-18.7-8.8l-55,21.8c-6.9,2.7-10.5,10.4-8.3,17.5C399.001,173.306,407.501,177.406,415.201,174.306z"/></svg>'
            },
            {
                href: '/upload-diskfile',
                label: 'Upload Diskfile',
                icon: '<svg class="dropdown-icon" viewBox="0 0 24 24"><path d="M19 9h-4V3H9v6H5l7 7 7-7zm-7 9c-4.97 0-9-4.03-9-9H1c0 5.52 4.48 10 10 10s10-4.48 10-10h-2c0 4.97-4.03 9-9 9z"/></svg>'
            }
        ];

        adminLinks.forEach(link => {
            const li = document.createElement('li');
            li.classList.add('dropdown-item-container');
            li.innerHTML = `
                <a href="${link.href}" class="dropdown-item ${window.location.pathname === link.href ? 'active' : ''}">
                    ${link.icon}
                    ${link.label}
                </a>
            `;

            const logoutItem = menu.querySelector('.logout-btn')?.parentElement;
            if (logoutItem) {
                menu.insertBefore(li, logoutItem);
            } else {
                menu.appendChild(li);
            }
        });
    }

    async handleLogout() {
        const result = await apiClient.post('/backend/logout.php');
        if (result?.success) {
            messageManager.showSuccess('Logged out successfully');
            setTimeout(() => {
                window.location.href = '/login';
            }, 1000);
        }
    }
}

new UserHeader();