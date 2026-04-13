import themeToggleInstance from './theme-toggle.js';

const logoImg = document.getElementById('logo-img');

const updateLogo = () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    logoImg.src = isDark
        ? '/assets/icons/heiST_dark.svg'
        : '/assets/icons/heiST.svg';
};

updateLogo();
themeToggleInstance.subscribe(updateLogo);