import themeToggleInstance from './theme-toggle.js';

const logoImg = document.getElementById('logo-img');

const updateLogo = () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    logoImg.src = isDark
        ? '/assets/icons/logo_dark.svg'
        : '/assets/icons/logo_light.svg';
};

updateLogo();
themeToggleInstance.subscribe(updateLogo);