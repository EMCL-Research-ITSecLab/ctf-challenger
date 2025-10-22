class LoginForm {
    constructor() {
        this.selectors = {
            loginForm: '#loginForm',
            usernameInput: '#username',
            passwordInput: '#password',
            rememberMeCheckbox: '#remember-me',
            passwordToggle: '.password-toggle',
            usernameIcon: '#username-icon',
            passwordIconError: '#password-icon',
            feedback: '#form-feedback'
        };

        this.elements = {};
        this.init();
    }

    init() {
        this.cacheElements();
        this.setupEventListeners();
        this.hideValidationIcons();
        this.autofillUsername();
        this.checkSessionStatus();
    }

    cacheElements() {
        for (const [key, selector] of Object.entries(this.selectors)) {
            this.elements[key] = document.querySelector(selector);
        }

        if (this.elements.passwordToggle) {
            this.elements.passwordIcon = this.elements.passwordToggle.querySelector('i');
        }
    }

    hideValidationIcons() {
        document.querySelectorAll('.input-error-icon').forEach(icon => {
            icon.style.display = 'none';
        });
    }

    autofillUsername() {
        if (localStorage.getItem('rememberMe') === 'true') {
            this.elements.rememberMeCheckbox.checked = true;
            this.elements.usernameInput.value = localStorage.getItem('savedUsername') || '';
        }
    }

    setupEventListeners() {
        if (this.elements.passwordToggle) {
            this.elements.passwordToggle.addEventListener('click', this.togglePasswordVisibility.bind(this));
        }

        if (this.elements.rememberMeCheckbox) {
            this.elements.rememberMeCheckbox.addEventListener('change', this.handleRememberMeChange.bind(this));
        }

        if (this.elements.usernameInput) {
            this.elements.usernameInput.addEventListener('input', this.handleUsernameInput.bind(this));
        }

        if (this.elements.loginForm) {
            this.elements.loginForm.addEventListener('submit', this.handleLogin.bind(this));
        }
    }

    togglePasswordVisibility() {
        const isHidden = this.elements.passwordInput.type === 'password';
        this.elements.passwordInput.type = isHidden ? 'text' : 'password';

        if (this.elements.passwordIcon) {
            this.elements.passwordIcon.classList.toggle('fa-eye', !isHidden);
            this.elements.passwordIcon.classList.toggle('fa-eye-slash', isHidden);
        }
    }

    handleRememberMeChange() {
        if (this.elements.rememberMeCheckbox.checked) {
            localStorage.setItem('rememberMe', 'true');
            localStorage.setItem('savedUsername', this.elements.usernameInput.value);
        } else {
            localStorage.removeItem('rememberMe');
            localStorage.removeItem('savedUsername');
        }
    }

    handleUsernameInput() {
        if (this.elements.rememberMeCheckbox.checked) {
            localStorage.setItem('savedUsername', this.elements.usernameInput.value);
        }
    }

    async checkSessionStatus() {
        try {
            const response = await fetch('../backend/login.php', {
                method: 'GET',
                headers: {'X-Requested-With': 'XMLHttpRequest'},
                credentials: 'same-origin'
            });


            const contentType = response.headers.get('content-type');
            if (contentType?.includes('application/json')) {
                const data = await response.json().catch(() => null);
                if (data && data.redirect) {
                    window.location.href = data.redirect;
                }
            }
        } catch (err) {
            console.warn('Session check failed:', err);
        }
    }

    resetFormState() {
        [this.elements.usernameInput, this.elements.passwordInput].forEach(input => {
            if (input) input.classList.remove('error');
        });

        [this.elements.usernameIcon, this.elements.passwordIconError].forEach(icon => {
            if (icon) icon.style.display = 'none';
        });

        if (this.elements.feedback) {
            this.elements.feedback.textContent = '';
            this.elements.feedback.style.display = 'none';
        }
    }

    async handleLogin(e) {
        e.preventDefault();
        this.resetFormState();

        try {
            const formData = new FormData(this.elements.loginForm);
            const response = await fetch('../backend/login.php', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.message || 'Login failed.');
            }

            setTimeout(() => {
                window.location.href = data.redirect || '/dashboard';
            }, 100);

        } catch (err) {
            if (this.elements.usernameInput) this.elements.usernameInput.classList.add('error');
            if (this.elements.passwordInput) this.elements.passwordInput.classList.add('error');
            if (this.elements.usernameIcon) this.elements.usernameIcon.style.display = 'inline';
            if (this.elements.passwordIconError) this.elements.passwordIconError.style.display = 'inline';

            if (this.elements.feedback) {
                this.elements.feedback.textContent = err.message || 'Something went wrong.';
                this.elements.feedback.style.display = 'block';
            }
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new LoginForm();
});