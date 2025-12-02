class ResetPasswordForm {
    constructor() {
        this.config = null;
        this.form = document.querySelector('.reset-password-form');
        this.passwordToggles = document.querySelectorAll('.password-toggle');
        this.submitButton = this.form?.querySelector('button[type="submit"]');
        this.formFeedback = document.getElementById('form-feedback');
        this.originalButtonText = this.submitButton?.textContent;

        this.errorMapping = {
            'Current password': 'current-password',
            'New password': 'new-password',
            'Confirm password': 'confirm-password',
            'Password': 'new-password'
        };

        this.loadConfig().then(() => {
            this.init();
        });
    }

    init() {
        if (!this.form) return;

        this.hideErrorIcons();
        this.setupPasswordToggles();
        this.setupFormSubmission();
        this.setupRealTimeValidation();
    }

    async loadConfig() {
        try {
            const response = await fetch('/config/general.config.json');
            const config = await response.json();
            this.config = config.user;

            // Store password requirements
            this.config.MIN_PASSWORD_LENGTH = this.config.MIN_PASSWORD_LENGTH || 8;
            this.config.MAX_PASSWORD_LENGTH = this.config.MAX_PASSWORD_LENGTH || 255;
        } catch (error) {
            console.error('Failed to load config:', error);
        }
    }

    setupRealTimeValidation() {
        const currentPasswordField = this.form.querySelector('#current_password');
        const newPasswordField = this.form.querySelector('#new_password');
        const confirmPasswordField = this.form.querySelector('#confirm_password');

        if (currentPasswordField) {
            currentPasswordField.addEventListener('blur', () =>
                this.validateCurrentPassword(currentPasswordField.value));
        }

        if (newPasswordField) {
            newPasswordField.addEventListener('blur', () =>
                this.validateNewPassword(newPasswordField.value));
        }

        if (confirmPasswordField) {
            confirmPasswordField.addEventListener('blur', () => {
                if (newPasswordField) {
                    this.validatePasswordMatch(newPasswordField.value, confirmPasswordField.value);
                }
            });
        }
    }

    validateCurrentPassword(password) {
        if (!password) {
            this.showError('current-password', 'Current password is required');
            return false;
        }

        this.clearError('current-password');
        return true;
    }

    validateNewPassword(password) {
        if (!password) {
            this.showError('new-password', 'New password is required');
            return false;
        }

        if (password.length < this.config.MIN_PASSWORD_LENGTH) {
            this.showError('new-password', `Password must be at least ${this.config.MIN_PASSWORD_LENGTH} characters`);
            return false;
        }

        if (password.length > this.config.MAX_PASSWORD_LENGTH) {
            this.showError('new-password', `Password cannot exceed ${this.config.MAX_PASSWORD_LENGTH} characters`);
            return false;
        }

        this.clearError('new-password');
        return true;
    }

    validatePasswordMatch(password, confirmPassword) {
        if (!confirmPassword) {
            this.showError('confirm-password', 'Please confirm your new password');
            return false;
        }

        if (password !== confirmPassword) {
            this.showError('confirm-password', 'Passwords do not match');
            return false;
        }

        this.clearError('confirm-password');
        return true;
    }

    clearError(fieldId) {
        const field = document.getElementById(fieldId);
        if (!field) return;

        const inputGroup = field.closest('.input-group');
        const errorElement = inputGroup?.querySelector('.error-message');
        const iconElement = inputGroup?.querySelector('.input-error-icon');

        if (errorElement && iconElement) {
            field.classList.remove('error');
            errorElement.textContent = '';
            iconElement.style.display = 'none';
        }
    }

    setupFormSubmission() {
        this.form.addEventListener('submit', async (e) => {
            e.preventDefault();
            this.resetErrorStates();

            const currentPassword = this.form.querySelector('#current_password')?.value;
            const newPassword = this.form.querySelector('#new_password')?.value;
            const confirmPassword = this.form.querySelector('#confirm_password')?.value;

            const isCurrentPasswordValid = this.validateCurrentPassword(currentPassword);
            const isNewPasswordValid = this.validateNewPassword(newPassword);
            const isPasswordMatchValid = this.validatePasswordMatch(newPassword, confirmPassword);

            if (!isCurrentPasswordValid || !isNewPasswordValid || !isPasswordMatchValid) {
                return;
            }

            try {
                this.setLoadingState(true);
                const response = await this.submitForm();
                const data = await response.json();

                if (data.success) {
                    this.handleSuccessResponse(data);
                } else {
                    this.handleFormError(data);
                }
            } catch (error) {
                this.displayGeneralError('An error occurred. Please try again.');
                console.error('Error:', error);
            } finally {
                this.setLoadingState(false);
            }
        });
    }

    hideErrorIcons() {
        document.querySelectorAll('.input-error-icon').forEach(icon => {
            icon.style.display = 'none';
        });
    }

    setupPasswordToggles() {
        this.passwordToggles.forEach(toggle => {
            const passwordInput = toggle.previousElementSibling;
            toggle.addEventListener('click', () => this.togglePasswordVisibility(passwordInput, toggle));
        });
    }

    togglePasswordVisibility(input, toggle) {
        if (input.type === 'password') {
            input.type = 'text';
            toggle.innerHTML = '<i class="fa-solid fa-eye-slash"></i>';
        } else {
            input.type = 'password';
            toggle.innerHTML = '<i class="fa-solid fa-eye"></i>';
        }
    }

    async submitForm() {
        const formData = new FormData(this.form);
        return await fetch('../backend/reset-password.php', {
            method: 'POST',
            body: formData
        });
    }

    setLoadingState(isLoading) {
        if (!this.submitButton) return;

        this.submitButton.disabled = isLoading;
        this.submitButton.textContent = isLoading ? 'Updating Password...' : this.originalButtonText;
    }

    handleFormError(data) {
        // Clear previous feedback
        if (this.formFeedback) {
            this.formFeedback.innerHTML = '';
        }

        // Display error in form feedback area
        if (data.message) {
            this.displayGeneralError(data.message);
        }

        // Map server errors to specific fields
        let fieldFound = false;
        for (const [keyword, fieldId] of Object.entries(this.errorMapping)) {
            if (data.message && data.message.toLowerCase().includes(keyword.toLowerCase())) {
                this.showError(fieldId, data.message);
                fieldFound = true;

                // If it's a password error, also highlight confirm password field
                if (keyword === 'Password' || keyword === 'New password') {
                    this.showError('confirm-password', data.message);
                }
            }
        }

        // If no specific field was found, show general error
        if (!fieldFound) {
            this.showError('current-password', data.message || 'An error occurred');
        }
    }

    handleSuccessResponse(data) {
        // Clear the form
        this.form.reset();

        // Show success message
        if (this.formFeedback) {
            this.formFeedback.innerHTML = `<div class="success-message">${data.message}</div>`;
        }

        // If there's a redirect, wait a moment then redirect
        if (data.redirect) {
            setTimeout(() => {
                window.location.href = data.redirect;
            }, 2000);
        }
    }

    displayGeneralError(message) {
        if (!this.formFeedback) return;

        this.formFeedback.innerHTML = `<div class="error-message-text">${message}</div>`;
    }

    showError(fieldId, message) {
        const field = document.getElementById(fieldId);
        if (!field) return;

        const inputGroup = field.closest('.input-group');
        const errorElement = inputGroup?.querySelector('.error-message');
        const iconElement = inputGroup?.querySelector('.input-error-icon');

        if (errorElement && iconElement) {
            field.classList.add('error');
            errorElement.textContent = message;
            iconElement.style.display = 'block';
            errorElement.style.display = 'block';
            errorElement.style.visibility = 'visible';
            errorElement.style.opacity = '1';
        }
    }

    resetErrorStates() {
        // Clear input field errors
        document.querySelectorAll('.input-group input').forEach(field => {
            field.classList.remove('error');
        });

        // Clear error icons
        document.querySelectorAll('.input-error-icon').forEach(icon => {
            icon.style.display = 'none';
        });

        // Clear error messages
        document.querySelectorAll('.error-message').forEach(msg => {
            msg.textContent = '';
            msg.style.display = 'none';
            msg.style.visibility = 'hidden';
            msg.style.opacity = '0';
        });

        // Clear form feedback
        if (this.formFeedback) {
            this.formFeedback.innerHTML = '';
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new ResetPasswordForm();
});