class MessageManager {
    constructor() {
        this.stackContainer = document.getElementById('message-stack-container');

        if (!this.stackContainer) {
            this.stackContainer = document.createElement('div');
            this.stackContainer.id = 'message-stack-container';
            this.stackContainer.className = 'message-stack-container';
            document.body.appendChild(this.stackContainer);
        }
    }

    showMessage(type, message, duration = 5000) {
        const container = document.createElement('div');
        container.className = `message ${type}-message`;
        container.setAttribute('data-duration', `${duration}ms`);

        const icon = type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle';
        container.innerHTML = `
            <i class="fa-solid ${icon} message-icon"></i>
            <span class="message-text">${message}</span>
            <button class="message-close-btn">&times;</button>
        `;

        this.stackContainer.appendChild(container);

        // Force reflow before animation
        requestAnimationFrame(() => {
            container.style.opacity = '1';
            container.style.transform = 'translateY(0)';
        });

        const timeout = setTimeout(() => {
            this.hideMessage(container);
        }, duration);

        container.querySelector('.message-close-btn').addEventListener('click', () => {
            clearTimeout(timeout);
            this.hideMessage(container);
        });
    }

    hideMessage(container) {
        container.style.opacity = '0';
        container.style.transform = 'translateY(-20px)';
        setTimeout(() => {
            container.remove();
        }, 300); // Match CSS transition duration
    }

    showSuccess(message, duration) {
        this.showMessage('success', message, duration);
    }

    showError(message, duration) {
        this.showMessage('error', message, duration);
    }
}



class ApiClient {
    constructor() {
        this.messageManager = new MessageManager();
        this.publicEndpoints = ['explore', 'header', 'challenge'];
    }

    isSamePageReferer() {
        const { referrer } = document;
        if (!referrer) return false;

        try {
            return new URL(referrer).href === window.location.href;
        } catch {
            return false;
        }
    }

    buildRequestConfig(method, data) {
        const hasData = data !== undefined && data !== null;
        const isFormData = hasData && data instanceof FormData;

        const config = {
            method,
            body: hasData ? (isFormData ? data : JSON.stringify(data)) : undefined,
        };


        if (!isFormData) {
            config.headers = {
                'Content-Type': 'application/json'
            };
        }

        return config;
    }

    async request(url, options = {}) {
        try {
            const pathname = new URL(url, window.location.origin).pathname;
            const filename = pathname.split('/').pop();
            const base = filename.replace(/\.php$/, '');
            const isPublicEndpoint = this.publicEndpoints.includes(base);

            const headers = {
                ...(options.headers || {}),
            };

            const response = await fetch(url, {
                ...options,
                headers,
                credentials: 'same-origin'
            });

            if (response.status === 401 || response.status === 403) {
                if (!isPublicEndpoint) {
                    const error = new Error(response.status === 401 ?
                        'Session expired. Please log in again.' :
                        'You do not have permission for this action');
                    if (this.isSamePageReferer()) {
                        this.messageManager.showError(error.message);
                        setTimeout(() => window.location.href = '/login', 1500);
                    } else {
                        window.location.href = '/login';
                    }
                    return null;
                }
            }

            const contentType = response.headers.get('content-type');
            if (contentType?.includes('application/octet-stream')) {
                return this.handleFileDownload(response, url);
            }

            if (!response.ok) {
                let errorMessage = `Request failed with status ${response.status}`;
                try {
                    const errorData = await response.json();
                    if (errorData.message) {
                        errorMessage = errorData.message;
                    }
                } catch (e) {
                    console.error('Failed to parse error response:', e);
                }
                this.messageManager.showError(errorMessage);
                return null;
            }

            if (response.status === 204) return null;

            return await response.json();
        } catch (error) {
            console.error('API request error:', error);
            this.messageManager.showError('Network error. Please check your connection and try again.');
            return null;
        }
    }

    async handleFileDownload(response, url) {
        const blob = await response.blob();
        const contentDisposition = response.headers.get('content-disposition');
        let filename = 'download';

        if (contentDisposition) {
            const match = contentDisposition.match(/filename="?([^"]+)"?/i);
            if (match) filename = match[1];
        } else {
            filename = url.split('/').pop() || filename;
        }

        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);

        return {success: true, filename};
    }

    async get(url) {
        return this.request(url);
    }

    async post(url, data) {
        return this.request(url, this.buildRequestConfig('POST', data));
    }

    async put(url, data) {
        return this.request(url, this.buildRequestConfig('PUT', data));
    }

    async delete(url, options = {}) {
        return this.request(url, this.buildRequestConfig('DELETE', options.data));
    }
}


export const messageManager = new MessageManager();
export const apiClient = new ApiClient();