document.addEventListener('DOMContentLoaded', function() {
    const userButton = document.getElementById('userMenuButton');
    const userDropdown = document.querySelector('.relative .absolute');

    if (userButton && userDropdown) {
        userButton.addEventListener('click', () => {
            userDropdown.classList.toggle('hidden');
        });
        document.addEventListener('click', (event) => {
            if (!userButton.contains(event.target) && !userDropdown.contains(event.target)) {
                userDropdown.classList.add('hidden');
            }
        });
    }

    // Cookie banner script
    const cookieBanner = document.getElementById('cookie-banner');
    if (cookieBanner && !localStorage.getItem('cookiesAccepted')) {
        cookieBanner.style.display = 'block';
    }

    const acceptCookiesButton = document.getElementById('accept-cookies-button');
    if (acceptCookiesButton) {
        acceptCookiesButton.addEventListener('click', acceptCookies);
    }

    // Password validation listener
    const passwordInput = document.getElementById('password');
    const passwordFeedback = document.getElementById('password-feedback');
    if (passwordInput && passwordFeedback) {
        passwordInput.addEventListener('input', validatePassword);
    }
});

function acceptCookies() {
        localStorage.setItem('cookiesAccepted', 'true');
        document.getElementById('cookie-banner').style.display = 'none';
}

    // Password validation script for registration page
    function validatePassword() {
        const passwordInput = document.getElementById('password');
        if (!passwordInput) return;
        const password = document.getElementById('password').value;
        const feedback = document.getElementById('password-feedback');
        if (feedback) {

        if (password.length < 8) {
            feedback.textContent = 'Password must be at least 8 characters';
            feedback.classList.remove('hidden');
            feedback.classList.remove('text-green-500');
            feedback.classList.add('text-red-500');
            return false;
        }
    }

        if (!/[A-Z]/.test(password)) {
            feedback.textContent = 'Password must contain at least one uppercase letter';
            feedback.classList.remove('hidden');
            feedback.classList.remove('text-green-500');
            feedback.classList.add('text-red-500');
            return false;
        }

        if (!/\d/.test(password)) {
            feedback.textContent = 'Password must contain at least one number';
            feedback.classList.remove('hidden');
            feedback.classList.remove('text-green-500');
            feedback.classList.add('text-red-500');
            return false;
        }

        feedback.textContent = 'Password meets all requirements';
        feedback.classList.remove('hidden');
        feedback.classList.remove('text-red-500');
        feedback.classList.add('text-green-500');
        return true;
    }
