document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('domain-form');
    const overlay = document.getElementById('spinnerOverlay');
    if (form && overlay) {
        form.addEventListener('submit', function () {
            overlay.style.display = 'flex';
        });
    }
});
