(function () {
    var saved = localStorage.getItem('theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);
})();

function toggleTheme() {
    var cur = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', cur);
    localStorage.setItem('theme', cur);
    applyThemeIcon();
}

function applyThemeIcon() {
    var dark = document.documentElement.getAttribute('data-theme') === 'dark';
    var btn = document.getElementById('themeBtn');
    if (btn) btn.textContent = dark ? '☀️' : '🌙';
    document.querySelectorAll('.theme-icon').forEach(function (el) {
        el.textContent = dark ? '☀️' : '🌙';
    });
}

function showToast(msg, type) {
    var t = document.createElement('div');
    t.className = 'toast' + (type ? ' ' + type : '');
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(function () { t.classList.add('show'); }, 10);
    setTimeout(function () {
        t.classList.remove('show');
        setTimeout(function () { t.remove(); }, 300);
    }, 3500);
}

// ===== Боковое меню =====
function openSidebar() {
    var sb = document.getElementById('sidebar');
    var ov = document.getElementById('sidebarOverlay');
    if (!sb || !ov) return;
    sb.classList.add('open');
    ov.classList.add('show');
    document.body.style.overflow = 'hidden';
}

function closeSidebar() {
    var sb = document.getElementById('sidebar');
    var ov = document.getElementById('sidebarOverlay');
    if (!sb || !ov) return;
    sb.classList.remove('open');
    ov.classList.remove('show');
    document.body.style.overflow = '';
}

function toggleMenuGroup(btn) {
    btn.parentElement.classList.toggle('open');
}

document.addEventListener('DOMContentLoaded', applyThemeIcon);
document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeSidebar();
});
