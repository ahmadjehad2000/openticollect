// Theme toggle: persists choice in localStorage, defaults to system preference.
(function () {
  function current() {
    try {
      return localStorage.getItem('theme') ||
        (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    } catch (e) {
      return 'light';
    }
  }
  function apply(t) {
    document.documentElement.setAttribute('data-theme', t);
  }
  apply(current());
  // Delegated so the toggle keeps working after htmx swaps.
  document.addEventListener('click', function (e) {
    if (!e.target.closest('#theme-toggle')) return;
    var next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    apply(next);
    try { localStorage.setItem('theme', next); } catch (e) {}
  });
})();
