(function () {
  const toggle = document.getElementById('theme-toggle');
  const navToggle = document.getElementById('nav-toggle');
  const siteNav = document.getElementById('site-nav');
  const body = document.body;

  function updateThemeLabel() {
    if (!toggle) return;
    const isLight = body.classList.contains('light-mode');
    toggle.setAttribute(
      'aria-label',
      isLight ? 'Switch to dark mode' : 'Switch to light mode'
    );
  }

  if (localStorage.getItem('theme') === 'light') {
    body.classList.add('light-mode');
  }
  updateThemeLabel();

  if (toggle) {
    toggle.addEventListener('click', function () {
      body.classList.toggle('light-mode');
      localStorage.setItem(
        'theme',
        body.classList.contains('light-mode') ? 'light' : 'dark'
      );
      updateThemeLabel();
      broadcastThemeToDemo();
    });
  }

  function broadcastThemeToDemo() {
    var theme = body.classList.contains('light-mode') ? 'light' : 'dark';
    var frame = document.getElementById('silmarils-demo-frame');
    if (frame && frame.contentWindow) {
      frame.contentWindow.postMessage({ type: 'qtl-theme', theme: theme }, '*');
    }
  }

  broadcastThemeToDemo();

  if (navToggle && siteNav) {
    navToggle.addEventListener('click', function () {
      const isOpen = siteNav.classList.toggle('is-open');
      navToggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
      navToggle.setAttribute(
        'aria-label',
        isOpen ? 'Close navigation menu' : 'Open navigation menu'
      );
    });

    siteNav.querySelectorAll('.nav-link').forEach(function (link) {
      link.addEventListener('click', function () {
        siteNav.classList.remove('is-open');
        navToggle.setAttribute('aria-expanded', 'false');
        navToggle.setAttribute('aria-label', 'Open navigation menu');
      });
    });

    document.addEventListener('click', function (event) {
      if (
        siteNav.classList.contains('is-open') &&
        !siteNav.contains(event.target) &&
        !navToggle.contains(event.target)
      ) {
        siteNav.classList.remove('is-open');
        navToggle.setAttribute('aria-expanded', 'false');
        navToggle.setAttribute('aria-label', 'Open navigation menu');
      }
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && siteNav.classList.contains('is-open')) {
        siteNav.classList.remove('is-open');
        navToggle.setAttribute('aria-expanded', 'false');
        navToggle.setAttribute('aria-label', 'Open navigation menu');
        navToggle.focus();
      }
    });
  }

  initScrollReveal();
})();

function initScrollReveal() {
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const targets = document.querySelectorAll('.reveal-target');

  if (!targets.length) return;

  if (reducedMotion) {
    targets.forEach(function (el) {
      el.classList.add('reveal-active');
    });
    return;
  }

  const staggerContainers = '.card-grid, .capabilities-grid, .research-grid, .timeline, .metrics-panel, .contact-grid, .contact-bullets';
  document.querySelectorAll(staggerContainers).forEach(function (container) {
    container.querySelectorAll('.reveal-target').forEach(function (el, index) {
      el.style.transitionDelay = Math.min(index * 0.1, 0.5) + 's';
    });
  });

  const observer = new IntersectionObserver(
    function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('reveal-active');
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.12, rootMargin: '0px 0px -40px 0px' }
  );

  targets.forEach(function (el) {
    observer.observe(el);
  });
}
