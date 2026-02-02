(() => {
  const prefersReduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const inView = (el) => {
    const r = el.getBoundingClientRect();
    return r.top < window.innerHeight * 0.86 && r.bottom > 0;
  };

  const animated = Array.from(document.querySelectorAll('[data-animate]'));
  const tick = () => {
    for (const el of animated) {
      if (el.classList.contains('in')) continue;
      if (inView(el)) {
        const d = Number(el.dataset.delay || '0');
        if (d) el.style.transitionDelay = `${d}ms`;
        el.classList.add('in');
      }
    }
  };

  if (!prefersReduced) {
    window.addEventListener('scroll', tick, { passive: true });
    window.addEventListener('resize', tick);
  }
  tick();

  const year = document.getElementById('year');
  if (year) year.textContent = String(new Date().getFullYear());

  const counters = Array.from(document.querySelectorAll('[data-count]'));
  const animateCounters = () => {
    for (const el of counters) {
      if (el.dataset.done === '1') continue;
      if (!inView(el)) continue;
      el.dataset.done = '1';
      const target = Number(el.dataset.count || '0');
      const start = performance.now();
      const dur = 900;
      const from = 0;
      const step = (t) => {
        const p = Math.min(1, (t - start) / dur);
        const eased = 1 - Math.pow(1 - p, 3);
        const v = Math.round(from + (target - from) * eased);
        el.textContent = String(v);
        if (p < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    }
  };

  if (!prefersReduced) {
    window.addEventListener('scroll', animateCounters, { passive: true });
    window.addEventListener('resize', animateCounters);
  }
  animateCounters();

  const stage = document.querySelector('[data-parallax]');
  const onMove = (e) => {
    if (!stage || prefersReduced) return;
    const rect = stage.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    stage.style.setProperty('--mx', (x * 16).toFixed(2));
    stage.style.setProperty('--my', (y * 14).toFixed(2));
  };

  if (stage && !prefersReduced) {
    stage.addEventListener('mousemove', onMove);
  }

  const applyParallax = () => {
    if (!stage || prefersReduced) return;
    const y = window.scrollY;
    const px = (Number(stage.style.getPropertyValue('--mx')) || 0);
    const py = (Number(stage.style.getPropertyValue('--my')) || 0);
    stage.style.transform = `translate3d(${px}px, ${py + Math.min(24, y * 0.04)}px, 0)`;
  };

  if (!prefersReduced) {
    window.addEventListener('scroll', applyParallax, { passive: true });
  }
  applyParallax();

  const track = document.querySelector('[data-carousel-track]');
  const prev = document.querySelector('[data-carousel-prev]');
  const next = document.querySelector('[data-carousel-next]');

  const scrollByCard = (dir) => {
    if (!track) return;
    const first = track.querySelector('.talent');
    const w = first ? first.getBoundingClientRect().width : 320;
    track.scrollBy({ left: dir * (w + 16), behavior: 'smooth' });
  };

  if (prev) prev.addEventListener('click', () => scrollByCard(-1));
  if (next) next.addEventListener('click', () => scrollByCard(1));


  const roleSelect = document.querySelector('[data-role-select]');
  const roleFields = Array.from(document.querySelectorAll('[data-role-field]'));
  const syncRoleFields = () => {
    if (!roleSelect) return;
    const role = String(roleSelect.value || 'audience');
    for (const wrap of roleFields) {
      const shouldShow = wrap.getAttribute('data-role-field') === role;
      wrap.hidden = !shouldShow;
      const inputs = Array.from(wrap.querySelectorAll('input, select, textarea'));
      for (const el of inputs) {
        if (el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement) {
          el.disabled = !shouldShow;
        }
      }
    }
  };
  if (roleSelect) {
    roleSelect.addEventListener('change', syncRoleFields);
    syncRoleFields();
  }

})();
