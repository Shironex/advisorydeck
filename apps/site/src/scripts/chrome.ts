/**
 * Behaviour every page shares: the theme toggle, the "/" shortcut and the search dialog. The
 * search index is a file of this site (search.json), loaded on first open; nothing is sent
 * anywhere.
 */

type Theme = 'light' | 'dark';

function currentTheme(): Theme {
  const set = document.documentElement.dataset['theme'];
  if (set === 'light' || set === 'dark') return set;
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function labelToggle(button: HTMLElement): void {
  button.setAttribute(
    'aria-label',
    currentTheme() === 'light' ? 'Switch to dark theme' : 'Switch to light theme',
  );
}

function startTheme(): void {
  const button = document.querySelector<HTMLElement>('[data-theme-toggle]');
  if (button === null) return;
  labelToggle(button);
  button.addEventListener('click', () => {
    const next: Theme = currentTheme() === 'light' ? 'dark' : 'light';
    document.documentElement.dataset['theme'] = next;
    try {
      localStorage.setItem('ad-theme', next);
    } catch {
      /* no storage: the choice lasts for this page */
    }
    labelToggle(button);
  });
  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
    labelToggle(button);
  });
}

interface Entry {
  /** Advisory ID or product name. */
  t: string;
  /** Title or category. */
  d: string;
  /** Product names, for advisories. */
  p: string;
  u: string;
}

function startSearch(): void {
  const dialog = document.querySelector<HTMLDialogElement>('[data-search-dialog]');
  const input = document.querySelector<HTMLInputElement>('[data-search-input]');
  const results = document.querySelector<HTMLUListElement>('[data-search-results]');
  const status = document.querySelector<HTMLElement>('[data-search-status]');
  if (dialog === null || input === null || results === null || status === null) return;
  let index: Entry[] | null = null;
  let loading: Promise<void> | null = null;

  function load(): Promise<void> {
    loading ??= fetch(results?.dataset['index'] ?? 'search.json')
      .then((r) =>
        r.ok ? (r.json() as Promise<Entry[]>) : Promise.reject(new Error(r.statusText)),
      )
      .then((entries) => {
        index = entries;
      })
      .catch(() => {
        if (status) status.textContent = 'The search index could not be loaded.';
      });
    return loading;
  }

  function render(): void {
    if (results === null || status === null || input === null) return;
    const query = input.value.trim().toLowerCase();
    results.replaceChildren();
    if (query === '' || index === null) {
      status.textContent =
        index === null
          ? 'Loading the index.'
          : 'Type to search. Nothing you type leaves this page.';
      return;
    }
    const words = query.split(/\s+/);
    const hits = index
      .filter((e) => {
        const hay = `${e.t} ${e.d} ${e.p}`.toLowerCase();
        return words.every((w) => hay.includes(w));
      })
      .slice(0, 20);
    for (const hit of hits) {
      const li = document.createElement('li');
      const a = document.createElement('a');
      a.href = hit.u;
      const id = document.createElement('span');
      id.className = 'search-id';
      id.textContent = hit.t;
      const text = document.createElement('span');
      text.className = 'search-text';
      text.textContent = hit.p ? `${hit.p}: ${hit.d}` : hit.d;
      a.append(id, text);
      li.append(a);
      results.append(li);
    }
    status.textContent =
      hits.length === 0
        ? 'No match.'
        : `${hits.length}${hits.length === 20 ? ' or more' : ''} ${hits.length === 1 ? 'match' : 'matches'}.`;
  }

  function open(): void {
    if (dialog === null || input === null) return;
    if (!dialog.open) dialog.showModal();
    input.focus();
    void load().then(render);
  }

  for (const button of document.querySelectorAll('[data-search-open]')) {
    button.addEventListener('click', open);
  }
  input.addEventListener('input', render);
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      const first = results.querySelector('a');
      if (first !== null) {
        event.preventDefault();
        window.location.href = first.href;
      }
    }
  });
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) dialog.close();
  });
  document.addEventListener('keydown', (event) => {
    const target = event.target as HTMLElement | null;
    const typing =
      target !== null &&
      (/^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName) || target.isContentEditable);
    if (event.key === '/' && !typing && !event.metaKey && !event.ctrlKey && !event.altKey) {
      event.preventDefault();
      open();
    }
  });
}

export function startChrome(): void {
  startTheme();
  startSearch();
}
