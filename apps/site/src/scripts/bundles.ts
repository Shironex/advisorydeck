/**
 * Release bundles and feed filters. Without JavaScript every row is shown and the toggles stay
 * hidden; with it, closed bundles fold to their head and open ones show their first rows.
 */

function rowsOf(bundle: HTMLElement): HTMLElement[] {
  return [...bundle.querySelectorAll<HTMLElement>('.rows > .row')];
}

function setBundle(bundle: HTMLElement, state: 'closed' | 'preview' | 'all'): void {
  const list = bundle.querySelector<HTMLElement>('.rows');
  const toggle = bundle.querySelector<HTMLButtonElement>('[data-bundle-toggle]');
  const foot = bundle.querySelector<HTMLElement>('[data-bundle-foot]');
  const preview = Number(bundle.dataset['preview'] ?? '3');
  const rows = rowsOf(bundle);
  if (list !== null) list.hidden = state === 'closed';
  rows.forEach((row, i) => {
    row.hidden = state === 'preview' && i >= preview;
  });
  if (foot !== null) foot.hidden = state !== 'preview';
  bundle.dataset['open'] = state === 'closed' ? 'false' : 'true';
  if (toggle !== null) {
    toggle.hidden = false;
    toggle.setAttribute('aria-expanded', state === 'closed' ? 'false' : 'true');
    toggle.textContent = state === 'closed' ? `Show all ${toggle.dataset['total'] ?? ''}` : 'Hide';
  }
}

export function startBundles(root: ParentNode = document): void {
  for (const bundle of root.querySelectorAll<HTMLElement>('[data-bundle]')) {
    setBundle(bundle, bundle.dataset['open'] === 'true' ? 'preview' : 'closed');
    bundle.querySelector('[data-bundle-toggle]')?.addEventListener('click', () => {
      setBundle(bundle, bundle.dataset['open'] === 'true' ? 'closed' : 'all');
    });
    bundle.querySelector('[data-bundle-more]')?.addEventListener('click', () => {
      setBundle(bundle, 'all');
      rowsOf(bundle)[Number(bundle.dataset['preview'] ?? '3')]?.querySelector('a')?.focus();
    });
  }
}

/**
 * Filters rows by severity and by product or branch. While a filter is on, every bundle opens
 * fully and groups without a matching row are hidden.
 */
export function startFilters(form: HTMLElement, scope: HTMLElement): void {
  const apply = (): void => {
    const sev = form.querySelector<HTMLInputElement>('input[type="radio"]:checked')?.value ?? '';
    const select = form.querySelector<HTMLSelectElement>('select');
    const key = select?.dataset['filter'] ?? 'product';
    const value = select?.value ?? '';
    const active = sev !== '' || value !== '';
    for (const row of scope.querySelectorAll<HTMLElement>('.row')) {
      const values = (row.dataset[key === 'branch' ? 'branches' : 'product'] ?? '').split(' ');
      const match =
        (sev === '' || row.dataset['sev'] === sev) && (value === '' || values.includes(value));
      row.toggleAttribute('data-filtered', !match);
    }
    for (const bundle of scope.querySelectorAll<HTMLElement>('[data-bundle]')) {
      if (active) setBundle(bundle, 'all');
      bundle.hidden = rowsOf(bundle).every((r) => r.hasAttribute('data-filtered'));
    }
    for (const group of scope.querySelectorAll<HTMLElement>('[data-group]')) {
      group.hidden = [...group.querySelectorAll<HTMLElement>('.row')].every((r) =>
        r.hasAttribute('data-filtered'),
      );
    }
    const empty = scope.querySelector<HTMLElement>('[data-filter-empty]');
    if (empty !== null) {
      empty.hidden = [...scope.querySelectorAll<HTMLElement>('.row')].some(
        (r) => !r.hasAttribute('data-filtered'),
      );
    }
  };
  form.addEventListener('change', apply);
  form.hidden = false;
}
