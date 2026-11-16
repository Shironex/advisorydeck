/**
 * The generator's browser side: reads the form, renders the three files, validates the config
 * against the schema, blocks Copy and Download while a problem exists, and keeps the setup in
 * the URL fragment. It makes no network requests.
 */
import {
  CHANNEL_TYPES,
  decodeState,
  defaultState,
  encodeState,
  formProblems,
  toCompose,
  toConfigYaml,
  toEnvTemplate,
  type FormProblem,
  type GeneratorState,
  type Mode,
  type PickedProduct,
  type Severity,
} from '../lib/generator.ts';
import { validateConfigYaml } from '../lib/validate-config.ts';

interface ProductInfo {
  slug: string;
  name: string;
  branches: { name: string; eol: boolean; latest: string | null }[];
  image: string | null;
}

interface Payload {
  feedUrl: string;
  products: ProductInfo[];
}

type OutputKey = 'config' | 'compose' | 'env';
const FILENAMES: Record<OutputKey, string> = {
  config: 'advisorydeck.yml',
  compose: 'compose.yml',
  env: '.env',
};

// The caller names the element type it expects from the selector.
// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters
function $<T extends Element>(root: ParentNode, selector: string): T {
  const element = root.querySelector<T>(selector);
  if (element === null) {
    throw new Error(`generator: missing ${selector}`);
  }
  return element;
}

function browserZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
}

function timeZones(): string[] {
  try {
    const zones = (
      Intl as unknown as { supportedValuesOf?: (key: string) => string[] }
    ).supportedValuesOf?.('timeZone');
    if (zones !== undefined && zones.length > 0) {
      return zones.includes('UTC') ? zones : ['UTC', ...zones];
    }
  } catch {
    /* older browser: fall through */
  }
  return ['UTC'];
}

/** One generated line as spans: keys, values and comments, for the line-numbered view. */
function highlight(line: string): HTMLElement {
  const ln = document.createElement('span');
  ln.className = 'ln';
  const add = (cls: string | null, text: string): void => {
    if (text === '') return;
    if (cls === null) {
      ln.append(text);
      return;
    }
    const span = document.createElement('span');
    span.className = cls;
    span.textContent = text;
    ln.append(span);
  };
  const comment = /^(\s*)(#.*)$/.exec(line);
  if (comment) {
    add(null, comment[1] ?? '');
    add('c', comment[2] ?? '');
    return ln;
  }
  const pair = /^(\s*(?:- )?)([A-Za-z_][\w-]*[:=])(.*)$/.exec(line);
  if (pair) {
    add(null, pair[1] ?? '');
    add('k', pair[2] ?? '');
    const rest = pair[3] ?? '';
    const tail = /^(.*?)(\s+#.*)?$/.exec(rest);
    const value = tail?.[1] ?? rest;
    const lead = /^\s*/.exec(value)?.[0] ?? '';
    add(null, lead);
    add('s', value.slice(lead.length));
    add('c', tail?.[2] ?? '');
    return ln;
  }
  const item = /^(\s*- )(.*)$/.exec(line);
  if (item) {
    add(null, item[1] ?? '');
    add('s', item[2] ?? '');
    return ln;
  }
  add(null, line);
  return ln;
}

/** Index of the generated line a problem points at, or -1. */
function badLine(lines: readonly string[], problem: FormProblem): number {
  const nth = (prefix: string, index: number): number => {
    let seen = -1;
    return lines.findIndex((l) => l.startsWith(prefix) && ++seen === index);
  };
  switch (problem.target.kind) {
    case 'product':
      return nth('    version:', problem.target.index);
    case 'channel':
      return nth('    url_env:', problem.target.index);
    case 'time':
      return nth('  time:', 0);
    case 'timezone':
      return nth('  timezone:', 0);
    default:
      return -1;
  }
}

export function startGenerator(): void {
  const root = document.querySelector<HTMLElement>('[data-generator]');
  const dataElement = document.getElementById('generator-data');
  if (root === null || dataElement === null) {
    return;
  }
  const payload = JSON.parse(dataElement.textContent || '{}') as Payload;
  const products = new Map(payload.products.map((p) => [p.slug, p]));
  const form = $<HTMLFormElement>(root, 'form');
  const list = $<HTMLUListElement>(root, '[data-products]');
  const template = $<HTMLTemplateElement>(root, '[data-product-template]');
  const addButton = $<HTMLButtonElement>(root, '[data-add-product]');
  const timeInput = $<HTMLInputElement>(form, '#digest-time');
  const zoneInput = $<HTMLInputElement>(form, '#timezone');
  const digestFields = $<HTMLElement>(form, '[data-digest-fields]');
  const valid = $<HTMLElement>(root, '[data-valid]');
  const copyButton = $<HTMLButtonElement>(root, '[data-copy]');
  const downloadButton = $<HTMLButtonElement>(root, '[data-download]');
  const outputs: Record<OutputKey, string> = { config: '', compose: '', env: '' };
  let active: OutputKey = 'config';
  let blocked = false;
  let rowId = 0;

  const zones = document.getElementById('time-zones');
  zones?.replaceChildren(
    ...timeZones().map((zone) => {
      const option = document.createElement('option');
      option.value = zone;
      return option;
    }),
  );

  function rows(): HTMLLIElement[] {
    return [...list.querySelectorAll<HTMLLIElement>(':scope > li')];
  }

  function syncRow(row: HTMLLIElement): PickedProduct {
    const slug = $<HTMLSelectElement>(row, '[data-product]').value;
    const info = products.get(slug);
    const floating =
      row.querySelector<HTMLInputElement>('[data-kind]:checked')?.value === 'floating';
    const input = $<HTMLInputElement>(row, '[data-version]');
    const version = input.value.trim();
    $<HTMLElement>(row, '[data-version-label]').textContent = floating ? 'Branch' : 'Version';
    $<HTMLElement>(row, '[data-pin-legend]').textContent = `How you pin ${info?.name ?? slug}`;
    $<HTMLElement>(row, '[data-remove-product]').setAttribute(
      'aria-label',
      `Remove ${info?.name ?? slug}`,
    );
    const supported = info?.branches.find((b) => !b.eol);
    input.placeholder = floating ? (supported?.name ?? '') : (supported?.latest ?? '');
    if (floating && info !== undefined && info.branches.length > 0) {
      input.setAttribute('list', `branches-${slug}`);
    } else {
      input.removeAttribute('list');
    }
    const hint = $<HTMLElement>(row, '[data-hint]');
    hint.replaceChildren();
    const branch = info?.branches.find((b) => b.name === version);
    if (floating) {
      const tag = info?.image && version !== '' ? `${info.image}:${version}` : null;
      if (branch?.eol) {
        hint.append(
          `Branch ${version} is end of life and gets no security fixes. The notifier will remind you.`,
        );
      } else if (tag !== null) {
        const code = document.createElement('code');
        code.className = 'code-inline';
        code.textContent = tag;
        hint.append('You pull ', code, `, so every ${version}.x release counts as yours.`);
      } else {
        hint.append('Every release of the branch counts as yours.');
      }
    } else {
      hint.append(
        version === ''
          ? 'The exact version you run.'
          : `Matches advisories that affect exactly ${version}.`,
      );
    }
    return { slug, kind: floating ? 'floating' : 'exact', version };
  }

  function addRow(picked: PickedProduct): HTMLLIElement {
    rowId += 1;
    const fragment = template.content.cloneNode(true) as DocumentFragment;
    const row = $<HTMLLIElement>(fragment, 'li');
    const select = $<HTMLSelectElement>(row, '[data-product]');
    const input = $<HTMLInputElement>(row, '[data-version]');
    select.id = `product-${rowId}`;
    input.id = `version-${rowId}`;
    $<HTMLElement>(row, '[data-for="product"]').setAttribute('for', select.id);
    $<HTMLElement>(row, '[data-for="version"]').setAttribute('for', input.id);
    const hint = $<HTMLElement>(row, '[data-hint]');
    hint.id = `version-${rowId}-hint`;
    const error = $<HTMLElement>(row, '[data-error]');
    error.id = `version-${rowId}-error`;
    input.setAttribute('aria-describedby', hint.id);
    for (const radio of row.querySelectorAll<HTMLInputElement>('[data-kind]')) {
      radio.name = `pin-${rowId}`;
      radio.checked = radio.value === picked.kind;
    }
    select.value = picked.slug;
    input.value = picked.version;
    list.append(row);
    syncRow(row);
    return row;
  }

  function nextFreeProduct(): string {
    const taken = new Set(rows().map((r) => $<HTMLSelectElement>(r, '[data-product]').value));
    return (
      payload.products.find((p) => !taken.has(p.slug))?.slug ?? payload.products[0]?.slug ?? ''
    );
  }

  function writeForm(state: GeneratorState): void {
    list.replaceChildren();
    for (const picked of state.products) {
      addRow(picked);
    }
    const severity = form.querySelector<HTMLInputElement>(
      `input[name="severity"][value="${state.minSeverity}"]`,
    );
    if (severity !== null) severity.checked = true;
    const mode = form.querySelector<HTMLInputElement>(`input[name="mode"][value="${state.mode}"]`);
    if (mode !== null) mode.checked = true;
    timeInput.value = state.digestTime;
    zoneInput.value = state.timezone;
    // One channel per type: the first of each type in the state wins.
    for (const type of CHANNEL_TYPES) {
      const item = $<HTMLElement>(form, `[data-channel="${type}"]`);
      const picked = state.channels.find((c) => c.type === type);
      $<HTMLInputElement>(item, '[data-channel-on]').checked = picked !== undefined;
      if (picked !== undefined)
        $<HTMLInputElement>(item, '[data-channel-env]').value = picked.urlEnv;
    }
  }

  function readForm(): GeneratorState {
    const state = defaultState(browserZone());
    state.products = rows().map(syncRow);
    state.minSeverity = (form.querySelector<HTMLInputElement>('input[name="severity"]:checked')
      ?.value ?? 'high') as Severity;
    state.mode = (form.querySelector<HTMLInputElement>('input[name="mode"]:checked')?.value ??
      'digest') as Mode;
    digestFields.hidden = state.mode === 'instant';
    state.digestTime = timeInput.value.trim();
    state.timezone = zoneInput.value.trim();
    state.channels = CHANNEL_TYPES.flatMap((type) => {
      const item = $<HTMLElement>(form, `[data-channel="${type}"]`);
      const on = $<HTMLInputElement>(item, '[data-channel-on]').checked;
      const env = $<HTMLInputElement>(item, '[data-channel-env]');
      env.disabled = !on;
      item.querySelector('.field')?.classList.toggle('is-off', !on);
      return on ? [{ type, urlEnv: env.value.trim(), name: '' }] : [];
    });
    for (const button of list.querySelectorAll<HTMLButtonElement>('[data-remove-product]')) {
      button.disabled = state.products.length <= 1;
    }
    addButton.disabled = state.products.length >= payload.products.length;
    return state;
  }

  /** The field a problem belongs to, for aria-invalid, its error text and the "Fix it" link. */
  function fieldOf(
    problem: FormProblem,
    state: GeneratorState,
  ): { input: HTMLElement; error: HTMLElement | null } | null {
    const t = problem.target;
    if (t.kind === 'product') {
      const row = rows()[t.index];
      return row
        ? {
            input: $<HTMLElement>(row, '[data-version]'),
            error: $<HTMLElement>(row, '[data-error]'),
          }
        : null;
    }
    if (t.kind === 'channel') {
      const type = state.channels[t.index]?.type;
      if (type === undefined) return null;
      return {
        input: $<HTMLElement>(form, `#env-${type}`),
        error: document.getElementById(`env-${type}-error`),
      };
    }
    if (t.kind === 'time')
      return { input: timeInput, error: document.getElementById('digest-time-error') };
    if (t.kind === 'timezone') return { input: zoneInput, error: null };
    if (t.kind === 'products')
      return { input: addButton, error: document.getElementById('products-error') };
    return {
      input: $<HTMLElement>(form, '#env-discord'),
      error: document.getElementById('channels-error'),
    };
  }

  function markFields(problems: FormProblem[], state: GeneratorState): void {
    for (const el of form.querySelectorAll<HTMLElement>('[aria-invalid="true"]')) {
      el.setAttribute('aria-invalid', 'false');
      const base = el.dataset['describedBy'];
      if (base !== undefined) el.setAttribute('aria-describedby', base);
    }
    for (const el of root?.querySelectorAll<HTMLElement>('.error-text') ?? []) el.hidden = true;
    for (const problem of problems) {
      const field = fieldOf(problem, state);
      if (field === null) continue;
      if (field.input.matches('input')) {
        field.input.setAttribute('aria-invalid', 'true');
        if (field.error !== null) {
          field.input.dataset['describedBy'] ??= field.input.getAttribute('aria-describedby') ?? '';
          field.input.setAttribute(
            'aria-describedby',
            `${field.input.dataset['describedBy']} ${field.error.id}`.trim(),
          );
        }
      }
      if (field.error !== null) {
        field.error.hidden = false;
        const text = field.error.querySelector('[data-error-text]');
        if (text !== null) text.textContent = problem.message.replace(/^[a-z0-9-]+: /, '');
      }
    }
  }

  function renderCode(key: OutputKey, bad: Set<number>): void {
    const target = $<HTMLElement>(root as HTMLElement, `[data-code="${key}"]`);
    const lines = outputs[key].replace(/\n$/, '').split('\n');
    target.replaceChildren(
      ...lines.map((line, i) => {
        const ln = highlight(line);
        if (bad.has(i)) ln.classList.add('is-bad');
        return ln;
      }),
    );
  }

  function renderValid(
    problems: FormProblem[],
    schemaProblems: string[],
    state: GeneratorState,
  ): void {
    valid.replaceChildren();
    const total = problems.length + schemaProblems.length;
    blocked = total > 0;
    valid.classList.toggle('valid--bad', blocked);
    const icon = valid.ownerDocument.createElementNS('http://www.w3.org/2000/svg', 'svg');
    icon.setAttribute('class', 'icon');
    icon.setAttribute('viewBox', '0 0 24 24');
    icon.setAttribute('aria-hidden', 'true');
    icon.innerHTML = blocked
      ? '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.8v5M12 15.9v.1"/>'
      : '<circle cx="12" cy="12" r="8.5"/><path d="M8.5 12.2l2.4 2.4 4.6-4.9"/>';
    const text = document.createElement('span');
    text.id = 'valid-text';
    const strong = document.createElement('strong');
    if (!blocked) {
      strong.textContent = 'Valid';
      text.append(strong, ' against the image-config v1 schema');
    } else {
      strong.textContent = `${total} ${total === 1 ? 'problem' : 'problems'}:`;
      const first = problems[0];
      text.append(strong, ` ${first?.message ?? schemaProblems[0] ?? ''} `);
      const field = first ? fieldOf(first, state) : null;
      if (field !== null && field.input.id !== '') {
        const link = document.createElement('a');
        link.href = `#${field.input.id}`;
        link.textContent = 'Fix it';
        link.addEventListener('click', (event) => {
          event.preventDefault();
          field.input.focus();
        });
        text.append(link, ' to copy or download.');
      } else {
        text.append('Fix it to copy or download.');
      }
    }
    valid.append(icon, text);
    for (const button of [copyButton, downloadButton]) {
      if (blocked) {
        button.setAttribute('aria-disabled', 'true');
        button.setAttribute('aria-describedby', 'valid-text');
      } else {
        button.removeAttribute('aria-disabled');
        button.removeAttribute('aria-describedby');
      }
    }
  }

  function render(): void {
    const state = readForm();
    outputs.config = toConfigYaml(state, payload.feedUrl);
    outputs.compose = toCompose(state);
    outputs.env = toEnvTemplate(state);
    const problems = formProblems(state);
    const schemaProblems = problems.length > 0 ? [] : validateConfigYaml(outputs.config);
    const configLines = outputs.config.split('\n');
    renderCode(
      'config',
      new Set(problems.map((p) => badLine(configLines, p)).filter((i) => i >= 0)),
    );
    renderCode('compose', new Set());
    renderCode('env', new Set());
    markFields(problems, state);
    renderValid(problems, schemaProblems, state);
    history.replaceState(null, '', `${location.pathname}${location.search}#${encodeState(state)}`);
  }

  function select(key: OutputKey, focus: boolean): void {
    active = key;
    for (const tab of root?.querySelectorAll<HTMLButtonElement>('[role="tab"]') ?? []) {
      const on = tab.dataset['tab'] === key;
      tab.setAttribute('aria-selected', on ? 'true' : 'false');
      tab.tabIndex = on ? 0 : -1;
      const panel = document.getElementById(tab.getAttribute('aria-controls') ?? '');
      if (panel !== null) panel.hidden = !on;
      if (on && focus) tab.focus();
    }
  }

  async function copy(text: string, label: Element | null, idle: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      if (label) label.textContent = 'Copied';
    } catch {
      if (label) label.textContent = 'Copy failed: select the text';
    }
    window.setTimeout(() => {
      if (label) label.textContent = idle;
    }, 1600);
  }

  function download(text: string, filename: string): void {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  form.addEventListener('input', render);
  form.addEventListener('change', render);
  form.addEventListener('submit', (event) => {
    event.preventDefault();
  });
  root.addEventListener('click', (event) => {
    const target = (event.target as Element).closest<HTMLButtonElement>('button');
    if (target === null) return;
    if (target.matches('[data-add-product]')) {
      const row = addRow({ slug: nextFreeProduct(), kind: 'exact', version: '' });
      render();
      $<HTMLInputElement>(row, '[data-version]').focus();
    } else if (target.matches('[data-remove-product]')) {
      const row = target.closest('li');
      const neighbour = row?.nextElementSibling ?? row?.previousElementSibling;
      row?.remove();
      render();
      (neighbour?.querySelector<HTMLElement>('[data-product]') ?? addButton).focus();
    } else if (target.dataset['tab'] !== undefined) {
      select(target.dataset['tab'] as OutputKey, false);
    } else if (target.matches('[data-copy]')) {
      if (!blocked) void copy(outputs[active], target.querySelector('[data-copy-label]'), 'Copy');
    } else if (target.matches('[data-download]')) {
      if (!blocked) download(outputs[active], FILENAMES[active]);
    } else if (target.matches('[data-copy-link]')) {
      void copy(location.href, target, 'Copy a link to this setup');
    }
  });
  root.addEventListener('keydown', (event) => {
    const tab = (event.target as Element).closest<HTMLButtonElement>('[role="tab"]');
    if (tab === null || (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft')) return;
    const keys: OutputKey[] = ['config', 'compose', 'env'];
    const i = keys.indexOf(tab.dataset['tab'] as OutputKey) + (event.key === 'ArrowRight' ? 1 : -1);
    select(keys[(i + keys.length) % keys.length] ?? 'config', true);
    event.preventDefault();
  });

  const state = decodeState(location.hash, new Set(products.keys()), browserZone());
  if (state.products.length === 0) {
    // A first row to start from: PostgreSQL on its newest supported branch when it is listed.
    const first = products.get('postgresql') ?? payload.products[0];
    const branch = first?.branches.find((b) => !b.eol);
    state.products.push({
      slug: first?.slug ?? '',
      kind: branch ? 'floating' : 'exact',
      version: branch?.name ?? '',
    });
  }
  writeForm(state);
  root.hidden = false;
  render();
}
