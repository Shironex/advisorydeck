/**
 * The generator's browser side: reads the form, renders the three files, validates the config
 * against the schema and keeps the setup in the URL fragment. It makes no network requests.
 */
import {
  decodeState,
  defaultState,
  encodeState,
  nextEnvName,
  stateProblems,
  toCompose,
  toConfigYaml,
  toEnvTemplate,
  type ChannelType,
  type GeneratorState,
  type Mode,
  type PickedChannel,
  type Severity,
} from '../lib/generator.ts';
import { validateConfigYaml } from '../lib/validate-config.ts';

interface Payload {
  feedUrl: string;
  products: {
    slug: string;
    name: string;
    branches: { name: string; eol: boolean; latest: string | null }[];
  }[];
}

type OutputKey = 'config' | 'compose' | 'env';

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

export function startGenerator(): void {
  const root = document.querySelector<HTMLElement>('[data-generator]');
  const dataElement = document.getElementById('generator-data');
  if (root === null || dataElement === null) {
    return;
  }
  const payload = JSON.parse(dataElement.textContent || '{}') as Payload;
  const products = new Map(payload.products.map((p) => [p.slug, p]));
  const form = $<HTMLFormElement>(root, 'form');
  const channelList = $<HTMLUListElement>(root, '[data-channels]');
  const channelTemplate = $<HTMLTemplateElement>(root, '[data-channel-template]');
  const zoneSelect = $<HTMLSelectElement>(form, 'select[name="timezone"]');
  const timeInput = $<HTMLInputElement>(form, 'input[name="digest-time"]');
  const digestFields = $<HTMLElement>(form, '[data-digest-fields]');
  const status = $<HTMLElement>(root, '[data-status]');
  const outputs: Record<OutputKey, string> = { config: '', compose: '', env: '' };

  // Time zones, filled here so the page ships no list of hundreds of names.
  const zones = timeZones();
  zoneSelect.replaceChildren(
    ...zones.map((zone) => {
      const option = document.createElement('option');
      option.value = zone;
      option.textContent = zone;
      return option;
    }),
  );

  function pickRow(slug: string): HTMLElement | null {
    return form.querySelector<HTMLElement>(`.pick[data-slug="${CSS.escape(slug)}"]`);
  }

  function addChannel(channel: PickedChannel): void {
    const fragment = channelTemplate.content.cloneNode(true) as DocumentFragment;
    const item = $<HTMLLIElement>(fragment, 'li');
    $<HTMLSelectElement>(item, '[data-channel-type]').value = channel.type;
    $<HTMLInputElement>(item, '[data-channel-env]').value = channel.urlEnv;
    $<HTMLInputElement>(item, '[data-channel-name]').value = channel.name;
    channelList.append(item);
  }

  /** Puts a state into the form (on load from the fragment). */
  function writeForm(state: GeneratorState): void {
    for (const picked of state.products) {
      const row = pickRow(picked.slug);
      if (row === null) {
        continue;
      }
      $<HTMLInputElement>(row, '[data-product-toggle]').checked = true;
      const kind = row.querySelector<HTMLInputElement>(`[data-kind][value="${picked.kind}"]`);
      if (kind !== null) {
        kind.checked = true;
      }
      if (picked.kind === 'floating') {
        const select = row.querySelector<HTMLSelectElement>('[data-branch]');
        if (select !== null && [...select.options].some((o) => o.value === picked.version)) {
          select.value = picked.version;
        }
      } else {
        $<HTMLInputElement>(row, '[data-exact]').value = picked.version;
      }
    }
    const severity = form.querySelector<HTMLInputElement>(
      `input[name="severity"][value="${state.minSeverity}"]`,
    );
    if (severity !== null) severity.checked = true;
    const mode = form.querySelector<HTMLInputElement>(`input[name="mode"][value="${state.mode}"]`);
    if (mode !== null) mode.checked = true;
    timeInput.value = state.digestTime;
    if (!zones.includes(state.timezone)) {
      const option = document.createElement('option');
      option.value = state.timezone;
      option.textContent = state.timezone;
      zoneSelect.prepend(option);
    }
    zoneSelect.value = state.timezone;
    channelList.replaceChildren();
    for (const channel of state.channels) {
      addChannel(channel);
    }
  }

  /** Reads the form into a state and syncs which panels are visible. */
  function readForm(): GeneratorState {
    const state = defaultState(browserZone());
    state.products = [];
    for (const row of form.querySelectorAll<HTMLElement>('.pick')) {
      const slug = row.dataset['slug'] ?? '';
      const on = $<HTMLInputElement>(row, '[data-product-toggle]').checked;
      const panel = $<HTMLElement>(row, '[data-version-panel]');
      panel.hidden = !on;
      if (!on || !products.has(slug)) {
        continue;
      }
      const floating =
        row.querySelector<HTMLInputElement>('[data-kind][value="floating"]')?.checked === true;
      const branchField = row.querySelector<HTMLElement>('[data-branch-field]');
      const exactField = $<HTMLElement>(row, '[data-exact-field]');
      const exact = $<HTMLInputElement>(row, '[data-exact]');
      if (branchField !== null) branchField.hidden = !floating;
      exactField.hidden = floating;
      const floatingHint = row.querySelector<HTMLElement>('[data-hint-floating]');
      if (floatingHint !== null) floatingHint.hidden = !floating;
      $<HTMLElement>(row, '[data-hint-exact]').hidden = floating;
      const branch = row.querySelector<HTMLSelectElement>('[data-branch]')?.value ?? '';
      const version = floating ? branch : exact.value.trim();
      const info = products.get(slug);
      const eol = floating && info?.branches.find((b) => b.name === branch)?.eol === true;
      $<HTMLElement>(row, '[data-eol-warning]').hidden = !eol;
      exact.setAttribute(
        'aria-invalid',
        !floating && version !== '' && !/^[0-9A-Za-z][0-9A-Za-z.+:~_-]*$/.test(version)
          ? 'true'
          : 'false',
      );
      state.products.push({ slug, kind: floating ? 'floating' : 'exact', version });
    }
    state.minSeverity = (form.querySelector<HTMLInputElement>('input[name="severity"]:checked')
      ?.value ?? 'high') as Severity;
    state.mode = (form.querySelector<HTMLInputElement>('input[name="mode"]:checked')?.value ??
      'digest') as Mode;
    digestFields.hidden = state.mode === 'instant';
    state.digestTime = timeInput.value || '08:00';
    state.timezone = zoneSelect.value || 'UTC';
    state.channels = [...channelList.querySelectorAll<HTMLLIElement>('li')].map((item) => ({
      type: $<HTMLSelectElement>(item, '[data-channel-type]').value as ChannelType,
      urlEnv: $<HTMLInputElement>(item, '[data-channel-env]').value.trim(),
      name: $<HTMLInputElement>(item, '[data-channel-name]').value,
    }));
    for (const button of channelList.querySelectorAll<HTMLButtonElement>('[data-remove-channel]')) {
      button.disabled = state.channels.length <= 1;
    }
    return state;
  }

  function renderStatus(problems: string[]): void {
    status.replaceChildren();
    const box = document.createElement('div');
    if (problems.length === 0) {
      box.className = 'ok';
      box.textContent =
        'advisorydeck.yml is valid: it passes the image config schema and the rules the image adds.';
    } else {
      box.className = 'bad';
      const lead = document.createElement('p');
      lead.textContent = 'Not ready yet:';
      const list = document.createElement('ul');
      for (const problem of problems) {
        const li = document.createElement('li');
        li.textContent = problem;
        list.append(li);
      }
      box.append(lead, list);
    }
    status.append(box);
  }

  function render(): void {
    const state = readForm();
    outputs.config = toConfigYaml(state, payload.feedUrl);
    outputs.compose = toCompose(state);
    outputs.env = toEnvTemplate(state);
    for (const key of Object.keys(outputs) as OutputKey[]) {
      $<HTMLElement>(root as HTMLElement, `[data-code="${key}"]`).textContent = outputs[key];
    }
    const formProblems = stateProblems(state);
    renderStatus(formProblems.length > 0 ? formProblems : validateConfigYaml(outputs.config));
    const fragment = encodeState(state);
    history.replaceState(null, '', `${location.pathname}${location.search}#${fragment}`);
  }

  async function copy(text: string, button: HTMLButtonElement): Promise<void> {
    const label = button.firstChild;
    try {
      await navigator.clipboard.writeText(text);
      if (label) label.textContent = 'Copied';
    } catch {
      if (label) label.textContent = 'Copy failed: select the text';
    }
    window.setTimeout(() => {
      if (label)
        label.textContent =
          button.dataset['copyLink'] !== undefined ? 'Copy a link to this setup' : 'Copy';
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
    if (target === null) {
      return;
    }
    if (target.matches('[data-add-channel]')) {
      const taken = [...channelList.querySelectorAll<HTMLInputElement>('[data-channel-env]')].map(
        (i) => i.value,
      );
      addChannel({ type: 'discord', urlEnv: nextEnvName('discord', taken), name: '' });
      render();
      channelList.querySelector<HTMLSelectElement>('li:last-child [data-channel-type]')?.focus();
    } else if (target.matches('[data-remove-channel]')) {
      const item = target.closest('li');
      const previous = item?.previousElementSibling ?? item?.nextElementSibling;
      item?.remove();
      render();
      (
        previous?.querySelector<HTMLSelectElement>('[data-channel-type]') ??
        $<HTMLButtonElement>(root, '[data-add-channel]')
      ).focus();
    } else if (target.dataset['copy'] !== undefined) {
      void copy(outputs[target.dataset['copy'] as OutputKey], target);
    } else if (target.dataset['download'] !== undefined) {
      download(
        outputs[target.dataset['download'] as OutputKey],
        target.dataset['filename'] ?? 'file.txt',
      );
    } else if (target.matches('[data-copy-link]')) {
      void copy(location.href, target);
    }
  });
  // Changing a channel's type moves a default variable name along with it.
  channelList.addEventListener('change', (event) => {
    const select = event.target as HTMLElement;
    if (!select.matches('[data-channel-type]')) {
      return;
    }
    const item = select.closest('li');
    const env = item?.querySelector<HTMLInputElement>('[data-channel-env]');
    if (env && /^(DISCORD|SLACK|GENERIC)_WEBHOOK_URL(_\d+)?$/.test(env.value)) {
      const others = [...channelList.querySelectorAll<HTMLInputElement>('[data-channel-env]')]
        .filter((i) => i !== env)
        .map((i) => i.value);
      env.value = nextEnvName((select as HTMLSelectElement).value as ChannelType, others);
    }
  });

  writeForm(decodeState(location.hash, new Set(products.keys()), browserZone()));
  root.hidden = false;
  render();
}
