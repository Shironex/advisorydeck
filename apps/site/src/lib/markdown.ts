/**
 * A deliberately small Markdown renderer for curated note bodies. Notes are contributor text, so
 * everything is escaped first and only a safe subset is turned back into markup: paragraphs,
 * lists, fenced code, inline code, bold, italics and https links. Raw HTML is shown as text.
 */

export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function inline(text: string): string {
  const codes: string[] = [];
  let out = escapeHtml(text).replace(/`([^`]+)`/g, (_m, code: string) => {
    codes.push(`<code>${code}</code>`);
    return `\u0000${codes.length - 1}\u0000`;
  });
  out = out
    .replace(
      /\[([^\]]+)\]\((https:\/\/[^\s)]+)\)/g,
      (_m, label: string, url: string) => `<a href="${url}" rel="noopener noreferrer">${label}</a>`,
    )
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^*\w])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>')
    .replace(/(^|[^_\w])_([^_\s][^_]*)_/g, '$1<em>$2</em>');
  // eslint-disable-next-line no-control-regex
  return out.replace(/\u0000(\d+)\u0000/g, (_m, i: string) => codes[Number(i)] ?? '');
}

export function renderNoteMarkdown(source: string): string {
  const lines = source.replace(/\r\n/g, '\n').split('\n');
  const blocks: string[] = [];
  let paragraph: string[] = [];
  let list: { ordered: boolean; items: string[] } | null = null;

  const flushParagraph = (): void => {
    if (paragraph.length > 0) {
      blocks.push(`<p>${inline(paragraph.join(' '))}</p>`);
      paragraph = [];
    }
  };
  const flushList = (): void => {
    if (list !== null) {
      const tag = list.ordered ? 'ol' : 'ul';
      blocks.push(`<${tag}>${list.items.map((i) => `<li>${inline(i)}</li>`).join('')}</${tag}>`);
      list = null;
    }
  };

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    if (line.startsWith('```')) {
      flushParagraph();
      flushList();
      const code: string[] = [];
      i += 1;
      while (i < lines.length && !(lines[i] ?? '').startsWith('```')) {
        code.push(lines[i] ?? '');
        i += 1;
      }
      blocks.push(`<pre><code>${escapeHtml(code.join('\n'))}</code></pre>`);
      continue;
    }
    const bullet = /^\s*[-*]\s+(.*)$/.exec(line);
    const numbered = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    if (bullet !== null || numbered !== null) {
      flushParagraph();
      const ordered = numbered !== null;
      if (list !== null && list.ordered !== ordered) {
        flushList();
      }
      list ??= { ordered, items: [] };
      list.items.push((bullet ?? numbered)?.[1] ?? '');
      continue;
    }
    if (line.trim() === '') {
      flushParagraph();
      flushList();
      continue;
    }
    flushList();
    paragraph.push(line.trim());
  }
  flushParagraph();
  flushList();
  return blocks.join('\n');
}
