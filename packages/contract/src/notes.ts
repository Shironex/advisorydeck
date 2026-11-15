import { readFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { listFiles, parseYaml, relativePath } from './files.ts';
import type { CuratedNote, FeedNote } from './generated/types.ts';
import type { Issue } from './issues.ts';
import { repoLayout, repoRoot } from './layout.ts';
import { validateAgainst } from './schemas.ts';

export interface NoteEntry {
  file: string;
  note: CuratedNote;
  /** Markdown body, trimmed, ending with one newline. */
  body: string;
}

const FRONT_MATTER = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;

/** Splits a note file into its YAML front matter (parsed) and Markdown body. */
export function splitNote(text: string): { frontMatter: unknown; body: string } {
  const match = FRONT_MATTER.exec(text);
  if (match === null) {
    throw new Error('a note starts with YAML front matter between --- lines');
  }
  const body = (match[2] ?? '').trim();
  return { frontMatter: parseYaml(match[1] ?? ''), body: body === '' ? '' : `${body}\n` };
}

/** Parses and validates one note file. Returns the entry or the problems found. */
export function readNote(path: string, root = repoRoot()): NoteEntry | Issue[] {
  const file = relativePath(root, path);
  let parts: { frontMatter: unknown; body: string };
  try {
    parts = splitNote(readFileSync(path, 'utf8'));
  } catch (error) {
    return [{ file, message: String(error) }];
  }
  const issues = validateAgainst('curated-note', parts.frontMatter, root).map((message) => ({
    file,
    message,
  }));
  if (issues.length > 0) {
    return issues;
  }
  const note = parts.frontMatter as CuratedNote;
  if (note.advisory !== basename(path, '.md')) {
    issues.push({ file, message: `advisory ${note.advisory} must equal the file name` });
  }
  if (parts.body === '') {
    issues.push({ file, message: 'the note body is empty' });
  }
  return issues.length > 0 ? issues : { file, note, body: parts.body };
}

/** Loads every note in notes/ (README.md is documentation, not a note). */
export function loadNotes(root = repoRoot()): { notes: NoteEntry[]; issues: Issue[] } {
  const notes: NoteEntry[] = [];
  const issues: Issue[] = [];
  for (const path of listFiles(join(root, repoLayout.notesDir), ['.md'])) {
    if (basename(path) === 'README.md') {
      continue;
    }
    const result = readNote(path, root);
    if (Array.isArray(result)) {
      issues.push(...result);
    } else {
      notes.push(result);
    }
  }
  return { notes, issues };
}

/** The note as it is published inside an advisory, or null: only reviewed notes are published. */
export function toFeedNote(note: CuratedNote, body: string): FeedNote | null {
  if (
    note.status !== 'reviewed' ||
    note.authorship === 'model-drafted' ||
    note.reviewed_by === undefined ||
    note.reviewed_at === undefined
  ) {
    return null;
  }
  return {
    status: 'reviewed',
    audience: note.audience,
    exposure: note.exposure,
    assumptions: note.assumptions,
    actions: note.actions,
    authorship: note.authorship,
    reviewed_by: note.reviewed_by,
    reviewed_at: note.reviewed_at,
    body,
  };
}
