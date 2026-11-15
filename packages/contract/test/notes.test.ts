import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { readNote, repoRoot, splitNote, toFeedNote, type CuratedNote } from '../src/index.ts';

const reviewed: CuratedNote = {
  advisory: 'CVE-2026-120154',
  products: ['postgresql'],
  audience: 'generic-selfhosters',
  exposure: 'not-default',
  assumptions: ['No row security policies are used.'],
  actions: [{ kind: 'upgrade' }],
  status: 'reviewed',
  authorship: 'human',
  reviewed_by: 'example-reviewer',
  reviewed_at: '2026-11-13',
};

describe('notes', () => {
  it('splits front matter from the body', () => {
    const parts = splitNote('---\nstatus: draft\n---\n\nHello.\n\n');
    expect(parts).toEqual({ frontMatter: { status: 'draft' }, body: 'Hello.\n' });
  });

  it('accepts Windows line endings', () => {
    expect(splitNote('---\r\nstatus: draft\r\n---\r\nHi\r\n').frontMatter).toEqual({
      status: 'draft',
    });
  });

  it('rejects a file without front matter', () => {
    expect(() => splitNote('# Just markdown\n')).toThrow(/front matter/);
  });

  it('reads the fixture note', () => {
    const entry = readNote(join(repoRoot(), 'fixtures/notes/CVE-2026-120154.md'));
    expect(Array.isArray(entry)).toBe(false);
  });

  it('publishes only reviewed notes', () => {
    expect(toFeedNote(reviewed, 'Body.\n')?.status).toBe('reviewed');
    for (const status of ['draft', 'disputed', 'superseded'] as const) {
      expect(toFeedNote({ ...reviewed, status }, 'Body.\n')).toBeNull();
    }
    expect(toFeedNote({ ...reviewed, authorship: 'model-drafted' }, 'Body.\n')).toBeNull();
  });
});
