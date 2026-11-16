import { createReadStream, createWriteStream } from 'node:fs';
import { open, type FileHandle } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import { createInflateRaw, inflateRawSync } from 'node:zlib';

/**
 * A small ZIP reader for the cvelistV5 release assets: stored and deflated entries, ZIP64 (the
 * midnight baseline holds several hundred thousand records), random access over a buffer or a
 * file. No dependency, because the format subset is small and the input is untrusted.
 */
export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  size: number;
  localOffset: number;
}

interface RandomAccess {
  size: number;
  read(offset: number, length: number): Promise<Buffer>;
}

const EOCD = 0x06054b50;
const ZIP64_LOCATOR = 0x07064b50;
const ZIP64_EOCD = 0x06064b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;
const MAX = 0xffffffff;

function bufferSource(buffer: Buffer): RandomAccess {
  return {
    size: buffer.length,
    read: (offset, length) => Promise.resolve(buffer.subarray(offset, offset + length)),
  };
}

function fileSource(handle: FileHandle, size: number): RandomAccess {
  return {
    size,
    async read(offset, length) {
      const out = Buffer.alloc(length);
      const { bytesRead } = await handle.read(out, 0, length, offset);
      return out.subarray(0, bytesRead);
    },
  };
}

function u64(buffer: Buffer, at: number): number {
  const value = buffer.readBigUInt64LE(at);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('zip: offset too large');
  return Number(value);
}

async function centralDirectory(source: RandomAccess): Promise<ZipEntry[]> {
  const tailLength = Math.min(source.size, 22 + 0xffff);
  const tail = await source.read(source.size - tailLength, tailLength);
  let at = -1;
  for (let i = tail.length - 22; i >= 0; i -= 1) {
    if (tail.readUInt32LE(i) === EOCD) {
      at = i;
      break;
    }
  }
  if (at < 0) throw new Error('zip: end of central directory not found');
  let count = tail.readUInt16LE(at + 10);
  let cdSize = tail.readUInt32LE(at + 12);
  let cdOffset = tail.readUInt32LE(at + 16);
  if (count === 0xffff || cdSize === MAX || cdOffset === MAX) {
    const locatorAt = at - 20;
    if (locatorAt < 0 || tail.readUInt32LE(locatorAt) !== ZIP64_LOCATOR) {
      throw new Error('zip: ZIP64 locator not found');
    }
    const record = await source.read(u64(tail, locatorAt + 8), 56);
    if (record.readUInt32LE(0) !== ZIP64_EOCD) throw new Error('zip: bad ZIP64 record');
    count = u64(record, 32);
    cdSize = u64(record, 40);
    cdOffset = u64(record, 48);
  }
  const cd = await source.read(cdOffset, cdSize);
  const entries: ZipEntry[] = [];
  let p = 0;
  for (let i = 0; i < count; i += 1) {
    if (cd.readUInt32LE(p) !== CENTRAL) throw new Error('zip: bad central directory entry');
    const method = cd.readUInt16LE(p + 10);
    let compressedSize = cd.readUInt32LE(p + 20);
    let size = cd.readUInt32LE(p + 24);
    const nameLength = cd.readUInt16LE(p + 28);
    const extraLength = cd.readUInt16LE(p + 30);
    const commentLength = cd.readUInt16LE(p + 32);
    let localOffset = cd.readUInt32LE(p + 42);
    const name = cd.toString('utf8', p + 46, p + 46 + nameLength);
    let e = p + 46 + nameLength;
    const extraEnd = e + extraLength;
    while (e + 4 <= extraEnd) {
      const id = cd.readUInt16LE(e);
      const length = cd.readUInt16LE(e + 2);
      if (id === 0x0001) {
        let q = e + 4;
        if (size === MAX) {
          size = u64(cd, q);
          q += 8;
        }
        if (compressedSize === MAX) {
          compressedSize = u64(cd, q);
          q += 8;
        }
        if (localOffset === MAX) localOffset = u64(cd, q);
      }
      e += 4 + length;
    }
    entries.push({ name, method, compressedSize, size, localOffset });
    p = extraEnd + commentLength;
  }
  return entries;
}

async function dataOffset(source: RandomAccess, entry: ZipEntry): Promise<number> {
  const header = await source.read(entry.localOffset, 30);
  if (header.readUInt32LE(0) !== LOCAL) throw new Error(`zip: bad local header for ${entry.name}`);
  return entry.localOffset + 30 + header.readUInt16LE(26) + header.readUInt16LE(28);
}

async function readEntry(source: RandomAccess, entry: ZipEntry): Promise<Buffer> {
  const start = await dataOffset(source, entry);
  const raw = await source.read(start, entry.compressedSize);
  if (entry.method === 0) return raw;
  if (entry.method === 8) return inflateRawSync(raw, { maxOutputLength: Math.max(entry.size, 1) });
  throw new Error(`zip: unsupported method ${entry.method} for ${entry.name}`);
}

/** Calls visit for each file entry whose name passes the filter, in central directory order. */
async function each(
  source: RandomAccess,
  filter: (name: string) => boolean,
  visit: (name: string, data: Buffer) => void | Promise<void>,
): Promise<void> {
  for (const entry of await centralDirectory(source)) {
    if (entry.name.endsWith('/') || !filter(entry.name)) continue;
    await visit(entry.name, await readEntry(source, entry));
  }
}

/** Reads every matching entry of a ZIP held in memory. */
export async function readZipBuffer(
  buffer: Buffer,
  filter: (name: string) => boolean,
  visit: (name: string, data: Buffer) => void | Promise<void>,
): Promise<void> {
  await each(bufferSource(buffer), filter, visit);
}

/** Reads every matching entry of a ZIP file without loading the file into memory. */
export async function readZipFile(
  path: string,
  filter: (name: string) => boolean,
  visit: (name: string, data: Buffer) => void | Promise<void>,
): Promise<void> {
  const handle = await open(path, 'r');
  try {
    const { size } = await handle.stat();
    await each(fileSource(handle, size), filter, visit);
  } finally {
    await handle.close();
  }
}

/** Streams the single entry named by pick out of a ZIP file into target (for the zip inside a zip). */
export async function extractZipEntry(
  path: string,
  pick: (name: string) => boolean,
  target: string,
): Promise<string> {
  const handle = await open(path, 'r');
  let entry: ZipEntry | undefined;
  let start: number;
  try {
    const { size } = await handle.stat();
    const source = fileSource(handle, size);
    entry = (await centralDirectory(source)).find((candidate) => pick(candidate.name));
    if (entry === undefined) throw new Error(`zip: no matching entry in ${path}`);
    start = await dataOffset(source, entry);
  } finally {
    await handle.close();
  }
  const input = createReadStream(path, { start, end: start + entry.compressedSize - 1 });
  if (entry.method === 0) {
    await pipeline(input, createWriteStream(target));
  } else if (entry.method === 8) {
    await pipeline(input, createInflateRaw(), createWriteStream(target));
  } else {
    throw new Error(`zip: unsupported method ${entry.method}`);
  }
  return entry.name;
}
