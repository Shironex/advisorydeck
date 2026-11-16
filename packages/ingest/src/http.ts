import { createWriteStream } from 'node:fs';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

/** The subset of fetch ingest uses; tests pass a fake that serves recorded responses. */
export type FetchLike = (
  url: string,
  init?: { headers?: Record<string, string> },
) => Promise<Response>;

export class RateLimitError extends Error {
  readonly url: string;
  readonly resetAt: Date | undefined;

  constructor(url: string, resetAt: Date | undefined) {
    super(
      `GitHub rate limit reached on ${url}${resetAt === undefined ? '' : `, resets at ${resetAt.toISOString()}`}. Set GITHUB_TOKEN for a higher limit.`,
    );
    this.url = url;
    this.resetAt = resetAt;
  }
}

export interface HttpOptions {
  fetch?: FetchLike;
  /** Sent as a bearer token to api.github.com only. */
  githubToken?: string | undefined;
  sleep?: (ms: number) => Promise<void>;
  log?: (message: string) => void;
  /** Longest wait for a rate limit reset before giving up (default 60 s). */
  maxWaitMs?: number;
}

export interface JsonResponse<T> {
  data: T;
  /** URL of the next page from the Link header, if any. */
  next: string | undefined;
}

const USER_AGENT = 'advisorydeck-ingest (+https://github.com/Shironex/advisorydeck)';

function nextLink(header: string | null): string | undefined {
  if (header === null) return undefined;
  for (const part of header.split(',')) {
    const match = /<([^>]+)>;\s*rel="next"/.exec(part);
    if (match?.[1] !== undefined) return match[1];
  }
  return undefined;
}

/** Native fetch with a user agent, GitHub auth and rate limit handling, and retries on 5xx. */
export class Http {
  private readonly fetchImpl: FetchLike;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly log: (message: string) => void;
  private readonly maxWaitMs: number;
  /** Lowest X-RateLimit-Remaining seen on api.github.com, for the run summary. */
  rateRemaining: number | undefined;
  private readonly options: HttpOptions;

  constructor(options: HttpOptions = {}) {
    this.options = options;
    this.fetchImpl = options.fetch ?? ((url, init) => fetch(url, init));
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.log = options.log ?? (() => undefined);
    this.maxWaitMs = options.maxWaitMs ?? 60_000;
  }

  /** Waits, with the injected sleep (tests pass one that returns at once). */
  pause(ms: number): Promise<void> {
    return this.sleep(ms);
  }

  get authenticated(): boolean {
    return this.options.githubToken !== undefined && this.options.githubToken !== '';
  }

  private headers(url: string): Record<string, string> {
    const headers: Record<string, string> = { 'User-Agent': USER_AGENT };
    if (new URL(url).hostname === 'api.github.com') {
      headers['Accept'] = 'application/vnd.github+json';
      headers['X-GitHub-Api-Version'] = '2022-11-28';
      if (this.authenticated) headers['Authorization'] = `Bearer ${this.options.githubToken ?? ''}`;
    }
    return headers;
  }

  /** Fetches with retries; returns undefined for 404 so callers can treat "gone" explicitly. */
  async request(url: string): Promise<Response | undefined> {
    for (let attempt = 1; ; attempt += 1) {
      let response: Response;
      try {
        response = await this.fetchImpl(url, { headers: this.headers(url) });
      } catch (error) {
        if (attempt >= 3) throw error;
        await this.sleep(1000 * 2 ** attempt);
        continue;
      }
      const remaining = response.headers.get('x-ratelimit-remaining');
      if (remaining !== null) {
        const value = Number(remaining);
        this.rateRemaining = Math.min(this.rateRemaining ?? value, value);
      }
      if (response.ok) return response;
      if (response.status === 404) return undefined;
      if (response.status === 403 || response.status === 429) {
        const retryAfter = response.headers.get('retry-after');
        const reset = response.headers.get('x-ratelimit-reset');
        const resetAt = reset === null ? undefined : new Date(Number(reset) * 1000);
        const limited = retryAfter !== null || remaining === '0';
        if (limited) {
          const waitMs =
            retryAfter !== null
              ? Number(retryAfter) * 1000
              : Math.max(0, (resetAt?.getTime() ?? Date.now()) - Date.now()) + 1000;
          if (waitMs > this.maxWaitMs || attempt >= 3) throw new RateLimitError(url, resetAt);
          this.log(`rate limited on ${url}, waiting ${Math.ceil(waitMs / 1000)} s`);
          await this.sleep(waitMs);
          continue;
        }
      }
      if (response.status >= 500 && attempt < 3) {
        await this.sleep(1000 * 2 ** attempt);
        continue;
      }
      throw new Error(`GET ${url}: HTTP ${response.status}`);
    }
  }

  async json<T>(url: string): Promise<JsonResponse<T> | undefined> {
    const response = await this.request(url);
    if (response === undefined) return undefined;
    return { data: (await response.json()) as T, next: nextLink(response.headers.get('link')) };
  }

  async bytes(url: string): Promise<Buffer | undefined> {
    const response = await this.request(url);
    return response === undefined ? undefined : Buffer.from(await response.arrayBuffer());
  }

  /** Streams a large download to a file (the midnight baseline is several hundred MB). */
  async download(url: string, target: string): Promise<void> {
    const response = await this.request(url);
    if (response?.body == null) throw new Error(`GET ${url}: not found`);
    await pipeline(Readable.fromWeb(response.body), createWriteStream(target));
  }
}
