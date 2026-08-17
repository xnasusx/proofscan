/**
 * Rate-limited, self-throttling, request-logging HTTP client for the dynamic
 * layer.
 *
 * Two non-negotiables from the build spec live here:
 *
 *  - "Rate-limit and back off automatically so scanning itself can't become a
 *    DoS against the target." Every request passes through a minimum-interval
 *    gate, and a 429 or 503 triggers exponential backoff that honours a
 *    Retry-After header when the server sends one.
 *  - "Log every request the dynamic layer makes (target, path, method,
 *    timestamp) to the same audit trail as findings." Every request is handed
 *    to a sink before the response is returned, so the audit log is a complete
 *    record of what the tool did to the target — including requests that failed.
 *
 * This client is the only thing in the dynamic layer that touches the network,
 * so those guarantees hold for the whole layer by construction.
 */

export interface DynamicRequestLog {
  seq: number;
  timestamp: string;
  actor: string;
  method: string;
  url: string;
  status: number | null;
  /** Milliseconds spent waiting on the rate-limit gate before sending. */
  throttledMs: number;
  /** How many times this request was retried after a backoff. */
  retries: number;
  /** Set when the request never got a response. */
  error: string | null;
}

export interface HttpResponse {
  status: number;
  body: unknown;
  headers: Record<string, string>;
}

export interface DynamicClientOptions {
  baseUrl: string;
  /** Minimum milliseconds between the start of one request and the next. */
  minIntervalMs?: number;
  /** Per-request timeout. */
  timeoutMs?: number;
  /** Max retries after a 429/503 backoff before giving up. */
  maxRetries?: number;
  /** Called with a log entry for every request attempt sequence. */
  onRequest: (log: DynamicRequestLog) => void;
  /** Injectable clock for deterministic tests. Defaults to real time/sleep. */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

const DEFAULT_MIN_INTERVAL_MS = 150;
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RETRIES = 3;

export class DynamicClient {
  private readonly baseUrl: string;
  private readonly minIntervalMs: number;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly onRequest: (log: DynamicRequestLog) => void;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;

  private lastStart = 0;
  private seq = 0;

  constructor(options: DynamicClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.minIntervalMs = options.minIntervalMs ?? DEFAULT_MIN_INTERVAL_MS;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.onRequest = options.onRequest;
    this.now = options.now ?? (() => Date.now());
    this.sleep = options.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  /** Wait until at least minIntervalMs has elapsed since the previous request start. */
  private async gate(): Promise<number> {
    const elapsed = this.now() - this.lastStart;
    const wait = Math.max(0, this.minIntervalMs - elapsed);
    if (wait > 0) await this.sleep(wait);
    this.lastStart = this.now();
    return wait;
  }

  /** Parse a Retry-After header (seconds, or an HTTP date) into milliseconds. */
  private retryAfterMs(headers: Record<string, string>): number | null {
    const raw = headers['retry-after'];
    if (!raw) return null;
    const seconds = Number(raw);
    if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
    const date = Date.parse(raw);
    return Number.isNaN(date) ? null : Math.max(0, date - this.now());
  }

  async request(
    actor: string,
    method: string,
    path: string,
    options: { token?: string | null; body?: unknown } = {},
  ): Promise<HttpResponse> {
    const url = path.startsWith('http') ? path : `${this.baseUrl}${path}`;
    const seq = ++this.seq;
    let retries = 0;
    let throttledMs = 0;

    for (;;) {
      throttledMs += await this.gate();

      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (options.token) headers.authorization = `Bearer ${options.token}`;

      let response: Response;
      try {
        response = await fetch(url, {
          method: method.toUpperCase(),
          headers,
          body: options.body === undefined ? undefined : JSON.stringify(options.body),
          signal: AbortSignal.timeout(this.timeoutMs),
        });
      } catch (err) {
        this.onRequest({
          seq,
          timestamp: new Date(this.now()).toISOString(),
          actor,
          method: method.toUpperCase(),
          url,
          status: null,
          throttledMs,
          retries,
          error: (err as Error).message,
        });
        throw err;
      }

      const respHeaders: Record<string, string> = {};
      response.headers.forEach((v, k) => {
        respHeaders[k.toLowerCase()] = v;
      });

      // Back off on rate-limit / overload signals rather than hammering.
      if ((response.status === 429 || response.status === 503) && retries < this.maxRetries) {
        const retryAfter = this.retryAfterMs(respHeaders);
        const backoff = retryAfter ?? Math.min(8000, this.minIntervalMs * 2 ** (retries + 1));
        this.onRequest({
          seq,
          timestamp: new Date(this.now()).toISOString(),
          actor,
          method: method.toUpperCase(),
          url,
          status: response.status,
          throttledMs,
          retries,
          error: `backing off ${backoff}ms after ${response.status}`,
        });
        retries++;
        await this.sleep(backoff);
        continue;
      }

      let body: unknown = null;
      try {
        const text = await response.text();
        body = text ? JSON.parse(text) : null;
      } catch {
        body = null;
      }

      this.onRequest({
        seq,
        timestamp: new Date(this.now()).toISOString(),
        actor,
        method: method.toUpperCase(),
        url,
        status: response.status,
        throttledMs,
        retries,
        error: null,
      });

      return { status: response.status, body, headers: respHeaders };
    }
  }
}
