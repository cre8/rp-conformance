import { randomUUID } from 'node:crypto';
import { type RequestLogEntry, type RunningServer, type ServerOptions, sendJson, startServer } from '@rp-conformance/core';

/** How the Test Status Provider answers for one URL (harness design section 4.6). */
export interface StatusBehaviour {
  /** HTTP status; default 200. */
  status?: number;
  /** Content type; default `application/statuslist+jwt`. */
  contentType?: string;
  /** Delay before answering, milliseconds. */
  latencyMs?: number;
  /** Redirect to this URL instead of answering. */
  redirectTo?: string;
}

interface Registration {
  body?: string;
  behaviour: StatusBehaviour;
}

export interface StatusProviderOptions extends ServerOptions {
  /** Base URL under which the Relying Party reaches the provider, for example `http://host.docker.internal:7001`. */
  publicBaseUrl?: string;
  /** Host name under which the Relying Party reaches the service, combined with the port it listens on. */
  publicHost?: string;
}

/**
 * Test Status Provider: serves the status artifact registered for each credential under its own URL
 * (`<base>/<run>/<uuid>`), so the Relying Party's cache never masks a fault and every request maps to one step.
 * Every request is logged.
 */
export class StatusProvider {
  private server?: RunningServer;
  private publicBaseUrl = '';
  private readonly registrations = new Map<string, Registration>();
  readonly log: RequestLogEntry[] = [];

  async start(options: StatusProviderOptions = {}): Promise<this> {
    this.server = await startServer(options, async (req, res) => {
      const path = new URL(req.url ?? '/', 'http://localhost').pathname;
      const registration = this.registrations.get(path);
      const status = registration ? (registration.behaviour.redirectTo ? 302 : (registration.behaviour.status ?? 200)) : 404;
      this.log.push({ at: new Date().toISOString(), method: req.method ?? 'GET', url: `${this.publicBaseUrl}${path}`, headers: req.headers, status });
      if (!registration) return sendJson(res, 404, { error: 'not_found' });
      const { behaviour, body } = registration;
      if (behaviour.latencyMs) await new Promise((resolve) => setTimeout(resolve, behaviour.latencyMs));
      if (behaviour.redirectTo) {
        res.writeHead(302, { location: behaviour.redirectTo });
        return res.end();
      }
      res.writeHead(status, { 'content-type': behaviour.contentType ?? 'application/statuslist+jwt', 'cache-control': 'no-store' });
      res.end(body ?? '');
    });
    const server = this.server;
    const fromHost = options.publicHost && `${new URL(server.localUrl).protocol}//${options.publicHost}:${server.port}`;
    this.publicBaseUrl = (options.publicBaseUrl ?? fromHost ?? server.localUrl).replace(/\/$/, '');
    return this;
  }

  get baseUrl(): string {
    return this.publicBaseUrl;
  }

  /** Allocates a new unique status URL for a credential of a run. */
  allocate(runId: string): string {
    if (!this.server) throw new Error('Status provider not started');
    return `${this.publicBaseUrl}/${runId}/${randomUUID()}`;
  }

  /** Registers what the URL serves. */
  register(url: string, body: string | undefined, behaviour: StatusBehaviour = {}) {
    this.registrations.set(new URL(url).pathname, { body, behaviour });
  }

  /** Requests for a URL, optionally only those at or after a time. */
  requestsFor(url: string, since?: Date): RequestLogEntry[] {
    return this.log.filter((entry) => entry.url === url && (!since || new Date(entry.at) >= since));
  }

  async stop() {
    await this.server?.close();
  }
}
