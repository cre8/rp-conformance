import { type RequestLogEntry, type RunningServer, type ServerOptions, sendJson, startServer } from '@rp-conformance/core';

export interface TrustInfrastructureOptions extends ServerOptions {
  /** Base URL under which the Relying Party reaches the lists, for example `http://host.docker.internal:7002`. */
  publicBaseUrl?: string;
  /** Host name under which the Relying Party reaches the service, combined with the port it listens on. */
  publicHost?: string;
}

interface PublishedVersion {
  version: number;
  body: string;
  contentType: string;
  publishedAt: string;
}

/**
 * Test Trust Infrastructure: serves the lists of `default_trust_configuration_rp` per namespace
 * (`<base>/<namespace>/<list>`), versioned, and logs every retrieval (harness design section 4.7): the LoTEs as JWTs,
 * the LOTL and `TL-QEAA` as XML (`<list>` ends in `.xml`, ETSI TS 119 612 clause 6.1).
 * `<base>/<namespace>/<list>` serves the latest version, `<base>/<namespace>/<list>/v<n>` a given one.
 */
export class TrustInfrastructure {
  private server?: RunningServer;
  private publicBaseUrl = '';
  private readonly lists = new Map<string, PublishedVersion[]>();
  readonly log: RequestLogEntry[] = [];

  async start(options: TrustInfrastructureOptions = {}): Promise<this> {
    this.server = await startServer(options, (req, res) => {
      const path = new URL(req.url ?? '/', 'http://localhost').pathname;
      const match = /^\/([^/]+)\/([^/]+)(?:\/v(\d+))?$/.exec(path);
      const versions = match ? this.lists.get(`${match[1]}/${match[2]}`) : undefined;
      const entry = versions && (match?.[3] ? versions.find((v) => v.version === Number(match[3])) : versions[versions.length - 1]);
      this.log.push({ at: new Date().toISOString(), method: req.method ?? 'GET', url: `${this.publicBaseUrl}${path}`, headers: req.headers, status: entry ? 200 : 404, version: entry?.version });
      if (!entry) return sendJson(res, 404, { error: 'not_found' });
      res.writeHead(200, { 'content-type': entry.contentType, 'cache-control': 'no-store', 'x-lote-version': String(entry.version) });
      res.end(entry.body);
    });
    const server = this.server;
    const fromHost = options.publicHost && `${new URL(server.localUrl).protocol}//${options.publicHost}:${server.port}`;
    this.publicBaseUrl = (options.publicBaseUrl ?? fromHost ?? server.localUrl).replace(/\/$/, '');
    return this;
  }

  get baseUrl(): string {
    return this.publicBaseUrl;
  }

  urlOf(namespace: string, listId: string): string {
    return `${this.publicBaseUrl}/${namespace}/${listId}`;
  }

  /** Publishes a new version of a list and returns its URL and version number. */
  publish(namespace: string, listId: string, body: string, contentType = 'application/jwt'): { url: string; version: number } {
    const key = `${namespace}/${listId}`;
    const versions = this.lists.get(key) ?? [];
    const version = versions.length + 1;
    versions.push({ version, body, contentType, publishedAt: new Date().toISOString() });
    this.lists.set(key, versions);
    return { url: this.urlOf(namespace, listId), version };
  }

  /** Retrievals of a list, optionally only those at or after a time. */
  retrievalsOf(namespace: string, listId: string, since?: Date): RequestLogEntry[] {
    const prefix = this.urlOf(namespace, listId);
    return this.log.filter((e) => (e.url === prefix || e.url.startsWith(`${prefix}/v`)) && (!since || new Date(e.at) >= since));
  }

  async stop() {
    await this.server?.close();
  }
}
