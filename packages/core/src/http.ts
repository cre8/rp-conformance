import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';

export interface TlsOptions {
  certificatePem: string;
  privateKeyPem: string;
}

export interface ServerOptions {
  /** Port to listen on; 0 picks a free port. */
  port?: number;
  /** Interface to bind; defaults to all interfaces so containers can reach the harness. */
  host?: string;
  tls?: TlsOptions;
}

export interface RunningServer {
  /** `http(s)://localhost:<port>` */
  localUrl: string;
  port: number;
  close(): Promise<void>;
}

export type Handler = (req: IncomingMessage, res: ServerResponse, body: Buffer) => Promise<unknown> | unknown;

/** Starts an HTTP(S) server that buffers each request body before calling the handler. */
export async function startServer(options: ServerOptions, handler: Handler): Promise<RunningServer> {
  const listener = (req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      Promise.resolve(handler(req, res, Buffer.concat(chunks))).catch((error: unknown) => {
        if (!res.headersSent) {
          sendJson(res, 500, { error: 'internal_error', message: (error as Error).message });
        } else {
          res.end();
        }
      });
    });
  };
  const server = options.tls
    ? createHttpsServer({ cert: options.tls.certificatePem, key: options.tls.privateKeyPem }, listener)
    : createHttpServer(listener);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port ?? 0, options.host ?? '0.0.0.0', () => resolve());
  });
  const { port } = server.address() as AddressInfo;
  return {
    localUrl: `${options.tls ? 'https' : 'http'}://localhost:${port}`,
    port,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

export function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
  res.end(JSON.stringify(body));
}

export function sendText(res: ServerResponse, status: number, body: string, contentType: string) {
  res.writeHead(status, { 'content-type': contentType, 'cache-control': 'no-store' });
  res.end(body);
}

/** One request received by a harness service, part of the evidence of a step. */
export interface RequestLogEntry {
  at: string;
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  status: number;
  /** The version of a list the Test Trust Infrastructure served. */
  version?: number;
}
