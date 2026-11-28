// How the Test Status Provider answers for the status list of a step (RP_PP_IA_Supportive): the URI the credential
// references and the behaviour registered for it.
import { createServer } from 'node:net';
import { durationMs, type Ics, type StatusEndpoint, type StatusListSpec } from '@eudi-pcaf/core';
import type { StatusBehaviour } from '@eudi-pcaf/status-provider';

/** How long after the declared timeout (ICS RP.R.6) a slow endpoint answers. */
export const SLOW_MARGIN_MS = 10_000;

/** A port of this host on which nothing listens: bound and released again, so the connection is refused. */
async function closedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '0.0.0.0', () => resolve());
  });
  const { port } = server.address() as { port: number };
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

/**
 * The status list URI of a step when it is not a new one of the Test Status Provider: the URI of an earlier step
 * (`uriOfStep`), the same path at a closed port of the harness host (`refused`), or the address the step names.
 */
export async function presetStatusUri(
  spec: StatusListSpec | null | undefined,
  earlier: Map<number, string>,
  allocate: () => string,
): Promise<string | undefined> {
  if (!spec) return undefined;
  if (spec.uriOfStep !== undefined) {
    const uri = earlier.get(spec.uriOfStep);
    if (!uri) throw new Error(`step ${spec.uriOfStep} recorded no status list URI`);
    return uri;
  }
  if (spec.endpoint?.kind === 'address') return spec.endpoint.uri;
  if (spec.endpoint?.kind === 'refused') {
    const url = new URL(allocate());
    url.port = String(await closedPort());
    return url.href;
  }
  return undefined;
}

/** Whether the Test Status Provider serves the step's status list at all. */
export const isServed = (endpoint: StatusEndpoint | undefined) => endpoint?.kind !== 'refused' && endpoint?.kind !== 'address';

/** The declared timeout of status list retrievals (ICS RP.R.6), milliseconds. */
export function statusTimeoutMs(ics: Ics): number | undefined {
  return durationMs(String(ics.items['RP.R.6'] ?? ''));
}

/** The behaviour and body the Test Status Provider serves for `uri`. */
export function servedAs(
  endpoint: StatusEndpoint | undefined,
  uri: string,
  served: { body: string | Uint8Array; contentType: string },
  ics: Ics,
): { body: string | Uint8Array; behaviour: StatusBehaviour } {
  const valid = { body: served.body, behaviour: { contentType: served.contentType } };
  switch (endpoint?.kind) {
    case undefined:
      return valid;
    case 'status':
      return {
        body: endpoint.body ?? served.body,
        behaviour: { status: endpoint.status, contentType: endpoint.contentType ?? served.contentType },
      };
    case 'slow': {
      const timeout = statusTimeoutMs(ics);
      if (timeout === undefined) throw new Error('the ICS declares no timeout for status list retrievals (RP.R.6)');
      return { ...valid, behaviour: { ...valid.behaviour, latencyMs: timeout + SLOW_MARGIN_MS } };
    }
    case 'redirect-loop':
      return { ...valid, behaviour: { ...valid.behaviour, redirectTo: uri } };
    default:
      return valid;
  }
}
