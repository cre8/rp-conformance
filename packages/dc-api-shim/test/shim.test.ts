import { startServer, sendJson, sendText, type RunningServer } from '@rp-conformance/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DcApiShim } from '../src/index';

// The shim against a minimal page: the page's request reaches the answer with the page's real Origin, the page's
// promise resolves with a DigitalCredential, and the request in which the page forwards the response is found.
let shim: DcApiShim;
let server: RunningServer;
const posted: unknown[] = [];

const PAGE = `<!doctype html><title>t</title><script type="module">
const credential = await navigator.credentials.get({ digital: { requests: [{ protocol: 'openid4vp-v1-signed', data: { request: 'abc' } }] } });
const proto = credential instanceof DigitalCredential;
await fetch('/forward', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ protocol: credential.protocol, data: credential.data, proto }) });
</script>`;

beforeAll(async () => {
  shim = await DcApiShim.launch();
  server = await startServer({ host: '127.0.0.1' }, (req, res, body) => {
    if (req.url === '/page') return sendText(res, 200, PAGE, 'text/html');
    posted.push(JSON.parse(body.toString()));
    return sendJson(res, 400, { error: 'invalid_request' });
  });
});

afterAll(async () => {
  await shim?.close();
  await server?.close();
});

describe('DC API shim', () => {
  it('forwards the request with the page origin and finds the delivery of the response', async () => {
    const run = await shim.run(`${server.localUrl}/page`, async (call) => {
      expect(call.origin).toBe(server.localUrl);
      expect(call.requests).toEqual([{ protocol: 'openid4vp-v1-signed', data: { request: 'abc' } }]);
      return { kind: 'respond', protocol: 'openid4vp-v1-signed', data: { response: 'jwe-marker' }, marker: 'jwe-marker' };
    });
    expect(run.error).toBeUndefined();
    expect(run.delivery).toMatchObject({ method: 'POST', url: `${server.localUrl}/forward`, status: 400 });
    expect(posted.at(-1)).toEqual({ protocol: 'openid4vp-v1-signed', data: { response: 'jwe-marker' }, proto: true });
  }, 30_000);

  it('withholds the response: the page never receives one', async () => {
    const before = posted.length;
    const run = await shim.run(`${server.localUrl}/page`, async () => ({ kind: 'withhold' }));
    expect(run.calls).toHaveLength(1);
    expect(run.delivery).toBeUndefined();
    expect(posted).toHaveLength(before);
  }, 30_000);
});
