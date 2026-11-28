// The publication checks of `OBS-SL` (issue 22), proven without a Provider, as the issuer harness design section 7
// asks of every output check: a status list the forge builds valid and serves well passes every check, and each mutation
// of the publication fails exactly its target check among the publication checks.
import { buildStatusListTokenCwt, buildStatusListTokenJwt, createTestPki, type TestPki } from '@eudi-pcaf/forge';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  evaluatePublishedStatus,
  type FetchedVersion,
  PUBLISHED_STATUS_CHECKS,
  type PublishedCheckResult,
  type PublishedStatusInput,
  readPublishedVersion,
} from '../src/index';

const URI = 'https://pp-a.rp-test/status/1';
const IDX = 7;
const ENTRIES = 16_384;
const MAX = 1 << 20;

let pki: TestPki;
beforeAll(async () => {
  pki = await createTestPki();
});

const signer = () => pki.entities['PP-A'].signers.revocation;
const statuses = (value = 0) => Array.from({ length: ENTRIES }, (_, i) => (i === IDX ? value : 0));

async function jwtVersion(options: { at?: Date; value?: number; ttl?: number; validitySeconds?: number; headers?: Record<string, string>; uri?: string; entries?: number } = {}): Promise<FetchedVersion> {
  const at = options.at ?? new Date();
  const body = await buildStatusListTokenJwt({
    signer: signer(),
    issuer: 'https://pp-a.rp-test',
    uri: options.uri ?? URI,
    statuses: options.entries ? Array.from({ length: options.entries }, () => 0) : statuses(options.value),
    bits: 2,
    now: at,
    ttl: options.ttl ?? 60,
    validitySeconds: options.validitySeconds ?? 120,
  });
  return { at, format: 'jwt', status: 200, headers: { 'content-type': 'application/statuslist+jwt', 'cache-control': 'max-age=60', ...options.headers }, body };
}

async function cwtVersion(): Promise<FetchedVersion> {
  const body = await buildStatusListTokenCwt({ signer: signer(), issuer: 'https://pp-a.rp-test', uri: URI, statuses: statuses(), bits: 2, ttl: 60, validitySeconds: 120 });
  return { at: new Date(), format: 'cwt', status: 200, headers: { 'content-type': 'application/statuslist+cwt' }, body };
}

async function valid(): Promise<PublishedStatusInput> {
  const first = await jwtVersion();
  const later = await jwtVersion({ at: new Date(Date.now() + 130_000) });
  return {
    format: 'jwt',
    reference: { uri: URI, idx: IDX },
    references: [
      { uri: URI, idx: IDX },
      { uri: URI, idx: IDX + 1 },
    ],
    issuer: { name: 'PP-A', statusAnchors: [pki.entities['PP-A'].anchors.revocation.certificate] },
    polls: [first, later],
    perFormat: [first, await cwtVersion()],
    declaredFormats: ['jwt', 'cwt'],
    minEntries: 10_000,
    allowLoopbackHttp: false,
    skewSeconds: 5,
    maxStatusListBytes: MAX,
  };
}

const failed = (results: PublishedCheckResult[]) => results.filter((r) => r.status === 'fail').map((r) => r.check);
const publicationFailures = (results: PublishedCheckResult[]) => failed(results).filter((c) => (PUBLISHED_STATUS_CHECKS as readonly string[]).includes(c));

describe('OBS-SL publication checks', () => {
  it('pass for a list served well, and the Status List Token checks pass too', async () => {
    const results = await evaluatePublishedStatus(await valid());
    expect(failed(results)).toEqual([]);
    for (const check of PUBLISHED_STATUS_CHECKS) expect(results.find((r) => r.check === check)?.status, check).toBe('pass');
    expect(results.find((r) => r.check === 'status-list-trust')?.status).toBe('pass');
  });

  const mutations: [string, (input: PublishedStatusInput) => Promise<void> | void][] = [
    ['sl-uri', (input) => {
      const uri = 'http://pp-a.rp-test/status/1';
      input.reference = { uri, idx: IDX };
      input.references = [{ uri, idx: IDX }, { uri, idx: IDX + 1 }];
    }],
    ['sl-anonymous', (input) => {
      (input.polls[0] as FetchedVersion).headers['www-authenticate'] = 'Bearer';
    }],
    ['sl-media-type', (input) => {
      (input.perFormat[1] as FetchedVersion).headers['content-type'] = 'application/statuslist+jwt';
    }],
    ['sl-cache', (input) => {
      const headers = (input.polls[0] as FetchedVersion).headers;
      headers['cache-control'] = 'public';
      delete headers.expires;
    }],
    ['sl-cache', (input) => {
      (input.polls[0] as FetchedVersion).headers['cache-control'] = 'max-age=3600';
    }],
    ['sl-uri-privacy', (input) => {
      input.references = [{ uri: URI, idx: IDX }, { uri: `${URI}x`, idx: IDX + 1 }];
    }],
    ['sl-uri-privacy', (input) => {
      (input.polls[0] as FetchedVersion).headers['set-cookie'] = 'id=1';
    }],
    ['sl-lifetime', async (input) => {
      // ttl 0, served with no-cache so that only the token's claims are wrong.
      const version = await jwtVersion({ ttl: 0, headers: { 'cache-control': 'no-cache' } });
      input.polls[0] = version;
      input.perFormat[0] = version;
    }],
    ['sl-entries', async (input) => {
      input.minEntries = 20_000;
    }],
    ['sl-signer-validity', async (input) => {
      // A token valid for longer than the signer certificate.
      const version = await jwtVersion({ validitySeconds: 20 * 365 * 24 * 60 * 60 });
      input.polls = [version];
      input.perFormat[0] = version;
    }],
    ['sl-continuity', async (input) => {
      const first = input.polls[0] as FetchedVersion;
      // The same (expired) version served again after its exp.
      input.polls[1] = { ...first, at: new Date(Date.now() + 130_000) };
    }],
  ];

  for (const [check, mutate] of mutations) {
    it(`a mutation of the publication fails exactly ${check}`, async () => {
      const input = await valid();
      await mutate(input);
      expect(publicationFailures(await evaluatePublishedStatus(input))).toEqual([check]);
    });
  }

  it('skips sl-continuity when no poll comes after the first exp, and sl-uri-privacy for one credential', async () => {
    const input = await valid();
    input.polls = input.polls.slice(0, 1);
    input.references = [input.reference];
    const results = await evaluatePublishedStatus(input);
    expect(results.find((r) => r.check === 'sl-continuity')?.status).toBe('skip');
    expect(results.find((r) => r.check === 'sl-uri-privacy')?.status).toBe('skip');
  });

  it('accepts http on a loopback host only in a local run', async () => {
    const input = await valid();
    const uri = 'http://127.0.0.1:3000/status/1';
    input.reference = { uri, idx: IDX };
    input.references = [{ uri, idx: IDX }, { uri, idx: IDX + 1 }];
    expect(publicationFailures(await evaluatePublishedStatus(input))).toEqual(['sl-uri']);
    input.allowLoopbackHttp = true;
    expect(publicationFailures(await evaluatePublishedStatus(input))).toEqual([]);
  });

  it('reads the status value and time claims of a version', async () => {
    expect(readPublishedVersion(await jwtVersion({ value: 1 }), IDX, MAX)).toMatchObject({ value: 1, ttl: 60 });
    expect(readPublishedVersion(await jwtVersion(), IDX, MAX).value).toBe(0);
    expect(readPublishedVersion({ ...(await jwtVersion()), status: 404 }, IDX, MAX)).toEqual({ error: 'HTTP 404' });
    expect(readPublishedVersion(await cwtVersion(), IDX, MAX).value).toBe(0);
  });
});
