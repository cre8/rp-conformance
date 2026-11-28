// Issue 26: the versions of `TL-WP` a `trust-list` step publishes (PP_Inf_SM_TrustMechanisms), built with the RP
// harness's trust-list faults, and the Wallet Units of `WP-C` and `WP-W` they are about.
import { base64url, buildTrustListVersion, createTestPki, type TestPki } from '@eudi-pcaf/forge';
import { StatusProvider } from '@eudi-pcaf/status-provider';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { anchorsInList, serviceFor, TestWalletProvider, tlWpEntities } from '../src/index';

let pki: TestPki;
let status: StatusProvider;

beforeAll(async () => {
  pki = await createTestPki();
  status = await new StatusProvider().start({ host: '127.0.0.1' });
});

afterAll(async () => {
  await status.stop();
});

const version = (action: Parameters<typeof buildTrustListVersion>[0], previous = 5) =>
  buildTrustListVersion(action, { pki, entities: action.list === 'TL-WP' ? [...tlWpEntities(pki, 1), ...((action as { add?: string[] }).add ?? [])] : [], sequenceNumber: 6, previousSequenceNumber: previous, graceMs: 0 });
const payload = (jws: string) => base64url.decodeJson<{ LoTE: { ListAndSchemeInformation?: { LoTESequenceNumber?: number } } & Record<string, unknown> }>(jws.split('.')[1] ?? '');
const wiaAnchors = (document: unknown, provider: string) => {
  const { type, name } = serviceFor(pki.entities[provider], 'wia');
  return anchorsInList(document, { entity: provider, type, name });
};

describe('TL-WP versions', () => {
  it('is sealed by the TL-WP scheme operator and lists WP-A with its WIA anchor', async () => {
    const built = await version({ kind: 'trust-list', list: 'TL-WP' });
    const header = base64url.decodeJson<{ x5c: string[] }>(built.body.split('.')[0] ?? '');
    expect(header.x5c[0]).toBe(Buffer.from(pki.schemeOperators['TL-WP'].certificate.der).toString('base64'));
    expect(wiaAnchors(payload(built.body), 'WP-A')).toHaveLength(1);
    expect(built.sequenceNumber).toBe(6);
  });

  it('withdraws the issuance services of an entity and keeps its revocation service', async () => {
    const document = payload((await version({ kind: 'trust-list', list: 'TL-WP', withdraw: ['WP-A'] })).body);
    expect(wiaAnchors(document, 'WP-A')).toEqual([]);
    expect(anchorsInList(document, { entity: 'WP-A', ...serviceFor(pki.entities['WP-A'], 'status') })).toHaveLength(1);
  });

  it('grants WP-W again and adds WP-C', async () => {
    expect(wiaAnchors(payload((await version({ kind: 'trust-list', list: 'TL-WP' })).body), 'WP-W')).toEqual([]);
    expect(wiaAnchors(payload((await version({ kind: 'trust-list', list: 'TL-WP', restoreIssuance: ['WP-W'] })).body), 'WP-W')).toHaveLength(1);
    expect(wiaAnchors(payload((await version({ kind: 'trust-list', list: 'TL-WP', add: ['WP-C'] })).body), 'WP-C')).toHaveLength(1);
  });

  it('rolls back below the previous sequence number', async () => {
    expect((await version({ kind: 'trust-list', list: 'TL-WP', faults: ['trust-list.rollback'] }, 5)).sequenceNumber).toBe(4);
  });

  it('has Wallet Units of WP-C and WP-W with their own status lists', async () => {
    const twp = await TestWalletProvider.create({ pki, statusProvider: status, runId: 'tl-wp-versions' });
    expect(twp.units['CW-C'].provider).toBe('WP-C');
    expect(twp.units['CW-W'].provider).toBe('WP-W');
    expect(twp.statusLists['WP-C'].id).toBe('SL-WP-C');
    expect(await twp.wia('CW-C')).toMatch(/^ey/);
  });
});
