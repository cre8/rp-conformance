import {
  FAULT_IDS,
  type FaultId,
  faultInfo,
  identifierListToken,
  pid,
  pidQueryOf,
  presentation,
  RESPONSE_CHECKS,
  statusListToken,
} from '@rp-conformance/core';
import { beforeAll, describe, expect, it } from 'vitest';
import { MDOC_IDENTIFIER_LIST_CHECKS, MDOC_STATUS_LIST_CHECKS, SD_JWT_VC_CHECKS } from '../src/index';
import { Fixture } from './fixture';

// Harness design section 7, steps 1 and 2: the valid artifacts pass every check of the reference validator, and every
// fault of the catalogue fails exactly its target check and no other.

let fixture: Fixture;

beforeAll(async () => {
  fixture = await Fixture.create();
});

/** A presentation with `fault`, in the credential format the fault applies to (SD-JWT VC for response faults). */
const actionWith = (fault?: FaultId, format: 'dc+sd-jwt' | 'mso_mdoc' = 'dc+sd-jwt') => {
  const info = fault && faultInfo(fault);
  const credentialFormat = info?.format === 'mso_mdoc' || info?.format === 'cwt' ? 'mso_mdoc' : format;
  const only = (point: string) => (info?.point === point ? [fault as FaultId] : []);
  return presentation({
    query: pidQueryOf(credentialFormat),
    credential: pid.of(credentialFormat, { faults: only('credential') }),
    ...(info?.point === 'identifier-list'
      ? { identifierList: identifierListToken.cwt({ contains: false, faults: only('identifier-list') }) }
      : { statusList: statusListToken.of(credentialFormat === 'mso_mdoc' ? 'cwt' : 'jwt', { faults: only('status-list') }) }),
    response: { faults: only('response') },
  });
};

const statuses = (checks: { check: string; status: string }[] | undefined) => checks?.map((c) => [c.check, c.status]);

describe('fault self-validation', () => {
  it('the valid SD-JWT VC presentation passes every check, the response checks included', async () => {
    const result = await fixture.validate(actionWith());
    expect(result.failures).toEqual([]);
    expect(statuses(result.response)).toEqual(RESPONSE_CHECKS.map((c) => [c, 'pass']));
    expect(statuses(result.credential?.checks)).toEqual(SD_JWT_VC_CHECKS.map((c) => [c, 'pass']));
  });

  it('the valid mdoc presentation with a Status List Token in CWT format passes every check', async () => {
    const result = await fixture.validate(actionWith(undefined, 'mso_mdoc'));
    expect(result.failures).toEqual([]);
    expect(statuses(result.response)).toEqual(RESPONSE_CHECKS.map((c) => [c, 'pass']));
    expect(statuses(result.credential?.checks)).toEqual(MDOC_STATUS_LIST_CHECKS.map((c) => [c, 'pass']));
  });

  it.each(['dc+sd-jwt', 'mso_mdoc'] as const)('the valid %s presentation via the DC API (dc_api.jwt, origin audience) passes every check', async (format) => {
    const result = await fixture.validate(actionWith(undefined, format), { flow: 'dc-api' });
    expect(result.failures).toEqual([]);
    expect(statuses(result.response)).toEqual(RESPONSE_CHECKS.map((c) => [c, 'pass']));
    expect(statuses(result.credential?.checks)).toEqual((format === 'mso_mdoc' ? MDOC_STATUS_LIST_CHECKS : SD_JWT_VC_CHECKS).map((c) => [c, 'pass']));
  });

  it('the valid mdoc presentation with an identifier list passes every check', async () => {
    const action = presentation({
      query: 'default_query_pid_mdoc',
      credential: pid.mdoc(),
      identifierList: identifierListToken.cwt({ contains: false }),
    });
    const result = await fixture.validate(action);
    expect(result.failures).toEqual([]);
    expect(statuses(result.credential?.checks)).toEqual(MDOC_IDENTIFIER_LIST_CHECKS.map((c) => [c, 'pass']));
  });

  it('an mdoc whose identifier is on its identifier list fails exactly identifier-status', async () => {
    const action = presentation({
      query: 'default_query_pid_mdoc',
      credential: pid.mdoc(),
      identifierList: identifierListToken.cwt({ contains: true }),
    });
    expect((await fixture.validate(action)).failures).toEqual(['identifier-status']);
  });

  it.each(FAULT_IDS.filter((fault) => faultInfo(fault).point === 'response' && !faultInfo(fault).flow))(
    '%s fails exactly its target check via the DC API too',
    async (fault) => {
      const other = fault === 'response.other-transaction-key' ? await fixture.transaction() : undefined;
      const result = await fixture.validate(actionWith(fault), { other, flow: 'dc-api' });
      const target = faultInfo(fault).target;
      expect(result.failures).toEqual(target ? [target] : []);
    },
  );

  it.each(FAULT_IDS)('%s fails exactly its target check', async (fault) => {
    const other = fault === 'response.other-transaction-key' ? await fixture.transaction() : undefined;
    const result = await fixture.validate(actionWith(fault), { other });
    const target = faultInfo(fault).target;
    expect(result.failures).toEqual(target ? [target] : []);
  });

  it('in first-failure mode an invalid credential stops before its status list is fetched', async () => {
    for (const fault of ['credential.exp-past', 'credential.signature-bitflip', 'mdoc.valid-until-past', 'mdoc.signature-bitflip'] as const) {
      const result = await fixture.validate(actionWith(fault), { mode: 'first-failure' });
      expect(result.credential?.failed).toBe(faultInfo(fault).target);
      expect(result.credential && 'statusListFetched' in result.credential && result.credential.statusListFetched).toBe(false);
    }
  });
});
