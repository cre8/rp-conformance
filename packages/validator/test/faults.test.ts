import { FAULT_IDS, type FaultId, faultInfo, pid, presentation, RESPONSE_CHECKS, statusListToken } from '@rp-conformance/core';
import { beforeAll, describe, expect, it } from 'vitest';
import { SD_JWT_VC_CHECKS } from '../src/index';
import { Fixture } from './fixture';

// Harness design section 7, steps 1 and 2: the valid artifacts pass every check of the reference validator, and every
// fault of the catalogue fails exactly its target check and no other.

let fixture: Fixture;

beforeAll(async () => {
  fixture = await Fixture.create();
});

const actionWith = (fault?: FaultId) => {
  const point = fault && faultInfo(fault).point;
  return presentation({
    query: 'default_query_pid',
    credential: pid.sdJwtVc({ faults: point === 'credential' ? [fault as FaultId] : [] }),
    statusList: statusListToken.jwt({ faults: point === 'status-list' ? [fault as FaultId] : [] }),
    response: { faults: point === 'response' ? [fault as FaultId] : [] },
  });
};

describe('fault self-validation', () => {
  it('the valid presentation passes every check, the response checks included', async () => {
    const result = await fixture.validate(actionWith());
    expect(result.failures).toEqual([]);
    expect(result.response.map((c) => [c.check, c.status])).toEqual(RESPONSE_CHECKS.map((c) => [c, 'pass']));
    expect(result.credential?.checks.map((c) => [c.check, c.status])).toEqual(SD_JWT_VC_CHECKS.map((c) => [c, 'pass']));
  });

  it.each(FAULT_IDS)('%s fails exactly its target check', async (fault) => {
    const other = fault === 'response.other-transaction-key' ? await fixture.transaction() : undefined;
    const result = await fixture.validate(actionWith(fault), { other });
    const target = faultInfo(fault).target;
    expect(result.failures).toEqual(target ? [target] : []);
  });

  it('in first-failure mode an invalid credential stops before its status list is fetched', async () => {
    for (const fault of ['credential.exp-past', 'credential.signature-bitflip'] as const) {
      const result = await fixture.validate(actionWith(fault), { mode: 'first-failure' });
      expect(result.credential?.failed).toBe(faultInfo(fault).target);
      expect(result.credential?.statusListFetched).toBe(false);
    }
  });
});
