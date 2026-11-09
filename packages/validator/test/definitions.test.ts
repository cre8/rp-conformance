import { faultInfo, faultsOf, type TestCaseDefinition } from '@rp-conformance/core';
import { executableDefinitions } from '@rp-conformance/definitions';
import { defaultEntitiesOf } from '@rp-conformance/forge';
import { beforeAll, describe, expect, it } from 'vitest';
import { Fixture, type Transaction } from './fixture';

// Harness design section 7 for the test definitions: every executable step is built exactly as the controller builds
// it and run through the reference validator in `all` mode. A step expected to be accepted passes every check; a step
// expected to be rejected fails exactly one check, the target of its fault if it has one. So each negative step
// carries one deliberate fault and nothing else.

let fixture: Fixture;

beforeAll(async () => {
  fixture = await Fixture.create();
});

const rejects = (codes: string[]) => codes.some((c) => c === 'REJ' || c === 'NOSTAT' || c === 'POLICY');

async function selfValidate(definition: TestCaseDefinition) {
  const outcomes: { step: number; expected: string; failures: string[]; target?: string }[] = [];
  const transactions = new Map<number, Transaction>();
  let pidList = defaultEntitiesOf(fixture.pki, 'TL-PID');
  try {
    for (const [i, step] of definition.steps.entries()) {
      const action = step.run;
      if (!action) throw new Error(`step ${i + 1} has no action`);
      if (action.kind === 'start') {
        transactions.set(i + 1, await fixture.transaction());
      } else if (action.kind === 'trust-list') {
        pidList = [...pidList.filter((e) => !action.remove?.includes(e)), ...(action.add ?? [])];
        await fixture.publish(action.list, pidList);
      } else {
        const other = action.response.keyOfStep ? transactions.get(action.response.keyOfStep) : undefined;
        const result = await fixture.validate(action, { other });
        const [fault] = faultsOf(action);
        outcomes.push({ step: i + 1, expected: step.expect.codes.join('+'), failures: result.failures, target: fault && (faultInfo(fault).target ?? undefined) });
      }
    }
  } finally {
    await fixture.publish('TL-PID');
  }
  return outcomes;
}

describe('executable definitions against the reference validator', () => {
  it('Phase 1 makes 52 test definitions executable (TrustMechanisms_006a awaits a representation of withdrawal)', () => {
    expect(executableDefinitions).toHaveLength(52);
  });

  it.each(executableDefinitions.map((d) => [d.id, d] as const))('%s: each step carries exactly its one fault', async (_id, definition) => {
    for (const outcome of await selfValidate(definition)) {
      const label = `step ${outcome.step} (${outcome.expected})`;
      if (!rejects(outcome.expected.split('+'))) {
        expect(outcome.failures, label).toEqual([]);
      } else {
        expect(outcome.failures, label).toHaveLength(1);
        if (outcome.target) expect(outcome.failures, label).toEqual([outcome.target]);
      }
    }
  });
});
