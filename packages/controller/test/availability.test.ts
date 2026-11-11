import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ReferenceAdapter } from '@rp-conformance/adapter-reference';
import { acc, defineTestCase, ics, pid, preconditions, presentationStep, type RelyingPartyResult, relevancy, step } from '@rp-conformance/core';
import { executableDefinitions } from '@rp-conformance/definitions';
import { describe, expect, it } from 'vitest';
import { loadIcs } from '../src/ics';
import { runConformance } from '../src/runner';

const CONTROL = 'RP_WS_IA_MainInteraction_001a';

/** The reference Relying Party, stopped right after it reported its second verification result. */
class DyingAdapter extends ReferenceAdapter {
  private results = 0;

  async readResult(transactionId: string, timeoutMs: number): Promise<RelyingPartyResult> {
    const result = await super.readResult(transactionId, timeoutMs);
    if (++this.results === 2) await this.tearDown();
    return result;
  }
}

const twoPresentations = (id: string) =>
  defineTestCase({
    id,
    objective: 'Two valid presentations in a row.',
    references: [],
    profile: [ics.requestsSdJwtVc],
    relevancy: relevancy.genericRequired,
    technology: [],
    preconditions: [...preconditions.base, preconditions.control(CONTROL)],
    control: CONTROL,
    steps: [0, 1].map(() => step({ ...presentationStep.valid({ credential: pid.sdJwtVc() }), expect: acc() })),
  });

describe('a Relying Party that stops answering', () => {
  it('fails the test case in which it stopped, and leaves the following ones inconclusive', async () => {
    const control = executableDefinitions.find((d) => d.id === CONTROL);
    if (!control) throw new Error('no control');
    const ics = await loadIcs(new URL('../../../adapters/reference/ics.yaml', import.meta.url).pathname);
    const { report } = await runConformance({
      adapter: new DyingAdapter(),
      ics,
      definitions: [control, twoPresentations('RP_WS_SM_Validity_901_UF'), twoPresentations('RP_WS_SM_Validity_902_UF')],
      reportDir: await mkdtemp(join(tmpdir(), 'rp-conformance-')),
      harnessHost: '127.0.0.1',
      // One flow, so the Relying Party stops after the control and the first presentation of 901.
      flows: ['redirect'],
    });
    const verdicts = Object.fromEntries(report.results.map((r) => [r.testCase, r]));
    expect(verdicts[CONTROL].verdict).toBe('PASS');
    const stopped = verdicts.RP_WS_SM_Validity_901_UF;
    expect(stopped.verdict).toBe('FAIL');
    expect(stopped.steps.map((s) => s.verdict)).toEqual(['PASS', 'FAIL']);
    expect(stopped.steps[1].reason).toMatch(/became unavailable/);
    expect(verdicts.RP_WS_SM_Validity_902_UF.verdict).toBe('INCONCLUSIVE');
  }, 60_000);
});
