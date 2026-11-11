import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ReferenceAdapter } from '@rp-conformance/adapter-reference';
import { flowsOf } from '@rp-conformance/core';
import { executableDefinitions as definitions } from '@rp-conformance/definitions';
import { describe, expect, it } from 'vitest';
import { loadIcs } from '../src/ics';
import { runConformance } from '../src/runner';

// Harness design section 7, step 3: every executable test case passes against the reference Relying Party in every flow
// it runs in (redirects, and the DC API through the shim), which also proves that each positive control is reachable.
describe('run against the reference Relying Party', () => {
  it('every executable test definition passes in both flows', async () => {
    const reportDir = await mkdtemp(join(tmpdir(), 'rp-conformance-'));
    const ics = await loadIcs(new URL('../../../adapters/reference/ics.yaml', import.meta.url).pathname);
    const { report, reportPath } = await runConformance({ adapter: new ReferenceAdapter(), ics, definitions, reportDir, harnessHost: '127.0.0.1' });
    const notPassed = report.results
      .filter((r) => r.verdict !== 'PASS')
      .map((r) => `${r.testCase}: ${r.verdict} ${r.reason ?? r.steps.filter((s) => s.verdict !== 'PASS').map((s) => `step ${s.step} ${s.reason}`).join('; ')}`);
    expect(notPassed).toEqual([]);
    const runs = (results: { testCase: string; flow: string }[]) => results.map((r) => `${r.testCase} ${r.flow}`).sort();
    expect(runs(report.results)).toEqual(runs(definitions.flatMap((d) => flowsOf(d).map((flow) => ({ testCase: d.id, flow })))));
    // 87 test cases in both flows, 11 only via redirects and 11 only via the DC API.
    expect(report.results.filter((r) => r.flow === 'redirect')).toHaveLength(98);
    expect(report.results.filter((r) => r.flow === 'dc-api')).toHaveLength(98);
    const written = JSON.parse(await readFile(reportPath, 'utf8'));
    const control = (flow: string) =>
      written.results.find((r: { testCase: string; flow: string }) => r.testCase === 'RP_WS_IA_MainInteraction_001a' && r.flow === flow);
    expect(control('redirect').steps[0]).toMatchObject({ expected: 'ACC', verdict: 'PASS', rpResponse: { endpoint: 'response_uri', status: 200 } });
    expect(control('redirect').steps[0].statusLog).toHaveLength(1);
    expect(control('dc-api').steps[0]).toMatchObject({
      expected: 'ACC',
      verdict: 'PASS',
      rpResponse: { endpoint: 'dc-api-forward', status: 200 },
      dcApi: { protocol: 'openid4vp-v1-signed' },
    });
    expect(control('dc-api').steps[0].statusLog).toHaveLength(1);
  }, 600_000);
});
