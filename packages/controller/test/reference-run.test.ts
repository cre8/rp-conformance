import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ReferenceAdapter } from '@rp-conformance/adapter-reference';
import { executableDefinitions as definitions } from '@rp-conformance/definitions';
import { describe, expect, it } from 'vitest';
import { loadIcs } from '../src/ics';
import { runConformance } from '../src/runner';

// Harness design section 7, step 3: every executable test case passes against the reference Relying Party, which also
// proves that each positive control is reachable.
describe('run against the reference Relying Party', () => {
  it('every executable test definition passes', async () => {
    const reportDir = await mkdtemp(join(tmpdir(), 'rp-conformance-'));
    const ics = await loadIcs(new URL('../../../adapters/reference/ics.yaml', import.meta.url).pathname);
    const { report, reportPath } = await runConformance({ adapter: new ReferenceAdapter(), ics, definitions, reportDir, harnessHost: '127.0.0.1' });
    const notPassed = report.results
      .filter((r) => r.verdict !== 'PASS')
      .map((r) => `${r.testCase}: ${r.verdict} ${r.reason ?? r.steps.filter((s) => s.verdict !== 'PASS').map((s) => `step ${s.step} ${s.reason}`).join('; ')}`);
    expect(notPassed).toEqual([]);
    expect(report.results.map((r) => r.testCase).sort()).toEqual(definitions.map((d) => d.id).sort());
    const written = JSON.parse(await readFile(reportPath, 'utf8'));
    const control = written.results.find((r: { testCase: string }) => r.testCase === 'RP_WS_IA_MainInteraction_001a');
    expect(control.steps[0]).toMatchObject({ expected: 'ACC', verdict: 'PASS', rpResponse: { endpoint: 'response_uri', status: 200 } });
    expect(control.steps[0].statusLog).toHaveLength(1);
  }, 600_000);
});
