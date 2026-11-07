import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ReferenceAdapter } from '@rp-conformance/adapter-reference';
import { definitions } from '@rp-conformance/definitions';
import { describe, expect, it } from 'vitest';
import { loadIcs } from '../src/ics';
import { runConformance } from '../src/runner';

// Harness design section 7, step 3: every test case of the baseline passes against the reference Relying Party.
describe('run against the reference Relying Party', () => {
  it('every executable test definition passes', async () => {
    const reportDir = await mkdtemp(join(tmpdir(), 'rp-conformance-'));
    const ics = await loadIcs(new URL('../../../adapters/reference/ics.yaml', import.meta.url).pathname);
    const { report, reportPath } = await runConformance({ adapter: new ReferenceAdapter(), ics, definitions, reportDir, harnessHost: 'localhost' });
    expect(report.results.map((r) => [r.testCase, r.flow, r.verdict])).toEqual(definitions.map((d) => [d.id, 'redirect', 'PASS']));
    const written = JSON.parse(await readFile(reportPath, 'utf8'));
    expect(written.results[0].steps[0]).toMatchObject({ expected: 'ACC', verdict: 'PASS', rpResponse: { endpoint: 'response_uri', status: 200 } });
    expect(written.results[0].steps[0].statusLog).toHaveLength(1);
  });
});
