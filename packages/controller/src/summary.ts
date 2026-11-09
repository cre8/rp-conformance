import { writeFile } from 'node:fs/promises';
import type { RunReport } from './runner';

/** A markdown summary of a run, next to report.json (harness design section 5). */
export async function writeSummary(report: RunReport, path: string): Promise<void> {
  const { run } = report;
  const lines = [
    `# RP conformance run ${run.id}`,
    '',
    `Adapter \`${run.adapter}\`, flows ${run.flows.join(', ') || 'none'}, ${run.startedAt} to ${run.finishedAt ?? ''}.`,
    '',
    Object.entries(run.summary).map(([verdict, count]) => `${verdict}: ${count}`).join(', ') || 'No test case ran.',
    ...(run.error ? ['', `Run error: ${run.error}`] : []),
    '',
    '| Test case | Flow | Verdict | Reason |',
    '| --- | --- | --- | --- |',
    ...report.results.map((r) => {
      const failed = r.steps.filter((s) => s.verdict !== 'PASS').map((s) => `step ${s.step}: ${s.reason}`);
      const reason = (r.reason ?? failed.join('; ')).replace(/\|/g, '\\|').replace(/\n/g, ' ');
      return `| ${r.testCase} | ${r.flow} | ${r.verdict} | ${reason} |`;
    }),
    '',
  ];
  await writeFile(path, lines.join('\n'));
}
