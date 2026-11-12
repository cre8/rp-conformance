import { writeFile } from 'node:fs/promises';
import type { RunReport } from './runner';

/** A markdown summary of a run, next to report.json (harness design section 5). */
export async function writeSummary(report: RunReport, path: string): Promise<void> {
  const { run } = report;
  const lines = [
    `# RP conformance run ${run.id}`,
    '',
    `Adapter \`${run.adapter}\`${run.rp ? ` (${Object.entries(run.rp).map(([k, v]) => `${k} \`${v}\``).join(', ')})` : ''}, flows ${run.flows.join(', ') || 'none'}, ${run.startedAt} to ${run.finishedAt ?? ''}.`,
    '',
    Object.entries(run.summary).map(([verdict, count]) => `${verdict}: ${count}`).join(', ') || 'No test case ran.',
    ...(run.error ? ['', `Run error: ${run.error}`] : []),
    '',
    '| Test case | Flow | Verdict | Reason |',
    '| --- | --- | --- | --- |',
    ...report.results.map((r) => {
      const failed = r.steps.filter((s) => s.verdict !== 'PASS').map((s) => `step ${s.step}: ${s.reason}`);
      const reason = [r.knownFinding && `Known finding: ${r.knownFinding}.`, r.reason ?? failed.join('; ')]
        .filter(Boolean)
        .join(' ')
        .replace(/\|/g, '\\|')
        .replace(/\n/g, ' ');
      return `| ${r.testCase} | ${r.flow} | ${r.verdict}${r.knownFinding ? ' (known)' : ''} | ${reason} |`;
    }),
    '',
  ];
  await writeFile(path, lines.join('\n'));
}
