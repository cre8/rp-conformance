import { readFile } from 'node:fs/promises';
import { FLOWS, type Flow } from '@rp-conformance/core';
import { parse } from 'yaml';
import type { RunReport } from './runner';

/**
 * A FAIL that is a known finding in the Relying Party under test, reported upstream with evidence. A run that knows it
 * still reports the FAIL, marked as known, but does not fail on it (the nightly job against EUDIPLO).
 */
export interface KnownFinding {
  testCase: string;
  /** The flows the finding shows in; default every flow. */
  flows?: Flow[];
  /** What the Relying Party does wrong, in one sentence. */
  finding: string;
  /** Where the finding is tracked, for example an issue or pull request. */
  reference?: string;
}

/** Reads a YAML list of known findings (`testCase`, optional `flows`, `finding`, optional `reference`). */
export async function loadKnownFindings(path: string): Promise<KnownFinding[]> {
  const findings = parse(await readFile(path, 'utf8')) as KnownFinding[] | null;
  if (!Array.isArray(findings)) throw new Error(`${path}: not a list of known findings`);
  for (const [i, f] of findings.entries()) {
    if (typeof f?.testCase !== 'string' || typeof f.finding !== 'string') throw new Error(`${path}: entry ${i + 1} needs testCase and finding`);
    if (f.flows && (!Array.isArray(f.flows) || f.flows.some((flow) => !FLOWS.includes(flow)))) {
      throw new Error(`${path}: entry ${i + 1} names an unknown flow (flows: ${FLOWS.join(', ')})`);
    }
  }
  return findings;
}

/** The known finding of a test case in a flow, if there is one. */
export function knownFindingOf(findings: KnownFinding[], testCase: string, flow: Flow): KnownFinding | undefined {
  return findings.find((f) => f.testCase === testCase && (!f.flows || f.flows.includes(flow)));
}

export const describeFinding = (finding: KnownFinding) => `${finding.finding}${finding.reference ? ` (${finding.reference})` : ''}`;

export interface RunOutcome {
  /** Whether the run passes: no run error, no INCONCLUSIVE or REVIEW, and every FAIL a known finding. */
  ok: boolean;
  /** Results that fail the run, as `<test case> [<flow>] <verdict>`. */
  unexpected: string[];
  /** FAILs that are known findings. */
  known: string[];
  /** Known findings whose test case passed in this run: the Relying Party may have fixed them. */
  resolved: string[];
}

/** Classifies the results of a run against the known findings of the Relying Party under test. */
export function runOutcome(report: RunReport, findings: KnownFinding[]): RunOutcome {
  const unexpected: string[] = report.run.error ? [`run error: ${report.run.error}`] : [];
  const known: string[] = [];
  const resolved: string[] = [];
  for (const result of report.results) {
    const label = `${result.testCase} [${result.flow}]`;
    const finding = knownFindingOf(findings, result.testCase, result.flow);
    if (result.verdict === 'FAIL' && finding) known.push(`${label}: ${describeFinding(finding)}`);
    else if (result.verdict === 'FAIL' || result.verdict === 'INCONCLUSIVE' || result.verdict === 'REVIEW') unexpected.push(`${label} ${result.verdict}`);
    else if (result.verdict === 'PASS' && finding) resolved.push(label);
  }
  return { ok: unexpected.length === 0, unexpected, known, resolved };
}
