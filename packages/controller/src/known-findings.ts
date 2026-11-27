import { readFile } from 'node:fs/promises';
import { FLOWS, type Flow } from '@eudi-pcaf/core';
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
  /** Where the evidence of the run that found it is, for a finding not yet reported upstream. */
  evidence?: string;
  /**
   * What the FAIL rests on (spec review of 2026-11-20): `confirmed`, a requirement of the base specification the product
   * implements; `profile`, a requirement of the EUDI profile (ARF, TS3, PID Rulebook) only, which the base specification
   * does not make.
   */
  basis?: FindingBasis;
}

/** What a known finding rests on: the base specification (`confirmed`), or the EUDI profile only (`profile`). */
export type FindingBasis = 'confirmed' | 'profile';
export const FINDING_BASES: readonly FindingBasis[] = ['confirmed', 'profile'];

/** Reads a YAML list of known findings (`testCase`, optional `flows`, `finding`, optional `reference`). */
export async function loadKnownFindings(path: string): Promise<KnownFinding[]> {
  const findings = parse(await readFile(path, 'utf8')) as KnownFinding[] | null;
  if (!Array.isArray(findings)) throw new Error(`${path}: not a list of known findings`);
  for (const [i, f] of findings.entries()) {
    if (typeof f?.testCase !== 'string' || typeof f.finding !== 'string') throw new Error(`${path}: entry ${i + 1} needs testCase and finding`);
    if (f.flows && (!Array.isArray(f.flows) || f.flows.some((flow) => !FLOWS.includes(flow)))) {
      throw new Error(`${path}: entry ${i + 1} names an unknown flow (flows: ${FLOWS.join(', ')})`);
    }
    if (f.basis !== undefined && !FINDING_BASES.includes(f.basis)) throw new Error(`${path}: entry ${i + 1}: basis is ${String(f.basis)}, not one of ${FINDING_BASES.join(', ')}`);
  }
  return findings;
}

/** The known finding of a test case in a flow, if there is one. */
export function knownFindingOf(findings: KnownFinding[], testCase: string, flow: Flow): KnownFinding | undefined {
  return findings.find((f) => f.testCase === testCase && (!f.flows || f.flows.includes(flow)));
}

export const describeFinding = (finding: KnownFinding) =>
  `${finding.basis === 'profile' ? '[EUDI profile] ' : ''}${finding.finding}${finding.reference ? ` (${finding.reference})` : ''}`;

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

/**
 * Classifies the results of a run against the known findings of the Relying Party under test. The test book items
 * (`report.testBook`) are always REVIEW and never fail the run; a REVIEW result of a test case does.
 */
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
