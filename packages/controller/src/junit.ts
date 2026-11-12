import { writeFile } from 'node:fs/promises';
import { hostname } from 'node:os';
import { parseTestCaseId } from '@rp-conformance/core';
import type { RunReport, TestCaseRecord } from './runner';

/** XML 1.0 text: escaped, without the control characters XML does not allow. */
const xml = (value: string) =>
  value
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

const seconds = (ms: number | undefined) => ((ms ?? 0) / 1000).toFixed(3);

/** The step reasons of a result that did not pass, one per line. */
const details = (record: TestCaseRecord) =>
  [record.reason, ...record.steps.filter((s) => s.verdict !== 'PASS').map((s) => `step ${s.step} (${s.expected}, fault ${s.fault ?? 'none'}): ${s.verdict}: ${s.reason}`)]
    .filter(Boolean)
    .join('\n');

function testCase(record: TestCaseRecord): string {
  const id = parseTestCaseId(record.testCase);
  const open = `    <testcase classname="RP_${id.sutClass}_${id.layer}.${id.area}" name="${xml(`${record.testCase} [${record.flow}]`)}" time="${seconds(record.durationMs)}"`;
  const message = (text: string) => xml(text.split('\n')[0].slice(0, 500));
  switch (record.verdict) {
    case 'PASS':
      return `${open}/>`;
    case 'FAIL': {
      const prefix = record.knownFinding ? `known finding: ${record.knownFinding}` : 'FAIL';
      return `${open}>\n      <failure type="${record.knownFinding ? 'known-finding' : 'FAIL'}" message="${message(`${prefix}: ${details(record)}`)}">${xml(details(record))}</failure>\n    </testcase>`;
    }
    case 'NOT APPLICABLE':
      return `${open}>\n      <skipped message="${message(`NOT APPLICABLE: ${record.reason ?? ''}`)}"/>\n    </testcase>`;
    default:
      // INCONCLUSIVE and REVIEW: the harness could not decide, so it is an error rather than a failure of the RP.
      return `${open}>\n      <error type="${record.verdict}" message="${message(`${record.verdict}: ${details(record)}`)}">${xml(details(record))}</error>\n    </testcase>`;
  }
}

/**
 * JUnit XML of a run, next to report.json: one test suite per flow, one test case per FCAF test case. FAIL is a
 * failure (type `known-finding` for a known finding of the Relying Party), INCONCLUSIVE and REVIEW are errors, NOT
 * APPLICABLE is skipped.
 */
export function junitXml(report: RunReport): string {
  const { run } = report;
  const properties = [
    ['run', run.id],
    ['adapter', run.adapter],
    ...Object.entries(run.rp ?? {}).map(([key, value]) => [`rp.${key}`, value]),
    ['harness.phase', String(run.harness.phase)],
    ...(run.error ? [['run.error', run.error]] : []),
  ];
  const count = (records: TestCaseRecord[]) => ({
    tests: records.length,
    failures: records.filter((r) => r.verdict === 'FAIL').length,
    errors: records.filter((r) => r.verdict === 'INCONCLUSIVE' || r.verdict === 'REVIEW').length,
    skipped: records.filter((r) => r.verdict === 'NOT APPLICABLE').length,
    time: seconds(records.reduce((sum, r) => sum + (r.durationMs ?? 0), 0)),
  });
  const attributes = (counts: ReturnType<typeof count>) =>
    `tests="${counts.tests}" failures="${counts.failures}" errors="${counts.errors}" skipped="${counts.skipped}" time="${counts.time}"`;
  const flows = [...new Set(report.results.map((r) => r.flow))];
  const suites = flows.map((flow) => {
    const records = report.results.filter((r) => r.flow === flow);
    return [
      `  <testsuite name="${xml(`${run.adapter} ${flow}`)}" ${attributes(count(records))} timestamp="${xml(run.startedAt)}" hostname="${xml(hostname())}">`,
      '    <properties>',
      ...properties.map(([name, value]) => `      <property name="${xml(name)}" value="${xml(value)}"/>`),
      '    </properties>',
      ...records.map(testCase),
      '  </testsuite>',
    ].join('\n');
  });
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuites name="${xml(`rp-conformance ${run.id}`)}" ${attributes(count(report.results))}>`,
    ...suites,
    '</testsuites>',
    '',
  ].join('\n');
}

export async function writeJUnit(report: RunReport, path: string): Promise<void> {
  await writeFile(path, junitXml(report));
}
