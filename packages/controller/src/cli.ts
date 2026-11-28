#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { type Flow, isExecutable, type RelyingPartyAdapter } from '@eudi-pcaf/core';
import { definitions, testBook } from '@eudi-pcaf/definitions';
import { type AdapterEntry, resolveAdapter } from './adapter-module';
import { loadIcs } from './ics';
import { loadKnownFindings, runOutcome } from './known-findings';
import { runConformance } from './runner';

const ADAPTERS: Record<string, AdapterEntry<RelyingPartyAdapter>> = {
  reference: { load: () => import('@eudi-pcaf/adapter-reference'), dir: 'reference' },
  eudiplo: { load: () => import('@eudi-pcaf/adapter-eudiplo'), dir: 'eudiplo' },
};

const usage = `Usage: eudi-pcaf run --adapter <${Object.keys(ADAPTERS).join('|')}|path> [options]

--adapter takes a built-in adapter or the path of an adapter module of your own (.ts or .js, exporting
createAdapter(): RelyingPartyAdapter of @eudi-pcaf/core); such a module needs --ics.

Options:
  --only <id>            Test case or test book item ID or pattern with *, repeatable or comma separated
  --ics <file>           ICS file (YAML); default: the adapter's ics.yaml
  --flows <list>         Flows to run, comma separated: redirect, dc-api; default: both
  --report-dir <dir>     Where reports go; default: reports
  --harness-host <host>  Host name under which the RP reaches the harness services
  --known-findings <file>
                         Known findings of the RP (YAML). A FAIL listed there is reported as known and does not fail
                         the run; any other FAIL, INCONCLUSIVE, REVIEW or a run error does (exit code 1). The test
                         book items (RP_TB_*) are always REVIEW and never fail the run
  --concurrency <n>      How many test case runs execute at a time; default 1 (one after another). With more, the test
                         cases that change trust lists run after the others, one at a time; the report keeps
                         definition order
  --list                 List the test definitions and test book items and exit

The report goes to <report-dir>/<run>/: report.json, summary.md, junit.xml and the artifacts of every step.

The issuer suite (a PID Provider or Attestation Provider as system under test): eudi-pcaf issuer --help
`;

async function main() {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: {
      adapter: { type: 'string' },
      only: { type: 'string', multiple: true },
      ics: { type: 'string' },
      flows: { type: 'string' },
      'report-dir': { type: 'string', default: 'reports' },
      'harness-host': { type: 'string' },
      'known-findings': { type: 'string' },
      concurrency: { type: 'string', default: '1' },
      list: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  if (values.help) return void process.stdout.write(usage);
  if (values.list) {
    for (const d of definitions) {
      const notes = [!d.control && 'positive control', !isExecutable(d) && 'text only'].filter(Boolean);
      process.stdout.write(`${d.id}${notes.length ? ` (${notes.join(', ')})` : ''}\n`);
    }
    for (const item of testBook) process.stdout.write(`${item.id} (test book)\n`);
    return;
  }
  if (positionals[0] !== 'run' || !values.adapter) {
    process.stderr.write(usage);
    process.exitCode = 2;
    return;
  }
  const concurrency = Number(values.concurrency);
  if (!Number.isInteger(concurrency) || concurrency < 1) {
    process.stderr.write(`--concurrency must be a positive integer, not ${values.concurrency}\n`);
    process.exitCode = 2;
    return;
  }
  const entry = resolveAdapter(values.adapter, ADAPTERS, 'adapter');
  if (!values.ics && !entry.dir) {
    process.stderr.write(`--ics is required with the adapter module ${values.adapter}\n`);
    process.exitCode = 2;
    return;
  }
  const adapter = (await entry.load()).createAdapter();
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
  const ics = await loadIcs(values.ics ? resolve(values.ics) : join(root, 'adapters', entry.dir!, 'ics.yaml'));
  const knownFindings = values['known-findings'] ? await loadKnownFindings(resolve(values['known-findings'])) : undefined;
  const { report, reportPath } = await runConformance({
    adapter,
    ics,
    definitions,
    testBook,
    only: values.only?.flatMap((v) => v.split(',')),
    flows: values.flows?.split(',') as Flow[] | undefined,
    reportDir: resolve(values['report-dir']),
    harnessHost: values['harness-host'] ?? adapter.harnessHost ?? '127.0.0.1',
    knownFindings,
    concurrency,
    log: (line) => process.stdout.write(`${line}\n`),
  });
  const summary = Object.entries(report.run.summary).map(([k, v]) => `${k} ${v}`).join(', ');
  process.stdout.write(`\n${summary || 'no test case ran'}\n`);
  if (report.testBook?.length) process.stdout.write(`test book: REVIEW ${report.testBook.length} (inspections; they do not fail the run)\n`);
  process.stdout.write(`report: ${reportPath}\n`);
  if (!knownFindings) {
    if (report.run.error || report.results.some((r) => r.verdict === 'FAIL' || r.verdict === 'INCONCLUSIVE')) process.exitCode = 1;
    return;
  }
  const outcome = runOutcome(report, knownFindings);
  for (const line of outcome.known) process.stdout.write(`known finding: ${line}\n`);
  for (const line of outcome.resolved) process.stdout.write(`known finding no longer fails: ${line}\n`);
  for (const line of outcome.unexpected) process.stdout.write(`unexpected: ${line}\n`);
  if (!outcome.ok) process.exitCode = 1;
}

// `eudi-pcaf issuer ...` runs the issuer suite (packages/controller/src/issuer/cli.ts).
const issuer = () =>
  import('./issuer/cli').then(async ({ issuerMain }) => {
    process.exitCode = await issuerMain(process.argv.slice(3), { out: (text) => process.stdout.write(text), err: (text) => process.stderr.write(text) });
  });

(process.argv[2] === 'issuer' ? issuer() : main()).catch((error: unknown) => {
  process.stderr.write(`${(error as Error).stack ?? error}\n`);
  process.exitCode = 1;
});
