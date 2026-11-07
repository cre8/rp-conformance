#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import type { Flow, RelyingPartyAdapter } from '@rp-conformance/core';
import { definitions } from '@rp-conformance/definitions';
import { loadIcs } from './ics';
import { runConformance } from './runner';

const ADAPTERS: Record<string, { load: () => Promise<{ createAdapter(): RelyingPartyAdapter }>; dir: string }> = {
  reference: { load: () => import('@rp-conformance/adapter-reference'), dir: 'reference' },
  eudiplo: { load: () => import('@rp-conformance/adapter-eudiplo'), dir: 'eudiplo' },
};

const usage = `Usage: rp-conformance run --adapter <${Object.keys(ADAPTERS).join('|')}> [options]

Options:
  --only <id>            Test case ID or pattern with *, repeatable or comma separated
  --ics <file>           ICS file (YAML); default: the adapter's ics.yaml
  --flows <list>         Flows to run; default: redirect (the DC API shim is Phase 3)
  --report-dir <dir>     Where reports go; default: reports
  --harness-host <host>  Host name under which the RP reaches the harness services
  --list                 List the test definitions and exit
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
      list: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  if (values.help) return void process.stdout.write(usage);
  if (values.list) {
    for (const d of definitions) process.stdout.write(`${d.id}${d.control ? '' : ' (positive control)'}\n`);
    return;
  }
  if (positionals[0] !== 'run' || !values.adapter) {
    process.stderr.write(usage);
    process.exitCode = 2;
    return;
  }
  const entry = ADAPTERS[values.adapter];
  if (!entry) throw new Error(`unknown adapter ${values.adapter}`);
  const adapter = (await entry.load()).createAdapter();
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
  const ics = await loadIcs(values.ics ?? join(root, 'adapters', entry.dir, 'ics.yaml'));
  const { report, reportPath } = await runConformance({
    adapter,
    ics,
    definitions,
    only: values.only?.flatMap((v) => v.split(',')),
    flows: values.flows?.split(',') as Flow[] | undefined,
    reportDir: resolve(values['report-dir']),
    harnessHost: values['harness-host'] ?? adapter.harnessHost ?? 'localhost',
    log: (line) => process.stdout.write(`${line}\n`),
  });
  const summary = Object.entries(report.run.summary).map(([k, v]) => `${k} ${v}`).join(', ');
  process.stdout.write(`\n${summary || 'no test case ran'}\nreport: ${reportPath}\n`);
  if (report.results.some((r) => r.verdict === 'FAIL' || r.verdict === 'INCONCLUSIVE')) process.exitCode = 1;
}

main().catch((error: unknown) => {
  process.stderr.write(`${(error as Error).stack ?? error}\n`);
  process.exitCode = 1;
});
