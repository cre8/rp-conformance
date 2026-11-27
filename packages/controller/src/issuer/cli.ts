// `eudi-pcaf issuer ...`: the issuer suite behind the same CLI as the RP suite (issuer harness design section 4).
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { durationMs, type IssuerAdapter, type IssuerTestCaseDefinition, isExecutable, variantOf } from '@eudi-pcaf/core';
import { issuerDefinitions } from '@eudi-pcaf/issuer-definitions';
import { type AdapterEntry, resolveAdapter } from '../adapter-module';
import { loadIssuerIcs } from './ics';
import { issuerRunOutcome, loadIssuerKnownFindings } from './known-findings';
import { runIssuerConformance } from './runner';

/** The issuer adapters, by the name `--adapter` takes; `dir` is the adapter's folder under `adapters/`. */
export const ISSUER_ADAPTERS: Record<string, AdapterEntry<IssuerAdapter>> = {
  eudiplo: { load: () => import('@eudi-pcaf/adapter-issuer-eudiplo'), dir: 'issuer-eudiplo' },
};

export const issuerUsage = `Usage: eudi-pcaf issuer run --adapter <${Object.keys(ISSUER_ADAPTERS).join('|')}|path> [options]
       eudi-pcaf issuer --list

Runs the issuer suite: a PID Provider or Attestation Provider as system under test. --adapter takes a built-in
adapter or the path of an adapter module of your own (.ts or .js, exporting createAdapter(): IssuerAdapter of
@eudi-pcaf/core); such a module needs --ics.

Options:
  --ics <file>           Issuer ICS file (YAML: profiles, items); default: the adapter's ics.yaml
  --only <id>            Test case ID or pattern with *, repeatable or comma separated; the positive controls the
                         selected test cases depend on are added
  --report-dir <dir>     Where reports go; default: reports
  --harness-host <host>  Host name under which the Provider reaches the harness services; default: the adapter's
  --known-findings <file>
                         Known findings of the Provider (YAML). A FAIL listed there is reported as known and does not
                         fail the run; any other FAIL, INCONCLUSIVE, REVIEW or a run error does (exit code 1)
  --max-wait <duration>  Longest a step may wait for an artifact to expire (its lifetime plus one hour), ISO 8601
                         (PT2H) or seconds; default 0. Steps that would wait longer are NOT APPLICABLE and the test
                         cases with such steps run last
  --list                 List the issuer test definitions, one line per test case and variant, and exit

The report goes to <report-dir>/<run>/: report.json, summary.md, junit.xml and the artifacts of every step.
`;

/** One line per issuer definition, as `--list` prints it: ID, variant and notes. */
export function listIssuerTestCases(definitions: IssuerTestCaseDefinition[]): string[] {
  return definitions.map((d) => {
    const notes = [!d.control && 'positive control', !isExecutable(d) && 'text only'].filter(Boolean);
    return `${d.id} [${variantOf(d)}]${notes.length ? ` (${notes.join(', ')})` : ''}`;
  });
}

interface Io {
  out: (text: string) => void;
  err: (text: string) => void;
}

/** Runs `eudi-pcaf issuer <args>`; returns the exit code. */
export async function issuerMain(argv: string[], io: Io, definitions = issuerDefinitions): Promise<number> {
  const { positionals, values } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      adapter: { type: 'string' },
      only: { type: 'string', multiple: true },
      ics: { type: 'string' },
      'report-dir': { type: 'string', default: 'reports' },
      'harness-host': { type: 'string' },
      'known-findings': { type: 'string' },
      'max-wait': { type: 'string' },
      list: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  if (values.help) {
    io.out(issuerUsage);
    return 0;
  }
  if (values.list) {
    for (const line of listIssuerTestCases(definitions)) io.out(`${line}\n`);
    return 0;
  }
  if (positionals[0] !== 'run' || !values.adapter) {
    io.err(issuerUsage);
    return 2;
  }
  const entry = resolveAdapter(values.adapter, ISSUER_ADAPTERS, 'issuer adapter');
  if (!values.ics && !entry.dir) {
    io.err(`--ics is required with the adapter module ${values.adapter}\n`);
    return 2;
  }
  const module = await entry.load();
  const adapter = module.createAdapter();
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
  const ics = await loadIssuerIcs(values.ics ? resolve(values.ics) : join(root, 'adapters', entry.dir!, 'ics.yaml'));
  const maxWait = values['max-wait'];
  const maxWaitSeconds = maxWait === undefined ? 0 : /^\d+$/.test(maxWait) ? Number(maxWait) : (durationMs(maxWait) ?? Number.NaN) / 1000;
  if (Number.isNaN(maxWaitSeconds)) throw new Error(`--max-wait ${maxWait}: not an ISO 8601 duration or a number of seconds`);
  const knownFindings = values['known-findings'] ? await loadIssuerKnownFindings(resolve(values['known-findings'])) : undefined;
  const { report, reportPath } = await runIssuerConformance({
    adapter,
    // Issue 27: one adapter per Provider instance of another category, so the categories run in parallel.
    createAdapter: () => module.createAdapter(),
    ics,
    definitions,
    only: values.only?.flatMap((v) => v.split(',')),
    reportDir: resolve(values['report-dir']),
    harnessHost: values['harness-host'] ?? adapter.harnessHost ?? '127.0.0.1',
    knownFindings,
    maxWaitSeconds,
    log: (line) => io.out(`${line}\n`),
  });
  const summary = Object.entries(report.run.summary).map(([k, v]) => `${k} ${v}`).join(', ');
  io.out(`\n${summary || 'no test case ran'}\nreport: ${reportPath}\n`);
  if (!knownFindings) return report.run.error || report.results.some((r) => r.verdict === 'FAIL' || r.verdict === 'INCONCLUSIVE') ? 1 : 0;
  const outcome = issuerRunOutcome(report, knownFindings);
  for (const line of outcome.known) io.out(`known finding: ${line}\n`);
  for (const line of outcome.resolved) io.out(`known finding no longer fails: ${line}\n`);
  for (const line of outcome.unexpected) io.out(`unexpected: ${line}\n`);
  return outcome.ok ? 0 : 1;
}
