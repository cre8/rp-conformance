// pnpm fcaf:render [--check] [--out <dir>]: renders the FCAF overlay from the definitions, or checks that it is current.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { definitions } from '@rp-conformance/definitions';
import { compareOverlay, renderBaseline, writeOverlay } from './write';

const { values } = parseArgs({ options: { check: { type: 'boolean' }, out: { type: 'string' } } });
const out = resolve(values.out ?? fileURLToPath(new URL('../../../fcaf-overlay/docs/fcaf', import.meta.url)));
const files = await renderBaseline(definitions);
if (values.check) {
  const differences = await compareOverlay(files, out);
  for (const { path, problem } of differences) process.stderr.write(`${problem}: ${path}\n`);
  process.stdout.write(`${files.size} files rendered, ${differences.length} differ from ${out}\n`);
  if (differences.length) {
    process.stderr.write('Run `pnpm fcaf:render` and commit the result.\n');
    process.exitCode = 1;
  }
} else {
  await writeOverlay(files, out);
  process.stdout.write(`${files.size} files written to ${out}\n`);
}
