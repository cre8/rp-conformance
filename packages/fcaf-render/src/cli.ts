// pnpm fcaf:render [--check] [--out <dir>] [--out-issuer <dir>]: renders both FCAF overlays from the definitions, the
// Relying Party one (fcaf-overlay/docs/fcaf) and the issuer one (fcaf-overlay-issuer/docs/fcaf), or checks that both
// are current.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { baselineDefinitions, definitions } from '@eudi-pcaf/definitions';
import { issuerDefinitions } from '@eudi-pcaf/issuer-definitions';
import { compareOverlay, renderBaseline, renderIssuer, writeOverlay } from './write';

const { values } = parseArgs({ options: { check: { type: 'boolean' }, out: { type: 'string' }, 'out-issuer': { type: 'string' } } });
const defaultDir = (overlay: string) => fileURLToPath(new URL(`../../../${overlay}/docs/fcaf`, import.meta.url));
const rpFiles = await renderBaseline(definitions, baselineDefinitions);
const overlays = [
  { out: resolve(values.out ?? defaultDir('fcaf-overlay')), files: rpFiles },
  { out: resolve(values['out-issuer'] ?? defaultDir('fcaf-overlay-issuer')), files: await renderIssuer(issuerDefinitions, rpFiles) },
];
for (const { out, files } of overlays) {
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
}
