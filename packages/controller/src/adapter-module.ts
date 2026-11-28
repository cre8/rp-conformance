// Loads the adapter that `--adapter` names: a built-in adapter by its name, or an adapter module of the user's own by
// its path (a `.ts`, `.mts`, `.js` or `.mjs` file that exports `createAdapter()`). The CLI runs under tsx, so a
// TypeScript module needs no build step. Such a module may import `@eudi-pcaf/core`; the Docker image makes that
// package resolvable from any directory (Dockerfile).
import { isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export interface AdapterEntry<A> {
  load: () => Promise<{ createAdapter(): A }>;
  /** The adapter's folder under `adapters/`, which holds its default ICS; undefined for an adapter module given by path. */
  dir?: string;
}

/** Whether `--adapter` names a module by its path rather than a built-in adapter. */
export function isAdapterPath(spec: string): boolean {
  return spec.includes('/') || spec.includes('\\') || /\.(m?ts|m?js)$/.test(spec);
}

export function resolveAdapter<A>(spec: string, builtIn: Record<string, AdapterEntry<A>>, kind: string): AdapterEntry<A> {
  if (!isAdapterPath(spec)) {
    const entry = builtIn[spec];
    if (!entry) throw new Error(`unknown ${kind} ${spec} (adapters: ${Object.keys(builtIn).join(', ')}, or the path of an adapter module)`);
    return entry;
  }
  const url = pathToFileURL(isAbsolute(spec) ? spec : resolve(spec)).href;
  return {
    load: async () => {
      const module = (await import(url)) as { createAdapter?: unknown; default?: { createAdapter?: unknown } };
      const createAdapter = module.createAdapter ?? module.default?.createAdapter;
      if (typeof createAdapter !== 'function') throw new Error(`${spec}: the module exports no createAdapter() function`);
      return { createAdapter: createAdapter as () => A };
    },
  };
}
