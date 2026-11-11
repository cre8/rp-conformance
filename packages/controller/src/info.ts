import { createRequire } from 'node:module';

const LIBRARIES = [
  '@sd-jwt/sd-jwt-vc',
  '@sd-jwt/core',
  '@owf/x509',
  '@owf/eudi-lote',
  '@owf/eudi-jades',
  '@owf/token-status-list',
  '@owf/mdoc',
  '@owf/cose',
  'cborg',
  '@owf/eudi-access-certificate',
  '@owf/eudi-registration-certificate',
];

/** Versions of the harness and of the libraries that built the artifacts, recorded in every report. */
export function harnessInfo() {
  const fromForge = createRequire(new URL('../../forge/package.json', import.meta.url));
  const fromWallet = createRequire(new URL('../../wallet/package.json', import.meta.url));
  const fromShim = createRequire(new URL('../../dc-api-shim/package.json', import.meta.url));
  const version = (req: NodeJS.Require, name: string) => {
    try {
      return (req(`${name}/package.json`) as { version: string }).version;
    } catch {
      return 'unknown';
    }
  };
  return {
    name: 'rp-conformance',
    phase: 3,
    node: process.version,
    libraries: {
      ...Object.fromEntries(LIBRARIES.map((name) => [name, version(fromForge, name)])),
      '@openid4vc/openid4vp': version(fromWallet, '@openid4vc/openid4vp'),
      playwright: version(fromShim, 'playwright'),
    },
  };
}
