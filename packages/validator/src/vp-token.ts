// The checks of a `vp_token` as a whole (RP_WS_UC_Presentation): before its presentations are validated, `vp-token`
// checks it against the DCQL query of the request; after them, `combined-binding` checks that the presented
// credentials belong to the same person by their identifying attributes (attribute-based binding).
import type { DcqlQuery } from '@eudi-pcaf/core';
import { base64url, type CborMap, decodeCbor } from '@eudi-pcaf/forge';
import { CheckFailure, CheckRecorder, type ValidationMode, type ValidationResult } from './checks';

const fail = (message: string): never => {
  throw new CheckFailure(message);
};

/** Whether a set of credential query ids satisfies the query (OpenID4VP 1.0 section 6.4.2). */
export function satisfiesQuery(query: DcqlQuery, presented: Set<string>): string | undefined {
  if (!query.credential_sets) {
    const missing = query.credentials.map((c) => c.id).filter((id) => !presented.has(id));
    return missing.length ? `no presentation for the credential queries ${missing.join(', ')}` : undefined;
  }
  for (const [index, set] of query.credential_sets.entries()) {
    if (set.required === false) continue;
    if (!set.options.some((option) => option.every((id) => presented.has(id)))) {
      return `the presented credential queries (${[...presented].join(', ') || 'none'}) satisfy no option of the required credential set ${index + 1} (${set.options.map((o) => `[${o.join(', ')}]`).join(' or ')})`;
    }
  }
  return undefined;
}

/**
 * `vp-token`: the `vp_token` is an object whose keys are `id`s of credential queries of the request, each with a
 * non-empty array of presentations that has one element unless the query sets `multiple` (OpenID4VP 1.0 section 8.1);
 * the presented queries satisfy every required credential query or credential set (section 6.4, 8.6 step 3); and an
 * mdoc presentation is a DeviceResponse with exactly one document (HAIP 1.0 section 5.3.1: each mdoc in a separate
 * DeviceResponse). Every failure of these rejects the whole `vp_token` (section 8.6).
 */
export async function validateVpToken(vpToken: unknown, query: DcqlQuery, mode: ValidationMode = 'first-failure'): Promise<ValidationResult> {
  const recorder = new CheckRecorder(mode);
  return recorder.collect(async () => {
    await recorder.run('vp-token', [], () => {
      if (!vpToken || typeof vpToken !== 'object' || Array.isArray(vpToken)) fail('the vp_token is not an object');
      const entries = Object.entries(vpToken as Record<string, unknown>);
      const ids = new Set(query.credentials.map((c) => c.id));
      const unknown = entries.map(([id]) => id).filter((id) => !ids.has(id));
      if (unknown.length) fail(`the vp_token has entries for ${unknown.join(', ')}, which are the id of no credential query of the request`);
      for (const [id, value] of entries) {
        const credentialQuery = query.credentials.find((c) => c.id === id);
        if (!Array.isArray(value) || value.length === 0 || value.some((p) => typeof p !== 'string')) fail(`the entry ${id} is not a non-empty array of presentations`);
        const presentations = value as string[];
        if (presentations.length > 1 && !credentialQuery?.multiple) fail(`the entry ${id} holds ${presentations.length} presentations, but its credential query does not set multiple`);
        if (credentialQuery?.format === 'mso_mdoc') {
          for (const presentation of presentations) {
            let documents: unknown;
            try {
              documents = decodeCbor<CborMap>(base64url.decode(presentation)).get('documents');
            } catch {
              // Not a DeviceResponse: the credential checks report it (`format`).
              continue;
            }
            if (Array.isArray(documents) && documents.length > 1) {
              fail(`the DeviceResponse of the entry ${id} carries ${documents.length} documents; each mdoc is returned in a separate DeviceResponse (HAIP 1.0 section 5.3.1)`);
            }
          }
        }
      }
      const unsatisfied = satisfiesQuery(query, new Set(entries.map(([id]) => id)));
      if (unsatisfied) fail(unsatisfied);
      return `entries for ${entries.map(([id]) => id).join(', ')}`;
    });
  });
}

/** The identifying attributes compared by attribute-based binding: family name, given name and birth date. */
const IDENTIFYING = [
  ['family_name', 'family_name'],
  ['given_name', 'given_name'],
  ['birthdate', 'birth_date'],
] as const;

/**
 * `combined-binding` (ARF section 6.6.3.10, attribute-based binding): every identifying attribute that more than one
 * presented credential discloses has the same value in each of them. `claims` holds each credential's disclosed claims,
 * top-level for an SD-JWT VC or by namespace for an mdoc; `birthdate` and `birth_date` are the same attribute. Passes
 * when fewer than two credentials disclose an identifying attribute.
 */
export async function validateCombinedBinding(
  claims: { id: string; format: string; claims: Record<string, unknown> }[],
  mode: ValidationMode = 'first-failure',
): Promise<ValidationResult> {
  const recorder = new CheckRecorder(mode);
  return recorder.collect(async () => {
    await recorder.run('combined-binding', [], () => {
      const compared: string[] = [];
      for (const names of IDENTIFYING) {
        const values = new Map<string, unknown>();
        for (const credential of claims) {
          const flat = credential.format === 'mso_mdoc' ? Object.assign({}, ...Object.values(credential.claims).filter((v) => v && typeof v === 'object')) : credential.claims;
          const name = names.find((n) => n in flat);
          if (name) values.set(credential.id, (flat as Record<string, unknown>)[name]);
        }
        if (values.size < 2) continue;
        const distinct = new Set([...values.values()].map((v) => JSON.stringify(v)));
        if (distinct.size > 1) fail(`${names[0]} differs between the credentials ${[...values.keys()].join(' and ')}`);
        compared.push(names[0]);
      }
      return compared.length ? `${compared.join(', ')} match` : 'no identifying attribute disclosed by two credentials';
    });
  });
}
