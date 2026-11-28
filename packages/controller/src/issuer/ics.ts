// The Provider's ICS (issuer catalogue section 4) as the controller reads it: profiles for the applicability of a test
// case and its variant, declared values for the steps.
import { readFile } from 'node:fs/promises';
import { CATEGORY_PROFILES, ISSUER_ICS_ITEMS, type IssuerIcs, type IssuerProfile, type IssuerTestCaseDefinition, PROVIDER_CATEGORIES, type ProviderCategory, VARIANT_PROFILES } from '@eudi-pcaf/core';
import { parse } from 'yaml';

const PROFILES = new Set<string>(Object.values(ISSUER_ICS_ITEMS).flatMap((item) => [...item.profiles]));

/**
 * Reads an issuer ICS file: `profiles`, the profiles the answers select, and `items`, the declared values keyed by ICS
 * item ID or `<item>.<name>`. Every profile must be one of the catalogue's, every item key one of ICS-01 to ICS-19.
 */
export async function loadIssuerIcs(path: string): Promise<IssuerIcs> {
  const parsed = parse(await readFile(path, 'utf8')) as { profiles?: unknown; items?: unknown } | null;
  if (!parsed || !Array.isArray(parsed.profiles) || !parsed.items || typeof parsed.items !== 'object') {
    throw new Error(`${path}: not an issuer ICS (profiles and items)`);
  }
  for (const profile of parsed.profiles) if (!PROFILES.has(String(profile))) throw new Error(`${path}: unknown profile ${String(profile)}`);
  for (const key of Object.keys(parsed.items)) if (!(key.split('.')[0] in ISSUER_ICS_ITEMS)) throw new Error(`${path}: unknown ICS item ${key}`);
  // Issue 27: the Attestation Provider instances of the same implementation, one per category.
  const categories = (parsed as { categories?: unknown }).categories;
  if (categories !== undefined) {
    if (!categories || typeof categories !== 'object') throw new Error(`${path}: categories is not a map`);
    for (const [category, entry] of Object.entries(categories as Record<string, { profiles?: unknown; items?: unknown }>)) {
      if (!['Q', 'PB', 'E'].includes(category)) throw new Error(`${path}: unknown category ${category} (Q, PB, E)`);
      if (!entry || !Array.isArray(entry.profiles)) throw new Error(`${path}: categories.${category} has no profiles`);
      for (const profile of entry.profiles) if (!PROFILES.has(String(profile))) throw new Error(`${path}: categories.${category}: unknown profile ${String(profile)}`);
      if (!entry.profiles.includes(CATEGORY_PROFILES[category as ProviderCategory])) throw new Error(`${path}: categories.${category} lacks the profile ${CATEGORY_PROFILES[category as ProviderCategory]}`);
      for (const key of Object.keys((entry.items ?? {}) as object)) if (!(key.split('.')[0] in ISSUER_ICS_ITEMS)) throw new Error(`${path}: categories.${category}: unknown ICS item ${key}`);
    }
  }
  return {
    profiles: parsed.profiles as IssuerProfile[],
    items: parsed.items as IssuerIcs['items'],
    ...(categories ? { categories: categories as IssuerIcs['categories'] } : {}),
  };
}

/**
 * Issue 27: the ICS of the Provider instance of a category. The top level is the instance whose profiles name its
 * category (usually the PID Provider); `categories.<category>` an instance of another category, with its own profiles
 * and the items that differ from the top level. Undefined when the ICS declares no instance of the category: its test
 * cases are NOT APPLICABLE.
 */
export function categoryIcs(ics: IssuerIcs, category: ProviderCategory): IssuerIcs | undefined {
  const entry = category === 'PID' ? undefined : ics.categories?.[category];
  if (entry) return { profiles: [...entry.profiles], items: { ...ics.items, ...(entry.items ?? {}) } };
  if (!ics.profiles.includes(CATEGORY_PROFILES[category])) return undefined;
  return { profiles: [...ics.profiles], items: { ...ics.items } };
}

/** Issue 27: the categories the ICS declares a Provider instance for, in the order PID, Q, PB, E. */
export function providerCategories(ics: IssuerIcs): ProviderCategory[] {
  return PROVIDER_CATEGORIES.filter((category) => categoryIcs(ics, category) !== undefined);
}

/** The profile applicability conditions and variant codes the ICS does not meet; empty when the test case applies. */
export function issuerApplicability(definition: IssuerTestCaseDefinition, ics: IssuerIcs): string[] {
  const unmet = definition.profile.filter((c) => !ics.profiles.includes(c.equals as IssuerProfile)).map((c) => `${c.item} ${c.equals} (${c.text})`);
  for (const variant of definition.variants ?? []) {
    const profile = VARIANT_PROFILES[variant];
    if (!ics.profiles.includes(profile) && !unmet.some((u) => u.includes(` ${profile} `))) unmet.push(`variant ${variant} needs ${profile}`);
  }
  return unmet;
}

/** A declared value as a string, undefined when the ICS does not declare it. */
export function issuerIcsValue(ics: IssuerIcs, key: string): string | undefined {
  const value = ics.items[key];
  if (value === undefined) return undefined;
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  return Array.isArray(value) ? value.join(', ') : String(value);
}

/**
 * Resolves the credential configurations of an issuance step: a reference `ICS-02.<format variant>` becomes the
 * configuration ID the ICS declares under it (`ICS-02.SD: pid-sd-jwt-vc`); anything else is taken as an ID.
 */
export function resolveConfigurations(configurations: string[], ics: IssuerIcs): string[] {
  return configurations.map((configuration) => {
    if (!/^ICS-\d{2}\./.test(configuration)) return configuration;
    const value = issuerIcsValue(ics, configuration);
    if (!value) throw new Error(`the ICS declares no credential configuration under ${configuration}`);
    return value;
  });
}

/**
 * Whether the pre-authorized code is protected by a `tx_code` (ICS-03.tx_code): the suite uses one unless the Provider
 * declares offers without one only.
 */
export function usesTxCode(ics: IssuerIcs): boolean {
  return !/^without$/i.test(issuerIcsValue(ics, 'ICS-03.tx_code') ?? 'with');
}
