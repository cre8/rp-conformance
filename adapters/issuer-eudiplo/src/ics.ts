import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { ISSUER_ICS_ITEMS, type IssuerIcs, type IssuerProfile } from '@eudi-pcaf/core';
import { parse } from 'yaml';

/** The ICS of EUDIPLO as this adapter configures it. */
export const ICS_PATH = fileURLToPath(new URL('../ics.yaml', import.meta.url));

const PROFILES = new Set<string>(Object.values(ISSUER_ICS_ITEMS).flatMap((item) => [...item.profiles]));

/**
 * Reads an issuer ICS file: `profiles`, the profiles the answers select, and `items`, the declared values keyed by ICS
 * item ID or `<item>.<name>` (`IssuerIcs`). Every profile must be one of the catalogue's, every item key one of
 * ICS-01 to ICS-19.
 */
export async function loadIssuerIcs(path = ICS_PATH): Promise<IssuerIcs> {
  const parsed = parse(await readFile(path, 'utf8')) as { profiles?: unknown; items?: unknown } | null;
  if (!parsed || !Array.isArray(parsed.profiles) || !parsed.items || typeof parsed.items !== 'object') {
    throw new Error(`${path}: not an issuer ICS (profiles and items)`);
  }
  for (const profile of parsed.profiles) {
    if (!PROFILES.has(String(profile))) throw new Error(`${path}: unknown profile ${String(profile)}`);
  }
  for (const key of Object.keys(parsed.items)) {
    if (!(key.split('.')[0] in ISSUER_ICS_ITEMS)) throw new Error(`${path}: unknown ICS item ${key}`);
  }
  // Issue 27: the Attestation Provider instances, one per category, with their own profiles and the items that differ.
  const categories = (parsed as { categories?: IssuerIcs['categories'] }).categories;
  const ics: IssuerIcs = { profiles: parsed.profiles as IssuerProfile[], items: parsed.items as IssuerIcs['items'], ...(categories ? { categories } : {}) };
  const problems = [
    ...icsProblems(ics),
    ...Object.entries(categories ?? {}).flatMap(([category, entry]) =>
      icsProblems({ profiles: entry?.profiles ?? [], items: { ...ics.items, ...(entry?.items ?? {}) } }).map((p) => `categories.${category}: ${p}`),
    ),
  ];
  if (problems.length) throw new Error(`${path}: ${problems.join('; ')}`);
  return ics;
}

/** Seconds of an ISO 8601 duration without years and months (`PT5M`, `P1DT2H`), or undefined if it is none. */
export function durationSeconds(value: unknown): number | undefined {
  const match = typeof value === 'string' ? /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(value) : null;
  if (!match || value === 'P' || value === 'PT') return undefined;
  const [, d = '0', h = '0', m = '0', sec = '0'] = match;
  return ((Number(d) * 24 + Number(h)) * 60 + Number(m)) * 60 + Number(sec);
}

/** The limits the catalogue sets on declared values (section 3.5, ICS-06, ICS-07, ICS-14, ICS-16, decisions 3 and 4). */
const MAXIMA: Record<string, number> = {
  'ICS-06.T_rev': 24 * 3600,
  'ICS-07.T_chain': 24 * 3600,
  'ICS-14.T_proof': 5 * 60,
  'ICS-14.T_skew': 5 * 60,
};

/**
 * What a declared ICS breaks of the catalogue's rules: a duration above its cap, fewer than 10 000 status list entries,
 * or a profile without the value it needs (`P-HOOK` needs `T_rev`, `P-CHAIN` needs `T_chain`). A value that is not a
 * duration (for example `not bounded`) is a declaration the test cases then take at the cap.
 */
export function icsProblems(ics: IssuerIcs): string[] {
  const problems: string[] = [];
  for (const [key, max] of Object.entries(MAXIMA)) {
    const seconds = durationSeconds(ics.items[key]);
    if (seconds !== undefined && seconds > max) problems.push(`${key} ${String(ics.items[key])} is above the catalogue's ${max} s`);
  }
  const entries = ics.items['ICS-16.min_entries'];
  if (entries !== undefined && !(Number(entries) >= 10_000)) problems.push(`ICS-16.min_entries ${String(entries)} is below 10 000 (decision 4)`);
  if (ics.profiles.includes('P-HOOK') && durationSeconds(ics.items['ICS-06.T_rev']) === undefined) problems.push('P-HOOK without a duration ICS-06.T_rev');
  if (ics.profiles.includes('P-CHAIN') && durationSeconds(ics.items['ICS-07.T_chain']) === undefined) problems.push('P-CHAIN without a duration ICS-07.T_chain');
  return problems;
}

/** A declared value as a list of strings (a YAML list, or one string). */
export function icsList(ics: IssuerIcs, key: string, fallback: string[]): string[] {
  const value = ics.items[key];
  if (value === undefined) return fallback;
  return Array.isArray(value) ? value.map(String) : [String(value)];
}

/** A declared value as a number. */
export function icsNumber(ics: IssuerIcs, key: string, fallback: number): number {
  const value = Number(ics.items[key]);
  return ics.items[key] === undefined || !Number.isFinite(value) ? fallback : value;
}
