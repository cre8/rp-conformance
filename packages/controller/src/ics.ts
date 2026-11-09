import { readFile } from 'node:fs/promises';
import type { Ics, TestCaseDefinition } from '@rp-conformance/core';
import { parse } from 'yaml';

/** Reads an ICS file: a YAML map from ICS item ID (for example `RP.G.1`) to the declared option. */
export async function loadIcs(path: string): Promise<Ics> {
  const items = parse(await readFile(path, 'utf8')) as Record<string, string | number | boolean>;
  if (!items || typeof items !== 'object') throw new Error(`${path}: not an ICS map`);
  for (const key of ['RP.P.4', 'RP.P.6']) {
    const value = Number(items[key]);
    if (key in items && (!Number.isFinite(value) || value < 0 || value > 300)) {
      throw new Error(`${path}: ${key} must be between 0 and 300 seconds (default_configuration_rp_1)`);
    }
  }
  return { items };
}

/** The declared answer, with booleans normalised to `Yes`/`No`. */
export function icsAnswer(ics: Ics, item: string): string | undefined {
  const value = ics.items[item];
  if (value === undefined) return undefined;
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  return String(value);
}

/** The `Profile applicability` conditions the ICS does not meet; empty when the test case applies. */
export function applicability(definition: TestCaseDefinition, ics: Ics): string[] {
  return definition.profile
    .filter((condition) => icsAnswer(ics, condition.item) !== condition.equals)
    .map((condition) => `${condition.item} (${condition.text}) is ${icsAnswer(ics, condition.item) ?? 'not declared'}`);
}

export type StatusMeaning = 'valid' | 'invalid' | string;

/**
 * The meanings of application-specific status values the Relying Party declares (ICS RP.R.3), as `None` or
 * `0x03=valid; 0x04=invalid`. `valid` and `invalid` are evaluated; any other text makes the verdict REVIEW.
 */
export function statusMeanings(ics: Ics): Map<number, StatusMeaning> {
  const declared = icsAnswer(ics, 'RP.R.3') ?? 'None';
  const meanings = new Map<number, StatusMeaning>();
  for (const match of declared.matchAll(/0x([0-9a-f]{1,2})\s*[:=]\s*([^;]+)/gi)) {
    meanings.set(Number.parseInt(match[1], 16), match[2].trim().toLowerCase());
  }
  return meanings;
}

/** The status values the Relying Party declares as VALID besides 0x00. */
export function validStatuses(ics: Ics): number[] {
  return [...statusMeanings(ics)].filter(([, meaning]) => meaning === 'valid').map(([value]) => value);
}
