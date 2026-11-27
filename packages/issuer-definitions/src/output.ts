// Building blocks of the test cases that check what the Provider issued (`OBS-CRED`): `SM_Validity` and the PID
// Rulebook areas `DM_*` (issuer catalogue sections 5.1.3 and 5.1.4). Each runs `SCN-I` without mutation and expects
// `CONF` with the named checks of the reference validator.
import { type CheckId, type FormatVariant, type GrantVariant, type IssuerExpectation, issuerProfiles } from '@eudi-pcaf/core';
import { FORMAT_NAMES, pidProfile } from './wording';

/** Every grant a test case runs in when the catalogue names none (section 2.3): one definition each. */
export const GRANTS: GrantVariant[] = ['PA', 'AC'];

/** The definitions of a test case for each format it names and each grant. */
export const expand = <T>(formats: FormatVariant[], build: (format: FormatVariant, grant: GrantVariant) => T): T[] =>
  formats.flatMap((format) => GRANTS.map((grant) => build(format, grant)));

/**
 * The short-lived configuration of a format (ICS-05, `P-SHORT`): `ICS-05.short.<format variant>` names the
 * configuration that issues the PID valid for at most 24 hours, without a status reference.
 */
export const shortConfigurationOf = (format: FormatVariant) => `ICS-05.short.${format}`;

/** The profile of a PID test case with a short-lived configuration. */
export const shortPidProfile = (format: FormatVariant, grant: GrantVariant) => [...pidProfile(format, grant), issuerProfiles['P-SHORT']];

/**
 * `CONF` (issuer catalogue section 2.5) on an issuance step: `ISS`, and the named checks of the rule pass as well. The
 * output checks run only where a test case names them, so each rule is judged by its own test case.
 */
export function conf(checks: CheckId[], rule: string, format?: FormatVariant): IssuerExpectation {
  return {
    codes: ['CONF'],
    checks,
    text: `The Provider issues the credential (HTTP 200)${format ? ` in ${FORMAT_NAMES[format]} format` : ''}, it passes every check of the reference validator, and ${rule} (${checks.map((c) => `\`${c}\``).join(', ')}).`,
  };
}

/** `Comments` shared by the output test cases. */
export const OUTPUT_COMMENTS = [
  'The named check runs in this test case only; the other checks of the reference validator run as in `PP_WS_IA_MainInteraction_001` and must pass too.',
  'Execute this test case once for each format named and each grant the Provider declares in its ICS (ICS-02, ICS-03).',
];
