// Building blocks of the issue 25 definitions (DPoP, batch, re-issuance, deferred, notification, encoding, encryption):
// the step texts of a fault, the `CONF`, `NOFETCH` and `UNCHANGED` expectations, and the variant they run in. Kept apart
// from ../wording.ts so each area's helpers stay in its own file.
import {
  type FormatVariant,
  type GrantVariant,
  type IssuanceAction,
  type IssuerExpectation,
  type IssuerFaultId,
  type IssuerStepDefinition,
  ISSUER_FAULTS,
  issuerProfiles,
  type IssuerProfile,
  SESSION_FAULTS,
  type SessionFaultId,
} from '@eudi-pcaf/core';
import { issuance, pidProfile, preconditions } from '../wording';

/**
 * The variant the issue 25 test cases are defined in: SD-JWT VC in the pre-authorized code flow, the variant of the
 * positive control `PP_WS_IA_MainInteraction_001` so far. The other variants follow with mdoc and the authorization
 * code flow.
 */
export const FORMAT: FormatVariant = 'SD';
export const GRANT: GrantVariant = 'PA';
export const MAIN = 'PP_WS_IA_MainInteraction_001';

/** The profile applicability: the PID Provider in the variant, plus the profiles the area needs (`P-BATCH`, `P-REISS`, ...). */
export const profileOf = (format: FormatVariant, grant: GrantVariant, ...extra: IssuerProfile[]) => [...pidProfile(format, grant), ...extra.map((p) => issuerProfiles[p])];

/** The preconditions of a `_UF` test case: the base and its positive control. */
export const ufPreconditions = (...extra: string[]) => [...preconditions.base, ...extra, preconditions.control(MAIN)];

const faultText = (fault: SessionFaultId | IssuerFaultId) => (fault in SESSION_FAULTS ? SESSION_FAULTS[fault as SessionFaultId].text : ISSUER_FAULTS[fault as IssuerFaultId].text);

/** "`CW-1` runs `SCN-I` as in the positive control, except that ..." */
export function faultStep(format: FormatVariant, grant: GrantVariant, fault: SessionFaultId | IssuerFaultId, expect: IssuerExpectation, options: Partial<Omit<IssuanceAction, 'kind' | 'grant' | 'faults'>> = {}): IssuerStepDefinition {
  return {
    text: `\`CW-1\` runs \`SCN-I\` for \`SUBJ-1\` as in the positive control \`${MAIN}\`, except that ${faultText(fault)} (fault \`${fault}\`).`,
    run: issuance(format, grant, { ...options, faults: [fault] }),
    expect,
  };
}

/** `CONF` with named checks of the session module (packages/controller/src/issuer/session.ts). */
export const conf = (checks: string[], text: string): IssuerExpectation => ({ codes: ['CONF'], checks, text });

/** `NOFETCH` of the URLs a fault points to the Test Status Provider. */
export const noFetch: IssuerExpectation = {
  codes: ['NOFETCH'],
  noFetch: 'the URL of the Test Status Provider the fault names',
  text: 'The Test Status Provider logs no request for the URL the fault points to during the step.',
};

/** `REJ` with alternatives: any of the named error codes passes. */
export const rejAny = (...codes: string[]): IssuerExpectation => ({
  codes: [`REJ:${codes.join('|')}`],
  text: `The Provider issues no credential and answers with HTTP 4xx and an OAuth or OpenID4VCI error object with \`error\` ${codes.map((c) => `\`${c}\``).join(' or ')}; never HTTP 5xx.`,
});

/** Joins two expectations into one step expectation. */
export const both = (a: IssuerExpectation, b: IssuerExpectation): IssuerExpectation => ({
  ...a,
  ...b,
  codes: [...a.codes, ...b.codes],
  ...(a.checks || b.checks ? { checks: [...(a.checks ?? []), ...(b.checks ?? [])] } : {}),
  text: `${a.text} ${b.text}`,
});
