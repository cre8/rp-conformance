// `CONF` (issuer catalogue section 2.5) for the message structure layer: the named checks of the reference validator
// over the captured metadata or offer (issue 24), with the FCAF wording of each.
import type { IssuerArtifactCheck, IssuerExpectation } from '@eudi-pcaf/core';

/** `CONF` with the named checks, each worded as what the captured artifact must satisfy. */
export function conf(checks: Partial<Record<IssuerArtifactCheck, string>>): IssuerExpectation {
  const entries = Object.entries(checks) as [IssuerArtifactCheck, string][];
  return {
    codes: ['CONF'],
    checks: entries.map(([check]) => check),
    text: `The captured artifact passes ${entries.map(([check, text]) => `\`${check}\` (${text})`).join('; ')}.`,
  };
}
