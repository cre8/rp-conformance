// PP_WS_SM_TokenBinding: DPoP-bound access tokens (issuer catalogue section 5.1.3). The DPoP faults are applied at the
// credential endpoint, the resource the access token is for; the nonce fault at the token endpoint.
import { defineIssuerTestCase, type FormatVariant, type GrantVariant, relevancy } from '@eudi-pcaf/core';
import { iss, issuance, preconditions, rej, technologyOf } from '../../wording';
import { conf, FORMAT, faultStep, GRANT, MAIN, profileOf, ufPreconditions } from '../session';

const RFC = '[RFC 9449]';

const tokenBinding001 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_TokenBinding_001',
    variants: [format, grant],
    objective: 'Verify that the token endpoint of the PID Provider issues a DPoP-bound access token (`token_type` `DPoP`), bound to the key of the DPoP proof of the token request.',
    references: ['[HAIP] section 4', `${RFC} section 5`, `${RFC} section 6`],
    profile: profileOf(format, grant),
    relevancy: relevancy.specificRequired,
    technology: technologyOf(format),
    preconditions: preconditions.base,
    steps: [
      {
        text: '`CW-1` runs `SCN-I` for `SUBJ-1` without mutation, with a DPoP proof at the token endpoint.',
        run: issuance(format, grant, { stopAfterToken: true }),
        expect: conf(
          ['token-dpop-bound'],
          'The token response carries `token_type` `DPoP`. Where the access token is a JWT, its `cnf.jkt` is the JWK SHA-256 thumbprint of the DPoP key of `CW-1`.',
        ),
      },
    ],
    comments: ['The binding itself is shown by `PP_WS_SM_TokenBinding_002_UF` and `_003_UF`: a Bearer presentation and a proof of another key are rejected.'],
  });

const tokenBinding002 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_TokenBinding_002_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider rejects its DPoP-bound access token presented as a Bearer token, or without a DPoP proof.',
    references: [`${RFC} section 7.1`],
    profile: profileOf(format, grant),
    relevancy: relevancy.genericRequired,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: [faultStep(format, grant, 'dpop.bearer', rej()), faultStep(format, grant, 'dpop.missing', rej())],
  });

const tokenBinding003 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_TokenBinding_003_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider rejects a DPoP proof signed with a key other than the one the access token is bound to.',
    references: [`${RFC} section 4.3`],
    profile: profileOf(format, grant),
    relevancy: relevancy.genericRequired,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: [faultStep(format, grant, 'dpop.other-key', rej())],
  });

const tokenBinding004 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_TokenBinding_004_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider rejects a DPoP proof with a wrong `htm` or `htu`, a missing or wrong `ath`, or a stale `iat`.',
    references: [`${RFC} section 4.2`, `${RFC} section 4.3`],
    profile: profileOf(format, grant),
    relevancy: relevancy.genericRequired,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: (['dpop.htm-wrong', 'dpop.htu-wrong', 'dpop.ath-missing', 'dpop.ath-wrong', 'dpop.iat-stale'] as const).map((fault) => faultStep(format, grant, fault, rej())),
  });

const tokenBinding005 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_TokenBinding_005_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider rejects a replayed DPoP proof (same `jti`).',
    references: [`${RFC} section 11.1`],
    profile: profileOf(format, grant),
    relevancy: relevancy.genericRequired,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: [
      { text: '`CW-1` runs `SCN-I` for `SUBJ-1` without mutation.', run: issuance(format, grant), expect: iss(format) },
      {
        text: '`CW-1` sends a second credential request with the access token of step 1, a fresh `c_nonce` and key proof, and the DPoP proof of the credential request of step 1 unchanged.',
        run: { kind: 'token-reuse', artifact: 'dpop-proof', ofStep: 1 },
        expect: rej(),
      },
    ],
    comments: ['Step 2 is sent within `T_proof` of step 1, so only the reuse of the `jti` makes the proof invalid.'],
  });

const tokenBinding006 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_TokenBinding_006_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that a PID Provider that requires a DPoP server nonce rejects a proof without it with `use_dpop_nonce` and a new `DPoP-Nonce`, and that the retry with the nonce succeeds.',
    references: [`${RFC} section 8`, `${RFC} section 9`],
    profile: profileOf(format, grant, 'P-DPN'),
    relevancy: relevancy.genericRequired,
    technology: technologyOf(format),
    preconditions: ufPreconditions('The Provider declares that it uses a DPoP server nonce (ICS-13.dpop_nonce Yes).'),
    steps: [
      faultStep(format, grant, 'dpop.nonce-omitted', rej('use_dpop_nonce')),
      {
        text: '`CW-1` runs `SCN-I` for `SUBJ-1` without mutation: it answers `use_dpop_nonce` with one retry carrying the `DPoP-Nonce`.',
        run: issuance(format, grant),
        expect: iss(format),
      },
    ],
    comments: ['NOT APPLICABLE when the Provider declares no DPoP server nonce (ICS-13.dpop_nonce No): `P-DPN` also stands for the nonce endpoint.'],
  });

const tokenBinding007 = (format: FormatVariant, grant: GrantVariant) =>
  defineIssuerTestCase({
    id: 'PP_WS_SM_TokenBinding_007_UF',
    variants: [format, grant],
    control: MAIN,
    objective: 'Verify that the PID Provider rejects an expired access token.',
    references: ['[RFC 6750] section 3.1'],
    profile: profileOf(format, grant),
    relevancy: relevancy.genericRequired,
    technology: technologyOf(format),
    preconditions: ufPreconditions(),
    steps: [faultStep(format, grant, 'access-token.expired', rej('invalid_token'))],
    comments: [
      'The step waits out the access token lifetime: `expires_in`, plus the `T_skew` the Provider declares (ICS-14, at most 5 minutes), plus one minute. The catalogue\'s "plus one hour" (section 3.5) moves time values the suite writes; a lifetime the Provider enforces can only be waited for, and one minute past the declared tolerance is past any tolerance the Provider declares. A run executes the step only when `ISSUER_MAX_WAIT_SECONDS` (default 600) allows the wait; otherwise the result is INCONCLUSIVE.',
    ],
  });

export const definitions = [tokenBinding001, tokenBinding002, tokenBinding003, tokenBinding004, tokenBinding005, tokenBinding006, tokenBinding007].map((d) => d(FORMAT, GRANT));
