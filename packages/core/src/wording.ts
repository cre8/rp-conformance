// The shared wording of the FCAF Relying Party test cases, ported from generator/tests.py so the 121 definitions do
// not repeat it. Texts must stay byte-identical to the committed fcaf-overlay files until the renderer replaces them.
import type { DefaultQueryId } from './adapter';
import {
  type CredentialSpec,
  type Expectation,
  type Flow,
  type IcsCondition,
  ics,
  presentation,
  type StatusListSpec,
  type StepAction,
} from './definition';

/** Markup of a `default_*` item, as the FCAF lint expects it. */
export const item = (name: string) => `\`${name}\``;

export const PID = item('default_credential_pid');
export const QUERY_PID = item('default_query_pid');

export interface FormatWording {
  /** Variant letter of the test case ID. */
  letter: 'a' | 'b';
  name: string;
  profile: IcsCondition;
  technology: string;
  /** Technology line of the Status List Token in this format. */
  statusListTechnology: string;
}

export const formats = {
  sdJwtVc: {
    letter: 'a',
    name: 'SD-JWT VC',
    profile: ics.requestsSdJwtVc,
    technology: 'Presentation of a credential in IETF SD-JWT VC format.',
    statusListTechnology: 'Status List Token in JWT format.',
  },
  mdoc: {
    letter: 'b',
    name: 'mdoc',
    profile: ics.requestsMdoc,
    technology: 'Presentation of a credential in ISO/IEC 18013-5 mdoc format.',
    statusListTechnology: 'Status List Token in CWT format.',
  },
} as const satisfies Record<string, FormatWording>;

export const flows = {
  redirect: {
    letter: 'a',
    profile: ics.supportsRedirects,
    technology: 'Presentation via redirects with response mode `direct_post.jwt`.',
    via: 'via redirects',
  },
  'dc-api': {
    letter: 'b',
    profile: ics.supportsDcApi,
    technology: 'Presentation via the W3C Digital Credentials API with response mode `dc_api.jwt`.',
    via: 'via the W3C Digital Credentials API',
  },
} as const satisfies Record<Flow, { letter: string; profile: IcsCondition; technology: string; via: string }>;

export const technology = {
  identifierListCwt: 'Identifier list in CWT format.',
};

/** The positive control of a credential format. */
export const positiveControlOf = (format: FormatWording) => `RP_WS_IA_MainInteraction_001${format.letter}`;

export const preconditions = {
  /** `default_configuration_rp_1` and `default_trust_configuration_rp`, the start of every test case. */
  base: [
    'The Relying Party is set to `default_configuration_rp_1`.',
    'The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.',
  ],
  /** The positive control that gates the test case; pair it with `control` in the definition. */
  control: (id: string) => `Test case \`${id}\` passed in the same environment.`,
  /** The positive controls of both formats, for test cases whose credential format does not matter. */
  controlOfFlow: (ids: [string, string]) =>
    `Test case \`${ids[0]}\` or \`${ids[1]}\` passed in the same environment for the presentation flow of this test case.`,
  freshStatusList:
    'Every credential presented in this test case references a status list URI from which the Relying Party has not retrieved a status list before.',
};

export const comments = {
  flow: 'Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).',
  nostat:
    'A Status List Token that cannot be used leaves no reliable revocation status. For PIDs the Relying Party SUT rejects the presentation in that case; for QEAA, PuB-EAA and non-qualified EAA the policy declared in the ICS applies (see [ARF] Annex 2, VCR_14).',
  positiveControl: (format: FormatWording) =>
    `This test case is the positive control for the unhappy-flow test cases of the Relying Party SUT that present a credential in ${format.name} format. When it fails, those test cases cannot produce a meaningful verdict in the same environment.`,
};

const REJ_TEXT =
  'The Relying Party rejects the presentation: its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.';

/** `ACC`: the Relying Party accepts the presentation. */
export const acc = (options: { credential?: string; query?: string } = {}): Expectation => ({
  codes: ['ACC'],
  text: `The Relying Party accepts the presentation: its verification result reports success and releases exactly the attributes requested in ${options.query ?? QUERY_PID}, with the values of ${options.credential ?? 'the presented credential'}.`,
});

/** `REJ`: the Relying Party rejects the presentation. */
export const rej = (): Expectation => ({ codes: ['REJ'], text: REJ_TEXT });

/**
 * `NOSTAT`: no reliable revocation status. A PID is rejected, so the text is that of `REJ`; for other categories the
 * controller applies the policy of the ICS. Pair it with `comments.nostat`.
 */
export const nostat = (): Expectation => ({ codes: ['NOSTAT'], text: REJ_TEXT });

/** `NOFETCH`: the Test Status Provider logs no request for the credential's status list. */
export const nofetch = (): Expectation => ({
  codes: ['NOFETCH'],
  text: 'The Test Status Provider logs no request from the Relying Party for the status list referenced by the credential.',
});

/** `FETCHED`: the Test Status Provider logs a request for the credential's status list. */
export const fetched = (): Expectation => ({
  codes: ['FETCHED'],
  text: 'The Test Status Provider has logged a request from the Relying Party for the status list referenced by the credential.',
});

/** Several expected results of one step, rendered as one line: for example `all(acc(...), fetched())`. */
export const all = (...parts: Expectation[]): Expectation => ({
  codes: parts.flatMap((p) => p.codes),
  text: parts.map((p) => p.text).join(' '),
});

/** Test scenario texts. */
export const scenario = {
  valid: (options: { credential?: string; query?: string; extra?: string } = {}) =>
    `Perform a presentation for ${options.query ?? QUERY_PID} in which the Conformance Wallet presents ${options.credential ?? PID} in a valid Authorization Response${options.extra ?? ''}.`,
  credentialVariant: (difference: string, options: { credential?: string; query?: string } = {}) =>
    `Perform a presentation for ${options.query ?? QUERY_PID} in which the Conformance Wallet presents, in an otherwise valid Authorization Response, a variant of ${options.credential ?? PID} that differs from it only in that ${difference}.`,
  statusValue: (value: string) =>
    `Perform a presentation for ${QUERY_PID} in which the Conformance Wallet presents ${PID} in a valid Authorization Response, while the status list referenced by the credential holds the value ${value} at the credential's index.`,
  statusListToken: (difference: string) =>
    `Perform a presentation for ${QUERY_PID} in which the Conformance Wallet presents ${PID} in a valid Authorization Response, while the Test Status Provider serves, for the status list referenced by the credential, a Status List Token that holds the value 0x00 at the credential's index and is valid in every other respect, except that ${difference}.`,
  encryption: (flow: Flow, difference: string) =>
    `Perform a presentation for ${QUERY_PID} ${flows[flow].via} in which the Conformance Wallet presents ${PID} in an Authorization Response that is valid except that ${difference}.`,
};

/** A step's scenario text together with what the harness executes for it. */
export interface ScenarioStep {
  text: string;
  run: StepAction;
}

/** Steps whose text and execution are defined together, so a fault and its description cannot drift apart. */
export const presentationStep = {
  /** A valid presentation of a default credential for a default query. */
  valid(options: { query: DefaultQueryId; credential: CredentialSpec; statusList?: StatusListSpec }): ScenarioStep {
    return {
      text: scenario.valid({ credential: item(options.credential.defaultCredential), query: item(options.query) }),
      run: presentation(options),
    };
  },
  /** A presentation of a variant of a default credential that differs only in `difference` (the fault). */
  credentialVariant(difference: string, options: { query: DefaultQueryId; credential: CredentialSpec; statusList?: StatusListSpec }): ScenarioStep {
    return {
      text: scenario.credentialVariant(difference, { credential: item(options.credential.defaultCredential), query: item(options.query) }),
      run: presentation(options),
    };
  },
};
