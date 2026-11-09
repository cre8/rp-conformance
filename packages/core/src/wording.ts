// The shared wording of the FCAF Relying Party test cases, so the 121 definitions do not repeat it. The FCAF markdown in
// fcaf-overlay/ is rendered from the definitions (packages/fcaf-render); a test checks that it is up to date.
import type { DefaultQueryId } from './adapter';
import {
  type CredentialSpec,
  type Expectation,
  type Flow,
  type IcsCondition,
  ics,
  pid,
  presentation,
  type ResponseSpec,
  type StatusListSpec,
  type StepAction,
  statusListToken,
} from './definition';
import { type FaultId, faultInfo } from './faults';

/** Markup of a `default_*` item, as the FCAF lint expects it. */
export const item = (name: string) => `\`${name}\``;

export const PID = item('default_credential_pid');
export const QUERY_PID = item('default_query_pid');

/** The default credentials of the Relying Party defaults, as test cases name them. */
export const credentials = {
  pid: PID,
  pidShort: item('default_credential_pid_short'),
  qeaa: item('default_credential_qeaa'),
  pubEaa: item('default_credential_pubeaa'),
  eaa: item('default_credential_eaa'),
};

/** The default queries of the Relying Party defaults, as test cases name them. */
export const queries = {
  pid: QUERY_PID,
  qeaa: item('default_query_qeaa'),
  pubEaa: item('default_query_pubeaa'),
  eaa: item('default_query_eaa'),
};

/** A Relying Party test case ID: `RP_<class>_<layer>_<area>_<nnn><variant>[_UF]`. */
export const testCaseId = (sutClass: 'WS' | 'PP', layer: 'IA' | 'SM', area: string, number: number, variant = '', unhappyFlow = false) =>
  `RP_${sutClass}_${layer}_${area}_${String(number).padStart(3, '0')}${variant}${unhappyFlow ? '_UF' : ''}`;

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
  statusValid: "The status list referenced by the presented credential holds the value 0x00 (VALID) at the credential's index.",
  identifierList:
    'The `status` element of the MSO of every presented credential carries an `identifier_list` entry (`id`, `uri`) that references an identifier list in CWT format (`application/identifierlist+cwt`) served by the Test Status Provider.',
  identifierListOmits: "The identifier list served for each presented credential does not contain the credential's identifier.",
  trustedAuthoritiesOfPpA:
    'The Relying Party is configured to restrict `default_query_pid` with a `trusted_authorities` entry of type `aki` that names only the PID/Issuance anchor of `PP-A`.',
};

export const comments = {
  flow: 'Execute this test case once for each presentation flow the Relying Party supports (redirects, W3C Digital Credentials API).',
  nostat:
    'A Status List Token that cannot be used leaves no reliable revocation status. For PIDs the Relying Party SUT rejects the presentation in that case; for QEAA, PuB-EAA and non-qualified EAA the policy declared in the ICS applies (see [ARF] Annex 2, VCR_14).',
  encryptionFormat:
    'The credential format does not affect this test case; use `default_credential_pid` in a format the Relying Party requests.',
  restoreTrustList: 'Restore the previous version of `TL-PID` after the test case.',
  oidf: (module: string) => `The OIDF verifier test module \`${module}\` covers the same objective.`,
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

/** `FETCHED` for the identifier list of an mdoc. */
export const fetchedIdentifierList = (): Expectation => ({
  codes: ['FETCHED'],
  text: 'The Test Status Provider has logged a request from the Relying Party for the identifier list.',
});

/**
 * `POLICY` for an application-specific status value (ICS RP.R.3): rejected unless the Relying Party declares a meaning
 * for it, otherwise handled as declared.
 */
export const policyApplicationSpecificStatus = (value: string): Expectation => ({
  codes: ['POLICY'],
  policy: { item: 'RP.R.3', status: Number.parseInt(value, 16) },
  text: `If the Relying Party declares no meaning for the status value ${value} in its ICS: ${REJ_TEXT[0].toLowerCase()}${REJ_TEXT.slice(1)} If it declares a meaning: it handles the presentation as declared.`,
});

/** `LIST_RETRIEVED`: the Relying Party retrieved the list version the step published. */
export const listRetrieved = (list: string): Expectation => ({
  codes: ['LIST_RETRIEVED'],
  text: `The Test Trust Infrastructure logs a retrieval of the new version of \`${list}\` by the Relying Party.`,
});

/** `ENC_KEY`: the request of a transaction carries an encryption key. */
export const encryptionKeyOf = (transaction: string): Expectation => ({
  codes: ['ENC_KEY'],
  text: `The request of ${transaction} carries an encryption key in its \`client_metadata\`.`,
});

/** Several expected results of one step, rendered as one line: for example `all(acc(...), fetched())`. */
export const all = (...parts: Expectation[]): Expectation => ({
  codes: parts.flatMap((p) => p.codes),
  text: parts.map((p) => p.text).join(' '),
  ...(parts.find((p) => p.policy) ? { policy: parts.find((p) => p.policy)?.policy } : {}),
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

/** The FCAF name of a default query: the restricted variant of `default_query_pid` is still `default_query_pid`. */
export const queryName = (query: DefaultQueryId) => item(query === 'default_query_pid_trusted_authorities' ? 'default_query_pid' : query);

interface PresentationOptions {
  query?: DefaultQueryId;
  credential?: CredentialSpec;
  statusList?: StatusListSpec | null;
  response?: ResponseSpec;
}

const run = (options: PresentationOptions) =>
  presentation({ query: options.query ?? 'default_query_pid', credential: options.credential ?? pid.sdJwtVc(), ...options });

/**
 * Steps whose text and execution are defined together: the fault a step applies is named once, and its FCAF wording
 * comes from the fault catalogue (`FAULTS`).
 */
export const presentationStep = {
  /** A valid presentation of a default credential for a default query. */
  valid(options: PresentationOptions & { text?: { credential?: string; extra?: string } } = {}): ScenarioStep {
    const credential = options.credential ?? pid.sdJwtVc();
    return {
      text: scenario.valid({
        credential: options.text?.credential ?? item(credential.defaultCredential),
        query: queryName(options.query ?? 'default_query_pid'),
        extra: options.text?.extra,
      }),
      run: run(options),
    };
  },
  /** A presentation of a variant of `default_credential_pid` that differs only in `difference`, for example its issuer. */
  credentialVariant(difference: string, options: PresentationOptions = {}): ScenarioStep {
    return { text: scenario.credentialVariant(difference, { query: queryName(options.query ?? 'default_query_pid') }), run: run(options) };
  },
  /** A presentation of `default_credential_pid` with a credential fault. */
  credentialFault(fault: FaultId, options: PresentationOptions = {}): ScenarioStep {
    return presentationStep.credentialVariant(faultInfo(fault).text, {
      ...options,
      credential: pid.sdJwtVc({ ...options.credential, faults: [fault] }),
    });
  },
  /** A presentation while the credential's status list holds `value` (for example `0x01 (INVALID)`) at its index. */
  statusValue(value: string, status: number): ScenarioStep {
    return { text: scenario.statusValue(value), run: run({ statusList: statusListToken.jwt({ status }) }) };
  },
  /** A presentation while the Status List Token has a fault; `text` replaces the wording where the scenario differs. */
  statusListFault(fault: FaultId, options: { text?: string } = {}): ScenarioStep {
    return {
      text: options.text ?? scenario.statusListToken(faultInfo(fault).text),
      run: run({ statusList: statusListToken.jwt({ faults: [fault] }) }),
    };
  },
  /** A presentation via `flow` whose Authorization Response has a fault. */
  encryptionFault(flow: Flow, fault: FaultId, options: { text?: string; response?: Omit<ResponseSpec, 'faults'> } = {}): ScenarioStep {
    return {
      text: options.text ?? scenario.encryption(flow, faultInfo(fault).text),
      run: run({ response: { ...options.response, faults: [fault] } }),
    };
  },
};
