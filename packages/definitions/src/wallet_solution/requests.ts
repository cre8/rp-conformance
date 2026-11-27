// Shared structure of the request-side test cases (catalogue scenario SCN-Q): `RP_WS_MS_ProtocolMessages`, `_Metadata`,
// `_CredentialFormats` and `RP_WS_SM_RpIntegrity`. Each test case starts presentations, captures the requests at the
// Conformance Wallet without answering them, and expects them to pass the request checks it names (`CONF`).
import {
  comments,
  conf,
  type DefaultQueryId,
  defineTestCase,
  type Flow,
  type FormatWording,
  flows,
  type IcsCondition,
  pidQueryOf,
  preconditions,
  QUERY_PID,
  type Relevancy,
  type RequestCheck,
  relevancy,
  step,
  testCaseId,
} from '@eudi-pcaf/core';

export interface RequestTestCase {
  layer: 'MS' | 'SM' | 'IA';
  area: string;
  number: number;
  /** The credential format whose query the test case requests (variant `a` or `b`), where the objective is per format. */
  format?: FormatWording;
  /** The flow the objective is about; left out when it applies to every flow. */
  flow?: Flow;
  objective: string;
  references: string[];
  /** Default `EUDI_generic | EUDI_required`. */
  relevancy?: Relevancy;
  profile?: IcsCondition[];
  preconditions?: string[];
  /** The query requested; default `default_query_pid` in the format of the test case, or in SD-JWT VC format. */
  query?: DefaultQueryId;
  /** Number of requests; default 1. */
  count?: number;
  checks: RequestCheck[];
  /** The rule the requests must follow, as the expected result states it. */
  rule: string;
  comments?: string[];
  /** How the Conformance Wallet retrieves each request object (ProtocolFlow_002, _003); `text` replaces the step text. */
  requestUri?: { method: 'twice' | 'post'; text: string };
}

const NOT_ANSWERED = 'The Conformance Wallet does not answer the requests; the test case checks only what the Relying Party sends.';

export const requestTestCase = (testCase: RequestTestCase) => {
  const count = testCase.count ?? 1;
  const via = testCase.flow ? ` ${flows[testCase.flow].via}` : '';
  const many = count > 1;
  return defineTestCase({
    id: testCaseId('WS', testCase.layer, testCase.area, testCase.number, testCase.format?.letter ?? '', false),
    objective: testCase.objective,
    references: [...testCase.references, '[CIR 2024/2982 amended] Annex II'],
    profile: [...(testCase.format ? [testCase.format.profile] : []), ...(testCase.flow ? [flows[testCase.flow].profile] : []), ...(testCase.profile ?? [])],
    relevancy: testCase.relevancy ?? relevancy.genericRequired,
    technology: [...(testCase.format ? [testCase.format.technology] : []), ...(testCase.flow ? [flows[testCase.flow].technology] : [])],
    preconditions: [...preconditions.base, ...(testCase.preconditions ?? [])],
    steps: [
      step({
        text:
          testCase.requestUri?.text ??
          `Start ${many ? `${count} presentations` : 'a presentation'} for ${QUERY_PID}${via} and capture the request${many ? 's' : ''} the Conformance Wallet receives, without answering ${many ? 'them' : 'it'}.`,
        run: {
          kind: 'request',
          query: testCase.query ?? pidQueryOf(testCase.format?.credentialFormat ?? 'dc+sd-jwt'),
          ...(many ? { count } : {}),
          ...(testCase.requestUri ? { requestUri: testCase.requestUri.method } : {}),
        },
        expect: conf(testCase.checks, testCase.rule),
      }),
    ],
    comments: [...(testCase.comments ?? []), NOT_ANSWERED, ...(testCase.flow ? [] : [comments.flow])],
  });
};
