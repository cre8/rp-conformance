// Shared structure of the RP_WS_SM_SessionBinding and RP_WS_SM_DeviceBinding test cases: one credential format, gated
// by that format's positive control, and either both presentation flows or the one the test case is about.
import {
  comments,
  defineTestCase,
  type FaultId,
  type Flow,
  type FormatWording,
  flows,
  positiveControlOf,
  preconditions,
  presentationStep,
  type Relevancy,
  rej,
  relevancy,
  type StepDefinition,
  step,
  testCaseId,
} from '@eudi-pcaf/core';

export interface BindingTestCase {
  number: number;
  /** Variant letter: `a` SD-JWT VC, `b` mdoc, where the objective is written for both formats. */
  variant?: 'a' | 'b';
  format: FormatWording;
  /** The flow the test case is about; left out when it is executed in each flow the Relying Party supports. */
  flow?: Flow;
  /** Default true. */
  unhappyFlow?: boolean;
  objective: string;
  references: string[];
  /** Default `EUDI_generic | EUDI_required`. */
  relevancy?: Relevancy;
  steps: StepDefinition[];
  comments?: string[];
}

/** The test case of `area`: the format's control, the flow's profile and technology where it names one. */
export const bindingTestCase = (area: 'SessionBinding' | 'DeviceBinding', testCase: BindingTestCase) =>
  defineTestCase({
    id: testCaseId('WS', 'SM', area, testCase.number, testCase.variant ?? '', testCase.unhappyFlow ?? true),
    objective: testCase.objective,
    references: [...testCase.references, '[CIR 2024/2982 amended] Annex II'],
    profile: [testCase.format.profile, ...(testCase.flow ? [flows[testCase.flow].profile] : [])],
    relevancy: testCase.relevancy ?? relevancy.genericRequired,
    technology: [testCase.format.technology, ...(testCase.flow ? [flows[testCase.flow].technology] : [])],
    preconditions: [...preconditions.base, preconditions.control(positiveControlOf(testCase.format))],
    control: positiveControlOf(testCase.format),
    steps: testCase.steps,
    comments: [...(testCase.comments ?? []), ...(testCase.flow ? [] : [comments.flow])],
  });

/** A step presenting `default_credential_pid` with a presentation fault, rejected; `flow` names the test case's flow. */
export const rejected = (fault: FaultId, flow?: Flow): StepDefinition => step({ ...presentationStep.presentationFault(fault, { flow }), expect: rej() });

/** The comment that an OIDF verifier test module covers the objective. */
export const oidf = (module: string) => comments.oidf(`oid4vp-1final-verifier-${module}`);
