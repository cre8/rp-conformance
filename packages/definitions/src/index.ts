import { isExecutable, type TestCaseDefinition } from '@rp-conformance/core';
import { definitions as ppRevocation } from './pid_provider/SecurityMechanisms/Revocation';
import { definitions as mainInteraction } from './wallet_solution/Interaction/MainInteraction';
import { definitions as wsRevocation } from './wallet_solution/SecurityMechanisms/Revocation';
import { definitions as sessionEncryption } from './wallet_solution/SecurityMechanisms/SessionEncryption';
import { definitions as trustMechanisms } from './wallet_solution/SecurityMechanisms/TrustMechanisms';
import { definitions as validity } from './wallet_solution/SecurityMechanisms/Validity';

/**
 * Every test definition of the baseline, the source of truth for the FCAF test cases (harness design section 4.2), in
 * the order of the baseline lists. A definition whose steps all have an action is executable; the others are text
 * only until a later phase implements them.
 */
export const definitions: TestCaseDefinition[] = [
  ...mainInteraction,
  ...validity,
  ...wsRevocation,
  ...ppRevocation,
  ...trustMechanisms,
  ...sessionEncryption,
];

/** The definitions the harness can execute. */
export const executableDefinitions = definitions.filter(isExecutable);
