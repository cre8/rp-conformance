import { isExecutable, type TestCaseDefinition } from '@eudi-pcaf/core';
import { definitions as ppRevocation } from './pid_provider/SecurityMechanisms/Revocation';
import { definitions as mainInteraction, furtherDefinitions as furtherMainInteraction } from './wallet_solution/Interaction/MainInteraction';
import { definitions as infTrustMechanisms } from './infrastructure/SecurityMechanisms/TrustMechanisms';
import { definitions as credentialFormats } from './wallet_solution/MessageStructure/CredentialFormats';
import { definitions as metadata } from './wallet_solution/MessageStructure/Metadata';
import { definitions as protocolMessages } from './wallet_solution/MessageStructure/ProtocolMessages';
import { definitions as rpIntegrity } from './wallet_solution/SecurityMechanisms/RpIntegrity';
import { definitions as issuerIntegrity } from './wallet_solution/SecurityMechanisms/IssuerIntegrity';
import { definitions as deviceBinding } from './wallet_solution/SecurityMechanisms/DeviceBinding';
import { definitions as wsRevocation } from './wallet_solution/SecurityMechanisms/Revocation';
import { definitions as sessionBinding } from './wallet_solution/SecurityMechanisms/SessionBinding';
import { definitions as sessionEncryption } from './wallet_solution/SecurityMechanisms/SessionEncryption';
import { definitions as trustMechanisms } from './wallet_solution/SecurityMechanisms/TrustMechanisms';
import { definitions as validity } from './wallet_solution/SecurityMechanisms/Validity';
import { definitions as encoding } from './wallet_solution/Shared/Encoding';
import { definitions as supportive } from './pid_provider/Interaction/Supportive';
import { definitions as revocationPolicy } from './pid_provider/SecurityMechanisms/RevocationPolicy';
import { definitions as revocationMechanisms } from './wallet_solution/SecurityMechanisms/RevocationMechanisms';
import { definitions as validityPolicy } from './wallet_solution/SecurityMechanisms/ValidityPolicy';
import { definitions as engagement } from './wallet_solution/Interaction/Engagement';
import { definitions as protocolFlow } from './wallet_solution/Interaction/ProtocolFlow';
import { definitions as identifyingData } from './wallet_solution/DataModel/IdentifyingData';
import { definitions as credentialMetadata } from './wallet_solution/DataModel/CredentialMetadata';
import { definitions as ucPresentation } from './wallet_solution/UseCases/Presentation';
import { attestationVariants } from './attestation_provider/variants';

/** The 121 baseline test definitions, in the order of the baseline lists. */
export const baselineDefinitions: TestCaseDefinition[] = [
  ...mainInteraction,
  ...validity,
  ...wsRevocation,
  ...ppRevocation,
  ...trustMechanisms,
  ...sessionEncryption,
];

/**
 * Every test definition, the source of truth for the FCAF test cases (harness design section 4.2): the baseline, then
 * the test cases of the remaining catalogue areas (Phase 5). A definition whose steps all have an action is executable;
 * the others are text only until a later phase implements them.
 */
export const definitions: TestCaseDefinition[] = [
  ...baselineDefinitions,
  ...sessionBinding,
  ...deviceBinding,
  ...issuerIntegrity,
  ...infTrustMechanisms,
  ...protocolMessages,
  ...metadata,
  ...credentialFormats,
  ...rpIntegrity,
  ...encoding,
  ...supportive,
  ...revocationPolicy,
  ...revocationMechanisms,
  ...validityPolicy,
  ...engagement,
  ...protocolFlow,
  ...furtherMainInteraction,
  ...identifyingData,
  ...credentialMetadata,
  ...ucPresentation,
];

/**
 * The `RP_AP` test definitions: the category variants `Q`, `PB` and `E` of the `RP_PP` ones (catalogue section 2.1),
 * after every other definition so the order of the earlier ones stays as it was.
 */
export const attestationProviderDefinitions: TestCaseDefinition[] = attestationVariants(definitions);
definitions.push(...attestationProviderDefinitions);

/** The definitions the harness can execute. */
export const executableDefinitions = definitions.filter(isExecutable);

/** The test book items (class `RP_TB`): inspections, reported as REVIEW with their method in every run. */
export { testBook } from './test_book/TestBook';
