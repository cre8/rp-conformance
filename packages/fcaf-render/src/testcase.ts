import { parseTestCaseId, type TestCaseDefinition } from '@eudi-pcaf/core';

export const CLASS_DIR: Record<string, string> = { WS: 'wallet_solution', PP: 'pid_provider', AP: 'attestation_provider', Inf: 'infrastructure' };
export const CLASS_TITLE: Record<string, string> = {
  WS: 'Relying Party - Wallet Solution',
  PP: 'Relying Party - PID Provider',
  AP: 'Relying Party - Attestation Provider',
  Inf: 'Relying Party - Trust Infrastructure',
};
export const LAYER_DIR: Record<string, string> = { IA: 'Interaction', SM: 'SecurityMechanisms', MS: 'MessageStructure', DM: 'DataModel', UC: 'UseCases', SH: 'Shared' };
export const LAYER_TITLE: Record<string, string> = { IA: 'Interaction', SM: 'Security Mechanisms', MS: 'Message Structure', DM: 'Data Model', UC: 'Use Cases', SH: 'Shared' };
export const AREA_TITLE: Record<string, string> = {
  MainInteraction: 'Main Interaction',
  Validity: 'Validity',
  Revocation: 'Revocation',
  TrustMechanisms: 'Trust Mechanisms',
  SessionEncryption: 'Session Encryption',
  SessionBinding: 'Session Binding',
  DeviceBinding: 'Device Binding',
  IssuerIntegrity: 'Issuer Integrity',
  ProtocolMessages: 'Protocol Messages',
  Metadata: 'Metadata',
  CredentialFormats: 'Credential Formats',
  RpIntegrity: 'Relying Party Integrity',
  Encoding: 'Encoding',
  Supportive: 'Supportive',
  Engagement: 'Engagement',
  ProtocolFlow: 'Protocol Flow',
  IdentifyingData: 'Identifying Data',
  CredentialMetadata: 'Credential Metadata',
  Presentation: 'Presentation',
};

const numbered = (items: string[]) => items.map((text, i) => `${i + 1}. ${text}`).join('\n');
const bullets = (items: string[]) => items.map((text) => `- ${text}`).join('\n');

/** The FCAF markdown of one test case. */
export function renderTestCase(definition: TestCaseDefinition): string {
  const parts = [`# ${definition.id}`, '## Objective', definition.objective, '## References', bullets(definition.references)];
  parts.push('## Profile applicability', definition.profile.length ? bullets(definition.profile.map((p) => p.text)) : 'None');
  parts.push('## EUDI-wallet relevancy', definition.relevancy);
  if (definition.technology.length) parts.push('## Technology', bullets(definition.technology));
  parts.push('## Preconditions', definition.preconditions.length ? numbered(definition.preconditions) : 'None');
  parts.push('## Test Scenario', numbered(definition.steps.map((s) => s.text)));
  parts.push('## Expected results', numbered(definition.steps.map((s) => s.expect.text)));
  if (definition.comments?.length) parts.push('## Comments', definition.comments.join('\n\n'));
  return `${parts.join('\n\n')}\n`;
}

/** Path of a test case below the Relying Party SUT directory `suts/relying_party`. */
export function testCasePathInSut(id: string): string {
  const { sutClass, layer, area } = parseTestCaseId(id);
  const classDir = CLASS_DIR[sutClass];
  const layerDir = LAYER_DIR[layer];
  if (!classDir || !layerDir) throw new Error(`${id}: no directory for class ${sutClass} or layer ${layer}`);
  return `${classDir}/${layerDir}/${area}/${id}.md`;
}

/** Path of a test case below the overlay root `docs/fcaf`. */
export function testCasePath(id: string): string {
  return `suts/relying_party/${testCasePathInSut(id)}`;
}
