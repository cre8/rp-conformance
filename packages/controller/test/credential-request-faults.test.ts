// Self-validation of the `credential-request` faults (issue 24, issuer harness design section 7, level 1): the valid
// credential request passes every credential request check of the reference validator, and each fault fails exactly
// its target check and no other (`null`: none). Level 2: every step of an issuer definition that names such a fault
// expects `REJ` exactly when the fault has a target.
import { CREDENTIAL_REQUEST_FAULT_IDS, CREDENTIAL_REQUEST_FAULTS, isCredentialRequestFault } from '@eudi-pcaf/core';
import { issuerDefinitions } from '@eudi-pcaf/issuer-definitions';
import { applyCredentialRequestFault, type CredentialRequestFaultContext, CredentialRequestFaultNotApplicable, credentialRequestFaultHook } from '@eudi-pcaf/issuer-wallet';
import { validateCredentialRequest } from '@eudi-pcaf/validator';
import { describe, expect, it } from 'vitest';

const context: CredentialRequestFaultContext = {
  configurationId: 'pid-sd-jwt-vc',
  configurationIds: ['pid-sd-jwt-vc', 'pid-sd-jwt-vc-2'],
  authorizedConfigurationIds: ['pid-sd-jwt-vc'],
  credentialIdentifiers: ['pid-sd-jwt-vc'],
  foreignIdentifier: 'identifier-of-another-session',
};
const valid = { credential_configuration_id: 'pid-sd-jwt-vc', proofs: { jwt: ['eyJ...'] } };
const checkContext = { configurationIds: context.configurationIds, authorizedConfigurationIds: context.authorizedConfigurationIds, credentialIdentifiers: context.credentialIdentifiers };

describe('credential-request faults', () => {
  it('the valid request passes every check', async () => {
    const result = await validateCredentialRequest(valid, checkContext);
    expect(result.failures).toEqual([]);
  });

  it.each(CREDENTIAL_REQUEST_FAULT_IDS)('%s fails exactly its target check', async (id) => {
    const faulty = applyCredentialRequestFault(id, valid, context);
    const result = await validateCredentialRequest(faulty, checkContext);
    const target = CREDENTIAL_REQUEST_FAULTS[id].target;
    expect(result.failures).toEqual(target ? [target] : []);
    expect(valid.credential_configuration_id).toBe('pid-sd-jwt-vc');
  });

  it('refuses a fault the flow cannot carry', () => {
    expect(() => applyCredentialRequestFault('credential-request.configuration-not-authorized', valid, { ...context, configurationIds: ['pid-sd-jwt-vc'] })).toThrow(
      CredentialRequestFaultNotApplicable,
    );
    expect(() => applyCredentialRequestFault('credential-request.both-identifiers', valid, { ...context, credentialIdentifiers: [] })).toThrow(CredentialRequestFaultNotApplicable);
    expect(() => applyCredentialRequestFault('credential-request.identifier-foreign', valid, { ...context, foreignIdentifier: 'pid-sd-jwt-vc' })).toThrow(
      CredentialRequestFaultNotApplicable,
    );
  });

  it('the hook changes the credential request only', async () => {
    const hook = credentialRequestFaultHook('credential-request.extra-member', () => context);
    const request = { method: 'POST', url: 'https://pp-t.rp-test/credential', headers: {}, body: JSON.stringify(valid) };
    expect(JSON.parse((await hook('credential', request)).body as string)).toEqual({ ...valid, foo: 'bar' });
    expect(await hook('token', request)).toBe(request);
  });

  it('every definition step with a credential request fault expects REJ exactly when the fault has a target', () => {
    const steps = issuerDefinitions.flatMap((d) => d.steps).filter((s) => s.run?.kind === 'issuance' && s.run.faults.some(isCredentialRequestFault));
    expect(steps.length).toBeGreaterThan(0);
    for (const step of steps) {
      const fault = (step.run as { faults: string[] }).faults.find(isCredentialRequestFault);
      const target = fault ? CREDENTIAL_REQUEST_FAULTS[fault].target : null;
      expect(step.expect.codes.some((c) => c.startsWith('REJ')), fault).toBe(target !== null);
    }
  });
});
