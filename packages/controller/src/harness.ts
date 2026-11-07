import type { Ics, PublishedTrustList, TestEnvironment } from '@rp-conformance/core';
import {
  buildSealedLote,
  DEFAULT_QUERIES,
  issueRegistrationCertificate,
  LIST_PROFILES,
  type LoteListId,
  type TestPki,
  createTestPki,
} from '@rp-conformance/forge';
import { StatusProvider } from '@rp-conformance/status-provider';
import { TrustInfrastructure } from '@rp-conformance/trust-infrastructure';

const LISTS: LoteListId[] = ['TL-PID', 'TL-PUB', 'TL-WP', 'TL-AC', 'TL-RC'];

export interface HarnessOptions {
  runId: string;
  /** Host name under which the Relying Party reaches the harness services. */
  harnessHost: string;
  /** Interface the harness services bind to. */
  bindHost?: string;
  statusPort?: number;
  trustPort?: number;
  /** Trust namespace of the run (harness design section 6). */
  namespace: string;
  ics: Ics;
}

export interface Harness {
  pki: TestPki;
  status: StatusProvider;
  trust: TrustInfrastructure;
  env: TestEnvironment;
  namespace: string;
  stop(): Promise<void>;
}

/**
 * Starts the harness services of a run: the test PKI of `default_trust_configuration_rp`, the Test Status Provider,
 * and the Test Trust Infrastructure with every LoTE published in the run's namespace.
 */
export async function startHarness(options: HarnessOptions): Promise<Harness> {
  const pki = await createTestPki();
  const bind = options.bindHost ?? '0.0.0.0';
  const status = await new StatusProvider().start({ host: bind, port: options.statusPort ?? 0, publicHost: options.harnessHost });
  const trust = await new TrustInfrastructure().start({ host: bind, port: options.trustPort ?? 0, publicHost: options.harnessHost });

  const trustLists: PublishedTrustList[] = [];
  for (const list of LISTS) {
    const url = trust.urlOf(options.namespace, list);
    const { jws } = await buildSealedLote({ list, pki, distributionPoint: url });
    trust.publish(options.namespace, list, jws);
    trustLists.push({
      id: list,
      loteType: LIST_PROFILES[list].loteType,
      url,
      schemeOperatorCertificatePem: pki.schemeOperators[list].certificate.pem,
    });
  }
  const access = pki.relyingPartyAccess;
  const env: TestEnvironment = {
    runId: options.runId,
    trustLists,
    accessCertificate: {
      certificatePem: access.certificate.pem,
      certificate: Buffer.from(access.certificate.der).toString('base64'),
      chainPem: access.chain.map((c) => c.pem),
      privateJwk: access.key.privateJwk,
      privateKeyPem: access.key.privateKeyPem,
    },
    registrationCertificate: await issueRegistrationCertificate(pki, Object.values(DEFAULT_QUERIES)),
    queries: DEFAULT_QUERIES,
    ics: options.ics,
  };
  return {
    pki,
    status,
    trust,
    env,
    namespace: options.namespace,
    async stop() {
      await status.stop();
      await trust.stop();
    },
  };
}
