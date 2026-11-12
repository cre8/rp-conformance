import type { Ics, PublishedTrustList, TestEnvironment } from '@rp-conformance/core';
import {
  buildSealedLote,
  buildTrustedLists,
  TRUSTED_LIST_MEDIA_TYPE,
  type TrustedListId,
  createTestPki,
  defaultEntitiesOf,
  defaultQueries,
  issueRegistrationCertificate,
  LIST_PROFILES,
  type LoteListId,
  type TestPki,
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
  /** Publishes a new version of a list with the given entities (default: `default_trust_configuration_rp`). */
  publishList(list: LoteListId, entities?: string[]): Promise<{ version: number; publishedAt: Date }>;
  stop(): Promise<void>;
}

/** Where the lists in ETSI TS 119 612 format are published: paths ending in `.xml` (clause 6.1). */
const TRUSTED_LIST_PATHS: Record<TrustedListId, string> = { LOTL: 'LOTL.xml', 'TL-QEAA': 'TL-QEAA.xml' };

/**
 * Starts the harness services of a run: the test PKI of `default_trust_configuration_rp`, the Test Status Provider,
 * and the Test Trust Infrastructure with every LoTE, the test LOTL and `TL-QEAA` published in the run's namespace.
 */
export async function startHarness(options: HarnessOptions): Promise<Harness> {
  const pki = await createTestPki();
  const bind = options.bindHost ?? '0.0.0.0';
  const status = await new StatusProvider().start({ host: bind, port: options.statusPort ?? 0, publicHost: options.harnessHost });
  const trust = await new TrustInfrastructure().start({ host: bind, port: options.trustPort ?? 0, publicHost: options.harnessHost });

  const trustLists: PublishedTrustList[] = [];
  let sequenceNumber = 1;
  const publishList = async (list: LoteListId, entities = defaultEntitiesOf(pki, list)) => {
    const url = trust.urlOf(options.namespace, list);
    const { jws } = await buildSealedLote({ list, pki, entities, distributionPoint: url, sequenceNumber: sequenceNumber++ });
    const publishedAt = new Date();
    const { version } = trust.publish(options.namespace, list, jws);
    return { version, publishedAt };
  };
  for (const list of LISTS) {
    const url = trust.urlOf(options.namespace, list);
    await publishList(list);
    trustLists.push({
      id: list,
      loteType: LIST_PROFILES[list].loteType,
      url,
      schemeOperatorCertificatePem: pki.schemeOperators[list].certificate.pem,
    });
  }
  const locations = {
    LOTL: trust.urlOf(options.namespace, TRUSTED_LIST_PATHS.LOTL),
    'TL-QEAA': trust.urlOf(options.namespace, TRUSTED_LIST_PATHS['TL-QEAA']),
  };
  const trustedLists = await buildTrustedLists({ pki, locations });
  for (const list of ['LOTL', 'TL-QEAA'] as TrustedListId[]) {
    trust.publish(options.namespace, TRUSTED_LIST_PATHS[list], trustedLists[list], TRUSTED_LIST_MEDIA_TYPE);
  }
  const access = pki.relyingPartyAccess;
  const queries = defaultQueries(pki);
  const env: TestEnvironment = {
    runId: options.runId,
    trustLists,
    listOfTrustedLists: {
      url: locations.LOTL,
      signingCertificatesPem: [pki.trustedListOperators.LOTL.certificate.pem],
      pointers: [{ id: 'TL-QEAA', url: locations['TL-QEAA'], schemeTerritory: 'DE' }],
    },
    // EP-A is on no list: the rulebook of default_credential_eaa defines CA-EP-A for its attestations and status lists.
    rulebooks: [{ credential: 'default_credential_eaa', anchorsPem: [pki.entities['EP-A'].anchors.issuance.certificate.pem] }],
    accessCertificate: {
      certificatePem: access.certificate.pem,
      certificate: Buffer.from(access.certificate.der).toString('base64'),
      chainPem: access.chain.map((c) => c.pem),
      privateJwk: access.key.privateJwk,
      privateKeyPem: access.key.privateKeyPem,
    },
    // Every default query the Relying Party uses; the restricted variants ask for the same credentials and claims.
    registrationCertificate: await issueRegistrationCertificate(
      pki,
      Object.entries(queries)
        .filter(([id]) => !id.endsWith('_trusted_authorities'))
        .map(([, query]) => query),
    ),
    queries,
    ics: options.ics,
  };
  return {
    pki,
    status,
    trust,
    env,
    namespace: options.namespace,
    publishList,
    async stop() {
      await status.stop();
      await trust.stop();
    },
  };
}
