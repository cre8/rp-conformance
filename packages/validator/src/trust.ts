import type { CredentialCategory } from '@rp-conformance/core';
import { verifyCompact } from '@owf/eudi-jades';
import { LoTEProfile, validateLoTEProfile } from '@owf/eudi-lote';
import {
  getPointerSigningCertificates,
  loadTrustedList,
  type ProfileRule,
  type TrustedList,
  TrustedListProfiles,
  validateTrustedListProfile,
} from '@owf/eudi-tl';
import { type Certificate, parseCertificate } from '@owf/x509';
import { base64url, verifyEs256 } from '@rp-conformance/forge';
import { validatePath } from './x509-path';

export interface TrustedService {
  type: string;
  /** The service status, where the list carries one (ETSI TS 119 612; Pub-EAA Providers lists of TS 119 602). */
  status?: string;
  anchors: Certificate[];
}

export interface TrustedEntity {
  name: string;
  services: TrustedService[];
}

export interface LoadedList {
  id: string;
  /** A LoTE (ETSI TS 119 602), a Trusted List reached through the LOTL (ETSI TS 119 612), or a rulebook's anchors. */
  kind: 'lote' | 'trusted-list' | 'rulebook';
  /** `LoTEType` or `TSLType`. */
  type: string;
  sequenceNumber: number;
  nextUpdate: Date;
  entities: TrustedEntity[];
}

/** How a Relying Party is configured for one list: where it is and which scheme operator certificate seals it. */
export interface ListSource {
  id: string;
  url: string;
  loteType: string;
  schemeOperatorCertificatePem: string;
}

/**
 * The list of trusted lists in ETSI TS 119 612 format: where it is and the certificates that may sign it. The Trusted
 * Lists it points to and their signing certificates come from the LOTL itself.
 */
export interface ListOfTrustedListsSource {
  url: string;
  signingCertificatesPem: string[];
}

/** A rulebook that defines its own anchors, for the credential it governs (`default_credential_eaa`). */
export interface RulebookSource {
  credential: string;
  anchorsPem: string[];
}

/** Every root of trust of `default_trust_configuration_rp` a Relying Party is configured with. */
export interface TrustSources {
  lotes: ListSource[];
  listOfTrustedLists?: ListOfTrustedListsSource;
  rulebooks?: RulebookSource[];
}

const PROFILE_BY_TYPE: Record<string, LoTEProfile> = {
  'http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList': LoTEProfile.EUPIDProvidersList,
  'http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList': LoTEProfile.EUPubEAAProvidersList,
  'http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList': LoTEProfile.EUWalletProvidersList,
  'http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList': LoTEProfile.EUWRPACProvidersList,
  'http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList': LoTEProfile.EUWRPRCProvidersList,
};

export class TrustListError extends Error {}

/**
 * Verifies a sealed LoTE as a Relying Party must: the JAdES signature with the configured scheme operator certificate
 * (any `x5c` must be that certificate), the profile of its `LoTEType` (ETSI TS 119 602, strict), and `NextUpdate`.
 */
export async function verifyLote(jws: string, source: ListSource, now = new Date()): Promise<LoadedList> {
  const operator = parseCertificate(source.schemeOperatorCertificatePem);
  const header = base64url.decodeJson<{ x5c?: string[] }>(jws.split('.')[0] ?? '');
  if (header.x5c && Buffer.from(header.x5c[0] ?? '', 'base64').compare(Buffer.from(operator.der)) !== 0) {
    throw new TrustListError(`${source.id}: sealed by a certificate other than the scheme operator certificate`);
  }
  const jwk = operator.publicKey.jwk;
  if (!jwk) throw new TrustListError(`${source.id}: scheme operator key is not supported`);
  const result = await verifyCompact(jws, (data, signature) => verifyEs256(jwk, data, base64url.decode(signature)));
  if (!result.valid) throw new TrustListError(`${source.id}: seal does not verify`);
  const profile = PROFILE_BY_TYPE[source.loteType];
  if (!profile) throw new TrustListError(`${source.id}: unsupported LoTEType ${source.loteType}`);
  const validation = validateLoTEProfile(result.payload, profile);
  if (!validation.valid) {
    throw new TrustListError(`${source.id}: not a valid ${profile}: ${validation.issues.map((i) => i.message).join('; ')}`);
  }
  const lote = (result.payload as { LoTE: Record<string, any> }).LoTE;
  const info = lote.ListAndSchemeInformation;
  const nextUpdate = new Date(info.NextUpdate);
  if (nextUpdate < now) throw new TrustListError(`${source.id}: NextUpdate ${info.NextUpdate} has passed`);
  const entities: TrustedEntity[] = (lote.TrustedEntitiesList ?? []).map((entity: any) => ({
    name: entity.TrustedEntityInformation.TEName[0].value,
    services: entity.TrustedEntityServices.map((svc: any) => ({
      type: svc.ServiceInformation.ServiceTypeIdentifier,
      ...(svc.ServiceInformation.ServiceStatus ? { status: svc.ServiceInformation.ServiceStatus } : {}),
      anchors: (svc.ServiceInformation.ServiceDigitalIdentity?.X509Certificates ?? []).map((c: { val: string }) => parseCertificate(c.val)),
    })),
  }));
  return { id: source.id, kind: 'lote', type: info.LoTEType, sequenceNumber: info.LoTESequenceNumber, nextUpdate, entities };
}

/** URIs of ETSI TS 119 612 V2.4.1 the Relying Party evaluates (clauses 5.3.3, 5.5.1, 5.5.4). */
export const TS119612 = {
  euGeneric: 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric',
  /** Issuance of qualified electronic attestations of attributes by a QTSP (clause 5.5.1.1 k). */
  qeaaIssuance: 'http://uri.etsi.org/TrstSvc/Svctype/EAA/Q',
  granted: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
};

/** The service types a Member State list reached through the LOTL may carry: the qualified ones and those for EAAs. */
const MEMBER_STATE_LIST: ProfileRule = {
  name: 'eu-generic with attestation services',
  tslType: TS119612.euGeneric,
  serviceTypes: [
    ...TrustedListProfiles.euGeneric.serviceTypes,
    TS119612.qeaaIssuance,
    'http://uri.etsi.org/TrstSvc/Svctype/EAA',
    'http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA',
    'http://uri.etsi.org/TrstSvc/Svctype/EAAValidation',
  ],
  serviceStatuses: TrustedListProfiles.euGeneric.serviceStatuses,
};

const der = (pem: string) => parseCertificate(pem).der;
const issuesOf = (result: { issues: { path: (string | number)[]; message: string }[] }) =>
  result.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');

/** `NextUpdate` of a Trusted List; a closed list (no date) or one whose date has passed is not used (clause 5.3.15). */
function nextUpdateOf(list: TrustedList, id: string, now: Date): Date {
  if (!list.nextUpdate) throw new TrustListError(`${id}: NextUpdate is null, the list is closed`);
  const nextUpdate = new Date(list.nextUpdate);
  if (Number.isNaN(nextUpdate.getTime())) throw new TrustListError(`${id}: NextUpdate ${list.nextUpdate} is not a date`);
  if (nextUpdate < now) throw new TrustListError(`${id}: NextUpdate ${list.nextUpdate} has passed`);
  return nextUpdate;
}

/** A Trusted List's providers as trusted entities: every service with its type, status and certificates. */
function entitiesOf(list: TrustedList): TrustedEntity[] {
  return list.providers.map((provider, i) => ({
    name: provider.name ?? `provider ${i + 1}`,
    services: provider.services.map((service) => ({
      type: service.serviceTypeIdentifier,
      status: service.serviceStatus,
      anchors: service.digitalIdentities.flatMap((identity) => (identity.certificate ? [parseCertificate(identity.certificate)] : [])),
    })),
  }));
}

/**
 * The root of trust of a credential category (`default_trust_configuration_rp`): the lists whose services may sign the
 * credential, and the anchors its status list or identifier list must be signed under.
 */
export interface TrustRule {
  /** For evidence, for example `TL-PID /PID/Issuance`. */
  name: string;
  lists: (list: LoadedList) => boolean;
  issuance: (service: TrustedService) => boolean;
  /** The anchors of a status list or identifier list of a credential that matched `service` of `entity`. */
  statusAnchors: (entity: TrustedEntity, service: TrustedService) => Certificate[];
}

const LOTE_SERVICE = (category: string, role: 'Issuance' | 'Revocation') => `http://uri.etsi.org/19602/SvcType/${category}/${role}`;
const PUB_EAA_WITHDRAWN = 'http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn';

/** The rule of a LoTE category: issuance and revocation services of the same entity in the same list. */
const loteRule = (list: string, category: string): TrustRule => ({
  name: `${list} ${category}/Issuance`,
  lists: (l) => l.kind === 'lote' && l.id === list,
  issuance: (service) => service.type === LOTE_SERVICE(category, 'Issuance') && service.status !== PUB_EAA_WITHDRAWN,
  statusAnchors: (entity) =>
    entity.services.filter((s) => s.type === LOTE_SERVICE(category, 'Revocation') && s.status !== PUB_EAA_WITHDRAWN).flatMap((s) => s.anchors),
});

/**
 * The trust rule of each credential category of `default_trust_configuration_rp`:
 * - PID: a PID/Issuance service of `TL-PID`; status lists under the PID/Revocation service of the same entity;
 * - QEAA: a granted service of type `EAA/Q` in a Member State list reached through the LOTL; status lists under the
 *   same anchor, since ETSI TS 119 612 defines no service type for the status of attestations;
 * - PuB-EAA: a PubEAA/Issuance service of `TL-PUB` that is not withdrawn; status lists under its PubEAA/Revocation
 *   service;
 * - non-qualified EAA: the anchor its rulebook defines, for the credential and its status lists.
 */
export const TRUST_RULES: Record<CredentialCategory, TrustRule> = {
  pid: loteRule('TL-PID', 'PID'),
  'pub-eaa': loteRule('TL-PUB', 'PubEAA'),
  qeaa: {
    name: 'TL-QEAA granted EAA/Q',
    lists: (l) => l.kind === 'trusted-list',
    issuance: (service) => service.type === TS119612.qeaaIssuance && service.status === TS119612.granted,
    statusAnchors: (_entity, service) => service.anchors,
  },
  eaa: {
    name: 'rulebook of default_credential_eaa',
    lists: (l) => l.kind === 'rulebook' && l.id === 'default_credential_eaa',
    issuance: () => true,
    statusAnchors: (_entity, service) => service.anchors,
  },
};

/** The issuer a credential matched: its entity and the anchors its status lists and identifier lists are signed under. */
export interface MatchedIssuer {
  name: string;
  statusAnchors: Certificate[];
}

export type TrustMatch =
  | { ok: true; list: LoadedList; entity: TrustedEntity; service: TrustedService; anchor: Certificate; leaf: Certificate }
  | { ok: false; reason: string };

/** The trust configuration of a Relying Party, derived from the lists of `default_trust_configuration_rp`. */
export class TrustStore {
  readonly lists = new Map<string, LoadedList>();
  /** Every retrieval, for evidence. */
  readonly retrievals: { id: string; url: string; at: string; status: number }[] = [];
  private readonly sources: TrustSources;

  constructor(
    sources: TrustSources | ListSource[],
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    this.sources = Array.isArray(sources) ? { lotes: sources } : sources;
  }

  private async fetchText(id: string, url: string): Promise<string> {
    const response = await this.fetchImpl(url);
    this.retrievals.push({ id, url, at: new Date().toISOString(), status: response.status });
    if (!response.ok) throw new TrustListError(`${id}: HTTP ${response.status}`);
    return (await response.text()).trim();
  }

  /**
   * Fetches and verifies every configured list: the LoTEs, the LOTL and the Trusted Lists it points to, and loads the
   * rulebook anchors. A list that fails is left out, so nothing it lists is trusted.
   */
  async refresh(now = new Date()): Promise<{ id: string; error?: string }[]> {
    const results: { id: string; error?: string }[] = [];
    for (const source of this.sources.lotes) {
      try {
        this.lists.set(source.id, await verifyLote(await this.fetchText(source.id, source.url), source, now));
        results.push({ id: source.id });
      } catch (error) {
        this.lists.delete(source.id);
        results.push({ id: source.id, error: (error as Error).message });
      }
    }
    if (this.sources.listOfTrustedLists) results.push(...(await this.refreshTrustedLists(this.sources.listOfTrustedLists, now)));
    for (const rulebook of this.sources.rulebooks ?? []) {
      const anchors = rulebook.anchorsPem.map((pem) => parseCertificate(pem));
      this.lists.set(rulebook.credential, {
        id: rulebook.credential,
        kind: 'rulebook',
        type: 'rulebook',
        sequenceNumber: 1,
        nextUpdate: new Date(8.64e15),
        entities: [{ name: `rulebook of ${rulebook.credential}`, services: [{ type: 'rulebook', anchors }] }],
      });
      results.push({ id: rulebook.credential });
    }
    return results;
  }

  /**
   * ETSI TS 119 612 Annex A: the LOTL is verified with the configured signing certificates (its XAdES signature, its
   * profile and `NextUpdate`); each Member State list it points to is verified with the certificates of its pointer, and
   * must have the `TSLType` and scheme territory the pointer announces.
   */
  private async refreshTrustedLists(source: ListOfTrustedListsSource, now: Date): Promise<{ id: string; error?: string }[]> {
    for (const [id, list] of this.lists) if (list.kind === 'trusted-list') this.lists.delete(id);
    let lotl: TrustedList;
    try {
      const xml = await this.fetchText('LOTL', source.url);
      lotl = await loadTrustedList(xml, { trustAnchors: source.signingCertificatesPem.map(der) });
      const profile = validateTrustedListProfile(lotl, TrustedListProfiles.euLotl);
      if (!profile.valid) throw new TrustListError(`LOTL: not a list of trusted lists: ${issuesOf(profile)}`);
      nextUpdateOf(lotl, 'LOTL', now);
    } catch (error) {
      return [{ id: 'LOTL', error: (error as Error).message }];
    }
    const results: { id: string; error?: string }[] = [{ id: 'LOTL' }];
    const pointers = (lotl.pointersToOtherLists ?? []).filter((p) => p.tslType?.replace(/^https?:\/\//, '') === TS119612.euGeneric.replace(/^https?:\/\//, ''));
    for (const pointer of pointers) {
      const id = `TL ${pointer.schemeTerritory ?? pointer.location}`;
      try {
        const xml = await this.fetchText(id, pointer.location);
        const list = await loadTrustedList(xml, { trustAnchors: getPointerSigningCertificates(lotl, { location: pointer.location }) });
        const profile = validateTrustedListProfile(list, MEMBER_STATE_LIST);
        if (!profile.valid) throw new TrustListError(`${id}: ${issuesOf(profile)}`);
        if (pointer.schemeTerritory && list.schemeTerritory !== pointer.schemeTerritory) {
          throw new TrustListError(`${id}: scheme territory ${list.schemeTerritory} differs from the LOTL pointer`);
        }
        this.lists.set(id, {
          id,
          kind: 'trusted-list',
          type: list.tslType ?? '',
          sequenceNumber: list.sequenceNumber ?? 0,
          nextUpdate: nextUpdateOf(list, id, now),
          entities: entitiesOf(list),
        });
        results.push({ id });
      } catch (error) {
        results.push({ id, error: (error as Error).message });
      }
    }
    if (pointers.length === 0) results.push({ id: 'LOTL', error: 'LOTL: no pointer to a Member State list' });
    return results;
  }

  /** Finds the service of a list of `rule` that may sign the credential and has an anchor the `x5c` chain validates to. */
  async match(rule: TrustRule, x5c: string[], now = new Date()): Promise<TrustMatch> {
    const lists = [...this.lists.values()].filter(rule.lists);
    if (lists.length === 0) return { ok: false, reason: `no list of ${rule.name} is available` };
    const reasons: string[] = [];
    for (const list of lists) {
      for (const entity of list.entities) {
        for (const service of entity.services.filter(rule.issuance)) {
          if (service.anchors.length === 0) continue;
          const path = await validatePath(x5c, service.anchors, now);
          if (path.ok) return { ok: true, list, entity, service, anchor: path.anchor, leaf: path.leaf };
          reasons.push(`${entity.name}: ${path.reason}`);
        }
      }
    }
    return { ok: false, reason: `no anchor of ${rule.name} validates the chain (${reasons.join('; ') || 'no candidates'})` };
  }
}
