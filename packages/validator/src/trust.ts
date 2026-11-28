import type { CredentialCategory, TrustListCheck } from '@eudi-pcaf/core';
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
import { base64url, verifyEs256 } from '@eudi-pcaf/forge';
import { CheckRecorder, type ValidationMode, type ValidationResult } from './checks';
import { fail } from './status-list';
import { validatePath } from './x509-path';

export interface TrustedService {
  type: string;
  /** The service status, where the list carries one (ETSI TS 119 612; Pub-EAA Providers lists of TS 119 602). */
  status?: string;
  /** The first ServiceName of a LoTE service: in `TL-WP` the Wallet Solution's `wallet_name` or the WSCD type (TS3 section 3.2). */
  name?: string;
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

export class TrustListError extends Error {
  /** The trust-list check the list failed, when it failed one. */
  constructor(
    message: string,
    readonly check?: TrustListCheck,
  ) {
    super(message);
  }
}

/** The outcome of loading one list: an error and the check it failed, when it was not loaded. */
export interface RefreshResult {
  id: string;
  error?: string;
  failed?: TrustListCheck;
}

const refused = (id: string, error: unknown): RefreshResult => ({
  id,
  error: (error as Error).message,
  ...(error instanceof TrustListError && error.check ? { failed: error.check } : {}),
});

export interface ListCheckOptions {
  now?: Date;
  /** The grace period `G` after `NextUpdate` (ICS RP.T.2), milliseconds; default 0. */
  graceMs?: number;
  /** The version of the list in use, whose sequence number a new version must not undercut. */
  current?: LoadedList;
  mode?: ValidationMode;
}

/** The checks of a new version of a trust list, and the list when it passed them. */
export interface ListValidation extends ValidationResult {
  list?: LoadedList;
}

/** The first failure of a list validation as an error, for callers that only need the list. */
const listOrThrow = (id: string, validation: ListValidation): LoadedList => {
  if (validation.list) return validation.list;
  const failed = validation.checks.find((c) => c.status === 'fail');
  throw new TrustListError(failed?.detail?.startsWith(`${id}:`) ? failed.detail : `${id}: ${failed?.detail ?? 'not usable'}`, failed?.check as TrustListCheck);
};

/** `NextUpdate` within the grace period: passes, and reports a list whose `NextUpdate` has passed as stale. */
function checkFreshness(id: string, nextUpdate: Date, now: Date, graceMs: number): string | undefined {
  if (Number.isNaN(nextUpdate.getTime())) fail(`${id}: NextUpdate is not a date`);
  if (now.getTime() > nextUpdate.getTime() + graceMs) fail(`${id}: NextUpdate ${nextUpdate.toISOString()} has passed${graceMs ? ' and the grace period with it' : ''}`);
  if (nextUpdate < now) return `${id}: NextUpdate ${nextUpdate.toISOString()} has passed; stale within the grace period`;
  return undefined;
}

/**
 * Checks a new version of a sealed LoTE as a Relying Party must before using it (`TRUST_LIST_CHECKS`): it is sealed by
 * the configured scheme operator certificate (any `x5c` must be that certificate), the JAdES seal verifies with it, its
 * `LoTEType` is the configured one and it passes the profile of that type (ETSI TS 119 602, strict), its `NextUpdate`
 * has not passed by more than the grace period, and its sequence number is not lower than that of the version in use.
 */
export async function checkLote(jws: string, source: ListSource, options: ListCheckOptions = {}): Promise<ListValidation> {
  const recorder = new CheckRecorder(options.mode ?? 'first-failure');
  const now = options.now ?? new Date();
  const operator = parseCertificate(source.schemeOperatorCertificatePem);
  let payload: unknown;
  let list: LoadedList | undefined;
  const result = await recorder.collect(async () => {
    await recorder.run('trust-list-signer', [], () => {
      let header: { x5c?: string[] };
      try {
        header = base64url.decodeJson<{ x5c?: string[] }>(jws.split('.')[0] ?? '');
      } catch {
        fail(`${source.id}: the seal header cannot be decoded`);
      }
      if (header!.x5c && Buffer.from(header!.x5c[0] ?? '', 'base64').compare(Buffer.from(operator.der)) !== 0) {
        fail(`${source.id}: sealed by a certificate other than the scheme operator certificate`);
      }
    });
    await recorder.run('trust-list-signature', ['trust-list-signer'], async () => {
      const jwk = operator.publicKey.jwk;
      if (!jwk) fail(`${source.id}: scheme operator key is not supported`);
      const verified = await verifyCompact(jws, (data, signature) => verifyEs256(jwk as JsonWebKey, data, base64url.decode(signature)));
      if (!verified.valid) fail(`${source.id}: seal does not verify`);
      payload = verified.payload;
    });
    await recorder.run('trust-list-type', ['trust-list-signature'], () => {
      const profile = PROFILE_BY_TYPE[source.loteType];
      if (!profile) fail(`${source.id}: unsupported LoTEType ${source.loteType}`);
      const type = (payload as { LoTE?: { ListAndSchemeInformation?: { LoTEType?: string } } }).LoTE?.ListAndSchemeInformation?.LoTEType;
      if (type !== source.loteType) fail(`${source.id}: LoTEType ${String(type)} is not the configured ${source.loteType}`);
      const validation = validateLoTEProfile(payload, profile);
      if (!validation.valid) fail(`${source.id}: not a valid ${profile}: ${validation.issues.map((i) => i.message).join('; ')}`);
    });
    const info = () => (payload as { LoTE: Record<string, any> }).LoTE.ListAndSchemeInformation;
    await recorder.run('trust-list-freshness', ['trust-list-signature'], () => checkFreshness(source.id, new Date(info().NextUpdate), now, options.graceMs ?? 0));
    await recorder.run('trust-list-sequence', ['trust-list-signature'], () => {
      const sequence = Number(info().LoTESequenceNumber);
      if (options.current && sequence < options.current.sequenceNumber) {
        fail(`${source.id}: LoTESequenceNumber ${sequence} is lower than ${options.current.sequenceNumber} of the version in use`);
      }
    });
    if (recorder.failures.length) return;
    const lote = (payload as { LoTE: Record<string, any> }).LoTE;
    list = {
      id: source.id,
      kind: 'lote',
      type: info().LoTEType,
      sequenceNumber: Number(info().LoTESequenceNumber),
      nextUpdate: new Date(info().NextUpdate),
      entities: (lote.TrustedEntitiesList ?? []).map((entity: any) => ({
        name: entity.TrustedEntityInformation.TEName[0].value,
        services: entity.TrustedEntityServices.map((svc: any) => ({
          type: svc.ServiceInformation.ServiceTypeIdentifier,
          ...(svc.ServiceInformation.ServiceStatus ? { status: svc.ServiceInformation.ServiceStatus } : {}),
          ...(svc.ServiceInformation.ServiceName?.[0]?.value ? { name: svc.ServiceInformation.ServiceName[0].value } : {}),
          anchors: (svc.ServiceInformation.ServiceDigitalIdentity?.X509Certificates ?? []).map((c: { val: string }) => parseCertificate(c.val)),
        })),
      })),
    };
  });
  return { ...result, ...(list ? { list } : {}) };
}

/**
 * Verifies a sealed LoTE as a Relying Party must (`checkLote`) and returns it; throws on the first check it fails.
 */
export async function verifyLote(jws: string, source: ListSource, now = new Date()): Promise<LoadedList> {
  return listOrThrow(source.id, await checkLote(jws, source, { now }));
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

/** The certificate in the `KeyInfo` of a list's XML signature, base64 DER. */
const signingCertificateOf = (xml: string) => {
  const signature = xml.search(/<(?:\w+:)?Signature[\s>]/);
  if (signature < 0) return undefined;
  return /<(?:\w+:)?X509Certificate>([^<]+)</.exec(xml.slice(signature))?.[1]?.replace(/\s+/g, '');
};

/** Where a Member State list is checked against: the certificates of its LOTL pointer and the territory it announces. */
export interface TrustedListPointerSource {
  id: string;
  /** DER of the certificates the LOTL pointer names. */
  anchors: Uint8Array[];
  schemeTerritory?: string;
}

/**
 * Checks a new version of a Member State Trusted List (ETSI TS 119 612) reached through the LOTL (`TRUST_LIST_CHECKS`):
 * it is signed by a certificate the LOTL pointer names, its XAdES signature verifies, its type, profile and territory
 * are those of the pointer, its `NextUpdate` has not passed by more than the grace period, and its sequence number is not
 * lower than that of the version in use.
 */
export async function checkTrustedList(xml: string, pointer: TrustedListPointerSource, options: ListCheckOptions = {}): Promise<ListValidation> {
  const recorder = new CheckRecorder(options.mode ?? 'first-failure');
  const now = options.now ?? new Date();
  const { id } = pointer;
  let tl: TrustedList | undefined;
  let list: LoadedList | undefined;
  const result = await recorder.collect(async () => {
    await recorder.run('trust-list-signer', [], () => {
      const certificate = signingCertificateOf(xml);
      if (!certificate) fail(`${id}: the signature carries no signing certificate`);
      const signer = Buffer.from(certificate as string, 'base64');
      if (!pointer.anchors.some((anchor) => signer.equals(Buffer.from(anchor)))) fail(`${id}: signed by a certificate the LOTL pointer does not name`);
    });
    await recorder.run('trust-list-signature', ['trust-list-signer'], async () => {
      try {
        tl = await loadTrustedList(xml, { trustAnchors: pointer.anchors });
      } catch (error) {
        fail(`${id}: ${(error as Error).message}`);
      }
    });
    await recorder.run('trust-list-type', ['trust-list-signature'], () => {
      const profile = validateTrustedListProfile(tl as TrustedList, MEMBER_STATE_LIST);
      if (!profile.valid) fail(`${id}: ${issuesOf(profile)}`);
      if (pointer.schemeTerritory && tl?.schemeTerritory !== pointer.schemeTerritory) {
        fail(`${id}: scheme territory ${tl?.schemeTerritory} differs from the LOTL pointer`);
      }
    });
    await recorder.run('trust-list-freshness', ['trust-list-signature'], () => {
      if (!tl?.nextUpdate) fail(`${id}: NextUpdate is null, the list is closed`);
      return checkFreshness(id, new Date(tl?.nextUpdate as string), now, options.graceMs ?? 0);
    });
    await recorder.run('trust-list-sequence', ['trust-list-signature'], () => {
      const sequence = tl?.sequenceNumber ?? 0;
      if (options.current && sequence < options.current.sequenceNumber) {
        fail(`${id}: TSLSequenceNumber ${sequence} is lower than ${options.current.sequenceNumber} of the version in use`);
      }
    });
    if (recorder.failures.length || !tl) return;
    list = { id, kind: 'trusted-list', type: tl.tslType ?? '', sequenceNumber: tl.sequenceNumber ?? 0, nextUpdate: new Date(tl.nextUpdate as string), entities: entitiesOf(tl) };
  });
  return { ...result, ...(list ? { list } : {}) };
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
  | {
      ok: true;
      list: LoadedList;
      entity: TrustedEntity;
      service: TrustedService;
      anchor: Certificate;
      leaf: Certificate;
      /** The list's `NextUpdate` has passed and it is used within the grace period: the result signals `trust-list-stale`. */
      stale: boolean;
    }
  | { ok: false; reason: string };

/** The trust configuration of a Relying Party, derived from the lists of `default_trust_configuration_rp`. */
export class TrustStore {
  readonly lists = new Map<string, LoadedList>();
  /** Every retrieval, for evidence. */
  readonly retrievals: { id: string; url: string; at: string; status: number }[] = [];
  private readonly sources: TrustSources;

  /** The grace period `G` after a list's `NextUpdate` (ICS RP.T.2), milliseconds. */
  readonly graceMs: number;

  constructor(
    sources: TrustSources | ListSource[],
    private readonly fetchImpl: typeof fetch = fetch,
    options: { graceMs?: number } = {},
  ) {
    this.sources = Array.isArray(sources) ? { lotes: sources } : sources;
    this.graceMs = options.graceMs ?? 0;
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
  async refresh(now = new Date()): Promise<RefreshResult[]> {
    const results: RefreshResult[] = [];
    for (const source of this.sources.lotes) {
      const current = this.lists.get(source.id);
      try {
        const validation = await checkLote(await this.fetchText(source.id, source.url), source, { now, graceMs: this.graceMs, current });
        this.lists.set(source.id, listOrThrow(source.id, validation));
        results.push({ id: source.id });
      } catch (error) {
        // The last valid version stays in use until its NextUpdate plus the grace period (RP_Inf_SM_TrustMechanisms_002).
        if (current && !this.usable(current, now)) this.lists.delete(source.id);
        results.push(refused(source.id, error));
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
   * profile and `NextUpdate`); each Member State list it points to is checked with the certificates of its pointer
   * (`checkTrustedList`). A list that fails keeps its last valid version in use until that one's `NextUpdate` plus the
   * grace period.
   */
  private async refreshTrustedLists(source: ListOfTrustedListsSource, now: Date): Promise<RefreshResult[]> {
    let lotl: TrustedList;
    try {
      const xml = await this.fetchText('LOTL', source.url);
      lotl = await loadTrustedList(xml, { trustAnchors: source.signingCertificatesPem.map(der) });
      const profile = validateTrustedListProfile(lotl, TrustedListProfiles.euLotl);
      if (!profile.valid) throw new TrustListError(`LOTL: not a list of trusted lists: ${issuesOf(profile)}`);
      checkFreshness('LOTL', new Date(lotl.nextUpdate ?? 'closed'), now, this.graceMs);
    } catch (error) {
      for (const [id, list] of this.lists) if (list.kind === 'trusted-list' && !this.usable(list, now)) this.lists.delete(id);
      return [{ id: 'LOTL', error: (error as Error).message }];
    }
    const results: RefreshResult[] = [{ id: 'LOTL' }];
    const pointers = (lotl.pointersToOtherLists ?? []).filter((p) => p.tslType?.replace(/^https?:\/\//, '') === TS119612.euGeneric.replace(/^https?:\/\//, ''));
    const ids = new Set<string>();
    for (const pointer of pointers) {
      const id = `TL ${pointer.schemeTerritory ?? pointer.location}`;
      ids.add(id);
      const current = this.lists.get(id);
      try {
        const xml = await this.fetchText(id, pointer.location);
        const validation = await checkTrustedList(xml, { id, anchors: getPointerSigningCertificates(lotl, { location: pointer.location }), schemeTerritory: pointer.schemeTerritory }, { now, graceMs: this.graceMs, current });
        this.lists.set(id, listOrThrow(id, validation));
        results.push({ id });
      } catch (error) {
        if (current && !this.usable(current, now)) this.lists.delete(id);
        results.push(refused(id, error));
      }
    }
    for (const [id, list] of this.lists) if (list.kind === 'trusted-list' && !ids.has(id)) this.lists.delete(id);
    if (pointers.length === 0) results.push({ id: 'LOTL', error: 'LOTL: no pointer to a Member State list' });
    return results;
  }

  /** A list may be used until its `NextUpdate` plus the grace period. */
  private usable(list: LoadedList, now: Date): boolean {
    return now.getTime() <= list.nextUpdate.getTime() + this.graceMs;
  }

  /** Finds the service of a list of `rule` that may sign the credential and has an anchor the `x5c` chain validates to. */
  async match(rule: TrustRule, x5c: string[], now = new Date()): Promise<TrustMatch> {
    const lists = [...this.lists.values()].filter(rule.lists).filter((list) => this.usable(list, now));
    if (lists.length === 0) return { ok: false, reason: `no list of ${rule.name} is available` };
    const reasons: string[] = [];
    for (const list of lists) {
      for (const entity of list.entities) {
        for (const service of entity.services.filter(rule.issuance)) {
          if (service.anchors.length === 0) continue;
          const path = await validatePath(x5c, service.anchors, now);
          if (path.ok) return { ok: true, list, entity, service, anchor: path.anchor, leaf: path.leaf, stale: list.nextUpdate < now };
          reasons.push(`${entity.name}: ${path.reason}`);
        }
      }
    }
    return { ok: false, reason: `no anchor of ${rule.name} validates the chain (${reasons.join('; ') || 'no candidates'})` };
  }
}
