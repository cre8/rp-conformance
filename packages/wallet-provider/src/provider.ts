// The Test Wallet Provider (issuer harness design section 5.2): the Wallet Units `CW-1`, `CW-2` (`WP-A`) and `CW-B`
// (`WP-B`), their WIAs, PoPs and KAs, and the status lists `SL-WP-A` and `SL-WP-B`, served by the Test Status Provider.
import { randomInt } from 'node:crypto';
import { buildStatusListTokenJwt, type EcKeyPair, generateEcKeyPair, type TestEntity, type TestPki } from '@eudi-pcaf/forge';
import type { StatusProvider } from '@eudi-pcaf/status-provider';
import {
  buildKeyAttestation,
  buildWia,
  buildWiaPop,
  certifiedSigner,
  type KeyAttestationOptions,
  keySigner,
  type WiaOptions,
  type WiaPopOptions,
} from './builders';
import type { StatusReference } from './claims';
import { signerFor } from './trust';

const DAY_MS = 24 * 60 * 60 * 1000;

// Issue 26: `WP-C` (on `TL-WP` from a later version) and the withdrawn `WP-W` have a Wallet Unit each, for
// PP_Inf_SM_TrustMechanisms; they are not default units, since no default version of `TL-WP` trusts them.
export type WalletProviderId = 'WP-A' | 'WP-B' | 'WP-C' | 'WP-W';
export type DefaultWalletUnitId = 'CW-1' | 'CW-2' | 'CW-B';
export type WalletUnitId = DefaultWalletUnitId | 'CW-C' | 'CW-W';
export type WalletProviderStatusListId = 'SL-WP-A' | 'SL-WP-B' | 'SL-WP-C' | 'SL-WP-W';

/** The Wallet Provider of each default Wallet Unit (issuer catalogue section 3.4). */
export const WALLET_UNITS: Record<DefaultWalletUnitId, WalletProviderId> = { 'CW-1': 'WP-A', 'CW-2': 'WP-A', 'CW-B': 'WP-B' };

/** Issue 26: the Wallet Units of the trust mechanism test cases, of a Wallet Provider the default `TL-WP` does not grant. */
export const TRUST_TEST_WALLET_UNITS: Record<Exclude<WalletUnitId, DefaultWalletUnitId>, WalletProviderId> = { 'CW-C': 'WP-C', 'CW-W': 'WP-W' };

export const STATUS_LIST_OF: Record<WalletProviderId, WalletProviderStatusListId> = { 'WP-A': 'SL-WP-A', 'WP-B': 'SL-WP-B', 'WP-C': 'SL-WP-C', 'WP-W': 'SL-WP-W' };

/** Status value of a revoked entry (Token Status List: `INVALID`). */
export const REVOKED = 1;

export interface WalletUnit {
  id: WalletUnitId;
  provider: WalletProviderId;
  /** The WIA's `sub`, the `client_id` the Wallet Unit uses at the Authorization Server. */
  clientId: string;
  /** The `cnf` key of the unit's WIAs, which signs their PoPs. Generated with the unit, shared with no other unit. */
  instanceKey: EcKeyPair;
  /** `client_status.status`: the Wallet Instance's entry in the status list of its provider. */
  wiaStatus: StatusReference;
  /** `key_storage_status.status`: the WSCD's entry in the same list. */
  kaStatus: StatusReference;
  /** `client_status.exp` and `key_storage_status.exp`: the end of the revocation maintenance period. */
  maintenanceUntil: Date;
}

export interface WalletProviderStatusList {
  id: WalletProviderStatusListId;
  provider: WalletProviderId;
  uri: string;
  statuses: number[];
  /** Versions published so far; each publication serves a new Status List Token under `uri`. */
  version: number;
  /** The token served now. */
  token: string;
}

export interface TestWalletProviderOptions {
  pki: TestPki;
  statusProvider: StatusProvider;
  /** Namespace of the status list URLs. */
  runId: string;
  /** Fixed time for every artifact; default the current time at each build. */
  now?: Date;
  /** Number of `attested_keys` of a KA; default 1. */
  batchSize?: number;
  /** Revocation maintenance period in days; default 400 (catalogue section 3.4: more than one year). */
  maintenanceDays?: number;
  /** Entries per status list; default 10 000 (TS3 section 2.5.1: at least 10 000 attestations). */
  listSize?: number;
  /** `wallet_version` of the Wallet Solutions; default `1.0.0`. */
  walletVersion?: string;
}

/** Per-artifact overrides: any builder option except the ones the Wallet Unit fixes is optional. */
export type WiaOverrides = Partial<WiaOptions>;
export type WiaPopOverrides = Partial<WiaPopOptions> & { audience: string };
export type KeyAttestationOverrides = Partial<KeyAttestationOptions> & { batchSize?: number };

/**
 * The Test Wallet Provider. Each Wallet Unit has one WIA entry and one KA entry in the status list of its provider:
 * TS3 section 2.5 option 2 (per-KA index) with per-issuer reuse, since a run talks to one PID or Attestation Provider.
 */
export class TestWalletProvider {
  private constructor(
    readonly pki: TestPki,
    private readonly statusProvider: StatusProvider,
    private readonly options: TestWalletProviderOptions,
    readonly units: Record<WalletUnitId, WalletUnit>,
    readonly statusLists: Record<WalletProviderId, WalletProviderStatusList>,
  ) {}

  static async create(options: TestWalletProviderOptions): Promise<TestWalletProvider> {
    const now = options.now ?? new Date();
    const listSize = options.listSize ?? 10_000;
    const maintenanceUntil = new Date(now.getTime() + (options.maintenanceDays ?? 400) * DAY_MS);
    const statusLists = {} as Record<WalletProviderId, WalletProviderStatusList>;
    const taken = new Map<WalletProviderId, Set<number>>();
    for (const provider of Object.keys(STATUS_LIST_OF) as WalletProviderId[]) {
      statusLists[provider] = {
        id: STATUS_LIST_OF[provider],
        provider,
        uri: options.statusProvider.allocate(options.runId),
        statuses: new Array<number>(listSize).fill(0),
        version: 0,
        token: '',
      };
      taken.set(provider, new Set());
    }
    // Unlinkable entries: random, distinct indices in the list of the provider.
    const entry = (provider: WalletProviderId): StatusReference => {
      const used = taken.get(provider)!;
      let idx: number;
      do idx = randomInt(listSize);
      while (used.has(idx));
      used.add(idx);
      return { idx, uri: statusLists[provider].uri };
    };
    const units = {} as Record<WalletUnitId, WalletUnit>;
    for (const [id, provider] of Object.entries({ ...WALLET_UNITS, ...TRUST_TEST_WALLET_UNITS }) as [WalletUnitId, WalletProviderId][]) {
      units[id] = {
        id,
        provider,
        clientId: `wallet-unit-${id.toLowerCase()}`,
        instanceKey: await generateEcKeyPair(),
        wiaStatus: entry(provider),
        kaStatus: entry(provider),
        maintenanceUntil,
      };
    }
    const twp = new TestWalletProvider(options.pki, options.statusProvider, options, units, statusLists);
    for (const provider of Object.keys(statusLists) as WalletProviderId[]) await twp.publishStatusList(provider);
    return twp;
  }

  entityOf(provider: WalletProviderId): TestEntity {
    return this.pki.entities[provider];
  }

  private get now() {
    return this.options.now ?? new Date();
  }

  /** A WIA of the unit, signed under its provider's WIA anchor. */
  async wia(unitId: WalletUnitId, overrides: WiaOverrides = {}): Promise<string> {
    const unit = this.units[unitId];
    const entity = this.entityOf(unit.provider);
    return buildWia({
      signer: certifiedSigner(signerFor(entity, 'wia')),
      clientId: unit.clientId,
      cnf: unit.instanceKey.publicJwk,
      status: unit.wiaStatus,
      maintenanceUntil: unit.maintenanceUntil,
      walletName: entity.spec.walletSolution!.name,
      walletVersion: this.options.walletVersion ?? '1.0.0',
      walletLink: `${entity.issuerUri}/wallet`,
      certificationInformation: `${entity.issuerUri}/certification/wallet-solution`,
      now: this.now,
      ...overrides,
    });
  }

  /** The PoP of the unit's WIA for an Authorization Server, signed with the unit's `cnf` key. */
  async pop(unitId: WalletUnitId, overrides: WiaPopOverrides): Promise<string> {
    const unit = this.units[unitId];
    return buildWiaPop({ signer: keySigner(unit.instanceKey), clientId: unit.clientId, now: this.now, ...overrides });
  }

  /**
   * A KA of the unit, signed under its provider's KA anchor, over `batchSize` fresh keys (TS3 section 2.2.2.1: a key is
   * in at most one KA). Returns the keys with it, for the proofs.
   */
  async keyAttestation(unitId: WalletUnitId, overrides: KeyAttestationOverrides = {}): Promise<{ jwt: string; keys: EcKeyPair[] }> {
    const unit = this.units[unitId];
    const entity = this.entityOf(unit.provider);
    const { batchSize, ...options } = overrides;
    const keys = await Promise.all(Array.from({ length: batchSize ?? this.options.batchSize ?? 1 }, () => generateEcKeyPair()));
    const jwt = await buildKeyAttestation({
      signer: certifiedSigner(signerFor(entity, 'ka')),
      attestedKeys: keys.map((key) => key.publicJwk),
      status: unit.kaStatus,
      maintenanceUntil: unit.maintenanceUntil,
      certification: `${entity.issuerUri}/certification/wscd`,
      now: this.now,
      ...options,
    });
    return { jwt, keys };
  }

  /** Revokes the unit's Wallet Instance: its WIA entry, in a new version of its provider's status list. */
  revokeInstance(unitId: WalletUnitId) {
    return this.setStatus(this.units[unitId].provider, this.units[unitId].wiaStatus, REVOKED);
  }

  /** Revokes the unit's WSCD: its KA entry, in a new version of its provider's status list. */
  revokeWscd(unitId: WalletUnitId) {
    return this.setStatus(this.units[unitId].provider, this.units[unitId].kaStatus, REVOKED);
  }

  /** Sets an entry and publishes the new version of the list. */
  async setStatus(provider: WalletProviderId, reference: StatusReference, status: number) {
    const list = this.statusLists[provider];
    if (reference.uri !== list.uri) throw new Error(`${reference.uri} is not ${list.id}`);
    list.statuses[reference.idx] = status;
    return this.publishStatusList(provider);
  }

  /** Signs the list's current content under the provider's status anchor and serves it under its URI. */
  async publishStatusList(provider: WalletProviderId): Promise<WalletProviderStatusList> {
    const list = this.statusLists[provider];
    const entity = this.entityOf(provider);
    list.token = await buildStatusListTokenJwt({
      signer: signerFor(entity, 'status'),
      issuer: entity.issuerUri,
      uri: list.uri,
      statuses: list.statuses,
      now: this.now,
    });
    list.version += 1;
    this.statusProvider.register(list.uri, list.token);
    return list;
  }
}
