// Issuer harness design section 7, level 1, for the points `authorization` and `token-request`: the valid authorization
// code flow (PAR, PKCE S256, `issuer_state`, `authorization_details`) and the valid pre-authorized code flow pass every
// grant check of the reference validator, every fault of `GRANT_FAULTS` fails exactly its target check and no other,
// and so does each reuse of an artifact by a `token-reuse` step. No issuer is involved: a capture Authorization Server
// answers every request with a fixed, valid-looking response and judges nothing; the reference validator alone decides.
import { randomUUID } from 'node:crypto';
import {
  GRANT_FAULT_IDS,
  GRANT_FAULTS,
  GRANT_STIMULI,
  type GrantCheck,
  type GrantFaultId,
  grantFaultInfo,
  type RunningServer,
  sendJson,
  startServer,
} from '@eudi-pcaf/core';
import { createTestPki } from '@eudi-pcaf/forge';
import { StatusProvider } from '@eudi-pcaf/status-provider';
import { checkAuthorizationResponse, type GrantFlowInput, type GrantFlowOptions, validateGrantFlow } from '@eudi-pcaf/validator';
import { TestWalletProvider } from '@eudi-pcaf/wallet-provider';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type Authenticate, type IssuanceEvidence, IssuanceClient, WALLET_REDIRECT_URI, walletUnitOf } from '../src/index';

const CONFIGURATION_ID = 'test_sd_jwt_vc';
const SECOND_CONFIGURATION_ID = 'second_sd_jwt_vc';
const TX_CODE = '493536';
const LIFETIME = 86_400;

/** A capture Authorization Server and Credential Issuer: PAR, authorization (through `authenticate`), token, nonce, credential. */
async function startCaptureIssuer() {
  let base = '';
  const pushed = new Map<string, Record<string, string>>();
  const configuration = (scope: string) => ({
    format: 'dc+sd-jwt',
    vct: `urn:test:${scope}`,
    scope,
    cryptographic_binding_methods_supported: ['jwk'],
    credential_signing_alg_values_supported: ['ES256'],
    proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
  });
  const server: RunningServer = await startServer({ host: '127.0.0.1' }, (req, res, body) => {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    if (path === '/.well-known/openid-credential-issuer') {
      return sendJson(res, 200, {
        credential_issuer: base,
        credential_endpoint: `${base}/credential`,
        nonce_endpoint: `${base}/nonce`,
        credential_configurations_supported: { [CONFIGURATION_ID]: configuration('test'), [SECOND_CONFIGURATION_ID]: configuration('second') },
      });
    }
    if (path === '/.well-known/oauth-authorization-server') {
      return sendJson(res, 200, {
        issuer: base,
        authorization_endpoint: `${base}/authorize`,
        pushed_authorization_request_endpoint: `${base}/par`,
        token_endpoint: `${base}/token`,
        grant_types_supported: ['authorization_code', 'urn:ietf:params:oauth:grant-type:pre-authorized_code'],
        token_endpoint_auth_methods_supported: ['attest_jwt_client_auth'],
      });
    }
    if (path === '/par') {
      const requestUri = `urn:ietf:params:oauth:request_uri:${randomUUID()}`;
      pushed.set(requestUri, Object.fromEntries(new URLSearchParams(body.toString())));
      return sendJson(res, 201, { request_uri: requestUri, expires_in: 60 });
    }
    if (path === '/token') return sendJson(res, 200, { access_token: randomUUID(), token_type: 'DPoP', expires_in: 300 });
    if (path === '/nonce') return sendJson(res, 200, { c_nonce: randomUUID() });
    if (path === '/credential') return sendJson(res, 200, { credentials: [{ credential: 'captured~' }] });
    return sendJson(res, 404, { error: 'not_found' });
  });
  base = server.localUrl;
  /** The adapter's part: the redirect with a fresh code, `state` and `iss`, for a pushed or a plain request alike. */
  const authenticate: Authenticate = async (url) => {
    const query = Object.fromEntries(new URL(url).searchParams);
    const params = query.request_uri ? (pushed.get(query.request_uri) ?? {}) : query;
    const redirect = new URL(params.redirect_uri ?? WALLET_REDIRECT_URI);
    redirect.searchParams.set('code', randomUUID());
    if (params.state) redirect.searchParams.set('state', params.state);
    redirect.searchParams.set('iss', base);
    return redirect.toString();
  };
  const offer = (grant: 'pre-authorized_code' | 'authorization_code', configurationId = CONFIGURATION_ID) =>
    `openid-credential-offer://?credential_offer=${encodeURIComponent(
      JSON.stringify({
        credential_issuer: base,
        credential_configuration_ids: [configurationId],
        grants:
          grant === 'pre-authorized_code'
            ? { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': randomUUID(), tx_code: { input_mode: 'numeric', length: 6 } } }
            : { authorization_code: { issuer_state: randomUUID() } },
      }),
    )}`;
  return { url: () => base, offer, authenticate, stop: () => server.close() };
}

/** What the validator needs, from the evidence of one issuance. */
function inputOf(evidence: IssuanceEvidence): GrantFlowInput {
  const grant = evidence.grant;
  if (!grant) throw new Error(`no grant in the evidence: ${evidence.error}`);
  const authorization = grant.authorization;
  return {
    grant: grant.grant,
    clientId: grant.clientId,
    ...(authorization
      ? {
          ...(authorization.pushed ? { par: authorization.parameters } : {}),
          ...(authorization.requestUri ? { requestUri: authorization.requestUri } : {}),
          ...(authorization.expiresIn !== undefined ? { expiresIn: authorization.expiresIn } : {}),
          ...(authorization.url ? { authorizationRequest: Object.fromEntries(new URL(authorization.url).searchParams) } : {}),
          secondsAfterPar: authorization.waitedSeconds ?? 0,
          ...(authorization.response?.code ? { issuedCode: authorization.response.code } : {}),
        }
      : {}),
    ...(grant.preAuthorizedCode ? { offerCode: grant.preAuthorizedCode } : {}),
    ...(grant.txCode !== undefined ? { offerTxCode: grant.txCode } : {}),
    secondsAfterOffer: grant.waitedSeconds ?? 0,
    ...(grant.wrongTxCodeAttempts !== undefined ? { wrongTxCodeAttempts: grant.wrongTxCodeAttempts } : {}),
    ...(grant.tokenRequest ? { tokenRequest: grant.tokenRequest } : {}),
  };
}

const failuresOf = async (input: GrantFlowInput, options: Partial<GrantFlowOptions> = {}) => {
  const result = await validateGrantFlow(input, {
    configurations: { [CONFIGURATION_ID]: { scope: 'test' }, [SECOND_CONFIGURATION_ID]: { scope: 'second' } },
    preAuthorizedCodeLifetimeSeconds: LIFETIME,
    ...options,
  });
  return { failures: result.failures, result };
};

let issuer: Awaited<ReturnType<typeof startCaptureIssuer>>;
let status: StatusProvider;
let twp: TestWalletProvider;

beforeAll(async () => {
  issuer = await startCaptureIssuer();
  status = await new StatusProvider().start({ host: '127.0.0.1' });
  twp = await TestWalletProvider.create({ pki: await createTestPki(), statusProvider: status, runId: 'grant-faults-test' });
}, 60_000);

afterAll(async () => {
  await issuer?.stop();
  await status?.stop();
});

const client = (unit: 'CW-1' | 'CW-2' = 'CW-1') => IssuanceClient.create(walletUnitOf(twp, unit), { allowInsecureUrls: true });
const noWait = { maxWaitSeconds: Number.MAX_SAFE_INTEGER, sleep: async () => {}, preAuthorizedCodeLifetimeSeconds: LIFETIME };

async function issue(grant: 'pre-authorized_code' | 'authorization_code', fault?: GrantFaultId, extra: { stopAfterAuthorization?: boolean } = {}) {
  const cw = await client();
  return cw.issue({
    offer: issuer.offer(grant),
    grant,
    signedMetadata: false,
    ...(grant === 'pre-authorized_code' ? { txCode: TX_CODE } : { authenticate: issuer.authenticate }),
    ...(fault ? { grantFault: fault } : {}),
    ...(fault && grantFaultInfo(fault).otherOffer ? { otherOffer: { offer: issuer.offer('pre-authorized_code', SECOND_CONFIGURATION_ID), txCode: '111111' } } : {}),
    ...noWait,
    ...extra,
  });
}

describe('grant checks: valid flows', () => {
  it('the valid authorization code flow passes every grant check: PAR, PKCE S256, issuer_state, authorization_details', async () => {
    const evidence = await issue('authorization_code');
    expect(evidence.error).toBeUndefined();
    expect(evidence.credentials).toHaveLength(1);
    expect(evidence.exchanges.map((e) => e.step)).toEqual(['metadata', 'metadata', 'par', 'authorization', 'token', 'nonce', 'credential']);
    const authorization = evidence.grant?.authorization;
    expect(authorization?.parameters).toMatchObject({ response_type: 'code', code_challenge_method: 'S256', redirect_uri: WALLET_REDIRECT_URI });
    expect(authorization?.parameters.issuer_state).toEqual(expect.any(String));
    const par = evidence.exchanges.find((e) => e.step === 'par');
    expect(par?.request.headers).toMatchObject({ 'OAuth-Client-Attestation': expect.any(String), 'OAuth-Client-Attestation-PoP': expect.any(String), DPoP: expect.any(String) });
    const { failures, result } = await failuresOf(inputOf(evidence));
    expect(failures).toEqual([]);
    expect(result.checks.filter((c) => c.status === 'pass').map((c) => c.check)).toEqual(['par', 'pkce', 'authorization-details', 'request-uri', 'authorization-code', 'code-binding', 'pkce-verifier']);
    expect(checkAuthorizationResponse(authorization?.response, { state: authorization?.state ?? '', issuer: issuer.url() }).map((c) => c.status)).toEqual(['pass', 'pass', 'pass']);
  });

  it('the valid pre-authorized code flow passes every grant check', async () => {
    const evidence = await issue('pre-authorized_code');
    expect(evidence.error).toBeUndefined();
    const { failures, result } = await failuresOf(inputOf(evidence));
    expect(failures).toEqual([]);
    expect(result.checks.filter((c) => c.status === 'pass').map((c) => c.check)).toEqual(['pre-authorized-code', 'tx-code']);
  });

  it('flags an authorization response with an altered state or without iss', () => {
    const checks = checkAuthorizationResponse({ code: 'c', state: 'other' }, { state: 's', issuer: 'https://as.example' });
    expect(checks.filter((c) => c.status === 'fail').map((c) => c.check)).toEqual(['authorization-response-state', 'authorization-response-iss']);
  });
});

describe('grant checks: each fault fails exactly its target check', () => {
  for (const id of GRANT_FAULT_IDS) {
    const info = GRANT_FAULTS[id];
    const ignored = 'mustIgnore' in info && info.mustIgnore;
    it(ignored ? `${id} is ignored: ${info.target} passes` : `${id} fails ${info.target}`, async () => {
      const evidence = await issue(info.grant, id);
      expect(evidence.grant?.fault).toBe(id);
      const { failures, result } = await failuresOf(inputOf(evidence));
      expect(failures, JSON.stringify(result.checks)).toEqual(ignored ? [] : [info.target]);
    });
  }

  it('waits the lifetime plus one hour, and refuses to above the run limit', async () => {
    let slept = 0;
    const cw = await client();
    const evidence = await cw.issue({
      offer: issuer.offer('authorization_code'),
      authenticate: issuer.authenticate,
      grantFault: 'authorization.request-uri-expired',
      signedMetadata: false,
      maxWaitSeconds: 4000,
      sleep: async (ms) => {
        slept = ms;
      },
    });
    expect(slept).toBe((60 + 3600) * 1000);
    expect(evidence.grant?.authorization?.waitedSeconds).toBe(3660);
    const limited = await (await client()).issue({ offer: issuer.offer('pre-authorized_code'), txCode: TX_CODE, grantFault: 'token-request.pre-authorized-code-expired', preAuthorizedCodeLifetimeSeconds: LIFETIME, signedMetadata: false });
    expect(limited.waitExceeded).toEqual({ waitsFor: 'pre-authorized-code', seconds: LIFETIME + 3600, limit: 0 });
    expect(limited.exchanges.some((e) => e.step === 'token')).toBe(false);
  });

  it('sends ten wrong tx_code values before the right one', async () => {
    const evidence = await issue('pre-authorized_code', 'token-request.tx-code-repeated');
    const tokens = evidence.exchanges.filter((e) => e.step === 'token').map((e) => new URLSearchParams(e.request.body).get('tx_code'));
    expect(tokens).toHaveLength(11);
    expect(tokens.slice(0, 10).every((code) => code !== TX_CODE && /^\d{6}$/.test(code ?? ''))).toBe(true);
    expect(tokens[10]).toBe(TX_CODE);
  });
});

describe('grant checks: token-reuse fails exactly one check', () => {
  const reuse: { name: string; check: GrantCheck; run: () => Promise<{ input: GrantFlowInput; options: Partial<GrantFlowOptions> }> }[] = [
    {
      name: 'a redeemed pre-authorized code',
      check: 'pre-authorized-code',
      run: async () => {
        const first = await issue('pre-authorized_code');
        const again = await (await client()).redeemAgain(first.metadata!, first.grant!);
        return { input: { ...inputOf(first), tokenRequest: again.grant?.tokenRequest }, options: { redeemedCodes: [first.grant!.preAuthorizedCode!] } };
      },
    },
    {
      name: 'a redeemed authorization code',
      check: 'authorization-code',
      run: async () => {
        const first = await issue('authorization_code');
        const again = await (await client()).redeemAgain(first.metadata!, first.grant!);
        return { input: { ...inputOf(first), tokenRequest: again.grant?.tokenRequest }, options: { redeemedCodes: [first.grant!.authorization!.response!.code!] } };
      },
    },
    {
      name: 'an authorization code redeemed by another Wallet Unit (CW-2)',
      check: 'code-binding',
      run: async () => {
        const first = await issue('authorization_code', undefined, { stopAfterAuthorization: true });
        expect(first.exchanges.at(-1)?.step).toBe('authorization');
        const again = await (await client('CW-2')).redeemAgain(first.metadata!, first.grant!);
        expect(again.exchanges.map((e) => e.step)).toEqual(['token']);
        return { input: { ...inputOf(first), clientId: again.grant!.clientId, tokenRequest: again.grant?.tokenRequest }, options: {} };
      },
    },
    {
      name: 'a used PAR request_uri',
      check: 'request-uri',
      run: async () => {
        const first = await issue('authorization_code');
        const again = await (await client()).reuseRequestUri(first.metadata!, first.grant!, issuer.authenticate);
        const url = again.grant?.authorization?.url;
        return {
          input: { ...inputOf(first), authorizationRequest: Object.fromEntries(new URL(url!).searchParams), tokenRequest: undefined },
          options: { usedRequestUris: [first.grant!.authorization!.requestUri!], redeemedCodes: [] },
        };
      },
    },
  ];
  for (const { name, check, run } of reuse) {
    it(`${name} fails ${check}`, async () => {
      const { input, options } = await run();
      const { failures, result } = await failuresOf(input, options);
      expect(failures, JSON.stringify(result.checks)).toEqual([check]);
    });
  }
});

describe('grant stimuli', () => {
  it('cover every fault, and every stimulus has a fault or says where it is implemented', () => {
    const covered = new Set(GRANT_STIMULI.flatMap((s) => s.faults));
    expect(GRANT_FAULT_IDS.filter((id) => !covered.has(id))).toEqual([]);
    for (const stimulus of GRANT_STIMULI) expect(stimulus.faults.length > 0 || Boolean(stimulus.leftOut), stimulus.testCase).toBe(true);
    for (const id of GRANT_FAULT_IDS) for (const testCase of GRANT_FAULTS[id].testCases) expect(GRANT_STIMULI.some((s) => s.testCase === testCase && s.faults.includes(id))).toBe(true);
  });
});
