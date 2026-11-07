# RP conformance harness: design

Draft 0.1, 2026-11-06. Phase 0 (section 11) is implemented in `packages/` and `adapters/`; see the README for how to run it. It describes the tool that executes the Relying Party test cases in [fcaf-overlay](fcaf-overlay/README.md) (121 baseline test cases) against any Relying Party, EUDIPLO first.

## 0. Summary

The harness plays every party around the Relying Party (RP): the wallet, the issuers, the status provider and the trust infrastructure. It sends the RP valid material and material with exactly one deliberate fault, then reads the RP's verdict and compares it with the expected result of the FCAF test case.

Key choices:

- **TypeScript monorepo**, same stack as EUDIPLO and WILMA, built on the OWF libraries (`@owf/*`, `@sd-jwt/*`, `@openid4vc/*`). They already create JOSE, COSE, SD-JWT VC, mdoc (including MSO status and identifier lists), Token Status Lists, X.509 certificates and CRLs, LoTEs with JAdES seals, and access and registration certificates.
- **Valid first, then one fault**: every artifact is built valid with the libraries, then a named mutation is applied in a separate fault-injection layer that assembles JOSE/COSE directly, so strict library validation never blocks a deliberately broken artifact.
- **The harness proves its own faults**: before a mutation is used against an RP, a reference validator confirms that the unmutated artifact passes every check and the mutated one fails exactly the targeted check.
- **RP-agnostic through adapters**: one small interface (start a presentation, read the verdict, optionally refresh trust). EUDIPLO gets the first adapter; a manual adapter covers RPs without an API.
- **Executable test definitions are the single source of truth**: the FCAF markdown is rendered from them, replacing the current Python generator, so the specification and the executed test cannot drift.

## 1. Goals and non-goals

Goals:

1. Execute the FCAF Relying Party test cases unattended and produce FCAF verdicts (PASS, FAIL, INCONCLUSIVE, NOT APPLICABLE, REVIEW) with evidence.
2. Work with any RP that offers the ICS items and a way to read its verification result.
3. Run in CI: nightly against EUDIPLO's main image, and on demand against other RPs.
4. Make every negative verdict explainable: which fault, which artifact, what the RP answered, what the status provider and trust infrastructure saw.

Non-goals for now:

- Testing wallets or issuers (WILMA and the OIDF suites cover those).
- Proximity flows (ISO/IEC 18013-5 device engagement); the FCAF approach is to adopt ISO/IEC TS 18013-6 reader tests by reference.
- Testing the browser's Digital Credentials API implementation; the harness replaces it with a shim (§4.5).
- Load, penetration and availability testing.

## 2. What the baseline needs from a harness

Derived from the 121 generated test cases ([generator/tests.py](generator/tests.py)):

| Capability | Used by | Notes |
| --- | --- | --- |
| Start a presentation at the RP for a default query and flow | all | Through the RP adapter |
| Answer a signed OpenID4VP request via redirects (`direct_post.jwt`) | all `a` variants, `SessionEncryption_*a` | Same-device flow including the redirect back |
| Answer via the W3C Digital Credentials API (`dc_api.jwt`) | `SessionEncryption_*b`, every test case once per supported flow | Browser shim |
| Issue PID SD-JWT VC and mdoc, with variants | `Validity`, `Revocation`, `TrustMechanisms` | Claims, validity, status reference, issuer, signature |
| Issue QEAA, PuB-EAA and non-qualified EAA | `TrustMechanisms_010`–`_015` | QEAA needs a Trusted List in XML |
| Build KB-JWT and mdoc DeviceAuth bound to the request | all | Valid in the baseline; faults come with `SessionBinding` and `DeviceBinding` later |
| Encrypt the response, with faults | `SessionEncryption` | JWE `alg`, `enc`, `epk`, `kid`, target key, tampering, unencrypted, JWS |
| Serve Status List Tokens (JWT, CWT) and identifier lists, with faults | `Revocation`, `RP_PP_SM_Revocation` | Signature, signer, claims, type, `lst`, `bits`, size |
| Log status list retrievals per credential | `Validity_005`, `_006`, `Revocation_001`, `_010`, `RP_PP_*` | Evidence for `NOFETCH` and `FETCHED` |
| Publish LoTEs and Trusted Lists, and new versions during a test | all; `TrustMechanisms_007`, `_008` | Logs retrievals |
| Test PKI per the trust configuration | all | `PP-A` … `CA-X`, revocation anchors, expired anchor |
| Read the RP verdict and released attributes | all | Through the RP adapter |
| Read the RP's ICS values (`T_skew`, `T_kb`, `T_refresh`, policies) | time faults, `NOSTAT`, list refresh | ICS file per RP |

The distinct faults (§4.3) number about 70; most are reused across test cases and variants.

## 3. Architecture

```mermaid
flowchart LR
    subgraph Harness
        C[Test controller]
        F[Artifact forge<br/>+ fault injection]
        W[Conformance Wallet]
        S[Test Status Provider]
        T[Test Trust Infrastructure]
        B[DC API shim<br/>Playwright]
    end
    A[RP adapter]
    RP[(Relying Party<br/>under test)]

    C --> F
    C --> W
    C --> S
    C --> T
    C --> A
    A -- start presentation / read verdict --> RP
    W -- fetch request, post response --> RP
    B -- navigator.credentials.get --> W
    RP -- fetch status lists --> S
    RP -- fetch trust lists --> T
    F --> W
    F --> S
    F --> T
```

| Component | Responsibility |
| --- | --- |
| Test controller | Loads the ICS and the test definitions, selects applicable test cases, runs positive controls first, executes steps, evaluates expected results, writes the report. CLI and HTTP API. |
| Artifact forge | Test PKI, credentials, presentations, responses, status lists, identifier lists, LoTEs, Trusted Lists. Builds valid artifacts, applies named faults. |
| Conformance Wallet | Wallet side of OpenID4VP: resolves `request_uri`, validates the request, builds and sends the response the step defines, follows or withholds the redirect. |
| DC API shim | Opens the RP's DC API page in Playwright and replaces `navigator.credentials.get` so the request goes to the Conformance Wallet and its response comes back to the page. |
| Test Status Provider | Serves status artifacts registered per credential under unique URLs, with programmable HTTP behaviour; logs every request. |
| Test Trust Infrastructure | Serves LoTEs and Trusted Lists per namespace, versioned; logs every retrieval. |
| RP adapter | The only RP-specific code: configure the RP, start a presentation, read the verdict, trigger a trust refresh. |

All harness services run in one process or as containers on one Docker network with fixed host names (`wallet.rp-test`, `status.rp-test`, `trust.rp-test`), served over TLS by a harness CA that the RP trusts (part of `default_configuration_rp_1`).

## 4. Components

### 4.1 Test controller

1. **Selection**: evaluates `Profile applicability` against the RP's ICS file; unmet conditions give NOT APPLICABLE.
2. **Gating**: runs each positive control (`RP_WS_IA_MainInteraction_001a`, `_001b`, and the per-flow equivalents) first. A test case whose control did not pass ends INCONCLUSIVE.
3. **Execution**: steps run in order; each step produces evidence and a step verdict; the test case passes only if every step passes.
4. **Flows**: the controller repeats every test case once per flow the RP supports, as the FCAF test cases instruct, and reports per flow.
5. **Scheduling**: test cases that only touch their own namespace run in parallel; test cases that change shared state (trust list versions) run serially unless the adapter supports namespaces (§6).

### 4.2 Executable test definitions

Each FCAF test case has one definition in `packages/definitions`. It holds every FCAF field and the executable steps, so the markdown is rendered from it and cannot disagree with what runs.

| FCAF section | Definition field | Rendering |
| --- | --- | --- |
| Title | `id` | `# <id>`; class, layer and area in the ID give the file location |
| Objective | `objective` | Paragraph |
| References | `references` | Bullet list |
| Profile applicability | `profile` (ICS conditions: item, exact `ics-rp.md` text, answer) | Bullet list of the texts, or `None`; the controller evaluates the items against the ICS |
| EUDI-wallet relevancy | `relevancy` | One of the five FCAF values |
| Technology | `technology` | Bullet list; left out when empty |
| Preconditions | `preconditions` | Numbered list, or `None`; the positive controls they name must equal `control`, which gates execution |
| Test Scenario | `steps[].text` | Numbered list |
| Expected results | `steps[].expect.text` | Numbered list; `steps[].expect.codes` (`ACC`, `REJ`, `NOSTAT`, ...) is what the controller evaluates |
| Comments | `comments` | Paragraphs; left out when empty |

Shared wording lives in `packages/core/src/wording.ts`, ported from `generator/tests.py`: the preconditions, the expected results (`acc()`, `rej()`, `nostat()`, `fetched()`, `nofetch()`, combined with `all()`), the scenario texts (`scenario.credentialVariant(...)`, `scenario.statusListToken(...)`, ...), the comments, and the format and flow texts. Step builders such as `presentationStep.valid(...)` return the scenario text together with the executable action, so a fault and its description are written in one place.

```ts
export default defineTestCase({
  id: 'RP_PP_SM_Revocation_004a_UF',
  objective: 'Verify that the Relying Party does not use an expired Status List Token in JWT format.',
  references: ['[Token Status List] section 5.1, 8.3' /* … */],
  profile: [formats.sdJwtVc.profile, ics.checksPidRevocation],
  relevancy: relevancy.genericRequired,
  technology: [formats.sdJwtVc.technology, formats.sdJwtVc.statusListTechnology],
  preconditions: [...preconditions.base, preconditions.control('RP_WS_IA_MainInteraction_001a'), preconditions.freshStatusList],
  control: 'RP_WS_IA_MainInteraction_001a',
  steps: [
    step({
      // Phase 1: a statusListStep builder pairs this text with the fault.
      text: scenario.statusListToken('its `exp` claim is set to the current time minus `T_skew` minus one hour'),
      run: presentation({
        query: 'default_query_pid',
        credential: pid.sdJwtVc(),
        statusList: statusListToken.jwt({ faults: ['statusList.expiredBy(T_skew+1h)'] }),
      }),
      expect: nostat(), // reject for PIDs, declared policy otherwise
    }),
  ],
  comments: [comments.nostat, comments.flow],
});
```

`packages/fcaf-render` renders a definition to FCAF markdown (`renderTestCase`, `testCasePath`). In Phase 0 a test checks that every definition renders byte-identical to the committed file in `fcaf-overlay/`. Phase 1 completes the renderer and replaces the Python generator:

1. Port `generator/render.py` and `generator/pages.py` to TypeScript. The port is correct when it reproduces the current 121 files and the shared pages exactly.
2. Run the patched FCAF lint (`fcaf-overlay/fcaf_lint-rp.patch`, Python) on the generated output in CI; CI also fails if the rendered files differ from the committed ones.
3. Remove the Python `generator/`.

### 4.3 Artifact forge and fault injection

Two layers:

- **Builders** create valid artifacts with the OWF libraries: `@sd-jwt/sd-jwt-vc` and `@sd-jwt/core`, `@owf/mdoc`, `@owf/token-status-list`, `@owf/x509`, `@owf/eudi-lote` with `@owf/eudi-jades`, `@owf/eudi-access-certificate`, `@owf/eudi-registration-certificate`, `@owf/jose`, `@owf/cose`.
- **Faults** are pure, named functions applied at one of six points. Where a library would refuse the faulty input, the fault works on the decoded structure and re-assembles JOSE or COSE directly (WebCrypto signing).

| Point | Faults in the baseline |
| --- | --- |
| Credential, before signing | `exp`/`nbf` shift; MSO `validFrom`/`validUntil`/`expectedUpdate` shift; issuer selection (any entity of the trust configuration); status reference removed, malformed (5 kinds) or out of range; identifier list reference |
| Credential, after signing | issuer signature bit flip |
| Response | JWE `enc` choice; `alg` key-wrap variants; `enc` CBC; target key foreign or of another transaction with copied `kid`; ciphertext or tag bit flip; `epk` off-curve or other curve; JWS or `alg: none` instead of JWE; unencrypted `direct_post`; unencrypted DC API `data`; extra payload member |
| Status List Token | signature bit flip; `alg: none`; bare list; `exp` shift; `sub` change; wrong `typ`/type; each required claim removed; signer from `CA-X`, without `x5c`, self-signed, under another entity's or list's anchor, the credential's own certificate, another certificate under the issuance CA, embedded root, expired or not yet valid; corrupt base64url or ZLIB; decompression bomb; `bits` = 3; status patterns for `bits` 1, 2, 4, 8; `ES256K`; `HS256` / `COSE_Mac0` keyed with the public key |
| Identifier list | contains or omits the identifier; signature bit flip; expired; signer from `CA-X` |
| Trust list | new version without an entity; new version with an added entity |

Faults for later areas (KB-JWT, DeviceAuth, SessionTranscript, disclosures, certificate paths, LoTE seal, rollback) plug into the same points.

### 4.4 Test PKI and trust configuration

A builder creates all entities of `default_trust_configuration_rp` from a seed: CAs, issuance and revocation anchors, signing certificates, the expired anchor of `PP-E`, `CA-X`, the RP's access certificate (`AC-A`) and registration certificate (`RC-A`), and the harness TLS CA. Material is generated per run by default; a fixed seed reproduces a run exactly. The RP adapter receives the scheme operator certificates, the access certificate with its key, and the registration certificate.

### 4.5 Conformance Wallet

- **Redirects**: fetches `request_uri` (GET, or POST when `request_uri_method=post`), verifies the request signature and `x509_hash` client identifier against `TL-AC`, reads `client_metadata`, builds the presentation (KB-JWT or DeviceResponse with the OpenID4VP handover), encrypts, posts to `response_uri`, and follows `redirect_uri` in the same browser session unless the step says otherwise.
- **Request findings**: the wallet records every deviation of the request from OpenID4VP and HAIP. In the baseline these only gate the positive controls; they become verdicts once the `MS_*` and `RpIntegrity` test cases are written.
- **DC API shim**: Playwright opens the RP page with an init script that replaces `navigator.credentials.get`. The script forwards the request to the Conformance Wallet and resolves with its response, keeping the page's real origin, so `expected_origins` and the `origin:` audience behave as in a browser. The platform's credential selection is not tested.

The Conformance Wallet starts from EUDIPLO's headless E2E wallet (`apps/client/e2e/support/wallet.ts`), which already answers signed OpenID4VP requests with `direct_post.jwt` using `@openid4vc/openid4vp` and `@sd-jwt/sd-jwt-vc`.

### 4.6 Test Status Provider

- Each issued credential gets a unique status URL (`https://status.rp-test/<run>/<uuid>`), so the RP's cache never masks a fault and the request log maps to exactly one test step.
- Per URL it serves a registered artifact with programmable behaviour: status code, content type, latency, timeout, redirect.
- The log (time, URL, headers) is part of the evidence. `NOFETCH` passes when no request for the step's URL appears between the step's start and the verdict; `FETCHED` when at least one does.

### 4.7 Test Trust Infrastructure

- Serves `TL-PID`, `TL-PUB`, `TL-WP`, `TL-AC`, `TL-RC` as JAdES-sealed LoTEs, and a test LOTL with a national Trusted List for `TL-QEAA`.
- Lists live under a namespace (`https://trust.rp-test/<namespace>/…`) and are versioned; a step can publish a new version and wait until the log shows the RP retrieved it, or call the adapter's refresh hook.
- Trusted Lists are XML with XAdES signatures; the OWF `eudi-tl` package only parses and verifies them, so creation needs an XAdES library (§10).

### 4.8 RP adapter

```ts
// Illustrative, not final API.
interface RelyingPartyAdapter {
  name: string;
  /** Configure the RP: trust anchors, access and registration certificate, default queries. */
  setUp(env: TestEnvironment, namespace: string): Promise<void>;
  startPresentation(req: {
    query: DefaultQueryId;
    flow: 'redirect' | 'dc-api';
    namespace: string;
  }): Promise<{ transactionId: string; invocation: { uri: string } | { dcApiPage: string } }>;
  readResult(transactionId: string, timeoutMs: number): Promise<{
    outcome: 'success' | 'failure' | 'pending';
    releasedAttributes?: Record<string, unknown>;
    flags?: string[];               // for example 'status-unknown', 'trust-list-stale'
    raw: unknown;                   // kept as evidence
  }>;
  /** Optional: make the RP fetch its trust lists now instead of waiting T_refresh. */
  refreshTrust?(namespace: string): Promise<void>;
}
```

Adapters planned:

| Adapter | How |
| --- | --- |
| EUDIPLO | One tenant per namespace. `setUp` imports the access key chain, registration certificate, presentation configs for the default queries and the trust list URLs through the management API. `startPresentation` calls `POST /verifier/offer` with `response_type` `uri` (redirects) or `dc-api` with `expected_origin`, passing `skewSeconds` from the ICS and optionally a `webhook`. EUDIPLO has no page of its own for the DC API, so for that flow the adapter serves a minimal relying-party page on its own origin: it passes the returned request to `navigator.credentials.get` (answered by the shim) and posts the result to `POST /presentations/:sessionId/oid4vp`. `readResult` reads `GET /session/:id`: status `completed` is success with the attributes from `credentials`, `failed` is failure, `active` and `fetched` are pending. EUDIPLO needs `OUTBOUND_URL_ALLOW_PRIVATE_NETWORK` or `OUTBOUND_URL_ALLOWED_HOSTS` for the harness hosts. |
| Webhook | For RPs that push their result: the harness exposes an endpoint and matches results by transaction. |
| Manual | Prints the invocation and asks the tester for the outcome; every verdict becomes REVIEW. |

### 4.9 OIDF bridge

For the 16 objectives the OIDF verifier suite already covers, the controller can run the OIDF module instead of its own steps and map the result to the FCAF verdict. EUDIPLO's `apps/backend/test/oidf` already drives the suite through its API and is the starting point. The bridge is optional: the harness also implements those objectives itself, so it does not depend on the OIDF suite being available.

## 5. Verdict and evidence

Expected-result codes from the catalogue map to checks:

| Code | Check |
| --- | --- |
| `ACC` | `outcome = success` and the released attributes equal the requested ones with the issued values |
| `REJ` | `outcome = failure`, or HTTP 4xx at `response_uri`; never HTTP 5xx; no released attributes |
| `NOFETCH` / `FETCHED` | Test Status Provider log for the step's URL |
| `NOSTAT` | `REJ` for PIDs; for other categories the ICS policy, and `status-unknown` in `flags` when accepted |
| `POLICY` | Compared with the ICS declaration |
| Trust list retrieved | Test Trust Infrastructure log |

Each test case produces a record like this, collected into JSON, JUnit XML and a markdown summary:

```json
{
  "testCase": "RP_PP_SM_Revocation_004a_UF",
  "flow": "redirect",
  "verdict": "PASS",
  "control": { "id": "RP_WS_IA_MainInteraction_001a", "verdict": "PASS" },
  "steps": [{
    "expected": "NOSTAT",
    "fault": "statusList.expiredBy(T_skew+1h)",
    "rpResponse": { "endpoint": "response_uri", "status": 400 },
    "rpResult": { "outcome": "failure" },
    "statusLog": [{ "url": "https://status.rp-test/r1/6f1c…", "at": "2026-11-06T10:14:03Z" }],
    "artifacts": ["credential.sd-jwt", "status-list.jwt", "response.jwe"],
    "verdict": "PASS"
  }]
}
```

## 6. Isolation, determinism and parallelism

- Every step uses newly issued credentials with unique status URLs, so the RP's status cache needs no reset.
- Trust state is per namespace. With an adapter that maps namespaces to tenants (EUDIPLO), trust-changing test cases run in parallel; otherwise they run serially at the end of the run and restore the lists.
- Time faults are computed from the RP's declared `T_skew` and `T_kb` plus one hour, so clock jitter never decides a verdict; the harness checks its own clock against NTP at start.
- `T_refresh` can be long; the adapter's refresh hook avoids waiting it out.

## 7. Harness self-validation

A wrong fault produces a false PASS, so every fault is tested before it is used against an RP:

1. A reference validator built from the same OWF libraries checks the unmutated artifact and must report no failure.
2. The mutated artifact must fail the targeted check and only that check (for example, `exp` in the past must fail the validity check but still pass the signature and digest checks).
3. The harness runs the whole baseline against a reference RP built from that validator in CI. Every test case must PASS there, which also proves each positive control is reachable.

## 8. Deployment and CI

- `docker compose up` starts the harness services and, for EUDIPLO runs, the EUDIPLO image with PostgreSQL. The RP under test trusts the harness TLS CA and allows the harness hosts.
- CLI: `rp-conformance run --adapter eudiplo --ics ics.yaml --flows redirect,dc-api [--only RP_WS_SM_Validity_*]`.
- Nightly GitHub Actions job against EUDIPLO's latest main image; the report is uploaded and summarised. Like WILMA, the harness lives outside eudiplo's CI; eudiplo only triggers it on image publication.

## 9. Reuse

| Source | Used for |
| --- | --- |
| OWF identity-common-ts (`@owf/*`, `@sd-jwt/*`, `@openid4vc/*`) | Builders, reference validator, OpenID4VP wallet side |
| `test-trust-lists` (BMI GitLab) | LoTE generation and JAdES sealing patterns |
| EUDIPLO `apps/client/e2e/support/wallet.ts` | Starting point for the Conformance Wallet |
| EUDIPLO `apps/backend/test/oidf` | OIDF bridge |
| WILMA (`cre8/walter`) | Run and verdict model, report conventions |
| `rp-conformance/generator` | Test text, replaced by the executable definitions |

## 10. Gaps and risks

| Item | Impact | Mitigation |
| --- | --- | --- |
| No Trusted List (ETSI TS 119 612) creation in the OWF libraries | `TrustMechanisms_010`, `_011` (QEAA) | XAdES signing with an existing library such as `xadesjs`, or contribute creation to `@owf/eudi-tl` |
| Strict libraries refuse to build invalid artifacts | Fault injection | Direct JOSE/COSE assembly in the fault layer (§4.3) |
| A fault that breaks more than intended | False PASS | Self-validation (§7) |
| RP outbound URL restrictions | RP cannot reach status or trust lists; tests fail for the wrong reason | Adapter configures allowed hosts; positive controls catch it |
| RPs without a machine-readable verdict | No automation | Manual adapter with REVIEW verdicts |
| `T_refresh` of hours | Slow trust tests | Adapter refresh hook |
| DC API shim instead of the real platform | Platform behaviour untested | Out of scope; documented |
| ISO/IEC 18013-5 second edition still a draft | Identifier list and MSO status structures may change | Pin to the version `@owf/mdoc` implements; record it in the report |

## 11. Delivery phases

| Phase | Content | Baseline test cases enabled |
| --- | --- | --- |
| 0 | Repository, controller skeleton, test PKI, Test Status Provider, Test Trust Infrastructure (LoTE), Conformance Wallet for SD-JWT VC via redirects, EUDIPLO adapter, reference RP, self-validation | Positive control `RP_WS_IA_MainInteraction_001a` |
| 1 | SD-JWT VC faults, Status List Tokens in JWT, response encryption via redirects; the TypeScript renderer replaces the Python generator (section 4.2) | 53 (`a` variants of `Validity`, `Revocation`, `RP_PP_SM_Revocation`, PID `TrustMechanisms`, `SessionEncryption` via redirects), including the control |
| 2 | mdoc: MSO, COSE, Status List Tokens in CWT, identifier lists | 45 (`b` variants and mdoc-only test cases) |
| 3 | DC API shim | 11 (`SessionEncryption` via the DC API), plus every earlier test case repeated per flow |
| 4 | QEAA (Trusted List XML), PuB-EAA, non-qualified EAA; OIDF bridge; nightly CI | 12 (`TrustMechanisms_010`–`_015`) |
| 5 | Remaining catalogue areas (`SessionBinding`, `DeviceBinding`, `IssuerIntegrity`, `RP_Inf`, request-side checks) | Beyond the baseline |

## 12. Decisions needed

1. **Where the harness lives**: decided 2026-11-06, the private repository `cre8/rp-conformance`, next to the catalogue and the baseline. A move to an organisation (EUDIPLO, OpenWallet Foundation Labs) stays possible later.
2. **Source of truth**: decided 2026-11-07, the executable test definitions; a TypeScript renderer in this monorepo produces the FCAF markdown and replaces the Python `generator/` (section 4.2).
3. **Reference RP**: a minimal RP built on the reference validator (recommended, proves the harness independently of EUDIPLO), or EUDIPLO itself as the reference.
4. **OIDF bridge**: run the 16 overlapping objectives through the OIDF suite in addition to the harness's own steps, or only through the harness.
