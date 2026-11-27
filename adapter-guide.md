# Testing your own Relying Party or issuer: writing an adapter

The project has two suites, and neither tests wallets: in both, the harness plays the wallet and everything else
around the system under test (SUT).

| Suite | System under test | What the harness plays | Adapter interface |
| --- | --- | --- | --- |
| Relying Party suite (`eudi-pcaf run`) | A Relying Party (verifier) | The wallet, the PID and attestation providers, the status lists, the trust lists | `RelyingPartyAdapter` |
| Issuer suite (`eudi-pcaf issuer run`) | A PID Provider or Attestation Provider | The wallet, the Wallet Provider with its attestations, the Registrar, the trust lists | `IssuerAdapter` |

For either suite, the one piece you write is the **adapter**: a TypeScript module that lets the harness drive your
system. The two interfaces differ, because a verifier and an issuer are driven differently.

Most of this guide covers the **Relying Party adapter**. Start from its template,
[adapters/template/src/index.ts](adapters/template/src/index.ts), and its ICS,
[adapters/template/ics.yaml](adapters/template/ics.yaml). The template talks to a made-up REST API and marks every call
with `TODO`. Replace those calls with your Relying Party's API and fill in the ICS, and you can run the suite.

For an **issuer adapter** (PID Provider or Attestation Provider), start from
[adapters/issuer-template/src/index.ts](adapters/issuer-template/src/index.ts) and its ICS,
[adapters/issuer-template/ics.yaml](adapters/issuer-template/ics.yaml), in the same way.
[Issuer adapters](#issuer-adapters) at the end walks through it. The sections on networking and known findings apply
to it as they are, and the report has the same layout; its ICS is a different one, with profiles and items of its own.

## How a run works

1. The controller starts the Test Trust Infrastructure (`TL-PID`, `TL-PUB`, `TL-WP`, `TL-AC`, `TL-RC`, the test LOTL
   and `TL-QEAA`) and the Test Status Provider, all on plain HTTP in a namespace of their own for the run. It issues
   your Relying Party an access certificate and a registration certificate.
2. It calls the adapter's `setUp` once, with all of that in a `TestEnvironment`. The adapter configures your Relying
   Party to trust those lists and to use those certificates.
3. For each test case and each flow the ICS declares (redirects, the DC API), it calls `startPresentation` with a
   default query. The Conformance Wallet answers the request your Relying Party created: with a valid presentation,
   or with one carrying exactly one fault, such as an expired credential, a revoked status, a wrong `nonce`, a bad
   signature or a stale trust list.
4. It calls `readResult` and compares what your Relying Party decided with the expected result: accept the valid
   presentation and release exactly the requested attributes, reject the faulty one.

A negative test case runs only after its **positive control** passed in the same flow. If your Relying Party cannot
accept a valid PID, every test case that depends on that is INCONCLUSIVE, not FAIL. Get the positive controls passing
first.

## Quick start

In a clone of this repository:

```bash
pnpm install
```

```bash
pnpm playwright:install
```

Copy the template to a folder of your own under `adapters/`, so it can import `@eudi-pcaf/core` from the
workspace, and change the `name` in its `package.json`:

```bash
cp -R adapters/template adapters/my-rp
```

Then run the two positive controls of the PID (SD-JWT VC and mdoc) against your running Relying Party:

```bash
MY_RP_URL=http://127.0.0.1:8080 pnpm eudi-pcaf run --adapter adapters/my-rp/src/index.ts --ics adapters/my-rp/ics.yaml --only 'RP_WS_IA_MainInteraction_001*'
```

Outside a clone, keep the adapter in your own repository and run it with the Docker image, which can resolve
`@eudi-pcaf/core` from any directory ([running.md](running.md#docker-image)). The
packages are not published to npm, so for type checking in your editor you still need a clone.

`pnpm eudi-pcaf --list` lists every test case and marks the positive controls.

## What the adapter implements

The interface is `RelyingPartyAdapter` in [packages/core/src/rp/adapter.ts](packages/core/src/rp/adapter.ts). The
module exports `createAdapter()`, which returns one.

| Member | Required | What it does |
| --- | --- | --- |
| `name` | yes | Shown in the log and the report. |
| `harnessHost` | no | The host name under which your Relying Party reaches the harness. See [Networking](#networking). |
| `setUp(env, namespace)` | yes | Configures your Relying Party for the run. See [What setUp configures](#what-setup-configures). |
| `startPresentation({ query, flow })` | yes | Starts a presentation and returns how the wallet is invoked. |
| `readResult(transactionId, timeoutMs)` | yes | Reports what your Relying Party decided. See [What readResult reports](#what-readresult-reports). |
| `refreshTrust(namespace)` | no | Makes your Relying Party fetch its trust lists now. |
| `describe()` | no | What the report records about your Relying Party, such as its version. |
| `tearDown()` | no | Releases what the adapter started or configured. |
| `frontEnd(req)` | no | Drives your Relying Party's front end. Only for ICS RP.P.9 Yes. |

### What setUp configures

`setUp` is called once per run. `namespace` is new for every run, and the URLs of the trust lists contain it, so a
configuration left over from an earlier run can never be mistaken for this one. Use it to keep runs apart, for
example as a tenant (EUDIPLO's adapter creates one tenant per namespace), or replace your Relying Party's whole
configuration.

| `TestEnvironment` field | What your Relying Party does with it | Needed when |
| --- | --- | --- |
| `trustLists`, the entry with `id` `TL-PID` | Fetches the list (ETSI TS 119 602 LoTE, JAdES-sealed) from `url`, verifies its seal with `schemeOperatorCertificatePem` and trusts its PID Providers, for the PID and its status lists | always |
| `trustLists`, the entry with `id` `TL-PUB` | The same, for PuB-EAA Providers | RP.G.4 Yes |
| `listOfTrustedLists` | Fetches the test LOTL (ETSI TS 119 612, XAdES) from `url`, pinned to `signingCertificatesPem`, follows its pointer to `TL-QEAA` and trusts the granted QEAA services there | RP.G.3 Yes |
| `rulebooks` | Trusts `anchorsPem` of `default_credential_eaa` directly: the anchor its rulebook defines, which no list publishes | RP.G.5 Yes |
| `accessCertificate` | Signs its requests with this key and certificate (`x509_hash` client ID): `chainPem` leaf first, the key as PKCS#8 PEM or as a JWK | always |
| `registrationCertificate` | Sends this JWT in `verifier_info` | always |
| `queries` | The DCQL query of each default query, by its ID. `startPresentation` names one of them | always |
| `ics` | The ICS the run uses. Configure from it the settings your Relying Party has: `T_skew` (RP.P.4), `T_kb` (RP.P.6), `T_tx` (RP.P.7), the status list timeout (RP.R.6), `T_refresh` (RP.T.1), the grace period (RP.T.2) | where your RP has a setting |

The other entries of `trustLists` (`TL-WP`, `TL-AC`, `TL-RC`) are for the other suites and SUTs; a Relying Party does
not need them.

Pinning matters: the trust list test cases publish versions sealed by another key, versions that are stale, rolled
back or of the wrong type. A Relying Party that trusts whatever list it finds at the URL fails them.

The template filters the queries to the categories the ICS declares, and leaves out the variants with
`trusted_authorities` unless RP.P.3 is Yes. A query your Relying Party is not configured for is never started: the
test cases that need it are NOT APPLICABLE by the ICS.

### startPresentation and the two flows

`startPresentation` gets a default query ID and a flow, starts a presentation and returns the transaction ID that
`readResult` gets later, and the invocation:

- **Redirects** (`flow: 'redirect'`, RP.P.1): `{ uri }`, the URI the wallet would be invoked with, for example
  `openid4vp://?client_id=…&request_uri=…`. The Conformance Wallet fetches the request object and posts the response
  (`direct_post.jwt`) to the `response_uri`.
- **The DC API** (`flow: 'dc-api'`, RP.P.2): `{ dcApiPage }`, the URL of a page of your Relying Party. The harness
  opens it in Chromium (Playwright), answers its `navigator.credentials.get` call with the Conformance Wallet's
  `dc_api.jwt` response, keeping the page's real origin, and records the request in which the page forwards the
  response to your back end. The page is whatever your relying service would show. If your Relying Party has no page
  of its own, the adapter can serve a minimal one, as [the EUDIPLO adapter](adapters/eudiplo/src/index.ts) does
  (`dcApiPage()`). Serve it on `127.0.0.1`, which Chromium treats as a secure context, and put that origin in the
  request's `expected_origins`.

Start with redirects only (RP.P.2 No, as in the template ICS) and add the DC API flow once that passes.

### What readResult reports

`readResult` waits up to `timeoutMs` for your Relying Party to decide, then returns a `RelyingPartyResult`:

| Field | Meaning |
| --- | --- |
| `outcome` | `success` when the Relying Party accepted the presentation, `failure` when it rejected it, `pending` when it has not decided by `timeoutMs` |
| `releasedAttributes` | On `success`: the attributes your Relying Party hands to the relying service. They can be nested objects or keys joined with `.`. For an mdoc, the namespace comes first: `eu.europa.ec.eudi.pid.1.family_name`, or `{ "eu.europa.ec.eudi.pid.1": { "family_name": … } }` |
| `flags` | Conditions the result signals; see below |
| `raw` | Your Relying Party's own answer, kept in the report as evidence |

Report what the relying service would get, not what the wallet sent. Accepting a valid presentation passes only when
the released attributes are exactly the requested ones, with the issued values. Technical claims (`iss`, `iat`,
`cnf`, `status`, …) are ignored. On a faulty presentation, any released attribute is a FAIL, even when the outcome is
`failure`.

A rejection also counts when your Relying Party answers the Authorization Response with HTTP 4xx. An answer with
HTTP 5xx is always a FAIL: the Relying Party must reject bad input, not crash on it.

Three flags carry meaning:

| Flag | When |
| --- | --- |
| `status-unknown` | You accepted an EAA whose revocation status could not be established reliably. Required with RP.R.2 "Accept and flag as status unknown" |
| `trust-list-stale` | You accepted a presentation that relies on a trust list past its `NextUpdate`, within the grace period (RP.T.2) |
| `attribute-invalid` | You accepted a presentation but marked an attribute as invalid, where the test case allows that instead of a rejection (a PID attribute of the wrong data type, `RP_WS_DM_IdentifyingData_004a_UF` and `_004b_UF`) |

### Optional hooks

- **`refreshTrust`**: the `RP_Inf` test cases publish a new version of a trust list and wait for your Relying Party
  to fetch it. With this hook they wait at most 10 seconds after calling it; without it they wait the whole
  `T_refresh` the ICS declares (RP.T.1). If your Relying Party has no way to trigger a refresh, declare a short
  `T_refresh` for the test run, or these test cases will be slow.
- **`describe`**: what the report records about the system under test, such as its URL, version and commit. Worth
  adding once you compare runs.
- **`tearDown`**: called after the last test case.
- **`frontEnd`**: only for a Relying Party that redeems the response code at its own front end (RP.P.9 Yes), for the
  test cases `RP_WS_IA_ProtocolFlow_006` to `_009`. With `url` it opens the front end the wallet redirected to, in the
  user agent that started the transaction (`same`) or a fresh one (`fresh`), and reports what was released to that
  user agent. See [the reference adapter](adapters/reference/src/index.ts). A back end that leaves the comparison of
  the response code to the relying service declares RP.P.9 No and does not need it.

## The ICS

The Implementation Conformance Statement says what your Relying Party supports and how it behaves. Every item is
defined in [ics-rp.md](fcaf-overlay/docs/fcaf/ics-rp.md); the template ICS has a line on each. It does three things:

- **It selects test cases.** A test case names the ICS answers it applies to in its profile. A test case whose profile
  the ICS does not meet is NOT APPLICABLE, as is every run in a flow the ICS does not declare (RP.P.1, RP.P.2).
- **It sets the timing.** `T_skew`, `T_kb`, `T_tx`, `T_refresh` and the grace period decide where the faults are
  placed: a credential "expired by more than `T_skew`" uses your declared `T_skew`.
- **It decides the policy test cases.** Where the specifications leave a choice (RP.P.12, RP.R.2, RP.R.3, RP.R.7,
  RP.T.4), the verdict compares the behaviour with what you declared.

Declare what your Relying Party does, not what it ought to do. A Yes for something it does not do gives FAILs, and a
No for something it does hides test cases. Where your Relying Party has a setting for an item, the adapter can set it
from `env.ics` in `setUp`, so the ICS and the configuration cannot drift apart. Where it has a fixed value, declare that
value.

## Networking

Your Relying Party and the harness reach each other both ways: the harness calls your API and endpoints, and your
Relying Party fetches trust lists and status lists from the harness.

- Use `127.0.0.1`, not `localhost`, in every URL. Node.js may resolve `localhost` to `::1` first, where another
  process can hold the same port.
- The harness serves plain HTTP. Your Relying Party has to allow HTTP for trust and status list URLs in the test
  setup (EUDIPLO: `OUTBOUND_URL_ALLOW_HTTP`), and must not insist on public IP addresses.
- If your Relying Party runs in a container, it reaches the harness at `host.docker.internal`: set `harnessHost` (or
  `HARNESS_HOST`, or `--harness-host`), and map that name to `host-gateway` in its Compose file, as
  [adapters/eudiplo/docker-compose.yml](adapters/eudiplo/docker-compose.yml) does.
- The Docker image of the harness runs on the host network (Linux; Docker Desktop needs host networking turned on).

## Reading the report

Each run writes `reports/<run>/report.json`, `summary.md` and `junit.xml`, and next to them, per test case, flow and
step, the artifacts: the credential and the Status List Token as served (and before their fault), the request, the
presentation, the response, the network log of the DC API page, and your Relying Party's result (`raw`).

| Verdict | Meaning |
| --- | --- |
| PASS | Your Relying Party did what the test case expects |
| FAIL | It did not. The reason names the check, for example `verification result is success` or `released attributes that were not requested: …` |
| INCONCLUSIVE | The test case could not be judged: its positive control did not pass, the response was not delivered, the adapter threw, or the ICS item it needs is not declared |
| NOT APPLICABLE | The ICS excludes it |
| REVIEW | A person has to judge it: an application-specific status value (RP.R.3), and the test book items `RP_TB_*`, which are inspections and never fail the run |

The run fails (exit code 1) on any FAIL or INCONCLUSIVE.

## A sensible order

1. The positive controls in one flow and one format: `--flows redirect --only 'RP_WS_IA_MainInteraction_001a'`.
   Until that passes, fix `setUp` and `readResult`; the artifacts of the step show the request your Relying Party
   created and the result it reported.
2. Both formats, then the other categories your Relying Party requests (`RP_WS_IA_MainInteraction_*`).
3. The whole suite in that flow, with `--concurrency 4` or so. Most of a full run is the deliberate waits of a few
   test cases, which overlap.
4. The DC API flow (RP.P.2 Yes).
5. For each FAIL, decide whether it is a bug in your Relying Party, a wrong ICS answer, or a bug in the suite (please
   open an issue). Bugs you accept for now go into a known findings file. A run with `--known-findings` reports them
   as known and fails only on new ones:

   ```yaml
   - testCase: RP_PP_SM_Revocation_005a_UF
     flows: [dc-api]          # optional; default every flow
     finding: What the Relying Party does wrong, in one sentence.
     reference: https://github.com/example/my-rp/issues/42   # optional: where it is tracked
   ```

6. Run it in CI with the [GitHub Action](running.md#github-action).

## Issuer adapters

The issuer suite tests a PID Provider or Attestation Provider. The harness plays the wallet (Wallet Units with their
wallet and key attestations), the Wallet Provider, the Registrar that certifies the Provider's keys, and the trust
lists. It runs every issuance itself, against the Provider's public OpenID4VCI endpoints, and checks every credential
the Provider issues. The adapter only does what a wallet cannot: enrol and configure the Provider, create offers, and
act as its back office.

Start from the template, [adapters/issuer-template/src/index.ts](adapters/issuer-template/src/index.ts), and its ICS,
[adapters/issuer-template/ics.yaml](adapters/issuer-template/ics.yaml). Like the Relying Party template, it talks to a
made-up admin API and marks every call with `TODO`. It is written for a PID Provider. Copy it to a folder of your own
under `adapters/`, then run the positive controls of the PID:

```bash
MY_ISSUER_URL=http://127.0.0.1:8080 pnpm eudi-pcaf issuer run --adapter adapters/my-issuer/src/index.ts --ics adapters/my-issuer/ics.yaml --only PP_WS_IA_MainInteraction_001
```

`pnpm eudi-pcaf issuer --list` lists every test case with its variants, and marks the positive controls.

### What the issuer adapter implements

The interface is `IssuerAdapter` in [packages/core/src/issuer/adapter.ts](packages/core/src/issuer/adapter.ts).

| Member | Required | What it does |
| --- | --- | --- |
| `enrol(namespace)` | yes | Returns CSRs for the Provider's keys, which the Test Registrar certifies: the credential signing keys (an SD-JWT VC signer, and for mdoc a document signer, each named in `credentialSigningProfiles`), the status list signer, and the access certificate key. Return `undefined` if your Provider cannot create CSRs: the Registrar then generates the keys, and `setUp` gets them to import |
| `setUp(env, namespace)` | yes | Configures the Provider; see below |
| `createOffer(req)` | yes | Creates a credential offer for the test subject and the configurations `req` names, with the grant it names, by value or by reference, optionally with a transaction code or deferred |
| `authenticateSubject` | for `P-AC` | Completes the subject's authentication for the authorization request and returns the redirect to the wallet; see below |
| `setStatus` | for `P-HOOK` | Revokes, suspends or reinstates what a session issued, and resolves once the Provider reports it done |
| `completeDeferred` | for `P-DEF` | Completes a deferred issuance, so the wallet's next poll returns the credential |
| `changeSubject` | no | The subject's data change in the Provider's records (`PP_WS_SM_Revocation_008`) |
| `changeDisclosurePolicy` | for `P-EDP` | Changes the embedded disclosure policy of a configuration (Attestation Providers) |
| `refreshTrust`, `describe`, `tearDown` | no | As for a Relying Party; `refreshTrust` makes the Provider fetch `TL-WP` now |

A hook you leave out goes with its profile: without `setStatus`, do not declare `P-HOOK`; without
`authenticateSubject`, do not declare `P-AC`. Without `changeSubject`, `PP_WS_SM_Revocation_008` is NOT APPLICABLE.

### What the issuer setUp configures

| `IssuerTestEnvironment` field | What your Provider does with it |
| --- | --- |
| `credentialSigningCertificates`, `credentialSigningProfiles` | Signs credentials with them: the SD-JWT VC signer and the mdoc document signer, in the order `enrol` named them. With a private key when the Registrar generated it |
| `statusListSigningCertificate` | Signs its status lists with it; absent when it signs them with the credential signing key |
| `accessCertificate` | Its access certificate from `AC-A` |
| `registrationCertificate` | Publishes this JWT in its metadata (ETSI TS 119 475) |
| `trustLists`, the entry with `id` `TL-WP` | Fetches the list from `url`, verifies its seal with `schemeOperatorCertificatePem`, and accepts wallet and key attestations only from the Wallet Providers on it |
| `ics` | Creates the credential configurations the ICS names (`ICS-02.SD`, `ICS-02.MD`, …) and sets what it has settings for: batch size, status list size, key attestation levels, the policy for attestations without obtainable status |

The test cases name a configuration by its ICS item, for example `ICS-02.SD`, and the ICS maps it to your
configuration ID (`ICS-02.SD: pid-sd-jwt-vc`). `createOffer` gets your IDs.

### Subjects, authentication and status

- **The test subjects.** The Conformance Wallet compares every issued value with the data of `SUBJ-1` and `SUBJ-2`
  (`PID_TEST_SUBJECTS` of `@eudi-pcaf/core`; `ATTESTATION_TEST_SUBJECTS` for `default_credential_A`). The
  template sends them with each offer, in the claim names of the format (`pidClaimsOf`). If your Provider takes the
  data from its own records, seed the two subjects there instead (ICS-17). The Provider adds the issuance metadata and
  the age attributes itself.
- **`authenticateSubject`.** In the authorization code grant the wallet opens your authorization endpoint, and the
  subject would log in. The template follows the redirect of an Authorization Server without a login step. If yours
  has one, drive it here, for example through a test identity provider, and return where the Authorization Server
  redirects: the wallet's `redirect_uri` with `code`, `state` and `iss`, or with `error`. An answer that is not a
  redirect is thrown as `AuthorizationEndpointError`, which the harness records as the endpoint's answer.
- **`setStatus`.** Resolve only once your Provider reports the change done. The harness then expects it on the status
  list within `T_rev` (ICS-06.T_rev).

### What differs from the Relying Party suite

- **The ICS** has profiles as well as items. The profiles select the test cases and variants, such as mdoc (`P-MD`),
  the authorization code grant (`P-AC`), deferred issuance (`P-DEF`) or short-lived credentials (`P-SHORT`); the items
  declare values, keyed by item or `<item>.<name>`. Its items are defined in
  [ics-issuer.md](fcaf-overlay-issuer/docs/fcaf/ics-issuer.md). The template ICS starts with a PID Provider in both
  formats and the pre-authorized code grant; [the EUDIPLO issuer ICS](adapters/issuer-eudiplo/ics.yaml) declares
  nearly every profile.
- **The verdicts** judge what the Provider issues, not what it accepts. An issuance passes (`ISS`) when every
  credential it issues passes the reference validator with the suite's trust configuration. A refusal passes (`REJ`)
  when the request the flow ended at got a 4xx with an OAuth error object and nothing was issued. A 5xx answer is
  never a pass.
- **Waiting for expiry.** Some test cases wait for an artifact to expire. `--max-wait` sets how long a step may wait
  (default 0); a step that would wait longer is NOT APPLICABLE.
- **`--only`** adds the positive controls the selected test cases depend on, so a single negative test case can be
  run on its own.
- **Attestation Providers** issue `default_credential_A` instead of the PID, and the ICS can declare one Provider
  instance per category (`categories`). The template does not cover that; the EUDIPLO issuer adapter does, with one
  tenant per category, and [its README](adapters/issuer-eudiplo/README.md) lists each hook with the calls it makes.
