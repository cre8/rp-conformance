# Running the harness

How to run both suites: from a clone with the CLI, with the Docker image, and in CI with the GitHub Action. Writing an
adapter for a system of your own is in [adapter-guide.md](adapter-guide.md); the details of the EUDIPLO adapters are in
[adapters/eudiplo/README.md](adapters/eudiplo/README.md) and
[adapters/issuer-eudiplo/README.md](adapters/issuer-eudiplo/README.md).

## Setup and the reference run

Requires Node.js 22.12 or later and pnpm. The DC API flow runs in Playwright's Chromium (headless shell), installed once:

```bash
pnpm install
```

```bash
pnpm playwright:install
```

```bash
pnpm test
```

```bash
pnpm eudi-pcaf run --adapter reference
```

`pnpm test` includes the self-validation (harness design §7): every fault of the catalogue fails exactly its target
check of the reference validator (the trust-list faults a check of the trust list, the request faults a request
check), every step of every executable definition carries exactly one fault in each flow it runs in, the test LOTL and
`TL-QEAA` that the forge signs are accepted by `@owf/eudi-tl`, and every executable test case passes against the
reference RP in both flows.

## Options

- `--adapter` takes a built-in adapter (`reference`, `eudiplo`) or the path of an adapter module of your own
  ([adapter-guide.md](adapter-guide.md)); an adapter module needs `--ics`.
- `--only` selects test cases by ID or pattern (`--only 'RP_PP_SM_Revocation_*'`).
- `--flows redirect` or `--flows dc-api` restricts the run to one flow.
- `--list` shows every definition and which are text only.
- `--concurrency <n>` runs up to `n` test case runs at a time (default 1, one after another).
- `--known-findings <file>` reports the FAILs listed there as known findings; the run then fails only on another FAIL,
  an INCONCLUSIVE or REVIEW result, or a harness error.
- `--harness-host` (or `HARNESS_HOST`) is the host name under which the system under test reaches the harness, for
  example `host.docker.internal` from a container.

Everything on the host uses `127.0.0.1`, not `localhost`: Node.js may resolve `localhost` to `::1` first, where another
process can hold the same port. The CLI resolves host names IPv4 first.

## Flows and ordering

Every test case runs once per flow the ICS declares (RP.P.1 redirects, RP.P.2 DC API), and its positive control must
have passed in the same flow. The `SessionEncryption` variants, the test cases on the audience and handover of one flow
(`SessionBinding_002`, `_006` to `_009`) and the request-side test cases of one flow (`ProtocolMessages_001`, `_002`,
`_004`, `_005`, `RpIntegrity_007`) name their flow in their profile and run only in it. The request-side test cases
start presentations and check the requests the Conformance Wallet captures, without answering them; the `RP_Inf` test
cases publish a new version of `TL-PID` or `TL-QEAA` and restore it afterwards. In the DC API flow the adapter returns a
page of the Relying Party; the shim opens it in Chromium, answers its `navigator.credentials.get` call with the
Conformance Wallet's `dc_api.jwt` response, keeping the page's real origin, and records the request in which the page
forwards the response to its backend.

Most of a full run is the deliberate waits of a few test cases (the late response of `ProtocolFlow_011`, the
`SessionEncryption` and `Encoding_001` waits), which overlap with `--concurrency`. A test case waits for its positive
control in the same flow. The test cases that publish trust list versions (`TrustMechanisms`) change the run's one
namespace, which every other test case relies on, so they run after the others, one at a time (harness design §6). The
report lists the results in definition order; the log lines come as the runs finish.

## The report

The report goes to `reports/<run>/report.json` with a `summary.md` and a `junit.xml`, and the artifacts of every step
(credential, Status List Token as served and before its fault, request, presentation, response form or DC API `data`,
the page's network log, the RP's verification result) next to it, per flow. [adapter-guide.md](adapter-guide.md#reading-the-report)
explains the verdicts.

## Against EUDIPLO

```bash
docker compose -f adapters/eudiplo/docker-compose.yml up -d --wait
```

```bash
pnpm eudi-pcaf run --adapter eudiplo --known-findings adapters/eudiplo/known-findings.yaml
```

[adapters/eudiplo/README.md](adapters/eudiplo/README.md) covers the image, the environment variables, the DC API page,
the trust configuration per category and a second EUDIPLO next to a running one.

## Issuer suite

```bash
pnpm eudi-pcaf issuer --list
```

```bash
docker compose --env-file adapters/issuer-eudiplo/reference.env -f adapters/eudiplo/docker-compose.yml up -d --wait
```

```bash
pnpm eudi-pcaf issuer run --adapter eudiplo --ics adapters/issuer-eudiplo/ics.yaml --known-findings adapters/issuer-eudiplo/known-findings.yaml
```

Per run the controller starts the Test Trust Infrastructure (`TL-WP`, `TL-PID`, `TL-AC`, `TL-RC`) and the Test Status
Provider (`SL-WP-A`, `SL-WP-B`), creates the Test Wallet Provider with its Wallet Units, enrols the Provider through the
Test Registrar (from its CSRs where the adapter returns them, otherwise with keys the Registrar generates) and sets the
adapter up once. Each step of action `issuance` creates an offer through the adapter and runs the pre-authorized code
flow with the issuance client of `packages/issuer-wallet` (WIA and PoP, DPoP, nonce, a proof that carries the KA).
Every credential the Provider issues goes through the reference validator with the suite's trust configuration
(`OBS-CRED`): format, `issuer-trust` to the enrolled `PP-T` on `TL-PID`, `issuer-signature`, `disclosures`,
`validity`, `holder-binding` (bound to a proof key the KA attests, in place of `key-binding`) and `status-reference`,
then the status list checks. `ISS` passes when every credential passes every check, `REJ` when the request at which the
flow ended got a 4xx with an OAuth error object and nothing was issued; no answer may be a 5xx. The definitions are in
`packages/issuer-definitions`, one per test case and variant; a step names its credential configuration by reference
to the ICS (`ICS-02.SD`), which the adapter's `ics.yaml` maps to the Provider's configuration ID.

The report goes to `reports/<run>/` as for the RP suite (`report.json` with every request and response and the check
results, `summary.md`, `junit.xml`, the credentials). `EUDIPLO_PORT` and `HARNESS_HOST` work as for the RP suite.

## Docker image

The image `ghcr.io/cre8/eudi-pcaf` ([Dockerfile](Dockerfile)) holds the CLI, both suites, the built-in adapters
and Chromium for the DC API flow, so a run needs neither a clone nor Node.js. Its working directory `/work` is where
relative paths resolve; an adapter module there can import `@eudi-pcaf/core` without installing it, and is an ES
module unless a `package.json` of its own says otherwise. On the host network the system under test and the harness
reach each other as with the bare CLI (Linux; Docker Desktop needs host networking turned on):

```bash
docker run --rm --init --network host --user "$(id -u):$(id -g)" -v "$PWD:/work" ghcr.io/cre8/eudi-pcaf:main run --adapter ./my-adapter.ts --ics my-ics.yaml
```

Tags: `main` and `sha-<commit>` from main, `<version>`, `v<major>` and `latest` from a release tag
([.github/workflows/image.yml](.github/workflows/image.yml)).

## GitHub Action

The GitHub Action ([action.yml](action.yml)) runs that image in a job that has started the system under test, writes
the summary to the job summary and uploads the report as an artifact. It fails the step as the CLI fails the run; the
outputs `report`, `junit` and `exit-code` name the run's report, for example for a test reporter.

```yaml
jobs:
  conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker compose up -d --wait   # the Relying Party under test
      - uses: cre8/eudi-pcaf@main
        env:
          MY_RP_URL: http://127.0.0.1:8080
          HARNESS_HOST: host.docker.internal   # if the RP runs in a container
        with:
          adapter: ./conformance/adapter.ts
          ics: conformance/ics.yaml
          known-findings: conformance/known-findings.yaml
          env-vars: MY_RP_URL
          concurrency: 4
```

`suite: issuer` runs the issuer suite; `only`, `flows`, `max-wait`, `harness-host` and `args` pass the CLI's options;
`env-vars` names the variables of the step that reach the adapter in the container (`HARNESS_HOST` always does);
`image` pins another image, and `build` builds it from the action's source. The image of `@main` is `main`, of `@v1`
it is `v1`. Paths are relative to the workspace. A container of the system under test reaches the harness at
`host.docker.internal` when its Compose file maps that name to `host-gateway`, as
[adapters/eudiplo/docker-compose.yml](adapters/eudiplo/docker-compose.yml) does.

## CI of this repository

- Every pull request runs the type check, `pnpm test` (with the self-validation and the reference run in both flows),
  `pnpm fcaf:render --check` and [scripts/fcaf-lint.sh](scripts/fcaf-lint.sh) ([CONTRIBUTING.md](CONTRIBUTING.md)).
- The job `Issuer reference run` ([.github/workflows/issuer-reference.yml](.github/workflows/issuer-reference.yml)) runs the issuer suite against the pinned EUDIPLO image
  (`adapters/issuer-eudiplo/reference.env`, the one place that names it) on every pull request that touches the issuer
  suite and uploads the report.
- The nightly job ([.github/workflows/nightly-eudiplo.yml](.github/workflows/nightly-eudiplo.yml), also started by
  hand) runs every test case of both suites against `ghcr.io/eudiplo/eudiplo:main`, or another image given when it is
  started by hand, with the known findings of each adapter. It uploads `reports/` as an artifact and adds each summary
  to the job summary; the issuer suite runs after the Relying Party suite, with its own report, JUnit XML and artifact
  (`issuer-conformance-eudiplo-<run>`). A FAIL there that is not a known finding is a regression of EUDIPLO's main to
  analyse, not a harness failure. PostgreSQL comes from Amazon ECR Public (`POSTGRES_IMAGE`), which has no anonymous
  pull limit like Docker Hub.
