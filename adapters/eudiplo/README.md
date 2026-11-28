# EUDIPLO adapter

`RelyingPartyAdapter` for [EUDIPLO](https://github.com/EUDIPLO/eudiplo) as the reference product of the Relying Party
suite (harness design section 4.8). Its ICS is [`ics.yaml`](ics.yaml), its known findings
[`known-findings.yaml`](known-findings.yaml), and the issue texts prepared for them are in
[`upstream-findings`](upstream-findings). The issuer suite has an adapter of its own,
[`adapters/issuer-eudiplo`](../issuer-eudiplo/README.md), which uses the same Compose file.

## Running it

EUDIPLO (latest published image) with PostgreSQL:

```bash
docker compose -f adapters/eudiplo/docker-compose.yml up -d --wait
```

```bash
pnpm eudi-pcaf run --adapter eudiplo --known-findings adapters/eudiplo/known-findings.yaml
```

`EUDIPLO_IMAGE=ghcr.io/eudiplo/eudiplo:main` runs the unreleased main image instead.

`EUDIPLO_URL`, `EUDIPLO_CLIENT_ID`, `EUDIPLO_CLIENT_SECRET` and `HARNESS_HOST` override the defaults of the Compose
file. The harness serves plain HTTP; the Compose file allows that with `OUTBOUND_URL_ALLOW_HTTP`.

`--known-findings` reports the FAILs listed in [`known-findings.yaml`](known-findings.yaml) as known findings; the run
then fails only on another FAIL, an INCONCLUSIVE or REVIEW result, or a harness error. The nightly job does this
against `ghcr.io/eudiplo/eudiplo:main` ([running.md](../../running.md#ci-of-this-repository)).

## The DC API page

EUDIPLO has no page of its own for the DC API, so the adapter serves a minimal relying-party page on
`http://127.0.0.1:<port>` (`EUDIPLO_PAGE_PORT`, default a free port). It creates the offer with `response_type`
`dc-api` and that origin as `expected_origin`, passes EUDIPLO's signed request object to `navigator.credentials.get`,
and posts the returned `data` to the request's `response_uri`, as EUDIPLO's SDK does.

## Trust per category

For QEAAs the adapter configures the test LOTL as an ETSI TS 119 612 Trusted List (`etsi_tl` with `format`
`trusted-list`), pinned to its signing certificates; EUDIPLO follows its pointer to `TL-QEAA`. EUDIPLO reads Trusted
Lists since [EUDIPLO/eudiplo#1513](https://github.com/EUDIPLO/eudiplo/pull/1513), which is on `main` but in no release
yet: 9.1.0 rejects that configuration (HTTP 400 when the adapter sets up), so run 9.1.0 with an ICS that declares
RP.G.3 (QEAAs) No (`--ics`), and its QEAA test cases are NOT APPLICABLE.

For PuB-EAAs the adapter configures `TL-PUB`; for non-qualified EAAs it registers the rulebook anchor `CA-EP-A` in a
trust list of the tenant, EUDIPLO's way of trusting an anchor that no list publishes.

## Host names and a second instance

Everything on the host uses `127.0.0.1`, not `localhost`: Docker publishes EUDIPLO on `127.0.0.1` only, and Node.js may
resolve `localhost` to `::1` first, where another process can hold the same port (an adapter login then fails with
HTTP 401 and `request_uri` with 404). The adapter defaults to `http://127.0.0.1:3000`, EUDIPLO's `PUBLIC_URL` in the
Compose file names `127.0.0.1`, and the CLI resolves host names IPv4 first.

For a second EUDIPLO next to a running one, give it another project name and port; `EUDIPLO_PORT` sets the published
port, the `PUBLIC_URL` and the adapter's default URL together:

```bash
EUDIPLO_PORT=3100 docker compose -p eudi-pcaf-eudiplo-2 -f adapters/eudiplo/docker-compose.yml up -d --wait
```

```bash
EUDIPLO_PORT=3100 pnpm eudi-pcaf run --adapter eudiplo
```
