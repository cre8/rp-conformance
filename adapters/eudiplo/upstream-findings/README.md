# Prepared upstream issues for EUDIPLO

Issue texts for the known findings in [`../known-findings.yaml`](../known-findings.yaml) that are not reported upstream
yet. Each file is one issue for `EUDIPLO/eudiplo`: the first heading is the title, the rest is the body. The confirmed
findings were filed on 2026-11-21 and the table links their issues; the others are opened by hand once the maintainer agrees, the issue reference then goes into the `reference` of the
entries and the file is removed.

All findings were reviewed against the primary specifications and EUDIPLO's source on 2026-11-20 (spec review of the
EUDIPLO findings). Each text names the specification version it quotes and says whether the requirement is one of the
base specification (`basis: confirmed` in the findings list) or of the EUDI profile only (`basis: profile`). Findings
whose test was wrong were removed with their texts; findings without a specification MUST are no longer FAILs, and the
texts kept for them are in [`suggestions/`](suggestions), clearly labelled as hardening suggestions or questions.

Checked against `ghcr.io/eudiplo/eudiplo:main` (`sha256:1a1f53b77b69cfeaf573f6950de6a70947b909181654a6de252f8207e1b138a7`,
version `9.1.0-main.ae0792a`, revision `ae0792a98991c28607879c2291d26b26b9ee9817`). Source links point to that
revision. The evidence is shortened; the certificates and credentials are test data of the suite's test PKI.

All findings are fixed on `ghcr.io/eudiplo/eudiplo:main` and removed from the findings list, which is empty since the
re-run of 2026-11-24 (`10.1.0-main.1c527a3`: 541 PASS, 23 NOT APPLICABLE, no FAIL):

| Issue | Basis | Test cases | Fixed by | Removed |
| --- | --- | --- | --- | --- |
| [EUDIPLO/eudiplo#1615](https://github.com/EUDIPLO/eudiplo/issues/1615) | confirmed | `RP_WS_SM_IssuerIntegrity_013_UF`, `_025_UF` | EUDIPLO main `7586139` | 2026-11-22 |
| [EUDIPLO/eudiplo#1616](https://github.com/EUDIPLO/eudiplo/issues/1616) | confirmed | `RP_WS_SM_IssuerIntegrity_034a_UF`, `_034b_UF`, `_037a_UF`, `_037b_UF` | EUDIPLO main `7586139` | 2026-11-22 |
| [EUDIPLO/eudiplo#1617](https://github.com/EUDIPLO/eudiplo/issues/1617) | confirmed | `RP_WS_DM_IdentifyingData_001b` | EUDIPLO main `7586139` | 2026-11-22 |
| [EUDIPLO/eudiplo#1649](https://github.com/EUDIPLO/eudiplo/issues/1649) | confirmed (RFC 9052 section 3) | `RP_WS_SH_Encoding_003_UF` step 5 (`mdoc.issuer-auth-duplicate-label`, found 2026-11-22) | [EUDIPLO/eudiplo#1660](https://github.com/EUDIPLO/eudiplo/pull/1660): an mDOC whose CBOR repeats a map key is refused | 2026-11-24 |
| no issue needed | profile (Token Status List section 8.3, draft-19 and later; HAIP 1.0 pins draft-14), low severity | `RP_WS_SM_Validity_005b_UF` (an expired mdoc's status list was fetched before the validity check, in `@owf/mdoc`) | [openwallet-foundation-labs/identity-common-ts#478](https://github.com/openwallet-foundation-labs/identity-common-ts/pull/478), released in `@owf/mdoc` 0.11.0, which EUDIPLO takes since [EUDIPLO/eudiplo#1663](https://github.com/EUDIPLO/eudiplo/pull/1663) | 2026-11-24 |

Suggestions and questions (not conformance findings, no FAIL in the suite):

| File | Test cases (informational or `POLICY`) |
| --- | --- |
| [suggestions/trust-list-invalid-seal-discards-last-valid.md](suggestions/trust-list-invalid-seal-discards-last-valid.md) | `RP_Inf_SM_TrustMechanisms_002_UF`, `_003_UF` (`POLICY` RP.T.4) |
| [suggestions/lote-type-not-checked.md](suggestions/lote-type-not-checked.md) | `RP_Inf_SM_TrustMechanisms_006_UF` (INFO) |

Removed after the review: the DC API `response_uri` text (`RP_WS_MS_ProtocolMessages_005`; OpenID4VP 1.0 Appendix A.2
allows additional parameters), and the document signer EKU part of the certificate path text
(`RP_WS_SM_IssuerIntegrity_027_UF`, now INFO: ETSI TS 119 412-6 clause 4 does not require the EKU, and the ISO/IEC
18013-5 profile could not be verified).

To reproduce any of them from a checkout of this repository:

```bash
pnpm install
```

```bash
EUDIPLO_IMAGE=ghcr.io/eudiplo/eudiplo:main docker compose -f adapters/eudiplo/docker-compose.yml up -d --wait
```

```bash
pnpm eudi-pcaf run --adapter eudiplo --only '<test case ID>'
```

The run writes `reports/<run>/report.json` and, per test case, flow and step, the request object, the credential, the
presentation and EUDIPLO's session (`rp-result.json`) under `reports/<run>/artifacts/`.
