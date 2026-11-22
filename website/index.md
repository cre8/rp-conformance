# Peer Conformance Assessment Framework (PCAF)

!!! warning "Unofficial draft"

    This site is not published or endorsed by the European Commission. It uses the method and the test case format of the Commission's Functional Conformance Assessment Framework (FCAF), as on its `submitted` branch at commit `@FCAF_SUBMITTED@`, for a proposed **Relying Party** System Under Test and draft **PID Provider** and **Attestation Provider** Systems Under Test. Wallet Solutions are tested with the official FCAF at [conformance.eudi.dev](https://conformance.eudi.dev).

The PCAF specifies functional conformance test cases for the **peers** of a Wallet Unit: the systems it talks to in the EUDI Wallet ecosystem. It is for

- **Relying Parties** and vendors of verifier software,
- **PID Providers**, **QEAA**, **PuB-EAA** and **non-qualified EAA Providers** and vendors of issuer software,
- the conformity assessment bodies, test laboratories, supervisory bodies and registrars that assess them.

It is not for testing a wallet: the FCAF does that.

## The gap

The FCAF names a System Under Test (SUT), splits it into test classes by interface, and specifies each test case step by step, with an Implementation Conformance Statement (ICS) in which the SUT declares what it supports. Today it has test cases for one SUT only: the Wallet Solution. Its `WS_RP` class covers the wallet's side of a presentation, and there the Relying Party is the test tool, not the thing being tested. The FCAF methodology names Relying Parties as a future SUT and reserves the classes `RP_WS`, `RP_PP`, `RP_AP` and `RP_Inf`, but none of them has test cases yet.

The OIDF verifier suite tests a Relying Party, but mostly on the happy flow: 16 of the 222 test objectives here correspond to one of its modules. The rest have no public test today: validity periods, status list tokens, trust anchor categories, trust lists, response encryption, session binding after the redirect and more.

A wallet that is certified gains little if the Relying Party accepts a revoked PID or trusts the wrong anchor. The PCAF fills the reserved classes with test cases in the FCAF format, so they can be contributed upstream, and comes with a harness that runs them. The focus is on what a Relying Party must reject: expired credentials, revoked or suspended credentials, unusable status lists, wrong trust anchors, stale trust lists, faulty response encryption.

It does the same, as a separate draft, for PID and Attestation Providers, for which the FCAF methodology reserves no test classes: the metadata and offers a Provider publishes when it issues credentials with OpenID4VCI, the Wallet Instance Attestations, key attestations and proofs it must reject, the PID or attestation it issues, checked against its rulebook, and the status lists it publishes.

## Where to start

| Page | Content |
| --- | --- |
| [Using the framework](pcaf/using-pcaf.md) | How a Relying Party or a Provider is tested: the SUT, the test environment, the ICS, preparation, execution and outcomes |
| [Relying Party (SUT)](pcaf/suts/relying_party/index.md) | Overview, test classes, the decisions applied |
| [(rp_ws) Wallet Solution](pcaf/suts/relying_party/wallet_solution/rp_ws.md) | Test cases on what the Relying Party receives from a Wallet Unit: validity, revocation, trust, session encryption |
| [(rp_pp) PID Provider](pcaf/suts/relying_party/pid_provider/rp_pp.md) | Test cases on the Status List Tokens and identifier lists of a PID Provider |
| [Defaults: Relying Party testing](pcaf/defaults.md#relying-party-testing) | Test roles, verification result, default configuration, credentials and queries |
| [ICS (Relying Party)](pcaf/ics-rp.md) | Capabilities, policies, time values and surrogate technology items a Relying Party declares |
| [PID Provider (SUT)](pcaf/suts/pid_provider/index.md) | Overview, test classes, variants, the decisions applied |
| [(pp_ws) Wallet Solution](pcaf/suts/pid_provider/wallet_solution/pp_ws.md) | Test cases on what the PID Provider receives from and issues to a Wallet Unit: metadata, offer, credential endpoint, client and key attestation, proofs, validity, revocation, the PID data model |
| [(pp_rp) Relying Party](pcaf/suts/pid_provider/relying_party/pp_rp.md) | Test cases on the status lists a PID Provider publishes for Relying Parties |
| [Attestation Provider (SUT)](pcaf/suts/attestation_provider/index.md) | Overview, test classes, the category variants `Q`, `PB` and `E`, the decisions applied |
| [(ap_ws) Wallet Solution](pcaf/suts/attestation_provider/wallet_solution/ap_ws.md) | Test cases on what a QEAA, PuB-EAA or non-qualified EAA Provider receives from and issues to a Wallet Unit, including configurations that are not device-bound, revocation chaining by policy and the rulebook of the attestation |
| [Defaults: PID Provider testing](pcaf/defaults.md#pid-provider-testing) | Test roles, trust configuration, Wallet Units and subjects, `default_configuration_PP_1`, expected result codes |
| [ICS (PID and Attestation Provider)](pcaf/ics-issuer.md) | The Provider ICS items and the profiles they select |
| [Relying Party suite](rp/index.md) | The Relying Party suite, its catalogue and harness design, and EUDIPLO as reference verifier with its ICS and known findings |
| [Issuer suite](issuer/index.md) | The issuer suite, its catalogue and harness design, and EUDIPLO as reference issuer with its ICS and known findings |

The [framework pages](pcaf/introduction.md) (introduction, methodology, using the framework, defaults) are those of the FCAF, rewritten for these SUTs. The FCAF's Wallet Solution pages are not part of this site.

## The harness

The test cases are rendered from executable definitions. The [harness](https://github.com/cre8/rp-conformance) runs them unattended against a Relying Party or a PID Provider through an adapter: a Conformance Wallet, status list and trust list servers, and an artifact forge that injects exactly one fault per test step, both over redirects and over the W3C Digital Credentials API; for a PID Provider an issuance client with a Test Wallet Provider and a Test Registrar. The [README](https://github.com/cre8/rp-conformance#readme) shows how to run it, and each suite has its test catalogue, which traces every test objective to the ARF, and its harness design: [Relying Party suite](rp/index.md), [issuer suite](issuer/index.md).

## Licence

[EUPL-1.2](https://github.com/cre8/rp-conformance/blob/main/LICENSE). The FCAF content is © European Union, under the same licence.
