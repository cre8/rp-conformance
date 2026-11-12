# Relying Party conformance

!!! warning "Unofficial draft"

    This site is not published or endorsed by the European Commission. It shows the Functional Conformance Assessment Framework (FCAF), as on its `submitted` branch at commit `@FCAF_SUBMITTED@`, with a proposed **Relying Party** System Under Test added. The official FCAF is at [conformance.eudi.dev](https://conformance.eudi.dev).

The FCAF tests only the Wallet Solution. This project adds the tests a Relying Party must pass: a service that requests and verifies PIDs and attestations from Wallet Units. The focus is on what it must reject: expired credentials, revoked or suspended credentials, unusable status lists, wrong trust anchors, stale trust lists, faulty response encryption.

## Where to start

| Page | Content |
| --- | --- |
| [Relying Party (SUT)](fcaf/suts/relying_party/index.md) | Overview, test classes, the decisions applied |
| [(rp_ws) Wallet Solution](fcaf/suts/relying_party/wallet_solution/rp_ws.md) | Test cases on what the Relying Party receives from a Wallet Unit: validity, revocation, trust, session encryption |
| [(rp_pp) PID Provider](fcaf/suts/relying_party/pid_provider/rp_pp.md) | Test cases on the Status List Tokens and identifier lists of a PID Provider |
| [Defaults: Relying Party testing](fcaf/defaults.md#relying-party-testing) | Test roles, verification result, default configuration, credentials and queries |
| [ICS (Relying Party)](fcaf/ics-rp.md) | Capabilities, policies, time values and surrogate technology items a Relying Party declares |

Everything else is the FCAF itself; of its pages only the defaults, the references, the navigation and the SUT overview are extended.

## The harness

The test cases are rendered from executable definitions. The [harness](https://github.com/cre8/rp-conformance) runs them unattended against a Relying Party through an adapter: a Conformance Wallet, status list and trust list servers, and an artifact forge that injects exactly one fault per test step, both over redirects and over the W3C Digital Credentials API. The [README](https://github.com/cre8/rp-conformance#readme) shows how to run it, the [test catalogue](https://github.com/cre8/rp-conformance/blob/main/rp-test-catalogue.md) traces every test objective to the ARF, and the [harness design](https://github.com/cre8/rp-conformance/blob/main/harness-design.md) describes its parts.

## Licence

[EUPL-1.2](https://github.com/cre8/rp-conformance/blob/main/LICENSE). The FCAF content is © European Union, under the same licence.
