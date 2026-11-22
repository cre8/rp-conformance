# Relying Party suite

The Relying Party suite tests a **Relying Party** as System Under Test: the service that requests and verifies PIDs and attestations from Wallet Units with OpenID4VP, over redirects and over the W3C Digital Credentials API. Every test case starts from a valid presentation, a negative test case applies exactly one named fault and runs only after its positive control passed, and every fault is proven against the reference verifier. The focus is on what a Relying Party must reject: expired, revoked or suspended credentials, unusable status lists, wrong trust anchors, stale trust lists, faulty response encryption.

## Test cases

The test cases are rendered from the executable definitions into an FCAF overlay: [Relying Party (SUT)](../pcaf/suts/relying_party/index.md), with the [Relying Party ICS](../pcaf/ics-rp.md) and the [defaults for Relying Party testing](../pcaf/defaults.md#relying-party-testing). A test case runs once per presentation flow the Relying Party declares.

## Documents

| Document | Content |
| --- | --- |
| [Test catalogue](rp-test-catalogue.md) | The test objectives for Relying Parties, traced to the ARF high-level requirements, with the test environment, the Relying Party ICS and the decisions taken |
| [Harness design](harness-design.md) | The Conformance Wallet, the status list and trust list servers, the artifact forge with fault injection, the Relying Party adapter, verdicts and delivery phases |

## Reference verifier and EUDIPLO

The suite has two references. The **reference verifier** is part of the harness and implements exactly what the test cases expect: every pull request runs all test cases against it, and a FAIL or an inconclusive result fails the build. It proves the test cases, not a product.

[EUDIPLO](https://github.com/EUDIPLO/eudiplo) is the reference product, through its adapter. A FAIL against it is analysed against the specifications before it is accepted as a finding of EUDIPLO.

| Page | Content |
| --- | --- |
| [ICS](eudiplo/ics.md) | EUDIPLO's answers to the Relying Party ICS, as the suite runs it |
| [Known findings](eudiplo/known-findings.md) | The FAILs reported as known findings, each with what it rests on: the specification EUDIPLO implements, or the EUDI profile only |
| [Upstream findings](eudiplo/upstream-findings/index.md) | The issue texts prepared for those findings, and suggestions that are not conformance findings |

A nightly job runs the suite against EUDIPLO's latest main image, before the issuer suite.
