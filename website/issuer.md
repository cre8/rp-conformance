# Issuer suite

The issuer suite tests a **PID Provider** or an **Attestation Provider** (QEAA, PuB-EAA or non-qualified EAA Provider) as System Under Test: the Credential Issuer and Authorization Server it runs for OpenID4VCI, the credentials it issues and the status information it publishes. It follows the method of the Relying Party suite: every test case starts from a valid issuance, a negative test case applies exactly one named fault and runs only after its positive control passed, and every fault is proven against the reference validator. An Attestation Provider runs every objective that is not specific to the PID, in the category variant `Q`, `PB` or `E`, and the objectives specific to Attestation Providers.

## Test cases

The test cases are rendered from the executable definitions into a second FCAF overlay, next to the Relying Party one: [PID Provider (SUT)](../pcaf/suts/pid_provider/index.md) and [Attestation Provider (SUT)](../pcaf/suts/attestation_provider/index.md), with the [Provider ICS](../pcaf/ics-issuer.md) and the [defaults for PID Provider testing](../pcaf/defaults.md#pid-provider-testing). A test case runs once per variant the Provider declares (credential format, grant and, for an Attestation Provider, its category); its page shows the variants together.

## Documents

| Document | Content |
| --- | --- |
| [Test catalogue](issuer-test-catalogue.md) | The test objectives for PID Providers and Attestation Providers, traced to the ARF high-level requirements, with the test environment, the Provider ICS and the decisions taken |
| [Harness design](issuer-harness-design.md) | What the issuer suite reuses from the Relying Party harness, the issuance client, Test Wallet Provider and Test Registrar, the issuer adapter, faults, expected results and delivery phases |

## EUDIPLO as reference issuer

The test cases are proven against [EUDIPLO](https://github.com/EUDIPLO/eudiplo) as reference PID Provider and, with one tenant per category, as reference Attestation Provider, through its issuer adapter, at a pinned image. A FAIL against it is analysed before it is accepted as a finding of EUDIPLO; such a test case is marked not validated until EUDIPLO is fixed.

| Page | Content |
| --- | --- |
| [Adapter](eudiplo/index.md) | The pinned image, what the adapter configures, what the image still lacks and the test cases it leaves not validated |
| [ICS](eudiplo/ics.md) | EUDIPLO's answers to the Provider ICS, as the suite runs it |
| [Known findings](eudiplo/known-findings.md) | The FAILs reported as known findings, with the test cases and variants they concern |
| [Upstream findings](eudiplo/upstream-findings/index.md) | The issue texts prepared for those findings |

Every pull request that touches the issuer suite runs it against the pinned image; a nightly job runs it against EUDIPLO's latest main image, after the Relying Party suite.
