# Using the framework

This section explains how to use the PCAF to verify that a Relying Party, a PID Provider or an Attestation Provider meets the functional requirements of the EUDI Wallet ecosystem. It follows the guidance of the FCAF for the Wallet Solution, adapted to these Systems Under Test.
Its coverage is limited to functional requirements at the interfaces of the SUT: the protocols with which it interacts with Wallet Units and the trust infrastructure, the credential formats, and the checks it must perform. A production-ready and compliant Relying Party or Provider must meet many other requirements, which must be covered elsewhere.

## Audience

The PCAF is intended for:

- **Relying Parties** and vendors of verifier software;
- **PID Providers**, **QEAA Providers**, **PuB-EAA Providers**, **non-qualified EAA Providers** and vendors of issuer software;
- **laboratories and conformity assessment bodies (CABs)** testing these systems;
- the **supervisory bodies, registrars and Member States** responsible for them.

Wallet Providers testing a Wallet Solution use the [FCAF](https://conformance.eudi.dev).

## Structure

The PCAF consists of test case specifications, one set per System Under Test, and the material they share: the [methodology](index.md), the [defaults](defaults.md) and an Implementation Conformance Statement per kind of SUT.
Use of the PCAF is not mandatory. Anyone applying it may verify compliance with parts of it, or with the whole, by other methods.

## Test case specifications

The test case specifications describe methods for testing individual requirements in a form that can be executed directly or implemented in automated test tooling.
They do not prescribe specific test tools. Each test case typically covers a single requirement, and a negative test case typically a single deviation from a valid flow.

### Using the test case specifications

#### System under test

The PCAF has three Systems Under Test:

- a **Relying Party**: the Relying Party Instance(s) together with the back end that decides whether a presentation is accepted;
- a **PID Provider**: its Credential Issuer and Authorization Server, the credentials it signs, and the status lists and identifier lists it publishes;
- an **Attestation Provider**: the same for a QEAA Provider, a PuB-EAA Provider or a non-qualified EAA Provider.

The Wallet Solution is not a SUT of the PCAF.

The SUT is placed in a controlled environment. Peers that interact with the SUT in this environment must send specific messages and capture responses from the SUT. For these SUTs the peers are test tools:

- for a Relying Party, a **Conformance Wallet** that acts as Wallet Unit, **Test Issuers** that issue the presented credentials, a **Test Status Provider** and a **Test Trust Infrastructure**;
- for a Provider, a **Conformance Wallet** that runs the issuance, a **Test Wallet Provider** that issues its Wallet Instance Attestations and key attestations, a **Test Registrar** and a **Test Trust Infrastructure**, and a reference validator that checks what the Provider returns.

The [defaults](defaults.md) define these roles. The SUT is considered a black box and is tested without assumptions about, or required knowledge of, its inner workings.

The controlled environment is essential to ensure that findings are objective, reproducible, and directly attributable to the SUT.
Most of its implications are left to the tester or a certification scheme. The following list provides non-exhaustive examples:

- fixed versions of the SUT's software and of the components it depends on, such as its runtime, database and libraries;
- stable network connectivity, including known and correctly functioning routing, time and DNS services, and a TLS certificate for the SUT that the test tools trust;
- test keys and test trust anchors for the trust infrastructure, the issuers and the Wallet Provider, loaded in the SUT in place of production ones. Negative test cases need peers that deliberately produce incorrect data, which production systems with production keys cannot do;
- testing each deployment configuration the SUT supports, for example each presentation flow of a Relying Party, or each credential format and grant of a Provider.

More information on conformance testing is available in the ISO/IEC 9646 series.

#### Implementation Conformance Statement (ICS)

The implementer of a SUT can make choices about many features. Some functionality is optional under the eIDAS Regulation and related legislation; other features are recommended or optional in the underlying standards and technical specifications. When a feature is implemented, specific requirements often apply to it.

In addition to supported features, other implementation choices must be known when testing. These include:

- the presentation flows a Relying Party supports, or the credential formats and grants a Provider supports;
- policies the requirements leave to the SUT, for example what a Relying Party does with a QEAA whose status cannot be obtained, or whether an Attestation Provider revokes its attestations with the Wallet Unit;
- time values such as clock tolerances, freshness windows and the time within which a revocation is published;
- how a tester reads the outcome of a transaction, for example the verification result of a Relying Party;
- deployment names and identifiers that may occur in items such as certificates and protocol messages.

As a result, not all test cases apply to every SUT. To capture these choices, the implementer completes the [Relying Party ICS](ics-rp.md) or the [PID and Attestation Provider ICS](ics-issuer.md).
A completed ICS selects the test cases that apply: the `Profile applicability` section of a test case is matched against it. Other ICS items provide input for test execution, such as the queries to request or the time values to use.

If a SUT supports multiple deployment settings or configurations, each matching a different ICS, the tester is responsible for executing the tests for every valid configuration. A SUT must conform to its ICS, because the ICS defines which requirements are relevant and what is tested.

#### Test preparation

Before testing, the SUT is deployed in the controlled environment and set up as a default configuration defines: `default_configuration_rp_1` for a Relying Party, `default_configuration_PP_1` for a PID or Attestation Provider. Most test cases start from it, and any deviation is listed explicitly in their preconditions. The tester must also set up the SUT to match its ICS.

Trust must be established in both directions: the SUT must trust the test systems acting as peers, and the test systems must trust the SUT. For a Relying Party this means loading the test trust configuration and providing it with an access certificate and a registration certificate from the test environment. For a Provider it means enrolling it with the Test Registrar and the test trust infrastructure, so that its signers are published under a test anchor, and letting it trust the Test Wallet Provider. Trust anchors, cryptographic keys, certificates or specific identifiers may need to be loaded into both the SUT and the test systems.

#### Test execution

Tests are designed to be independent of the tools used. They can be fully automated by specialised tooling or executed manually by a tester who crafts the messages of the peers.

Whether automated or manual, the tester starts each transaction at the SUT and plays the peers: for a Relying Party the tester triggers a presentation for a given query and answers it as the Wallet Unit, for a Provider the tester obtains a credential offer, or starts an authorization, and runs the issuance as the Wallet Unit. The test specifications describe the steps in functional terms, and the tester maps them to the SUT, for example through an API or an administration interface that the ICS names.

Test case specifications include preconditions, a test scenario and expected results. The tester must ensure that the preconditions are met, execute the steps in the test scenario, and observe and evaluate the expected results. A negative test case usually requires that its positive control passed in the same environment, so that a rejection is attributable to the one deviation the test step applies and not to the environment.

The configuration should not change during test execution. If a change to the SUT or the environment is necessary to continue a test or to obtain a passing result, the test should be considered failed for the specific ICS or configuration.

Practical concerns may impede test execution. For example, a Provider may require user authentication of the test subject before it issues a PID, or a Relying Party may show its verification result only in a user interface. How to handle such situations, including whether a workaround poses a compliance risk to the final solution, is outside the scope of the PCAF. Where the ICS has an item for it, such as how the verification result is read or which test subject a Provider knows, the tester follows the declared answer.

#### Test completion

Not all test case specifications describe a use case to its end. When the end of a test scenario is reached and all expected results have been evaluated, the tester may complete the use case.
The PCAF defines test case specifications, not a certification scheme, so it does not include reporting instructions. The tester is responsible for recording test execution, results and findings. Tests are designed to have one of three outcomes:

- Not applicable. If a test case has a `Profile applicability` condition that is not met by the ICS, the test is not applicable to the SUT.
- Test pass. The SUT passes the test, and is therefore compliant with the tested requirement, if the test scenario can be completed and all expected results are met.
- Test fail. If the SUT does not pass an applicable test, the test fails.

Automated tooling may report a fourth outcome, inconclusive, when the environment prevented a verdict, for example because the positive control failed. An inconclusive test has to be repeated; it is neither a pass nor a fail.

A SUT that passes all applicable tests complies with all tested requirements. This does not automatically mean that the SUT is fully compliant: other requirements, particularly non-functional ones, must also be assessed. Certification or another declaration of compliance is outside the scope of the PCAF.

After completing a test, the tester should return the SUT to a neutral state before the next test, for example by clearing the status list cache of a Relying Party, or by using a fresh test subject or Wallet Unit for a Provider where a credential or an offer can be used only once.
