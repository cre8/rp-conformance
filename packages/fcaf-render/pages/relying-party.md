# Relying Party (SUT)

The **Relying Party** System Under Test covers a service provider interacting with Wallet Units to request and verify attributes from PIDs and attestations: the Relying Party Instance(s) together with the back end that decides whether a presentation is accepted. In line with the [Methodology](../../index.md), Attestation Providers are not part of this SUT.

The Relying Party is tested as a black box in the controlled environment described in the [defaults](../../defaults.md). Peers acting as Wallet Unit, issuers, status providers and trust infrastructure send valid messages and deliberately faulty ones, and the tester reads the Relying Party's verification result. The [Relying Party ICS](../../ics-rp.md) selects the applicable test cases.

## Test Classes within the Relying Party

- **RelyingParty_WalletSolution (RP_WS)**: presentation interface, including all checks the Relying Party performs on the presented credentials.
- **RelyingParty_PidProvider (RP_PP)**: retrieval and validation of status information published for PIDs.
- **RelyingParty_AttestationProvider (RP_AP)**: retrieval and validation of status information published for attestations. Not yet defined; the `RP_PP` test cases are expected to apply with the same numbers.
- **RelyingParty_Infrastructure (RP_Inf)**: retrieval and validation of trust lists. Not yet defined.

## Decisions applied in these test cases

- A Relying Party exposes its verification result so that a tester can read it; for automated execution through an API or a webhook.
- A PID without reliable revocation status information is rejected. For QEAA, PuB-EAA and non-qualified EAA the Relying Party applies the policy it declares in the ICS ([ARF] Annex 2, VCR_14).
- The test environment defines every root of trust per purpose in `default_trust_configuration_rp`, including which anchors may sign status lists.
- The clock tolerance and the freshness window for key binding JWTs and device authentication are each at most 300 seconds.
