# Systems Under Test (SUTs)

Functional conformance testing is organised around **Systems Under Test (SUTs)**.
A SUT defines a logical system boundary for which functional requirements can be assessed in a controlled and repeatable way.

The PCAF defines three SUTs, the peers of a Wallet Unit:

| SUT | What is tested | Test classes |
| --- | --- | --- |
| [Relying Party](relying_party/index.md) | The Relying Party Instance(s) and the back end that decides whether a presentation is accepted: what it requests, and what it must accept and reject | `RP_WS`, `RP_PP`, `RP_Inf` (`RP_AP` reserved) |
| [PID Provider](pid_provider/index.md) | The Credential Issuer and Authorization Server, the PIDs it issues and the status information it publishes | `PP_WS`, `PP_RP`, `PP_Inf` |
| [Attestation Provider](attestation_provider/index.md) | The same for a QEAA Provider, a PuB-EAA Provider or a non-qualified EAA Provider, in the category variants `Q`, `PB` and `E` | `AP_WS`, `AP_RP`, `AP_Inf` |

The Relying Party SUT is a proposal for the classes the FCAF methodology reserves for Relying Parties. The PID Provider and Attestation Provider SUTs are drafts: the FCAF methodology names these SUTs but reserves no test classes for them yet.

The Wallet Solution is the SUT of the [FCAF](https://conformance.eudi.dev) and is not repeated here.
