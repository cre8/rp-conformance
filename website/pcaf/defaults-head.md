# Default items

The following sections define the configurations, test roles, credentials and trust anchors used throughout the test case specifications.
These definitions are intentionally logical rather than physical: they describe the required structures and characteristics, but not specific values. The tester or test tooling supplies concrete values for test execution.

## Test trust establishment

Tests are designed to run in a controlled environment. The PCAF assumes that this environment is separate from production and that all aspects of it can be controlled.
A separate environment is necessary to control which systems in the ecosystem are trusted. Functional testing includes tests with explicitly trusted and untrusted systems, as well as unsuccessful flows, or negative test cases, so control of trust relationships is essential. Production trust infrastructure cannot support this because its policies do not allow trust in test systems that intentionally produce incorrect data.
A controlled environment also prevents external changes from influencing or disrupting testing.

To establish trust for tests, and explicit non-trust for negative tests, the trust configurations below describe the trusted lists, trust lists and certificate hierarchies of the test environment, logically. Testers and test tools supply specific instances of them. The tests assume that the SUT has loaded them, or can download them, as its default configuration states.

## Default credentials

### `default_credential_A`

The attestation of the test cases that need one that is not a PID, as defined by the FCAF: a Credential, specifically an EAA, in both mdoc and SD-JWT VC format. The Credential is issued by `Issuer A`. It may be any type of Credential, identified by an mdoc `doctype` or an SD-JWT VC `vct`. The Relying Party test cases use it as QEAA, PuB-EAA and non-qualified EAA (`default_credential_qeaa`, `default_credential_pubeaa`, `default_credential_eaa` below), and an Attestation Provider issues it as its attestation.

The Credential has at least the following Attributes:

| Attribute | Type | Value |
| --- | --- | --- |
| `attribute_A` | numerical | positive number |
| `attribute_B` | string | non-empty string consisting of Latin-1 characters, with a maximum length of 64 characters |
| `attribute_C` | date | valid date in the past |
