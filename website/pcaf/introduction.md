# Introduction

The **Peer Conformance Assessment Framework (PCAF)** is a set of functional test cases for the systems that a Wallet Unit talks to in the EUDI Wallet ecosystem: **Relying Parties**, **PID Providers** and **Attestation Providers** (QEAA Providers, PuB-EAA Providers and non-qualified EAA Providers). From the Wallet Unit's point of view these are its peers, hence the name.

The PCAF is not a publication of the European Commission. It applies the method of the Commission's [Functional Conformance Assessment Framework (FCAF)](https://conformance.eudi.dev), which specifies test cases for the **Wallet Solution**, to the other side of the same interfaces. Its test cases use the FCAF test case format and the FCAF identifiers that the FCAF methodology reserves for these Systems Under Test, so they can be contributed to the FCAF. The Wallet Solution test cases are not repeated here; they are in the FCAF.

## Why test the peers

A certified Wallet Unit is only as useful as the systems it talks to. If a Relying Party accepts a revoked PID or trusts the wrong anchor, or a PID Provider issues a PID to a Wallet Unit whose attestation it did not check, the protection that the Wallet Unit provides is lost. Interoperability, too, depends on both sides: a Wallet Unit that implements OpenID4VP and OpenID4VCI as profiled for the EUDI Wallet can only rely on its peers if they implement the same profile.

The FCAF covers the Wallet Solution, which is certified under [Commission Implementing Regulation (EU) 2024/2981](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202402981). Its peers have their own obligations, for example under [CIR (EU) 2024/2977](https://eur-lex.europa.eu/eli/reg_impl/2024/2977/oj) on PID and electronic attestations of attributes, [CIR (EU) 2024/2982](https://eur-lex.europa.eu/eli/reg_impl/2024/2982/oj) on protocols and interfaces and [CIR (EU) 2025/848](https://eur-lex.europa.eu/eli/reg_impl/2025/848/oj) on the registration of wallet-relying parties, and the Architecture and Reference Framework [ARF] states the high-level requirements for each of them. There is, however, no common set of functional test cases for them. Public test suites test a Relying Party or a Provider mostly on the happy flow, and what a peer must **reject** has no public test: expired, revoked or suspended credentials, unusable status lists, wrong trust anchors, stale trust lists, faulty response encryption, invalid Wallet Instance Attestations, key attestations and proofs.

## Audience

- **Relying Parties** and vendors of verifier software, to test their implementation before they go live and after each change.
- **PID Providers**, **QEAA Providers**, **PuB-EAA Providers**, **non-qualified EAA Providers** and vendors of issuer software, likewise.
- **Conformity assessment bodies and test laboratories** that assess a Provider, for example a qualified trust service provider issuing QEAA, or that test Relying Parties for a scheme.
- **Supervisory bodies, registrars and Member States** that notify PID Providers or register Relying Parties, as a common reference for what such a system must do.
- **Wallet Providers**, to know what they may expect from their peers. The Wallet Solution itself is tested with the FCAF, not here.

## Scope

The PCAF covers the **functional and functional-security requirements** of its Systems Under Test that are observable at their interfaces:

- a Relying Party: the presentation interface to Wallet Units (OpenID4VP over redirects and over the W3C Digital Credentials API, SD-JWT VC and mdoc), the status information it retrieves from PID and Attestation Providers, and the trust lists it retrieves;
- a PID Provider or an Attestation Provider: the issuance interface to Wallet Units (OpenID4VCI metadata, offers and endpoints, and the checks on Wallet Instance Attestations, key attestations and proofs), the credentials it issues, the status information it publishes for Relying Parties, and its use of the trust infrastructure.

Each System Under Test is tested as a black box, in a controlled environment in which the test tooling plays every peer: a Conformance Wallet, Test Issuers, a Test Wallet Provider, a Test Registrar, status providers and trust infrastructure. Every test case starts from a flow that succeeds, and a negative test case changes exactly one thing in it.

## Out of scope

As the FCAF, the PCAF addresses functional conformance only. It does **not** cover:

- the Wallet Solution, which the FCAF covers;
- cybersecurity assurance, such as resistance to attacks, vulnerability management or secure development;
- procedural or operational assurance, such as organisational controls, lifecycle governance, incident handling or monitoring, and the registration and notification procedures themselves;
- privacy and data protection assurance, except where a requirement is expressed as functional behaviour at an interface, for example a Relying Party requesting only the attributes it is registered for;
- non-functional testing, such as performance, scalability, availability or penetration testing.

Passing the PCAF test cases is not a certification or a declaration of compliance. It shows that a system behaves as the tested requirements state.

## Elements

The PCAF consists of:

- the [methodology](index.md): Systems Under Test, test classes, layers and the test case format, as in the FCAF;
- [guidance on using the framework](using-pcaf.md): system under test, ICS, preparation, execution and outcomes;
- the [defaults](defaults.md): test roles, trust configurations, credentials and configurations shared by the test cases;
- the test cases of each [System Under Test](suts/index.md), each traced to the requirements it tests;
- an Implementation Conformance Statement (ICS) for [Relying Parties](ics-rp.md) and for [PID and Attestation Providers](ics-issuer.md).

The test cases are tool-agnostic and can be executed manually. They are also rendered from executable definitions, and an [open-source harness](https://github.com/cre8/rp-conformance) runs them unattended.
