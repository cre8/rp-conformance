## Relying Party testing

The following items apply when the System Under Test is a Relying Party: the Relying Party Instance(s) together with the back end that decides whether a presentation is accepted.

### Test roles

| Role | Function |
| --- | --- |
| Conformance Wallet | Acts as Wallet Unit. Receives the Relying Party's Authorization Request and sends Authorization Responses that are valid, or valid except for the deviation a test step defines. For presentations via the W3C Digital Credentials API it is available to the browser as a credential provider, or the tester injects its response at the browser API. |
| Test Issuers | Issue the credentials of the test cases, including the variants a test step defines. A credential *issued by* an entity is signed by a certificate under that entity's issuance anchor in `default_trust_configuration_rp`; the signing certificate and any intermediate certificates, without the anchor, are carried in `x5c` (SD-JWT VC) or `x5chain` (mdoc). The status list such a credential references is signed under the revocation anchor of the same entity, unless a test step states otherwise. |
| Test Status Provider | Serves status lists and identifier lists with controllable content, signature and lifetime, and logs every request it receives. |
| Test Trust Infrastructure | Publishes the lists of `default_trust_configuration_rp` and new versions of them, and logs every retrieval. |

### Verification result

The verification result is the outcome the Relying Party hands to the relying service for a transaction: success with the released attributes, or failure. The Relying Party declares in its ICS how a tester reads it. For automated execution this is an API or a webhook. An HTTP status 4xx at the endpoint receiving the Authorization Response also counts as a reported failure. Where the result can only be observed in a user interface, the tester records evidence of it, for example a screenshot.

A Relying Party *accepts* a presentation when its verification result reports success and releases exactly the requested attributes with the values of the presented credential. It *rejects* a presentation when its verification result reports a failure and releases no attribute value from the presentation, and the endpoint receiving the Authorization Response does not answer with HTTP status 5xx.

### `default_configuration_rp_1`

| Property | Setting, contents, or value |
| --- | --- |
| Deployment | The Relying Party Instance(s) and back end run in the controlled environment and are reachable by the Conformance Wallet over TLS with a certificate the Conformance Wallet trusts. |
| Registration | The Relying Party holds an access certificate issued by `AC-A` and a registration certificate issued by `RC-A` for its service. The registration certificate lists the attributes of every default query the Relying Party uses. |
| Trust | The Relying Party has loaded `default_trust_configuration_rp` and no other trust anchors. |
| Presentation trigger | The tester can start a presentation for a given default query. |
| Verification result | The tester can read the verification result of every transaction, as declared in the ICS. |
| Status list cache | Empty at the start of each test case. |
| Clock | Synchronised with the time source of the test environment. The clock tolerance `T_skew` and the freshness window `T_kb` for key binding JWTs and device authentication are those declared in the ICS, each at most 300 seconds. |
| Network connectivity | The Relying Party can reach the Test Status Provider and the Test Trust Infrastructure. |

### `default_trust_configuration_rp`

The test environment defines every root of trust, so that each test case has exactly one correct outcome. The Relying Party is configured with the scheme operator certificates of the test lists only, the test counterpart of the publication of trust anchors in the Official Journal, and derives everything else from the lists. Where other specifications allow wider choices, for example [Token Status List] section 11.3, this configuration decides.

| Purpose | Root of trust |
| --- | --- |
| The lists themselves | The scheme operator certificates of `TL-PID`, `TL-PUB`, `TL-WP`, `TL-AC` and `TL-RC`; the signing certificates of the test list of trusted lists that points to `TL-QEAA`. |
| Signing a PID | An anchor under the PID/Issuance service of an entity in `TL-PID`. |
| Signing a QEAA | An anchor of a granted qualified service for the issuance of QEAAs in `TL-QEAA`. |
| Signing a PuB-EAA | An anchor under the issuance service of an entity in `TL-PUB`. |
| Signing a non-qualified EAA | The anchor `CA-EP-A` that the rulebook of `default_credential_eaa` defines. |
| Signing a status list or identifier list | An anchor under the revocation service of the same entity whose issuance anchor validated the credential, in the same list. An entity that signs its status lists with its issuance key publishes that CA under both services. For a QEAA, the anchor of the granted qualified service that validated the credential, since [ETSI TS 119 612] defines no service type for the revocation status of attestations. For a non-qualified EAA, the anchor its rulebook defines for status lists (`CA-EP-A`). |
| Signing a request (access certificate) | An anchor in `TL-AC`. |
| Signing a registration certificate | An anchor in `TL-RC`. |

A signer is trusted for a purpose only if its certificate chain ends in an anchor this configuration defines for that purpose and, where stated, for that entity. A valid chain to an anchor defined for another purpose, another entity or another list is not trusted.

| Entity | List | Services and anchors |
| --- | --- | --- |
| `PP-A` | `TL-PID` | PID/Issuance with anchor `CA-PP-A`; PID/Revocation with the separate anchor `CA-PP-A-REV`; both granted. |
| `PP-B` | `TL-PID` | PID/Issuance and PID/Revocation, both with the anchor `CA-PP-B`; granted. |
| `PP-C` | none | Not listed. Test cases add it to `TL-PID`. |
| `PP-D` | `TL-PID` | Like `PP-B`. Test cases remove it from `TL-PID`. |
| `PP-E` | `TL-PID` | Like `PP-B`, but the anchor certificate has expired. |
| `PP-W` | `TL-PID` | PID/Revocation with the anchor `CA-PP-W`; granted. Its PID/Issuance service, under the same anchor, is withdrawn and therefore not listed, since [ETSI TS 119 602] Annex D gives PID Providers lists no service status. |
| `QP-A` | `TL-QEAA` | Granted qualified service for the issuance of QEAAs with the anchor `CA-QP-A`, under which it also signs its status lists. |
| `QP-N` | `TL-QEAA` | Like `QP-A`, but the issuance service is not qualified. |
| `QP-W` | `TL-QEAA` | Like `QP-A`, with the qualified service for the issuance of QEAAs withdrawn. |
| `PB-A` | `TL-PUB` | Issuance and revocation services, both with the anchor `CA-PB-A`; granted. |
| `EP-A` | none | Signs under `CA-EP-A`, the anchor its rulebook defines; its status lists are signed under the same anchor. |
| `WP-A` | `TL-WP` | Wallet Provider with issuance and revocation services. |
| `AC-A` | `TL-AC` | Access Certificate Authority that issued the Relying Party's access certificate. |
| `RC-A` | `TL-RC` | Provider of registration certificates that issued the Relying Party's registration certificate. |
| `CA-X` | none | Self-signed CA on no list. |

| List | Content |
| --- | --- |
| `TL-PID` | List of trusted entities per [ETSI TS 119 602] of type PID Providers list. |
| `TL-PUB` | List of trusted entities of PuB-EAA Providers. |
| `TL-WP` | List of trusted entities of Wallet Providers. |
| `TL-AC` | List of trusted entities of Access Certificate Authorities. |
| `TL-RC` | List of trusted entities of Providers of registration certificates. |
| `TL-QEAA` | Test Trusted List per [ETSI TS 119 612], reached through a test list of trusted lists. |

### `default_credential_pid`

A PID per the [PID rulebook], available in SD-JWT VC and in mdoc format, as each test case states.

| Property | Setting, contents, or value |
| --- | --- |
| Issuer | Issued by `PP-A`. |
| Device binding | Bound to a key of the Conformance Wallet: `cnf` with a `jwk` (SD-JWT VC) or `deviceKeyInfo` (mdoc). |
| Validity | Valid at the time of the test; validity period longer than 24 hours. |
| Revocation information | A status reference to a status list served by the Test Status Provider: the `status` claim with `status_list` (SD-JWT VC), or the `status` element with `status_list` in the MSO (mdoc). Unless a test case states otherwise, the status list holds 0x00 (VALID) at the credential's index and is signed under the revocation anchor of the entity that issued the credential, `CA-PP-A-REV` for `PP-A`. |
| Attributes | At least the family name, the given name and the birth date. |

### `default_credential_pid_short`

Like `default_credential_pid`, with a validity period shorter than 24 hours and without revocation information.

### `default_credential_qeaa`

`default_credential_A` issued by `QP-A` as a QEAA, device-bound and with revocation information as for `default_credential_pid`.

### `default_credential_pubeaa`

`default_credential_A` issued by `PB-A` as a PuB-EAA, device-bound and with revocation information as for `default_credential_pid`.

### `default_credential_eaa`

`default_credential_A` issued by `EP-A` as a non-qualified EAA under a rulebook that defines `CA-EP-A` as its trust anchor, device-bound and with revocation information as for `default_credential_pid`.

### `default_query_pid`

A DCQL query with one credential query for a PID in the credential format of the test case, requesting the family name, the given name and the birth date, with cryptographic holder binding required and without `trusted_authorities` unless a test case states otherwise.

### `default_query_qeaa`

A DCQL query with one credential query for `default_credential_qeaa`, requesting `attribute_A`, `attribute_B` and `attribute_C`.

### `default_query_pubeaa`

A DCQL query with one credential query for `default_credential_pubeaa`, requesting `attribute_A`, `attribute_B` and `attribute_C`.

### `default_query_eaa`

A DCQL query with one credential query for `default_credential_eaa`, requesting `attribute_A`, `attribute_B` and `attribute_C`.
