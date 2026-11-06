"""Baseline test case definitions for the Relying Party SUT (FCAF format)."""

REL = {
    "GR": "EUDI_generic | EUDI_required",
    "GO": "EUDI_generic | EUDI_optional",
    "GU": "EUDI_generic | EUDI_undefined",
    "SR": "EUDI_specific | EUDI_required",
    "SO": "EUDI_specific | EUDI_optional",
}

FMT = {
    "SD": dict(
        letter="a",
        name="SD-JWT VC",
        prof="Relying Party requests credentials in IETF SD-JWT VC format.",
        tech="Presentation of a credential in IETF SD-JWT VC format.",
    ),
    "MD": dict(
        letter="b",
        name="mdoc",
        prof="Relying Party requests credentials in ISO/IEC 18013-5 mdoc format.",
        tech="Presentation of a credential in ISO/IEC 18013-5 mdoc format.",
    ),
}
FLOW = {
    "RD": dict(
        letter="a",
        prof="Relying Party supports presentations via redirects.",
        tech="Presentation via redirects with response mode `direct_post.jwt`.",
        via="via redirects",
    ),
    "DC": dict(
        letter="b",
        prof="Relying Party supports presentations via the W3C Digital Credentials API.",
        tech="Presentation via the W3C Digital Credentials API with response mode `dc_api.jwt`.",
        via="via the W3C Digital Credentials API",
    ),
}
SLT = {"SD": "Status List Token in JWT format.", "MD": "Status List Token in CWT format."}
REV = "Relying Party checks the revocation status of PIDs."
SKEW = "Relying Party applies a clock tolerance greater than zero."
P_QEAA = "Relying Party requests QEAAs."
P_PUB = "Relying Party requests PuB-EAAs."
P_EAA = "Relying Party requests non-qualified EAAs."
P_TA = "Relying Party uses `trusted_authorities` in DCQL queries."

PID = "`default_credential_pid`"
QPID = "`default_query_pid`"

PRE_BASE = [
    "The Relying Party is set to `default_configuration_rp_1`.",
    "The test environment publishes `default_trust_configuration_rp`, and the Relying Party has loaded it.",
]
PRE_STATUS = (
    "Every credential presented in this test case references a status list URI from which "
    "the Relying Party has not retrieved a status list before."
)

REJ = (
    "The Relying Party rejects the presentation: its verification result reports a failure and "
    "releases no attribute value from the presentation, and the endpoint receiving the "
    "Authorization Response does not answer with HTTP status 5xx."
)
NOFETCH = (
    " The Test Status Provider logs no request from the Relying Party for the status list "
    "referenced by the credential."
)
FETCHED = (
    " The Test Status Provider has logged a request from the Relying Party for the status list "
    "referenced by the credential."
)


def acc(cred="the presented credential", query=QPID):
    return (
        "The Relying Party accepts the presentation: its verification result reports success and "
        f"releases exactly the attributes requested in {query}, with the values of {cred}."
    )


def control(fmt):
    return f"Test case `RP_WS_IA_MainInteraction_001{FMT[fmt]['letter']}` passed in the same environment."


def valid_step(cred=PID, query=QPID, extra=""):
    return (
        f"Perform a presentation for {query} in which the Conformance Wallet presents {cred} "
        f"in a valid Authorization Response{extra}."
    )


def cred_step(diff, cred=PID, query=QPID):
    return (
        f"Perform a presentation for {query} in which the Conformance Wallet presents, in an "
        f"otherwise valid Authorization Response, a variant of {cred} that differs from it only "
        f"in that {diff}."
    )


def status_value_step(value):
    return (
        f"Perform a presentation for {QPID} in which the Conformance Wallet presents {PID} in a "
        f"valid Authorization Response, while the status list referenced by the credential holds "
        f"the value {value} at the credential's index."
    )


def slt_step(diff):
    return (
        f"Perform a presentation for {QPID} in which the Conformance Wallet presents {PID} in a "
        "valid Authorization Response, while the Test Status Provider serves, for the status list "
        "referenced by the credential, a Status List Token that holds the value 0x00 at the "
        f"credential's index and is valid in every other respect, except that {diff}."
    )


def enc_step(flow, diff):
    return (
        f"Perform a presentation for {QPID} {FLOW[flow]['via']} in which the Conformance Wallet "
        f"presents {PID} in an Authorization Response that is valid except that {diff}."
    )


FLOW_COMMENT = (
    "Execute this test case once for each presentation flow the Relying Party supports "
    "(redirects, W3C Digital Credentials API)."
)
NOSTAT_COMMENT = (
    "A Status List Token that cannot be used leaves no reliable revocation status. For PIDs the "
    "Relying Party SUT rejects the presentation in that case; for QEAA, PuB-EAA and "
    "non-qualified EAA the policy declared in the ICS applies (see [ARF] Annex 2, VCR_14)."
)

TESTS = []


def add(**t):
    t.setdefault("comments", [])
    t.setdefault("pre", [])
    t.setdefault("tech", [])
    TESTS.append(t)


def tid(cls, layer, area, num, letter="", uf=False):
    return f"RP_{cls}_{layer}_{area}_{num:03d}{letter}" + ("_UF" if uf else "")


# --------------------------------------------------------------------------- IA_MainInteraction

for fmt in ("SD", "MD"):
    f = FMT[fmt]
    add(
        id=tid("WS", "IA", "MainInteraction", 1, f["letter"]),
        cls="WS", layer="IA", area="MainInteraction",
        objective=(
            f"Verify that the Relying Party accepts a valid presentation of a PID in {f['name']} "
            "format and releases exactly the requested attributes."
        ),
        refs=[
            "[ARF] Annex 2, " + ("OIA_03c, OIA_08a, OIA_12" if fmt == "SD" else "OIA_03b, OIA_08, OIA_12"),
            "[HAIP] section 5, " + ("6.1" if fmt == "SD" else "5.3.1"),
            "[OpenID4VP] section 8.6",
            "[CIR 2024/2982 amended] Annex II",
        ],
        profile=[f["prof"]],
        rel="SR",
        tech=[f["tech"]],
        pre=PRE_BASE,
        steps=[valid_step()],
        expected=[acc(PID)],
        comments=[
            "This test case is the positive control for the unhappy-flow test cases of the "
            f"Relying Party SUT that present a credential in {f['name']} format. When it fails, "
            "those test cases cannot produce a meaningful verdict in the same environment.",
            FLOW_COMMENT,
        ],
    )

# --------------------------------------------------------------------------- SM_Validity

SD_VALIDITY_REFS = [
    "[RFC9901] section 7.1",
    "[SD-JWT VC] section 2.4",
    "[OpenID4VP] section 8.6",
    "[CIR 2024/2982 amended] Annex II",
]
MD_VALIDITY_REFS = [
    "[ISO/IEC 18013-5] section 9.3.1",
    "[OpenID4VP] section 8.6",
    "[HAIP] section 5.3.1",
    "[CIR 2024/2982 amended] Annex II",
]

add(
    id=tid("WS", "SM", "Validity", 1, uf=True), cls="WS", layer="SM", area="Validity",
    objective="Verify that the Relying Party rejects a credential in SD-JWT VC format whose expiration time has passed.",
    refs=["[RFC7519] section 4.1.4"] + SD_VALIDITY_REFS,
    profile=[FMT["SD"]["prof"]], rel="GR", tech=[FMT["SD"]["tech"]],
    pre=PRE_BASE + [control("SD")],
    steps=[cred_step("its Issuer-signed JWT carries an `exp` claim set to the current time minus `T_skew` minus one hour")],
    expected=[REJ], comments=[FLOW_COMMENT],
)
add(
    id=tid("WS", "SM", "Validity", 2), cls="WS", layer="SM", area="Validity",
    objective=(
        "Verify that the Relying Party accepts a credential in SD-JWT VC format whose expiration "
        "time has passed by less than the declared clock tolerance."
    ),
    refs=["[RFC7519] section 4.1.4"] + SD_VALIDITY_REFS,
    profile=[FMT["SD"]["prof"], SKEW], rel="GR", tech=[FMT["SD"]["tech"]],
    pre=PRE_BASE + [control("SD")],
    steps=[cred_step("its Issuer-signed JWT carries an `exp` claim set to the current time minus half of `T_skew`")],
    expected=[acc()], comments=[FLOW_COMMENT],
)
add(
    id=tid("WS", "SM", "Validity", 3, uf=True), cls="WS", layer="SM", area="Validity",
    objective="Verify that the Relying Party rejects a credential in SD-JWT VC format that is not yet valid.",
    refs=["[RFC7519] section 4.1.5"] + SD_VALIDITY_REFS,
    profile=[FMT["SD"]["prof"]], rel="GR", tech=[FMT["SD"]["tech"]],
    pre=PRE_BASE + [control("SD")],
    steps=[cred_step("its Issuer-signed JWT carries an `nbf` claim set to the current time plus `T_skew` plus one hour")],
    expected=[REJ], comments=[FLOW_COMMENT],
)
for fmt in ("SD", "MD"):
    f = FMT[fmt]
    exp_diff = (
        "its Issuer-signed JWT carries an `exp` claim set to the current time minus `T_skew` minus one hour"
        if fmt == "SD"
        else "the `validUntil` value in the `validityInfo` of its MSO is set to the current time minus `T_skew` minus one hour"
    )
    add(
        id=tid("WS", "SM", "Validity", 5, f["letter"], uf=True), cls="WS", layer="SM", area="Validity",
        objective=(
            f"Verify that the Relying Party rejects an expired credential in {f['name']} format whose "
            "revocation status is VALID, without retrieving its status list."
        ),
        refs=["[Token Status List] section 7.1, 8.3", "[ARF] Annex 2, VCR_13"]
        + (SD_VALIDITY_REFS if fmt == "SD" else MD_VALIDITY_REFS)
        + ["[CIR 2024/2979 amended] Annex II"],
        profile=[f["prof"], REV], rel="GR", tech=[f["tech"]],
        pre=PRE_BASE + [control(fmt), PRE_STATUS,
                        "The status list referenced by the presented credential holds the value 0x00 (VALID) at the credential's index."],
        steps=[cred_step(exp_diff)],
        expected=[REJ + NOFETCH],
        comments=[
            "[Token Status List] section 8.3 requires the validation of the credential itself to "
            "precede any evaluation of its status, and states that status list procedures, such as "
            "fetching the Status List Token, must not be performed once the credential is found "
            "invalid, unless the use case requires further evaluation. Presenting a PID does not.",
            FLOW_COMMENT,
        ],
    )
    sig_diff = (
        "one bit of the signature value of its Issuer-signed JWT is flipped"
        if fmt == "SD"
        else "one bit of the signature value of its `IssuerAuth` structure is flipped"
    )
    add(
        id=tid("WS", "SM", "Validity", 6, f["letter"], uf=True), cls="WS", layer="SM", area="Validity",
        objective=(
            f"Verify that the Relying Party does not retrieve the status list of a credential in "
            f"{f['name']} format whose issuer signature is invalid."
        ),
        refs=["[Token Status List] section 8.3"]
        + (["[RFC9901] section 7.1"] if fmt == "SD" else ["[ISO/IEC 18013-5] section 9.3.1"])
        + ["[CIR 2024/2979 amended] Annex II"],
        profile=[f["prof"], REV], rel="GR", tech=[f["tech"]],
        pre=PRE_BASE + [control(fmt), PRE_STATUS],
        steps=[cred_step(sig_diff)],
        expected=[REJ + NOFETCH], comments=[FLOW_COMMENT],
    )

for num, diff, expected, objective in (
    (10, "the `validUntil` value in the `validityInfo` of its MSO is set to the current time minus `T_skew` minus one hour",
     REJ, "Verify that the Relying Party rejects a credential in mdoc format whose validity period has ended."),
    (11, "the `validFrom` value in the `validityInfo` of its MSO is set to the current time plus `T_skew` plus one hour",
     REJ, "Verify that the Relying Party rejects a credential in mdoc format whose validity period has not started."),
    (12, "the `expectedUpdate` value in the `validityInfo` of its MSO lies one day in the past, while `validUntil` lies in the future",
     acc(), "Verify that the Relying Party accepts a credential in mdoc format whose expected update time has passed while its validity period has not ended."),
):
    add(
        id=tid("WS", "SM", "Validity", num, uf=(expected == REJ)), cls="WS", layer="SM", area="Validity",
        objective=objective,
        refs=MD_VALIDITY_REFS if num != 12 else ["[ISO/IEC 18013-5] section 9.1.2.4"] + MD_VALIDITY_REFS,
        profile=[FMT["MD"]["prof"]], rel="GR", tech=[FMT["MD"]["tech"]],
        pre=PRE_BASE + [control("MD")],
        steps=[cred_step(diff)], expected=[expected], comments=[FLOW_COMMENT],
    )

# --------------------------------------------------------------------------- SM_Revocation (credential side)

REV_REFS_SD = [
    "[Token Status List] section 6.2, 7.1, 8.3",
    "[SD-JWT VC] section 2.4",
    "[HAIP] section 6.1",
    "[ARF] Annex 2, VCR_11a, VCR_13",
    "[CIR 2024/2979 amended] Annex II",
]
REV_REFS_MD = [
    "[Token Status List] section 6.3, 7.1, 8.3",
    "[ISO/IEC 18013-5 ed2]",
    "[HAIP] section 5.3.1",
    "[ARF] Annex 2, VCR_11, VCR_12, VCR_13",
    "[CIR 2024/2979 amended] Annex II",
]


def rev_refs(fmt):
    return REV_REFS_SD if fmt == "SD" else REV_REFS_MD


for fmt in ("SD", "MD"):
    f = FMT[fmt]
    L = f["letter"]
    base = dict(cls="WS", layer="SM", area="Revocation", profile=[f["prof"], REV], tech=[f["tech"]],
                pre=PRE_BASE + [control(fmt), PRE_STATUS])
    add(id=tid("WS", "SM", "Revocation", 1, L), **base, rel="SR",
        objective=f"Verify that the Relying Party accepts a PID in {f['name']} format whose revocation status is VALID.",
        refs=rev_refs(fmt), steps=[status_value_step("0x00 (VALID)")], expected=[acc(PID) + FETCHED],
        comments=[FLOW_COMMENT])
    add(id=tid("WS", "SM", "Revocation", 2, L, True), **base, rel="SR",
        objective=f"Verify that the Relying Party rejects a revoked PID in {f['name']} format.",
        refs=rev_refs(fmt), steps=[status_value_step("0x01 (INVALID)")], expected=[REJ],
        comments=["The OIDF verifier test module `oid4vp-1final-verifier-present-revoked-credential` covers the same objective.", FLOW_COMMENT])
    add(id=tid("WS", "SM", "Revocation", 3, L, True), **base, rel="SR",
        objective=f"Verify that the Relying Party rejects a suspended PID in {f['name']} format.",
        refs=rev_refs(fmt), steps=[status_value_step("0x02 (SUSPENDED)")], expected=[REJ],
        comments=[FLOW_COMMENT])
    add(id=tid("WS", "SM", "Revocation", 4, L, True), **base, rel="GU",
        objective=(
            f"Verify that the Relying Party does not treat an application-specific status value as VALID "
            f"for a PID in {f['name']} format, unless it declared a meaning for that value."
        ),
        refs=rev_refs(fmt), steps=[status_value_step("0x03 (application-specific)")],
        expected=[
            "If the Relying Party declares no meaning for the status value 0x03 in its ICS: " + REJ[0].lower() + REJ[1:]
            + " If it declares a meaning: it handles the presentation as declared."
        ],
        comments=[FLOW_COMMENT])

    if fmt == "SD":
        malformed = [
            "its `status.status_list` object has no `idx` member",
            "its `status.status_list` object has no `uri` member",
            "the `idx` member of its `status.status_list` object is -1",
            "the `idx` member of its `status.status_list` object is the string `7` instead of a number",
            "the `uri` member of its `status.status_list` object is the string `not a uri`",
        ]
    else:
        malformed = [
            "the `status_list` map in the `status` element of its MSO has no `idx` entry",
            "the `status_list` map in the `status` element of its MSO has no `uri` entry",
            "the `idx` entry of the `status_list` map in its MSO is -1",
            "the `idx` entry of the `status_list` map in its MSO is the text string `7` instead of an unsigned integer",
            "the `uri` entry of the `status_list` map in its MSO is the text string `not a uri`",
        ]
    add(id=tid("WS", "SM", "Revocation", 5, L, True), **base, rel="GR",
        objective=f"Verify that the Relying Party rejects a PID in {f['name']} format whose status reference is malformed.",
        refs=rev_refs(fmt), steps=[cred_step(d) for d in malformed], expected=[REJ] * len(malformed),
        comments=[NOSTAT_COMMENT, FLOW_COMMENT])
    add(id=tid("WS", "SM", "Revocation", 6, L, True), **base, rel="GR",
        objective=f"Verify that the Relying Party rejects a PID in {f['name']} format whose status index lies outside the status list.",
        refs=rev_refs(fmt),
        steps=[cred_step("the index in its status reference equals the number of entries in the referenced status list, one past the last valid index")],
        expected=[REJ], comments=[FLOW_COMMENT])
    add(id=tid("WS", "SM", "Revocation", 7, L), **base, rel="SR",
        objective=(
            f"Verify that the Relying Party accepts a PID in {f['name']} format without revocation "
            "information whose validity period is shorter than 24 hours."
        ),
        refs=rev_refs(fmt)[:-1] + ["[ARF] Annex 2, VCR_01, VCR_01b", "[CIR 2024/2979 amended] Annex II"],
        steps=[valid_step("`default_credential_pid_short`")], expected=[acc("`default_credential_pid_short`")],
        comments=["The OIDF verifier test module `oid4vp-1final-verifier-present-credential-without-status` covers the same objective.", FLOW_COMMENT])
    no_status = (
        "it carries no `status` claim" if fmt == "SD" else "its MSO carries no `status` element"
    )
    add(id=tid("WS", "SM", "Revocation", 8, L, True), **base, rel="SR",
        objective=(
            f"Verify that the Relying Party rejects a PID in {f['name']} format without revocation "
            "information whose validity period is longer than 24 hours."
        ),
        refs=rev_refs(fmt)[:-1] + ["[ARF] Annex 2, VCR_01, VCR_01b, VCR_14", "[CIR 2024/2979 amended] Annex II"],
        steps=[cred_step(no_status)], expected=[REJ],
        comments=[
            "A PID valid for longer than 24 hours must carry revocation information ([ARF] Annex 2, "
            "VCR_01 and VCR_01b). Without it no reliable revocation status is available, and the "
            "Relying Party SUT rejects PIDs in that case.",
            FLOW_COMMENT,
        ])

IDL_PRE = (
    "The `status` element of the MSO of every presented credential carries an `identifier_list` "
    "entry (`id`, `uri`) that references an identifier list in CWT format "
    "(`application/identifierlist+cwt`) served by the Test Status Provider."
)
add(id=tid("WS", "SM", "Revocation", 9, uf=True), cls="WS", layer="SM", area="Revocation", rel="SR",
    objective="Verify that the Relying Party rejects a PID in mdoc format whose identifier is listed in the referenced identifier list.",
    refs=REV_REFS_MD, profile=[FMT["MD"]["prof"], REV], tech=[FMT["MD"]["tech"], "Identifier list in CWT format."],
    pre=PRE_BASE + [control("MD"), PRE_STATUS, IDL_PRE],
    steps=[f"Perform a presentation for {QPID} in which the Conformance Wallet presents {PID} in a valid Authorization Response, while the referenced identifier list contains the credential's identifier."],
    expected=[REJ],
    comments=["The OIDF verifier test module `oid4vp-1final-verifier-present-credential-on-identifier-list` covers the same objective.", FLOW_COMMENT])
add(id=tid("WS", "SM", "Revocation", 10), cls="WS", layer="SM", area="Revocation", rel="SR",
    objective="Verify that the Relying Party accepts a PID in mdoc format whose identifier is not listed in the referenced identifier list.",
    refs=REV_REFS_MD, profile=[FMT["MD"]["prof"], REV], tech=[FMT["MD"]["tech"], "Identifier list in CWT format."],
    pre=PRE_BASE + [control("MD"), PRE_STATUS, IDL_PRE],
    steps=[f"Perform a presentation for {QPID} in which the Conformance Wallet presents {PID} in a valid Authorization Response, while the referenced identifier list does not contain the credential's identifier."],
    expected=[acc(PID) + " The Test Status Provider has logged a request from the Relying Party for the identifier list."],
    comments=[FLOW_COMMENT])

# --------------------------------------------------------------------------- RP_PP SM_Revocation (status list token)

SLT_REFS = {
    "SD": ["[Token Status List] section 5.1, 8.3", "[RFC7519] section 7.2"],
    "MD": ["[Token Status List] section 5.2, 8.3", "[RFC8392] section 7.2"],
}
PP_COMMON_REFS = ["[ARF] Annex 2, PPNot_05, VCR_13, VCR_14", "[ETSI TS 119 602]", "[CIR 2024/2979 amended] Annex II"]


def pp_refs(fmt, *extra):
    return SLT_REFS[fmt] + list(extra) + PP_COMMON_REFS


def x5(fmt):
    return "`x5c`" if fmt == "SD" else "`x5chain`"


for fmt in ("SD", "MD"):
    f = FMT[fmt]
    L = f["letter"]
    ftxt = "JWT" if fmt == "SD" else "CWT"
    base = dict(cls="PP", layer="SM", area="Revocation", profile=[f["prof"], REV], tech=[f["tech"], SLT[fmt]],
                pre=PRE_BASE + [control(fmt), PRE_STATUS])
    comments = [NOSTAT_COMMENT, FLOW_COMMENT]

    valid_desc = (
        "with `typ` `statuslist+jwt`, a `sub` claim equal to the credential's status `uri`, an `iat` claim, "
        "an `exp` claim in the future and a `ttl` claim"
        if fmt == "SD"
        else "with the type header (16) `application/statuslist+cwt`, a subject (2) equal to the credential's "
        "status `uri`, an issued at claim (6), an expiration time (4) in the future and a time to live (65534)"
    )
    add(id=tid("PP", "SM", "Revocation", 1, L), **base, rel="GR",
        objective=f"Verify that the Relying Party evaluates a valid Status List Token in {ftxt} format and accepts a PID whose status is VALID.",
        refs=pp_refs(fmt, "[HAIP] section 6.1"),
        steps=[f"Perform a presentation for {QPID} in which the Conformance Wallet presents {PID} in a valid Authorization Response, while the Test Status Provider serves, for the status list referenced by the credential, a Status List Token {valid_desc}, signed by a certificate under the revocation anchor of `PP-A`, that holds the value 0x00 at the credential's index."],
        expected=[acc(PID) + FETCHED], comments=[FLOW_COMMENT])
    add(id=tid("PP", "SM", "Revocation", 2, L, True), **base, rel="GR",
        objective=f"Verify that the Relying Party does not use a Status List Token in {ftxt} format with an invalid signature.",
        refs=pp_refs(fmt), steps=[slt_step("one bit of its signature value is flipped")], expected=[REJ], comments=comments)

    if fmt == "SD":
        unsecured = [
            slt_step("it is an unsecured JWT with `alg` `none` and an empty signature"),
            f"Perform a presentation for {QPID} in which the Conformance Wallet presents {PID} in a valid Authorization Response, while the Test Status Provider serves, for the status list referenced by the credential, the bare status list JSON object (`bits`, `lst`) instead of a Status List Token.",
        ]
    else:
        unsecured = [
            f"Perform a presentation for {QPID} in which the Conformance Wallet presents {PID} in a valid Authorization Response, while the Test Status Provider serves, for the status list referenced by the credential, the bare status list CBOR map (`bits`, `lst`) instead of a Status List Token.",
        ]
    add(id=tid("PP", "SM", "Revocation", 3, L, True), **base, rel="GR",
        objective=f"Verify that the Relying Party does not use an unsigned Status List Token or a bare status list in place of a Status List Token in {ftxt} format.",
        refs=pp_refs(fmt), steps=unsecured, expected=[REJ] * len(unsecured), comments=comments)
    add(id=tid("PP", "SM", "Revocation", 4, L, True), **base, rel="GR",
        objective=f"Verify that the Relying Party does not use an expired Status List Token in {ftxt} format.",
        refs=pp_refs(fmt),
        steps=[slt_step(("its `exp` claim" if fmt == "SD" else "its expiration time (4)") + " is set to the current time minus `T_skew` minus one hour")],
        expected=[REJ], comments=comments)
    add(id=tid("PP", "SM", "Revocation", 5, L, True), **base, rel="GR",
        objective=f"Verify that the Relying Party does not use a Status List Token in {ftxt} format whose subject differs from the status list URI in the credential.",
        refs=pp_refs(fmt),
        steps=[slt_step(("its `sub` claim" if fmt == "SD" else "its subject (2)") + " is the URI of a different status list")],
        expected=[REJ], comments=comments)
    add(id=tid("PP", "SM", "Revocation", 6, L, True), **base, rel="GR",
        objective=f"Verify that the Relying Party does not use a Status List Token in {ftxt} format that declares the wrong type.",
        refs=pp_refs(fmt),
        steps=[slt_step("its `typ` header is `JWT`" if fmt == "SD" else "its type header (16) is `application/cwt`")],
        expected=[REJ], comments=comments)
    missing = (
        ["its payload has no `sub` claim", "its payload has no `iat` claim", "its payload has no `status_list` claim",
         "its `status_list` claim has no `bits` member", "its `status_list` claim has no `lst` member"]
        if fmt == "SD"
        else ["its claims set has no subject (2)", "its claims set has no issued at claim (6)",
              "its claims set has no status list claim (65533)", "its status list claim has no `bits` entry",
              "its status list claim has no `lst` entry"]
    )
    add(id=tid("PP", "SM", "Revocation", 7, L, True), **base, rel="GR",
        objective=f"Verify that the Relying Party does not use a Status List Token in {ftxt} format that lacks a required claim.",
        refs=pp_refs(fmt), steps=[slt_step(d) for d in missing], expected=[REJ] * len(missing), comments=comments)
    untrusted = [
        f"it is signed by a certificate issued by `CA-X`, with that certificate chain in {x5(fmt)}",
        f"it carries no {x5(fmt)} header, so its signer cannot be validated",
        "it is signed by a self-signed certificate that is not part of `default_trust_configuration_rp`",
    ]
    add(id=tid("PP", "SM", "Revocation", 8, L, True), **base, rel="GR",
        objective=f"Verify that the Relying Party does not use a Status List Token in {ftxt} format whose signer is not trusted.",
        refs=pp_refs(fmt, "[HAIP] section 6.1", "[Token Status List] section 11.3"),
        steps=[slt_step(d) for d in untrusted], expected=[REJ] * 3, comments=comments)
    other = [
        "it is signed by a certificate under the revocation anchor of `PP-B`",
        "it is signed by a certificate under the revocation anchor of the Wallet Provider `WP-A` in `TL-WP`",
        "it is signed by a certificate under the anchor of `AC-A` in `TL-AC`",
    ]
    add(id=tid("PP", "SM", "Revocation", 9, L, True), **base, rel="SR",
        objective=(
            f"Verify that the Relying Party does not use a Status List Token in {ftxt} format signed under a "
            "trusted anchor of another entity or another list."
        ),
        refs=pp_refs(fmt, "[Token Status List] section 11.3"),
        steps=[slt_step(d) for d in other], expected=[REJ] * 3,
        comments=["`default_trust_configuration_rp` defines that a status list is trusted only under the revocation anchor of the entity that issued the credential."] + comments)
    add(id=tid("PP", "SM", "Revocation", 10, L), **base, rel="SR",
        objective=(
            f"Verify that the Relying Party uses a Status List Token in {ftxt} format signed under the "
            "revocation anchor of the entity that issued the credential."
        ),
        refs=pp_refs(fmt, "[Token Status List] section 11.3"),
        steps=[
            f"Perform a presentation for {QPID} in which the Conformance Wallet presents {PID} in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it that holds the value 0x00 at the credential's index and is signed by a certificate under the revocation anchor `CA-PP-A-REV` of `PP-A`.",
            f"Perform a presentation for {QPID} in which the Conformance Wallet presents a variant of {PID} issued by `PP-B` in a valid Authorization Response, while the Test Status Provider serves a valid Status List Token for it that holds the value 0x00 at the credential's index and is signed with the same key and certificate as that credential.",
        ],
        expected=[acc(PID) + FETCHED, acc() + FETCHED],
        comments=[
            "In the second step the issuance CA of `PP-B` is also published under the revocation "
            "service of `PP-B`, which is how `default_trust_configuration_rp` represents an issuer "
            "that signs its status lists with its issuance key ([Token Status List] section 11.3).",
            FLOW_COMMENT,
        ])
    add(id=tid("PP", "SM", "Revocation", 11, L, True), **base, rel="SR",
        objective=(
            f"Verify that the Relying Party does not use a Status List Token in {ftxt} format whose signer "
            "chains only to the issuance anchor of the issuing entity, when that anchor is not published "
            "under the entity's revocation service."
        ),
        refs=pp_refs(fmt, "[Token Status List] section 11.3"),
        steps=[
            slt_step("it is signed with the key and certificate that signed the presented credential"),
            slt_step("it is signed by another certificate issued under the issuance CA `CA-PP-A` of `PP-A`"),
        ],
        expected=[REJ, REJ],
        comments=["`PP-A` publishes separate CAs for its issuance and revocation services, so its issuance CA is not a root of trust for its status lists."] + comments)
    add(id=tid("PP", "SM", "Revocation", 12, L, True), **base, rel="GR",
        objective=f"Verify that the Relying Party does not trust a root certificate embedded in the {x5(fmt)} header of a Status List Token in {ftxt} format.",
        refs=pp_refs(fmt, "[HAIP] section 6.1"),
        steps=[slt_step(f"its signer certificate chains to a self-signed root that {x5(fmt)} includes and that is not part of `default_trust_configuration_rp`")],
        expected=[REJ], comments=comments)
    add(id=tid("PP", "SM", "Revocation", 13, L, True), **base, rel="GR",
        objective=f"Verify that the Relying Party does not use a Status List Token in {ftxt} format whose signer certificate is outside its validity period.",
        refs=pp_refs(fmt, "[RFC5280] section 6.1.3"),
        steps=[slt_step("its signer certificate has expired"), slt_step("its signer certificate is not yet valid")],
        expected=[REJ, REJ], comments=comments)
    corrupt = (
        ["the `lst` member of its `status_list` claim is not valid base64url",
         "the `lst` member of its `status_list` claim decodes to bytes that are not valid ZLIB data"]
        if fmt == "SD"
        else ["the `lst` entry of its status list claim is not valid ZLIB data"]
    )
    add(id=tid("PP", "SM", "Revocation", 15, L, True), **base, rel="GR",
        objective=f"Verify that the Relying Party does not use a Status List Token in {ftxt} format whose compressed status list is corrupt.",
        refs=pp_refs(fmt, "[Token Status List] section 4.1, 11.1"),
        steps=[slt_step(d) for d in corrupt], expected=[REJ] * len(corrupt), comments=comments)
    add(id=tid("PP", "SM", "Revocation", 16, L, True), **base, rel="GR",
        objective=(
            f"Verify that the Relying Party refuses a Status List Token in {ftxt} format whose status list "
            "decompresses to more than its declared maximum size, and stays available."
        ),
        refs=pp_refs(fmt, "[Token Status List] section 4.1, 11.1"),
        steps=[
            slt_step("its `lst` value decompresses to more bytes than the maximum status list size the Relying Party declares, for example a ZLIB stream that inflates to 1 GiB of zero bytes"),
            valid_step(f"a newly issued {PID}", extra=", immediately after the previous step, while the status list referenced by that credential is valid and holds the value 0x00 at its index"),
        ],
        expected=[REJ, acc()],
        comments=["Every entry of the inflated list holds 0x00, so a Relying Party that processes the list without a size limit accepts the presentation in the first step."] + comments)
    add(id=tid("PP", "SM", "Revocation", 17, L, True), **base, rel="GR",
        objective=f"Verify that the Relying Party does not use a Status List Token in {ftxt} format with an unsupported number of bits per status.",
        refs=pp_refs(fmt, "[Token Status List] section 4.1"),
        steps=[slt_step("the `bits` value of its status list is 3")], expected=[REJ], comments=comments)

    steps, expected = [], []
    for bits in (1, 2, 4, 8):
        idx = 16 // bits - 1
        common = (
            f"Perform a presentation for {QPID} in which the Conformance Wallet presents {PID}, issued "
            f"with status index {idx}, in a valid Authorization Response, while the Test Status Provider "
            f"serves a valid Status List Token for it with `bits` set to {bits}, in which "
        )
        steps.append(common + "the entry at index " + str(idx) + " holds 0x01 and every other entry holds 0x00.")
        expected.append(REJ)
        steps.append(common + "the entry at index " + str(idx) + " holds 0x00 and every other entry holds 0x01.")
        expected.append(acc())
    add(id=tid("PP", "SM", "Revocation", 18, L), **base, rel="GR",
        objective=f"Verify that the Relying Party reads the status value at the credential's index correctly from a Status List Token in {ftxt} format, for every permitted number of bits per status.",
        refs=pp_refs(fmt, "[Token Status List] section 4.1"),
        steps=steps, expected=expected,
        comments=[
            "Each index is the last entry of the second byte of the status list, so a Relying Party "
            "that reads the bits in the wrong order within a byte, or computes the byte offset "
            "incorrectly, reads a neighbouring entry. Every step uses a newly issued credential.",
            FLOW_COMMENT,
        ])
    algs = (
        ["it is signed with `ES256K` (curve secp256k1)",
         "it is protected with `HS256`, keyed with the encoded public key of the certificate in its `x5c` header"]
        if fmt == "SD"
        else ["it is signed with `ES256K` (curve secp256k1)",
              "it is protected with a `COSE_Mac0` structure using HMAC 256/256, keyed with the encoded public key of the certificate in its `x5chain` header"]
    )
    add(id=tid("PP", "SM", "Revocation", 19, L, True), **base, rel="SR",
        objective=f"Verify that the Relying Party does not use a Status List Token in {ftxt} format protected with an algorithm outside the agreed cryptographic mechanisms.",
        refs=pp_refs(fmt, "[ECCG ACM]", "[HAIP] section 6.1, 7", "[RFC8725] section 3.1"),
        steps=[slt_step(d) for d in algs], expected=[REJ, REJ], comments=comments)

add(id=tid("PP", "SM", "Revocation", 30, uf=True), cls="PP", layer="SM", area="Revocation", rel="SR",
    objective="Verify that the Relying Party does not use an identifier list in CWT format that is badly signed, expired or signed by an untrusted signer.",
    refs=["[ISO/IEC 18013-5 ed2]", "[RFC8392] section 7.2", "[ARF] Annex 2, PPNot_05, VCR_11, VCR_12, VCR_14", "[ETSI TS 119 602]", "[CIR 2024/2979 amended] Annex II"],
    profile=[FMT["MD"]["prof"], REV], tech=[FMT["MD"]["tech"], "Identifier list in CWT format."],
    pre=PRE_BASE + [control("MD"), PRE_STATUS, IDL_PRE,
                    "The identifier list served for each presented credential does not contain the credential's identifier."],
    steps=[
        f"Perform a presentation for {QPID} in which the Conformance Wallet presents {PID} in a valid Authorization Response, while one bit of the signature value of the referenced identifier list is flipped.",
        f"Perform a presentation for {QPID} in which the Conformance Wallet presents {PID} in a valid Authorization Response, while the expiration time (4) of the referenced identifier list lies `T_skew` plus one hour in the past.",
        f"Perform a presentation for {QPID} in which the Conformance Wallet presents {PID} in a valid Authorization Response, while the referenced identifier list is signed by a certificate issued by `CA-X`.",
    ],
    expected=[REJ, REJ, REJ], comments=[NOSTAT_COMMENT, FLOW_COMMENT])

# --------------------------------------------------------------------------- SM_TrustMechanisms

TRUST_REFS = {
    "SD": ["[SD-JWT VC] section 2.5", "[HAIP] section 6.1.1", "[RFC5280] section 6.1"],
    "MD": ["[ISO/IEC 18013-5] section 9.3.1", "[RFC5280] section 6.1"],
}


def tm_refs(fmt, arf, lists=("[ETSI TS 119 602]",)):
    return [f"[ARF] Annex 2, {arf}"] + TRUST_REFS[fmt] + list(lists)


for fmt in ("SD", "MD"):
    f = FMT[fmt]
    L = f["letter"]
    base = dict(cls="WS", layer="SM", area="TrustMechanisms", tech=[f["tech"]],
                pre=PRE_BASE + [control(fmt)])
    pp = [f["prof"]]
    add(id=tid("WS", "SM", "TrustMechanisms", 1, L), **base, profile=pp, rel="SR",
        objective=f"Verify that the Relying Party accepts a PID in {f['name']} format signed under a PID/Issuance anchor of the PID Provider list.",
        refs=tm_refs(fmt, "OIA_12, PPNot_05"), steps=[valid_step()], expected=[acc(PID)], comments=[FLOW_COMMENT])
    add(id=tid("WS", "SM", "TrustMechanisms", 2, L, True), **base, profile=pp, rel="SR",
        objective=f"Verify that the Relying Party rejects a PID in {f['name']} format signed by a QTSP whose anchor appears only in a Trusted List.",
        refs=tm_refs(fmt, "OIA_12, OIA_15", ("[ETSI TS 119 602]", "[ETSI TS 119 612]")),
        steps=[cred_step("it is issued by `QP-A`")], expected=[REJ], comments=[FLOW_COMMENT])
    add(id=tid("WS", "SM", "TrustMechanisms", 3, L, True), **base, profile=pp, rel="SR",
        objective=f"Verify that the Relying Party rejects a PID in {f['name']} format signed under an anchor of a list other than the PID Provider list.",
        refs=tm_refs(fmt, "OIA_12, OIA_15"),
        steps=[cred_step("it is issued by the Wallet Provider `WP-A` from `TL-WP`"),
               cred_step("it is issued by `AC-A` from `TL-AC`"),
               cred_step("it is issued by the PuB-EAA Provider `PB-A` from `TL-PUB`")],
        expected=[REJ] * 3, comments=[FLOW_COMMENT])
    add(id=tid("WS", "SM", "TrustMechanisms", 4, L, True), **base, profile=pp, rel="SR",
        objective=f"Verify that the Relying Party rejects a PID in {f['name']} format signed under an anchor published only for the revocation service of a PID Provider.",
        refs=tm_refs(fmt, "OIA_12, PPNot_05"),
        steps=[cred_step("it is signed by a certificate under the revocation anchor `CA-PP-A-REV` of `PP-A`")],
        expected=[REJ], comments=[FLOW_COMMENT])
    add(id=tid("WS", "SM", "TrustMechanisms", 5, L, True), **base, profile=pp, rel="SR",
        objective=f"Verify that the Relying Party rejects a PID in {f['name']} format from an issuer that is on no trust list.",
        refs=tm_refs(fmt, "OIA_12"), steps=[cred_step("it is issued by `CA-X`")], expected=[REJ], comments=[FLOW_COMMENT])
    add(id=tid("WS", "SM", "TrustMechanisms", 6, L, True), **base, profile=pp, rel="SR",
        objective=f"Verify that the Relying Party rejects a PID in {f['name']} format from a PID Provider whose entry is withdrawn.",
        refs=tm_refs(fmt, "OIA_12, OIA_15a"), steps=[cred_step("it is issued by `PP-W`")], expected=[REJ], comments=[FLOW_COMMENT])
    add(id=tid("WS", "SM", "TrustMechanisms", 7, L, True), **base, profile=pp, rel="SR",
        objective=f"Verify that the Relying Party stops accepting PIDs in {f['name']} format from a PID Provider once its entry is removed from the PID Provider list.",
        refs=tm_refs(fmt, "OIA_15a"),
        steps=[cred_step("it is issued by `PP-D`"),
               "The Test Trust Infrastructure publishes a new version of `TL-PID` without the entry of `PP-D`. Wait until the Relying Party has retrieved it, at most `T_refresh`.",
               cred_step("it is issued by `PP-D`")],
        expected=[acc(), "The Test Trust Infrastructure logs a retrieval of the new version of `TL-PID` by the Relying Party.", REJ],
        comments=["Restore the previous version of `TL-PID` after the test case.", FLOW_COMMENT])
    add(id=tid("WS", "SM", "TrustMechanisms", 8, L), **base, profile=pp, rel="SR",
        objective=f"Verify that the Relying Party starts accepting PIDs in {f['name']} format from a PID Provider once its entry is added to the PID Provider list.",
        refs=tm_refs(fmt, "OIA_15a"),
        steps=[cred_step("it is issued by `PP-C`"),
               "The Test Trust Infrastructure publishes a new version of `TL-PID` that adds an entry for `PP-C` with a granted PID/Issuance and PID/Revocation service. Wait until the Relying Party has retrieved it, at most `T_refresh`.",
               cred_step("it is issued by `PP-C`")],
        expected=[REJ, "The Test Trust Infrastructure logs a retrieval of the new version of `TL-PID` by the Relying Party.", acc()],
        comments=["Restore the previous version of `TL-PID` after the test case.", FLOW_COMMENT])
    add(id=tid("WS", "SM", "TrustMechanisms", 9, L, True), **base, profile=pp, rel="SR",
        objective=f"Verify that the Relying Party rejects a PID in {f['name']} format signed under an expired trust anchor.",
        refs=tm_refs(fmt, "OIA_15a"), steps=[cred_step("it is issued by `PP-E`, whose PID/Issuance anchor certificate has expired")],
        expected=[REJ], comments=[FLOW_COMMENT])

    for num, prof, query, cred, issuer, arf, lists, name in (
        (10, P_QEAA, "`default_query_qeaa`", "`default_credential_qeaa`", "QP-A", "OIA_13, OIA_15b", ("[ETSI TS 119 612]",), "QEAA"),
        (12, P_PUB, "`default_query_pubeaa`", "`default_credential_pubeaa`", "PB-A", "OIA_14, PuBPNot_06", ("[ETSI TS 119 602]",), "PuB-EAA"),
        (14, P_EAA, "`default_query_eaa`", "`default_credential_eaa`", "EP-A", "OIA_15", ("[ETSI TS 119 602]",), "non-qualified EAA"),
    ):
        add(id=tid("WS", "SM", "TrustMechanisms", num, L), **base, profile=pp + [prof], rel="SR",
            objective=f"Verify that the Relying Party accepts a {name} in {f['name']} format signed under the root of trust defined for {name}s.",
            refs=tm_refs(fmt, arf, lists), steps=[valid_step(cred, query)], expected=[acc(cred, query)], comments=[FLOW_COMMENT])

    add(id=tid("WS", "SM", "TrustMechanisms", 11, L, True), **base, profile=pp + [P_QEAA], rel="SR",
        objective=f"Verify that the Relying Party does not accept an attestation in {f['name']} format as QEAA when its issuer has no granted qualified service.",
        refs=tm_refs(fmt, "OIA_13, OIA_15b", ("[ETSI TS 119 612]",)),
        steps=[cred_step("it is issued by `QP-N`, whose service is not qualified", "`default_credential_qeaa`", "`default_query_qeaa`"),
               cred_step("it is issued by `QP-W`, whose qualified service is withdrawn", "`default_credential_qeaa`", "`default_query_qeaa`")],
        expected=[REJ, REJ], comments=[FLOW_COMMENT])
    add(id=tid("WS", "SM", "TrustMechanisms", 13, L, True), **base, profile=pp + [P_PUB], rel="SR",
        objective=f"Verify that the Relying Party rejects a PuB-EAA in {f['name']} format signed under a PID Provider anchor.",
        refs=tm_refs(fmt, "OIA_14, OIA_15"),
        steps=[cred_step("it is issued by `PP-A`", "`default_credential_pubeaa`", "`default_query_pubeaa`")],
        expected=[REJ], comments=[FLOW_COMMENT])
    add(id=tid("WS", "SM", "TrustMechanisms", 15, L, True), **base, profile=pp + [P_EAA], rel="SR",
        objective=f"Verify that the Relying Party rejects a non-qualified EAA in {f['name']} format signed under an anchor that its rulebook does not define.",
        refs=tm_refs(fmt, "OIA_15"),
        steps=[cred_step("it is issued by `PP-A`", "`default_credential_eaa`", "`default_query_eaa`")],
        expected=[REJ], comments=[FLOW_COMMENT])
    add(id=tid("WS", "SM", "TrustMechanisms", 16, L, True), cls="WS", layer="SM", area="TrustMechanisms",
        tech=[f["tech"]], profile=pp + [P_TA], rel="GR",
        objective=(
            f"Verify that the Relying Party enforces the `trusted_authorities` of its own request and rejects a "
            f"PID in {f['name']} format from another trusted PID Provider."
        ),
        refs=["[OpenID4VP] section 6.1.1.1, 14.9", "[HAIP] section 5"] + TRUST_REFS[fmt] + ["[CIR 2024/2982 amended] Annex II"],
        pre=base["pre"] + ["The Relying Party is configured to restrict `default_query_pid` with a `trusted_authorities` entry of type `aki` that names only the PID/Issuance anchor of `PP-A`."],
        steps=[cred_step("it is issued by `PP-B`")], expected=[REJ],
        comments=["[OpenID4VP] section 14.9 states that the Verifier must not rely on the Wallet to enforce the constraints of its request.", FLOW_COMMENT])

# --------------------------------------------------------------------------- SM_SessionEncryption

ENC_REFS = {
    "RD": ["[HAIP] section 5, 5.1", "[OpenID4VP] section 8.3, 8.3.1"],
    "DC": ["[HAIP] section 5, 5.2", "[OpenID4VP] section 8.3, A.4"],
}
ENC_ARF = {"RD": "[ARF] Annex 2, OIA_03b, OIA_03c", "DC": "[ARF] Annex 2, OIA_08, OIA_08a"}


def enc_refs(flow, *extra):
    return ENC_REFS[flow] + list(extra) + [ENC_ARF[flow], "[CIR 2024/2982 amended] Annex II"]


ENC_CONTROL = (
    "Test case `RP_WS_IA_MainInteraction_001a` or `RP_WS_IA_MainInteraction_001b` passed in the same "
    "environment for the presentation flow of this test case."
)
ENC_COMMENT = (
    "The credential format does not affect this test case; use `default_credential_pid` in a format "
    "the Relying Party requests."
)


def enc_add(num, flows, uf, objective, steps_for, expected_for, rel="GR", extra_refs=(), comments=()):
    for flow in flows:
        fl = FLOW[flow]
        letter = fl["letter"] if len(flows) > 1 else ""
        add(id=tid("WS", "SM", "SessionEncryption", num, letter, uf), cls="WS", layer="SM", area="SessionEncryption",
            objective=objective(flow), refs=enc_refs(flow, *extra_refs), profile=[fl["prof"]], rel=rel, tech=[fl["tech"]],
            pre=PRE_BASE + [ENC_CONTROL], steps=steps_for(flow), expected=expected_for(flow),
            comments=list(comments) + [ENC_COMMENT])


def resp(flow):
    return "the `response` parameter" if flow == "RD" else "the `response` member of the returned `data` object"


for num, enc in ((1, "A128GCM"), (2, "A256GCM")):
    enc_add(num, ("RD", "DC"), False,
            lambda flow, enc=enc: f"Verify that the Relying Party accepts an Authorization Response {FLOW[flow]['via']} encrypted with `ECDH-ES` on P-256 and `{enc}`.",
            lambda flow, enc=enc: [f"Perform a presentation for {QPID} {FLOW[flow]['via']} in which the Conformance Wallet presents {PID} in a valid Authorization Response, encrypted as a JWE with `alg` `ECDH-ES` (P-256) and `enc` `{enc}` to the encryption key from the `client_metadata` of the request."],
            lambda flow: [acc(PID)], extra_refs=("[RFC7516] section 5.2", "[RFC7518] section 4.6, 5.3"))
enc_add(3, ("RD",), True,
        lambda flow: "Verify that the Relying Party rejects an unencrypted Authorization Response when it requested response mode `direct_post.jwt`.",
        lambda flow: [enc_step(flow, "it is not encrypted: the Conformance Wallet posts `vp_token` and `state` as form parameters to the `response_uri`, as in response mode `direct_post`")],
        lambda flow: [REJ])
enc_add(4, ("RD", "DC"), True,
        lambda flow: f"Verify that the Relying Party rejects an Authorization Response {FLOW[flow]['via']} encrypted to a key it did not issue.",
        lambda flow: [enc_step(flow, "it is encrypted to a newly generated P-256 key that the Relying Party did not issue, while the JWE header carries the `kid` of the Relying Party's encryption key")],
        lambda flow: [REJ])
enc_add(5, ("RD", "DC"), True,
        lambda flow: f"Verify that the Relying Party rejects an Authorization Response {FLOW[flow]['via']} encrypted to the ephemeral key of another transaction.",
        lambda flow: [f"Start a presentation for {QPID} {FLOW[flow]['via']} (transaction T1) and record the encryption key from the `client_metadata` of its request. Send no response for T1.",
                      f"Perform a presentation for {QPID} {FLOW[flow]['via']} (transaction T2) in which the Conformance Wallet encrypts an otherwise valid Authorization Response for T2 to the encryption key recorded for T1, with the `kid` of that key."],
        lambda flow: ["The request of T1 carries an encryption key in its `client_metadata`.", REJ])
enc_add(6, ("RD", "DC"), True,
        lambda flow: f"Verify that the Relying Party rejects an Authorization Response {FLOW[flow]['via']} encrypted with a key management algorithm other than `ECDH-ES`.",
        lambda flow: [enc_step(flow, "its JWE uses `alg` `ECDH-ES+A128KW` with the Relying Party's encryption key"),
                      enc_step(flow, "its JWE uses `alg` `ECDH-ES+A256KW` with the Relying Party's encryption key")],
        lambda flow: [REJ, REJ], extra_refs=("[RFC7518] section 4.6",))
enc_add(7, ("RD", "DC"), True,
        lambda flow: f"Verify that the Relying Party rejects an Authorization Response {FLOW[flow]['via']} encrypted with a content encryption algorithm it did not list.",
        lambda flow: [enc_step(flow, "its JWE uses `enc` `A128CBC-HS256`")],
        lambda flow: [REJ], extra_refs=("[RFC7518] section 5.2",))
enc_add(8, ("RD", "DC"), True,
        lambda flow: f"Verify that the Relying Party rejects an Authorization Response {FLOW[flow]['via']} whose JWE was modified.",
        lambda flow: [enc_step(flow, "one bit of its JWE ciphertext is flipped"),
                      enc_step(flow, "one bit of its JWE authentication tag is flipped")],
        lambda flow: [REJ, REJ], extra_refs=("[RFC7516] section 5.2",))
enc_add(9, ("RD", "DC"), True,
        lambda flow: f"Verify that the Relying Party rejects an Authorization Response {FLOW[flow]['via']} whose ephemeral public key is not a valid P-256 point.",
        lambda flow: [enc_step(flow, "the `epk` header of its JWE holds coordinates that are not a point on P-256"),
                      enc_step(flow, "the `epk` header of its JWE holds a key on curve P-384")],
        lambda flow: [REJ, REJ], extra_refs=("[RFC7518] section 4.6", "[RFC8725] section 3.4"))
enc_add(10, ("RD", "DC"), True,
        lambda flow: f"Verify that the Relying Party rejects an Authorization Response {FLOW[flow]['via']} that is signed or unsecured instead of encrypted.",
        lambda flow: [enc_step(flow, f"{resp(flow)} is a JWS signed with a key of the Conformance Wallet instead of a JWE"),
                      enc_step(flow, f"{resp(flow)} is an unsecured JWT with `alg` `none` instead of a JWE")],
        lambda flow: [REJ, REJ], extra_refs=("[RFC8725] section 3.1",))
enc_add(11, ("DC",), True,
        lambda flow: "Verify that the Relying Party rejects an unencrypted Authorization Response via the W3C Digital Credentials API.",
        lambda flow: [enc_step(flow, "it is not encrypted: the `data` object returned through the Digital Credentials API carries the `vp_token` directly instead of an encrypted `response`")],
        lambda flow: [REJ])
enc_add(12, ("RD", "DC"), False,
        lambda flow: f"Verify that the Relying Party ignores unrecognised members in a decrypted Authorization Response {FLOW[flow]['via']}.",
        lambda flow: [f"Perform a presentation for {QPID} {FLOW[flow]['via']} in which the Conformance Wallet presents {PID} in a valid Authorization Response whose decrypted payload additionally contains the member `foo` with the value `bar`."],
        lambda flow: [acc(PID)], extra_refs=("[OpenID4VP] section 8.1",))
