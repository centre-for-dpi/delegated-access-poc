# ADR: A Reusable Delegated-Access Adapter for VC Ecosystems

- **Status:** Proposed
- **Date:** 2026-06-24
- **Context:** Delegated access for W3C Verifiable Credentials, deployable into multiple
  Digital Public Goods (Inji and walt.id first; Credebl and others later).
- **Scope of this record:** architecture decisions only — self-contained and
  implementation-agnostic. It can be read, understood, and built from without reference to any
  prior prototype or codebase.

---

## 1. Context & problem statement

A trusted party (the **delegate**, e.g. a parent) must be able to hold, present, and consent
to verification of a credential on behalf of the **subject** (e.g. a minor child), such that:

- the delegation is **verifiable by any relying party** without proprietary infrastructure;
- the delegation is **independently revocable** without reissuing the underlying credential;
- **control transitions cleanly** to the subject when the delegation lapses (e.g. age of majority);
- it is **stack-, wallet-, and format-agnostic** within the JSON-LD / JWT VC families.

We want this capability packaged as a **slim, reusable adapter** that drops into existing DPG
stacks rather than a vertically-integrated product.

---

## 2. Decision drivers

1. **Preserve the VC trust triangle (Issuer → Holder → Verifier).** The adapter must not become
   a fourth party that any of the three must newly trust for credential *authenticity*.
2. **Slim & reusable.** No duplication of crypto, DID resolution, or the OID4VP exchange that the
   host DPGs already implement.
3. **Interoperable on the wire.** Must work against verifiers that understand *only* standard
   OID4VP + DIF Presentation Exchange (notably Inji, which validates signatures but does not
   evaluate PE constraints).
4. **Cryptographically rigorous delegation** (attenuation, expiry, optional re-delegation) —
   beyond "two DIDs happen to match."
5. **Single source of truth for the delegation decision** — the linkage check must have one
   implementation, not a separate code path per credential format.

---

## 3. Scope & non-goals

**In scope (v1):** Inji and walt.id; `ldp_vc` (JSON-LD, Ed25519Signature2020 / Data Integrity)
and `jwt_vc_json`; issuance-side construction and presentation-side evaluation of delegation.

**Out of scope (v1):**
- **Hosting status lists** — this is an issuer capability and stays with the issuer.
- **mso_mdoc (ISO mDL)** — deferred; the format-abstraction layer (D5) leaves room for it.
- **SD-JWT VC** is *not* deferred at the design level — it is specified in full as a format
  extension in §12. The v1 *implementation* still leads with `ldp_vc` + `jwt_vc_json`; SD-JWT VC
  is the planned next format and slots into the same normalization layer (D5).
- **Being the system of record for credentials or keys** — the adapter is stateless about
  credential authenticity.
- **Credebl** and other DPGs — designed for, but not validated against, in v1.

---

## 4. Trust-triangle invariants (constraints every decision must satisfy)

These are testable invariants, not aspirations:

- **I1 — Issuer is the sole authority/signer.** The issuance adapter never substitutes its own
  signature for the issuer's. Delegation credentials and capability-delegation proofs are signed
  by the issuer's key (or the issuer's existing signing service), not the adapter's.
- **I2 — Holder owns the presentation.** The presentation adapter never mints, re-signs, or
  alters a Verifiable Presentation. It only *evaluates* what the holder presented.
- **I3 — Verifier's trust anchor is unchanged.** The relying party continues to anchor trust in
  the issuer (via its trust registry). The adapter is an internal policy component of the
  verifier, not an independently-trusted attestor of credential validity.
- **I4 — No forge-enabling secrets.** The adapter holds no key whose compromise would let it
  forge a credential or a presentation. Its only key signs *audit/consent receipts*, which
  attest "the adapter evaluated X" — never "credential X is authentic."

---

## 5. Decisions

### D1 — Two adapters, each inside an existing trust boundary

Split the capability into two independently-deployable services:

| Adapter | Lives inside | Owns | Never does |
|---|---|---|---|
| **Issuance Adapter** | the **Issuer's** trust boundary | constructing the delegation credential + capability, driving the issuer's OID4VCI flow, allocating the issuer's status index | signing credentials itself; holding the root authority |
| **Presentation Adapter** | the **Verifier's** trust boundary | synthesizing presentation-definition (PD) constraints, evaluating linkage + capability + status, emitting the verdict + audit receipt | verifying issuer signatures as a new trust anchor; altering the VP |

This directly satisfies I1–I3: each adapter is an *extension of* a vertex it already belongs to,
so the triangle keeps three vertices.

### D2 — Layered delegation model: `same_subject` on the wire, ZCAP-LD on the backend

- **On the wire** (what any OID4VP verifier sees): a separate, issuer-signed **delegation
  credential** that references the subject's DID, linked to the identity credential via a DIF
  Presentation Exchange **`same_subject`** constraint. Fully interoperable today.
- **On the backend** (what only the adapters read): an **Authorization Capability (ZCAP-LD)**
  carried *inside* the delegation credential, rooted at the issuer, expressing the delegated
  authority, its caveats (validity window, permitted actions), and whether it may be
  re-delegated. This is the cryptographically rigorous layer.

**Honest precision on "invocation":** the *delegation* link is a genuine ZCAP-LD
`capabilityDelegation` proof chain signed by the issuer. The *invocation* is realized through the
**OID4VP holder binding** — the delegate signs the VP — which the presentation adapter binds to
the capability by requiring `VP.holder == capability.delegate == delegation.credentialSubject.id`.
We deliberately do **not** require a literal ZCAP-LD `capabilityInvocation` HTTP-signature, because
that is not part of the OID4VP exchange. The holder binding is the invocation proof.

### D3 — Linked Credential Chain, **Type I** (issuer-issued), delegate-as-subject

The **issuer** issues the delegation credential (Type I), not the child (Type II) — a minor
cannot reliably issue or consent. Within the delegation credential:

- `credentialSubject.id` = the **delegate's** DID (holder-bound → becomes the invoker), and
- `credentialSubject.onBehalfOf.id` = the **subject's** DID (the `same_subject` anchor).

Putting the delegate as the credential subject aligns the DID used for VP holder binding with the
DID named in the capability, making the invocation check a single identity equality.

### D4 — Status lists stay issuer-owned; the adapter *checks*, never *hosts*

- The **issuer** publishes a W3C **Bitstring Status List** credential and embeds a
  `BitstringStatusListEntry` in *every* credential, including the delegation credential.
- **`credentialStatus` must survive signing in both formats** — it must *not* be stripped to
  appease a verifier. A common failure mode: a JSON-LD verifier expects the *status list itself*
  to be a JSON-LD credential, so an integrator strips `credentialStatus` rather than fixing the
  list. The correct approach is to publish the status list as a resolvable JSON-LD credential and
  keep the entry intact.
- The **presentation adapter** performs the status check **uniformly** for every presented
  credential, regardless of format. Revocation thus works identically across formats — the
  *check* is centralized in one component, while *hosting* stays with the issuer.

### D5 — Format scope `ldp_vc` + `jwt_vc_json` behind one normalization layer

A thin **claim-normalization layer** parses each supported format into a common internal shape
(`{ types, subjectId, claims, references, status, proofValidity }`). All linkage, capability, and
status logic runs **once** against the normalized shape. This eliminates the "two code paths for
`same_subject`" problem by construction and leaves a seam to add SD-JWT VC / mdoc later.

### D6 — Capability invocation produces a signed consent/audit receipt

Each successful (or denied) evaluation emits an **adapter-signed audit record**: who invoked,
which capability and caveats, which verifier, when, and the verdict. This is the
runtime-consent/accountability artifact (alignable with Kantara Consent Receipt / ISO 27560).
Per I4, this receipt attests only to the *evaluation*, never to credential authenticity.

---

## 6. The delegation credential profile (normative shape)

Fixing the shape in a published profile (rather than leaving it per-deployment) removes any
ambiguity about *where* the cross-credential link lives — e.g. a flat reference field vs. a value
nested inside an object — which otherwise differs between integrations and silently breaks the
linkage check. Sketch:

```jsonc
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/zcap/v1",
    "https://<profile-ns>/delegated-access/v1"
  ],
  "type": ["VerifiableCredential", "DelegatedAccessCredential"],
  "issuer": "did:web:registry.example.gov",          // I1: the authority signs this VC
  "validFrom": "2026-02-25T00:00:00Z",
  "validUntil": "2033-03-10T00:00:00Z",               // = subject's age of majority → expiry-driven transition
  "credentialSubject": {
    "id": "did:key:zParent…",                         // D3: the DELEGATE (holder-bound, becomes invoker)
    "role": "Mother",
    "onBehalfOf": { "id": "did:key:zChild…" }         // same_subject anchor → SUBJECT of the identity credential
  },
  "termsOfUse": [{
    "type": "DelegationCapability",                   // D2: ZCAP-LD capability carried here
    "controller": "did:web:registry.example.gov",     // root authority = issuer
    "invocationTarget": "did:key:zChild…",
    "delegate": "did:key:zParent…",
    "allowedAction": ["present", "consent:disclose"],
    "caveat": [{ "type": "ValidWhile", "validUntil": "2033-03-10T00:00:00Z" }],
    "allowFurtherDelegation": false
  }],
  "credentialStatus": {                               // D4: issuer-owned; NOT stripped
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "94567",
    "statusListCredential": "https://registry.example.gov/status/3"
  },
  "proof": { /* issuer Data Integrity proof, capabilityDelegation-aware */ }
}
```

The **invocation** is the VP the delegate signs at presentation:

```jsonc
VP {
  holder: "did:key:zParent…",                         // I2: holder owns this; == capability.delegate
  verifiableCredential: [ <BirthCert subject=child>, <DelegatedAccessCredential> ],
  proof: { /* delegate's holder binding == the capability invocation */ }
}
```

---

## 7. Component responsibilities & flows

### 7a. Issuance flow (Issuance Adapter ⊂ issuer)

1. Operator selects subject identity credential (→ child DID) and the delegate (→ parent DID),
   scope (`allowedAction`), and validity (`validUntil`).
2. Adapter **constructs** the `DelegatedAccessCredential` per the profile (§6), allocates a
   **status index from the issuer's** Bitstring Status List, and builds the ZCAP-LD capability.
3. Adapter hands the unsigned credential to the **issuer's signing/issuance service** (OID4VCI);
   **the issuer signs** (I1).
4. The signed credential is delivered to the delegate's wallet via the standard pre-authorized
   OID4VCI flow.

### 7b. Presentation flow (Presentation Adapter ⊂ verifier)

The adapter is the **authoritative delegation evaluator** and does **not** rely on the host
verifier supporting PE `same_subject` (because Inji does not). Two touchpoints:

- **Pre-request:** supplies the host verifier with the PD input-descriptors (identity + delegation
  + `same_subject`) to put in its OID4VP request.
- **Post-response:** receives the host-verified VP and runs, against the normalized claims:
  1. **(host) signature & holder-binding** already verified by the DPG verifier (no duplication);
     adapter trusts that verdict in policy-only mode (I3).
  2. **Linkage:** `identity.subjectId == delegation.onBehalfOf.id`.
  3. **Invocation:** `VP.holder == delegation.credentialSubject.id == capability.delegate`.
  4. **Capability:** `capability.controller == issuer`; chain valid; caveats satisfied
     (now ≤ `validUntil`); `allowedAction` covers the requested action; re-delegation links valid
     if present.
  5. **Status:** resolve each `statusListCredential`, check the bit → not revoked (D4).
  6. **Verdict + signed audit/consent receipt** (D6) returned to the host verifier.

### 7c. DPG asymmetry to design around

| | walt.id verifier-api | Inji (inji-verify) |
|---|---|---|
| Issuer signature + VP holder binding | ✅ | ✅ |
| DIF PE `same_subject` evaluation | ✅ native | ❌ signatures only |
| Bitstring status check (JSON-LD) | partial | ❌ not enforced |

→ The presentation adapter **owns linkage + capability + status for both**, treating walt.id's
native `same_subject` as defense-in-depth, not a dependency. This keeps one code path (D5) and
portability.

---

## 8. Failure modes this architecture prevents

Each row is a way delegated access commonly breaks when built naïvely, and the decision that
prevents it.

| Failure mode | Prevented by |
|---|---|
| Revocation enforced inconsistently across formats (e.g. only on the JWT path because `credentialStatus` was stripped for JSON-LD) | D4: keep `credentialStatus` intact in every format; issuer publishes a JSON-LD status list; **the adapter checks status uniformly**. |
| Cross-credential linkage implemented differently per format → drift and divergent bugs | D5: a single normalization layer → one linkage/capability/status implementation. |
| Linkage is mere data-matching, with no delegation *semantics* (scope, expiry, attenuation) | D2/D3: a ZCAP-LD capability chain with caveats + invocation binding → real, attenuable, optionally re-delegatable authority. |
| No runtime consent or accountability trail | D6: a signed consent/audit receipt per invocation. |
| The cross-credential link path varies per deployment, so verifiers can't reliably find it | §6: a single published **profile** fixes the credential shape and link paths. |
| Transition of control requires manual reissuance | D3 + caveats: `validUntil` = age of majority gives **automatic** expiry-driven transition; reissuing to the subject's own wallet is then an ordinary issuance (issuer-owned). |

---

## 9. Standards: ownership & maturity

Three different standards bodies own three different layers, and the interoperability of this
design depends on keeping them straight. In particular, the cross-credential link (`same_subject`)
is **not** part of the W3C credential data model and is **not** vendor-specific — it is an open
**DIF** query-language construct that any compliant verifier can be asked to evaluate.

**Who owns which layer**

| Layer | Standards body | Defines | Delegation construct that lives here |
|---|---|---|---|
| Credential data model | **W3C** — VC Data Model 2.0 | the credential itself: `credentialSubject`, `holder`, `proof`, `termsOfUse`, `credentialStatus`; and the *concept* that the holder need not be the subject | the **holder ≠ subject** capability; the delegation credential and its embedded capability |
| Credential format (alternative) | **IETF** — SD-JWT VC | a JWT credential with selective disclosure and *optional* `cnf` holder-key binding | bearer identity credential; key-bound delegation credential (§12) |
| Query / constraint language | **DIF** — Presentation Exchange | `presentation_definition`, `input_descriptors`, `constraints`, and the cross-credential linkers `same_subject` / `is_holder` / `subject_is_issuer` | **`same_subject`** — the on-the-wire linkage |
| Transport | **OpenID Foundation** — OID4VCI / OID4VP | how issuance & presentation requests/responses move; OID4VP *embeds* the DIF query document | carries the PD (request) and the VP (response) |
| Backend capability | **W3C CCG** — ZCAP-LD | authorization-capability chains via the `capabilityDelegation` proof purpose | the cryptographic delegation layer, carried inside the credential |

> **Query-language evolution:** newer OID4VP drafts replace DIF Presentation Exchange with **DCQL**
> (Digital Credentials Query Language), which expresses cross-credential linking via
> `credential_sets` + claim matching rather than a `same_subject` directive. The normalization
> layer (D5) is where the adapter absorbs either dialect — it reasons about "linkage" internally
> and emits whichever query language the host verifier speaks.

**Maturity**

| Standard | Maturity |
|---|---|
| W3C VC Data Model 2.0 | Recommendation |
| W3C Bitstring Status List 1.0 | Recommendation |
| W3C DID Core + `did:key` / `did:web` | Recommendation / method specs |
| OpenID4VCI / OpenID4VP | OpenID Foundation (finalized / late-draft) |
| DIF Presentation Exchange 2.x | DIF specification (not a W3C standard) |
| DCQL (OID4VP query language) | OpenID Foundation draft |
| IETF SD-JWT (selective disclosure for JWTs) | IETF (RFC) |
| IETF SD-JWT VC | IETF draft |
| IETF Token Status List | IETF draft |
| ZCAP-LD (Authorization Capabilities for Linked Data) | **W3C CCG report — NOT a Recommendation** |
| Kantara Consent Receipt / ISO/IEC 27560 | external (optional) |

⚠️ **Accepted trade-off:** ZCAP-LD is a CCG draft, not a ratified W3C Recommendation. We accept
this deliberately — it stays *inside* the adapters (never on the interop wire), so its maturity
does not affect interoperability with any DPG. If ZCAP-LD stalls, the backend layer can be swapped
for VC-`termsOfUse`-only semantics without changing the wire format or the trust model.

---

## 10. Consequences

**Positive**
- Trust triangle provably intact (I1–I4 are checkable).
- Works unchanged against verifiers that only validate signatures (e.g. Inji) and those that also evaluate PE constraints (e.g. walt.id).
- One delegation decision implementation; revocation uniform across formats.
- Capability rigor (attenuation, expiry, re-delegation) without DPG buy-in to ZCAP-LD.
- Issuance and presentation deploy, scale, and are secured independently.

**Negative / risks**
- The presentation adapter must reliably receive the *host-verified* VP; DPGs differ in how
  cleanly they expose that hook (integration risk — see open questions).
- Carrying a capability inside `termsOfUse` relies on issuers populating it correctly; the
  Issuance Adapter is the mitigation, but issuers integrating without it would emit linkage-only
  credentials (which still verify, just without backend rigor).
- ZCAP-LD tooling in Go/Java/JS is thin; some capability-chain validation may be hand-rolled.
- did:web issuers require resolvable, available endpoints at verification time.

---

## 11. Alternatives considered & rejected

- **Single combined adapter** — rejected: couples issuer-side and verifier-side concerns and
  blurs the trust boundary (risks creating a fourth vertex).
- **Standalone full verifier (adapter terminates OID4VP)** — rejected for v1: duplicates crypto
  the DPGs already have and inserts the adapter as a de-facto trust anchor (tension with I3).
- **Multi-subject credential (relationship embedded in one VC)** — rejected: cannot revoke the
  delegation independently of the identity credential.
- **Adapter hosts the status list** — rejected per constraint: status is an issuer capability.
- **ZCAP-LD on the wire** — rejected: no DPG verifier consumes it; would break interop (D2 keeps
  it on the backend instead).
- **Embedded library only** — rejected as the primary model: per-language ports + release coupling
  to each DPG; may still ship as a thin client of the service.

---

## 12. SD-JWT VC profile & flows (format extension)

This section is the SD-JWT VC counterpart to the JSON-LD worked example in §6–§7, at the same
depth. **Every structural decision is unchanged** — the trust-triangle invariants (§4), the
two-adapter split (D1), the single normalization layer (D5), and issuer-owned status (D4) all
hold. Only the format-specific mechanics differ. SD-JWT VC is an IETF credential format favoured
by the EUDI ARF and emerging MOSIP profiles; supporting it broadens reach without touching the
trust model.

### 12.1 Why SD-JWT VC suits delegation

- **`cnf` + Key Binding JWT (KB-JWT)** give *per-credential* cryptographic proof of "I am the
  intended holder" — a cleaner primitive than VP-level holder binding.
- **Key binding is optional.** A credential issued without `cnf` is a **bearer** credential; this
  is what enables transition *without reissuance* (see 12.6).
- **Selective disclosure** lets a delegate reveal only the claims an interaction needs — a privacy
  gain when acting on someone else's behalf.

### 12.2 Binding model — bearer identity credential + key-bound authority credentials

| Credential | `cnf`? | Rationale |
|---|---|---|
| Identity credential (e.g. birth certificate) | **none → bearer** | never reissued; transitions like a paper document / offline QR; the subject (a minor) need not hold a key |
| Delegation credential | **`cnf` = delegate (parent)** | the delegate proves possession via KB-JWT → strong presenter authentication; the issuer's signature remains the authority |

The identity credential is *data about* the subject; **authority to wield it is externalised into
separate, key-bound, independently-revocable credentials.** The holder never needs the subject's
key — this is the SD-JWT realisation of the trust model in §2/§4.

### 12.3 Credential profiles (decoded issuer-signed JWT payloads)

**(a) Bearer identity credential — birth certificate** (no `cnf`)

```jsonc
{
  "vct": "https://<profile-ns>/BirthCertificate",   // SD-JWT VC type
  "iss": "https://registry.example.gov",
  "iat": 1739491200,
  "sub": "urn:person:TST-2015-00042",                // stable subject id → the linkage anchor
  "_sd_alg": "sha-256",
  "_sd": [                                            // digests of selectively-disclosable claims
    "G7kP...c2",  // → given_name
    "qz9F...aA",  // → family_name
    "Lm3X...uH"   // → birth_date
  ],
  "place_of_birth": { "country": "TST", "city": "Testa Gava" },
  "status": {                                         // IETF Token Status List (see 12.6)
    "status_list": { "idx": 4012, "uri": "https://registry.example.gov/statuslists/births" }
  }
  // NO cnf  → bearer
}
```

Disclosures travel after the JWT, each `base64url(JSON array)`; the holder reveals only what a
given interaction needs:

```
~WyJzYWx0MSIsImdpdmVuX25hbWUiLCJNYXJpYSJd          // ["salt1","given_name","Maria"]
~WyJzYWx0MiIsImJpcnRoX2RhdGUiLCIyMDE1LTAzLTEwIl0   // ["salt2","birth_date","2015-03-10"]
```

**(b) Key-bound delegation credential — parental delegation** (`cnf` = parent)

```jsonc
{
  "vct": "https://<profile-ns>/DelegationCredential",
  "iss": "https://registry.example.gov",
  "iat": 1739491200,
  "exp": 1994630400,                                 // = age of majority; defence-in-depth (status list is primary)
  "sub": "urn:person:TST-2015-00042",                // == identity credential's sub (linkage anchor)
  "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." } },  // KEY BINDING → the delegate (parent)
  "delegation": {                                     // capability as plain JSON (the JOSE analog of ZCAP-LD)
    "delegate_role": "Mother",
    "on_behalf_of": "urn:person:TST-2015-00042",
    "allowed_action": ["present", "consent:disclose"],
    "valid_until": "2033-03-10T00:00:00Z",
    "allow_further_delegation": false
  },
  "status": {
    "status_list": { "idx": 88231, "uri": "https://registry.example.gov/statuslists/delegations" }
  }
}
```

### 12.4 Presentation serialisation

SD-JWT presentations concatenate parts with `~`. The delegation credential, presented by the
parent, carries a **KB-JWT** proving possession of the `cnf` key; the bearer identity credential
carries **none**:

```
delegation:  <issuer-JWT>~<disclosure>~…~<KB-JWT>
identity:    <issuer-JWT>~<disclosure>~…~          (no KB-JWT — bearer)
```

KB-JWT (decoded):

```jsonc
// header: { "typ": "kb+jwt", "alg": "EdDSA" }
{
  "iat": 1739577600,
  "aud": "https://service.example.gov/verifier",   // the relying party — anti-misdirection
  "nonce": "n-0S6_WzA2Mj",                          // from the verifier's request — anti-replay
  "sd_hash": "X9y...="                              // hash over issuer-JWT + the presented disclosures
}
// signed with the parent's private key (the one whose public JWK is in delegation.cnf)
```

### 12.5 Flows

**Issuance (Issuance Adapter ⊂ issuer — constructs; the issuer signs, per I1):**

```python
def issue_delegation(subject_id, delegate_jwk, scope, valid_until):
    idx = issuer.status_list("delegations").allocate()      # D4: issuer owns the list
    payload = {
      "vct": f"{NS}/DelegationCredential",
      "iss": ISSUER_ID, "iat": now(), "exp": epoch(valid_until),
      "sub": subject_id,                                    # linkage anchor == identity.sub
      "cnf": {"jwk": delegate_jwk},                         # bind to the delegate's key
      "delegation": {
        "on_behalf_of": subject_id,
        "allowed_action": scope.actions,
        "valid_until": valid_until,
        "allow_further_delegation": scope.re_delegable,
      },
      "status": {"status_list": {"idx": idx, "uri": STATUS_URI}},
    }
    return ISSUER.sign_sdjwt(payload, sd_claims=[])         # I1: the ISSUER signs, not the adapter
# Bearer identity credential: same shape, NO cnf, births status list, sd_claims=[given_name, birth_date, …]
```

**Presentation & verification (Presentation Adapter ⊂ verifier):**

```python
def evaluate(presented, request):                          # presented: [{sdjwt, disclosures, kbjwt?}]
    creds, holder_key = [], {}
    for p in presented:
        assert verify_issuer_sig(p.sdjwt, TRUSTED_ISSUERS)  # I3: the issuer is the trust anchor
        claims = reconstruct(p.sdjwt, p.disclosures)        # digest-check every disclosure
        if "cnf" in claims:                                 # key binding only if cnf is present
            assert p.kbjwt and verify_jwt(p.kbjwt, key=claims["cnf"]["jwk"])
            assert p.kbjwt["aud"]    == THIS_VERIFIER         # anti-misdirection
            assert p.kbjwt["nonce"]  == request.nonce         # anti-replay
            assert p.kbjwt["sd_hash"] == sd_hash(p.sdjwt, p.disclosures)
            holder_key[id(p)] = jwk_thumbprint(claims["cnf"]["jwk"])
        creds.append((p, claims))

    identity = first(c for _, c in creds if "delegation" not in c)
    deleg_p, delegation = (first((p, c) for p, c in creds if "delegation" in c)
                           or (None, None))

    if delegation is None:                                  # self-presentation (post-transition)
        return decide_self_service(identity, request)

    # LINKAGE — the same_subject analog, enforced HERE (DCQL credential_sets requested the pair)
    assert delegation["delegation"]["on_behalf_of"] == identity["sub"]
    # INVOCATION — the presenter must be the named delegate
    assert holder_key[id(deleg_p)] == jwk_thumbprint(delegation["cnf"]["jwk"])
    # AUTHORIZATION / caveats
    assert delegation["iss"] in TRUSTED_ISSUERS
    assert now() <= parse(delegation["delegation"]["valid_until"])
    assert request.action in delegation["delegation"]["allowed_action"]
    if "parent_capability" in delegation:                   # re-delegation chain (JWT links)
        assert verify_delegation_chain(delegation)          # each link signed + attenuating
    # STATUS — Token Status List, checked uniformly across formats (D4)
    for c in (identity, delegation):
        if "status" in c:
            assert status_bit(c["status"]["status_list"]) == 0   # 0 = valid
    # THRESHOLD authorization is verifier POLICY over claims, never binding (see 12.7)
    assert compute_age(identity["birth_date"], now()) >= request.required_age

    emit_consent_receipt(identity, delegation, request)     # D6
    return ALLOW
```

### 12.6 Revocation & transition — Token Status List (the 1:1 of Bitstring Status List)

Revocation is a pure format substitution; the model is identical.

| | W3C Bitstring Status List (JSON-LD) | IETF Token Status List (SD-JWT) |
|---|---|---|
| Pointer in credential | `credentialStatus` → `statusListIndex` + `statusListCredential` | `status` → `status_list` (`idx` + `uri`) |
| Published artefact | a status-list **VC** (gzipped bit array) | a **Status List Token** (JWT/CWT, compressed bit array) |
| Revoke / verify | issuer flips the bit; verifier fetches + checks | issuer flips the bit; verifier fetches + checks |

**Transition without reissuance:** the bearer identity credential is **never reissued**. Control
transitions — emancipation, majority, custody change — by the issuer **flipping the *delegation*
credential's status bit** (or letting its `exp` lapse). The adapter's status check (D4) then fails
the delegation, ending the delegate's authority, while the identity credential is untouched. This
is the exact mirror of the JSON-LD/Bitstring behaviour.

### 12.7 Lifecycle — short-term and long-term

Binding (whose key is in `cnf`) and authorization (what age threshold the claims + verifier policy
establish) are **independent axes**. Age thresholds live in verifier policy over `birth_date`; they
are never encoded in binding. One bearer credential therefore serves *every* threshold, and a
capable minor can self-act at the age of consent **without any reissuance**.

| Phase | Identity credential | Delegation credential | Who acts |
|---|---|---|---|
| **Minority** | bearer, issued once | valid, `cnf` = parent | parent only (bearer identity is inert without it) |
| **Consent window** (e.g. 15–18) | *same* bearer credential | valid but *scoped* (caveats exclude matters the minor may self-handle) | **both, concurrently** — child self-presents for age-of-consent matters; parent for guardianship matters |
| **Majority / emancipation** | *same* bearer credential | revoked (status bit) or `exp` lapsed | child only |

The transition is therefore **delegation revocation**, not identity reissuance. Between the
delegation lapsing and any optional upgrade, the safe default is *deny* for anything requiring
authority — no dangling access.

### 12.8 Safeguards

1. **Bearer identity is inert alone.** Any action requiring authority needs a co-presented,
   key-bound authority credential naming the presenter. A thief holding the identity bytes cannot
   forge the KB-JWT for a credential bound to someone else's key, nor obtain an issuer-minted one.
2. **Delegate authentication** via `cnf` + KB-JWT, with `aud` (anti-misdirection), `nonce`
   (anti-replay), and `sd_hash` (binds the KB-JWT to exactly what was presented).
3. **Independent revocation** of the delegation via Token Status List (issuer-owned, D4), checked
   uniformly across formats by the adapter.
4. **Self-expiring delegation** via `exp` / `valid_until` — defence-in-depth behind the status list.
5. **Safe gap** — no valid delegation + bearer identity ⇒ deny for authority-bearing actions.
6. **Binding ≠ authorization** — age thresholds are verifier policy over claims; a minor at the age
   of consent self-acts without reissuance.
7. **Optional strong-binding uplift** — for high-assurance, device-bound *self*-service, reissue the
   identity credential with `cnf` = child. Honest caveat: a *bearer* identity credential has weak
   presenter authentication for solo self-service (a property it shares with bearer JSON-LD and with
   paper documents); the uplift is the only way past it, and it is opt-in.

### 12.9 JSON-LD ↔ SD-JWT VC mapping

| Concern | JSON-LD path | SD-JWT VC path |
|---|---|---|
| Credential format | W3C VCDM (JSON-LD) + Data Integrity (Ed25519Signature2020) | IETF SD-JWT VC |
| Holder binding | VP-layer (control of subject DID) / bearer QR | `cnf` + KB-JWT (per credential) / bearer (no `cnf`) |
| Cross-credential linkage | DIF PE `same_subject` | DCQL `credential_sets` + adapter policy (claim equality on `sub`) |
| Capability backend | ZCAP-LD (`capabilityDelegation` proof chain) | JSON `delegation` claims + JWT chain for re-delegation |
| Revocation | W3C Bitstring Status List | IETF Token Status List |
| Selective disclosure | not native (whole-VC) | native (per-claim disclosures) |
| Transition w/o reissuance | bearer VC + revoke delegation | bearer SD-JWT + revoke delegation |
| Optional strong self-auth | reissue to a child-controlled DID (key custody) | reissue with `cnf` = child |

Both paths converge on the **same trust model, the same two adapters, and the same uniform status
check** — they diverge only in encoding. D5's normalization layer is precisely the seam that lets
one delegation-decision implementation serve both.

---

## 13. Open questions

1. **Integration hook depth:** what is the cleanest, supported way to (a) inject PD constraints
   into, and (b) retrieve the verified VP from, Inji and walt.id respectively? This determines how
   "policy-only" the presentation adapter can stay vs. how much it must re-verify.
2. **Capability carrier:** `termsOfUse` vs `evidence` vs a dedicated profile property — which
   survives both issuers' canonicalization and both verifiers' processing without being dropped?
3. **Re-delegation policy:** do v1 use cases need parent → secondary-guardian re-delegation, or is
   single-hop issuer → delegate sufficient?
4. **Receipt trust:** do relying parties need to *verify* the adapter's audit receipt, or is it
   purely an internal accountability log? (Affects whether the receipt key needs publishing.)
5. **Status freshness:** caching policy for issuer status lists at the presentation adapter
   (latency vs. revocation propagation time).
6. **Bearer linkage anchor (SD-JWT):** which stable subject identifier — `sub`, a registry person
   ID, or a dedicated claim — anchors the linkage check for *bearer* SD-JWT identity credentials,
   which carry no holder-key DID? (See §12.)
