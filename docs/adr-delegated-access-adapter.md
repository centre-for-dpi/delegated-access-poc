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
- **SD-JWT VC and mso_mdoc** — deferred; the format-abstraction layer (D5) leaves room for them.
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

## 12. Open questions

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
```
