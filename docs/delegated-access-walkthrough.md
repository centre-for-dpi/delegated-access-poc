# Delegated Access — Walkthrough & Standards Alignment

> How this PoC implements delegated access for Verifiable Credentials, and how that
> implementation maps onto the W3C recommended patterns and the internal
> *Technical Note: Delegated Access for VCs*.

---

## 1. The problem in one sentence

A **parent** must be able to hold, present, and consent to verification of a credential
on behalf of a **child** (the credential subject) — verifiably, with the delegation
**independently revocable** and a **clean path to transfer control** when the child comes
of age — without anyone needing proprietary infrastructure.

This PoC answers that by issuing **two** credentials and binding them together at
verification time:

| Credential | Subject | Holder (presenter) | Role |
|---|---|---|---|
| **Birth Certificate** | the child (`did:key` minted by the issuer) | the parent | proves *who* the child is |
| **Parental Delegation Credential** | the parent (parent's wallet DID) | the parent | proves the parent may *act for* that child |

At verification both are presented in a **single Verifiable Presentation**, and the
verifier enforces a `same_subject` constraint: *the child referenced inside the delegation
credential must be the same DID as the subject of the birth certificate.* Either credential
can be revoked independently via a W3C BitstringStatusList.

This is the **Linked Credential Chain (Type I)** pattern from the Technical Note, presented
using the **Holder ≠ Subject** mechanism of the W3C VC Data Model.

---

## 2. The trust model — why the parent never needs the child's key

The subtle but important design decision: **the parent does not control the child's DID.**

- The birth certificate's subject is a `did:key` that the **issuer generated** for the child
  (`subjectDidStrategy: "generate"`, `issuer-portal/issuance.go:127`). It is just *data about*
  the child; the parent holds a copy but proves nothing about that key.
- The delegation credential's subject is the **parent's own wallet DID**
  (`subjectDidStrategy: "wallet"`). When the parent presents the VP, their wallet signs it,
  proving control of the *parent's* key.
- The delegation credential is **signed by the issuer** (the civil registry) and authoritatively
  states "parent P acts on behalf of child C". The verifier trusts that assertion because it
  trusts the issuer's signature — not because the parent demonstrated possession of the child's key.

So the chain of trust is:

```
  Issuer signature on delegation cred  →  asserts "parent P → child C"
  Parent's wallet signature on the VP  →  proves the presenter IS parent P
  same_subject check                   →  proves child C == subject of the birth cert
  ─────────────────────────────────────────────────────────────────────────────
  ∴ the presenter is authorised to act for the subject of the birth certificate
```

This is exactly the property the Technical Note's Scope demands: *act on behalf of the subject
while preserving verifiability.*

---

## 3. How delegation is **expressed** (issuance)

The delegation relationship is created entirely at issuance, by the issuer, with two ideas:

### 3a. `subjectDidStrategy` — who owns the subject DID

`issuer-portal/models.go:133` — every schema declares one of:

- `"generate"` → the issuer mints a fresh `did:key` for the subject (identity credentials, e.g. Birth Certificate).
- `"wallet"` → the subject DID is supplied by the holder's wallet at claim time (delegation credentials — subject is the parent).

### 3b. `did_ref` — the cross-credential link

`issuer-portal/issuance.go:42,55` — a schema field can have type `did_ref`. In the issue form
this renders a **credential picker** (`templates/did_ref_results.html`,
`handleCredentialDIDSearch` at `issuance.go:335`) that lists previously-issued credentials by
subject DID. When issuing the parent's delegation credential, the operator searches for the
child's birth certificate and selects it; the child's DID is written into the `did_ref` field
(e.g. `credentialSubject.onBehalfOf.id`).

That single shared DID — the child's `did:key`, appearing as the **subject** of the birth
certificate and as a **reference** inside the delegation credential — *is* the link in the
"linked credential chain". No proprietary structure; just a DID that appears in two places.

```
Birth Certificate                         Parental Delegation Credential
{                                         {
  credentialSubject: {                      credentialSubject: {
    id: "did:key:zChild…"   ◄───────┐         id: "did:key:zParent…",   (parent's wallet DID)
    fullName: "Maria…"              │         role: "Mother",
  }                                 └──────────onBehalfOf: { id: "did:key:zChild…" }   (did_ref)
}                                         }
```

Both credentials also carry a `credentialStatus` (BitstringStatusListEntry) with **their own**
status-list index, so each is revocable on its own (`issuance.go:160`).

---

## 4. How delegation is **verified** (presentation)

The verifier's policy, in the Technical Note's words, is: *accept a presentation where the
holder differs from the subject **if** a valid delegation credential is co-presented and its
referenced subject matches the identity credential.* The PoC builds the presentation-definition
that encodes this **dynamically from the schemas** — it is not hardcoded to "birth certificate +
parental delegation".

### Dynamic constraint generation

`verification-portal/verifier.go` (jwt_vc_json) and `oidc4vp-adapter/verifier.go` (ldp_vc) both:

1. Fetch all schemas from the issuer portal (`/api/schemas`).
2. `AnalyzeSchemas()` classifies each schema:
   - has a `did_ref` field → **delegation** schema (`verifier.go:74`),
   - else `subjectDidStrategy == "generate"` → **identity** schema,
   - else → other.
3. `findDidRefPaths()` walks the schema (recursing into nested objects) to find every `did_ref`
   path.
4. `BuildVerificationRequest()` / `BuildPresentationDefinition()` emits input descriptors that:
   - tag the identity credential's `credentialSubject.id` with a field id, and
   - add a **`same_subject`** constraint on the delegation credential linking that field id to
     the `did_ref` path (`verifier.go:168`).

The emitted constraint is the heart of it:

```json
"same_subject": [
  { "field_id": ["subject_id_birthcertificate", "ref_parentaldelegation_onBehalfOf_id"],
    "directive": "required" }
]
```

### Two verification code paths

The PoC supports two credential formats, and each enforces `same_subject` differently — worth
understanding because it shows where the standard does (and doesn't) do the work for you:

| Path | Format | Verifier | How `same_subject` is enforced |
|---|---|---|---|
| **A** | `jwt_vc_json` | walt.id `verifier-api` (:7003) | The verifier **natively** evaluates the DIF Presentation Exchange `same_subject` directive. The PoC just hands it the constraint. |
| **B** | `ldp_vc` | `oidc4vp-adapter` (:7112) + MOSIP inji-verify-service | inji-verify only validates **signatures** — it does *not* evaluate PE constraints. So the adapter re-implements the check itself: `CheckSameSubject()` (`oidc4vp-adapter/verifier.go:401`) does a pairwise recursive DID cross-reference across the presented credentials, and the result is ANDed with per-credential signature validity (`handlers.go:235`). |

Both paths also run `signature`, `expired`, `not-before`, and `credential-status`
(BitstringStatusList) policies. The end-to-end happy-path + revoke + reinstate cycle for Path A
is exercised by `docs/test-delegated-access.sh`.

---

## 5. Lifecycle & transition of control

The Technical Note lists three transition mechanisms. The PoC implements two of them directly
and supports the third trivially:

| Mechanism (Technical Note) | Status in PoC | Where |
|---|---|---|
| **Status-list revocation of delegation** | ✅ Fully implemented & tested | Per-issuer `BitstringStatusList` (`issuer-portal/bitstring.go`); each credential has its own index; `/status/revoke`, `/reinstate`, `/query` endpoints. Test B/C revokes then reinstates and re-verifies. |
| **Expiry-driven delegation** | ✅ Implemented | The delegation credential is issued with `expirationDate` = the child's **18th birthday** (test data: child born `2015-03-10`, delegation expires `2033-03-10`), and the verifier runs the `expired` policy. After that date the delegation simply stops validating — no active revocation needed. |
| **Reissuance** | ◻️ Manual | When the child comes of age they can be issued a fresh credential bound to their own wallet DID. The issuer portal already supports `subjectDidStrategy: "wallet"`, so this is an ordinary issuance — no special code path. |

Because the delegation has its **own** status index, separate from the birth certificate, it
can be revoked **without touching the underlying identity credential** — the exact requirement
from the Note ("independently revocable… e.g. in a custody dispute"). Revoking the delegation
leaves the child's birth certificate fully valid.

---

## 6. Mapping to the Technical Note's four approaches

The Note evaluates four patterns. Here is how the PoC relates to each:

| Approach | Note's assessment | Used here? |
|---|---|---|
| **1. Multi-Subject Credential** (relationship embedded in `credentialSubject`) | Simple, works on offline cards, **but delegation can't be revoked independently** | ❌ Deliberately avoided — fails the independent-revocation requirement. |
| **2. Linked Credential Chain — Type I** (issuer issues a separate delegation credential) | **Recommended.** Independent revocation, clean transition, multiple delegates | ✅ **This is the implemented pattern.** Issuer (civil registry) issues both credentials. |
| **3. Linked Credential Chain — Type II** (the *child* issues the delegation credential) | Same benefits, but depends on the child being able to issue/consent | ❌ Not used — a minor can't reliably issue/consent, which is the whole point. |
| **4. Holder ≠ Subject Presentation** (VP `holder` ≠ VC subject + co-presented guardianship proof) | Spec-aligned; requires verifier policy configuration | ✅ **Also used — it's the *presentation mechanism* for Approach 2.** The parent is the VP holder; the birth-cert subject is the child; the delegation credential is the co-presented guardianship proof; the `same_subject` policy is the verifier configuration. |

**The key insight:** Approaches 2 and 4 are not alternatives here — the PoC uses **2 for how the
delegation is *expressed*** (a separate, independently-revocable issuer-signed credential) and
**4 for how it is *presented and verified*** (holder ≠ subject + verifier policy). That
combination is precisely what the Note's "Considerations" section anticipates: *"the main
implementation work would be on the verifier policy side: teaching verifiers to accept a
two-credential presentation and validate the delegation chain."* That verifier-side work is
`AnalyzeSchemas` + `same_subject` generation + the adapter's `CheckSameSubject`.

---

## 7. Mapping to W3C / standards

| Standard | How it's used |
|---|---|
| **W3C VC Data Model** (subject vs holder) | The architecture rests on the data model's distinction between `credentialSubject` and a presentation's `holder`. The birth cert's subject is the child; the VP's holder/signer is the parent. |
| **W3C VC Implementation Guidelines** (the "Verifiable Implementations Guideline" cited in the Note) | Source of the four delegation patterns. The PoC implements the guide's Linked-Credential-Chain + Holder≠Subject patterns. |
| **W3C Bitstring Status List v1.0** | `BitstringStatusListEntry` with `statusPurpose: "revocation"` on each credential; per-issuer 131,072-bit bitstring served as a status-list credential; verifier fetches it and checks the bit. Enables independent, reissue-free revocation. |
| **DIF Presentation Exchange** (used by OID4VP) | `input_descriptors`, `constraints.fields`, JSONPath filters, and the **`same_subject`** directive that links the two credentials. Note: `same_subject` is a DIF PE feature, natively honoured by walt.id (Path A) and re-implemented by the adapter for ldp_vc (Path B). |
| **OpenID for Verifiable Credential Issuance (OID4VCI)** | Pre-authorized-code flow carries both credentials into the wallet. The issuer-portal even runs its own minimal OID4VCI server for `ldp_vc` (`issuer-portal/oidc.go`). |
| **OpenID for Verifiable Presentations (OID4VP)** | `openid4vp://` request, `direct_post` response carrying the `vp_token`. Used for both online verification paths. |
| **Ed25519Signature2020 / `did:key`** | Proof suite and DID method for the `ldp_vc` path, verifiable offline by MOSIP inji-verify. |

A note on rigor: the "chain" here is a **data-level reference** (a shared DID enforced by
verifier policy), not a cryptographic capability chain (e.g. ZCAP-LD `capabilityDelegation`).
For the parent/child-guardianship use case this is appropriate and matches the W3C guidance — the
issuer's signature on the delegation credential is the authority, so a formal capability-proof
chain isn't required.

---

## 8. The "stack-agnostic / wallet-agnostic / physical media" requirement

The Note requires the solution work *"across issuing platforms, verification platforms, and
wallet-agnostic supporting both digital wallets and physical media such as signed QR codes on
plastic cards."* The PoC addresses this with its **`ldp_vc` path**:

- The credential is a **JSON-LD VC with an embedded Ed25519Signature2020 proof** — self-contained,
  not dependent on the issuing platform being online.
- The **PixelPass adapter** (:7110) encodes that signed VC as a **CBOR → zlib → Base45 QR code**
  — the "signed QR code on a plastic card" case — which **MOSIP Inji Verify** scans and validates
  **fully offline** (signature + structure), no proprietary backend.
- Verification is split across **independent platforms** (walt.id verifier *and* MOSIP inji-verify),
  demonstrating cross-stack interoperability rather than a single vendor's closed loop.

The digital-wallet case is covered by the walt.id demo wallet (jwt_vc_json) and the custom
**go-wallet** (:7111, ldp_vc).

---

## 9. Honest gaps & things to be aware of

- **Two formats, two enforcement points.** `same_subject` is enforced *by the verifier* for
  jwt_vc_json but *by the adapter* for ldp_vc (because inji-verify only checks signatures). The
  security property is equivalent, but it lives in different code — worth knowing when reasoning
  about trust.
- **`did_ref` path vs nested-object shape.** The dynamic portal links on the literal `did_ref`
  field path; the hand-written `test-delegated-access.sh` nests the child DID under
  `onBehalfOf.id`. Both work, but a schema's `did_ref` field must sit at the path the verifier
  expects — keep schema design and the picker in sync.
- **Reissuance is manual.** Transition-by-reissuance is supported by the issuance machinery but
  isn't an automated workflow.
- **No proof the parent consented vs. was authorised.** The model proves the *issuer* authorised
  the parent; it does not separately capture the parent's runtime consent beyond their act of
  presenting. That's consistent with the use case but not a cryptographic consent receipt.
- **`credentialStatus` is stripped from `ldp_vc` before signing** (`signing.go`, see
  architecture.md §"ldp_vc Signing") because MOSIP's `LdpStatusChecker` expects a JSON-LD status
  list. So for the ldp_vc path, BitstringStatusList revocation is **not** currently enforced at
  verification — revocation is fully wired only on the jwt_vc_json (walt.id) path. This is a known
  limitation of the offline/MOSIP path.

---

## 10. Where to look in the code

| Concern | File |
|---|---|
| Schema model: `subjectDidStrategy`, field types | `issuer-portal/models.go` |
| `did_ref` field → credential picker at issuance | `issuer-portal/issuance.go` (`buildFormFields`, `handleCredentialDIDSearch`) |
| Identity vs delegation classification, `did_ref` discovery | `verification-portal/verifier.go` & `oidc4vp-adapter/verifier.go` (`AnalyzeSchemas`, `findDidRefPaths`) |
| Dynamic `same_subject` PD generation (jwt_vc_json) | `verification-portal/verifier.go` (`BuildVerificationRequest`) |
| Dynamic PD + manual cross-reference (ldp_vc) | `oidc4vp-adapter/verifier.go` (`BuildPresentationDefinition`, `CheckSameSubject`) |
| BitstringStatusList revocation | `issuer-portal/bitstring.go` |
| Ed25519Signature2020 signing (ldp_vc) | `issuer-portal/signing.go` |
| Offline signed-QR encoding | `pixelpass-adapter/server.js` |
| End-to-end lifecycle test (issue→verify→revoke→reinstate) | `docs/test-delegated-access.sh` |
| Full architecture reference | `docs/architecture.md` |

---

### TL;DR

This PoC implements the W3C-recommended **Linked Credential Chain (Type I)** delegation pattern,
**presented** via the **Holder ≠ Subject** mechanism. The issuer issues a separately-revocable
delegation credential that references the child's DID; at verification both credentials are
co-presented and a dynamically-generated `same_subject` policy proves the delegation refers to
the identity credential's subject. Independent revocation (BitstringStatusList) and expiry-driven
transition (delegation `expirationDate` = the child's 18th birthday) cover the
transfer-of-control requirement. The `ldp_vc` + PixelPass-QR + MOSIP-Inji path delivers the
stack-agnostic / offline / physical-card requirement.
