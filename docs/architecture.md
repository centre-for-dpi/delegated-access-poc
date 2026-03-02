# Delegated Access PoC — Architecture

## What This Project Does

A parent needs to access government services on behalf of their child — enrolling them in school, collecting benefits, or visiting a hospital. Today this typically requires physical documents and in-person visits. This project proves that **verifiable digital credentials** can solve this problem securely and instantly.

An administrator designs credential schemas through the **Issuer Portal** — defining identity credentials (e.g. Birth Certificate) and delegation credentials (e.g. Parental Delegation) with fields that reference other credentials via DID. The system dynamically detects these `did_ref` links and enforces `same_subject` constraints at verification time, ensuring the delegation credential refers to the correct identity credential.

If a credential is compromised or a delegation is withdrawn, an administrator can revoke it instantly through the Issuer Portal. Any subsequent verification attempt will fail.

---

## Architecture Overview

```
                    ┌──────────────────────────────┐
                    │       Issuer Portal (:7107)   │
                    │  schema design, issuance,     │
                    │  revocation, status list mgmt  │
                    └──────────┬───────────────────┘
                               │ issues via issuer-api
                 ┌─────────────┼──────────────────┐
                 ▼                                 ▼
       ┌───────────────────┐           ┌─────────────────────────┐
       │ Identity Credential│           │ Delegation Credential    │
       │ subjectDID: generate│◄────────►│ subjectDID: wallet       │
       │ e.g. BirthCert     │same_subject│ did_ref → identity DID  │
       └────────┬───────────┘  linking  └────────┬────────────────┘
                │                                │
                └────────────┬───────────────────┘
                             ▼
                  ┌─────────────────────┐
                  │   Holder's Wallet   │
                  │  (wallet-api :7001) │
                  └────────┬────────────┘
                           │ presents both
                           ▼
              ┌──────────────────────────┐
              │  Verification Portal     │
              │       (:7108)            │
              │  dynamic schema select,  │
              │  QR code, result display │
              └────────┬─────────────────┘
                       │ creates session via
                       ▼
              ┌─────────────────────┐
              │   verifier-api      │
              │     (:7003)         │
              └─────────────────────┘
```

## Credential Linking (same_subject)

Credentials are linked dynamically based on schema field types:

- **Identity credentials** have `subjectDidStrategy: "generate"` — the issuer generates a unique DID for the credential subject (stored in `credentialSubject.id`).
- **Delegation credentials** contain one or more `did_ref` fields — these reference DIDs from other credentials (e.g. `credentialSubject.onBehalfOf` or `credentialSubject.onBehalfOf.id`).

The verification portals discover these relationships at runtime by fetching schemas from the Issuer Portal's `/api/schemas` endpoint. The presentation definition's `same_subject` constraint ensures the `did_ref` value in the delegation credential matches `credentialSubject.id` in the identity credential. Both credentials must be presented together; neither is sufficient alone.

## Revocation (BitstringStatusList)

Each credential embeds a `credentialStatus` block pointing to a shared status list:

```json
{
  "type": "BitstringStatusListEntry",
  "statusPurpose": "revocation",
  "statusListIndex": "N",
  "statusListCredential": "http://status-list-service:7006/status/revocation/1"
}
```

The status list service maintains a 131,072-bit bitstring (W3C BitstringStatusList spec). Each credential is assigned a unique index. Setting bit N to 1 revokes the credential at that index. The verifier fetches the status list during verification and checks the relevant bit.

```txt
Bitstring:  [0][0][0][1][0][0]...   ← bit 3 is set = credential at index 3 is revoked
             0  1  2  3  4  5
```

## Services

| Service | Port | Technology | Role |
| --- | --- | --- | --- |
| **issuer-api** | 7002 | walt.id (Kotlin) | Signs and issues credentials via OID4VCI |
| **verifier-api** | 7003 | walt.id (Kotlin) | Verifies presentations via OID4VP |
| **wallet-api** | 7001 | walt.id (Kotlin) | Stores credentials, handles claim/present flows |
| **issuer-portal** | 7107 | Go | Schema design, credential issuance, revocation, status list management |
| **verification-portal** | 7108 | Go | Dynamic credential verification UI with per-credential result coloring |
| **verification-adapter** | 7105 | Go | Original verification UI (hardcoded credential types) |
| **opa-server** | 8181 | Open Policy Agent | Policy evaluation for verifier |
| **web-portal** | 7102 | Next.js (walt.id) | walt.id credential issuance and verification portal |
| **vc-repo** | 7103 | Nuxt (walt.id) | Credential template repository |
| **demo-wallet** | 7101 | Nuxt (walt.id) | Browser-based wallet UI |
| **caddy** | — | Caddy | Reverse proxy, routes all ports |
| **postgres** | 5432 | PostgreSQL | Wallet persistence |

## Custom Components

### Issuer Portal (`issuer-portal/`)

A Go web application for schema design, credential issuance, and revocation management.

| File | Purpose |
| --- | --- |
| `main.go` | HTTP server, route registration, config |
| `models.go` | Schema registry with field types (`string`, `number`, `date`, `did_ref`, etc.) |
| `schema.go` | Schema CRUD, HOCON config generation for issuer-api |
| `issuance.go` | Credential issuance via OID4VCI (creates offer URLs) |
| `bitstring.go` | BitstringStatusList revocation (131,072-bit array) |
| `signing.go` | JWT signing delegation to issuer-api |
| `api.go` | REST API endpoints (`/api/schemas`, `/api/issue`, etc.) |
| `docker.go` | Live issuer-api container restart on schema changes |

**Key concepts:**
- **`subjectDidStrategy`**: `"generate"` = issuer creates a unique DID for the subject (identity credentials); `"wallet"` = subject DID comes from the holder's wallet (delegation credentials)
- **`did_ref` field type**: Marks a field as a DID reference to another credential's subject, enabling automatic `same_subject` constraint generation
- **Schema API** (`/api/schemas`): Returns all registered schemas with fields and `subjectDidStrategy`, consumed by verification portals

### Verification Portal (`verification-portal/`)

A Go web application providing dynamic credential verification with per-credential result coloring.

| File | Purpose |
| --- | --- |
| `main.go` | HTTP server, session cleanup, template loading |
| `verifier.go` | Fetches schemas from issuer-portal, detects delegation relationships, builds dynamic verification requests with `same_subject` constraints |
| `handlers.go` | Home page, QR display, polling, per-credential result rendering |
| `session.go` | In-memory session store, polymorphic policy error handling |

**Dynamic delegation detection:** On each verification request, the portal fetches schemas from the issuer-portal API, identifies identity schemas (`subjectDidStrategy: "generate"`) and delegation schemas (containing `did_ref` fields), and builds a presentation definition with `same_subject` constraints linking the delegation's `did_ref` path to the identity credential's `credentialSubject.id`.

**Per-credential result coloring:** When verification fails, each credential card is individually colored red or green based on which policies failed. VP-level `same_subject` failures are attributed to the delegation credential (identified by `ref_` prefix in the constraint field IDs).

### Verification Adapter (`verification-adapter-waltid/`)

The original Go verification UI with hardcoded credential types (BirthCertificate + ParentalDelegationCredential). Superseded by the verification-portal for dynamic use cases.

## Verification Policies

Every verification checks these policies:

| Level | Policy | What It Checks |
| --- | --- | --- |
| VC | `signature` | EdDSA cryptographic signature is valid |
| VC | `expired` | Credential has not passed its expiration date |
| VC | `not-before` | Credential's validity period has started |
| VC | `credential-status` | BitstringStatusList bit is 0 (not revoked) |
| VP | `signature` | Verifiable presentation signature is valid |
| VP | `presentation-definition` | All required credential types are present |
| VP | `same_subject` | DID references match across linked credentials |

The `same_subject` constraint is generated dynamically based on `did_ref` fields discovered in the schemas.

## Docker Networking

All inter-service communication uses Docker DNS (e.g. `http://issuer-api:7002`, `http://issuer-portal:7107`). The `statusListCredential` URL embedded in credentials uses the Docker service name so the verifier can fetch the status list from inside the Docker network. External access from the host uses `localhost:{port}` via Caddy.
