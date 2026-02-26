# Delegated Access PoC — Architecture

## What This Project Does

A parent needs to access government services on behalf of their child — enrolling them in school, collecting benefits, or visiting a hospital. Today this typically requires physical documents and in-person visits. This project proves that **verifiable digital credentials** can solve this problem securely and instantly.

The system issues two digital credentials: a **Birth Certificate** proving the child's identity, and a **Parental Delegation Credential** proving the parent's authority to act on the child's behalf. These are cryptographically linked — a verifier can confirm in seconds that the parent is authorised to represent that specific child, that the credentials haven't expired, and that neither has been revoked.

If a credential is compromised or a delegation is withdrawn, an administrator can revoke it instantly through a web interface. Any subsequent verification attempt will fail.

---

## Architecture Overview

```md
                         ┌──────────────────────────┐
                         │      Credential Issuer    │
                         │   (issuer-api :7002)      │
                         └────────┬─────────────────┘
                                  │ issues
                    ┌─────────────┼─────────────────┐
                    ▼                                ▼
          ┌──────────────────┐            ┌──────────────────────────┐
          │ BirthCertificate │            │ ParentalDelegation       │
          │ subject: child   │◄──────────►│ subject: parent          │
          │ index: N         │ same_subject│ onBehalfOf: child       │
          └────────┬─────────┘  linking   │ index: M                 │
                   │                      └────────┬─────────────────┘
                   │                               │
                   └───────────┬───────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │   Parent's Wallet   │
                    │  (wallet-api :7001) │
                    └────────┬────────────┘
                             │ presents both
                             ▼
                    ┌─────────────────────┐      ┌─────────────────────┐
                    │      Verifier       │─────►│  Status List Service│
                    │ (verifier-api :7003)│checks │  (:7006)            │
                    └─────────────────────┘      └─────────────────────┘
```

## Credential Linking (same_subject)

The two credentials are linked by the child's DID:

| Field | BirthCertificate | ParentalDelegationCredential |
| --- | --- | --- |
| Subject DID | `credentialSubject.id` = child | `credentialSubject.id` = parent |
| Link to child | — | `credentialSubject.onBehalfOf.id` = child |

The verifier's presentation definition enforces a `same_subject` constraint: `BirthCertificate.credentialSubject.id` must equal `ParentalDelegationCredential.credentialSubject.onBehalfOf.id`. Both credentials must be presented together; neither is sufficient alone.

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
| **status-list-service** | 7006 | Go | Manages revocation bitstring, signs status list credential, provides management UI |
| **verification-adapter** | 7105 | Go | User-facing verification UI with QR code and result display |
| **web-portal** | 7102 | Next.js (walt.id) | Credential issuance and verification portal |
| **vc-repo** | 7103 | Nuxt (walt.id) | Credential template repository |
| **demo-wallet** | 7101 | Nuxt (walt.id) | Browser-based wallet UI |
| **caddy** | — | Caddy | Reverse proxy, routes all ports |
| **postgres** | 5432 | PostgreSQL | Wallet persistence |

## Custom Components

### Status List Service (`status-list-service/`)

A Go microservice implementing W3C BitstringStatusList revocation.

| File | Purpose |
| --- | --- |
| `main.go` | HTTP server, route registration, config from env vars |
| `bitstring.go` | 131,072-bit array with GZIP+base64url encoding, disk persistence |
| `handlers.go` | Revoke, reinstate, allocate index, query status, list credentials |
| `signing.go` | Delegates JWT signing to issuer-api's `/raw/jwt/sign` endpoint |
| `wallet.go` | Proxies wallet API for the management UI (avoids CORS) |

**Key endpoints:**

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/status/revocation/1` | Serves signed BitstringStatusListCredential (verifiers fetch this) |
| POST | `/status/revoke` | Sets bit to 1 (revoked) |
| POST | `/status/reinstate` | Sets bit to 0 (active) |
| POST | `/status/allocate` | Returns next available index |
| GET | `/status/query/{index}` | Returns current status of an index |
| GET | `/` | Management UI (login with wallet credentials, revoke/reinstate) |

### Verification Adapter (`verification-adapter-waltid/`)

A Go web application providing a user-friendly verification flow.

| File | Purpose |
| --- | --- |
| `main.go` | HTTP server, session cleanup, template loading |
| `verifier.go` | Creates verification sessions with presentation definition and policies |
| `handlers.go` | Home page, QR display, polling, result rendering |
| `session.go` | In-memory session store with 30-minute TTL |

The presentation definition requests both credential types and enforces `same_subject` linking between `credentialSubject.id` (BirthCertificate) and `credentialSubject.onBehalfOf.id` (ParentalDelegationCredential).

## Verification Policies

Every verification checks these policies:

| Policy | What It Checks |
| --- | --- |
| `signature` | EdDSA cryptographic signature is valid |
| `expired` | Credential has not passed its expiration date |
| `not-before` | Credential's validity period has started |
| `credential-status` | BitstringStatusList bit is 0 (not revoked) |
| `presentation-definition` | Both required credential types are present |
| `same_subject` | Child's DID matches across both credentials |

## Test Script (`test-delegated-access.sh`)

Automated end-to-end test covering the full lifecycle:

```txt
A. Issue both credentials → Verify → PASS (all policies green)
B. Revoke BirthCertificate → Verify → FAIL (credential-status fails)
C. Reinstate BirthCertificate → Verify → PASS (all policies green again)
```

Run: `bash scripts/test-delegated-access.sh`

## Docker Networking

All inter-service communication uses Docker DNS (`http://issuer-api:7002`, `http://status-list-service:7006`). The `statusListCredential` URL embedded in credentials uses the Docker service name so the verifier can fetch the status list from inside the Docker network. External access from the host uses `localhost:{port}` via Caddy.
