# Delegated Access PoC — Architecture

## Purpose

A parent accesses government services on behalf of their child using two verifiable credentials: an **identity credential** (e.g. Birth Certificate) and a **delegation credential** (e.g. Parental Delegation). The system enforces that the delegation refers to the correct identity via a `same_subject` DID constraint — both credentials must be presented together.

Schemas are designed dynamically through the Issuer Portal. Fields marked as `did_ref` create cross-credential DID links detected automatically at verification time. Credentials can be revoked instantly via BitstringStatusList.

---

## System Diagram

```
                     Issuer Portal (:7107)
                    schema design, issuance,
                  ldp_vc signing (Ed25519), revocation
                          │
            ┌─────────────┴──────────────┐
            ▼                            ▼
    Identity Credential         Delegation Credential
    subjectDID: generate   ◄──► subjectDID: wallet
    e.g. BirthCert          same_subject  did_ref → identity DID
            │                            │
            └────────────┬───────────────┘
                         ▼
                  Go Wallet (:7111)
                  ldp_vc credential store
                         │
           ┌─────────────┴──────────────────┐
           ▼                                ▼
   Verification Portal        PixelPass Adapter (:7110)
        (:7108)               wallet cred → CBOR+zlib+Base45 QR
   walt.id OID4VP flow                     │
   same_subject constraint                 ▼
           │                     Inji Verify (:7109)
           ▼                     offline QR scan + online OID4VP
    verifier-api (:7003)                   │
                                           ▼
                              inji-verify-service (internal)
                              Ed25519Signature2020 validation
```

---

## Services

### Core Infrastructure

| Service | Port | Image | Role |
|---|---|---|---|
| caddy | all published | caddy:2 | Reverse proxy for all services |
| postgres | 5432 | postgres | Wallet-api persistence |
| inji-verify-postgres | internal | postgres:13 | Inji verify-service persistence (Flyway) |

### Walt.id Services

| Service | Port | Role |
|---|---|---|
| wallet-api | 7001 | Credential store, OID4VCI/OID4VP flows (jwt_vc_json only) |
| issuer-api | 7002 | JWT credential signing via OID4VCI |
| verifier-api | 7003 | OID4VP presentation verification |
| demo-wallet | 7101 | Browser wallet UI |
| web-portal | 7102 | Walt.id issuance/verification portal |
| vc-repo | 7103 | Credential template repository |

### Custom Services (Go)

| Service | Port | Role |
|---|---|---|
| issuer-portal | 7107 | Schema CRUD, dual-format issuance, Ed25519 ldp_vc signing, revocation |
| go-wallet | 7111 | ldp_vc wallet — OID4VCI + OID4VP client, per-user Ed25519 keys, HTMX UI |
| verification-portal | 7108 | Dynamic OID4VP verification with same_subject constraints (jwt_vc_json) |
| oidc4vp-adapter | 7112 | OID4VP verifier for ldp_vc — Ed25519 sig validation via inji-verify-service, same_subject |
| verification-adapter | 7105 | Original hardcoded verification UI (superseded) |

### MOSIP Inji Verify

| Service | Port | Role |
|---|---|---|
| inji-verify-ui | 7109 (via Caddy) | React/nginx — online QR + offline scan UI |
| inji-verify-service | 8080 (internal) | Java Spring Boot — OID4VP sessions + VC signature validation |

### PixelPass Adapter

| Service | Port | Role |
|---|---|---|
| pixelpass-adapter | 7110 | Node.js — encodes ldp_vc as PixelPass QR; proxies vc-verification with Content-Type correction |

---

## Credential Formats

| Format | Issued by | Signed by | Verified by | Notes |
|---|---|---|---|---|
| `ldp_vc` | issuer-portal OID4VCI (`/oidc/*`) | issuer-portal Go process (Ed25519Signature2020) | inji-verify-service `LdpVerifier` | Target format. `@vocab` context entry required for cross-processor canonical consistency |
| `jwt_vc_json` | issuer-portal → walt.id issuer-api | issuer-api (JWT/EdDSA) | verifier-api | Legacy path. No embedded proof — incompatible with Inji Verify offline |

---

## Credential Linking

| Concept | Value | Meaning |
|---|---|---|
| `subjectDidStrategy: "generate"` | Identity credential | Issuer generates a unique DID for the subject |
| `subjectDidStrategy: "wallet"` | Delegation credential | Subject DID comes from the holder's wallet |
| `did_ref` field type | Any schema field | Marks a cross-credential DID reference → triggers `same_subject` constraint |

Verification portals fetch schemas from `/api/schemas`, detect `did_ref` links, and build presentation definitions with `same_subject` constraints automatically.

---

## ldp_vc Signing (issuer-portal `signing.go`)

```
hashData = SHA256(URDNA2015(proofOptions)) || SHA256(URDNA2015(credential))
proofValue = 'z' + base58btc(Ed25519.Sign(privateKey, hashData))
```

| Normalization | Why |
|---|---|
| `issuer` coerced to plain DID string | Java/Go JSON-LD processors diverge on `{id, name}` objects under `@type: @id` |
| `credentialStatus` stripped | Issuer-portal status lists are JWT; MOSIP `LdpStatusChecker` expects JSON-LD |
| `issuanceDate` in UTC | MOSIP rejects `ERR_ISSUANCE_DATE_IS_FUTURE_DATE` when local-time offset exceeds UTC |
| `@vocab` added to `@context` | Go `json-gold` keeps undefined `@type` values; Java Titanium/Python pyld drop them — `@vocab` forces consistent IRI expansion |
| Ed25519-2020 context added | Required for proof term definitions during canonicalization |

---

## Revocation (BitstringStatusList)

Each jwt_vc_json credential embeds a `credentialStatus` with a `statusListIndex`. The issuer-portal maintains a 131,072-bit bitstring per issuer. Setting bit N revokes credential N. The verifier fetches the status list at verification time.

ldp_vc credentials have `credentialStatus` stripped before signing (see above).

---

## Caddy Routing

| Port | Route | Upstream |
|---|---|---|
| 7001 | `/*` | wallet-api:7001 |
| 7002 | `/*` | issuer-api:7002 |
| 7003 | `/*` | verifier-api:7003 |
| 7101 | `/wallet-api/*` | wallet-api:7001 |
| 7101 | `/*` | waltid-demo-wallet:7101 |
| 7107 | `/*` | issuer-portal:7107 |
| 7108 | `/*` | verification-portal:7108 |
| 7109 | `/v1/verify/vc-verification` | pixelpass-adapter:7110 **(must be first)** |
| 7109 | `/v1/verify/*` | inji-verify-service:8080 |
| 7109 | `/*` | inji-verify-ui:8000 |
| 7110 | `/*` | pixelpass-adapter:7110 |
| 7111 | `/*` | go-wallet:7111 |
| 7112 | `/*` | oidc4vp-adapter:7112 |

---

## Custom Service Files

### issuer-portal/

| File | Purpose |
|---|---|
| main.go | HTTP server, routes, config |
| models.go | Schema/session types, `EffectiveFormat()` |
| schema.go | Schema CRUD; ldp_vc activates instantly, jwt_vc_json updates HOCON + restarts Walt.id |
| issuance.go | Dual-format issuance; ldp_vc creates pre-auth session + offer URL |
| oidc.go | Native OID4VCI: `/.well-known/openid-credential-issuer`, `/oidc/token`, `/oidc/credential` |
| signing.go | Ed25519Signature2020 signing (URDNA2015 via json-gold); private key stays in-process |
| bitstring.go | BitstringStatusList revocation |
| api.go | REST: `/api/schemas`, `/api/issuers` (key redacted), `/api/sign/ldp` |
| hocon.go | Generates issuer-api HOCON for jwt_vc_json schemas |
| docker.go | Live issuer-api container restart |

### go-wallet/

| File | Purpose |
|---|---|
| main.go | HTTP server, HTMX UI handlers, template rendering |
| models.go | Per-user data store (credentials, Ed25519 keys, sessions), did:key derivation |
| oidc.go | OID4VCI client: resolve offer → metadata → token exchange → credential request with proof JWT |
| presentation.go | OID4VP client: parse openid4vp:// URL, fetch PD, match credentials, build JWT VP, submit |
| api.go | Walt.id-compatible REST API (login, wallets, credentials) for pixelpass-adapter |

### oidc4vp-adapter/

| File | Purpose |
|---|---|
| main.go | HTTP server, routes, config |
| verifier.go | Schema fetch (ldp_vc only), PD building, VP token validation, did:key resolution, same_subject check |
| session.go | Session store, credential/result types |
| handlers.go | HTTP handlers: create session, serve PD, receive VP direct_post, poll results |

### verification-portal/

| File | Purpose |
|---|---|
| main.go | HTTP server, session cleanup |
| verifier.go | Fetches schemas, detects delegation relationships, builds same_subject constraints |
| handlers.go | QR display, polling, per-credential result coloring |
| session.go | Session store, policy error handling |

### pixelpass-adapter/

| File | Purpose |
|---|---|
| server.js | Express app: QR encoding (CBOR→zlib→Base45), `/api/qr` JSON endpoint, vc-verification proxy |

---

## MOSIP Inji Verify Internals

| Aspect | Detail |
|---|---|
| Signature verification | `LdpVerifier` → `URDNA2015Canonicalizer` → `SHA256(canon_proof) \|\| SHA256(canon_doc)` → Ed25519 verify |
| JSON-LD library | Titanium JSON-LD (`com.apicatalog.jsonld`) + `com.apicatalog.rdf.canon.RdfCanon` |
| Proof options context | `LdProof.builder().defaultContexts(true)` → `https://w3id.org/security/v3` (bundled locally; URL returns 404) |
| Multibase decoding | `io.ipfs.multibase.Multibase.decode()` — strips `z` prefix, base58btc decodes |
| Pre-signature validation | Rejects `issuanceDate > now` (`ERR_ISSUANCE_DATE_IS_FUTURE_DATE`) before checking signature |
| Status checking | `LdpStatusChecker` — warns if no `credentialStatus` (not fatal); expects JSON-LD status list |
| DID resolution | `did:key`, `did:jwk`, `did:web` |
| Debug logging | Set `LOGGING_LEVEL_IO_MOSIP: TRACE` env to see `Credential Verification Summary` with error codes |

---

## Docker Networking

All inter-service communication uses Docker DNS (e.g. `http://issuer-portal:7107`). External access from the host uses `localhost:{port}` via Caddy. For EC2 deployment, set `SERVICE_HOST` in `.env` to the public IP — all DIDs and callback URLs update automatically.

## Start Command

```bash
cd waltid-identity/docker-compose && docker compose --profile identity up -d --build
```
