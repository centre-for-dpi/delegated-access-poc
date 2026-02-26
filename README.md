# Delegated Access PoC

A proof of concept for enabling a trusted party (e.g. a parent) to act on behalf of a credential subject (e.g. a minor child) using W3C Verifiable Credentials — while preserving verifiability, independent revocability, and a clear path for transitioning control when the delegation is no longer needed.

## Approach

The W3C [Verifiable Credentials Implementation Guidelines 1.0](https://www.w3.org/TR/vc-imp-guide/) describes several delegation patterns. This PoC implements a **Linked Credential Chain** such that the issuer issues a separate delegation credential that is presented alongside the subject's credential at verification time.

This approach was chosen because it supports independent revocation of the delegation without reissuing the underlying credential, enables clean transition of control (e.g. when a minor reaches legal age), and does not require the subject to participate in issuing the delegation.

## How it works

Two credentials are issued and held in the parent's wallet:

- **Birth Certificate** — issued to the child (proving their identity)
- **Parental Delegation Credential** — issued to the parent, referencing the child's DID via an `onBehalfOf` field

At verification, both must be presented together. The verifier enforces a `same_subject` constraint confirming that the child referenced in the delegation matches the subject of the birth certificate. Either credential can be independently revoked at any time via [W3C BitstringStatusList](https://www.w3.org/TR/vc-bitstring-status-list/).

Built on the [walt.id](https://walt.id) identity stack.

## Prerequisites

- Docker and Docker Compose
- ~2GB RAM

## Quick Start

```bash
cd waltid-identity/docker-compose
docker compose up --build -d
```

This starts all services. First run takes a few minutes to build.

## Services

| Service | URL | Purpose |
| --- | --- | --- |
| Wallet | <http://localhost:7101> | Credential wallet |
| Web Portal | <http://localhost:7102> | Issue and verify credentials |
| Verification UI | <http://localhost:7105> | Verify delegated credentials and result display in a custom UI |
| Revocation Manager | <http://localhost:7006> | Revoke/reinstate credentials in a custom UI |

## Run Tests

```bash
bash scripts/test-delegated-access.sh
```

Runs the full lifecycle: issue → verify → revoke → verify (fails) → reinstate → verify (passes).

## Docker Hub Images

| Image | Tag |
| --- | --- |
| `adammwaniki/adamrepo` | `stable` (verifier-api) |
| `adammwaniki/adamrepo` | `status-list-service-stable` |
| `adammwaniki/adamrepo` | `verification-adapter-stable` |

## Further Reading

See [docs/architecture.md](docs/architecture.md) for the full architectural document covering credential linking, revocation, service details, and verification policies.
