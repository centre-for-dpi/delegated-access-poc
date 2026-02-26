#!/bin/bash
#
# Delegated Access PoC — End-to-End Test Script
#
# Tests the Linked Credential Chain (Type I) pattern:
#   1. Issues a BirthCertificate (child as subject) with credentialStatus
#   2. Issues a ParentalDelegationCredential (parent as subject, onBehalfOf child)
#   3. Claims both into the parent's wallet
#   4. Creates a verification session with same_subject + credential-status policies
#   5. Presents both credentials in a single VP
#   6. Verifies the result (happy path)
#   7. Revokes the BirthCertificate and verifies failure
#   8. Reinstates the BirthCertificate and verifies success again
#
# Prerequisites:
#   - Docker Compose stack running: COMPOSE_PROFILES=identity,opa docker compose up -d
#   - A wallet account registered (default: adamndegwa@gmail.com / 1234)
#
# Usage:
#   ./scripts/test-delegated-access.sh
#   ./scripts/test-delegated-access.sh --email user@example.com --password secret
#

set -euo pipefail

# --- Configuration -----------------------------------------------------------

SERVICE_HOST="${SERVICE_HOST:-localhost}"
ISSUER_API="http://${SERVICE_HOST}:7002"
VERIFIER_API="http://${SERVICE_HOST}:7003"
WALLET_API="http://${SERVICE_HOST}:7001"
STATUS_LIST_API="http://${SERVICE_HOST}:7006"

WALLET_EMAIL="${WALLET_EMAIL:-adamndegwa@gmail.com}"
WALLET_PASSWORD="${WALLET_PASSWORD:-1234}"

# Parse CLI args
while [[ $# -gt 0 ]]; do
  case $1 in
    --email) WALLET_EMAIL="$2"; shift 2 ;;
    --password) WALLET_PASSWORD="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# Issuer key (Ed25519 test key from walt.id examples)
ISSUER_KEY='{"type":"jwk","jwk":{"kty":"OKP","d":"mDhpwaH6JYSrD2Bq7Cs-pzmsjlLj4EOhxyI-9DM1mFI","crv":"Ed25519","kid":"Vzx7l5fh56F3Pf9aR3DECU5BwfrY6ZJe05aiWYWzan8","x":"T3T4-u1Xz3vAV2JwPNxWfs4pik_JLiArz_WTCvrCFUM"}}'
ISSUER_DID="did:key:z6MkjoRhq1jSNJdLiruSXrFFxagqrztZaXHqHGUTKJbcNywp"

# Child DID (deterministic for reproducibility)
CHILD_DID="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

# Status list credential URL embedded in credentials (Docker service name for
# verifier-api to fetch from inside the Docker network)
STATUS_LIST_CREDENTIAL_URL="http://status-list-service:7006/status/revocation/1"

# --- Helpers -----------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

step() { echo -e "\n${CYAN}=== $1 ===${NC}"; }
ok()   { echo -e "${GREEN}  ✓ $1${NC}"; }
fail() { echo -e "${RED}  ✗ $1${NC}"; }
info() { echo -e "${YELLOW}  → $1${NC}"; }

check_service() {
  local name=$1 url=$2
  if curl -sf -o /dev/null "$url" 2>/dev/null || curl -sf -o /dev/null -L "$url" 2>/dev/null; then
    ok "$name is reachable"
  else
    fail "$name at $url is not reachable"
    exit 1
  fi
}

# create_verify_session: creates a verification session and returns "VERIFY_URL SESSION_ID"
create_verify_session() {
  local verify_url
  verify_url=$(curl -s -X POST "$VERIFIER_API/openid4vc/verify" \
    -H "Content-Type: application/json" \
    -H "successRedirectUri: http://${SERVICE_HOST}:7102/success" \
    -H "errorRedirectUri: http://${SERVICE_HOST}:7102/error" \
    -d '{
    "vp_policies": ["signature", "presentation-definition"],
    "vc_policies": ["signature", "expired", "not-before", {"policy": "credential-status", "args": {"discriminator": "w3c", "value": 0, "purpose": "revocation", "type": "BitstringStatusList"}}],
    "request_credentials": [
      {
        "format": "jwt_vc_json",
        "input_descriptor": {
          "id": "birth_certificate",
          "name": "Child Birth Certificate",
          "purpose": "Verify child identity",
          "format": {"jwt_vc_json": {"alg": ["EdDSA"]}},
          "constraints": {
            "fields": [
              {"path": ["$.vc.type"], "filter": {"type": "string", "pattern": "BirthCertificate"}},
              {"id": "child_subject_id", "path": ["$.vc.credentialSubject.id"]}
            ]
          }
        }
      },
      {
        "format": "jwt_vc_json",
        "input_descriptor": {
          "id": "delegation_credential",
          "name": "Parental Delegation Credential",
          "purpose": "Verify delegated authority over the child",
          "format": {"jwt_vc_json": {"alg": ["EdDSA"]}},
          "constraints": {
            "same_subject": [{"field_id": ["child_subject_id", "delegated_child_id"], "directive": "required"}],
            "fields": [
              {"path": ["$.vc.type"], "filter": {"type": "string", "pattern": "ParentalDelegationCredential"}},
              {"id": "delegated_child_id", "path": ["$.vc.credentialSubject.onBehalfOf.id"]}
            ]
          }
        }
      }
    ]
  }')

  local session_id
  session_id=$(echo "$verify_url" | grep -oP 'state=\K[^&]+')
  echo "$verify_url" "$session_id"
}

# present_and_check: presents credentials and checks the verification result.
# Args: $1=VERIFY_URL $2=SESSION_ID $3=expected ("pass" or "fail")
present_and_check() {
  local verify_url=$1 session_id=$2 expected=$3

  local present_result
  present_result=$(curl -s -X POST "$WALLET_API/wallet-api/wallet/$WALLET_ID/exchange/usePresentationRequest" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"presentationRequest\": \"$verify_url\",
      \"selectedCredentials\": [\"$BIRTH_ID\", \"$DELEG_ID\"],
      \"disclosures\": null
    }")

  local redirect_uri
  redirect_uri=$(echo "$present_result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('redirectUri',''))" 2>/dev/null || echo "")

  # Fetch session result
  local session_result verification_result
  session_result=$(curl -s "$VERIFIER_API/openid4vc/session/$session_id")
  verification_result=$(echo "$session_result" | python3 -c "import json,sys; print(json.load(sys.stdin)['verificationResult'])")

  # Print policy details
  echo "$session_result" | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data['policyResults']['results']
for group in results:
    cred = group['credential']
    for p in group['policyResults']:
        status = '✓' if p['is_success'] else '✗'
        print(f'  {status} {cred}: {p[\"policy\"]}')
" 2>/dev/null || true

  if [ "$expected" = "pass" ]; then
    if [ "$verification_result" = "True" ]; then
      ok "verificationResult: true (as expected)"
      return 0
    else
      fail "verificationResult: $verification_result (expected: true)"
      echo "$session_result" | python3 -m json.tool 2>/dev/null || echo "$session_result"
      return 1
    fi
  else
    if [ "$verification_result" = "False" ]; then
      ok "verificationResult: false (as expected — credential revoked)"
      return 0
    else
      fail "verificationResult: $verification_result (expected: false)"
      return 1
    fi
  fi
}

# --- Pre-flight checks -------------------------------------------------------

step "Pre-flight checks"
check_service "Issuer API"       "$ISSUER_API"
check_service "Verifier API"     "$VERIFIER_API"
check_service "Wallet API"       "$WALLET_API"
check_service "Status List API"  "$STATUS_LIST_API/health"

# Verify credential types are registered
ISSUER_METADATA=$(curl -s "$ISSUER_API/draft13/.well-known/openid-credential-issuer")
if echo "$ISSUER_METADATA" | python3 -c "import json,sys; d=json.load(sys.stdin); assert 'BirthCertificate_jwt_vc_json' in d['credential_configurations_supported']" 2>/dev/null; then
  ok "BirthCertificate_jwt_vc_json registered in issuer metadata"
else
  fail "BirthCertificate_jwt_vc_json not found in issuer metadata"
  exit 1
fi
if echo "$ISSUER_METADATA" | python3 -c "import json,sys; d=json.load(sys.stdin); assert 'ParentalDelegationCredential_jwt_vc_json' in d['credential_configurations_supported']" 2>/dev/null; then
  ok "ParentalDelegationCredential_jwt_vc_json registered in issuer metadata"
else
  fail "ParentalDelegationCredential_jwt_vc_json not found in issuer metadata"
  exit 1
fi

# --- Step 1: Authenticate to wallet -----------------------------------------

step "Step 1: Authenticate to wallet"
TOKEN=$(curl -s -X POST "$WALLET_API/wallet-api/auth/login" \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d "{\"type\":\"email\",\"email\":\"$WALLET_EMAIL\",\"password\":\"$WALLET_PASSWORD\"}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
ok "Logged in as $WALLET_EMAIL"

WALLET_ID=$(curl -s "$WALLET_API/wallet-api/wallet/accounts/wallets" \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['wallets'][0]['id'])")
ok "Wallet ID: $WALLET_ID"

# --- Step 1b: Clear old credentials from wallet ------------------------------

step "Step 1b: Clear old credentials from wallet"
OLD_CREDS=$(curl -s "$WALLET_API/wallet-api/wallet/$WALLET_ID/credentials" \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -c "
import json, sys
creds = json.load(sys.stdin)
for c in creds:
    print(c['id'])
")
DELETED=0
for cred_id in $OLD_CREDS; do
  curl -s -X DELETE "$WALLET_API/wallet-api/wallet/$WALLET_ID/credentials/$cred_id" \
    -H "Authorization: Bearer $TOKEN" > /dev/null
  DELETED=$((DELETED + 1))
done
ok "Deleted $DELETED old credential(s)"

# --- Step 2: Allocate status list indices ------------------------------------

step "Step 2: Allocate status list indices"
BIRTH_INDEX=$(curl -s -X POST "$STATUS_LIST_API/status/allocate" \
  -H "Content-Type: application/json" \
  -d '{"credentialType":"BirthCertificate","holderName":"Maria Garcia Lopez"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['index'])")
DELEG_INDEX=$(curl -s -X POST "$STATUS_LIST_API/status/allocate" \
  -H "Content-Type: application/json" \
  -d '{"credentialType":"ParentalDelegationCredential","holderName":"Ana Lopez Martinez"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['index'])")
ok "BirthCertificate index: $BIRTH_INDEX"
ok "ParentalDelegationCredential index: $DELEG_INDEX"

# --- Step 3: Issue BirthCertificate -----------------------------------------

step "Step 3: Issue BirthCertificate (child as subject, with credentialStatus)"
info "Issuer DID: $ISSUER_DID"
info "Child DID:  $CHILD_DID"
info "Status list index: $BIRTH_INDEX"

BIRTH_CERT_OFFER=$(curl -s -X POST "$ISSUER_API/openid4vc/jwt/issue" \
  -H "Content-Type: application/json" \
  -d '{
  "issuerKey": '"$ISSUER_KEY"',
  "issuerDid": "'"$ISSUER_DID"'",
  "credentialConfigurationId": "BirthCertificate_jwt_vc_json",
  "credentialData": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": "urn:uuid:birth-cert-001",
    "type": ["VerifiableCredential", "BirthCertificate"],
    "issuer": {
      "id": "'"$ISSUER_DID"'",
      "name": "Testa Gava Civil Registry"
    },
    "issuanceDate": "2026-02-25T00:00:00Z",
    "credentialSubject": {
      "id": "'"$CHILD_DID"'",
      "fullName": "Maria Garcia Lopez",
      "firstName": "Maria",
      "lastName": "Garcia Lopez",
      "dateOfBirth": "2015-03-10",
      "sex": "F",
      "placeOfBirth": {"country": "Testland", "city": "Testa Gava"},
      "nationality": "TST",
      "documentNumber": "12345678",
      "registrationNumber": "REG-2015-00042",
      "dateOfRegistration": "2015-03-15"
    },
    "credentialStatus": {
      "type": "BitstringStatusListEntry",
      "statusPurpose": "revocation",
      "statusListIndex": "'"$BIRTH_INDEX"'",
      "statusListCredential": "'"$STATUS_LIST_CREDENTIAL_URL"'"
    }
  },
  "mapping": {
    "id": "<uuid>",
    "issuer": {"id": "<issuerDid>"},
    "issuanceDate": "<timestamp>"
  },
  "authenticationMethod": "PRE_AUTHORIZED"
}')

if echo "$BIRTH_CERT_OFFER" | grep -q "openid-credential-offer://"; then
  ok "BirthCertificate credential offer created"
else
  fail "Failed to create BirthCertificate offer: $BIRTH_CERT_OFFER"
  exit 1
fi

# --- Step 4: Issue ParentalDelegationCredential ------------------------------

step "Step 4: Issue ParentalDelegationCredential (parent as subject, onBehalfOf child)"
info "Status list index: $DELEG_INDEX"

DELEGATION_OFFER=$(curl -s -X POST "$ISSUER_API/openid4vc/jwt/issue" \
  -H "Content-Type: application/json" \
  -d '{
  "issuerKey": '"$ISSUER_KEY"',
  "issuerDid": "'"$ISSUER_DID"'",
  "credentialConfigurationId": "ParentalDelegationCredential_jwt_vc_json",
  "credentialData": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": "urn:uuid:delegation-001",
    "type": ["VerifiableCredential", "ParentalDelegationCredential"],
    "issuer": {
      "id": "'"$ISSUER_DID"'",
      "name": "Testa Gava Civil Registry"
    },
    "issuanceDate": "2026-02-25T00:00:00Z",
    "expirationDate": "2033-03-10T00:00:00Z",
    "credentialSubject": {
      "id": "placeholder-for-parent-did",
      "fullName": "Ana Lopez Martinez",
      "firstName": "Ana",
      "lastName": "Lopez Martinez",
      "documentNumber": "87654321",
      "role": "Mother",
      "onBehalfOf": {
        "id": "'"$CHILD_DID"'",
        "fullName": "Maria Garcia Lopez",
        "documentNumber": "12345678",
        "dateOfBirth": "2015-03-10"
      }
    },
    "credentialStatus": {
      "type": "BitstringStatusListEntry",
      "statusPurpose": "revocation",
      "statusListIndex": "'"$DELEG_INDEX"'",
      "statusListCredential": "'"$STATUS_LIST_CREDENTIAL_URL"'"
    }
  },
  "mapping": {
    "id": "<uuid>",
    "issuer": {"id": "<issuerDid>"},
    "credentialSubject": {"id": "<subjectDid>"},
    "issuanceDate": "<timestamp>",
    "expirationDate": "<timestamp-in:2557d>"
  },
  "authenticationMethod": "PRE_AUTHORIZED"
}')

if echo "$DELEGATION_OFFER" | grep -q "openid-credential-offer://"; then
  ok "ParentalDelegationCredential credential offer created"
else
  fail "Failed to create ParentalDelegationCredential offer: $DELEGATION_OFFER"
  exit 1
fi

# --- Step 5: Claim credentials into wallet -----------------------------------

step "Step 5: Claim both credentials into wallet"

# Claim BirthCertificate
CLAIM_RESULT=$(curl -s -X POST "$WALLET_API/wallet-api/wallet/$WALLET_ID/exchange/useOfferRequest" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: text/plain" \
  -d "$BIRTH_CERT_OFFER")
ok "BirthCertificate claimed"

# Claim ParentalDelegationCredential
CLAIM_RESULT=$(curl -s -X POST "$WALLET_API/wallet-api/wallet/$WALLET_ID/exchange/useOfferRequest" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: text/plain" \
  -d "$DELEGATION_OFFER")
ok "ParentalDelegationCredential claimed"

# --- Step 6: Verify wallet contents ------------------------------------------

step "Step 6: Verify wallet contents"

CRED_INFO=$(curl -s "$WALLET_API/wallet-api/wallet/$WALLET_ID/credentials" \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -c "
import json, sys, base64
creds = json.load(sys.stdin)
birth_id = None
deleg_id = None
for c in creds:
    parts = c['document'].split('.')
    payload = parts[1] + '=' * (4 - len(parts[1]) % 4)
    decoded = json.loads(base64.urlsafe_b64decode(payload))
    vc = decoded.get('vc', {})
    types = vc.get('type', [])
    cred_id = vc.get('id', c['id'])
    subj = vc.get('credentialSubject', {})
    status = vc.get('credentialStatus', {})
    if 'BirthCertificate' in types:
        birth_id = cred_id
        print(f'BIRTH_ID={cred_id}')
        print(f'BIRTH_SUBJECT={subj.get(\"id\", \"N/A\")}')
        print(f'BIRTH_STATUS_INDEX={status.get(\"statusListIndex\", \"N/A\")}')
    elif 'ParentalDelegationCredential' in types:
        deleg_id = cred_id
        print(f'DELEG_ID={cred_id}')
        print(f'DELEG_SUBJECT={subj.get(\"id\", \"N/A\")}')
        print(f'DELEG_ON_BEHALF_OF={subj.get(\"onBehalfOf\", {}).get(\"id\", \"N/A\")}')
        print(f'DELEG_STATUS_INDEX={status.get(\"statusListIndex\", \"N/A\")}')
")

eval "$CRED_INFO"

if [ -z "${BIRTH_ID:-}" ] || [ -z "${DELEG_ID:-}" ]; then
  fail "Could not find both credentials in wallet"
  info "Wallet contains: $CRED_INFO"
  exit 1
fi

ok "BirthCertificate in wallet (subject: $BIRTH_SUBJECT, statusIndex: $BIRTH_STATUS_INDEX)"
ok "ParentalDelegationCredential in wallet (onBehalfOf: $DELEG_ON_BEHALF_OF, statusIndex: $DELEG_STATUS_INDEX)"

if [ "$BIRTH_SUBJECT" = "$DELEG_ON_BEHALF_OF" ]; then
  ok "Child DID matches across both credentials: $BIRTH_SUBJECT"
else
  fail "Child DID mismatch: BirthCert=$BIRTH_SUBJECT vs Delegation.onBehalfOf=$DELEG_ON_BEHALF_OF"
  exit 1
fi

# =============================================================================
# TEST A: Happy path (not revoked)
# =============================================================================

step "TEST A: Verify credentials (should PASS — not revoked)"

read -r VERIFY_URL SESSION_ID <<< "$(create_verify_session)"
ok "Verification session created: $SESSION_ID"

present_and_check "$VERIFY_URL" "$SESSION_ID" "pass" || exit 1

# =============================================================================
# TEST B: Revoke BirthCertificate, verify again (should FAIL)
# =============================================================================

step "TEST B: Revoke BirthCertificate (index $BIRTH_INDEX)"

REVOKE_RESULT=$(curl -s -X POST "$STATUS_LIST_API/status/revoke" \
  -H "Content-Type: application/json" \
  -d "{\"statusListIndex\": $BIRTH_INDEX}")
REVOKE_STATUS=$(echo "$REVOKE_RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
ok "Revocation response: $REVOKE_STATUS"

# Confirm via query
QUERY_STATUS=$(curl -s "$STATUS_LIST_API/status/query/$BIRTH_INDEX" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
ok "Query confirms index $BIRTH_INDEX is: $QUERY_STATUS"

step "TEST B: Verify credentials (should FAIL — BirthCertificate revoked)"

read -r VERIFY_URL SESSION_ID <<< "$(create_verify_session)"
ok "Verification session created: $SESSION_ID"

present_and_check "$VERIFY_URL" "$SESSION_ID" "fail" || exit 1

# =============================================================================
# TEST C: Reinstate BirthCertificate, verify again (should PASS)
# =============================================================================

step "TEST C: Reinstate BirthCertificate (index $BIRTH_INDEX)"

REINSTATE_RESULT=$(curl -s -X POST "$STATUS_LIST_API/status/reinstate" \
  -H "Content-Type: application/json" \
  -d "{\"statusListIndex\": $BIRTH_INDEX}")
REINSTATE_STATUS=$(echo "$REINSTATE_RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
ok "Reinstatement response: $REINSTATE_STATUS"

# Confirm via query
QUERY_STATUS=$(curl -s "$STATUS_LIST_API/status/query/$BIRTH_INDEX" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
ok "Query confirms index $BIRTH_INDEX is: $QUERY_STATUS"

step "TEST C: Verify credentials (should PASS — BirthCertificate reinstated)"

read -r VERIFY_URL SESSION_ID <<< "$(create_verify_session)"
ok "Verification session created: $SESSION_ID"

present_and_check "$VERIFY_URL" "$SESSION_ID" "pass" || exit 1

# --- Summary -----------------------------------------------------------------

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Delegated Access PoC — ALL TESTS PASSED${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Pattern:  Linked Credential Chain (Type I)"
echo "  Issuer:   $ISSUER_DID"
echo "  Child:    $CHILD_DID (Maria Garcia Lopez)"
echo "  Parent:   Wallet holder (Ana Lopez Martinez)"
echo ""
echo "  Status List:"
echo "    BirthCertificate index:            $BIRTH_INDEX"
echo "    ParentalDelegationCredential index: $DELEG_INDEX"
echo "    Status list URL:                   $STATUS_LIST_CREDENTIAL_URL"
echo ""
echo "  Tests:"
echo "    A. Happy path (not revoked)        — PASS"
echo "    B. Revoked BirthCertificate        — correctly FAILED verification"
echo "    C. Reinstated BirthCertificate     — PASS again"
echo ""
echo "  Policies verified:"
echo "    - signature (EdDSA)"
echo "    - expired / not-before"
echo "    - credential-status (BitstringStatusList revocation)"
echo "    - same_subject cross-credential validation"
echo "    - presentation-definition"
echo ""
