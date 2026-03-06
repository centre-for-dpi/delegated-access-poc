package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/piprate/json-gold/ld"
)

// --- Shared JSON-LD processor (stateless, thread-safe) ---

var ldProcessor = ld.NewJsonLdProcessor()

// ldDocumentLoader caches HTTP fetches of JSON-LD contexts so repeated
// canonicalization calls don't re-download the same context URLs.
var ldDocumentLoader = ld.NewCachingDocumentLoader(ld.NewDefaultDocumentLoader(nil))

// canonicalize returns the URDNA2015 N-quads canonical form of a JSON-LD document.
func canonicalize(doc map[string]any) (string, error) {
	opts := ld.NewJsonLdOptions("")
	opts.Algorithm = "URDNA2015"
	opts.Format = "application/n-quads"
	opts.DocumentLoader = ldDocumentLoader

	result, err := ldProcessor.Normalize(doc, opts)
	if err != nil {
		return "", fmt.Errorf("URDNA2015: %w", err)
	}
	s, ok := result.(string)
	if !ok {
		return "", fmt.Errorf("normalize returned %T, want string", result)
	}
	return s, nil
}

// sha256Digest returns the SHA-256 hash of s as a byte slice.
func sha256Digest(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// base58btcEncode encodes b using the base58btc alphabet (Bitcoin / multibase 'z').
func base58btcEncode(b []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	// Count leading zero bytes — each maps to a leading '1'.
	leading := 0
	for _, v := range b {
		if v != 0 {
			break
		}
		leading++
	}
	// Encode remaining bytes via repeated division by 58.
	num := make([]byte, len(b))
	copy(num, b)
	var out []byte
	for len(num) > 0 {
		rem := 0
		var next []byte
		for _, v := range num {
			cur := rem*256 + int(v)
			if len(next) > 0 || cur/58 > 0 {
				next = append(next, byte(cur/58))
			}
			rem = cur % 58
		}
		out = append(out, alphabet[rem])
		num = next
	}
	for i := 0; i < leading; i++ {
		out = append(out, '1')
	}
	// Reverse.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// verificationMethodFor derives the verification method ID from an issuer DID.
func verificationMethodFor(did string) string {
	switch {
	case strings.HasPrefix(did, "did:key:"):
		key := strings.TrimPrefix(did, "did:key:")
		return did + "#" + key
	case strings.HasPrefix(did, "did:jwk:"):
		return did + "#0"
	default:
		return did + "#key-0"
	}
}

// ed25519KeyFromIssuer extracts the ed25519 private key from an IssuerProfile's stored JWK.
// The JWK is stored as { "type": "jwk", "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "...", "d": "..." } }.
// The private key seed is the base64url-decoded "d" parameter.
func ed25519KeyFromIssuer(issuer *IssuerProfile) (ed25519.PrivateKey, error) {
	var container struct {
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(issuer.IssuerKey, &container); err != nil {
		return nil, fmt.Errorf("parse issuerKey outer: %w", err)
	}
	raw := container.JWK
	if len(raw) == 0 {
		raw = issuer.IssuerKey // flat JWK format fallback
	}
	var jwk struct {
		D string `json:"d"`
	}
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("parse JWK: %w", err)
	}
	if jwk.D == "" {
		return nil, fmt.Errorf("issuerKey has no private key (d parameter missing)")
	}
	seed, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("decode private key seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed length %d != %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// normalizeContextArray converts the @context value from a JSON-LD document
// into a []any suitable for use as a context array. Preserves both string
// URIs and object entries (e.g. {"@vocab": "..."}).
func normalizeContextArray(raw any) []any {
	switch v := raw.(type) {
	case string:
		return []any{v}
	case []any:
		return v
	default:
		return nil
	}
}

// contextHasStringEntry checks if a context array contains a specific string URI.
func contextHasStringEntry(ctx []any, uri string) bool {
	for _, item := range ctx {
		if s, ok := item.(string); ok && s == uri {
			return true
		}
	}
	return false
}

// contextHasVocab checks if any object entry in the context array defines @vocab.
func contextHasVocab(ctx []any) bool {
	for _, item := range ctx {
		if m, ok := item.(map[string]any); ok {
			if _, has := m["@vocab"]; has {
				return true
			}
		}
	}
	return false
}

// signLdpVc signs a JSON-LD credential as an Ed25519Signature2020 ldp_vc.
//
// The private key is extracted from the issuer profile and used entirely within
// this function — it is never returned or written anywhere outside this process.
//
// Normalizations applied before signing:
//   - issuer is coerced to a plain DID string (avoids canonical-form divergence
//     between JSON-LD processors when the issuer field is an {id, name} object)
//   - credentialStatus is stripped (JWT-format status lists are not accepted by
//     Inji's LdpStatusChecker; revocation via Walt.id verifier still works for
//     jwt_vc_json credentials issued through the standard flow)
//   - Ed25519Signature2020 context is added if absent
//
// The signature algorithm matches ld-signatures-java / Inji vcverifier-jar:
//   hashData = SHA256(URDNA2015(proofOptions)) || SHA256(URDNA2015(credential))
//   proofValue = 'z' + base58btc(Ed25519Sign(hashData))
func signLdpVc(issuer *IssuerProfile, document map[string]any) (map[string]any, error) {
	privateKey, err := ed25519KeyFromIssuer(issuer)
	if err != nil {
		return nil, err
	}

	issuerDID := issuer.IssuerDID
	vm := verificationMethodFor(issuerDID)

	// Shallow copy + normalise
	doc := make(map[string]any, len(document)+1)
	for k, v := range document {
		doc[k] = v
	}
	doc["issuer"] = issuerDID  // coerce to plain IRI string
	delete(doc, "credentialStatus") // strip JWT status list reference

	// Build context array: ensure Ed25519Signature2020 context is present,
	// and add @vocab for custom terms so all JSON-LD processors (Go json-gold,
	// Java Titanium, Python pyld) produce identical canonical N-quads.
	const ed25519Ctx = "https://w3id.org/security/suites/ed25519-2020/v1"
	ctxAny := normalizeContextArray(doc["@context"])
	if !contextHasStringEntry(ctxAny, ed25519Ctx) {
		ctxAny = append(ctxAny, ed25519Ctx)
	}
	if !contextHasVocab(ctxAny) {
		ctxAny = append(ctxAny, map[string]any{"@vocab": "https://example.org/vocab#"})
	}
	doc["@context"] = ctxAny

	now := time.Now().UTC().Format(time.RFC3339)
	proofOptions := map[string]any{
		"@context":           ctxAny,
		"type":               "Ed25519Signature2020",
		"created":            now,
		"verificationMethod": vm,
		"proofPurpose":       "assertionMethod",
	}

	canonProof, err := canonicalize(proofOptions)
	if err != nil {
		return nil, fmt.Errorf("canonicalize proof options: %w", err)
	}
	canonCred, err := canonicalize(doc)
	if err != nil {
		return nil, fmt.Errorf("canonicalize credential: %w", err)
	}

	hashData := append(sha256Digest(canonProof), sha256Digest(canonCred)...)
	sig := ed25519.Sign(privateKey, hashData)
	proofValue := "z" + base58btcEncode(sig)

	proof := map[string]any{
		"type":               "Ed25519Signature2020",
		"created":            now,
		"verificationMethod": vm,
		"proofPurpose":       "assertionMethod",
		"proofValue":         proofValue,
	}

	result := make(map[string]any, len(doc)+1)
	for k, v := range doc {
		result[k] = v
	}
	result["proof"] = proof
	return result, nil
}

// handleAPISignLdp handles POST /api/sign/ldp.
//
// Request body: { "issuerDid": "did:key:...", "document": { ...JSON-LD credential... } }
// Response: signed ldp_vc document as JSON.
//
// If SIGN_API_TOKEN is configured, the request must include:
//   Authorization: Bearer <token>
func handleAPISignLdp(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.SignAPIToken != "" {
			if r.Header.Get("Authorization") != "Bearer "+cfg.SignAPIToken {
				jsonError(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		var req struct {
			IssuerDID string         `json:"issuerDid"`
			Document  map[string]any `json:"document"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.IssuerDID == "" || req.Document == nil {
			jsonError(w, "issuerDid and document are required", http.StatusBadRequest)
			return
		}

		var issuer *IssuerProfile
		for _, p := range store.ListIssuers() {
			if p.IssuerDID == req.IssuerDID {
				issuer = p
				break
			}
		}
		if issuer == nil {
			jsonError(w, "no issuer found for DID: "+req.IssuerDID, http.StatusNotFound)
			return
		}

		signed, err := signLdpVc(issuer, req.Document)
		if err != nil {
			jsonError(w, "signing failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signed)
	}
}

// signStatusListCredential signs a BitstringStatusListCredential as a JWT via
// the Walt.id issuer-api. Kept for backward compatibility with jwt_vc_json
// credentials whose credentialStatus references expect a JWT-format status list.
func signStatusListCredential(cfg Config, issuer *IssuerProfile, credentialData map[string]any) (string, error) {
	body := map[string]any{
		"issuerKey":      json.RawMessage(issuer.IssuerKey),
		"issuerDid":      issuer.IssuerDID,
		"subjectDid":     issuer.IssuerDID,
		"credentialData": credentialData,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal signing request: %w", err)
	}

	resp, err := http.Post(cfg.IssuerAPIURL+"/raw/jwt/sign", "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return "", fmt.Errorf("call issuer-api: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("issuer-api returned %d: %s", resp.StatusCode, string(respBody))
	}

	jwt := strings.Trim(string(respBody), "\" \n\r")
	return jwt, nil
}
