package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// SchemaField mirrors the issuer-portal's FieldDefinition.
type SchemaField struct {
	Name   string        `json:"name"`
	Type   string        `json:"type"`
	Nested []SchemaField `json:"nested,omitempty"`
}

// SchemaInfo represents a credential schema from the issuer portal.
type SchemaInfo struct {
	ID                 string        `json:"id"`
	IssuerID           string        `json:"issuerId"`
	IssuerName         string        `json:"issuerName"`
	TypeName           string        `json:"typeName"`
	DisplayName        string        `json:"displayName"`
	Description        string        `json:"description"`
	Fields             []SchemaField `json:"fields"`
	FieldCount         int           `json:"fieldCount"`
	SubjectDidStrategy string        `json:"subjectDidStrategy"`
	Format             string        `json:"format"`
	IsDelegation       bool          `json:"-"`
}

// SchemaAnalysis holds the result of analyzing schemas for delegation relationships.
type SchemaAnalysis struct {
	IdentitySchemas   []SchemaInfo
	DelegationSchemas []SchemaInfo
	OtherSchemas      []SchemaInfo
	DidRefPaths       map[string][]string // typeName → list of JSON paths to did_ref fields
	HasDelegation     bool
}

// findDidRefPaths recursively finds fields of type "did_ref" and returns their JSON paths.
func findDidRefPaths(fields []SchemaField, prefix string) []string {
	var paths []string
	for _, f := range fields {
		path := f.Name
		if prefix != "" {
			path = prefix + "." + f.Name
		}
		if f.Type == "did_ref" {
			paths = append(paths, path)
		}
		if len(f.Nested) > 0 {
			paths = append(paths, findDidRefPaths(f.Nested, path)...)
		}
	}
	return paths
}

// AnalyzeSchemas classifies schemas into identity, delegation, and other categories.
func AnalyzeSchemas(schemas []SchemaInfo) SchemaAnalysis {
	analysis := SchemaAnalysis{
		DidRefPaths: make(map[string][]string),
	}

	for i := range schemas {
		paths := findDidRefPaths(schemas[i].Fields, "")
		if len(paths) > 0 {
			schemas[i].IsDelegation = true
			analysis.DelegationSchemas = append(analysis.DelegationSchemas, schemas[i])
			analysis.DidRefPaths[schemas[i].TypeName] = paths
			analysis.HasDelegation = true
		} else if schemas[i].SubjectDidStrategy == "generate" {
			analysis.IdentitySchemas = append(analysis.IdentitySchemas, schemas[i])
		} else {
			analysis.OtherSchemas = append(analysis.OtherSchemas, schemas[i])
		}
	}

	return analysis
}

// FetchLdpVcSchemas retrieves all registered ldp_vc schemas from the issuer portal.
func FetchLdpVcSchemas(cfg Config) ([]SchemaInfo, error) {
	resp, err := httpClient.Get(cfg.IssuerPortalURL + "/api/schemas")
	if err != nil {
		return nil, fmt.Errorf("fetching schemas: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("issuer portal returned %d: %s", resp.StatusCode, string(body))
	}

	var schemas []SchemaInfo
	if err := json.NewDecoder(resp.Body).Decode(&schemas); err != nil {
		return nil, fmt.Errorf("decoding schemas: %w", err)
	}

	// Filter to ldp_vc only
	var ldpSchemas []SchemaInfo
	for _, s := range schemas {
		if s.Format == "ldp_vc" {
			ldpSchemas = append(ldpSchemas, s)
		}
	}
	return ldpSchemas, nil
}

// BuildPresentationDefinition constructs a PD for ldp_vc credentials.
func BuildPresentationDefinition(schemas []SchemaInfo) map[string]any {
	analysis := AnalyzeSchemas(schemas)

	var inputDescriptors []map[string]any
	identityFieldIDs := make(map[string]string) // typeName → field_id

	// Identity schemas
	for _, s := range analysis.IdentitySchemas {
		fieldID := fmt.Sprintf("subject_id_%s", strings.ToLower(s.TypeName))
		identityFieldIDs[s.TypeName] = fieldID

		fields := []map[string]any{
			{
				"path": []string{"$.type"},
				"filter": map[string]any{
					"type":     "array",
					"contains": map[string]any{"const": s.TypeName},
				},
			},
		}
		if analysis.HasDelegation {
			fields = append(fields, map[string]any{
				"id":   fieldID,
				"path": []string{"$.credentialSubject.id"},
			})
		}

		inputDescriptors = append(inputDescriptors, map[string]any{
			"id":      strings.ToLower(s.TypeName),
			"name":    s.DisplayName,
			"purpose": "Verify " + s.DisplayName,
			"format": map[string]any{
				"ldp_vc": map[string]any{
					"proof_type": []string{"Ed25519Signature2020"},
				},
			},
			"constraints": map[string]any{"fields": fields},
		})
	}

	// Delegation schemas with same_subject constraints
	for _, s := range analysis.DelegationSchemas {
		paths := analysis.DidRefPaths[s.TypeName]
		fields := []map[string]any{
			{
				"path": []string{"$.type"},
				"filter": map[string]any{
					"type":     "array",
					"contains": map[string]any{"const": s.TypeName},
				},
			},
		}

		var sameSubjectEntries []map[string]any
		for _, path := range paths {
			jsonPath := "$.credentialSubject." + path
			refFieldID := fmt.Sprintf("ref_%s_%s",
				strings.ToLower(s.TypeName),
				strings.ReplaceAll(path, ".", "_"))

			fields = append(fields, map[string]any{
				"id":   refFieldID,
				"path": []string{jsonPath},
			})

			for _, identityFieldID := range identityFieldIDs {
				sameSubjectEntries = append(sameSubjectEntries, map[string]any{
					"field_id":  []string{identityFieldID, refFieldID},
					"directive": "required",
				})
			}
		}

		constraints := map[string]any{"fields": fields}
		if len(sameSubjectEntries) > 0 {
			constraints["same_subject"] = sameSubjectEntries
		}

		inputDescriptors = append(inputDescriptors, map[string]any{
			"id":      strings.ToLower(s.TypeName),
			"name":    s.DisplayName,
			"purpose": "Verify delegated authority via " + s.DisplayName,
			"format": map[string]any{
				"ldp_vc": map[string]any{
					"proof_type": []string{"Ed25519Signature2020"},
				},
			},
			"constraints": constraints,
		})
	}

	// Other schemas
	for _, s := range analysis.OtherSchemas {
		inputDescriptors = append(inputDescriptors, map[string]any{
			"id":      strings.ToLower(s.TypeName),
			"name":    s.DisplayName,
			"purpose": "Verify " + s.DisplayName,
			"format": map[string]any{
				"ldp_vc": map[string]any{
					"proof_type": []string{"Ed25519Signature2020"},
				},
			},
			"constraints": map[string]any{
				"fields": []map[string]any{
					{
						"path": []string{"$.type"},
						"filter": map[string]any{
							"type":     "array",
							"contains": map[string]any{"const": s.TypeName},
						},
					},
				},
			},
		})
	}

	return map[string]any{
		"id":                "delegated-access-ldp-" + generateID()[:8],
		"input_descriptors": inputDescriptors,
	}
}

// BuildOpenID4VPURL constructs the openid4vp:// authorization URL.
func BuildOpenID4VPURL(cfg Config, state, nonce string) string {
	pdURI := cfg.SelfURL + "/openid4vc/pd/" + state
	responseURI := cfg.SelfURL + "/openid4vc/verify/" + state

	return fmt.Sprintf(
		"openid4vp://authorize?response_type=vp_token&client_id=%s&state=%s&response_mode=direct_post&response_uri=%s&presentation_definition_uri=%s&nonce=%s",
		cfg.SelfURL,
		state,
		responseURI,
		pdURI,
		nonce,
	)
}

// ValidateVPToken decodes and validates a JWT VP token.
func ValidateVPToken(vpTokenStr string, sess *VerificationSession) ([]map[string]any, error) {
	parts := strings.SplitN(vpTokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	// Decode header
	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	// Decode payload
	payloadJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}

	// Extract signer DID from kid or iss
	signerDID := ""
	if kid, ok := header["kid"].(string); ok && strings.HasPrefix(kid, "did:key:") {
		signerDID = kid
	}
	if signerDID == "" {
		if iss, ok := payload["iss"].(string); ok && strings.HasPrefix(iss, "did:key:") {
			signerDID = iss
		}
	}
	if signerDID == "" {
		return nil, fmt.Errorf("no did:key found in JWT header.kid or payload.iss")
	}

	// Resolve public key from did:key
	pubKey, err := resolveDidKey(signerDID)
	if err != nil {
		return nil, fmt.Errorf("resolve did:key: %w", err)
	}

	// Verify EdDSA signature
	sigBytes, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	if !ed25519.Verify(pubKey, signingInput, sigBytes) {
		return nil, fmt.Errorf("EdDSA signature verification failed")
	}

	// Check nonce
	if nonce, ok := payload["nonce"].(string); ok {
		if nonce != sess.Nonce {
			return nil, fmt.Errorf("nonce mismatch: expected %s, got %s", sess.Nonce, nonce)
		}
	}

	// Check audience
	if aud, ok := payload["aud"].(string); ok {
		log.Printf("VP audience: %s", aud)
	}

	// Extract verifiable credentials from vp
	vp, ok := payload["vp"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no vp claim in JWT payload")
	}

	vcArray, ok := vp["verifiableCredential"].([]any)
	if !ok {
		return nil, fmt.Errorf("no verifiableCredential array in vp")
	}

	var credentials []map[string]any
	for _, vcRaw := range vcArray {
		switch vc := vcRaw.(type) {
		case map[string]any:
			// ldp_vc — JSON-LD object with embedded proof
			credentials = append(credentials, vc)
		case string:
			// JWT VC — try to decode
			vcPayload, err := parseJWTPayload(vc)
			if err != nil {
				log.Printf("WARNING: could not decode JWT VC: %v", err)
				continue
			}
			if vcBody, ok := vcPayload["vc"].(map[string]any); ok {
				credentials = append(credentials, vcBody)
			}
		default:
			log.Printf("WARNING: unexpected VC type: %T", vcRaw)
		}
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("no valid credentials found in VP")
	}

	return credentials, nil
}

// VerifyCredentialSignature validates an ldp_vc credential's Ed25519Signature2020
// by sending it to inji-verify-service.
func VerifyCredentialSignature(cfg Config, cred map[string]any) (bool, error) {
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return false, fmt.Errorf("marshal credential: %w", err)
	}

	verifyURL := cfg.InjiVerifyServiceURL + "/v1/verify/vc-verification"
	req, err := http.NewRequest("POST", verifyURL, bytes.NewReader(credJSON))
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/vc+ld+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("call inji-verify-service: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("inji-verify-service returned %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("parse response: %w", err)
	}

	status, _ := result["verificationStatus"].(string)
	return status == "SUCCESS", nil
}

// CheckSameSubject performs pairwise DID cross-reference matching across credentials.
func CheckSameSubject(credentials []map[string]any) *SameSubjectResult {
	for i := 0; i < len(credentials); i++ {
		subjA, ok := credentials[i]["credentialSubject"].(map[string]any)
		if !ok {
			continue
		}
		didA, ok := subjA["id"].(string)
		if !ok || !strings.HasPrefix(didA, "did:") {
			continue
		}
		typeA := extractTypeName(credentials[i])

		for j := 0; j < len(credentials); j++ {
			if i == j {
				continue
			}
			subjB, ok := credentials[j]["credentialSubject"].(map[string]any)
			if !ok {
				continue
			}
			// Search B's credentialSubject (excluding its own id) for A's DID
			searchObj := make(map[string]any)
			for k, v := range subjB {
				if k != "id" {
					searchObj[k] = v
				}
			}
			matches := findDidMatches(searchObj, didA, "")
			if len(matches) > 0 {
				typeB := extractTypeName(credentials[j])
				return &SameSubjectResult{
					Matched:        true,
					IdentityDid:    didA,
					MatchPath:      "credentialSubject." + matches[0],
					IdentityType:   typeA,
					DelegationType: typeB,
				}
			}
		}
	}
	return &SameSubjectResult{
		Matched: false,
		Reason:  "No cross-credential DID reference found",
	}
}

// findDidMatches recursively searches an object for a specific DID string.
func findDidMatches(obj map[string]any, targetDID string, prefix string) []string {
	var matches []string
	for key, val := range obj {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		switch v := val.(type) {
		case string:
			if v == targetDID {
				matches = append(matches, path)
			}
		case map[string]any:
			matches = append(matches, findDidMatches(v, targetDID, path)...)
		}
	}
	return matches
}

func extractTypeName(cred map[string]any) string {
	types, ok := cred["type"].([]any)
	if !ok || len(types) == 0 {
		return "unknown"
	}
	for _, t := range types {
		if s, ok := t.(string); ok && s != "VerifiableCredential" {
			return s
		}
	}
	return "unknown"
}

// --- did:key resolution ---

func resolveDidKey(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, "did:key:z") {
		return nil, fmt.Errorf("unsupported DID format: %s", did)
	}

	// Strip "did:key:z" prefix and base58btc decode
	encoded := did[len("did:key:z"):]
	decoded, err := base58btcDecode(encoded)
	if err != nil {
		return nil, fmt.Errorf("base58btc decode: %w", err)
	}

	// Strip multicodec prefix 0xed 0x01 (Ed25519)
	if len(decoded) < 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, fmt.Errorf("invalid Ed25519 multicodec prefix")
	}

	return ed25519.PublicKey(decoded[2:]), nil
}

const base58btcAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58btcDecode(input string) ([]byte, error) {
	result := big.NewInt(0)
	base := big.NewInt(58)

	for _, c := range input {
		idx := strings.IndexRune(base58btcAlphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58btc character: %c", c)
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(idx)))
	}

	// Count leading '1's (zero bytes)
	leadingZeros := 0
	for _, c := range input {
		if c != '1' {
			break
		}
		leadingZeros++
	}

	decoded := result.Bytes()
	// Prepend leading zero bytes
	output := make([]byte, leadingZeros+len(decoded))
	copy(output[leadingZeros:], decoded)
	return output, nil
}

func base58btcEncode(input []byte) string {
	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var result []byte
	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		result = append(result, base58btcAlphabet[mod.Int64()])
	}
	for _, b := range input {
		if b != 0 {
			break
		}
		result = append(result, base58btcAlphabet[0])
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}

// --- JWT helpers ---

func parseJWTPayload(jwt string) (map[string]any, error) {
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid JWT")
	}
	decoded, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(decoded, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}
