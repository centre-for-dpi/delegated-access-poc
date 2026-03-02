package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// SchemaField mirrors the issuer-portal's FieldDefinition for JSON decoding.
type SchemaField struct {
	Name   string        `json:"name"`
	Type   string        `json:"type"`
	Nested []SchemaField `json:"nested,omitempty"`
}

// SchemaInfo represents a credential schema fetched from the issuer portal registry.
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
	IsDelegation       bool          `json:"-"` // computed, not from JSON
}

// SchemaAnalysis holds the result of analyzing schemas for delegation relationships.
type SchemaAnalysis struct {
	IdentitySchemas   []SchemaInfo
	DelegationSchemas []SchemaInfo
	OtherSchemas      []SchemaInfo            // schemas that are neither identity nor delegation
	DidRefPaths       map[string][]string     // typeName → list of JSON paths to did_ref fields
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

// AnalyzeSelectedSchemas runs analysis on a subset of selected schemas.
func AnalyzeSelectedSchemas(selected []SchemaInfo) SchemaAnalysis {
	return AnalyzeSchemas(selected)
}

// FetchSchemas retrieves all registered credential schemas from the issuer portal.
func FetchSchemas(cfg Config) ([]SchemaInfo, error) {
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
	return schemas, nil
}

// BuildVerificationRequest constructs the verifier API request body for the selected schemas,
// dynamically adding same_subject constraints when delegation credentials are present.
func BuildVerificationRequest(schemas []SchemaInfo) map[string]any {
	analysis := AnalyzeSelectedSchemas(schemas)

	var requestCredentials []map[string]any

	// Track field IDs for identity schemas (used in same_subject linking)
	identityFieldIDs := make(map[string]string) // typeName → field_id

	// Add identity schemas first (with subject ID field for same_subject linking)
	for _, s := range analysis.IdentitySchemas {
		fieldID := fmt.Sprintf("subject_id_%s", strings.ToLower(s.TypeName))
		identityFieldIDs[s.TypeName] = fieldID

		fields := []map[string]any{
			{"path": []string{"$.vc.type"}, "filter": map[string]any{"type": "string", "pattern": s.TypeName}},
		}
		// Only add subject ID field if there are delegation schemas that need it
		if analysis.HasDelegation {
			fields = append(fields, map[string]any{
				"id": fieldID, "path": []string{"$.vc.credentialSubject.id"},
			})
		}

		requestCredentials = append(requestCredentials, map[string]any{
			"format": "jwt_vc_json",
			"input_descriptor": map[string]any{
				"id":          strings.ToLower(s.TypeName),
				"name":        s.DisplayName,
				"purpose":     "Verify " + s.DisplayName,
				"format":      map[string]any{"jwt_vc_json": map[string]any{"alg": []string{"EdDSA"}}},
				"constraints": map[string]any{"fields": fields},
			},
		})
	}

	// Add delegation schemas with same_subject constraints
	for _, s := range analysis.DelegationSchemas {
		paths := analysis.DidRefPaths[s.TypeName]

		fields := []map[string]any{
			{"path": []string{"$.vc.type"}, "filter": map[string]any{"type": "string", "pattern": s.TypeName}},
		}

		var sameSubjectEntries []map[string]any

		for _, path := range paths {
			jsonPath := "$.vc.credentialSubject." + path
			refFieldID := fmt.Sprintf("ref_%s_%s", strings.ToLower(s.TypeName), strings.ReplaceAll(path, ".", "_"))

			fields = append(fields, map[string]any{
				"id": refFieldID, "path": []string{jsonPath},
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

		requestCredentials = append(requestCredentials, map[string]any{
			"format": "jwt_vc_json",
			"input_descriptor": map[string]any{
				"id":          strings.ToLower(s.TypeName),
				"name":        s.DisplayName,
				"purpose":     "Verify delegated authority via " + s.DisplayName,
				"format":      map[string]any{"jwt_vc_json": map[string]any{"alg": []string{"EdDSA"}}},
				"constraints": constraints,
			},
		})
	}

	// Add other schemas (no special constraints)
	for _, s := range analysis.OtherSchemas {
		requestCredentials = append(requestCredentials, map[string]any{
			"format": "jwt_vc_json",
			"input_descriptor": map[string]any{
				"id":      strings.ToLower(s.TypeName),
				"name":    s.DisplayName,
				"purpose": "Verify " + s.DisplayName,
				"format":  map[string]any{"jwt_vc_json": map[string]any{"alg": []string{"EdDSA"}}},
				"constraints": map[string]any{
					"fields": []map[string]any{
						{"path": []string{"$.vc.type"}, "filter": map[string]any{"type": "string", "pattern": s.TypeName}},
					},
				},
			},
		})
	}

	return map[string]any{
		"vp_policies": []string{"signature", "presentation-definition"},
		"vc_policies": []any{
			"signature", "expired", "not-before",
			map[string]any{
				"policy": "credential-status",
				"args": map[string]any{
					"discriminator": "w3c",
					"value":         0,
					"purpose":       "revocation",
					"type":          "BitstringStatusList",
				},
			},
		},
		"request_credentials": requestCredentials,
	}
}

// CreateVerificationRequest sends a verification request to the verifier API
// and returns the openid4vp:// URL.
func CreateVerificationRequest(cfg Config, schemas []SchemaInfo) (string, error) {
	reqURL := cfg.VerifierAPIURL + "/openid4vc/verify"

	body := BuildVerificationRequest(schemas)
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", reqURL, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("successRedirectUri", cfg.SelfURL+"/result/$id")
	req.Header.Set("errorRedirectUri", cfg.SelfURL+"/result/$id")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling verifier API: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("verifier returned %d: %s", resp.StatusCode, string(respBody))
	}

	return string(respBody), nil
}

type tokenResponse struct {
	VPToken json.RawMessage `json:"vp_token"`
}

type verifierSessionResponse struct {
	VerificationResult *bool          `json:"verificationResult"`
	PolicyResults      *PolicyResults `json:"policyResults"`
	TokenResponse      *tokenResponse `json:"tokenResponse"`
}

func CheckSessionStatus(cfg Config, state string) (*SessionResult, error) {
	reqURL := cfg.VerifierAPIURL + "/openid4vc/session/" + url.PathEscape(state)

	resp, err := httpClient.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("polling verifier: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verifier returned %d", resp.StatusCode)
	}

	var session verifierSessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if session.VerificationResult == nil {
		return nil, nil // still pending
	}

	result := &SessionResult{
		VerificationResult: *session.VerificationResult,
	}
	if session.PolicyResults != nil {
		result.PolicyResults = *session.PolicyResults
	}
	if session.TokenResponse != nil {
		result.Credentials = extractCredentials(session.TokenResponse.VPToken)
	}
	return result, nil
}

func ExtractState(openid4vpURL string) string {
	normalized := strings.Replace(openid4vpURL, "openid4vp:", "https:", 1)
	u, err := url.Parse(normalized)
	if err != nil {
		return ""
	}
	return u.Query().Get("state")
}

func BuildWalletURL(cfg Config, openid4vpURL string) string {
	qIdx := strings.Index(openid4vpURL, "?")
	if qIdx < 0 {
		return cfg.DemoWalletFrontendURL + "/api/siop/initiatePresentation"
	}
	return cfg.DemoWalletFrontendURL + "/api/siop/initiatePresentation" + openid4vpURL[qIdx:]
}

// parseJWTPayload decodes the payload (second segment) of a JWT.
func parseJWTPayload(jwt string) (map[string]any, error) {
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid JWT")
	}
	payload := parts[1]
	// Add padding
	if m := len(payload) % 4; m != 0 {
		payload += strings.Repeat("=", 4-m)
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(decoded, &result); err != nil {
		return nil, err
	}
	return result, nil
}

var camelCaseRe = regexp.MustCompile(`([a-z0-9])([A-Z])`)

// camelToTitle converts "BirthCertificate" to "Birth Certificate"
func camelToTitle(s string) string {
	spaced := camelCaseRe.ReplaceAllString(s, "${1} ${2}")
	if len(spaced) > 0 {
		spaced = strings.ToUpper(spaced[:1]) + spaced[1:]
	}
	return spaced
}

// extractCredentials parses the vp_token JWT to extract presented VCs.
func extractCredentials(vpTokenRaw json.RawMessage) []Credential {
	var vpTokenStr string
	if err := json.Unmarshal(vpTokenRaw, &vpTokenStr); err != nil {
		return nil
	}

	vpPayload, err := parseJWTPayload(vpTokenStr)
	if err != nil {
		return nil
	}

	vp, ok := vpPayload["vp"].(map[string]any)
	if !ok {
		return nil
	}
	vcArray, ok := vp["verifiableCredential"].([]any)
	if !ok {
		return nil
	}

	var creds []Credential
	for _, vcRaw := range vcArray {
		vcJWT, ok := vcRaw.(string)
		if !ok {
			continue
		}
		vcPayload, err := parseJWTPayload(vcJWT)
		if err != nil {
			continue
		}

		vc, ok := vcPayload["vc"].(map[string]any)
		if !ok {
			continue
		}

		cred := buildCredential(vc)

		vcJSON, _ := json.MarshalIndent(vc, "", "  ")
		cred.RawJSON = string(vcJSON)

		creds = append(creds, cred)
	}
	return creds
}

func buildCredential(vc map[string]any) Credential {
	cred := Credential{}

	if types, ok := vc["type"].([]any); ok && len(types) > 0 {
		lastType := fmt.Sprintf("%v", types[len(types)-1])
		cred.Type = lastType
		cred.Title = camelToTitle(lastType)
	}

	subj, ok := vc["credentialSubject"].(map[string]any)
	if !ok {
		return cred
	}

	cred.Fields = flattenSubject("", subj)
	return cred
}

func flattenSubject(prefix string, obj map[string]any) []CredentialField {
	var fields []CredentialField
	for key, val := range obj {
		if key == "id" && prefix == "" {
			continue
		}
		label := camelToTitle(key)
		if prefix != "" {
			label = prefix + " " + label
		}
		switch v := val.(type) {
		case string:
			if strings.HasPrefix(v, "did:") && len(v) > 30 {
				v = v[:25] + "..."
			}
			fields = append(fields, CredentialField{Key: label, Value: v})
		case float64:
			fields = append(fields, CredentialField{Key: label, Value: fmt.Sprintf("%g", v)})
		case map[string]any:
			fields = append(fields, flattenSubject(label, v)...)
		default:
			s := fmt.Sprintf("%v", v)
			if len(s) > 0 && len(s) <= 80 {
				fields = append(fields, CredentialField{Key: label, Value: s})
			}
		}
	}
	return fields
}
