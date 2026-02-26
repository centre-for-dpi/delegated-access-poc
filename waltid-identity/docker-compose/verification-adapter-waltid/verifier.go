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

const verificationRequestBody = `{
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
}`

func CreateVerificationRequest(cfg Config) (string, error) {
	reqURL := cfg.VerifierAPIURL + "/openid4vc/verify"

	req, err := http.NewRequest("POST", reqURL, strings.NewReader(verificationRequestBody))
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("verifier returned %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
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

// camelToTitle converts "BirthCertificate" to "Birth Certificate", "firstName" to "First Name"
func camelToTitle(s string) string {
	spaced := camelCaseRe.ReplaceAllString(s, "${1} ${2}")
	if len(spaced) > 0 {
		spaced = strings.ToUpper(spaced[:1]) + spaced[1:]
	}
	return spaced
}

// extractCredentials parses the vp_token JWT to extract presented VCs.
func extractCredentials(vpTokenRaw json.RawMessage) []Credential {
	// vp_token is a JWT string
	var vpTokenStr string
	if err := json.Unmarshal(vpTokenRaw, &vpTokenStr); err != nil {
		return nil
	}

	vpPayload, err := parseJWTPayload(vpTokenStr)
	if err != nil {
		return nil
	}

	// Get vp.verifiableCredential array
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

		// Pretty-print the VC JSON for detail view
		vcJSON, _ := json.MarshalIndent(vc, "", "  ")
		cred.RawJSON = string(vcJSON)

		creds = append(creds, cred)
	}
	return creds
}

func buildCredential(vc map[string]any) Credential {
	cred := Credential{}

	// Extract type
	if types, ok := vc["type"].([]any); ok && len(types) > 0 {
		lastType := fmt.Sprintf("%v", types[len(types)-1])
		cred.Type = lastType
		cred.Title = camelToTitle(lastType)
	}

	// Extract credentialSubject fields
	subj, ok := vc["credentialSubject"].(map[string]any)
	if !ok {
		return cred
	}

	cred.Fields = flattenSubject("", subj)
	return cred
}

// flattenSubject recursively extracts key-value pairs from the credential subject.
func flattenSubject(prefix string, obj map[string]any) []CredentialField {
	var fields []CredentialField
	for key, val := range obj {
		// Skip raw DID id fields — they're long and not human-readable
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
				// Truncate long DIDs for display
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
