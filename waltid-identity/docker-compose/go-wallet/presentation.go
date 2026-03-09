package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PresentationRequest holds the parsed openid4vp:// authorization request.
type PresentationRequest struct {
	ResponseType             string
	ClientID                 string
	State                    string
	ResponseMode             string
	ResponseURI              string
	PresentationDefinitionURI string
	Nonce                    string
}

// PresentationDefinition holds the fetched PD.
type PresentationDefinition struct {
	ID               string                   `json:"id"`
	InputDescriptors []map[string]any         `json:"input_descriptors"`
	Raw              map[string]any           `json:"-"`
}

// MatchedCredential represents a wallet credential matched to a PD input descriptor.
type MatchedCredential struct {
	DescriptorID string
	Credential   *WalletCredential
}

// parsePresentationRequest parses an openid4vp:// URL into a PresentationRequest.
func parsePresentationRequest(rawURL string) (*PresentationRequest, error) {
	// Replace openid4vp: scheme with https: for URL parsing
	normalized := strings.Replace(rawURL, "openid4vp:", "https:", 1)
	u, err := url.Parse(normalized)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	q := u.Query()
	pr := &PresentationRequest{
		ResponseType:             q.Get("response_type"),
		ClientID:                 q.Get("client_id"),
		State:                    q.Get("state"),
		ResponseMode:             q.Get("response_mode"),
		ResponseURI:              q.Get("response_uri"),
		PresentationDefinitionURI: q.Get("presentation_definition_uri"),
		Nonce:                    q.Get("nonce"),
	}

	if pr.State == "" {
		return nil, fmt.Errorf("missing state parameter")
	}
	if pr.ResponseURI == "" {
		return nil, fmt.Errorf("missing response_uri parameter")
	}

	return pr, nil
}

// fetchPresentationDefinition GETs the PD from the URI.
func fetchPresentationDefinition(pdURI string) (*PresentationDefinition, error) {
	resp, err := http.Get(pdURI)
	if err != nil {
		return nil, fmt.Errorf("fetch PD: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PD endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode PD: %w", err)
	}

	pd := &PresentationDefinition{Raw: raw}
	if id, ok := raw["id"].(string); ok {
		pd.ID = id
	}

	if descs, ok := raw["input_descriptors"].([]any); ok {
		for _, d := range descs {
			if dm, ok := d.(map[string]any); ok {
				pd.InputDescriptors = append(pd.InputDescriptors, dm)
			}
		}
	}

	return pd, nil
}

// matchCredentials matches wallet credentials to PD input descriptors based on type filters.
func matchCredentials(pd *PresentationDefinition, creds []*WalletCredential) []MatchedCredential {
	var matched []MatchedCredential

	for _, desc := range pd.InputDescriptors {
		descID, _ := desc["id"].(string)

		// Extract the required type from constraints.fields[].filter
		requiredType := extractRequiredType(desc)
		if requiredType == "" {
			continue
		}

		// Find a credential matching this type
		for _, cred := range creds {
			if credHasType(cred, requiredType) {
				matched = append(matched, MatchedCredential{
					DescriptorID: descID,
					Credential:   cred,
				})
				break
			}
		}
	}

	return matched
}

// extractRequiredType finds the credential type constraint in a PD input descriptor.
func extractRequiredType(desc map[string]any) string {
	constraints, ok := desc["constraints"].(map[string]any)
	if !ok {
		return ""
	}
	fields, ok := constraints["fields"].([]any)
	if !ok {
		return ""
	}
	for _, f := range fields {
		field, ok := f.(map[string]any)
		if !ok {
			continue
		}
		paths, ok := field["path"].([]any)
		if !ok {
			continue
		}
		for _, p := range paths {
			if ps, ok := p.(string); ok && (ps == "$.type" || ps == "$.vc.type") {
				filter, ok := field["filter"].(map[string]any)
				if !ok {
					continue
				}
				// Handle contains.const pattern
				if contains, ok := filter["contains"].(map[string]any); ok {
					if c, ok := contains["const"].(string); ok {
						return c
					}
				}
				// Handle pattern
				if pattern, ok := filter["pattern"].(string); ok {
					return pattern
				}
			}
		}
	}
	return ""
}

// credHasType checks if a credential has the given type.
func credHasType(cred *WalletCredential, typeName string) bool {
	types, ok := cred.ParsedDocument["type"].([]any)
	if !ok {
		return false
	}
	for _, t := range types {
		if s, ok := t.(string); ok && s == typeName {
			return true
		}
	}
	return false
}

// buildVPToken creates a JWT Verifiable Presentation containing ldp_vc credentials.
func buildVPToken(wk *WalletKey, matchedCreds []MatchedCredential, audience, nonce string) string {
	// Collect ldp_vc objects
	var vcObjects []any
	for _, mc := range matchedCreds {
		vcObjects = append(vcObjects, mc.Credential.ParsedDocument)
	}

	header := map[string]any{
		"alg": "EdDSA",
		"typ": "JWT",
		"kid": wk.DID,
	}
	payload := map[string]any{
		"iss":   wk.DID,
		"aud":   audience,
		"iat":   time.Now().Unix(),
		"nonce": nonce,
		"vp": map[string]any{
			"@context":             []string{"https://www.w3.org/2018/credentials/v1"},
			"type":                 []string{"VerifiablePresentation"},
			"verifiableCredential": vcObjects,
		},
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64
	sig := ed25519.Sign(wk.PrivateKey, []byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64
}

// buildPresentationSubmission creates the presentation_submission JSON.
func buildPresentationSubmission(pd *PresentationDefinition, matchedCreds []MatchedCredential) map[string]any {
	var descriptorMap []map[string]any
	for i, mc := range matchedCreds {
		descriptorMap = append(descriptorMap, map[string]any{
			"id":     mc.DescriptorID,
			"format": "ldp_vc",
			"path":   "$",
			"path_nested": map[string]any{
				"format": "ldp_vc",
				"path":   fmt.Sprintf("$.vp.verifiableCredential[%d]", i),
			},
		})
	}

	return map[string]any{
		"id":                generateID(),
		"definition_id":    pd.ID,
		"descriptor_map":   descriptorMap,
	}
}

// submitPresentation POSTs the VP token to the verifier's response_uri.
func submitPresentation(responseURI, vpToken string, submission map[string]any, state string) error {
	submissionJSON, _ := json.Marshal(submission)

	form := url.Values{
		"vp_token":                {vpToken},
		"presentation_submission": {string(submissionJSON)},
		"state":                   {state},
	}

	log.Printf("Submitting VP to %s (state=%s...)", responseURI, state[:8])

	resp, err := http.PostForm(responseURI, form)
	if err != nil {
		return fmt.Errorf("submit VP: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("VP submission response: %d %s", resp.StatusCode, string(body))

	if resp.StatusCode >= 400 {
		return fmt.Errorf("verifier returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
