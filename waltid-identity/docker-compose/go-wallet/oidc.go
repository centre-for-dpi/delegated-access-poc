package main

import (
	"bytes"
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

// ClaimResult holds the result of an OID4VCI credential claim.
type ClaimResult struct {
	Credential *WalletCredential
	Error      string
}

// ClaimCredentialOffer executes the full OID4VCI pre-authorized code flow.
func ClaimCredentialOffer(offerURL string, walletKey *WalletKey) (*ClaimResult, error) {
	// 1. Parse the offer URL
	offer, err := parseCredentialOffer(offerURL)
	if err != nil {
		return nil, fmt.Errorf("parse offer: %w", err)
	}

	issuerURL, _ := offer["credential_issuer"].(string)
	if issuerURL == "" {
		return nil, fmt.Errorf("no credential_issuer in offer")
	}

	// Extract pre-authorized code
	preAuthCode := extractPreAuthCode(offer)
	if preAuthCode == "" {
		return nil, fmt.Errorf("no pre-authorized_code in offer")
	}

	log.Printf("Claiming from %s (code=%s...)", issuerURL, preAuthCode[:8])

	// 2. Fetch issuer metadata
	metadata, err := fetchIssuerMetadata(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata: %w", err)
	}

	tokenEndpoint, _ := metadata["token_endpoint"].(string)
	credentialEndpoint, _ := metadata["credential_endpoint"].(string)
	if tokenEndpoint == "" || credentialEndpoint == "" {
		return nil, fmt.Errorf("metadata missing token_endpoint or credential_endpoint")
	}

	// 3. Exchange pre-auth code for access token
	accessToken, err := exchangePreAuthCode(tokenEndpoint, preAuthCode)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	// 4. Request credential
	credResponse, err := requestCredential(credentialEndpoint, accessToken, walletKey)
	if err != nil {
		return nil, fmt.Errorf("credential request: %w", err)
	}

	// 5. Parse the credential response
	cred, err := parseCredentialResponse(credResponse)
	if err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &ClaimResult{Credential: cred}, nil
}

func parseCredentialOffer(offerURL string) (map[string]any, error) {
	// Handle both openid-credential-offer:// and regular URLs
	rawURL := offerURL

	// Parse the URL to get query parameters
	var params url.Values
	if idx := strings.Index(rawURL, "?"); idx >= 0 {
		var err error
		params, err = url.ParseQuery(rawURL[idx+1:])
		if err != nil {
			return nil, fmt.Errorf("parse query: %w", err)
		}
	} else {
		return nil, fmt.Errorf("no query parameters in offer URL")
	}

	offerJSON := params.Get("credential_offer")
	if offerJSON == "" {
		// Try credential_offer_uri
		offerURI := params.Get("credential_offer_uri")
		if offerURI != "" {
			resp, err := http.Get(offerURI)
			if err != nil {
				return nil, fmt.Errorf("fetch offer URI: %w", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			offerJSON = string(body)
		} else {
			return nil, fmt.Errorf("no credential_offer or credential_offer_uri parameter")
		}
	}

	var offer map[string]any
	if err := json.Unmarshal([]byte(offerJSON), &offer); err != nil {
		return nil, fmt.Errorf("decode offer JSON: %w", err)
	}

	return offer, nil
}

func extractPreAuthCode(offer map[string]any) string {
	grants, ok := offer["grants"].(map[string]any)
	if !ok {
		return ""
	}
	preAuth, ok := grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]any)
	if !ok {
		return ""
	}
	code, _ := preAuth["pre-authorized_code"].(string)
	return code
}

func fetchIssuerMetadata(issuerURL string) (map[string]any, error) {
	metadataURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-credential-issuer"
	resp, err := http.Get(metadataURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("metadata returned %d: %s", resp.StatusCode, string(body))
	}

	var metadata map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, err
	}
	return metadata, nil
}

func exchangePreAuthCode(tokenEndpoint, preAuthCode string) (string, error) {
	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthCode},
	}

	resp, err := http.PostForm(tokenEndpoint, form)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp map[string]any
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", err
	}

	token, _ := tokenResp["access_token"].(string)
	if token == "" {
		return "", fmt.Errorf("no access_token in response")
	}
	return token, nil
}

func requestCredential(credentialEndpoint, accessToken string, walletKey *WalletKey) (map[string]any, error) {
	// Build the credential request body
	reqBody := map[string]any{
		"format": "ldp_vc",
	}

	// Add proof JWT with wallet DID as issuer
	if walletKey != nil {
		proofJWT := buildProofJWT(walletKey, credentialEndpoint)
		reqBody["proof"] = map[string]any{
			"proof_type": "jwt",
			"jwt":        proofJWT,
		}
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, err := http.NewRequest("POST", credentialEndpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("credential endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var credResp map[string]any
	if err := json.Unmarshal(body, &credResp); err != nil {
		return nil, err
	}
	return credResp, nil
}

// buildProofJWT creates a minimal JWT proving the wallet's DID ownership.
// The issuer-portal extracts the `iss` claim to use as the subject DID.
func buildProofJWT(wk *WalletKey, audience string) string {
	header := map[string]any{
		"alg": "EdDSA",
		"typ": "openid4vci-proof+jwt",
	}
	payload := map[string]any{
		"iss": wk.DID,
		"aud": audience,
		"iat": time.Now().Unix(),
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

func parseCredentialResponse(resp map[string]any) (*WalletCredential, error) {
	format, _ := resp["format"].(string)

	credRaw, ok := resp["credential"]
	if !ok {
		return nil, fmt.Errorf("no credential in response")
	}

	// The credential may be a JSON string (stringified VC) or a JSON object
	var document string
	var parsed map[string]any

	switch v := credRaw.(type) {
	case string:
		document = v
		if err := json.Unmarshal([]byte(v), &parsed); err != nil {
			return nil, fmt.Errorf("credential string is not valid JSON: %w", err)
		}
	case map[string]any:
		b, _ := json.Marshal(v)
		document = string(b)
		parsed = v
	default:
		return nil, fmt.Errorf("unexpected credential type: %T", credRaw)
	}

	// Extract type name
	typeName := "Credential"
	if types, ok := parsed["type"].([]any); ok {
		for _, t := range types {
			if s, ok := t.(string); ok && s != "VerifiableCredential" {
				typeName = s
			}
		}
	}

	// Extract issuer DID
	var issuerDID string
	switch v := parsed["issuer"].(type) {
	case string:
		issuerDID = v
	case map[string]any:
		issuerDID, _ = v["id"].(string)
	}

	// Extract credential ID
	credID, _ := parsed["id"].(string)
	if credID == "" {
		credID = generateID()
	}

	return &WalletCredential{
		ID:             credID,
		Format:         format,
		Document:       document,
		ParsedDocument: parsed,
		AddedOn:        time.Now().Format(time.RFC3339),
		IssuerDID:      issuerDID,
		TypeName:       typeName,
	}, nil
}
