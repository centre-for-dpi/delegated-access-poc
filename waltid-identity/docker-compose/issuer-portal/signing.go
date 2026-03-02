package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// signStatusListCredential signs a BitstringStatusListCredential via the issuer-api.
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
