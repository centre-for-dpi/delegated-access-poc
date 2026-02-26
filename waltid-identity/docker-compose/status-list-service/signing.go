package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// signViaIssuerAPI delegates JWT signing to the issuer-api's raw signing endpoint.
// POST http://issuer-api:7002/raw/jwt/sign
func signViaIssuerAPI(cfg Config, credentialData map[string]any) (string, error) {
	body := map[string]any{
		"issuerKey":      json.RawMessage(cfg.IssuerKey),
		"issuerDid":      cfg.IssuerDID,
		"subjectDid":     cfg.IssuerDID, // status list credential subject is the issuer
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

	// The response is a JSON string (JWT wrapped in quotes)
	jwt := strings.Trim(string(respBody), "\" \n\r")
	return jwt, nil
}
