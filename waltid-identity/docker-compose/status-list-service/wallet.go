package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// WalletCredential is a decoded credential from the wallet with status info.
type WalletCredential struct {
	ID             string `json:"id"`
	CredentialType string `json:"credentialType"`
	HolderName     string `json:"holderName"`
	SubjectID      string `json:"subjectId"`
	IssuerName     string `json:"issuerName"`
	IssuanceDate   string `json:"issuanceDate"`
	StatusIndex    int    `json:"statusIndex"`
	StatusPurpose  string `json:"statusPurpose"`
	StatusListURL  string `json:"statusListUrl"`
	Status         string `json:"status"` // "active", "revoked", or "unknown"
	ManagedByUs    bool   `json:"managedByUs"`
}

// handleWalletLogin proxies login to wallet-api and returns the token.
func handleWalletLogin(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		walletURL := "http://wallet-api:" + envOr("WALLET_BACKEND_PORT", "7001")
		resp, err := http.Post(walletURL+"/wallet-api/auth/login", "application/json", strings.NewReader(string(body)))
		if err != nil {
			http.Error(w, "failed to reach wallet API", http.StatusBadGateway)
			log.Printf("ERROR wallet login: %v", err)
			return
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
	}
}

// handleWalletCredentials fetches credentials from the wallet, decodes them,
// and cross-references with the status list bitstring.
func handleWalletCredentials(cfg Config, bs *Bitstring) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}

		walletURL := "http://wallet-api:" + envOr("WALLET_BACKEND_PORT", "7001")

		// Get wallet ID
		walletID, err := getWalletID(walletURL, token)
		if err != nil {
			http.Error(w, "failed to get wallet: "+err.Error(), http.StatusBadGateway)
			return
		}

		// Fetch credentials
		creds, err := getWalletCredentials(walletURL, walletID, token)
		if err != nil {
			http.Error(w, "failed to get credentials: "+err.Error(), http.StatusBadGateway)
			return
		}

		// Decode and enrich with status
		var result []WalletCredential
		for _, cred := range creds {
			decoded := decodeCredential(cred, bs)
			if decoded != nil {
				result = append(result, *decoded)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func getWalletID(walletURL, token string) (string, error) {
	req, _ := http.NewRequest("GET", walletURL+"/wallet-api/wallet/accounts/wallets", nil)
	req.Header.Set("Authorization", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var data struct {
		Wallets []struct {
			ID string `json:"id"`
		} `json:"wallets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	if len(data.Wallets) == 0 {
		return "", fmt.Errorf("no wallets found")
	}
	return data.Wallets[0].ID, nil
}

func getWalletCredentials(walletURL, walletID, token string) ([]json.RawMessage, error) {
	req, _ := http.NewRequest("GET", walletURL+"/wallet-api/wallet/"+walletID+"/credentials", nil)
	req.Header.Set("Authorization", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var creds []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		return nil, err
	}
	return creds, nil
}

func decodeCredential(raw json.RawMessage, bs *Bitstring) *WalletCredential {
	var wrapper struct {
		ID        string  `json:"id"`
		Document  string  `json:"document"`
		DeletedOn *string `json:"deletedOn"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil
	}

	// Skip soft-deleted credentials
	if wrapper.DeletedOn != nil {
		return nil
	}

	// Decode JWT payload (second segment)
	parts := strings.Split(wrapper.Document, ".")
	if len(parts) < 2 {
		return nil
	}

	payload := parts[1]
	// Add padding
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil
	}

	var jwt struct {
		VC struct {
			ID                string   `json:"id"`
			Type              []string `json:"type"`
			Issuer            any      `json:"issuer"`
			IssuanceDate      string   `json:"issuanceDate"`
			CredentialSubject struct {
				ID       string `json:"id"`
				FullName string `json:"fullName"`
			} `json:"credentialSubject"`
			CredentialStatus struct {
				Type                 string `json:"type"`
				StatusPurpose        string `json:"statusPurpose"`
				StatusListIndex      string `json:"statusListIndex"`
				StatusListCredential string `json:"statusListCredential"`
			} `json:"credentialStatus"`
		} `json:"vc"`
	}
	if err := json.Unmarshal(decoded, &jwt); err != nil {
		return nil
	}

	// Determine credential type (last non-VerifiableCredential type)
	credType := "Unknown"
	for _, t := range jwt.VC.Type {
		if t != "VerifiableCredential" {
			credType = t
		}
	}

	// Extract issuer name
	issuerName := ""
	switch v := jwt.VC.Issuer.(type) {
	case string:
		issuerName = v
	case map[string]any:
		if name, ok := v["name"].(string); ok {
			issuerName = name
		} else if id, ok := v["id"].(string); ok {
			issuerName = id
		}
	}

	wc := &WalletCredential{
		ID:             jwt.VC.ID,
		CredentialType: credType,
		HolderName:     jwt.VC.CredentialSubject.FullName,
		SubjectID:      jwt.VC.CredentialSubject.ID,
		IssuerName:     issuerName,
		IssuanceDate:   jwt.VC.IssuanceDate,
		StatusIndex:    -1,
		Status:         "no status",
		ManagedByUs:    false,
	}

	// Check if credential has a status entry
	if jwt.VC.CredentialStatus.Type != "" {
		idx := 0
		fmt.Sscanf(jwt.VC.CredentialStatus.StatusListIndex, "%d", &idx)
		wc.StatusIndex = idx
		wc.StatusPurpose = jwt.VC.CredentialStatus.StatusPurpose
		wc.StatusListURL = jwt.VC.CredentialStatus.StatusListCredential

		// Check if this status list is managed by us
		if strings.Contains(wc.StatusListURL, "status-list-service") ||
			strings.Contains(wc.StatusListURL, "localhost:7006") {
			wc.ManagedByUs = true
			if bs.GetBit(idx) {
				wc.Status = "revoked"
			} else {
				wc.Status = "active"
			}
		} else {
			wc.Status = "external"
		}
	}

	return wc
}
