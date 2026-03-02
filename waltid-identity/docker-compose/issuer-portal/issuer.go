package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

func handleDashboard(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		issuers := store.ListIssuers()
		renderPage(w, "home.html", map[string]any{
			"Title":   "Issuer Portal",
			"Issuers": issuers,
			"Cfg":     cfg,
		})
	}
}

func handleNewIssuerForm(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		renderPage(w, "onboard.html", map[string]any{
			"Title": "Onboard New Issuer",
			"Cfg":   cfg,
		})
	}
}

func handleCreateIssuer(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		name := r.FormValue("name")
		keyType := r.FormValue("keyType")
		didMethod := r.FormValue("didMethod")

		if name == "" {
			renderPage(w, "onboard.html", map[string]any{
				"Title": "Onboard New Issuer",
				"Error": "Issuer name is required",
				"Cfg":   cfg,
			})
			return
		}

		if keyType == "" {
			keyType = "Ed25519"
		}
		if didMethod == "" {
			didMethod = "key"
		}

		// Call issuer-api onboarding endpoint
		onboardReq := map[string]any{
			"key": map[string]any{
				"backend": "jwk",
				"keyType": keyType,
			},
			"did": map[string]any{
				"method": didMethod,
			},
		}

		reqBody, _ := json.Marshal(onboardReq)
		resp, err := http.Post(cfg.IssuerAPIURL+"/onboard/issuer", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			log.Printf("onboard issuer error: %v", err)
			renderPage(w, "onboard.html", map[string]any{
				"Title": "Onboard New Issuer",
				"Error": "Failed to connect to issuer API: " + err.Error(),
				"Cfg":   cfg,
			})
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			log.Printf("onboard issuer returned %d: %s", resp.StatusCode, string(body))
			renderPage(w, "onboard.html", map[string]any{
				"Title": "Onboard New Issuer",
				"Error": fmt.Sprintf("Issuer API returned %d: %s", resp.StatusCode, string(body)),
				"Cfg":   cfg,
			})
			return
		}

		var onboardResp struct {
			IssuerKey json.RawMessage `json:"issuerKey"`
			IssuerDID string          `json:"issuerDid"`
		}
		if err := json.Unmarshal(body, &onboardResp); err != nil {
			renderPage(w, "onboard.html", map[string]any{
				"Title": "Onboard New Issuer",
				"Error": "Failed to parse onboarding response",
				"Cfg":   cfg,
			})
			return
		}

		issuer := &IssuerProfile{
			ID:        generateID(),
			Name:      name,
			KeyType:   keyType,
			DIDMethod: didMethod,
			IssuerKey: onboardResp.IssuerKey,
			IssuerDID: onboardResp.IssuerDID,
			CreatedAt: time.Now().Format(time.RFC3339),
		}

		store.SaveIssuer(issuer)
		log.Printf("Onboarded issuer: %s (DID: %s)", name, issuer.IssuerDID)

		http.Redirect(w, r, "/issuers/"+issuer.ID, http.StatusSeeOther)
	}
}

func handleIssuerDetail(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		issuer := store.GetIssuer(issuerID)
		if issuer == nil {
			http.NotFound(w, r)
			return
		}

		schemas := store.ListSchemasByIssuer(issuerID)
		creds := store.ListCredentialsByIssuer(issuerID)

		renderPage(w, "issuer_detail.html", map[string]any{
			"Title":       issuer.Name,
			"Issuer":      issuer,
			"Schemas":     schemas,
			"Credentials": creds,
			"Cfg":         cfg,
		})
	}
}
