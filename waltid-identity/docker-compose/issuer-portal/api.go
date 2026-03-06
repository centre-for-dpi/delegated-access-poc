package main

import (
	"encoding/json"
	"net/http"
)

// JSON API endpoints for programmatic/script access.

func handleAPIOnboardIssuer(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name      string `json:"name"`
			KeyType   string `json:"keyType"`
			DIDMethod string `json:"didMethod"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			jsonError(w, "name is required", http.StatusBadRequest)
			return
		}
		if req.KeyType == "" {
			req.KeyType = "Ed25519"
		}
		if req.DIDMethod == "" {
			req.DIDMethod = "key"
		}

		// Call issuer-api onboarding
		onboardReq := map[string]any{
			"key": map[string]any{"backend": "jwk", "keyType": req.KeyType},
			"did": map[string]any{"method": req.DIDMethod},
		}
		onboardResp, err := postJSON(cfg.IssuerAPIURL+"/onboard/issuer", onboardReq)
		if err != nil {
			jsonError(w, "onboarding failed: "+err.Error(), http.StatusBadGateway)
			return
		}

		issuer := &IssuerProfile{
			ID:        generateID(),
			Name:      req.Name,
			KeyType:   req.KeyType,
			DIDMethod: req.DIDMethod,
			IssuerKey: onboardResp["issuerKey"].(json.RawMessage),
			IssuerDID: onboardResp["issuerDid"].(string),
			CreatedAt: timeNow(),
		}
		store.SaveIssuer(issuer)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":        issuer.ID,
			"name":      issuer.Name,
			"issuerDid": issuer.IssuerDID,
		})
	}
}

func handleAPIImportIssuer(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name      string          `json:"name"`
			KeyType   string          `json:"keyType"`
			DIDMethod string          `json:"didMethod"`
			IssuerKey json.RawMessage `json:"issuerKey"`
			IssuerDID string          `json:"issuerDid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if req.Name == "" || req.IssuerDID == "" || len(req.IssuerKey) == 0 {
			jsonError(w, "name, issuerDid, and issuerKey are required", http.StatusBadRequest)
			return
		}
		if req.KeyType == "" {
			req.KeyType = "Ed25519"
		}
		if req.DIDMethod == "" {
			req.DIDMethod = "key"
		}

		issuer := &IssuerProfile{
			ID:        generateID(),
			Name:      req.Name,
			KeyType:   req.KeyType,
			DIDMethod: req.DIDMethod,
			IssuerKey: req.IssuerKey,
			IssuerDID: req.IssuerDID,
			CreatedAt: timeNow(),
		}
		store.SaveIssuer(issuer)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":        issuer.ID,
			"name":      issuer.Name,
			"issuerDid": issuer.IssuerDID,
		})
	}
}

func handleAPIAllocateIndex(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		issuer := store.GetIssuer(issuerID)
		if issuer == nil {
			jsonError(w, "issuer not found", http.StatusNotFound)
			return
		}

		bs := store.GetBitstring(issuerID)
		index := bs.AllocateIndex()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"index":    index,
			"issuerID": issuerID,
		})
	}
}

func handleAPIRevoke(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		issuer := store.GetIssuer(issuerID)
		if issuer == nil {
			jsonError(w, "issuer not found", http.StatusNotFound)
			return
		}

		var req struct {
			StatusListIndex int `json:"statusListIndex"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		bs := store.GetBitstring(issuerID)
		if !bs.SetBit(req.StatusListIndex) {
			jsonError(w, "invalid status list index", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":          "revoked",
			"statusListIndex": req.StatusListIndex,
		})
	}
}

func handleAPIReinstate(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		issuer := store.GetIssuer(issuerID)
		if issuer == nil {
			jsonError(w, "issuer not found", http.StatusNotFound)
			return
		}

		var req struct {
			StatusListIndex int `json:"statusListIndex"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		bs := store.GetBitstring(issuerID)
		if !bs.ClearBit(req.StatusListIndex) {
			jsonError(w, "invalid status list index", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":          "active",
			"statusListIndex": req.StatusListIndex,
		})
	}
}

func handleAPIQueryStatus(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		issuer := store.GetIssuer(issuerID)
		if issuer == nil {
			jsonError(w, "issuer not found", http.StatusNotFound)
			return
		}

		var req struct {
			StatusListIndex int `json:"statusListIndex"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		bs := store.GetBitstring(issuerID)
		revoked := bs.GetBit(req.StatusListIndex)

		status := "active"
		if revoked {
			status = "revoked"
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":          status,
			"statusListIndex": req.StatusListIndex,
		})
	}
}

// publicIssuerProfile is a safe view of IssuerProfile that omits the private key.
type publicIssuerProfile struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	KeyType   string `json:"keyType"`
	DIDMethod string `json:"didMethod"`
	IssuerDID string `json:"issuerDid"`
	CreatedAt string `json:"createdAt"`
}

func handleAPIListIssuers(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuers := store.ListIssuers()
		public := make([]publicIssuerProfile, len(issuers))
		for i, p := range issuers {
			public[i] = publicIssuerProfile{
				ID:        p.ID,
				Name:      p.Name,
				KeyType:   p.KeyType,
				DIDMethod: p.DIDMethod,
				IssuerDID: p.IssuerDID,
				CreatedAt: p.CreatedAt,
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(public)
	}
}

func handleAPIListAllSchemas(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		schemas := store.ListAllRegisteredSchemas()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(schemas)
	}
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
