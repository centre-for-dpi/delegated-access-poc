package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// REST API handlers — compatible with the Walt.id wallet-api surface
// that the pixelpass-adapter already calls.

func handleAPILogin(store *DataStore, sessions *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Type     string `json:"type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}

		if !store.AuthenticateUser(body.Email, body.Password) {
			http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
			return
		}

		token := sessions.Create(body.Email)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"token": token,
		})
	}
}

func handleAPIGetWallets(store *DataStore, sessions *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email, ok := extractBearerToken(r, sessions)
		if !ok {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"wallets": []map[string]any{
				{"id": store.GetWalletID(email)},
			},
		})
	}
}

func handleAPIListCredentials(store *DataStore, sessions *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email, ok := extractBearerToken(r, sessions)
		if !ok {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		creds := store.ListCredentials(email)

		// Return as JSON array (same shape as Walt.id wallet-api)
		result := make([]map[string]any, 0, len(creds))
		for _, c := range creds {
			result = append(result, map[string]any{
				"id":             c.ID,
				"format":         c.Format,
				"document":       c.Document,
				"parsedDocument": c.ParsedDocument,
				"addedOn":        c.AddedOn,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func handleAPIGetCredential(store *DataStore, sessions *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email, ok := extractBearerToken(r, sessions)
		if !ok {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		credID := r.PathValue("credID")
		cred := store.GetCredential(email, credID)
		if cred == nil {
			http.Error(w, `{"error":"credential not found"}`, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":             cred.ID,
			"format":         cred.Format,
			"document":       cred.Document,
			"parsedDocument": cred.ParsedDocument,
			"addedOn":        cred.AddedOn,
		})
	}
}

func extractBearerToken(r *http.Request, sessions *SessionStore) (string, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	return sessions.Validate(token)
}
