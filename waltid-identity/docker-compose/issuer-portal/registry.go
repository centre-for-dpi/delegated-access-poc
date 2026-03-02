package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func handleListCredentials(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		issuer := store.GetIssuer(issuerID)
		if issuer == nil {
			http.NotFound(w, r)
			return
		}

		creds := store.ListCredentialsByIssuer(issuerID)

		// Update status from actual bitstring
		bs := store.GetBitstring(issuerID)
		for _, c := range creds {
			if bs.GetBit(c.StatusListIndex) {
				c.Status = "revoked"
			} else {
				c.Status = "active"
			}
		}

		renderPage(w, "credentials.html", map[string]any{
			"Title":       "Credential Registry",
			"Issuer":      issuer,
			"Credentials": creds,
			"Cfg":         cfg,
		})
	}
}

func handleRevokeCredential(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		credID := r.PathValue("credID")

		issuer := store.GetIssuer(issuerID)
		if issuer == nil {
			http.NotFound(w, r)
			return
		}

		cred := store.GetCredential(credID)
		if cred == nil || cred.IssuerID != issuerID {
			http.NotFound(w, r)
			return
		}

		bs := store.GetBitstring(issuerID)
		if !bs.SetBit(cred.StatusListIndex) {
			renderPartial(w, "error.html", map[string]any{
				"Error": "Failed to revoke: invalid status list index",
			})
			return
		}

		cred.Status = "revoked"
		store.SaveCredential(cred)

		log.Printf("Revoked credential %s (index=%d, type=%s)", credID, cred.StatusListIndex, cred.TypeName)

		renderPartial(w, "credential_row.html", map[string]any{
			"Cred":   cred,
			"Issuer": issuer,
		})
	}
}

func handleReinstateCredential(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		credID := r.PathValue("credID")

		issuer := store.GetIssuer(issuerID)
		if issuer == nil {
			http.NotFound(w, r)
			return
		}

		cred := store.GetCredential(credID)
		if cred == nil || cred.IssuerID != issuerID {
			http.NotFound(w, r)
			return
		}

		bs := store.GetBitstring(issuerID)
		if !bs.ClearBit(cred.StatusListIndex) {
			renderPartial(w, "error.html", map[string]any{
				"Error": "Failed to reinstate: invalid status list index",
			})
			return
		}

		cred.Status = "active"
		store.SaveCredential(cred)

		log.Printf("Reinstated credential %s (index=%d, type=%s)", credID, cred.StatusListIndex, cred.TypeName)

		renderPartial(w, "credential_row.html", map[string]any{
			"Cred":   cred,
			"Issuer": issuer,
		})
	}
}

func handleGetStatusListCredential(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		issuer := store.GetIssuer(issuerID)
		if issuer == nil {
			http.Error(w, "issuer not found", http.StatusNotFound)
			return
		}

		bs := store.GetBitstring(issuerID)
		encodedList, err := bs.Encode()
		if err != nil {
			http.Error(w, "failed to encode bitstring", http.StatusInternalServerError)
			log.Printf("ERROR encoding bitstring for issuer %s: %v", issuerID, err)
			return
		}

		statusListVC := map[string]any{
			"@context": []string{
				"https://www.w3.org/2018/credentials/v1",
				"https://www.w3.org/ns/credentials/status/v1",
			},
			"type": []string{"VerifiableCredential", "BitstringStatusListCredential"},
			"issuer": map[string]any{
				"id": issuer.IssuerDID,
			},
			"credentialSubject": map[string]any{
				"type":          "BitstringStatusList",
				"statusPurpose": "revocation",
				"encodedList":   encodedList,
			},
		}

		jwt, err := signStatusListCredential(cfg, issuer, statusListVC)
		if err != nil {
			http.Error(w, "failed to sign status list credential", http.StatusInternalServerError)
			log.Printf("ERROR signing status list for issuer %s: %v", issuerID, err)
			return
		}

		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(jwt))
	}
}

// handleListCredentialsAPI returns credentials as JSON (for HTMX refresh).
func handleListCredentialsAPI(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		creds := store.ListCredentialsByIssuer(issuerID)

		bs := store.GetBitstring(issuerID)
		for _, c := range creds {
			if bs.GetBit(c.StatusListIndex) {
				c.Status = "revoked"
			} else {
				c.Status = "active"
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(creds)
	}
}
