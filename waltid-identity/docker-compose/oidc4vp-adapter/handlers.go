package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func handleHome(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		schemas, err := FetchLdpVcSchemas(cfg)
		if err != nil {
			log.Printf("fetch schemas: %v", err)
			renderPage(w, "home.html", map[string]any{
				"Title":   "ldp_vc Credential Verification",
				"Error":   "Could not load credential types: " + err.Error(),
				"Schemas": []SchemaInfo{},
			})
			return
		}

		analysis := AnalyzeSchemas(schemas)

		renderPage(w, "home.html", map[string]any{
			"Title":             "ldp_vc Credential Verification",
			"Schemas":           schemas,
			"IdentitySchemas":   analysis.IdentitySchemas,
			"DelegationSchemas": analysis.DelegationSchemas,
			"HasDelegation":     analysis.HasDelegation,
			"GoWalletURL":       cfg.GoWalletURL,
		})
	}
}

func handleVerify(cfg Config, store *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			renderPartial(w, "error.html", map[string]any{
				"Error": "Invalid form data",
			})
			return
		}

		selectedIDs := r.Form["schema"]
		if len(selectedIDs) == 0 {
			renderPartial(w, "error.html", map[string]any{
				"Error": "Please select at least one credential type to verify",
			})
			return
		}

		allSchemas, err := FetchLdpVcSchemas(cfg)
		if err != nil {
			renderPartial(w, "error.html", map[string]any{
				"Error": "Could not load credential types: " + err.Error(),
			})
			return
		}

		selected := make(map[string]bool)
		for _, id := range selectedIDs {
			selected[id] = true
		}
		var schemas []SchemaInfo
		for _, s := range allSchemas {
			if selected[s.ID] {
				schemas = append(schemas, s)
			}
		}

		if len(schemas) == 0 {
			renderPartial(w, "error.html", map[string]any{
				"Error": "None of the selected credential types were found",
			})
			return
		}

		// Build presentation definition
		pd := BuildPresentationDefinition(schemas)
		state := generateID()
		nonce := generateID()
		sessionID := generateID()

		openid4vpURL := BuildOpenID4VPURL(cfg, state, nonce)
		walletURL := cfg.GoWalletURL + "/present/oid4vp?request_uri=" + openid4vpURL

		store.Create(&VerificationSession{
			ID:                     sessionID,
			State:                  state,
			Nonce:                  nonce,
			PresentationDefinition: pd,
			OpenID4VPURL:           openid4vpURL,
			WalletURL:              walletURL,
			Status:                 "pending",
			CreatedAt:              time.Now(),
		})

		log.Printf("Created OID4VP session %s (state=%s) with %d schemas", sessionID, state[:8], len(schemas))

		renderPartial(w, "qrcode.html", map[string]any{
			"SessionID":    sessionID,
			"OpenID4VPURL": openid4vpURL,
			"WalletURL":    walletURL,
		})
	}
}

func handlePoll(cfg Config, store *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionID")
		sess, ok := store.Get(sessionID)
		if !ok {
			renderPartial(w, "error.html", map[string]any{
				"Error": "Session not found or expired",
			})
			return
		}

		if sess.Status != "pending" {
			renderResult(w, sess)
			return
		}

		// Still waiting
		renderPartial(w, "polling.html", map[string]any{
			"SessionID": sessionID,
		})
	}
}

// handleServePD serves the presentation definition for a session.
func handleServePD(store *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := r.PathValue("state")
		sess, ok := store.GetByState(state)
		if !ok {
			http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sess.PresentationDefinition)
	}
}

// handleReceiveVP receives the wallet's VP submission (direct_post).
func handleReceiveVP(cfg Config, store *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := r.PathValue("state")
		sess, ok := store.GetByState(state)
		if !ok {
			http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
			return
		}

		if sess.Status != "pending" {
			http.Error(w, `{"error":"session already completed"}`, http.StatusBadRequest)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, `{"error":"invalid form data"}`, http.StatusBadRequest)
			return
		}

		vpToken := r.FormValue("vp_token")
		if vpToken == "" {
			http.Error(w, `{"error":"missing vp_token"}`, http.StatusBadRequest)
			return
		}

		log.Printf("Received VP submission for state %s...", state[:8])

		// Validate VP token and extract credentials
		credentials, err := ValidateVPToken(vpToken, sess)
		if err != nil {
			log.Printf("VP validation failed: %v", err)
			store.Update(sess.ID, "failure", &SessionResult{
				OverallSuccess: false,
				CredentialResults: []CredentialResult{
					{Type: "VP Token", Status: "INVALID", Error: err.Error()},
				},
			})
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"status": "failure",
				"error":  err.Error(),
			})
			return
		}

		log.Printf("VP contains %d credentials, verifying signatures...", len(credentials))

		// Verify each credential's signature via inji-verify-service
		var credResults []CredentialResult
		var credDisplays []Credential
		allValid := true

		for _, cred := range credentials {
			typeName := extractTypeName(cred)
			success, err := VerifyCredentialSignature(cfg, cred)
			status := "SUCCESS"
			errMsg := ""
			if err != nil {
				status = "INVALID"
				errMsg = err.Error()
				allValid = false
				log.Printf("  %s: INVALID (%v)", typeName, err)
			} else if !success {
				status = "INVALID"
				errMsg = "signature verification failed"
				allValid = false
				log.Printf("  %s: INVALID (signature failed)", typeName)
			} else {
				log.Printf("  %s: SUCCESS", typeName)
			}

			credResults = append(credResults, CredentialResult{
				Type:   typeName,
				Status: status,
				Error:  errMsg,
			})

			display := buildCredential(cred)
			display.Failed = status != "SUCCESS"
			credDisplays = append(credDisplays, display)
		}

		// Check same_subject if multiple credentials
		var sameSubject *SameSubjectResult
		if len(credentials) > 1 {
			sameSubject = CheckSameSubject(credentials)
			if !sameSubject.Matched {
				allValid = false
				log.Printf("  same_subject: FAILED (%s)", sameSubject.Reason)
			} else {
				log.Printf("  same_subject: MATCHED (%s → %s via %s)",
					sameSubject.IdentityType, sameSubject.DelegationType, sameSubject.MatchPath)
			}
		}

		resultStatus := "success"
		if !allValid {
			resultStatus = "failure"
		}

		result := &SessionResult{
			OverallSuccess:    allValid,
			Credentials:       credDisplays,
			CredentialResults: credResults,
			SameSubject:       sameSubject,
		}

		store.Update(sess.ID, resultStatus, result)

		log.Printf("Session %s: %s (%d credentials)", sess.ID[:8], resultStatus, len(credentials))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":            resultStatus,
			"credentialResults": credResults,
			"sameSubject":       sameSubject,
		})
	}
}

// handleAPISession returns session status as JSON (for polling from go-wallet).
func handleAPISession(store *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionID")
		sess, ok := store.Get(sessionID)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "session not found"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sessionResultJSON(sess))
	}
}

func renderResult(w http.ResponseWriter, sess *VerificationSession) {
	data := map[string]any{
		"SessionID":      sess.ID,
		"OverallSuccess": sess.Status == "success",
	}
	if sess.Result != nil {
		data["Credentials"] = sess.Result.Credentials
		data["CredentialResults"] = sess.Result.CredentialResults
		data["SameSubject"] = sess.Result.SameSubject
	}
	renderPartial(w, "result_detail.html", data)
}
