package main

import (
	"log"
	"net/http"
	"strings"
	"time"
)

func handleHome(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		schemas, err := FetchSchemas(cfg)
		if err != nil {
			log.Printf("fetch schemas: %v", err)
			renderPage(w, "home.html", map[string]any{
				"Title":   "Credential Verification",
				"Error":   "Could not load credential types: " + err.Error(),
				"Schemas": []SchemaInfo{},
			})
			return
		}

		analysis := AnalyzeSchemas(schemas)

		renderPage(w, "home.html", map[string]any{
			"Title":             "Credential Verification",
			"Schemas":           schemas,
			"IdentitySchemas":   analysis.IdentitySchemas,
			"DelegationSchemas": analysis.DelegationSchemas,
			"HasDelegation":     analysis.HasDelegation,
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

		// Fetch schemas to get full info for selected IDs
		allSchemas, err := FetchSchemas(cfg)
		if err != nil {
			renderPartial(w, "error.html", map[string]any{
				"Error": "Could not load credential types: " + err.Error(),
			})
			return
		}

		// Filter to selected schemas
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
				"Error": "None of the selected credential types were found in the registry",
			})
			return
		}

		openid4vpURL, err := CreateVerificationRequest(cfg, schemas)
		if err != nil {
			log.Printf("verify error: %v", err)
			renderPartial(w, "error.html", map[string]any{
				"Error": "Failed to create verification session: " + err.Error(),
			})
			return
		}

		state := ExtractState(openid4vpURL)
		if state == "" {
			renderPartial(w, "error.html", map[string]any{
				"Error": "Invalid response from verifier: no session state",
			})
			return
		}

		walletURL := BuildWalletURL(cfg, openid4vpURL)
		sessionID := generateID()

		store.Create(&VerificationSession{
			ID:           sessionID,
			State:        state,
			OpenID4VPURL: openid4vpURL,
			WalletURL:    walletURL,
			Status:       "pending",
			CreatedAt:    time.Now(),
		})

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

		result, err := CheckSessionStatus(cfg, sess.State)
		if err != nil || result == nil {
			renderPartial(w, "polling.html", map[string]any{
				"SessionID": sessionID,
			})
			return
		}

		status := "failure"
		if result.VerificationResult {
			status = "success"
		}
		store.Update(sessionID, status, result)

		sess, _ = store.Get(sessionID)
		renderResult(w, sess)
	}
}

func renderResult(w http.ResponseWriter, sess *VerificationSession) {
	data := map[string]any{
		"SessionID":      sess.ID,
		"OverallSuccess": sess.Status == "success",
	}
	if sess.Result != nil {
		// Build a set of credential names that have at least one failed policy
		failedCreds := make(map[string]bool)
		for _, group := range sess.Result.PolicyResults.Results {
			for _, p := range group.PolicyResults {
				if !p.IsSuccess {
					if group.Credential == "VerifiablePresentation" {
						// For VP-level failures (e.g. same_subject), extract credential
						// names from the error's field IDs to attribute the failure.
						if p.Error != nil && p.Error.Constraint == "same_subject" {
							// The error description contains field IDs like
							// "ref_babajaba_..." (delegation) and "subject_id_jabajuniorcertificate" (identity).
							// Only the delegation credential (with "ref_" prefix) is at fault.
							desc := p.Error.FieldIDs
							for _, cred := range sess.Result.Credentials {
								nameLower := strings.ToLower(cred.Type)
								if strings.Contains(desc, "ref_"+nameLower) {
									failedCreds[cred.Type] = true
								}
							}
						} else {
							// Other VP-level failures: mark all credentials
							for _, cred := range sess.Result.Credentials {
								failedCreds[cred.Type] = true
							}
						}
					} else {
						failedCreds[group.Credential] = true
					}
				}
			}
		}

		// Mark each credential's Failed flag
		creds := make([]Credential, len(sess.Result.Credentials))
		copy(creds, sess.Result.Credentials)
		for i := range creds {
			if failedCreds[creds[i].Type] {
				creds[i].Failed = true
			}
		}

		data["PolicyResults"] = sess.Result.PolicyResults
		data["Credentials"] = creds
	}

	renderPartial(w, "result_detail.html", data)
}

func handleResultRedirect(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionID")

		result, err := CheckSessionStatus(cfg, sessionID)
		if err != nil {
			renderPage(w, "result.html", map[string]any{
				"Title": "Verification Result",
				"Error": "Failed to retrieve session: " + err.Error(),
			})
			return
		}
		if result == nil {
			renderPage(w, "result.html", map[string]any{
				"Title": "Verification Result",
				"Error": "Session is still pending or not found.",
			})
			return
		}

		// Mark per-credential failure based on policy results
		failedCreds := make(map[string]bool)
		for _, group := range result.PolicyResults.Results {
			for _, p := range group.PolicyResults {
				if !p.IsSuccess {
					if group.Credential == "VerifiablePresentation" {
						if p.Error != nil && p.Error.Constraint == "same_subject" {
							desc := p.Error.FieldIDs
							for _, cred := range result.Credentials {
								nameLower := strings.ToLower(cred.Type)
								if strings.Contains(desc, "ref_"+nameLower) {
									failedCreds[cred.Type] = true
								}
							}
						}
					} else {
						failedCreds[group.Credential] = true
					}
				}
			}
		}
		creds := make([]Credential, len(result.Credentials))
		copy(creds, result.Credentials)
		for i := range creds {
			if failedCreds[creds[i].Type] {
				creds[i].Failed = true
			}
		}

		data := map[string]any{
			"Title":         "Verification Result",
			"Success":       result.VerificationResult,
			"PolicyResults": result.PolicyResults,
			"Credentials":   creds,
		}
		renderPage(w, "result.html", data)
	}
}
