package main

import (
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"
)

var (
	pageTmpl    map[string]*template.Template
	partialTmpl map[string]*template.Template
)

func initTemplates() {
	funcMap := template.FuncMap{
		"formatPolicyName": formatPolicyName,
	}

	layout := "templates/layout.html"
	pages := []string{"home.html", "result.html"}
	partials := []string{"qrcode.html", "polling.html", "result_success.html",
		"result_failure.html", "error.html"}

	pageTmpl = make(map[string]*template.Template)
	for _, p := range pages {
		pageTmpl[p] = template.Must(
			template.New("").Funcs(funcMap).ParseFiles(layout, "templates/"+p),
		)
	}

	partialTmpl = make(map[string]*template.Template)
	for _, p := range partials {
		partialTmpl[p] = template.Must(
			template.New(p).Funcs(funcMap).ParseFiles("templates/"+p),
		)
	}
}

func renderPage(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTmpl[name].ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("render page %s: %v", name, err)
		http.Error(w, "Internal Server Error", 500)
	}
}

func renderPartial(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := partialTmpl[name].ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render partial %s: %v", name, err)
		http.Error(w, "Internal Server Error", 500)
	}
}

func handleHome(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		schemas, err := FetchSchemas(cfg)
		if err != nil {
			log.Printf("Failed to fetch schemas: %v", err)
			renderPage(w, "home.html", map[string]any{
				"Title": "Delegated Access Verification",
				"Error": "Could not load credential schemas: " + err.Error(),
			})
			return
		}

		analysis := AnalyzeSchemas(schemas)

		renderPage(w, "home.html", map[string]any{
			"Title":             "Delegated Access Verification",
			"IdentitySchemas":   analysis.IdentitySchemas,
			"DelegationSchemas": analysis.DelegationSchemas,
			"HasDelegation":     analysis.HasDelegation,
			"SchemaCount":       len(analysis.IdentitySchemas) + len(analysis.DelegationSchemas),
		})
	}
}

func handleVerify(cfg Config, store *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		schemas, err := FetchSchemas(cfg)
		if err != nil {
			log.Printf("verify: failed to fetch schemas: %v", err)
			renderPartial(w, "error.html", map[string]any{
				"Error": "Failed to load credential schemas: " + err.Error(),
			})
			return
		}

		analysis := AnalyzeSchemas(schemas)

		if len(analysis.IdentitySchemas) == 0 && len(analysis.DelegationSchemas) == 0 {
			renderPartial(w, "error.html", map[string]any{
				"Error": "No registered credential schemas found. Please create and register schemas in the issuer portal first.",
			})
			return
		}

		openid4vpURL, err := CreateVerificationRequest(cfg, analysis)
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
			// Still pending or transient error — keep polling
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
		"SessionID": sess.ID,
	}
	if sess.Result != nil {
		data["PolicyResults"] = sess.Result.PolicyResults
		data["Credentials"] = sess.Result.Credentials
	}

	if sess.Status == "success" {
		renderPartial(w, "result_success.html", data)
	} else {
		renderPartial(w, "result_failure.html", data)
	}
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

		data := map[string]any{
			"Title":         "Verification Result",
			"Success":       result.VerificationResult,
			"PolicyResults": result.PolicyResults,
			"Credentials":   result.Credentials,
		}
		renderPage(w, "result.html", data)
	}
}

func handleHealth() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}
}

func formatPolicyName(name string) string {
	name = strings.ReplaceAll(name, "-", " ")
	name = strings.ReplaceAll(name, "_", " ")
	if len(name) > 0 {
		name = strings.ToUpper(name[:1]) + name[1:]
	}
	return name
}
