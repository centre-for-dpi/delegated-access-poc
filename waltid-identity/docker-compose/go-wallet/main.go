package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	Port                string
	ServiceHost         string
	IssuerPortalURL     string
	PixelPassAdapterURL string
	InjiVerifyURL       string
	DataDir             string
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var (
	pageTmpl    map[string]*template.Template
	partialTmpl map[string]*template.Template
)

var funcMap = template.FuncMap{
	"json": func(v any) string {
		b, _ := json.MarshalIndent(v, "", "  ")
		return string(b)
	},
	"truncate": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "..."
	},
	"credSubject": func(parsed map[string]any) map[string]any {
		if cs, ok := parsed["credentialSubject"].(map[string]any); ok {
			return cs
		}
		return nil
	},
	"issuerName": func(parsed map[string]any) string {
		switch v := parsed["issuer"].(type) {
		case string:
			if len(v) > 30 {
				return v[:30] + "..."
			}
			return v
		case map[string]any:
			if name, ok := v["name"].(string); ok {
				return name
			}
			if id, ok := v["id"].(string); ok {
				if len(id) > 30 {
					return id[:30] + "..."
				}
				return id
			}
		}
		return "Unknown"
	},
	"urlEncode": func(s string) string {
		return url.PathEscape(s)
	},
}

func initTemplates() {
	layout := "templates/layout.html"
	pages := []string{
		"login.html", "register.html", "home.html", "claim.html",
		"credential_detail.html", "present.html", "present_qr.html",
	}
	partials := []string{
		"claim_result.html",
	}

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

const sessionCookieName = "wallet_session"

// requireLogin wraps a handler to enforce UI session authentication.
func requireLogin(uiSessions *UISessionStore, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		email, ok := uiSessions.Validate(cookie.Value)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// Store email in request context via header (simple approach)
		r.Header.Set("X-User-Email", email)
		handler(w, r)
	}
}

func main() {
	port := envOr("PORT", "7111")
	serviceHost := envOr("SERVICE_HOST", "localhost")
	pixelPassPort := envOr("PIXELPASS_ADAPTER_PORT", "7110")

	cfg := Config{
		Port:                port,
		ServiceHost:         serviceHost,
		IssuerPortalURL:     envOr("ISSUER_PORTAL_URL", "http://issuer-portal:7107"),
		PixelPassAdapterURL: envOr("PIXELPASS_ADAPTER_URL", "http://pixelpass-adapter:"+pixelPassPort),
		InjiVerifyURL:       fmt.Sprintf("http://%s:%s", serviceHost, envOr("INJI_VERIFY_UI_PORT", "7109")),
		DataDir:             envOr("DATA_DIR", "/app/data"),
	}

	store := NewDataStore(cfg.DataDir)
	apiSessions := NewSessionStore()
	uiSessions := NewUISessionStore()
	initTemplates()

	mux := http.NewServeMux()

	// Auth routes (no session required)
	mux.HandleFunc("GET /login", handleLoginPage(cfg))
	mux.HandleFunc("POST /login", handleLoginSubmit(cfg, store, uiSessions))
	mux.HandleFunc("GET /register", handleRegisterPage(cfg))
	mux.HandleFunc("POST /register", handleRegisterSubmit(cfg, store, uiSessions))
	mux.HandleFunc("GET /logout", handleLogout(uiSessions))

	// UI routes (session required)
	mux.HandleFunc("GET /", requireLogin(uiSessions, handleHome(cfg, store)))
	mux.HandleFunc("GET /claim", requireLogin(uiSessions, handleClaimForm(cfg)))
	mux.HandleFunc("POST /claim", requireLogin(uiSessions, handleClaimSubmit(cfg, store)))
	mux.HandleFunc("GET /credentials/{credID}", requireLogin(uiSessions, handleCredentialDetail(cfg, store)))
	mux.HandleFunc("POST /credentials/{credID}/delete", requireLogin(uiSessions, handleDeleteCredential(store)))
	mux.HandleFunc("GET /present", requireLogin(uiSessions, handlePresent(cfg, store)))
	mux.HandleFunc("GET /credentials/{credID}/present", requireLogin(uiSessions, handlePresentQR(cfg, store)))

	// Wallet API routes (pixelpass-adapter compatible — uses API sessions, not UI sessions)
	mux.HandleFunc("POST /wallet-api/auth/login", handleAPILogin(store, apiSessions))
	mux.HandleFunc("GET /wallet-api/wallet/accounts/wallets", handleAPIGetWallets(store, apiSessions))
	mux.HandleFunc("GET /wallet-api/wallet/{walletID}/credentials", handleAPIListCredentials(store, apiSessions))
	mux.HandleFunc("GET /wallet-api/wallet/{walletID}/credentials/{credID}", handleAPIGetCredential(store, apiSessions))

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	addr := "0.0.0.0:" + port
	log.Printf("Go Wallet listening on %s", addr)
	log.Printf("UI: http://%s:%s", serviceHost, port)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// --- Auth Handlers ---

func handleLoginPage(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		errorMsg := r.URL.Query().Get("error")
		renderPage(w, "login.html", map[string]any{
			"Title": "Sign In",
			"Error": errorMsg,
			"Cfg":   cfg,
		})
	}
}

func handleLoginSubmit(cfg Config, store *DataStore, uiSessions *UISessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		email := r.FormValue("email")
		password := r.FormValue("password")

		if !store.AuthenticateUser(email, password) {
			http.Redirect(w, r, "/login?error=Invalid+email+or+password", http.StatusSeeOther)
			return
		}

		token := uiSessions.Create(email)
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    token,
			Path:     "/",
			MaxAge:   86400,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		// Check for redirect after login (e.g., claim URL)
		redirect := r.FormValue("redirect")
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func handleRegisterPage(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		errorMsg := r.URL.Query().Get("error")
		renderPage(w, "register.html", map[string]any{
			"Title": "Create Account",
			"Error": errorMsg,
			"Cfg":   cfg,
		})
	}
}

func handleRegisterSubmit(cfg Config, store *DataStore, uiSessions *UISessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		email := strings.TrimSpace(r.FormValue("email"))
		password := r.FormValue("password")
		confirm := r.FormValue("confirm")

		if email == "" || password == "" {
			http.Redirect(w, r, "/register?error=Email+and+password+are+required", http.StatusSeeOther)
			return
		}
		if password != confirm {
			http.Redirect(w, r, "/register?error=Passwords+do+not+match", http.StatusSeeOther)
			return
		}
		if len(password) < 4 {
			http.Redirect(w, r, "/register?error=Password+must+be+at+least+4+characters", http.StatusSeeOther)
			return
		}

		if err := store.RegisterUser(email, password); err != nil {
			http.Redirect(w, r, "/register?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}

		log.Printf("New user registered: %s (DID: %s)", email, store.GetWalletKey(email).DID)

		// Auto-login after registration
		token := uiSessions.Create(email)
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    token,
			Path:     "/",
			MaxAge:   86400,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func handleLogout(uiSessions *UISessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			uiSessions.Delete(cookie.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name:   sessionCookieName,
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

// --- UI Handlers ---

func handleHome(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := r.Header.Get("X-User-Email")

		// Check for claim via query param (from issuer-portal redirect)
		offer := r.URL.Query().Get("offer")
		if offer != "" {
			http.Redirect(w, r, "/claim?offer="+url.QueryEscape(offer), http.StatusSeeOther)
			return
		}

		creds := store.ListCredentials(email)
		wk := store.GetWalletKey(email)
		walletDID := ""
		if wk != nil {
			walletDID = wk.DID
		}
		renderPage(w, "home.html", map[string]any{
			"Title":       "Credentials",
			"Credentials": creds,
			"WalletDID":   walletDID,
			"Email":       email,
			"Cfg":         cfg,
		})
	}
}

func handleClaimForm(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		offer := r.URL.Query().Get("offer")
		email := r.Header.Get("X-User-Email")
		renderPage(w, "claim.html", map[string]any{
			"Title":    "Receive Credential",
			"OfferURL": offer,
			"Email":    email,
			"Cfg":      cfg,
		})
	}
}

func handleClaimSubmit(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		email := r.Header.Get("X-User-Email")

		offerURL := r.FormValue("offerURL")
		if offerURL == "" {
			renderPartial(w, "claim_result.html", map[string]any{
				"Error": "Please provide a credential offer URL",
			})
			return
		}

		wk := store.GetWalletKey(email)
		if wk == nil {
			renderPartial(w, "claim_result.html", map[string]any{
				"Error": "No wallet key found for this user",
			})
			return
		}

		result, err := ClaimCredentialOffer(offerURL, wk)
		if err != nil {
			log.Printf("Claim error: %v", err)
			renderPartial(w, "claim_result.html", map[string]any{
				"Error": err.Error(),
			})
			return
		}

		store.SaveCredential(email, result.Credential)
		log.Printf("Claimed credential for %s: %s (%s)", email, result.Credential.TypeName, result.Credential.ID)

		renderPartial(w, "claim_result.html", map[string]any{
			"Credential": result.Credential,
		})
	}
}

func handleCredentialDetail(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := r.Header.Get("X-User-Email")
		credID := r.PathValue("credID")
		cred := store.GetCredential(email, credID)
		if cred == nil {
			http.NotFound(w, r)
			return
		}

		renderPage(w, "credential_detail.html", map[string]any{
			"Title":      cred.TypeName,
			"Credential": cred,
			"Email":      email,
			"Cfg":        cfg,
		})
	}
}

func handleDeleteCredential(store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := r.Header.Get("X-User-Email")
		credID := r.PathValue("credID")
		store.DeleteCredential(email, credID)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func handlePresent(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := r.Header.Get("X-User-Email")
		creds := store.ListCredentials(email)
		renderPage(w, "present.html", map[string]any{
			"Title":       "Present Credential",
			"Credentials": creds,
			"Email":       email,
			"Cfg":         cfg,
		})
	}
}

func handlePresentQR(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := r.Header.Get("X-User-Email")
		credID := r.PathValue("credID")
		cred := store.GetCredential(email, credID)
		if cred == nil {
			http.NotFound(w, r)
			return
		}

		// Call pixelpass-adapter to generate QR
		qrDataURL := ""
		encodedLen := 0
		qrError := ""

		reqBody, _ := json.Marshal(map[string]any{
			"parsedDocument": cred.ParsedDocument,
		})
		resp, err := http.Post(cfg.PixelPassAdapterURL+"/api/qr", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			qrError = "Failed to connect to PixelPass adapter: " + err.Error()
		} else {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				qrError = "PixelPass adapter error: " + string(body)
			} else {
				var qrResp struct {
					Encoded string `json:"encoded"`
					QR      string `json:"qr"`
				}
				if err := json.Unmarshal(body, &qrResp); err != nil {
					qrError = "Failed to parse QR response"
				} else {
					qrDataURL = qrResp.QR
					encodedLen = len(qrResp.Encoded)
				}
			}
		}

		// Extract subject fields for display
		var subjectFields map[string]any
		if cs, ok := cred.ParsedDocument["credentialSubject"].(map[string]any); ok {
			subjectFields = make(map[string]any)
			for k, v := range cs {
				if k != "id" {
					subjectFields[k] = v
				}
			}
		}

		renderPage(w, "present_qr.html", map[string]any{
			"Title":         "Present — " + cred.TypeName,
			"Credential":    cred,
			"QRDataURL":     template.URL(qrDataURL),
			"EncodedLen":    encodedLen,
			"QRError":       qrError,
			"InjiVerifyURL": cfg.InjiVerifyURL,
			"SubjectFields": subjectFields,
			"Email":         email,
			"Cfg":           cfg,
		})
	}
}

// issuerShortName extracts a short display name from an issuer DID.
func issuerShortName(did string) string {
	if strings.HasPrefix(did, "did:key:") {
		return "did:key:" + did[8:20] + "..."
	}
	if strings.HasPrefix(did, "did:jwk:") {
		return "did:jwk:..."
	}
	if len(did) > 30 {
		return did[:30] + "..."
	}
	return did
}
