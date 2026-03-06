package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
)

type Config struct {
	Port                   string
	ServiceHost            string
	IssuerAPIURL           string
	IssuerAPIPort          string
	DemoWalletFrontendPort string
	DemoWalletFrontendURL  string
	SelfURL                string
	InternalURL            string // Docker-internal URL for status list references
	DataDir                string
	IssuerAPIConfigDir     string // Shared volume for issuer-api HOCON config
	SignAPIToken           string // Optional bearer token for POST /api/sign/ldp
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
	"json":       tmplJSON,
	"camelTitle": camelToTitle,
	"truncate":   truncate,
	"add":        func(a, b int) int { return a + b },
	"seq": func(n int) []int {
		s := make([]int, n)
		for i := range s {
			s[i] = i
		}
		return s
	},
}

func initTemplates() {
	layout := "templates/layout.html"
	pages := []string{
		"home.html", "onboard.html", "issuer_detail.html",
		"schemas.html", "schema_form.html",
		"issue_form.html", "credentials.html",
	}
	partials := []string{
		"schema_preview.html", "issue_result.html",
		"credential_row.html", "error.html", "toast.html",
		"field_row.html", "did_ref_results.html",
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

func main() {
	port := envOr("PORT", "7107")
	serviceHost := envOr("SERVICE_HOST", "localhost")
	issuerPort := envOr("ISSUER_API_PORT", "7002")
	walletPort := envOr("DEMO_WALLET_FRONTEND_PORT", "7101")

	cfg := Config{
		Port:                   port,
		ServiceHost:            serviceHost,
		IssuerAPIURL:           "http://issuer-api:" + issuerPort,
		IssuerAPIPort:          issuerPort,
		DemoWalletFrontendPort: walletPort,
		DemoWalletFrontendURL:  "http://" + serviceHost + ":" + walletPort,
		SelfURL:                "http://" + serviceHost + ":" + port,
		InternalURL:            "http://issuer-portal:" + port,
		DataDir:                envOr("DATA_DIR", "/app/data"),
		IssuerAPIConfigDir:     envOr("ISSUER_API_CONFIG_DIR", "/issuer-api-config"),
		SignAPIToken:           envOr("SIGN_API_TOKEN", ""),
	}

	store := NewDataStore(cfg.DataDir)
	sessions := newLdpVCSessionStore()
	initTemplates()

	mux := http.NewServeMux()

	// Dashboard
	mux.HandleFunc("GET /", handleDashboard(cfg, store))

	// Issuer management
	mux.HandleFunc("GET /issuers/new", handleNewIssuerForm(cfg))
	mux.HandleFunc("POST /issuers", handleCreateIssuer(cfg, store))
	mux.HandleFunc("GET /issuers/{issuerID}", handleIssuerDetail(cfg, store))

	// Schema design
	mux.HandleFunc("GET /issuers/{issuerID}/schemas", handleListSchemas(cfg, store))
	mux.HandleFunc("GET /issuers/{issuerID}/schemas/new", handleNewSchemaForm(cfg, store))
	mux.HandleFunc("POST /issuers/{issuerID}/schemas", handleCreateSchema(cfg, store))
	mux.HandleFunc("POST /issuers/{issuerID}/schemas/preview", handleSchemaPreview(cfg, store))
	mux.HandleFunc("POST /issuers/{issuerID}/schemas/{schemaID}/register", handleRegisterSchema(cfg, store))

	// Credential issuance
	mux.HandleFunc("GET /issuers/{issuerID}/schemas/{schemaID}/issue", handleIssueForm(cfg, store))
	mux.HandleFunc("POST /issuers/{issuerID}/schemas/{schemaID}/issue", handleIssueCredential(cfg, store, sessions))
	mux.HandleFunc("GET /issuers/{issuerID}/credentials/dids", handleCredentialDIDSearch(cfg, store))

	// Credential registry + revocation
	mux.HandleFunc("GET /issuers/{issuerID}/credentials", handleListCredentials(cfg, store))
	mux.HandleFunc("POST /issuers/{issuerID}/credentials/{credID}/revoke", handleRevokeCredential(cfg, store))
	mux.HandleFunc("POST /issuers/{issuerID}/credentials/{credID}/reinstate", handleReinstateCredential(cfg, store))

	// Per-issuer status list credential endpoint (verifier fetches this)
	mux.HandleFunc("GET /issuers/{issuerID}/status/revocation/1", handleGetStatusListCredential(cfg, store))

	// OID4VCI endpoints (ldp_vc issuance — served by this portal, not Walt.id)
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", handleOIDCIssuerMetadata(cfg, store))
	mux.HandleFunc("POST /oidc/token", handleOIDCToken(sessions))
	mux.HandleFunc("POST /oidc/credential", handleOIDCCredential(cfg, store, sessions))

	// JSON API endpoints (for scripts and programmatic access)
	mux.HandleFunc("POST /api/sign/ldp", handleAPISignLdp(cfg, store))
	mux.HandleFunc("POST /api/issuers", handleAPIOnboardIssuer(cfg, store))
	mux.HandleFunc("POST /api/issuers/import", handleAPIImportIssuer(cfg, store))
	mux.HandleFunc("GET /api/issuers", handleAPIListIssuers(cfg, store))
	mux.HandleFunc("GET /api/schemas", handleAPIListAllSchemas(cfg, store))
	mux.HandleFunc("POST /api/issuers/{issuerID}/status/allocate", handleAPIAllocateIndex(cfg, store))
	mux.HandleFunc("POST /api/issuers/{issuerID}/status/revoke", handleAPIRevoke(cfg, store))
	mux.HandleFunc("POST /api/issuers/{issuerID}/status/reinstate", handleAPIReinstate(cfg, store))
	mux.HandleFunc("POST /api/issuers/{issuerID}/status/query", handleAPIQueryStatus(cfg, store))

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	addr := "0.0.0.0:" + port
	log.Printf("Issuer portal listening on %s", addr)
	log.Printf("UI: http://%s:%s", serviceHost, port)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// Template helpers

func tmplJSON(v any) string {
	b, _ := jsonMarshalIndent(v, "", "  ")
	return string(b)
}

func camelToTitle(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteByte(' ')
		}
		if i == 0 {
			result.WriteRune(r - 32 + 32) // keep as-is but ensure title case below
		} else {
			result.WriteRune(r)
		}
	}
	s = result.String()
	if len(s) > 0 {
		return strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
