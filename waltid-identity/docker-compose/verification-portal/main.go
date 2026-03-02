package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type Config struct {
	Port                  string
	VerifierAPIURL        string
	DemoWalletFrontendURL string
	IssuerPortalURL       string
	ServiceHost           string
	SelfURL               string
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

func initTemplates() {
	funcMap := template.FuncMap{
		"formatPolicyName": formatPolicyName,
	}

	layout := "templates/layout.html"
	pages := []string{"home.html", "result.html"}
	partials := []string{"qrcode.html", "polling.html", "result_detail.html",
		"error.html"}

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

func formatPolicyName(name string) string {
	name = strings.ReplaceAll(name, "-", " ")
	name = strings.ReplaceAll(name, "_", " ")
	if len(name) > 0 {
		name = strings.ToUpper(name[:1]) + name[1:]
	}
	return name
}

func main() {
	port := envOr("PORT", "7108")
	serviceHost := envOr("SERVICE_HOST", "localhost")
	verifierPort := envOr("VERIFIER_API_PORT", "7003")
	walletPort := envOr("DEMO_WALLET_FRONTEND_PORT", "7101")
	issuerPortalPort := envOr("ISSUER_PORTAL_PORT", "7107")

	cfg := Config{
		Port:                  port,
		VerifierAPIURL:        "http://verifier-api:" + verifierPort,
		DemoWalletFrontendURL: "http://" + serviceHost + ":" + walletPort,
		IssuerPortalURL:       "http://issuer-portal:" + issuerPortalPort,
		ServiceHost:           serviceHost,
		SelfURL:               "http://" + serviceHost + ":" + port,
	}

	initTemplates()

	store := NewSessionStore()

	// Session cleanup
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			store.Cleanup(30 * time.Minute)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", handleHome(cfg))
	mux.HandleFunc("POST /verify", handleVerify(cfg, store))
	mux.HandleFunc("GET /poll/{sessionID}", handlePoll(cfg, store))
	mux.HandleFunc("GET /result/{sessionID}", handleResultRedirect(cfg))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	addr := "0.0.0.0:" + port
	log.Printf("Verification portal listening on %s", addr)
	log.Printf("UI: http://%s:%s", serviceHost, port)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
