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
	ServiceHost           string
	IssuerPortalURL       string
	InjiVerifyServiceURL  string
	GoWalletURL           string
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
	partials := []string{"qrcode.html", "polling.html", "result_detail.html", "error.html"}

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
	port := envOr("PORT", "7112")
	serviceHost := envOr("SERVICE_HOST", "localhost")
	goWalletPort := envOr("GO_WALLET_PORT", "7111")

	cfg := Config{
		Port:                 port,
		ServiceHost:          serviceHost,
		IssuerPortalURL:      envOr("ISSUER_PORTAL_URL", "http://issuer-portal:7107"),
		InjiVerifyServiceURL: envOr("INJI_VERIFY_SERVICE_URL", "http://inji-verify-service:8080"),
		GoWalletURL:          "http://" + serviceHost + ":" + goWalletPort,
		SelfURL:              "http://" + serviceHost + ":" + port,
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

	// OID4VP endpoints (called by the wallet)
	mux.HandleFunc("GET /openid4vc/pd/{state}", handleServePD(store))
	mux.HandleFunc("POST /openid4vc/verify/{state}", handleReceiveVP(cfg, store))

	// API endpoints
	mux.HandleFunc("GET /api/session/{sessionID}", handleAPISession(store))

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	addr := "0.0.0.0:" + port
	log.Printf("OID4VP Adapter listening on %s", addr)
	log.Printf("UI: http://%s:%s", serviceHost, port)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
