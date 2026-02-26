package main

import (
	"log"
	"net/http"
	"os"
)

type Config struct {
	Port         string
	ServiceHost  string
	StatusPort   string
	IssuerAPIURL string
	IssuerKey    string
	IssuerDID    string
	SelfURL      string
	DataDir      string
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	port := envOr("PORT", "7006")
	serviceHost := envOr("SERVICE_HOST", "localhost")
	issuerPort := envOr("ISSUER_API_PORT", "7002")

	cfg := Config{
		Port:         port,
		ServiceHost:  serviceHost,
		StatusPort:   port,
		IssuerAPIURL: "http://issuer-api:" + issuerPort,
		IssuerKey:    envOr("ISSUER_KEY", ""),
		IssuerDID:    envOr("ISSUER_DID", ""),
		SelfURL:      "http://" + serviceHost + ":" + port,
		DataDir:      envOr("DATA_DIR", "/app/data"),
	}

	if cfg.IssuerKey == "" || cfg.IssuerDID == "" {
		log.Fatal("ISSUER_KEY and ISSUER_DID environment variables are required")
	}

	bs := NewBitstring(cfg.DataDir + "/revocation.bin")
	reg := NewRegistry(cfg.DataDir)

	mux := http.NewServeMux()

	// Web UI
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "templates/index.html")
	})

	// Status list credential endpoint (verifier fetches this)
	mux.HandleFunc("GET /status/revocation/1", handleGetStatusList(cfg, bs))

	// Revocation management
	mux.HandleFunc("POST /status/revoke", handleRevoke(cfg, bs, reg))
	mux.HandleFunc("POST /status/reinstate", handleReinstate(cfg, bs, reg))

	// Index allocation (used during issuance)
	mux.HandleFunc("POST /status/allocate", handleAllocate(bs, reg))

	// Query status of an index
	mux.HandleFunc("GET /status/query/{index}", handleQuery(bs, reg))

	// List all registered credentials
	mux.HandleFunc("GET /status/credentials", handleListCredentials(bs, reg))

	// Wallet integration (proxied through backend to avoid CORS)
	mux.HandleFunc("POST /api/wallet/login", handleWalletLogin(cfg))
	mux.HandleFunc("GET /api/wallet/credentials", handleWalletCredentials(cfg, bs))

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	addr := "0.0.0.0:" + port
	log.Printf("Status list service listening on %s", addr)
	log.Printf("Status list credential URL: %s/status/revocation/1", cfg.SelfURL)
	log.Printf("Management UI: http://%s:%s", serviceHost, port)
	log.Fatal(http.ListenAndServe(addr, mux))
}
