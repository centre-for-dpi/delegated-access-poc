package main

import (
	"log"
	"net/http"
	"os"
	"time"
)

type Config struct {
	Port                  string
	VerifierAPIURL        string
	DemoWalletFrontendURL string
	ServiceHost           string
	SelfURL               string
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loadConfig() Config {
	port := envOr("PORT", "7105")
	serviceHost := envOr("SERVICE_HOST", "localhost")
	verifierPort := envOr("VERIFIER_API_PORT", "7003")
	walletPort := envOr("DEMO_WALLET_FRONTEND_PORT", "7101")

	return Config{
		Port:                  port,
		VerifierAPIURL:        "http://verifier-api:" + verifierPort,
		DemoWalletFrontendURL: "http://" + serviceHost + ":" + walletPort,
		ServiceHost:           serviceHost,
		SelfURL:               "http://" + serviceHost + ":" + port,
	}
}

func main() {
	cfg := loadConfig()

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
	mux.HandleFunc("GET /health", handleHealth())

	addr := "0.0.0.0:" + cfg.Port
	log.Printf("Verification adapter listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
