package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// handleOIDCIssuerMetadata serves GET /.well-known/openid-credential-issuer
// describing the portal's own OID4VCI pre-authorized code endpoint (ldp_vc only).
func handleOIDCIssuerMetadata(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		baseURL := fmt.Sprintf("http://%s:%s", cfg.ServiceHost, cfg.Port)

		// Collect all active ldp_vc schemas
		schemas := store.ListAllLdpVcSchemas()
		credConfigs := map[string]any{}
		for _, s := range schemas {
			credConfigs[s.TypeName+"_ldp_vc"] = map[string]any{
				"format": "ldp_vc",
				"credential_definition": map[string]any{
					"type": []string{"VerifiableCredential", s.TypeName},
				},
				"cryptographic_binding_methods_supported": []string{"did"},
				"credential_signing_alg_values_supported": []string{"EdDSA"},
			}
		}

		meta := map[string]any{
			// Core OID4VCI fields
			"credential_issuer":    baseURL,
			"credential_endpoint":  baseURL + "/oidc/credential",
			"token_endpoint":       baseURL + "/oidc/token",
			"authorization_endpoint": baseURL + "/oidc/authorize",
			"jwks_uri":             baseURL + "/oidc/jwks",
			// Draft 13 credential configs
			"credential_configurations_supported": credConfigs,
			// OpenID Connect fields expected by Walt.id wallet deserializer
			"issuer":                              baseURL,
			"scopes_supported":                    []string{"openid"},
			"response_types_supported":            []string{"code"},
			"response_modes_supported":            []string{"query"},
			"grant_types_supported":               []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			"subject_types_supported":             []string{"public"},
			"id_token_signing_alg_values_supported": []string{"EdDSA"},
			"code_challenge_methods_supported":     []string{"S256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	}
}

// handleOIDCToken serves POST /oidc/token — exchanges a pre-auth code for an access token.
func handleOIDCToken(sessions *ldpVCSessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}

		grantType := r.FormValue("grant_type")
		if grantType != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
			return
		}

		code := r.FormValue("pre-authorized_code")
		if code == "" {
			http.Error(w, `{"error":"invalid_request","error_description":"missing pre-authorized_code"}`, http.StatusBadRequest)
			return
		}

		_, token, ok := sessions.exchangePreAuth(code)
		if !ok {
			http.Error(w, `{"error":"invalid_grant","error_description":"pre-authorized_code not found or expired"}`, http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": token,
			"token_type":   "Bearer",
			"expires_in":   900,
		})
	}
}

// handleOIDCCredential serves POST /oidc/credential — issues a signed ldp_vc.
func handleOIDCCredential(cfg Config, store *DataStore, sessions *ldpVCSessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract Bearer token
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" || token == authHeader {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}

		sess, ok := sessions.consumeToken(token)
		if !ok {
			http.Error(w, `{"error":"invalid_token","error_description":"token not found or expired"}`, http.StatusUnauthorized)
			return
		}

		issuer := store.GetIssuer(sess.IssuerID)
		if issuer == nil {
			http.Error(w, `{"error":"server_error","error_description":"issuer not found"}`, http.StatusInternalServerError)
			return
		}
		schema := store.GetSchema(sess.SchemaID)
		if schema == nil {
			http.Error(w, `{"error":"server_error","error_description":"schema not found"}`, http.StatusInternalServerError)
			return
		}

		// Resolve subject DID
		subjectDID := sess.PreGeneratedDID
		if sess.SubjectDIDStrategy == "wallet" {
			// Extract holder DID from key-binding proof JWT (iss claim)
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
				if proof, ok := body["proof"].(map[string]any); ok {
					if jwt, ok := proof["jwt"].(string); ok {
						if did, err := extractSubjectDIDFromProofJWT(jwt); err == nil {
							subjectDID = did
						}
					}
				}
			}
			if subjectDID == "" {
				http.Error(w, `{"error":"invalid_request","error_description":"could not extract holder DID from proof"}`, http.StatusBadRequest)
				return
			}
		}

		// Build the credential document
		credData := deepCopy(sess.CredentialData)
		if cs, ok := credData["credentialSubject"].(map[string]any); ok {
			cs["id"] = subjectDID
		}

		// Sign as ldp_vc
		signed, err := signLdpVc(issuer, credData)
		if err != nil {
			log.Printf("ERROR signing ldp_vc: %v", err)
			http.Error(w, `{"error":"server_error","error_description":"signing failed"}`, http.StatusInternalServerError)
			return
		}

		// Persist as issued credential
		issuedCred := &IssuedCredential{
			ID:              generateID(),
			IssuerID:        sess.IssuerID,
			SchemaID:        sess.SchemaID,
			TypeName:        schema.TypeName,
			SubjectDID:      subjectDID,
			SubjectName:     sess.SubjectName,
			StatusListIndex: sess.StatusListIndex,
			Status:          "active",
			OfferURL:        sess.OfferURL,
			FieldValues:     sess.FieldValues,
			IssuedAt:        time.Now().Format(time.RFC3339),
		}
		store.SaveCredential(issuedCred)

		log.Printf("Issued ldp_vc %s (schema %s) to %s", issuedCred.ID, schema.TypeName, subjectDID)

		// Walt.id wallet calls .jsonPrimitive.content on the credential field,
		// expecting a string even for ldp_vc. Return the signed VC as a JSON string.
		signedJSON, _ := json.Marshal(signed)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"format":     "ldp_vc",
			"credential": string(signedJSON),
		})
	}
}

// extractSubjectDIDFromProofJWT extracts the `iss` claim from the unsecured
// key-binding proof JWT sent by the wallet at the credential endpoint.
func extractSubjectDIDFromProofJWT(jwt string) (string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("not a JWT")
	}
	payload, err := decodeBase64URL(parts[1])
	if err != nil {
		return "", err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	iss, _ := claims["iss"].(string)
	if iss == "" {
		return "", fmt.Errorf("no iss claim")
	}
	return iss, nil
}

// decodeBase64URL decodes a URL-safe base64 string (no padding required).
func decodeBase64URL(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// deepCopy returns a shallow-deep copy of a map (sufficient for credential data).
func deepCopy(src map[string]any) map[string]any {
	b, _ := json.Marshal(src)
	var dst map[string]any
	json.Unmarshal(b, &dst)
	return dst
}
