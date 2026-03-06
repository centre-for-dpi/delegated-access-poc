package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FormField is a pre-computed template-friendly field descriptor for the issue form.
type FormField struct {
	FormName  string      // HTML form field name, e.g., "field_firstName" or "field_placeOfBirth_country"
	Label     string      // Display label
	InputType string      // HTML input type: "text", "date", "number", "boolean", "did_ref"
	Required  bool
	IsGroup   bool        // True for object fields that contain children
	Children  []FormField // Nested fields (only if IsGroup)
	IssuerID  string      // Populated for did_ref fields to build HTMX API URL
}

// buildFormFields converts schema FieldDefinitions into template-friendly FormFields.
func buildFormFields(fields []FieldDefinition, issuerID string) []FormField {
	var result []FormField
	for _, f := range fields {
		if f.Type == "object" && len(f.Nested) > 0 {
			ff := FormField{
				Label:   f.Label,
				IsGroup: true,
			}
			for _, nf := range f.Nested {
				child := FormField{
					FormName:  fmt.Sprintf("field_%s_%s", f.Name, nf.Name),
					Label:     nf.Label,
					InputType: nf.Type,
					Required:  nf.Required,
				}
				if nf.Type == "did_ref" {
					child.IssuerID = issuerID
				}
				ff.Children = append(ff.Children, child)
			}
			result = append(result, ff)
		} else {
			ff := FormField{
				FormName:  fmt.Sprintf("field_%s", f.Name),
				Label:     f.Label,
				InputType: f.Type,
				Required:  f.Required,
			}
			if f.Type == "did_ref" {
				ff.IssuerID = issuerID
			}
			result = append(result, ff)
		}
	}
	return result
}

func handleIssueForm(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		schemaID := r.PathValue("schemaID")

		issuer := store.GetIssuer(issuerID)
		if issuer == nil {
			http.NotFound(w, r)
			return
		}

		schema := store.GetSchema(schemaID)
		if schema == nil {
			http.NotFound(w, r)
			return
		}

		formFields := buildFormFields(schema.Fields, issuerID)

		renderPage(w, "issue_form.html", map[string]any{
			"Title":      "Issue " + schema.DisplayName,
			"Issuer":     issuer,
			"Schema":     schema,
			"FormFields": formFields,
			"Cfg":        cfg,
		})
	}
}

func handleIssueCredential(cfg Config, store *DataStore, sessions *ldpVCSessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		schemaID := r.PathValue("schemaID")

		issuer := store.GetIssuer(issuerID)
		if issuer == nil {
			http.NotFound(w, r)
			return
		}

		schema := store.GetSchema(schemaID)
		if schema == nil {
			http.NotFound(w, r)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		subjectName := r.FormValue("subjectName")

		// Branch on credential format
		if schema.EffectiveFormat() == "ldp_vc" {
			handleIssueLdpVC(w, r, cfg, store, sessions, issuer, schema, subjectName)
			return
		}

		// jwt_vc_json path: delegate to Walt.id issuer-api via OID4VCI

		// Generate subject DID if strategy is "generate"
		var subjectDID string
		if schema.SubjectDIDStrategy == "generate" {
			did, err := generateSubjectDID(cfg)
			if err != nil {
				log.Printf("Failed to generate subject DID: %v", err)
				renderPartial(w, "error.html", map[string]any{
					"Error": "Failed to generate subject DID: " + err.Error(),
				})
				return
			}
			subjectDID = did
		}

		// Allocate status list index
		bs := store.GetBitstring(issuerID)
		statusIndex := bs.AllocateIndex()

		// Build credential subject from form values
		credSubject := buildCredentialSubject(schema, r, subjectDID)

		// Build the status list credential URL (Docker-internal)
		statusListURL := fmt.Sprintf("%s/issuers/%s/status/revocation/1", cfg.InternalURL, issuerID)

		// Build full credential data
		credentialData := map[string]any{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"id":       fmt.Sprintf("urn:uuid:%s", generateID()),
			"type":     []string{"VerifiableCredential", schema.TypeName},
			"issuer": map[string]any{
				"id":   issuer.IssuerDID,
				"name": issuer.Name,
			},
			"issuanceDate":      time.Now().UTC().Format(time.RFC3339),
			"credentialSubject": credSubject,
			"credentialStatus": map[string]any{
				"type":                 "BitstringStatusListEntry",
				"statusPurpose":       "revocation",
				"statusListIndex":     fmt.Sprintf("%d", statusIndex),
				"statusListCredential": statusListURL,
			},
		}

		// Build mapping (conditionally include subjectDid)
		mapping := map[string]any{
			"id":           "<uuid>",
			"issuer":       map[string]any{"id": "<issuerDid>"},
			"issuanceDate": "<timestamp>",
		}
		if schema.SubjectDIDStrategy == "wallet" {
			mapping["credentialSubject"] = map[string]any{"id": "<subjectDid>"}
		}

		// Build the credential configuration ID
		configID := fmt.Sprintf("%s_jwt_vc_json", schema.TypeName)

		// Issue via OID4VCI
		issueReq := map[string]any{
			"issuerKey":                json.RawMessage(issuer.IssuerKey),
			"issuerDid":               issuer.IssuerDID,
			"credentialConfigurationId": configID,
			"credentialData":           credentialData,
			"mapping":                  mapping,
			"authenticationMethod":     "PRE_AUTHORIZED",
		}

		reqBody, _ := json.Marshal(issueReq)
		resp, err := http.Post(cfg.IssuerAPIURL+"/openid4vc/jwt/issue", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			log.Printf("Issue credential error: %v", err)
			renderPartial(w, "error.html", map[string]any{
				"Error": "Failed to connect to issuer API: " + err.Error(),
			})
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			log.Printf("Issue credential returned %d: %s", resp.StatusCode, string(body))
			renderPartial(w, "error.html", map[string]any{
				"Error": fmt.Sprintf("Issuer API returned %d: %s", resp.StatusCode, string(body)),
			})
			return
		}

		offerURL := strings.TrimSpace(string(body))
		offerURL = strings.Trim(offerURL, "\"")

		// Build wallet URL
		walletURL := buildWalletClaimURL(cfg, offerURL)

		// Collect field values for registry
		fieldValues := collectFieldValues(schema, r)

		// Save to registry
		cred := &IssuedCredential{
			ID:              generateID(),
			IssuerID:        issuerID,
			SchemaID:        schemaID,
			TypeName:        schema.TypeName,
			SubjectDID:      subjectDID,
			SubjectName:     subjectName,
			StatusListIndex: statusIndex,
			Status:          "active",
			OfferURL:        offerURL,
			FieldValues:     fieldValues,
			IssuedAt:        time.Now().Format(time.RFC3339),
		}
		store.SaveCredential(cred)

		log.Printf("Issued %s credential (index=%d, subject=%s)", schema.TypeName, statusIndex, subjectName)

		renderPartial(w, "issue_result.html", map[string]any{
			"Credential": cred,
			"OfferURL":   offerURL,
			"WalletURL":  walletURL,
			"Schema":     schema,
			"Issuer":     issuer,
		})
	}
}

// generateSubjectDID calls the issuer-api onboarding endpoint to generate a new did:key.
func generateSubjectDID(cfg Config) (string, error) {
	body := map[string]any{
		"key": map[string]any{
			"backend": "jwk",
			"keyType": "Ed25519",
		},
		"did": map[string]any{
			"method": "key",
		},
	}

	jsonBody, _ := json.Marshal(body)
	resp, err := http.Post(cfg.IssuerAPIURL+"/onboard/issuer", "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return "", fmt.Errorf("call onboard/issuer: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("onboard returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		IssuerDID string `json:"issuerDid"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	return result.IssuerDID, nil
}

// buildCredentialSubject constructs the credentialSubject from form data and schema.
func buildCredentialSubject(schema *CredentialSchema, r *http.Request, subjectDID string) map[string]any {
	subject := make(map[string]any)

	if subjectDID != "" {
		subject["id"] = subjectDID
	}

	for _, field := range schema.Fields {
		if field.Type == "object" && len(field.Nested) > 0 {
			nested := make(map[string]any)
			for _, nf := range field.Nested {
				key := fmt.Sprintf("field_%s_%s", field.Name, nf.Name)
				val := r.FormValue(key)
				if val != "" {
					nested[nf.Name] = val
				}
			}
			if len(nested) > 0 {
				subject[field.Name] = nested
			}
		} else {
			key := fmt.Sprintf("field_%s", field.Name)
			val := r.FormValue(key)
			if val != "" {
				subject[field.Name] = val
			}
		}
	}

	return subject
}

// collectFieldValues collects all form field values for storage in the registry.
func collectFieldValues(schema *CredentialSchema, r *http.Request) map[string]any {
	values := make(map[string]any)
	for _, field := range schema.Fields {
		if field.Type == "object" && len(field.Nested) > 0 {
			nested := make(map[string]any)
			for _, nf := range field.Nested {
				key := fmt.Sprintf("field_%s_%s", field.Name, nf.Name)
				nested[nf.Name] = r.FormValue(key)
			}
			values[field.Name] = nested
		} else {
			key := fmt.Sprintf("field_%s", field.Name)
			values[field.Name] = r.FormValue(key)
		}
	}
	return values
}

// handleCredentialDIDSearch returns an HTMX partial with credential DID options for the picker.
func handleCredentialDIDSearch(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		if store.GetIssuer(issuerID) == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(`<p class="text-xs text-gray-300 p-3">Issuer not found</p>`))
			return
		}

		search := strings.ToLower(r.URL.Query().Get("search"))
		fieldName := r.URL.Query().Get("fieldName")
		creds := store.ListCredentialsByIssuer(issuerID)
		bs := store.GetBitstring(issuerID)

		type credOption struct {
			SubjectDID  string
			SubjectName string
			TypeName    string
			IssuedAt    string
		}

		var options []credOption
		for _, c := range creds {
			if c.SubjectDID == "" || bs.GetBit(c.StatusListIndex) {
				continue
			}
			if search != "" &&
				!strings.Contains(strings.ToLower(c.SubjectName), search) &&
				!strings.Contains(strings.ToLower(c.SubjectDID), search) &&
				!strings.Contains(strings.ToLower(c.TypeName), search) {
				continue
			}
			options = append(options, credOption{
				SubjectDID:  c.SubjectDID,
				SubjectName: c.SubjectName,
				TypeName:    c.TypeName,
				IssuedAt:    c.IssuedAt,
			})
		}

		renderPartial(w, "did_ref_results.html", map[string]any{
			"Credentials": options,
			"FieldName":   fieldName,
		})
	}
}

// handleIssueLdpVC builds a pre-authorized OID4VCI offer for an ldp_vc schema.
// The credential is signed later by /oidc/credential when the wallet claims it.
func handleIssueLdpVC(w http.ResponseWriter, r *http.Request, cfg Config, store *DataStore, sessions *ldpVCSessionStore, issuer *IssuerProfile, schema *CredentialSchema, subjectName string) {
	// Generate subject DID now only for "generate" strategy
	var preGeneratedDID string
	if schema.SubjectDIDStrategy == "generate" {
		did, err := generateSubjectDID(cfg)
		if err != nil {
			log.Printf("Failed to generate subject DID for ldp_vc: %v", err)
			renderPartial(w, "error.html", map[string]any{
				"Error": "Failed to generate subject DID: " + err.Error(),
			})
			return
		}
		preGeneratedDID = did
	}

	// Allocate status list index
	bs := store.GetBitstring(issuer.ID)
	statusIndex := bs.AllocateIndex()

	// Build unsigned credential data (issuer as plain DID string; no credentialStatus)
	credSubject := buildCredentialSubject(schema, r, preGeneratedDID)
	credentialData := map[string]any{
		"@context": []any{
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
			// @vocab ensures custom types and fields get proper IRI expansion
			// so all JSON-LD processors produce identical canonical N-quads
			map[string]any{"@vocab": "https://example.org/vocab#"},
		},
		"id":   fmt.Sprintf("urn:uuid:%s", generateID()),
		"type": []string{"VerifiableCredential", schema.TypeName},
		// issuer must be a plain DID string for Ed25519Signature2020 canonical form
		"issuer":            issuer.IssuerDID,
		"issuanceDate":      time.Now().UTC().Format(time.RFC3339),
		"credentialSubject": credSubject,
	}

	fieldValues := collectFieldValues(schema, r)

	// Create pre-auth code and session
	preAuthCode := generateID()
	offerURL := buildLdpVcOfferURL(cfg, schema, preAuthCode)

	sess := &ldpVCSession{
		IssuerID:           issuer.ID,
		SchemaID:           schema.ID,
		CredentialData:     credentialData,
		SubjectDIDStrategy: schema.SubjectDIDStrategy,
		PreGeneratedDID:    preGeneratedDID,
		SubjectName:        subjectName,
		StatusListIndex:    statusIndex,
		OfferURL:           offerURL,
		FieldValues:        fieldValues,
		ExpiresAt:          time.Now().Add(15 * time.Minute),
	}
	sessions.storePreAuth(preAuthCode, sess)

	// For ldp_vc, point to the Go wallet instead of the demo wallet
	goWalletPort := envOr("GO_WALLET_PORT", "7111")
	walletURL := fmt.Sprintf("http://%s:%s/claim?offer=%s", cfg.ServiceHost, goWalletPort, url.QueryEscape(offerURL))

	// Return a placeholder credential record for the UI (not persisted yet — saved on /oidc/credential)
	log.Printf("Created ldp_vc offer for schema %s (code=%s, index=%d)", schema.TypeName, preAuthCode[:8], statusIndex)

	renderPartial(w, "issue_result.html", map[string]any{
		"Credential": &IssuedCredential{
			TypeName:        schema.TypeName,
			SubjectName:     subjectName,
			StatusListIndex: statusIndex,
			Status:          "pending",
			OfferURL:        offerURL,
		},
		"OfferURL":  offerURL,
		"WalletURL": walletURL,
		"Schema":    schema,
		"Issuer":    issuer,
	})
}

// buildLdpVcOfferURL constructs the openid-credential-offer:// URL for the portal's own OID4VCI server.
func buildLdpVcOfferURL(cfg Config, schema *CredentialSchema, preAuthCode string) string {
	portalExternal := "http://" + cfg.ServiceHost + ":" + cfg.Port
	offer := map[string]any{
		"credential_issuer": portalExternal,
		"credential_configuration_ids": []string{schema.TypeName + "_ldp_vc"},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": preAuthCode,
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	return "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))
}

// buildWalletClaimURL constructs the demo wallet deep link for claiming a credential.
func buildWalletClaimURL(cfg Config, offerURL string) string {
	// The wallet expects the full credential offer URL as a query parameter
	idx := strings.Index(offerURL, "?")
	if idx < 0 {
		return cfg.DemoWalletFrontendURL + "/api/siop/initiateIssuance"
	}
	return cfg.DemoWalletFrontendURL + "/api/siop/initiateIssuance" + offerURL[idx:]
}
