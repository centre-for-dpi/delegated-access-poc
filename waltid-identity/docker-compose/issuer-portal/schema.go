package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func handleListSchemas(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		issuer := store.GetIssuer(issuerID)
		if issuer == nil {
			http.NotFound(w, r)
			return
		}

		schemas := store.ListSchemasByIssuer(issuerID)
		renderPage(w, "schemas.html", map[string]any{
			"Title":   "Credential Schemas",
			"Issuer":  issuer,
			"Schemas": schemas,
			"Cfg":     cfg,
		})
	}
}

func handleNewSchemaForm(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		issuer := store.GetIssuer(issuerID)
		if issuer == nil {
			http.NotFound(w, r)
			return
		}

		renderPage(w, "schema_form.html", map[string]any{
			"Title":  "Design New Schema",
			"Issuer": issuer,
			"Cfg":    cfg,
		})
	}
}

func handleCreateSchema(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerID := r.PathValue("issuerID")
		issuer := store.GetIssuer(issuerID)
		if issuer == nil {
			http.NotFound(w, r)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		typeName := r.FormValue("typeName")
		displayName := r.FormValue("displayName")
		description := r.FormValue("description")
		strategy := r.FormValue("subjectDidStrategy")
		format := r.FormValue("credentialFormat")

		if typeName == "" || displayName == "" {
			renderPage(w, "schema_form.html", map[string]any{
				"Title":  "Design New Schema",
				"Issuer": issuer,
				"Error":  "Type name and display name are required",
				"Cfg":    cfg,
			})
			return
		}

		if strategy == "" {
			strategy = "generate"
		}
		if format != "ldp_vc" {
			format = "jwt_vc_json"
		}

		fields := parseFieldsFromForm(r)

		schema := &CredentialSchema{
			ID:                 generateID(),
			IssuerID:           issuerID,
			TypeName:           typeName,
			DisplayName:        displayName,
			Description:        description,
			Fields:             fields,
			SubjectDIDStrategy: strategy,
			Format:             format,
			CreatedAt:          time.Now().Format(time.RFC3339),
		}

		store.SaveSchema(schema)
		log.Printf("Created schema: %s for issuer %s", typeName, issuer.Name)

		http.Redirect(w, r, "/issuers/"+issuerID+"/schemas", http.StatusSeeOther)
	}
}

func handleSchemaPreview(cfg Config, store *DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			renderPartial(w, "schema_preview.html", map[string]any{"JSON": "{}"})
			return
		}

		typeName := r.FormValue("typeName")
		if typeName == "" {
			typeName = "CustomCredential"
		}

		fields := parseFieldsFromForm(r)
		strategy := r.FormValue("subjectDidStrategy")
		if strategy == "" {
			strategy = "generate"
		}

		vcJSON := buildVCTemplate(typeName, fields, strategy)
		prettyJSON, _ := json.MarshalIndent(vcJSON, "", "  ")

		renderPartial(w, "schema_preview.html", map[string]any{
			"JSON": string(prettyJSON),
		})
	}
}

func handleRegisterSchema(cfg Config, store *DataStore) http.HandlerFunc {
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

		if schema.EffectiveFormat() == "ldp_vc" {
			// ldp_vc schemas are served by the portal's own OID4VCI endpoint.
			// No Walt.id config change or container restart needed.
			schema.RegisteredWithIssuerAPI = true
			store.SaveSchema(schema)
			log.Printf("Activated ldp_vc schema %s (portal OID4VCI)", schema.TypeName)
			renderPartial(w, "toast.html", map[string]any{
				"Message": fmt.Sprintf("Schema '%s' activated for ldp_vc issuance.", schema.DisplayName),
				"Color":   "green",
			})
			return
		}

		// jwt_vc_json: append to credential-issuer-metadata.conf and restart Walt.id issuer-api
		if err := appendCredentialType(cfg.IssuerAPIConfigDir, schema); err != nil {
			log.Printf("Failed to update issuer-api config: %v", err)
			renderPartial(w, "toast.html", map[string]any{
				"Message": "Failed to update configuration: " + err.Error(),
				"Color":   "red",
			})
			return
		}

		// Auto-restart issuer-api container
		go func() {
			if err := restartContainer("issuer-api"); err != nil {
				log.Printf("WARNING: failed to restart issuer-api: %v", err)
			}
		}()

		schema.RegisteredWithIssuerAPI = true
		store.SaveSchema(schema)

		log.Printf("Registered schema %s with issuer-api (restart initiated)", schema.TypeName)

		renderPartial(w, "toast.html", map[string]any{
			"Message": fmt.Sprintf("Schema '%s' registered. Issuer API is restarting...", schema.DisplayName),
			"Color":   "green",
		})
	}
}

// parseFieldsFromForm extracts field definitions from form data.
// Form fields are named like field_name_0, field_label_0, field_type_0, field_required_0
// For nested fields: field_name_0_0, field_label_0_0, etc.
func parseFieldsFromForm(r *http.Request) []FieldDefinition {
	var fields []FieldDefinition

	for i := 0; ; i++ {
		name := r.FormValue(fmt.Sprintf("field_name_%d", i))
		if name == "" {
			break
		}

		field := FieldDefinition{
			Name:     name,
			Label:    r.FormValue(fmt.Sprintf("field_label_%d", i)),
			Type:     r.FormValue(fmt.Sprintf("field_type_%d", i)),
			Required: r.FormValue(fmt.Sprintf("field_required_%d", i)) == "on",
		}

		if field.Label == "" {
			field.Label = camelToTitle(name)
		}
		if field.Type == "" {
			field.Type = "string"
		}

		// Check for nested fields
		if field.Type == "object" {
			nestedCountStr := r.FormValue(fmt.Sprintf("field_nested_count_%d", i))
			nestedCount, _ := strconv.Atoi(nestedCountStr)
			for j := 0; j < nestedCount; j++ {
				nestedName := r.FormValue(fmt.Sprintf("field_name_%d_%d", i, j))
				if nestedName == "" {
					continue
				}
				nested := FieldDefinition{
					Name:     nestedName,
					Label:    r.FormValue(fmt.Sprintf("field_label_%d_%d", i, j)),
					Type:     r.FormValue(fmt.Sprintf("field_type_%d_%d", i, j)),
					Required: r.FormValue(fmt.Sprintf("field_required_%d_%d", i, j)) == "on",
				}
				if nested.Label == "" {
					nested.Label = camelToTitle(nestedName)
				}
				if nested.Type == "" {
					nested.Type = "string"
				}
				field.Nested = append(field.Nested, nested)
			}
		}

		fields = append(fields, field)
	}

	return fields
}

// buildVCTemplate generates a W3C VC JSON template from schema fields.
func buildVCTemplate(typeName string, fields []FieldDefinition, strategy string) map[string]any {
	subject := map[string]any{}
	if strategy == "generate" {
		subject["id"] = "did:key:z6Mk... (generated at issuance)"
	} else {
		subject["id"] = "THIS WILL BE REPLACED WITH DYNAMIC DATA FUNCTION"
	}

	for _, f := range fields {
		if f.Type == "object" && len(f.Nested) > 0 {
			nested := map[string]any{}
			for _, nf := range f.Nested {
				nested[nf.Name] = exampleValue(nf.Type)
			}
			subject[f.Name] = nested
		} else {
			subject[f.Name] = exampleValue(f.Type)
		}
	}

	vc := map[string]any{
		"@context": []string{"https://www.w3.org/2018/credentials/v1"},
		"id":       "THIS WILL BE REPLACED WITH DYNAMIC DATA FUNCTION",
		"type":     []string{"VerifiableCredential", typeName},
		"issuer": map[string]any{
			"id":   "THIS WILL BE REPLACED WITH DYNAMIC DATA FUNCTION",
			"name": "Issuer Name",
		},
		"issuanceDate":     "THIS WILL BE REPLACED WITH DYNAMIC DATA FUNCTION",
		"credentialSubject": subject,
		"credentialStatus": map[string]any{
			"type":                 "BitstringStatusListEntry",
			"statusPurpose":       "revocation",
			"statusListIndex":     "0",
			"statusListCredential": "http://issuer-portal:7107/issuers/{issuerId}/status/revocation/1",
		},
	}

	return vc
}

func exampleValue(fieldType string) string {
	switch strings.ToLower(fieldType) {
	case "date":
		return "2025-01-01"
	case "number":
		return "0"
	case "boolean":
		return "false"
	case "did_ref":
		return "did:key:z6Mk... (referenced from credential)"
	default:
		return ""
	}
}
