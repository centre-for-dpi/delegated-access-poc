package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// appendCredentialType appends a new credential type configuration to the
// credential-issuer-metadata.conf HOCON file.
// ldp_vc schemas are managed entirely by the issuer-portal's own OID4VCI server
// and do not need to be registered with Walt.id issuer-api.
func appendCredentialType(configDir string, schema *CredentialSchema) error {
	if schema.EffectiveFormat() == "ldp_vc" {
		return nil // not managed by Walt.id; no HOCON entry needed
	}
	configPath := filepath.Join(configDir, "credential-issuer-metadata.conf")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	content := string(data)

	// Check if this type is already registered
	configID := fmt.Sprintf("%s_jwt_vc_json", schema.TypeName)
	if strings.Contains(content, configID) {
		return nil // already registered
	}

	// Build the simple type entry
	simpleEntry := fmt.Sprintf("    %s = [VerifiableCredential, %s],", schema.TypeName, schema.TypeName)

	// Build the jwt_vc_json entry
	jwtEntry := buildJWTVCJsonEntry(schema)

	// Find the last closing brace and insert before it
	lastBrace := strings.LastIndex(content, "}")
	if lastBrace == -1 {
		return fmt.Errorf("invalid HOCON: no closing brace found")
	}

	newContent := content[:lastBrace] + "\n" + simpleEntry + "\n\n" + jwtEntry + "\n" + content[lastBrace:]

	return os.WriteFile(configPath, []byte(newContent), 0644)
}

func buildJWTVCJsonEntry(schema *CredentialSchema) string {
	configID := fmt.Sprintf("%s_jwt_vc_json", schema.TypeName)

	// Escape description for HOCON
	desc := strings.ReplaceAll(schema.Description, `"`, `\"`)

	return fmt.Sprintf(`    "%s" = {
        format = "jwt_vc_json"
        cryptographic_binding_methods_supported = ["did"]
        credential_signing_alg_values_supported = ["EdDSA", "ES256"]
        credential_definition = {
            type = ["VerifiableCredential", "%s"]
        }
        display = [
            {
                name = "%s"
                description = "%s"
                locale = "en-US"
                background_color = "#FFFFFF"
                text_color = "#000000"
            }
        ]
    }`, configID, schema.TypeName, schema.DisplayName, desc)
}
