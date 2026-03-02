package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// IssuerProfile represents an onboarded issuer with their key material and DID.
type IssuerProfile struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	KeyType   string          `json:"keyType"`
	DIDMethod string          `json:"didMethod"`
	IssuerKey json.RawMessage `json:"issuerKey"`
	IssuerDID string          `json:"issuerDid"`
	CreatedAt string          `json:"createdAt"`
}

// FieldDefinition defines a single field in a credential schema.
type FieldDefinition struct {
	Name     string            `json:"name"`
	Label    string            `json:"label"`
	Type     string            `json:"type"`
	Required bool              `json:"required"`
	Nested   []FieldDefinition `json:"nested,omitempty"`
}

// CredentialSchema defines a custom credential type.
type CredentialSchema struct {
	ID                      string            `json:"id"`
	IssuerID                string            `json:"issuerId"`
	TypeName                string            `json:"typeName"`
	DisplayName             string            `json:"displayName"`
	Description             string            `json:"description"`
	Fields                  []FieldDefinition `json:"fields"`
	SubjectDIDStrategy      string            `json:"subjectDidStrategy"` // "generate" or "wallet"
	RegisteredWithIssuerAPI bool              `json:"registeredWithIssuerApi"`
	CreatedAt               string            `json:"createdAt"`
}

// IssuedCredential tracks a credential that was issued through this portal.
type IssuedCredential struct {
	ID              string         `json:"id"`
	IssuerID        string         `json:"issuerId"`
	SchemaID        string         `json:"schemaId"`
	TypeName        string         `json:"typeName"`
	SubjectDID      string         `json:"subjectDid"`
	SubjectName     string         `json:"subjectName"`
	StatusListIndex int            `json:"statusListIndex"`
	Status          string         `json:"status"` // "active" or "revoked"
	OfferURL        string         `json:"offerUrl"`
	FieldValues     map[string]any `json:"fieldValues"`
	IssuedAt        string         `json:"issuedAt"`
}

// DataStore manages file-based persistence for all entities.
type DataStore struct {
	mu         sync.RWMutex
	dataDir    string
	issuers    map[string]*IssuerProfile
	schemas    map[string]*CredentialSchema
	creds      map[string]*IssuedCredential
	bitstrings map[string]*Bitstring
}

func NewDataStore(dataDir string) *DataStore {
	os.MkdirAll(dataDir, 0755)
	ds := &DataStore{
		dataDir:    dataDir,
		issuers:    make(map[string]*IssuerProfile),
		schemas:    make(map[string]*CredentialSchema),
		creds:      make(map[string]*IssuedCredential),
		bitstrings: make(map[string]*Bitstring),
	}
	ds.loadAll()
	return ds
}

func (ds *DataStore) loadAll() {
	ds.loadJSON("issuers.json", &ds.issuers)
	ds.loadJSON("schemas.json", &ds.schemas)
	ds.loadJSON("credentials.json", &ds.creds)
}

func (ds *DataStore) loadJSON(filename string, target any) {
	path := filepath.Join(ds.dataDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if err := json.Unmarshal(data, target); err != nil {
		log.Printf("WARNING: failed to load %s: %v", filename, err)
	}
}

func (ds *DataStore) saveJSON(filename string, data any) {
	path := filepath.Join(ds.dataDir, filename)
	b, err := jsonMarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("WARNING: failed to marshal %s: %v", filename, err)
		return
	}
	if err := os.WriteFile(path, b, 0644); err != nil {
		log.Printf("WARNING: failed to write %s: %v", filename, err)
	}
}

// Issuer operations

func (ds *DataStore) SaveIssuer(p *IssuerProfile) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.issuers[p.ID] = p
	ds.saveJSON("issuers.json", ds.issuers)
}

func (ds *DataStore) GetIssuer(id string) *IssuerProfile {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.issuers[id]
}

func (ds *DataStore) ListIssuers() []*IssuerProfile {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	result := make([]*IssuerProfile, 0, len(ds.issuers))
	for _, p := range ds.issuers {
		result = append(result, p)
	}
	return result
}

// Schema operations

func (ds *DataStore) SaveSchema(s *CredentialSchema) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.schemas[s.ID] = s
	ds.saveJSON("schemas.json", ds.schemas)
}

func (ds *DataStore) GetSchema(id string) *CredentialSchema {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.schemas[id]
}

func (ds *DataStore) ListSchemasByIssuer(issuerID string) []*CredentialSchema {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	var result []*CredentialSchema
	for _, s := range ds.schemas {
		if s.IssuerID == issuerID {
			result = append(result, s)
		}
	}
	return result
}

// Credential operations

func (ds *DataStore) SaveCredential(c *IssuedCredential) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.creds[c.ID] = c
	ds.saveJSON("credentials.json", ds.creds)
}

func (ds *DataStore) GetCredential(id string) *IssuedCredential {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.creds[id]
}

func (ds *DataStore) ListCredentialsByIssuer(issuerID string) []*IssuedCredential {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	var result []*IssuedCredential
	for _, c := range ds.creds {
		if c.IssuerID == issuerID {
			result = append(result, c)
		}
	}
	return result
}

// Schema queries

func (ds *DataStore) ListAllRegisteredSchemas() []map[string]any {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	var result []map[string]any
	for _, s := range ds.schemas {
		if !s.RegisteredWithIssuerAPI {
			continue
		}
		issuerName := ""
		if issuer, ok := ds.issuers[s.IssuerID]; ok {
			issuerName = issuer.Name
		}
		result = append(result, map[string]any{
			"id":                 s.ID,
			"issuerId":           s.IssuerID,
			"issuerName":         issuerName,
			"typeName":           s.TypeName,
			"displayName":        s.DisplayName,
			"description":        s.Description,
			"fields":             s.Fields,
			"fieldCount":         len(s.Fields),
			"subjectDidStrategy": s.SubjectDIDStrategy,
		})
	}
	return result
}

// Bitstring operations (per-issuer)

func (ds *DataStore) GetBitstring(issuerID string) *Bitstring {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if bs, ok := ds.bitstrings[issuerID]; ok {
		return bs
	}
	dir := filepath.Join(ds.dataDir, "bitstrings", issuerID)
	bs := NewBitstring(filepath.Join(dir, "revocation.bin"))
	ds.bitstrings[issuerID] = bs
	return bs
}

// Helpers

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func jsonMarshalIndent(v any, prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(v, prefix, indent)
}

func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func generateShortID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func timeNow() string {
	return time.Now().Format(time.RFC3339)
}

// postJSON posts a JSON body and returns the parsed response.
func postJSON(url string, body any) (map[string]any, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	// Preserve issuerKey as json.RawMessage
	if _, ok := result["issuerKey"]; ok {
		// Re-extract raw issuerKey
		var raw struct {
			IssuerKey json.RawMessage `json:"issuerKey"`
		}
		json.Unmarshal(respBody, &raw)
		result["issuerKey"] = raw.IssuerKey
	}

	return result, nil
}
