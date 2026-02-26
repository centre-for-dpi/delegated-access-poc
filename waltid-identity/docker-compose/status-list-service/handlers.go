package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// CredentialRecord tracks metadata about a credential assigned to a status list index.
type CredentialRecord struct {
	Index          int    `json:"index"`
	Status         string `json:"status"`
	CredentialType string `json:"credentialType"`
	HolderName     string `json:"holderName"`
}

// Registry keeps an in-memory map of index -> credential metadata, persisted to disk.
type Registry struct {
	mu      sync.RWMutex
	records map[int]*CredentialRecord
	path    string
}

func NewRegistry(dataDir string) *Registry {
	r := &Registry{
		records: make(map[int]*CredentialRecord),
		path:    filepath.Join(dataDir, "registry.json"),
	}
	if data, err := os.ReadFile(r.path); err == nil {
		var records []*CredentialRecord
		if json.Unmarshal(data, &records) == nil {
			for _, rec := range records {
				r.records[rec.Index] = rec
			}
			log.Printf("Loaded %d credential records from registry", len(records))
		}
	}
	return r
}

func (r *Registry) Set(rec *CredentialRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records[rec.Index] = rec
	r.persist()
}

func (r *Registry) Get(index int) *CredentialRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.records[index]
}

func (r *Registry) UpdateStatus(index int, status string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec, ok := r.records[index]; ok {
		rec.Status = status
		r.persist()
	}
}

func (r *Registry) All() []*CredentialRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*CredentialRecord, 0, len(r.records))
	for _, rec := range r.records {
		result = append(result, rec)
	}
	return result
}

func (r *Registry) persist() {
	records := make([]*CredentialRecord, 0, len(r.records))
	for _, rec := range r.records {
		records = append(records, rec)
	}
	data, _ := json.Marshal(records)
	os.WriteFile(r.path, data, 0644)
}

// handleGetStatusList serves the signed BitstringStatusListCredential JWT.
func handleGetStatusList(cfg Config, bs *Bitstring) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		encodedList, err := bs.Encode()
		if err != nil {
			http.Error(w, "failed to encode bitstring", http.StatusInternalServerError)
			log.Printf("ERROR encoding bitstring: %v", err)
			return
		}

		statusListVC := map[string]any{
			"@context": []string{
				"https://www.w3.org/2018/credentials/v1",
				"https://www.w3.org/ns/credentials/status/v1",
			},
			"type": []string{"VerifiableCredential", "BitstringStatusListCredential"},
			"issuer": map[string]any{
				"id": cfg.IssuerDID,
			},
			"credentialSubject": map[string]any{
				"type":          "BitstringStatusList",
				"statusPurpose": "revocation",
				"encodedList":   encodedList,
			},
		}

		jwt, err := signViaIssuerAPI(cfg, statusListVC)
		if err != nil {
			http.Error(w, "failed to sign status list credential", http.StatusInternalServerError)
			log.Printf("ERROR signing status list: %v", err)
			return
		}

		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(jwt))
	}
}

// handleRevoke sets a bit to 1 (revoked).
func handleRevoke(cfg Config, bs *Bitstring, reg *Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			StatusListIndex int `json:"statusListIndex"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if !bs.SetBit(req.StatusListIndex) {
			http.Error(w, fmt.Sprintf("index %d out of range (0-%d)", req.StatusListIndex, BitstringSize*8-1), http.StatusBadRequest)
			return
		}

		reg.UpdateStatus(req.StatusListIndex, "revoked")
		log.Printf("Revoked credential at index %d", req.StatusListIndex)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"index":                req.StatusListIndex,
			"status":              "revoked",
			"statusListCredential": cfg.SelfURL + "/status/revocation/1",
		})
	}
}

// handleReinstate sets a bit back to 0 (active).
func handleReinstate(cfg Config, bs *Bitstring, reg *Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			StatusListIndex int `json:"statusListIndex"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if !bs.ClearBit(req.StatusListIndex) {
			http.Error(w, fmt.Sprintf("index %d out of range (0-%d)", req.StatusListIndex, BitstringSize*8-1), http.StatusBadRequest)
			return
		}

		reg.UpdateStatus(req.StatusListIndex, "active")
		log.Printf("Reinstated credential at index %d", req.StatusListIndex)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"index":                req.StatusListIndex,
			"status":              "active",
			"statusListCredential": cfg.SelfURL + "/status/revocation/1",
		})
	}
}

// handleAllocate returns the next available index and registers credential metadata.
func handleAllocate(bs *Bitstring, reg *Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CredentialType string `json:"credentialType"`
			HolderName     string `json:"holderName"`
		}
		// Body is optional — support both empty POST and JSON POST
		json.NewDecoder(r.Body).Decode(&req)

		idx := bs.AllocateIndex()

		rec := &CredentialRecord{
			Index:          idx,
			Status:         "active",
			CredentialType: req.CredentialType,
			HolderName:     req.HolderName,
		}
		reg.Set(rec)

		log.Printf("Allocated index %d (type=%s, holder=%s)", idx, req.CredentialType, req.HolderName)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"index": idx,
		})
	}
}

// handleQuery returns the current status of a given index.
func handleQuery(bs *Bitstring, reg *Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		indexStr := r.PathValue("index")
		index, err := strconv.Atoi(indexStr)
		if err != nil {
			http.Error(w, "invalid index", http.StatusBadRequest)
			return
		}

		revoked := bs.GetBit(index)
		status := "active"
		if revoked {
			status = "revoked"
		}

		resp := map[string]any{
			"index":  index,
			"status": status,
		}

		if rec := reg.Get(index); rec != nil {
			resp["credentialType"] = rec.CredentialType
			resp["holderName"] = rec.HolderName
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// handleListCredentials returns all registered credentials with their current status.
func handleListCredentials(bs *Bitstring, reg *Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		records := reg.All()
		// Update status from the actual bitstring
		for _, rec := range records {
			if bs.GetBit(rec.Index) {
				rec.Status = "revoked"
			} else {
				rec.Status = "active"
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(records)
	}
}
