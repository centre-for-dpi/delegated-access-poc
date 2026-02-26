package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type PolicyEntry struct {
	Policy    string `json:"policy"`
	IsSuccess bool   `json:"is_success"`
}

type PolicyGroup struct {
	Credential    string        `json:"credential"`
	PolicyResults []PolicyEntry `json:"policyResults"`
}

type PolicyResults struct {
	Results     []PolicyGroup `json:"results"`
	PoliciesRun int           `json:"policiesRun"`
	Time        string        `json:"time"`
}

type Credential struct {
	Type    string            // Last type name, e.g. "BirthCertificate"
	Title   string            // Human-readable, e.g. "Birth Certificate"
	Fields  []CredentialField // Key-value pairs from credentialSubject
	RawJSON string            // Full VC JSON for detail view
}

type CredentialField struct {
	Key   string
	Value string
}

type SessionResult struct {
	VerificationResult bool
	PolicyResults      PolicyResults
	Credentials        []Credential
}

type VerificationSession struct {
	ID           string
	State        string
	OpenID4VPURL string
	WalletURL    string
	Status       string // "pending", "success", "failure"
	Result       *SessionResult
	CreatedAt    time.Time
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*VerificationSession
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*VerificationSession),
	}
}

func (s *SessionStore) Create(sess *VerificationSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
}

func (s *SessionStore) Get(id string) (*VerificationSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

func (s *SessionStore) Update(id, status string, result *SessionResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		sess.Status = status
		sess.Result = result
	}
}

func (s *SessionStore) Cleanup(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for id, sess := range s.sessions {
		if sess.CreatedAt.Before(cutoff) {
			delete(s.sessions, id)
		}
	}
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
