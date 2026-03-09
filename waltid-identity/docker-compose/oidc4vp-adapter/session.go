package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

type VerificationSession struct {
	ID                     string
	State                  string
	Nonce                  string
	PresentationDefinition map[string]any
	OpenID4VPURL           string
	WalletURL              string
	Status                 string // "pending", "success", "failure"
	Result                 *SessionResult
	CreatedAt              time.Time
}

type SessionResult struct {
	OverallSuccess    bool
	Credentials       []Credential
	SameSubject       *SameSubjectResult
	CredentialResults []CredentialResult
}

type CredentialResult struct {
	Type   string `json:"type"`
	Status string `json:"status"` // "SUCCESS" or "INVALID"
	Error  string `json:"error,omitempty"`
}

type SameSubjectResult struct {
	Matched        bool   `json:"matched"`
	IdentityDid    string `json:"identityDid,omitempty"`
	MatchPath      string `json:"matchPath,omitempty"`
	IdentityType   string `json:"identityType,omitempty"`
	DelegationType string `json:"delegationType,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

type Credential struct {
	Type   string
	Title  string
	Fields []CredentialField
	Failed bool
}

type CredentialField struct {
	Key   string
	Value string
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

func (s *SessionStore) GetByState(state string) (*VerificationSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sess := range s.sessions {
		if sess.State == state {
			return sess, true
		}
	}
	return nil, false
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

var camelCaseRe = regexp.MustCompile(`([a-z0-9])([A-Z])`)

func camelToTitle(s string) string {
	spaced := camelCaseRe.ReplaceAllString(s, "${1} ${2}")
	if len(spaced) > 0 {
		spaced = strings.ToUpper(spaced[:1]) + spaced[1:]
	}
	return spaced
}

func buildCredential(vc map[string]any) Credential {
	cred := Credential{}
	if types, ok := vc["type"].([]any); ok && len(types) > 0 {
		lastType := fmt.Sprintf("%v", types[len(types)-1])
		cred.Type = lastType
		cred.Title = camelToTitle(lastType)
	}

	subj, ok := vc["credentialSubject"].(map[string]any)
	if !ok {
		return cred
	}
	cred.Fields = flattenSubject("", subj)
	return cred
}

func flattenSubject(prefix string, obj map[string]any) []CredentialField {
	var fields []CredentialField
	for key, val := range obj {
		if key == "id" && prefix == "" {
			continue
		}
		label := camelToTitle(key)
		if prefix != "" {
			label = prefix + " " + label
		}
		switch v := val.(type) {
		case string:
			if strings.HasPrefix(v, "did:") && len(v) > 30 {
				v = v[:25] + "..."
			}
			fields = append(fields, CredentialField{Key: label, Value: v})
		case float64:
			fields = append(fields, CredentialField{Key: label, Value: fmt.Sprintf("%g", v)})
		case map[string]any:
			fields = append(fields, flattenSubject(label, v)...)
		default:
			s := fmt.Sprintf("%v", v)
			if len(s) > 0 && len(s) <= 80 {
				fields = append(fields, CredentialField{Key: label, Value: s})
			}
		}
	}
	return fields
}

// sessionResultJSON returns a JSON-serializable view of the session for the API.
func sessionResultJSON(sess *VerificationSession) map[string]any {
	result := map[string]any{
		"id":     sess.ID,
		"status": sess.Status,
	}
	if sess.Result != nil {
		result["overallSuccess"] = sess.Result.OverallSuccess

		var creds []map[string]any
		for _, c := range sess.Result.Credentials {
			cm := map[string]any{
				"type":   c.Type,
				"title":  c.Title,
				"failed": c.Failed,
			}
			var fields []map[string]string
			for _, f := range c.Fields {
				fields = append(fields, map[string]string{"key": f.Key, "value": f.Value})
			}
			cm["fields"] = fields
			creds = append(creds, cm)
		}
		result["credentials"] = creds

		var credResults []map[string]any
		for _, cr := range sess.Result.CredentialResults {
			m := map[string]any{"type": cr.Type, "status": cr.Status}
			if cr.Error != "" {
				m["error"] = cr.Error
			}
			credResults = append(credResults, m)
		}
		result["credentialResults"] = credResults

		if sess.Result.SameSubject != nil {
			ssJSON, _ := json.Marshal(sess.Result.SameSubject)
			var ssMap map[string]any
			json.Unmarshal(ssJSON, &ssMap)
			result["sameSubject"] = ssMap
		}
	}
	return result
}
