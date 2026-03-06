package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// WalletCredential represents a stored verifiable credential.
type WalletCredential struct {
	ID             string         `json:"id"`
	Format         string         `json:"format"`              // "ldp_vc"
	Document       string         `json:"document"`            // raw JSON string of the signed VC
	ParsedDocument map[string]any `json:"parsedDocument"`      // parsed VC as map
	AddedOn        string         `json:"addedOn"`             // RFC3339 timestamp
	IssuerDID      string         `json:"issuerDid,omitempty"` // issuer DID extracted from VC
	TypeName       string         `json:"typeName,omitempty"`  // credential type name
}

// WalletUser represents a user account (simple PoC — plaintext password).
type WalletUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// WalletKey holds the wallet's Ed25519 keypair and derived did:key.
type WalletKey struct {
	PrivateKey ed25519.PrivateKey `json:"-"`
	PublicKey  ed25519.PublicKey  `json:"-"`
	DID        string             `json:"did"`
	PrivHex    string             `json:"privateKeyHex"`
	PubHex     string             `json:"publicKeyHex"`
}

// DataStore manages file-based persistence with per-user credentials and keys.
type DataStore struct {
	mu          sync.RWMutex
	dataDir     string
	credentials map[string]map[string]*WalletCredential // email → credID → cred
	users       map[string]*WalletUser                  // keyed by email
	walletKeys  map[string]*WalletKey                   // email → key
}

func NewDataStore(dataDir string) *DataStore {
	os.MkdirAll(dataDir, 0755)
	ds := &DataStore{
		dataDir:     dataDir,
		credentials: make(map[string]map[string]*WalletCredential),
		users:       make(map[string]*WalletUser),
		walletKeys:  make(map[string]*WalletKey),
	}
	ds.loadAll()
	return ds
}

func (ds *DataStore) loadAll() {
	ds.loadJSON("credentials.json", &ds.credentials)
	ds.loadJSON("users.json", &ds.users)
	ds.loadWalletKeys()
	ds.migrateOldData()

	// Create default user if none exist
	if len(ds.users) == 0 {
		ds.registerUserInternal("user@example.com", "1234")
		log.Printf("Created default user: user@example.com / 1234")
	}
}

// migrateOldData handles migration from single-wallet format to per-user format.
func (ds *DataStore) migrateOldData() {
	// Migrate old wallet_key.json (single key) → per-user wallet_keys.json
	oldKeyPath := filepath.Join(ds.dataDir, "wallet_key.json")
	if data, err := os.ReadFile(oldKeyPath); err == nil {
		var wk WalletKey
		if err := json.Unmarshal(data, &wk); err == nil {
			privBytes, _ := hex.DecodeString(wk.PrivHex)
			pubBytes, _ := hex.DecodeString(wk.PubHex)
			if len(privBytes) == ed25519.PrivateKeySize && len(pubBytes) == ed25519.PublicKeySize {
				wk.PrivateKey = ed25519.PrivateKey(privBytes)
				wk.PublicKey = ed25519.PublicKey(pubBytes)
				// Assign to default user if they exist and don't already have a key
				defaultEmail := "user@example.com"
				if _, exists := ds.walletKeys[defaultEmail]; !exists {
					ds.walletKeys[defaultEmail] = &wk
					ds.saveJSON("wallet_keys.json", ds.walletKeys)
					log.Printf("Migrated old wallet key to user %s: %s", defaultEmail, wk.DID)
				}
			}
		}
		os.Remove(oldKeyPath)
	}

	// Migrate old flat credentials.json (credID → cred) → per-user format
	// Detect by checking if any top-level value is a WalletCredential (has "id" field)
	credsPath := filepath.Join(ds.dataDir, "credentials.json")
	if data, err := os.ReadFile(credsPath); err == nil {
		var flat map[string]json.RawMessage
		if err := json.Unmarshal(data, &flat); err == nil && len(flat) > 0 {
			// Check if this is old flat format by testing if a value looks like a credential
			for _, raw := range flat {
				var probe struct {
					ID     string `json:"id"`
					Format string `json:"format"`
				}
				if json.Unmarshal(raw, &probe) == nil && probe.ID != "" && probe.Format != "" {
					// Old flat format detected — migrate all to default user
					var oldCreds map[string]*WalletCredential
					if json.Unmarshal(data, &oldCreds) == nil {
						defaultEmail := "user@example.com"
						if ds.credentials[defaultEmail] == nil {
							ds.credentials[defaultEmail] = make(map[string]*WalletCredential)
						}
						for id, c := range oldCreds {
							ds.credentials[defaultEmail][id] = c
						}
						ds.saveJSON("credentials.json", ds.credentials)
						log.Printf("Migrated %d credentials to user %s", len(oldCreds), defaultEmail)
					}
				}
				break // only check first entry
			}
		}
	}
}

func (ds *DataStore) loadWalletKeys() {
	ds.loadJSON("wallet_keys.json", &ds.walletKeys)
	// Restore private/public key bytes from hex
	for email, wk := range ds.walletKeys {
		privBytes, _ := hex.DecodeString(wk.PrivHex)
		pubBytes, _ := hex.DecodeString(wk.PubHex)
		if len(privBytes) == ed25519.PrivateKeySize && len(pubBytes) == ed25519.PublicKeySize {
			wk.PrivateKey = ed25519.PrivateKey(privBytes)
			wk.PublicKey = ed25519.PublicKey(pubBytes)
		} else {
			log.Printf("WARNING: invalid key data for %s, regenerating", email)
			ds.generateWalletKey(email)
		}
	}
}

func (ds *DataStore) generateWalletKey(email string) *WalletKey {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate Ed25519 key: %v", err)
	}
	did := pubKeyToDIDKey(pub)
	wk := &WalletKey{
		PrivateKey: priv,
		PublicKey:  pub,
		DID:        did,
		PrivHex:    hex.EncodeToString(priv),
		PubHex:     hex.EncodeToString(pub),
	}
	ds.walletKeys[email] = wk
	ds.saveJSON("wallet_keys.json", ds.walletKeys)
	log.Printf("Generated wallet key for %s: %s", email, did)
	return wk
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
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("WARNING: failed to marshal %s: %v", filename, err)
		return
	}
	if err := os.WriteFile(path, b, 0644); err != nil {
		log.Printf("WARNING: failed to write %s: %v", filename, err)
	}
}

// --- User operations ---

func (ds *DataStore) AuthenticateUser(email, password string) bool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	u, ok := ds.users[email]
	return ok && u.Password == password
}

func (ds *DataStore) RegisterUser(email, password string) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if _, exists := ds.users[email]; exists {
		return fmt.Errorf("user already exists")
	}
	return ds.registerUserInternal(email, password)
}

// registerUserInternal creates user + wallet key (must hold lock or be called during init).
func (ds *DataStore) registerUserInternal(email, password string) error {
	ds.users[email] = &WalletUser{Email: email, Password: password}
	ds.saveJSON("users.json", ds.users)
	ds.credentials[email] = make(map[string]*WalletCredential)
	ds.generateWalletKey(email)
	return nil
}

// --- Credential operations (per-user) ---

func (ds *DataStore) SaveCredential(email string, c *WalletCredential) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if ds.credentials[email] == nil {
		ds.credentials[email] = make(map[string]*WalletCredential)
	}
	ds.credentials[email][c.ID] = c
	ds.saveJSON("credentials.json", ds.credentials)
}

func (ds *DataStore) GetCredential(email, id string) *WalletCredential {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	userCreds := ds.credentials[email]
	if userCreds == nil {
		return nil
	}
	return userCreds[id]
}

func (ds *DataStore) ListCredentials(email string) []*WalletCredential {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	userCreds := ds.credentials[email]
	result := make([]*WalletCredential, 0, len(userCreds))
	for _, c := range userCreds {
		result = append(result, c)
	}
	return result
}

func (ds *DataStore) DeleteCredential(email, id string) bool {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	userCreds := ds.credentials[email]
	if userCreds == nil {
		return false
	}
	if _, ok := userCreds[id]; !ok {
		return false
	}
	delete(userCreds, id)
	ds.saveJSON("credentials.json", ds.credentials)
	return true
}

// --- Wallet key operations (per-user) ---

func (ds *DataStore) GetWalletKey(email string) *WalletKey {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.walletKeys[email]
}

func (ds *DataStore) GetWalletID(email string) string {
	return "wallet-" + strings.ReplaceAll(email, "@", "-at-")
}

// --- API Session store (for pixelpass-adapter REST API) ---

type apiSession struct {
	email     string
	expiresAt time.Time
}

type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*apiSession
}

func NewSessionStore() *SessionStore {
	s := &SessionStore{sessions: make(map[string]*apiSession)}
	go s.reap()
	return s
}

func (s *SessionStore) Create(email string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := generateID()
	s.sessions[token] = &apiSession{
		email:     email,
		expiresAt: time.Now().Add(1 * time.Hour),
	}
	return token
}

func (s *SessionStore) Validate(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok || time.Now().After(sess.expiresAt) {
		delete(s.sessions, token)
		return "", false
	}
	return sess.email, true
}

func (s *SessionStore) reap() {
	for range time.Tick(5 * time.Minute) {
		now := time.Now()
		s.mu.Lock()
		for k, v := range s.sessions {
			if now.After(v.expiresAt) {
				delete(s.sessions, k)
			}
		}
		s.mu.Unlock()
	}
}

// --- UI Session store (for browser cookie sessions) ---

type UISessionStore struct {
	mu       sync.Mutex
	sessions map[string]*apiSession // reuse same struct
}

func NewUISessionStore() *UISessionStore {
	s := &UISessionStore{sessions: make(map[string]*apiSession)}
	go func() {
		for range time.Tick(5 * time.Minute) {
			now := time.Now()
			s.mu.Lock()
			for k, v := range s.sessions {
				if now.After(v.expiresAt) {
					delete(s.sessions, k)
				}
			}
			s.mu.Unlock()
		}
	}()
	return s
}

func (s *UISessionStore) Create(email string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := generateID()
	s.sessions[token] = &apiSession{
		email:     email,
		expiresAt: time.Now().Add(24 * time.Hour),
	}
	return token
}

func (s *UISessionStore) Validate(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok || time.Now().After(sess.expiresAt) {
		delete(s.sessions, token)
		return "", false
	}
	return sess.email, true
}

func (s *UISessionStore) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

// --- Helpers ---

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// pubKeyToDIDKey derives a did:key from an Ed25519 public key.
// Format: did:key:z + base58btc(0xed01 + pubkey)
func pubKeyToDIDKey(pub ed25519.PublicKey) string {
	// Multicodec prefix for Ed25519 public key: 0xed 0x01
	multicodec := make([]byte, 2+len(pub))
	multicodec[0] = 0xed
	multicodec[1] = 0x01
	copy(multicodec[2:], pub)
	return fmt.Sprintf("did:key:z%s", base58btcEncode(multicodec))
}

const base58btcAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58btcEncode(input []byte) string {
	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var result []byte
	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		result = append(result, base58btcAlphabet[mod.Int64()])
	}

	// Leading zeros
	for _, b := range input {
		if b != 0 {
			break
		}
		result = append(result, base58btcAlphabet[0])
	}

	// Reverse
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}
