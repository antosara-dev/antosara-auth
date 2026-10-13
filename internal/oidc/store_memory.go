package oidc

import (
	"context"
	"sync"
	"time"
)

// MemoryStores is an in-process implementation used by tests.
type MemoryStores struct {
	mu       sync.Mutex
	codes    map[string]AuthCode
	refresh  map[string]RefreshRecord
	consents map[string]Consent
}

// NewMemoryStores returns empty in-memory OIDC stores.
func NewMemoryStores() *MemoryStores {
	return &MemoryStores{
		codes:    make(map[string]AuthCode),
		refresh:  make(map[string]RefreshRecord),
		consents: make(map[string]Consent),
	}
}

func (m *MemoryStores) Put(ctx context.Context, codeHash string, code AuthCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[codeHash] = code
	return nil
}

func (m *MemoryStores) Consume(ctx context.Context, codeHash string) (*AuthCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	code, ok := m.codes[codeHash]
	if !ok {
		return nil, ErrNotFound
	}
	delete(m.codes, codeHash)
	if time.Now().After(code.ExpiresAt) {
		return nil, ErrNotFound
	}
	out := code
	return &out, nil
}

func (m *MemoryStores) PutRefresh(ctx context.Context, tokenHash string, rec RefreshRecord) error {
	return m.PutToken(ctx, tokenHash, rec)
}

func (m *MemoryStores) PutToken(ctx context.Context, tokenHash string, rec RefreshRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh[tokenHash] = rec
	return nil
}

func (m *MemoryStores) ConsumeRefresh(ctx context.Context, tokenHash string) (*RefreshRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.refresh[tokenHash]
	if !ok {
		return nil, ErrNotFound
	}
	if time.Now().After(rec.ExpiresAt) {
		delete(m.refresh, tokenHash)
		return nil, ErrNotFound
	}
	if rec.Consumed {
		return &rec, ErrReuseDetected
	}
	rec.Consumed = true
	m.refresh[tokenHash] = rec
	out := rec
	return &out, nil
}

func (m *MemoryStores) RevokeFamily(ctx context.Context, familyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, rec := range m.refresh {
		if rec.FamilyID == familyID {
			delete(m.refresh, k)
		}
	}
	return nil
}

func (m *MemoryStores) RevokeBySub(ctx context.Context, sub string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, rec := range m.refresh {
		if rec.Sub == sub {
			delete(m.refresh, k)
		}
	}
	return nil
}

func (m *MemoryStores) GetConsent(ctx context.Context, sub, clientID string) (*Consent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.consents[sub+"\x00"+clientID]
	if !ok {
		return nil, ErrNotFound
	}
	out := c
	return &out, nil
}

func (m *MemoryStores) PutConsent(ctx context.Context, c Consent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consents[c.Sub+"\x00"+c.ClientID] = c
	return nil
}

// Adapter methods so MemoryStores can be used as the three store interfaces
// via thin wrappers in NewMemoryOIDCStores.

type memoryCodeStore struct{ m *MemoryStores }
type memoryRefreshStore struct{ m *MemoryStores }
type memoryConsentStore struct{ m *MemoryStores }

func (s memoryCodeStore) Put(ctx context.Context, codeHash string, code AuthCode) error {
	return s.m.Put(ctx, codeHash, code)
}
func (s memoryCodeStore) Consume(ctx context.Context, codeHash string) (*AuthCode, error) {
	return s.m.Consume(ctx, codeHash)
}

func (s memoryRefreshStore) Put(ctx context.Context, tokenHash string, rec RefreshRecord) error {
	return s.m.PutToken(ctx, tokenHash, rec)
}
func (s memoryRefreshStore) Consume(ctx context.Context, tokenHash string) (*RefreshRecord, error) {
	return s.m.ConsumeRefresh(ctx, tokenHash)
}
func (s memoryRefreshStore) RevokeFamily(ctx context.Context, familyID string) error {
	return s.m.RevokeFamily(ctx, familyID)
}
func (s memoryRefreshStore) RevokeBySub(ctx context.Context, sub string) error {
	return s.m.RevokeBySub(ctx, sub)
}

func (s memoryConsentStore) Get(ctx context.Context, sub, clientID string) (*Consent, error) {
	return s.m.GetConsent(ctx, sub, clientID)
}
func (s memoryConsentStore) Put(ctx context.Context, c Consent) error {
	return s.m.PutConsent(ctx, c)
}

// NewMemoryOIDCStores returns Code/Refresh/Consent stores backed by memory.
func NewMemoryOIDCStores() Stores {
	m := NewMemoryStores()
	return Stores{
		Codes:    memoryCodeStore{m},
		Refresh:  memoryRefreshStore{m},
		Consents: memoryConsentStore{m},
	}
}
