package mpcrsa

import (
	"log"
	"sync"
	"time"
)

// SessionCache provides an in-memory cache for MPC protocol sessions.
// This is needed because some MPC libraries (like nekryptology) have internal
// state that cannot be easily serialized.
//
// For production distributed deployments, this should be replaced with:
// - Redis-based session storage with serialization support
// - Fork of nekryptology with proper serialization
// - Sticky sessions to route requests to the same server

var (
	globalSessionCache = NewSessionCache()
)

// Session represents an MPC protocol session
type Session struct {
	ID        string
	Protocol  string
	CreatedAt time.Time
	ExpiresAt time.Time
	Data      interface{} // Protocol-specific state
}

// SessionCache manages MPC protocol sessions
type SessionCache struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewSessionCache creates a new session cache
func NewSessionCache() *SessionCache {
	cache := &SessionCache{
		sessions: make(map[string]*Session),
	}
	// Start cleanup goroutine
	go cache.cleanupLoop()
	return cache
}

// GetSessionCache returns the global session cache
func GetSessionCache() *SessionCache {
	return globalSessionCache
}

// ListSessions returns all session IDs (for debugging)
func (c *SessionCache) ListSessions() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ids := make([]string, 0, len(c.sessions))
	for id := range c.sessions {
		ids = append(ids, id)
	}
	return ids
}

// Put stores a session
func (c *SessionCache) Put(id string, protocol string, data interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	c.sessions[id] = &Session{
		ID:        id,
		Protocol:  protocol,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Data:      data,
	}
	log.Printf("SessionCache.Put: id=%s protocol=%s type=%T totalSessions=%d", id, protocol, data, len(c.sessions))
}

// Get retrieves a session
func (c *SessionCache) Get(id string) (*Session, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	session, ok := c.sessions[id]
	if !ok {
		log.Printf("SessionCache.Get: id=%s NOT FOUND (totalSessions=%d)", id, len(c.sessions))
		return nil, false
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) {
		log.Printf("SessionCache.Get: id=%s EXPIRED (protocol=%s)", id, session.Protocol)
		return nil, false
	}

	log.Printf("SessionCache.Get: id=%s FOUND protocol=%s type=%T", id, session.Protocol, session.Data)
	return session, true
}

// Delete removes a session
func (c *SessionCache) Delete(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.sessions[id]; exists {
		log.Printf("SessionCache.Delete: id=%s (was present)", id)
	} else {
		log.Printf("SessionCache.Delete: id=%s (was NOT present)", id)
	}
	delete(c.sessions, id)
}

// cleanupLoop periodically removes expired sessions
func (c *SessionCache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanup()
	}
}

func (c *SessionCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for id, session := range c.sessions {
		if now.After(session.ExpiresAt) {
			delete(c.sessions, id)
		}
	}
}

// (DKLsBobSession type removed — not needed in mpc-wasm; that path uses the
// dkls23-wasm Rust crate, not this Go-wasm module.)
