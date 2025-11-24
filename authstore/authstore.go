package authstore

import (
	"sync"
)

// AuthInfo contains backend authentication details
type AuthInfo struct {
	PasswordHash string
	UpstreamHost string
	UpstreamPort string
	UpstreamUser string
	UpstreamPass string
}

// Store holds authentication info keyed by username
type Store struct {
	mu   sync.RWMutex
	data map[string]*AuthInfo
}

var global = &Store{
	data: make(map[string]*AuthInfo),
}

// Set stores auth info for a username
func Set(username string, info *AuthInfo) {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.data[username] = info
}

// Get retrieves auth info for a username
func Get(username string) *AuthInfo {
	global.mu.RLock()
	defer global.mu.RUnlock()
	return global.data[username]
}

// Delete removes auth info for a username (optional, for cleanup)
func Delete(username string) {
	global.mu.Lock()
	defer global.mu.Unlock()
	delete(global.data, username)
}