package proxy

import "time"

func (a *AuthInterceptor) SetTestCacheEntry(connID, sessionID string) {
	a.sessionMu.Lock()
	a.sessionCache[connID] = &cacheEntry{
		sessionID:  sessionID,
		lastAccess: time.Now(),
	}
	a.sessionMu.Unlock()
}

func (a *AuthInterceptor) SetTestCacheEntryWithTime(connID, sessionID string, lastAccess time.Time) {
	a.sessionMu.Lock()
	a.sessionCache[connID] = &cacheEntry{
		sessionID:  sessionID,
		lastAccess: lastAccess,
	}
	a.sessionMu.Unlock()
}
