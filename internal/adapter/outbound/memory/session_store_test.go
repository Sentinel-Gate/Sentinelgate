// Package memory provides in-memory implementations of outbound ports.
package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"go.uber.org/goleak"
)

func TestSessionStore_CreateAndGet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewSessionStore()

	sess := &session.Session{
		ID:         "sess-1",
		IdentityID: "user-1",
		Roles:      []auth.Role{auth.RoleUser},
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(30 * time.Minute),
		LastAccess: time.Now().UTC(),
	}

	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	got, err := store.Get(ctx, "sess-1")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}

	if got.ID != "sess-1" {
		t.Errorf("ID = %q, want %q", got.ID, "sess-1")
	}
	if got.IdentityID != "user-1" {
		t.Errorf("IdentityID = %q, want %q", got.IdentityID, "user-1")
	}
	if len(got.Roles) != 1 || got.Roles[0] != auth.RoleUser {
		t.Errorf("Roles = %v, want [%s]", got.Roles, auth.RoleUser)
	}
}

func TestSessionStore_GetNonExistent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewSessionStore()

	_, err := store.Get(ctx, "nonexistent")
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("Get() error = %v, want ErrSessionNotFound", err)
	}
}

func TestSessionStore_ExpiredSession(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewSessionStore()

	// Create already-expired session
	sess := &session.Session{
		ID:         "sess-expired",
		IdentityID: "user-1",
		Roles:      []auth.Role{auth.RoleUser},
		CreatedAt:  time.Now().UTC().Add(-time.Hour),
		ExpiresAt:  time.Now().UTC().Add(-time.Minute), // Already expired
		LastAccess: time.Now().UTC().Add(-time.Hour),
	}

	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Get should fail (lazy expiration check - but no deletion anymore)
	_, err := store.Get(ctx, "sess-expired")
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("Get() for expired session error = %v, want ErrSessionNotFound", err)
	}

	// Second get should also fail (session is still there but expired)
	_, err = store.Get(ctx, "sess-expired")
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("Get() after first check error = %v, want ErrSessionNotFound", err)
	}
}

func TestSessionStore_Update(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewSessionStore()

	sess := &session.Session{
		ID:         "sess-update",
		IdentityID: "user-1",
		ExpiresAt:  time.Now().UTC().Add(30 * time.Minute),
		LastAccess: time.Now().UTC().Add(-10 * time.Minute),
	}

	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Update the session
	sess.LastAccess = time.Now().UTC()
	sess.IdentityID = "user-2"
	if err := store.Update(ctx, sess); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	// Verify the update persisted
	got, err := store.Get(ctx, "sess-update")
	if err != nil {
		t.Fatalf("Get() after update error: %v", err)
	}
	if got.IdentityID != "user-2" {
		t.Errorf("IdentityID = %q, want %q", got.IdentityID, "user-2")
	}
}

func TestSessionStore_UpdateNonExistent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewSessionStore()

	sess := &session.Session{
		ID:        "nonexistent",
		ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
	}

	err := store.Update(ctx, sess)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("Update() error = %v, want ErrSessionNotFound", err)
	}
}

func TestSessionStore_Delete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewSessionStore()

	sess := &session.Session{
		ID:        "sess-delete",
		ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
	}

	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Delete the session
	if err := store.Delete(ctx, "sess-delete"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	// Get should fail
	_, err := store.Get(ctx, "sess-delete")
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("Get() after Delete() should return ErrSessionNotFound, got %v", err)
	}
}

func TestSessionStore_DeleteNonExistent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewSessionStore()

	// Delete non-existent session should not error
	if err := store.Delete(ctx, "nonexistent"); err != nil {
		t.Errorf("Delete() on non-existent session should not error, got %v", err)
	}
}

func TestSessionStore_CopyOnReturn(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewSessionStore()

	sess := &session.Session{
		ID:         "sess-copy-test",
		IdentityID: "user-1",
		Roles:      []auth.Role{auth.RoleUser},
		ExpiresAt:  time.Now().UTC().Add(30 * time.Minute),
	}

	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Get and modify
	got1, err := store.Get(ctx, "sess-copy-test")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	got1.IdentityID = "modified-user"
	got1.Roles = append(got1.Roles, auth.RoleAdmin)

	// Get again - should not be modified
	got2, err := store.Get(ctx, "sess-copy-test")
	if err != nil {
		t.Fatalf("Get() second call error: %v", err)
	}

	if got2.IdentityID == "modified-user" {
		t.Error("Store returned reference instead of copy (IdentityID was modified)")
	}
	if len(got2.Roles) != 1 {
		t.Errorf("Store returned reference instead of copy (Roles length = %d, want 1)", len(got2.Roles))
	}
}

func TestSessionStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewSessionStore()

	// Create some sessions for concurrent access
	for i := 0; i < 10; i++ {
		sess := &session.Session{
			ID:         "sess-concurrent-" + string(rune('0'+i)),
			IdentityID: "user-1",
			ExpiresAt:  time.Now().UTC().Add(30 * time.Minute),
		}
		if err := store.Create(ctx, sess); err != nil {
			t.Fatalf("Create() error: %v", err)
		}
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 400)

	// 100 goroutines reading
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sessID := "sess-concurrent-" + string(rune('0'+(idx%10)))
			_, err := store.Get(ctx, sessID)
			if err != nil && !errors.Is(err, session.ErrSessionNotFound) {
				errCh <- err
			}
		}(i)
	}

	// 100 goroutines writing (updates)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sessID := "sess-concurrent-" + string(rune('0'+(idx%10)))
			sess := &session.Session{
				ID:         sessID,
				IdentityID: "user-updated",
				ExpiresAt:  time.Now().UTC().Add(30 * time.Minute),
			}
			// Update might fail if session was deleted, which is ok for this test
			_ = store.Update(ctx, sess)
		}(i)
	}

	// 50 goroutines creating new sessions
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sess := &session.Session{
				ID:        "sess-new-" + string(rune('a'+idx)),
				ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
			}
			if err := store.Create(ctx, sess); err != nil {
				errCh <- err
			}
		}(i)
	}

	// 50 goroutines deleting
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sessID := "sess-concurrent-" + string(rune('0'+(idx%10)))
			// Delete should never error
			if err := store.Delete(ctx, sessID); err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent access error: %v", err)
	}
}

func TestSessionStore_CreateWithEmptyRoles(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewSessionStore()

	sess := &session.Session{
		ID:         "sess-no-roles",
		IdentityID: "user-1",
		Roles:      nil,
		ExpiresAt:  time.Now().UTC().Add(30 * time.Minute),
	}

	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	got, err := store.Get(ctx, "sess-no-roles")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}

	if got.Roles == nil {
		// nil is acceptable
	} else if len(got.Roles) != 0 {
		t.Errorf("Roles = %v, want empty or nil", got.Roles)
	}
}

// TestSessionStoreCleanup verifies that expired sessions are removed by background cleanup.
func TestSessionStoreCleanup(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create store with short cleanup interval
	store := NewSessionStoreWithConfig(50 * time.Millisecond)
	store.StartCleanup(ctx)
	defer store.Stop()

	// Create a session that expires in 100ms
	sess := &session.Session{
		ID:         "sess-cleanup-test",
		IdentityID: "user-1",
		Roles:      []auth.Role{auth.RoleUser},
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(100 * time.Millisecond),
		LastAccess: time.Now().UTC(),
	}

	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Verify session exists initially
	_, err := store.Get(ctx, "sess-cleanup-test")
	if err != nil {
		t.Fatalf("Get() should succeed initially: %v", err)
	}

	// Verify internal map has the session
	if store.Size() != 1 {
		t.Errorf("Size() = %d, want 1", store.Size())
	}

	// Wait for expiration + cleanup cycle
	time.Sleep(250 * time.Millisecond)

	// Session should be cleaned up - Get returns ErrSessionNotFound
	_, err = store.Get(ctx, "sess-cleanup-test")
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("Get() after cleanup should return ErrSessionNotFound, got %v", err)
	}

	// Internal map should also be clean
	if store.Size() != 0 {
		t.Errorf("Size() after cleanup = %d, want 0", store.Size())
	}
}

// TestSessionStoreNoGoroutineLeak verifies that cleanup goroutine exits properly.
func TestSessionStoreNoGoroutineLeak(t *testing.T) {
	defer goleak.VerifyNone(t)

	ctx, cancel := context.WithCancel(context.Background())

	store := NewSessionStoreWithConfig(50 * time.Millisecond)
	store.StartCleanup(ctx)

	// Create and get some sessions
	for i := 0; i < 5; i++ {
		sess := &session.Session{
			ID:        "sess-leak-test-" + string(rune('0'+i)),
			ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
		}
		_ = store.Create(ctx, sess)
		_, _ = store.Get(ctx, sess.ID)
	}

	// Wait a bit for cleanup goroutine to run
	time.Sleep(100 * time.Millisecond)

	// Cancel context and stop cleanup
	cancel()
	store.Stop()

	// goleak.VerifyNone will fail if goroutine leaked
}

// TestSessionStoreConcurrentAccessDuringCleanup verifies no races during cleanup.
func TestSessionStoreConcurrentAccessDuringCleanup(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create store with very short cleanup interval
	store := NewSessionStoreWithConfig(10 * time.Millisecond)
	store.StartCleanup(ctx)
	defer store.Stop()

	var wg sync.WaitGroup
	done := make(chan struct{})

	// Launch 10 goroutines that continuously Create/Get/Delete sessions
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			bgCtx := context.Background()
			counter := 0
			for {
				select {
				case <-done:
					return
				default:
					sessID := "sess-concurrent-cleanup-" + string(rune('a'+idx)) + "-" + string(rune('0'+counter%10))
					sess := &session.Session{
						ID:        sessID,
						ExpiresAt: time.Now().UTC().Add(50 * time.Millisecond), // Short expiry
					}
					_ = store.Create(bgCtx, sess)
					_, _ = store.Get(bgCtx, sessID)
					_ = store.Delete(bgCtx, sessID)
					counter++
				}
			}
		}(i)
	}

	// Run for 500ms
	time.Sleep(500 * time.Millisecond)
	close(done)
	wg.Wait()

	// If we got here without panics or race conditions, the test passed
}

// TestSessionStoreGetNoLockUpgrade verifies Get() doesn't deadlock on expired sessions.
func TestSessionStoreGetNoLockUpgrade(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewSessionStore()

	// Create an expired session
	sess := &session.Session{
		ID:         "sess-lock-upgrade-test",
		IdentityID: "user-1",
		ExpiresAt:  time.Now().UTC().Add(-time.Minute), // Already expired
	}
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	// 100 goroutines all calling Get() on same expired session
	// If old lock upgrade pattern existed, this would likely deadlock
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Get(ctx, "sess-lock-upgrade-test")
			if err != nil && !errors.Is(err, session.ErrSessionNotFound) {
				errCh <- err
			}
		}()
	}

	// This should complete quickly (< 1 second)
	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		// Success - completed without deadlock
	case <-time.After(2 * time.Second):
		t.Fatal("Test timed out - possible deadlock in Get()")
	}

	close(errCh)
	for err := range errCh {
		t.Errorf("Get() error: %v", err)
	}
}

// TestSessionStoreStopMultipleCalls verifies Stop() can be called multiple times safely.
func TestSessionStoreStopMultipleCalls(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := NewSessionStoreWithConfig(50 * time.Millisecond)
	store.StartCleanup(ctx)

	// Call Stop() multiple times - should not panic
	store.Stop()
	store.Stop()
	store.Stop()
}

func TestSessionStoreLongRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	defer goleak.VerifyNone(t)

	store := NewSessionStoreWithConfig(100 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer store.Stop()

	store.StartCleanup(ctx)

	// Create many sessions with short TTL
	sessionCount := 0
	start := time.Now()
	for time.Since(start) < 3*time.Second {
		sess := &session.Session{
			ID:         "sess-" + string(rune('0'+sessionCount/1000)) + string(rune('0'+(sessionCount/100)%10)) + string(rune('0'+(sessionCount/10)%10)) + string(rune('0'+sessionCount%10)),
			IdentityID: "test-user",
			CreatedAt:  time.Now(),
			ExpiresAt:  time.Now().Add(200 * time.Millisecond), // Short TTL
			LastAccess: time.Now(),
			Roles:      []auth.Role{auth.RoleUser},
		}
		_ = store.Create(context.Background(), sess)
		sessionCount++
		time.Sleep(time.Millisecond)
	}

	// Wait for cleanup cycles
	time.Sleep(500 * time.Millisecond)

	// Verify map size is bounded
	size := store.Size()
	t.Logf("Created %d sessions, map size after cleanup: %d", sessionCount, size)

	// Should have cleaned most sessions (200ms TTL, 500ms wait)
	if size > sessionCount/4 {
		t.Errorf("Map size %d is too large (created %d sessions), cleanup not working", size, sessionCount)
	}
}
