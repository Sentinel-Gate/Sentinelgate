package httpgw

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testCertCache(t *testing.T, ttl time.Duration) (*CertCache, *CAManager) {
	t.Helper()
	dir := t.TempDir()
	cfg := CAConfig{
		CertFile:      filepath.Join(dir, "ca-cert.pem"),
		KeyFile:       filepath.Join(dir, "ca-key.pem"),
		Organization:  "Test CA",
		ValidityYears: 1,
	}
	logger := testLogger()
	cm, err := NewCAManager(cfg, logger)
	if err != nil {
		t.Fatalf("NewCAManager: %v", err)
	}
	return NewCertCache(cm, ttl, logger), cm
}

// TestCertCache_Miss verifies that a cache miss generates a new cert.
func TestCertCache_Miss(t *testing.T) {
	cache, _ := testCertCache(t, time.Hour)

	cert, err := cache.GetCert("example.com")
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if cert == nil {
		t.Fatal("GetCert returned nil cert")
	}
	if cache.Size() != 1 {
		t.Errorf("Size = %d, want 1", cache.Size())
	}
}

// TestCertCache_Hit verifies that the same cert is returned for repeated calls.
func TestCertCache_Hit(t *testing.T) {
	cache, _ := testCertCache(t, time.Hour)

	cert1, err := cache.GetCert("example.com")
	if err != nil {
		t.Fatalf("GetCert 1: %v", err)
	}
	cert2, err := cache.GetCert("example.com")
	if err != nil {
		t.Fatalf("GetCert 2: %v", err)
	}

	// Same pointer means same cert (cache hit, not regenerated)
	if cert1 != cert2 {
		t.Error("second call returned different cert pointer (expected cache hit)")
	}
	if cache.Size() != 1 {
		t.Errorf("Size = %d, want 1", cache.Size())
	}
}

// TestCertCache_Expiry verifies that expired entries trigger regeneration.
func TestCertCache_Expiry(t *testing.T) {
	cache, _ := testCertCache(t, 1*time.Millisecond)

	cert1, err := cache.GetCert("example.com")
	if err != nil {
		t.Fatalf("GetCert 1: %v", err)
	}

	// Wait for TTL to expire
	time.Sleep(5 * time.Millisecond)

	cert2, err := cache.GetCert("example.com")
	if err != nil {
		t.Fatalf("GetCert 2: %v", err)
	}

	// Different serial means a new cert was generated
	if cert1.Leaf.SerialNumber.Cmp(cert2.Leaf.SerialNumber) == 0 {
		t.Error("expected different serial after expiry (cert was not regenerated)")
	}
}

// TestCertCache_Concurrent verifies that concurrent access to the cache
// is safe and produces valid results.
func TestCertCache_Concurrent(t *testing.T) {
	cache, _ := testCertCache(t, time.Hour)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			cert, err := cache.GetCert("concurrent.example.com")
			if err != nil {
				errs <- err
				return
			}
			if cert == nil {
				errs <- err
				return
			}
			if cert.Leaf == nil {
				errs <- err
				return
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent GetCert error: %v", err)
	}

	if cache.Size() != 1 {
		t.Errorf("Size = %d, want 1 (single domain)", cache.Size())
	}
}

// TestCertCache_MultipleDomains verifies that different domains get separate entries.
func TestCertCache_MultipleDomains(t *testing.T) {
	cache, _ := testCertCache(t, time.Hour)

	domains := []string{"a.example.com", "b.example.com", "c.example.com"}
	for _, d := range domains {
		_, err := cache.GetCert(d)
		if err != nil {
			t.Fatalf("GetCert(%q): %v", d, err)
		}
	}

	if cache.Size() != 3 {
		t.Errorf("Size = %d, want 3", cache.Size())
	}
}

// TestCertCache_Clear verifies that Clear removes all cached entries.
func TestCertCache_Clear(t *testing.T) {
	cache, _ := testCertCache(t, time.Hour)

	// Populate with some domains
	for _, d := range []string{"a.com", "b.com", "c.com"} {
		_, err := cache.GetCert(d)
		if err != nil {
			t.Fatalf("GetCert(%q): %v", d, err)
		}
	}

	if cache.Size() != 3 {
		t.Errorf("Size before clear = %d, want 3", cache.Size())
	}

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Size after clear = %d, want 0", cache.Size())
	}
}
