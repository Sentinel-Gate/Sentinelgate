package compliance

import (
	"testing"
)

func TestCompliancePackDefinitions(t *testing.T) {
	if len(BuiltinPacks) == 0 {
		t.Fatal("BuiltinPacks is empty; expected at least one compliance pack")
	}
	t.Logf("BuiltinPacks contains %d pack(s)", len(BuiltinPacks))
}

func TestPackRequirements(t *testing.T) {
	for id, pack := range BuiltinPacks {
		if pack == nil {
			t.Errorf("pack %q is nil", id)
			continue
		}
		if len(pack.Requirements) == 0 {
			t.Errorf("pack %q has no requirements", id)
			continue
		}
		for _, req := range pack.Requirements {
			if req.ID == "" {
				t.Errorf("pack %q contains a requirement with empty ID", id)
			}
			if req.Article == "" {
				t.Errorf("pack %q requirement %q has empty Article", id, req.ID)
			}
			if req.Title == "" {
				t.Errorf("pack %q requirement %q has empty Title", id, req.ID)
			}
			if req.Description == "" {
				t.Errorf("pack %q requirement %q has empty Description", id, req.ID)
			}
			if len(req.EvidenceChecks) == 0 {
				t.Errorf("pack %q requirement %q has no EvidenceChecks", id, req.ID)
			}
		}
	}
}

func TestGetPack_Exists(t *testing.T) {
	knownID := "eu-ai-act-transparency"
	pack, ok := BuiltinPacks[knownID]
	if !ok {
		t.Fatalf("expected BuiltinPacks to contain %q", knownID)
	}
	if pack == nil {
		t.Fatalf("pack %q is nil", knownID)
	}
	if pack.ID != knownID {
		t.Errorf("pack.ID = %q, want %q", pack.ID, knownID)
	}
	if pack.Name == "" {
		t.Error("pack.Name is empty")
	}
	if pack.Framework == "" {
		t.Error("pack.Framework is empty")
	}
	if pack.Version == "" {
		t.Error("pack.Version is empty")
	}
	if pack.Description == "" {
		t.Error("pack.Description is empty")
	}
}

func TestGetPack_NotFound(t *testing.T) {
	pack, ok := BuiltinPacks["nonexistent-pack-id"]
	if ok {
		t.Error("expected BuiltinPacks lookup for unknown ID to return false")
	}
	if pack != nil {
		t.Error("expected nil pack for unknown ID")
	}
}

func TestPackEvidenceChecks(t *testing.T) {
	for id, pack := range BuiltinPacks {
		if pack == nil {
			continue
		}
		for _, req := range pack.Requirements {
			for _, check := range req.EvidenceChecks {
				if check.ID == "" {
					t.Errorf("pack %q, req %q: EvidenceCheck has empty ID", id, req.ID)
				}
				if check.Description == "" {
					t.Errorf("pack %q, req %q, check %q: empty Description", id, req.ID, check.ID)
				}
				if check.CheckType == "" {
					t.Errorf("pack %q, req %q, check %q: empty CheckType", id, req.ID, check.ID)
				}
				if check.Source == "" {
					t.Errorf("pack %q, req %q, check %q: empty Source", id, req.ID, check.ID)
				}
			}
		}
	}
}

func TestPackMapKeyMatchesID(t *testing.T) {
	for key, pack := range BuiltinPacks {
		if pack == nil {
			continue
		}
		if key != pack.ID {
			t.Errorf("BuiltinPacks key %q does not match pack.ID %q", key, pack.ID)
		}
	}
}
