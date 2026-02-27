package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// ErrTemplateNotFound is returned when a template ID does not match any built-in template.
var ErrTemplateNotFound = errors.New("template not found")

// TemplateService provides read access to built-in policy templates
// and the ability to apply (instantiate) them as real, editable policies.
type TemplateService struct {
	policyAdmin *PolicyAdminService
	logger      *slog.Logger
}

// NewTemplateService creates a new TemplateService.
func NewTemplateService(policyAdmin *PolicyAdminService, logger *slog.Logger) *TemplateService {
	return &TemplateService{
		policyAdmin: policyAdmin,
		logger:      logger,
	}
}

// List returns all built-in policy templates.
func (s *TemplateService) List() []policy.PolicyTemplate {
	return policy.AllTemplates()
}

// Get returns a specific template by ID.
// Returns ErrTemplateNotFound if the ID does not match any built-in template.
func (s *TemplateService) Get(id string) (*policy.PolicyTemplate, error) {
	tmpl, ok := policy.GetTemplate(id)
	if !ok {
		return nil, ErrTemplateNotFound
	}
	return tmpl, nil
}

// Apply instantiates a template as a real, editable policy by creating it
// through PolicyAdminService. The resulting policy is independent of the
// template and can be freely modified or deleted.
func (s *TemplateService) Apply(ctx context.Context, id string) (*policy.Policy, error) {
	tmpl, err := s.Get(id)
	if err != nil {
		return nil, err
	}

	p := tmpl.ToPolicy()

	created, err := s.policyAdmin.Create(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("apply template %q: %w", id, err)
	}

	s.logger.Info("template applied", "template_id", id, "policy_id", created.ID)
	return created, nil
}
