package cmd

import (
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/admin"
)

// bootAdminAPI creates the AdminAPIHandler with all dependencies.
func (bc *bootContext) bootAdminAPI() {
	bc.apiHandler = admin.NewAdminAPIHandler(
		admin.WithUpstreamService(bc.upstreamService),
		admin.WithUpstreamManager(bc.upstreamManager),
		admin.WithDiscoveryService(bc.discoveryService),
		admin.WithToolCache(bc.toolCache),
		admin.WithPolicyService(bc.policyService),
		admin.WithPolicyStore(bc.policyStore),
		admin.WithPolicyEvalService(bc.policyEvalService),
		admin.WithPolicyAdminService(bc.policyAdminService),
		admin.WithTemplateService(bc.templateService),
		admin.WithIdentityService(bc.identityService),
		admin.WithAuditService(bc.auditService),
		admin.WithAuditReader(bc.auditStore),
		admin.WithStatsService(bc.statsService),
		admin.WithStateStore(bc.stateStore),
		admin.WithToolSecurityService(bc.toolSecurityService),
		admin.WithNotificationService(bc.notificationService),
		admin.WithAPILogger(bc.logger),
		admin.WithBuildInfo(&admin.BuildInfo{
			Version:   Version,
			Commit:    Commit,
			BuildDate: BuildDate,
		}),
		admin.WithStartTime(bc.startTime),
	)
}
