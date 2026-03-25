package admin

import (
	"net/http"
	"time"
)

// BuildInfo holds build-time version information.
// Injected via WithBuildInfo option to avoid import cycles with cmd package.
type BuildInfo struct {
	Version   string
	Commit    string
	BuildDate string
}

// SystemInfoResponse is the JSON response for GET /admin/api/system.
// L-13: GoVersion, OS, and Arch are intentionally omitted to avoid exposing
// runtime fingerprint information that could aid attackers with compromised
// admin credentials. Version, Commit, and BuildDate are retained for
// operational use (identifying deployed builds).
type SystemInfoResponse struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	Uptime    string `json:"uptime"`
	UptimeSec int64  `json:"uptime_seconds"`
}

// handleSystemInfo returns system information including version, uptime,
// Go version, OS, and architecture.
func (h *AdminAPIHandler) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(h.startTime)

	version := "dev"
	commit := "none"
	buildDate := "unknown"

	if h.buildInfo != nil {
		version = h.buildInfo.Version
		commit = h.buildInfo.Commit
		buildDate = h.buildInfo.BuildDate
	}

	resp := SystemInfoResponse{
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
		Uptime:    uptime.Truncate(time.Second).String(),
		UptimeSec: int64(uptime.Seconds()),
	}

	h.respondJSON(w, http.StatusOK, resp)
}
