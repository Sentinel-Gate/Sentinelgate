package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/httpgw"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/google/uuid"
)

// HTTPGatewayController provides admin API access to HTTP Gateway config.
// Implemented by the concrete httpGatewayControllerImpl in start.go.
type HTTPGatewayController interface {
	// TLS inspection
	TLSEnabled() bool
	SetTLSEnabled(enabled bool)
	BypassList() []string
	SetBypassList(list []string)
	// Upstream targets (from state.json)
	Targets() []httpgw.UpstreamTarget
	SetTargets(targets []httpgw.UpstreamTarget)
	// CA cert (PEM bytes, nil if no CA)
	CACertPEM() []byte
}

// SetHTTPGatewayController sets the HTTP Gateway controller after construction.
// This is needed when the HTTP gateway is created after the AdminAPIHandler (due to
// boot sequence ordering where BOOT-07 builds the gateway after services).
func (h *AdminAPIHandler) SetHTTPGatewayController(ctrl HTTPGatewayController) {
	h.httpGatewayCtrl = ctrl
}

// --- HTTP Gateway API request/response types ---

type httpGatewayConfigResponse struct {
	TLSInspection httpGatewayTLSResponse  `json:"tls_inspection"`
	Targets       []httpGatewayTargetJSON `json:"targets"`
	SinglePort    bool                    `json:"single_port"`
}

type httpGatewayTLSResponse struct {
	Enabled    bool     `json:"enabled"`
	BypassList []string `json:"bypass_list"`
}

type httpGatewayTargetJSON struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	PathPrefix  string            `json:"path_prefix"`
	Upstream    string            `json:"upstream"`
	StripPrefix bool              `json:"strip_prefix"`
	Headers     map[string]string `json:"headers,omitempty"`
	Enabled     bool              `json:"enabled"`
}

type httpGatewayTLSRequest struct {
	Enabled    *bool    `json:"enabled"`
	BypassList []string `json:"bypass_list"`
}

type httpGatewayTargetRequest struct {
	Name        string            `json:"name"`
	PathPrefix  string            `json:"path_prefix"`
	Upstream    string            `json:"upstream"`
	StripPrefix bool              `json:"strip_prefix"`
	Headers     map[string]string `json:"headers,omitempty"`
	Enabled     *bool             `json:"enabled"`
}

// --- Handlers ---

// handleGetHTTPGatewayConfig returns the current HTTP Gateway configuration.
// GET /admin/api/v1/security/http-gateway
func (h *AdminAPIHandler) handleGetHTTPGatewayConfig(w http.ResponseWriter, r *http.Request) {
	if h.httpGatewayCtrl == nil {
		h.respondError(w, http.StatusServiceUnavailable, "HTTP Gateway not configured")
		return
	}

	targets := h.httpGatewayCtrl.Targets()
	targetJSON := make([]httpGatewayTargetJSON, len(targets))
	for i, t := range targets {
		targetJSON[i] = httpGatewayTargetJSON{
			ID:          t.ID,
			Name:        t.Name,
			PathPrefix:  t.PathPrefix,
			Upstream:    t.Upstream,
			StripPrefix: t.StripPrefix,
			Headers:     t.Headers,
			Enabled:     t.Enabled,
		}
	}

	h.respondJSON(w, http.StatusOK, httpGatewayConfigResponse{
		TLSInspection: httpGatewayTLSResponse{
			Enabled:    h.httpGatewayCtrl.TLSEnabled(),
			BypassList: h.httpGatewayCtrl.BypassList(),
		},
		Targets:    targetJSON,
		SinglePort: true,
	})
}

// handlePutHTTPGatewayTLS updates the TLS inspection configuration.
// PUT /admin/api/v1/security/http-gateway/tls
func (h *AdminAPIHandler) handlePutHTTPGatewayTLS(w http.ResponseWriter, r *http.Request) {
	if h.httpGatewayCtrl == nil {
		h.respondError(w, http.StatusServiceUnavailable, "HTTP Gateway not configured")
		return
	}

	var req httpGatewayTLSRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate bypass_list entries
	if req.BypassList != nil {
		for _, entry := range req.BypassList {
			if strings.TrimSpace(entry) == "" {
				h.respondError(w, http.StatusBadRequest, "bypass_list entries must be non-empty strings")
				return
			}
		}
	}

	// Apply changes
	if req.Enabled != nil {
		h.httpGatewayCtrl.SetTLSEnabled(*req.Enabled)
	}
	if req.BypassList != nil {
		h.httpGatewayCtrl.SetBypassList(req.BypassList)
	}

	// Persist to state.json
	if h.stateStore != nil {
		if err := h.persistTLSInspectionConfig(req); err != nil {
			h.logger.Error("failed to persist TLS inspection config", "error", err)
		}
	}

	enabled := h.httpGatewayCtrl.TLSEnabled()
	bypassList := h.httpGatewayCtrl.BypassList()

	h.logger.Info("TLS inspection configuration updated",
		"enabled", enabled,
		"bypass_domains", len(bypassList),
	)

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"tls_inspection": httpGatewayTLSResponse{
			Enabled:    enabled,
			BypassList: bypassList,
		},
		"message": "TLS inspection configuration updated",
	})
}

// persistTLSInspectionConfig saves the TLS inspection config to state.json.
func (h *AdminAPIHandler) persistTLSInspectionConfig(req httpGatewayTLSRequest) error {
	appState, err := h.stateStore.Load()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	if appState.TLSInspectionConfig == nil {
		appState.TLSInspectionConfig = &state.TLSInspectionState{}
	}

	if req.Enabled != nil {
		appState.TLSInspectionConfig.Enabled = *req.Enabled
	}
	if req.BypassList != nil {
		appState.TLSInspectionConfig.BypassList = req.BypassList
	}
	appState.TLSInspectionConfig.UpdatedAt = now

	return h.stateStore.Save(appState)
}

// handleGetCACert downloads the CA certificate as a PEM file.
// GET /admin/api/v1/security/http-gateway/ca-cert
func (h *AdminAPIHandler) handleGetCACert(w http.ResponseWriter, r *http.Request) {
	if h.httpGatewayCtrl == nil {
		h.respondError(w, http.StatusServiceUnavailable, "HTTP Gateway not configured")
		return
	}

	pemBytes := h.httpGatewayCtrl.CACertPEM()
	if len(pemBytes) == 0 {
		h.respondError(w, http.StatusNotFound, "no CA certificate configured (TLS inspection may be disabled)")
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="sentinelgate-ca.pem"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pemBytes)
}

// handleGetSetupScript downloads a proxy configuration setup script.
// GET /admin/api/v1/security/http-gateway/setup-script
func (h *AdminAPIHandler) handleGetSetupScript(w http.ResponseWriter, r *http.Request) {
	if h.httpGatewayCtrl == nil {
		h.respondError(w, http.StatusServiceUnavailable, "HTTP Gateway not configured")
		return
	}

	// Determine the server address from the request
	serverAddr := r.Host
	if serverAddr == "" {
		serverAddr = "localhost:3000"
	}

	script := generateSetupScript(serverAddr)

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Header().Set("Content-Disposition", `attachment; filename="setup-sentinelgate-proxy.sh"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(script))
}

// generateSetupScript creates a shell script for proxy configuration.
func generateSetupScript(serverAddr string) string {
	return fmt.Sprintf(`#!/bin/bash
# SentinelGate Proxy Setup Script
# Generated for server: %s
#
# This script configures your environment to use SentinelGate as an HTTP proxy
# with TLS inspection. It downloads the CA certificate and sets up proxy variables.

set -e

PROXY_HOST="%s"
PROXY_URL="http://${PROXY_HOST}"
CA_CERT_URL="http://${PROXY_HOST}/admin/api/v1/security/http-gateway/ca-cert"
CA_CERT_PATH="${HOME}/.sentinelgate/sentinelgate-ca.pem"

echo "=== SentinelGate Proxy Setup ==="
echo ""

# 1. Download CA certificate
echo "[1/3] Downloading CA certificate..."
mkdir -p "$(dirname "${CA_CERT_PATH}")"
curl -sf "${CA_CERT_URL}" -o "${CA_CERT_PATH}"
echo "  Saved to: ${CA_CERT_PATH}"

# 2. Trust the CA certificate
echo "[2/3] Installing CA certificate..."
if [ "$(uname)" = "Darwin" ]; then
    echo "  macOS detected. To trust the CA cert system-wide, run:"
    echo "    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${CA_CERT_PATH}"
elif [ -d /usr/local/share/ca-certificates ]; then
    echo "  Linux detected (Debian/Ubuntu). To trust the CA cert system-wide, run:"
    echo "    sudo cp ${CA_CERT_PATH} /usr/local/share/ca-certificates/sentinelgate-ca.crt"
    echo "    sudo update-ca-certificates"
elif [ -d /etc/pki/ca-trust/source/anchors ]; then
    echo "  Linux detected (RHEL/CentOS). To trust the CA cert system-wide, run:"
    echo "    sudo cp ${CA_CERT_PATH} /etc/pki/ca-trust/source/anchors/sentinelgate-ca.pem"
    echo "    sudo update-ca-trust"
else
    echo "  Unknown OS. Please manually add ${CA_CERT_PATH} to your system trust store."
fi

# 3. Set proxy environment variables
echo "[3/3] Proxy environment variables:"
echo ""
echo "  Add these to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
echo ""
echo "    export HTTP_PROXY=${PROXY_URL}"
echo "    export HTTPS_PROXY=${PROXY_URL}"
echo "    export NO_PROXY=localhost,127.0.0.1"
echo ""

# Application-specific instructions
echo "=== Application-Specific Setup ==="
echo ""
echo "  Python (requests):"
echo "    export REQUESTS_CA_BUNDLE=${CA_CERT_PATH}"
echo "    # or: requests.get(url, proxies={'http': '${PROXY_URL}', 'https': '${PROXY_URL}'}, verify='${CA_CERT_PATH}')"
echo ""
echo "  Python (httpx):"
echo "    export SSL_CERT_FILE=${CA_CERT_PATH}"
echo ""
echo "  Node.js:"
echo "    export NODE_EXTRA_CA_CERTS=${CA_CERT_PATH}"
echo ""
echo "  curl:"
echo "    curl --proxy ${PROXY_URL} --cacert ${CA_CERT_PATH} https://example.com"
echo ""
echo "=== Setup Complete ==="
`, serverAddr, serverAddr)
}

// handleCreateTarget creates a new upstream target.
// POST /admin/api/v1/security/http-gateway/targets
func (h *AdminAPIHandler) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	if h.httpGatewayCtrl == nil {
		h.respondError(w, http.StatusServiceUnavailable, "HTTP Gateway not configured")
		return
	}

	var req httpGatewayTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate
	if err := validateTargetRequest(req); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Generate ID
	id := uuid.New().String()
	now := time.Now().UTC()

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Persist to state.json
	if h.stateStore != nil {
		appState, err := h.stateStore.Load()
		if err != nil {
			h.respondError(w, http.StatusInternalServerError, "failed to load state")
			return
		}

		entry := state.HTTPGatewayTargetEntry{
			ID:          id,
			Name:        req.Name,
			PathPrefix:  req.PathPrefix,
			Upstream:    req.Upstream,
			StripPrefix: req.StripPrefix,
			Headers:     req.Headers,
			Enabled:     enabled,
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		appState.HTTPGatewayTargets = append(appState.HTTPGatewayTargets, entry)
		if err := h.stateStore.Save(appState); err != nil {
			h.respondError(w, http.StatusInternalServerError, "failed to save state")
			return
		}
	}

	// Update live targets via controller
	newTarget := httpgw.UpstreamTarget{
		ID:          id,
		Name:        req.Name,
		PathPrefix:  req.PathPrefix,
		Upstream:    req.Upstream,
		StripPrefix: req.StripPrefix,
		Headers:     req.Headers,
		Enabled:     enabled,
	}
	allTargets := append(h.httpGatewayCtrl.Targets(), newTarget)
	h.httpGatewayCtrl.SetTargets(allTargets)

	h.logger.Info("HTTP Gateway target created", "id", id, "name", req.Name, "path_prefix", req.PathPrefix)

	h.respondJSON(w, http.StatusCreated, httpGatewayTargetJSON{
		ID:          id,
		Name:        req.Name,
		PathPrefix:  req.PathPrefix,
		Upstream:    req.Upstream,
		StripPrefix: req.StripPrefix,
		Headers:     req.Headers,
		Enabled:     enabled,
	})
}

// handleUpdateTarget updates an existing upstream target.
// PUT /admin/api/v1/security/http-gateway/targets/{id}
func (h *AdminAPIHandler) handleUpdateTarget(w http.ResponseWriter, r *http.Request) {
	if h.httpGatewayCtrl == nil {
		h.respondError(w, http.StatusServiceUnavailable, "HTTP Gateway not configured")
		return
	}

	id := h.pathParam(r, "id")

	var req httpGatewayTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if err := validateTargetRequest(req); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	now := time.Now().UTC()

	// Update in state.json
	if h.stateStore != nil {
		appState, err := h.stateStore.Load()
		if err != nil {
			h.respondError(w, http.StatusInternalServerError, "failed to load state")
			return
		}

		found := false
		for i := range appState.HTTPGatewayTargets {
			if appState.HTTPGatewayTargets[i].ID == id {
				appState.HTTPGatewayTargets[i].Name = req.Name
				appState.HTTPGatewayTargets[i].PathPrefix = req.PathPrefix
				appState.HTTPGatewayTargets[i].Upstream = req.Upstream
				appState.HTTPGatewayTargets[i].StripPrefix = req.StripPrefix
				appState.HTTPGatewayTargets[i].Headers = req.Headers
				if req.Enabled != nil {
					appState.HTTPGatewayTargets[i].Enabled = *req.Enabled
				}
				appState.HTTPGatewayTargets[i].UpdatedAt = now
				found = true
				break
			}
		}

		if !found {
			h.respondError(w, http.StatusNotFound, "target not found")
			return
		}

		if err := h.stateStore.Save(appState); err != nil {
			h.respondError(w, http.StatusInternalServerError, "failed to save state")
			return
		}
	}

	// Update live targets via controller
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	targets := h.httpGatewayCtrl.Targets()
	found := false
	for i := range targets {
		if targets[i].ID == id {
			targets[i].Name = req.Name
			targets[i].PathPrefix = req.PathPrefix
			targets[i].Upstream = req.Upstream
			targets[i].StripPrefix = req.StripPrefix
			targets[i].Headers = req.Headers
			targets[i].Enabled = enabled
			found = true
			break
		}
	}

	if !found {
		h.respondError(w, http.StatusNotFound, "target not found")
		return
	}

	h.httpGatewayCtrl.SetTargets(targets)

	h.logger.Info("HTTP Gateway target updated", "id", id, "name", req.Name)

	h.respondJSON(w, http.StatusOK, httpGatewayTargetJSON{
		ID:          id,
		Name:        req.Name,
		PathPrefix:  req.PathPrefix,
		Upstream:    req.Upstream,
		StripPrefix: req.StripPrefix,
		Headers:     req.Headers,
		Enabled:     enabled,
	})
}

// handleDeleteTarget removes an upstream target.
// DELETE /admin/api/v1/security/http-gateway/targets/{id}
func (h *AdminAPIHandler) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	if h.httpGatewayCtrl == nil {
		h.respondError(w, http.StatusServiceUnavailable, "HTTP Gateway not configured")
		return
	}

	id := h.pathParam(r, "id")

	// Remove from state.json
	if h.stateStore != nil {
		appState, err := h.stateStore.Load()
		if err != nil {
			h.respondError(w, http.StatusInternalServerError, "failed to load state")
			return
		}

		found := false
		newTargets := make([]state.HTTPGatewayTargetEntry, 0, len(appState.HTTPGatewayTargets))
		for _, t := range appState.HTTPGatewayTargets {
			if t.ID == id {
				found = true
				continue
			}
			newTargets = append(newTargets, t)
		}

		if !found {
			h.respondError(w, http.StatusNotFound, "target not found")
			return
		}

		appState.HTTPGatewayTargets = newTargets
		if err := h.stateStore.Save(appState); err != nil {
			h.respondError(w, http.StatusInternalServerError, "failed to save state")
			return
		}
	}

	// Remove from live targets via controller
	targets := h.httpGatewayCtrl.Targets()
	newTargets := make([]httpgw.UpstreamTarget, 0, len(targets))
	for _, t := range targets {
		if t.ID == id {
			continue
		}
		newTargets = append(newTargets, t)
	}
	h.httpGatewayCtrl.SetTargets(newTargets)

	h.logger.Info("HTTP Gateway target deleted", "id", id)

	h.respondJSON(w, http.StatusOK, map[string]string{
		"message": "target deleted",
	})
}

// validateTargetRequest validates a target create/update request.
func validateTargetRequest(req httpGatewayTargetRequest) error {
	if strings.TrimSpace(req.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if !strings.HasPrefix(req.PathPrefix, "/") {
		return fmt.Errorf("path_prefix must start with /")
	}
	if _, err := url.Parse(req.Upstream); err != nil || req.Upstream == "" {
		return fmt.Errorf("upstream must be a valid URL")
	}
	if !strings.HasPrefix(req.Upstream, "http://") && !strings.HasPrefix(req.Upstream, "https://") {
		return fmt.Errorf("upstream must start with http:// or https://")
	}
	return nil
}
