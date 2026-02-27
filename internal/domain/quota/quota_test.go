package quota

import (
	"testing"
)

func TestQuotaConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  QuotaConfig
		wantErr bool
	}{
		{
			name: "valid config with max calls",
			config: QuotaConfig{
				IdentityID:         "id-1",
				MaxCallsPerSession: 100,
				Action:             QuotaActionDeny,
				Enabled:            true,
			},
			wantErr: false,
		},
		{
			name: "valid config with multiple limits",
			config: QuotaConfig{
				IdentityID:          "id-1",
				MaxCallsPerSession:  100,
				MaxWritesPerSession: 50,
				MaxCallsPerMinute:   10,
				Action:              QuotaActionWarn,
				Enabled:             true,
			},
			wantErr: false,
		},
		{
			name: "valid disabled config (no limits required)",
			config: QuotaConfig{
				IdentityID: "id-1",
				Action:     QuotaActionDeny,
				Enabled:    false,
			},
			wantErr: false,
		},
		{
			name: "invalid — missing identity ID",
			config: QuotaConfig{
				MaxCallsPerSession: 100,
				Action:             QuotaActionDeny,
				Enabled:            true,
			},
			wantErr: true,
		},
		{
			name: "invalid — no limits set when enabled",
			config: QuotaConfig{
				IdentityID: "id-1",
				Action:     QuotaActionDeny,
				Enabled:    true,
			},
			wantErr: true,
		},
		{
			name: "invalid — bad action",
			config: QuotaConfig{
				IdentityID:         "id-1",
				MaxCallsPerSession: 100,
				Action:             "invalid",
				Enabled:            true,
			},
			wantErr: true,
		},
		{
			name: "valid config with tool limits only",
			config: QuotaConfig{
				IdentityID: "id-1",
				ToolLimits: map[string]int64{"write_file": 10},
				Action:     QuotaActionDeny,
				Enabled:    true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
