package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateStoreConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "default file store",
			config: Config{
				Tailscale: Tailscale{
					StateDir: "/var/lib/tsbridge",
				},
			},
			wantErr: false,
		},
		{
			name: "explicit file store",
			config: Config{
				Tailscale: Tailscale{
					StateDir:  "/var/lib/tsbridge",
					StoreType: "file",
				},
			},
			wantErr: false,
		},
		{
			name: "memory store without config",
			config: Config{
				Tailscale: Tailscale{
					StoreType: "mem",
				},
			},
			wantErr: false,
		},
		{
			name: "memory store with unnecessary config",
			config: Config{
				Tailscale: Tailscale{
					StoreType:   "mem",
					StoreConfig: "should-not-be-set",
				},
			},
			wantErr: true,
			errMsg:  "store_config is not used with store_type 'mem'",
		},
		{
			name: "kube store without config",
			config: Config{
				Tailscale: Tailscale{
					StoreType: "kube",
				},
			},
			wantErr: true,
			errMsg:  "store_config (Kubernetes secret name) is required when store_type is 'kube'",
		},
		{
			name: "kube store with config",
			config: Config{
				Tailscale: Tailscale{
					StoreType:   "kube",
					StoreConfig: "tsbridge-state",
				},
			},
			wantErr: false,
		},
		{
			name: "arn store without config",
			config: Config{
				Tailscale: Tailscale{
					StoreType: "arn",
				},
			},
			wantErr: true,
			errMsg:  "store_config (AWS SSM parameter ARN) is required when store_type is 'arn'",
		},
		{
			name: "arn store with invalid ARN",
			config: Config{
				Tailscale: Tailscale{
					StoreType:   "arn",
					StoreConfig: "not-an-arn",
				},
			},
			wantErr: true,
			errMsg:  "store_config must be a valid ARN starting with 'arn:'",
		},
		{
			name: "arn store with valid ARN",
			config: Config{
				Tailscale: Tailscale{
					StoreType:   "arn",
					StoreConfig: "arn:aws:ssm:us-east-1:123456789:parameter/tsbridge/state",
				},
			},
			wantErr: false,
		},
		{
			name: "arn store with ARN and KMS key",
			config: Config{
				Tailscale: Tailscale{
					StoreType:   "arn",
					StoreConfig: "arn:aws:ssm:us-east-1:123456789:parameter/tsbridge/state?kmsKey=alias/my-key",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid store type",
			config: Config{
				Tailscale: Tailscale{
					StoreType: "invalid",
				},
			},
			wantErr: true,
			errMsg:  "invalid store_type \"invalid\": must be one of 'file', 'mem', 'kube', or 'arn'",
		},
		{
			name: "state_dir with mem store",
			config: Config{
				Tailscale: Tailscale{
					StoreType: "mem",
					StateDir:  "/var/lib/tsbridge",
				},
			},
			wantErr: true,
			errMsg:  "state_dir cannot be used with store_type \"mem\"",
		},
		{
			name: "state_dir with kube store",
			config: Config{
				Tailscale: Tailscale{
					StoreType:   "kube",
					StoreConfig: "tsbridge-state",
					StateDir:    "/var/lib/tsbridge",
				},
			},
			wantErr: true,
			errMsg:  "state_dir cannot be used with store_type \"kube\"",
		},
		{
			name: "state_dir with arn store",
			config: Config{
				Tailscale: Tailscale{
					StoreType:   "arn",
					StoreConfig: "arn:aws:ssm:us-east-1:123456789:parameter/tsbridge/state",
					StateDir:    "/var/lib/tsbridge",
				},
			},
			wantErr: true,
			errMsg:  "state_dir cannot be used with store_type \"arn\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validateStoreConfig()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
