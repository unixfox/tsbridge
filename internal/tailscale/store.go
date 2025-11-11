// Package tailscale manages Tailscale server instances and lifecycle.
package tailscale

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/jtdowney/tsbridge/internal/config"
	tserrors "github.com/jtdowney/tsbridge/internal/errors"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/ipn/store/kubestore"
	"tailscale.com/types/logger"
)

// createStateStore creates an appropriate ipn.StateStore based on the configuration.
// It supports file (default), mem (in-memory), kube (Kubernetes Secret), and arn (AWS SSM) stores.
func createStateStore(cfg config.Tailscale, serviceName string, ephemeral bool) (ipn.StateStore, error) {
	// Determine the store type
	storeType := cfg.StoreType
	if storeType == "" {
		storeType = "file" // default to file store
	}

	slog.Debug("creating state store",
		"service", serviceName,
		"store_type", storeType,
		"ephemeral", ephemeral,
	)

	// Create the logger function for store creation
	logf := func(format string, args ...any) {
		slog.Debug(fmt.Sprintf(format, args...),
			"service", serviceName,
			"store_type", storeType,
		)
	}

	var stateStore ipn.StateStore
	var err error

	switch storeType {
	case "mem":
		// Memory store - only allowed for ephemeral nodes
		if !ephemeral {
			return nil, tserrors.NewConfigError("in-memory store (store_type='mem') can only be used with ephemeral services")
		}
		// Use the store.New function with "mem:" prefix
		stateStore, err = store.New(logf, "mem:")
		if err != nil {
			return nil, tserrors.WrapConfig(err, "creating memory store")
		}
		slog.Debug("created memory state store", "service", serviceName)

	case "kube":
		// Kubernetes Secret store
		// Each service gets its own secret named: <store_config>-<service_name>
		// If store_config is empty, use "tsbridge" as the prefix
		prefix := cfg.StoreConfig
		if prefix == "" {
			prefix = "tsbridge"
		}
		secretName := fmt.Sprintf("%s-%s", prefix, serviceName)
		
		// Use kubestore.New directly (like tailscale-ingress-controller)
		stateStore, err = kubestore.New(logf, secretName)
		if err != nil {
			return nil, tserrors.WrapConfig(err, fmt.Sprintf("creating Kubernetes store with secret %q", secretName))
		}
		slog.Info("created Kubernetes state store",
			"service", serviceName,
			"secret_name", secretName,
		)

	case "arn":
		// AWS SSM Parameter Store
		if cfg.StoreConfig == "" {
			return nil, tserrors.NewConfigError("store_config (AWS SSM parameter ARN) is required when store_type is 'arn'")
		}
		if !strings.HasPrefix(cfg.StoreConfig, "arn:") {
			return nil, tserrors.NewConfigError(fmt.Sprintf("store_config must be a valid ARN starting with 'arn:' when store_type is 'arn', got: %q", cfg.StoreConfig))
		}
		// Use the store.New function with the ARN directly
		stateStore, err = store.New(logf, cfg.StoreConfig)
		if err != nil {
			return nil, tserrors.WrapConfig(err, fmt.Sprintf("creating AWS store with ARN %q", cfg.StoreConfig))
		}
		slog.Info("created AWS SSM state store",
			"service", serviceName,
			"arn", cfg.StoreConfig,
		)

	case "file":
		// File store is handled separately in the tailscale package
		// because it needs the service-specific state directory
		// Return nil to indicate file store should be used (default behavior)
		return nil, nil

	default:
		return nil, tserrors.NewConfigError(fmt.Sprintf("unknown store_type %q: must be one of 'file', 'mem', 'kube', or 'arn'", storeType))
	}

	return stateStore, nil
}

// Ensure we're using the correct logger type
var _ logger.Logf = func(string, ...any) {}
