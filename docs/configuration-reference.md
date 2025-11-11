# Configuration Reference

Complete reference for all tsbridge configuration options.

## Configuration Structure

```toml
[tailscale]
# Tailscale authentication and settings

[global]
# Default settings for all services

[[services]]
# Service definitions (multiple allowed)
```

## [tailscale] Section

### Authentication

You must provide either OAuth credentials OR an auth key.

> **Resolution Order**: tsbridge resolves secret values in the following priority order:
>
> 1. **Direct value** (inline in config file)
> 2. **File** (from `_file` suffix)
> 3. **Environment variable** (from `_env` suffix)
> 4. **Default environment variable** (e.g., `TS_OAUTH_CLIENT_ID`, `TS_OAUTH_CLIENT_SECRET`, `TS_AUTHKEY`)
>
> If any configured source (file or env var) is specified but cannot be accessed or is empty, tsbridge will return an error instead of falling back to the next priority level.

#### OAuth Credentials

```toml
# Client ID - choose one method:
oauth_client_id = "k12...89"                      # Direct value (highest priority)
oauth_client_id_file = "/etc/tsbridge/oauth-id"   # From file (second priority)
oauth_client_id_env = "TS_OAUTH_CLIENT_ID"        # From environment variable (third priority)
# Will fallback to TS_OAUTH_CLIENT_ID env var if none of the above are specified

# Client Secret - choose one method:
oauth_client_secret = "tskey-client-..."                   # Direct value (highest priority)
oauth_client_secret_file = "/etc/tsbridge/oauth-secret"    # From file (second priority)
oauth_client_secret_env = "TS_OAUTH_CLIENT_SECRET"         # From environment variable (third priority)
# Will fallback to TS_OAUTH_CLIENT_SECRET env var if none of the above are specified
```

#### Auth Key (Alternative)

```toml
# Auth key - choose one method:
auth_key = "tskey-auth-..."              # Direct value (highest priority)
auth_key_file = "/etc/tsbridge/authkey"  # From file (second priority)
auth_key_env = "TS_AUTHKEY"              # From environment variable (third priority)
# Will fallback to TS_AUTHKEY env var if none of the above are specified
```

### Other Tailscale Options

```toml
# State directory for tsnet data (file store only)
state_dir = "/var/lib/tsbridge"          # Direct path
state_dir_env = "CUSTOM_STATE_DIR"       # From environment variable

# State store type (optional - defaults to "file")
store_type = "file"  # Options: "file", "mem", "kube", "arn"

# Store-specific configuration (required for non-file stores)
store_config = ""  # See examples below

# Default tags for all services (required when using OAuth)
default_tags = ["tag:server", "tag:proxy"]

# Control server URL (for Headscale or custom servers)
control_url = "https://headscale.example.com"

# Preauthorize OAuth-generated auth keys (optional - defaults to true)
# Set to false to require manual approval of devices in the admin console
# Can be overridden per-service: set [[services]].oauth_preauthorized = false
# Breaking change: Default is now true; set to false if you require manual approval.
oauth_preauthorized = false
```

### State Storage Backends

tsbridge supports multiple state storage backends for persisting Tailscale node state:

#### File Store (Default)

Stores state in local files on the filesystem. Each service gets its own subdirectory.

```toml
[tailscale]
state_dir = "/var/lib/tsbridge"  # Base directory for all service state
store_type = "file"              # Optional - file is the default
```

State files are stored at: `{state_dir}/{service_name}/tailscaled.state`

#### Memory Store

Stores state in memory only. **Only supported for ephemeral services** - state is lost when the process restarts.

```toml
[tailscale]
store_type = "mem"

[[services]]
name = "temp-service"
backend_addr = "localhost:8080"
ephemeral = true  # Required when using mem store
```

#### Kubernetes Secret Store

Stores state in Kubernetes Secrets. Ideal for running tsbridge in Kubernetes.

```toml
[tailscale]
store_type = "kube"
store_config = "tsbridge-state"  # Secret name prefix (optional, defaults to "tsbridge")
```

Each service gets its own Secret with the naming pattern: `<prefix>-<service_name>`

Examples:
- With `store_config = "tsbridge-state"` and service `api`: Secret name is `tsbridge-state-api`
- With `store_config = "myapp"` and service `postgres`: Secret name is `myapp-postgres`
- With no `store_config` (or empty) and service `web`: Secret name is `tsbridge-web`

Requirements:
- Must run in a Kubernetes pod
- Service account must have permissions to read/write Secrets in the namespace
- Secrets will be created automatically if they don't exist

##### Kubernetes Deployment Example

Complete example with ServiceAccount, RBAC, and Deployment:

```yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tsbridge
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: tsbridge
  namespace: default
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: tsbridge
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: tsbridge
subjects:
- kind: ServiceAccount
  name: tsbridge
  namespace: default
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: tsbridge-config
  namespace: default
data:
  tsbridge.toml: |
    [tailscale]
    oauth_client_id_env = "TS_OAUTH_CLIENT_ID"
    oauth_client_secret_env = "TS_OAUTH_CLIENT_SECRET"
    store_type = "kube"
    store_config = "tsbridge-state"
    default_tags = ["tag:server"]
    
    [global]
    metrics_addr = ":9090"
    
    [[services]]
    name = "api"
    backend_addr = "localhost:8080"
---
apiVersion: v1
kind: Secret
metadata:
  name: tsbridge-oauth
  namespace: default
type: Opaque
stringData:
  TS_OAUTH_CLIENT_ID: "your-oauth-client-id"
  TS_OAUTH_CLIENT_SECRET: "your-oauth-client-secret"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tsbridge
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tsbridge
  template:
    metadata:
      labels:
        app: tsbridge
    spec:
      serviceAccountName: tsbridge
      containers:
      - name: tsbridge
        image: unixfox/tsbridge:latest
        args:
        - "-config"
        - "/etc/tsbridge/tsbridge.toml"
        envFrom:
        - secretRef:
            name: tsbridge-oauth
        ports:
        - name: metrics
          containerPort: 9090
          protocol: TCP
        volumeMounts:
        - name: config
          mountPath: /etc/tsbridge
          readOnly: true
        securityContext:
          runAsNonRoot: true
          runAsUser: 65532
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
      volumes:
      - name: config
        configMap:
          name: tsbridge-config
```

**Important Notes:**
- The ServiceAccount needs `get`, `list`, `create`, `update`, and `patch` permissions on Secrets
- Each service defined in the config will create its own Secret (e.g., `tsbridge-state-api`)
- Store OAuth credentials in a Kubernetes Secret and reference via environment variables
- Use a ConfigMap for the tsbridge.toml configuration file
- The deployment runs as non-root user 65532 for security

#### AWS SSM Parameter Store

Stores state in AWS Systems Manager Parameter Store. Ideal for cloud deployments.

```toml
[tailscale]
store_type = "arn"
store_config = "arn:aws:ssm:us-east-1:123456789:parameter/tsbridge/state"
```

Optional: Add KMS encryption key:
```toml
store_config = "arn:aws:ssm:us-east-1:123456789:parameter/tsbridge/state?kmsKey=alias/my-key"
```

Requirements:
- IAM permissions for `ssm:GetParameter` and `ssm:PutParameter`
- If using KMS: permission for `kms:Decrypt` and `kms:Encrypt`
- The parameter will be created automatically with Intelligent Tiering

**Note**: AWS store has an 8KB size limit. If state exceeds this, new state will only be stored in memory and restarts may fail until you delete the parameter.

#### Important Notes

- **File store** (`store_type = "file"`): Compatible with `state_dir` setting
- **Other stores**: Do not use `state_dir` with `mem`, `kube`, or `arn` stores
- **Ephemeral services**: Memory store (`mem`) can only be used with `ephemeral = true`
- **Per-service isolation**: Each service maintains its own state regardless of store type


### Tag Ownership and OAuth Security

tsbridge supports Tailscale's tag ownership model for enhanced security. This allows an OAuth client with a parent tag to manage multiple service tags through a permission hierarchy.

#### Setting Up Tag Ownership

Configure tag ownership in your Tailscale ACL policy:

```jsonc
{
  "tagOwners": {
    "tag:tsbridge": [], // Parent tag for OAuth client
    "tag:server": ["tag:tsbridge"],
    "tag:proxy": ["tag:tsbridge"],
    "tag:prod": ["tag:tsbridge"],
    "tag:dev": ["tag:tsbridge"]
  }
}
```

In this configuration:

- `tag:tsbridge` is the parent tag for the OAuth client
- `tag:server`, `tag:proxy`, `tag:prod`, and `tag:dev` are service tags owned by `tag:tsbridge`

#### Creating the OAuth Client

1. Go to **Settings** → **OAuth clients** in Tailscale admin console
2. Click **Generate OAuth client...**
3. Configure:
   - **Scopes**: Check both **Read** and **Write** under **Auth Keys**
   - **Tags**: Select `tag:tsbridge` (the parent tag, NOT the service tags)
4. Save the credentials

**Important**: Select only the parent tag for the OAuth client. This grants permission to create auth keys for all tags it owns.

#### Using Tag Hierarchies in tsbridge

```toml
[tailscale]
oauth_client_id_env = "TS_OAUTH_CLIENT_ID"
oauth_client_secret_env = "TS_OAUTH_CLIENT_SECRET"
# These tags must be owned by tag:tsbridge in your ACL
default_tags = ["tag:server", "tag:proxy"]

[[services]]
name = "api"
backend_addr = "localhost:8080"
tags = ["tag:server", "tag:prod"]  # Both owned by tag:tsbridge
```

This approach provides centralized permission management while maintaining clear security boundaries between services.

## [global] Section

All settings here provide defaults that can be overridden per-service.

### Timeouts

All timeouts use Go duration format (`"30s"`, `"5m"`, `"1h30m"`). Set to `"0s"` to disable.

```toml
# Server timeouts
read_header_timeout = "30s"      # Time to read request headers (default: 30s)
write_timeout = "30s"            # Time to write response (default: 30s)
idle_timeout = "120s"            # Keep-alive timeout (default: 120s)
shutdown_timeout = "15s"         # Graceful shutdown timeout (default: 15s)

# Backend connection timeouts
dial_timeout = "30s"                   # Time to establish connection (default: 30s)
response_header_timeout = "0s"         # Time to wait for backend headers (default: 0s = no timeout)
keep_alive_timeout = "30s"             # Keep-alive probe interval (default: 30s)
idle_conn_timeout = "90s"              # Idle connection timeout (default: 90s)
tls_handshake_timeout = "10s"          # TLS handshake timeout (default: 10s)
expect_continue_timeout = "1s"         # 100-continue timeout (default: 1s)

# Metrics endpoint timeout
metrics_read_header_timeout = "5s"     # Header read timeout for metrics (default: 5s)
```

### Response Handling

```toml
# Flush interval for response buffering - choose one:
flush_interval = "0s"        # Default buffering (default)
# flush_interval = "-1ms"    # Immediate flushing (for streaming)
# flush_interval = "100ms"   # Flush every 100ms

# Request body size limit - choose one:
max_request_body_size = "52428800"  # In bytes (default: 50MB)
# max_request_body_size = "10MB"    # Human readable format
# max_request_body_size = "-1"      # No limit
```

### Observability

```toml
# Prometheus metrics endpoint
metrics_addr = ":9090"     # Listen address (empty to disable)

# Access logging
access_log = true          # Enable/disable (default: true)
```

### Security

```toml
# Trusted proxy IPs for X-Forwarded-For handling
# Supports both CIDR ranges and individual IPs
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12", "192.168.1.1"]
```

## [[services]] Section

Each service requires `name` and `backend_addr`. All global settings can be overridden.

### Basic Configuration

```toml
[[services]]
name = "api"                           # Required: becomes api.<tailnet>.ts.net
backend_addr = "localhost:8080"        # Required: where to proxy to
tags = ["tag:api", "tag:prod"]         # Service tags (overrides default_tags)
```

### Backend Address Formats

```toml
# TCP addresses
backend_addr = "localhost:8080"
# backend_addr = "10.0.0.5:3000"
# backend_addr = "backend.internal:80"

# HTTPS backends
# backend_addr = "https://api.example.com:443"
# backend_addr = "https://self-signed.internal"
# insecure_skip_verify = true    # Skip TLS certificate verification (default: false)

# Unix sockets
# backend_addr = "unix:///var/run/app.sock"
```

### TLS Configuration

For HTTPS backends, you can control TLS certificate verification:

```toml
[[services]]
name = "self-signed-api"
backend_addr = "https://internal-service.lan:8443"
insecure_skip_verify = true    # Skip TLS certificate verification
```

> **⚠️ Security Warning**: Setting `insecure_skip_verify = true` disables TLS certificate validation, making connections vulnerable to man-in-the-middle attacks. Only use this for trusted internal services with self-signed certificates. A warning will be logged when this option is enabled.

### Network Options

```toml
# TLS mode
# Accepted values: "auto" (default), "off"
# - "auto": Use Tailscale HTTPS with automatic certificates
# - "off":  Serve HTTP only (transport still encrypted over WireGuard)
tls_mode = "auto"

# Listening configuration
listen_addr = "0.0.0.0:8443"  # Listen on specific address and port (default: ":443" for TLS, ":80" for non-TLS)
```

### Tailscale Features

```toml
# Whois identity headers
whois_enabled = true       # Add X-Tailscale-User headers (default: false)
whois_timeout = "1s"       # Whois lookup timeout (default: from global or 1s)

# Funnel (public access)
funnel_enabled = true      # Expose to internet via Funnel (default: false)

# Ephemeral nodes
ephemeral = true           # Don't persist node state (default: false)
```

### Header Manipulation

```toml
# Add headers to requests going to backend
upstream_headers = {
  "X-Service-Name" = "tsbridge",
  "X-Request-ID" = "generated"
}

# Add headers to responses going to client
downstream_headers = {
  "Strict-Transport-Security" = "max-age=31536000",
  "X-Frame-Options" = "DENY"
}

# Remove headers from requests
# (array in TOML, comma-separated string when set via Docker labels)
remove_upstream = ["Cookie", "Authorization"]

# Remove headers from responses
# (array in TOML, comma-separated string when set via Docker labels)
remove_downstream = ["Server", "X-Powered-By"]
```

### Service-Specific Overrides

Any global setting can be overridden:

```toml
[[services]]
name = "streaming"
backend_addr = "localhost:8080"

# Override timeouts
write_timeout = "0s"              # No timeout for streaming
response_header_timeout = "30s"   # Different from global
flush_interval = "-1ms"           # Immediate flushing

# Override other settings
access_log = false                # Disable for this service
max_request_body_size = "100MB"   # Larger uploads allowed
```

## Environment Variables

Default environment variables checked if no config specified:

- `TS_OAUTH_CLIENT_ID` - OAuth client ID
- `TS_OAUTH_CLIENT_SECRET` - OAuth client secret
- `TS_AUTHKEY` - Auth key
- `STATE_DIRECTORY` - State directory (systemd)
- `TSBRIDGE_STATE_DIR` - State directory

## Secret Resolution

tsbridge resolves secrets using different modes based on what you specify:

**Direct mode** (when you set a value directly):

```toml
oauth_client_id = "k12...89"  # This value is used
```

**Environment variable mode** (when you use `_env`):

```toml
oauth_client_id_env = "MY_CUSTOM_VAR"  # Reads from MY_CUSTOM_VAR
# Must be set; if unset or empty, tsbridge returns an error.
# Fallback to TS_OAUTH_CLIENT_ID is used only when no oauth_client_id/_env/_file is configured at all.
```

**File mode** (when you use `_file`):

```toml
oauth_client_id_file = "/path/to/file"  # Reads from file
# Must be readable; if missing or unreadable, tsbridge returns an error.
# Fallback to TS_OAUTH_CLIENT_ID is used only when no oauth_client_id/_env/_file is configured at all.
```

**Important**: If you specify `_env` or `_file`, any direct value is ignored. You cannot mix modes.

**Override**: Environment variables prefixed with `TSBRIDGE_` can override any configuration:

- `TSBRIDGE_TAILSCALE_OAUTH_CLIENT_ID` overrides `tailscale.oauth_client_id`
- `TSBRIDGE_GLOBAL_METRICS_ADDR` overrides `global.metrics_addr`

## Configuration Validation

Run with `-validate` flag to check configuration:

```bash
tsbridge -config tsbridge.toml -validate
```

Validates:

- Required fields present
- No duplicate service names
- Valid duration formats
- Valid addresses
- File permissions for secrets
- Authentication configured
- Services have tags (when using OAuth)

## Complete Example

```toml
[tailscale]
oauth_client_id_env = "TS_OAUTH_CLIENT_ID"
oauth_client_secret_file = "/etc/tsbridge/oauth-secret"
state_dir = "/var/lib/tsbridge"
default_tags = ["tag:server", "tag:proxy"]

[global]
# Timeouts
read_header_timeout = "30s"
write_timeout = "30s"
idle_timeout = "120s"
shutdown_timeout = "30s"

# Backend connection
dial_timeout = "10s"
response_header_timeout = "0s"

# Observability
metrics_addr = ":9090"
access_log = true

# Security
trusted_proxies = ["10.0.0.0/8"]

# Limits
max_request_body_size = "50MB"

[[services]]
name = "api"
backend_addr = "api.internal:8080"
tags = ["tag:api", "tag:prod"]
whois_enabled = true
downstream_headers = {
  "Strict-Transport-Security" = "max-age=63072000"
}

[[services]]
name = "streaming"
backend_addr = "localhost:4000"
write_timeout = "0s"
flush_interval = "-1ms"
max_request_body_size = "-1"

[[services]]
name = "admin"
backend_addr = "unix:///var/run/admin.sock"
whois_enabled = true
funnel_enabled = false
access_log = true
```
