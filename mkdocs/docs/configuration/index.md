# Configuration Guide

ionscale uses a flexible YAML-based configuration system that supports environment variable substitution and sensible defaults. This guide explains how to configure your ionscale instance.

## Configuration File Format

ionscale uses YAML for its configuration files. Here's a basic example:

```yaml
# Server network configuration
listen_addr: ":8080"
public_addr: "ionscale.example.com:443"
stun_listen_addr: ":3478"
stun_public_addr: "ionscale.example.com:3478"

# TLS configuration
tls:
  disable: false
  force_https: true
  cert_file: /etc/ionscale/cert.pem
  key_file: /etc/ionscale/key.pem

# Database configuration
database:
  type: postgres
  url: postgres://user:password@localhost:5432/ionscale
```

## Loading Configuration

When starting ionscale, you can specify a configuration file using the `--config` or `-c` flag:

```bash
ionscale server --config /etc/ionscale/config.yaml
```

If no configuration file is provided, ionscale will use its default values.

## Environment Variable Support

ionscale supports two ways to use environment variables in configuration:

### 1. Direct Configuration via Environment Variables

You can provide the entire configuration as a base64-encoded string using the `IONSCALE_CONFIG_BASE64` environment variable. This is useful for containerized deployments where you want to inject configuration without mounting files.

```bash
# Create base64-encoded config
CONFIG_B64=$(cat config.yaml | base64 -w0)

# Run ionscale with environment config
IONSCALE_CONFIG_BASE64=$CONFIG_B64 ionscale server
```

### 2. Variable Substitution in YAML Files

You can reference environment variables directly in your YAML configuration files using:

- `${VAR}` syntax for required variables
- `${VAR:default}` syntax for variables with default values

For example:

```yaml
database:
  type: ${DB_TYPE:sqlite}
  url: ${DB_URL}
  max_open_conns: ${DB_MAX_OPEN_CONNS:10}
```

In this example:
- `DB_TYPE` has a default value of "sqlite" if the environment variable is not set
- `DB_URL` is required and must be set in the environment
- `DB_MAX_OPEN_CONNS` defaults to 10 if not set

If a required variable is missing, the configuration loading will fail with an error.

## Default Configuration

If no configuration file is provided, ionscale uses these default values:

```yaml
listen_addr: ":8080"
metrics_listen_addr: ":9091"
stun_listen_addr: ":3478"

database:
  type: sqlite
  url: ./ionscale.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)
  max_idle_conns: 2

poll_net:
  keep_alive_interval: 1m

dns:
  magic_dns_suffix: ionscale.net

derp:
  server:
    disabled: false
    region_id: 1000
    region_code: ionscale
    region_name: ionscale Embedded DERP

logging:
  level: info
```

## Configuration Sections

### Server Network Configuration

Controls the network interfaces and addresses:

```yaml
# The HTTP(S) listen address for the control plane
listen_addr: ":8080"

# The metrics listen address (for Prometheus)
metrics_listen_addr: ":9091"

# The STUN listen address when using the embedded DERP
stun_listen_addr: ":3478"

# The DNS name of the server HTTP(S) endpoint as accessible by clients
public_addr: "ionscale.example.com:443"

# The DNS name of the STUN endpoint as accessible by clients
stun_public_addr: "ionscale.example.com:3478"
```

### TLS Configuration

Controls HTTPS and certificate usage:

```yaml
tls:
  # Disable TLS (not recommended for production)
  disable: false
  
  # Force HTTPS redirect
  force_https: true
  
  # Path to certificate files (when not using ACME)
  cert_file: /etc/ionscale/cert.pem
  key_file: /etc/ionscale/key.pem
  
  # Let's Encrypt ACME configuration
  acme: true
  acme_email: admin@example.com
  acme_ca: https://acme-v02.api.letsencrypt.org/directory
```

### Database Configuration

Controls the database storage:

```yaml
database:
  # Database type: sqlite or postgres
  type: postgres
  
  # Database connection URL
  url: postgres://user:password@localhost:5432/ionscale
  
  # Connection pool settings
  max_open_conns: 10
  max_idle_conns: 5
  conn_max_life_time: 5m
  conn_max_idle_time: 5m
```

### OIDC Configuration

Controls OpenID Connect authentication providers and admin access:

```yaml
auth:
  # OIDC provider configuration
  provider:
    issuer: https://auth.example.com
    client_id: client_id
    client_secret: client_secret
    additional_scopes: ["profile", "email"]
  
  # System administrators configuration
  system_admins:
    emails: ["admin@example.com"]
    subs: ["subject123"]
    filters: ["domain == example.com"]

  # Organization-scoped tailnets (optional)
  # When a claim is configured, every OIDC login is resolved to a single
  # organization and a tailnet bound to an organization is only ever offered
  # to identities of that same organization, regardless of its IAM policy.
  # The boundary cuts both ways: an identity carrying an organization only
  # sees its organization's tailnets, so a membership maps to exactly one
  # tailnet and interactive logins complete without a tailnet picker. Logins
  # from an organization without a tailnet are refused; tailnets are never
  # created implicitly at login — provision them through the API/CLI when an
  # organization is created.
  organizations:
    # OIDC claim (id_token first, then userinfo) holding the organization
    # identifier; setting it enables organization scoping
    claim: "org"
    # Claim holding the identity's role identifiers within the organization
    roles_claim: "roles"
    # Role values that grant tailnet-admin on the organization's tailnets
    admin_roles: ["admin"]
    # Reject logins whose identity carries no organization claim
    required: false
```

For more details about configuring OIDC authentication, see [OIDC Configuration](./auth-oidc.md).

Tailnets are bound to an organization at creation time with `ionscale tailnets create --name <name> --org <organization-id>` (or the equivalent `CreateTailnet` API call with the `organization` field, e.g. issued by the identity-provider backend when it creates an organization); at most one tailnet may exist per organization (`CreateTailnet` returns `AlreadyExists` otherwise, making provisioning idempotent). `ionscale tailnets list --org <id>` filters by organization. The organization claim and roles are also available in IAM policy filter expressions as `org` and `roles` (e.g. `org == 42` or `roles contains "admin"`).

When the identity provider revokes a membership, revoke the account's access immediately with `ionscale users revoke-account --external-id <oidc-subject> [--org <id>]` (RPC `RevokeAccount`): it deletes the account's users, machines, api keys and auth keys in the affected tailnets and pushes a netmap update, instead of waiting for machine keys to expire.

### Tailnet defaults

Deployment-level defaults applied to tailnets and machines:

```yaml
tailnets:
  # how long a machine's node key stays valid before re-authentication
  machine_key_expiry: 4320h   # default: 180 days
  # enable machine authorization on newly created tailnets
  machine_authorization: false
  # optional HuJSON ACL policy for newly created tailnets; when empty the
  # built-in allow-all default is used
  default_acl_policy: |
    {
      "acls": [
        { "action": "accept", "src": ["*"], "dst": ["*:*"] }
      ]
    }
```

Security-relevant actions — logins (and refusals), tailnet lifecycle, IAM/ACL changes, key issuance and revocations — are emitted as structured events on the `audit` logger; with `logging.format: json` they can be filtered and shipped by the `logger` field.

### Tailnet lock

ionscale implements the control-plane side of [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock): nodes cryptographically verify that new nodes were signed by a tailnet-held key authority, so even a compromised control server cannot inject rogue nodes.

Enable the capability per tailnet, then drive the rest from any node with the standard tailscale CLI:

```bash
ionscale tailnets enable-tailnet-lock --tailnet <name>

# on a node in the tailnet:
tailscale lock init --gen-disablements=3 tlpub:<this-node's-lock-key>
tailscale lock sign nodekey:<new-node> tlpub:<its-lock-key>   # admit nodes that joined later
tailscale lock add|remove tlpub:<key>                          # manage trusted keys
tailscale lock disable disablement-secret:<secret>             # shut the authority down
```

Notes: enabling the key authority requires a signature for **every** existing node (`tailscale lock init` collects them automatically); nodes joining a locked tailnet via a plain auth key stay locked out until signed with `tailscale lock sign`; `ionscale tailnets disable-tailnet-lock` only revokes the capability and is refused while a key authority is active — disable it with the disablement secret first.

### DNS Configuration

Controls DNS settings:

```yaml
dns:
  # Suffix for MagicDNS
  magic_dns_suffix: ionscale.net
  
  # DNS provider for dynamic updates
  provider:
    name: cloudflare
    zone: example.com
    config:
      auth_token: ${CLOUDFLARE_TOKEN}
```

For more details about configuring DNS providers, see [DNS Providers](./dns-providers.md).

### DERP Configuration

Controls relay server configuration:

```yaml
derp:
  # Embedded DERP server configuration
  server:
    disabled: false
    region_id: 1000
    region_code: ionscale
    region_name: ionscale Embedded DERP
  
  # External DERP maps to load
  sources:
    - https://controlplane.tailscale.com/derpmap/default
    - file:///etc/ionscale/custom-derp.json
```

For more details about configuring DERP servers, see [DERP Configuration](./derp.md).

### Logging Configuration

Controls log output:

```yaml
logging:
  # Log level: debug, info, warn, error
  level: info
  
  # Log format: text, json
  format: text
  
  # Optional file output (in addition to stdout)
  file: /var/log/ionscale.log
```

### Keys and Security

You can configure private keys for the system:

```yaml
keys:
  # System administrator key for CLI authentication
  system_admin_key: your-private-key
  
  # Control plane keys (optional, auto-generated when not provided)
  control_key: your-control-key
  legacy_control_key: your-legacy-control-key
```

The `control_key` and `legacy_control_key` are optional and will be automatically generated if not provided. Once generated, they are stored in the database and reused across restarts.

!!! warning
    Never commit sensitive keys in your configuration files to version control. Use environment variables for sensitive values.

## Configuration File Locations

Common locations for ionscale configuration files:

- `/etc/ionscale/config.yaml` - System-wide configuration
- `$HOME/.config/ionscale/config.yaml` - User-specific configuration
- `./config.yaml` - Local directory configuration

## Complete Configuration Example

Below is a complete configuration file example with comments:

```yaml
# Network configuration
listen_addr: ":8080"               # HTTP/HTTPS control plane address
stun_listen_addr: ":3478"          # STUN server listen address
metrics_listen_addr: ":9091"       # Prometheus metrics address
public_addr: "ionscale.example.com:443"      # Public HTTPS endpoint for clients
stun_public_addr: "ionscale.example.com:3478" # Public STUN endpoint for clients

# TLS configuration
tls:
  disable: false                   # Set to true if behind a TLS-terminating proxy
  force_https: true                # Redirect HTTP to HTTPS
  # Provide your own certificates
  cert_file: "/etc/ionscale/cert.pem"  
  key_file: "/etc/ionscale/key.pem"
  # Or use Let's Encrypt
  acme: false                      # Enable ACME/Let's Encrypt
  acme_email: "admin@example.com"  # Contact email for Let's Encrypt
  acme_ca: "https://acme-v02.api.letsencrypt.org/directory"
  acme_path: "./data"              # Storage path for ACME certificates

# Database configuration
database:
  # SQLite configuration
  type: "sqlite"
  url: "/var/lib/ionscale/ionscale.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"
  
  # Or PostgreSQL configuration
  # type: "postgres"
  # url: "postgres://user:password@localhost:5432/ionscale?sslmode=disable"
  
  # Connection pool settings
  max_open_conns: 10
  max_idle_conns: 5
  conn_max_life_time: "5m"
  conn_max_idle_time: "5m"

# DERP (relay) configuration
derp:
  # Embedded DERP server
  server:
    disabled: false                # Set to true to disable embedded DERP
    region_id: 1000                # Region ID (1000+ reserved for ionscale)
    region_code: "ionscale"        # Short code for the region
    region_name: "ionscale Embedded DERP" # Human-readable name
  
  # External DERP sources (optional)
  sources:
    - https://controlplane.tailscale.com/derpmap/default  # Tailscale's DERP map
    # - file:///etc/ionscale/custom-derp.json            # Custom DERP map
    # - git::https://github.com/example/derp//map.json   # DERP map from git

# Security keys
keys:
  # System admin key for CLI authentication (required for admin CLI usage)
  system_admin_key: "${IONSCALE_SYSTEM_ADMIN_KEY}"  # Use environment variable
  
  # Control keys (optional, auto-generated if not provided)
  # control_key: "privkey:xxxxxx"
  # legacy_control_key: "privkey:xxxxxx"

# Network polling configuration
poll_net:
  # How often to send keep-alive messages
  keep_alive_interval: "60s"

# OIDC authentication configuration
auth:
  # OIDC provider settings
  provider:
    issuer: "https://auth.example.com"     # OIDC issuer URL
    client_id: "your-client-id"            # OAuth client ID
    client_secret: "${OIDC_CLIENT_SECRET}" # OAuth client secret from env var
    additional_scopes: ["profile", "email"] # Extra scopes to request
  
  # System administrator policy
  system_admins:
    # Users identified by email
    emails: ["admin@example.com"]
    # Users identified by subject ID
    subs: ["subject-id-12345"]
    # Users matching expression filters
    filters: ["domain == example.com"]

  # Organization-scoped tailnets
  organizations:
    # OIDC claim holding the organization identifier; enables org scoping
    claim: "org"
    # Claim holding the identity's organization roles
    roles_claim: "roles"
    # Role values granting tailnet-admin
    admin_roles: ["admin"]
    # Reject logins without an organization claim
    required: false

# DNS configuration
dns:
  # Suffix for MagicDNS hostnames
  magic_dns_suffix: "ionscale.net"
  
  # DNS provider for automatic DNS management (optional)
  provider:
    name: "cloudflare"              # Provider name (cloudflare, route53, etc.)
    zone: "example.com"             # DNS zone to manage
    config:                         # Provider-specific configuration
      auth_token: "${DNS_API_TOKEN}"

# Logging configuration
logging:
  level: "info"                     # debug, info, warn, error
  format: "text"                    # text or json
  file: "/var/log/ionscale.log"     # Optional log file path
```

!!! note "Environment variables"
    In this example, we use environment variables for sensitive values:
    ```
    ${IONSCALE_SYSTEM_ADMIN_KEY} - System admin key for CLI authentication
    ${OIDC_CLIENT_SECRET} - OIDC client secret
    ${DNS_API_TOKEN} - DNS provider API token
    ```
    
    These must be set in your environment before starting ionscale.