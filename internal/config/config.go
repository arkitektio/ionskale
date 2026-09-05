package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/caddyserver/certmagic"
	"github.com/jsiebens/ionscale/internal/domain"
	"github.com/jsiebens/ionscale/internal/key"
	"github.com/jsiebens/ionscale/internal/util"
	"github.com/mitchellh/go-homedir"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sigs.k8s.io/yaml"
	"strings"
	"tailscale.com/tailcfg"
	tkey "tailscale.com/types/key"
	"time"
)

const (
	defaultKeepAliveInterval = 1 * time.Minute
	defaultMagicDNSSuffix    = "ionscale.net"
	defaultMachineKeyExpiry  = 180 * 24 * time.Hour
)

var (
	keepAliveInterval     = defaultKeepAliveInterval
	magicDNSSuffix        = defaultMagicDNSSuffix
	machineKeyExpiry      = defaultMachineKeyExpiry
	dnsProviderConfigured = false
)

func KeepAliveInterval() time.Duration {
	return keepAliveInterval
}

func MagicDNSSuffix() string {
	return magicDNSSuffix
}

func MachineKeyExpiry() time.Duration {
	return machineKeyExpiry
}

func DNSProviderConfigured() bool {
	return dnsProviderConfigured
}

func LoadConfig(path string) (*Config, error) {
	cfg := defaultConfig()

	if len(path) != 0 {
		expandedPath, err := homedir.Expand(path)
		if err != nil {
			return nil, err
		}

		absPath, err := filepath.Abs(expandedPath)
		if err != nil {
			return nil, err
		}

		b, err := os.ReadFile(absPath)
		if err != nil {
			return nil, err
		}

		b, err = expandEnvVars(b)
		if err != nil {
			return nil, err
		}

		if err := yaml.Unmarshal(b, cfg); err != nil {
			return nil, err
		}
	}

	envCfgB64 := os.Getenv("IONSCALE_CONFIG_BASE64")
	if len(envCfgB64) != 0 {
		b, err := base64.StdEncoding.DecodeString(envCfgB64)
		if err != nil {
			return nil, err
		}

		b, err = expandEnvVars(b)
		if err != nil {
			return nil, err
		}

		if err := yaml.Unmarshal(b, cfg); err != nil {
			return nil, err
		}
	}

	keepAliveInterval = time.Duration(cfg.PollNet.KeepAliveInterval)
	magicDNSSuffix = cfg.DNS.MagicDNSSuffix

	if cfg.Tailnets.MachineKeyExpiry <= 0 {
		cfg.Tailnets.MachineKeyExpiry = Duration(defaultMachineKeyExpiry)
	}
	machineKeyExpiry = time.Duration(cfg.Tailnets.MachineKeyExpiry)

	if cfg.DNS.Provider.Zone != "" {
		dnsProviderConfigured = true
	}

	return cfg.Validate()
}

func defaultConfig() *Config {
	return &Config{
		ListenAddr:        ":8080",
		MetricsListenAddr: ":9091",
		StunListenAddr:    ":3478",
		Database: Database{
			Type:         "sqlite",
			Url:          "./ionscale.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)",
			MaxOpenConns: 0,
			MaxIdleConns: 2,
		},
		Tls: Tls{
			Disable:     false,
			ForceHttps:  true,
			AcmeEnabled: false,
			AcmeCA:      certmagic.LetsEncryptProductionCA,
		},
		PollNet: PollNet{
			KeepAliveInterval: Duration(defaultKeepAliveInterval),
		},
		DNS: DNS{
			MagicDNSSuffix: defaultMagicDNSSuffix,
		},
		DERP: DERP{
			Server: DERPServer{
				Disabled:   false,
				RegionID:   1000,
				RegionCode: "ionscale",
				RegionName: "ionscale Embedded DERP",
			},
		},
		Logging: Logging{
			Level: "info",
		},
		Tailnets: Tailnets{
			MachineKeyExpiry: Duration(defaultMachineKeyExpiry),
		},
	}
}

type ServerKeys struct {
	SystemAdminKey   *key.ServerPrivate
	ControlKey       tkey.MachinePrivate
	LegacyControlKey tkey.MachinePrivate
}

type Config struct {
	ListenAddr        string   `json:"listen_addr,omitempty"`
	StunListenAddr    string   `json:"stun_listen_addr,omitempty"`
	MetricsListenAddr string   `json:"metrics_listen_addr,omitempty"`
	PublicAddr        string   `json:"public_addr,omitempty"`
	StunPublicAddr    string   `json:"stun_public_addr,omitempty"`
	Tls               Tls      `json:"tls,omitempty"`
	PollNet           PollNet  `json:"poll_net,omitempty"`
	Keys              Keys     `json:"keys,omitempty"`
	Database          Database `json:"database,omitempty"`
	Auth              Auth     `json:"auth,omitempty"`
	Tailnets          Tailnets `json:"tailnets,omitempty"`
	DNS               DNS      `json:"dns,omitempty"`
	DERP              DERP     `json:"derp,omitempty"`
	Logging           Logging  `json:"logging,omitempty"`

	PublicUrl *url.URL `json:"-"`

	stunHost string
	stunPort int
	derpHost string
	derpPort int
}

type Tls struct {
	Disable     bool   `json:"disable"`
	ForceHttps  bool   `json:"force_https"`
	CertFile    string `json:"cert_file,omitempty"`
	KeyFile     string `json:"key_file,omitempty"`
	AcmeEnabled bool   `json:"acme,omitempty"`
	AcmeEmail   string `json:"acme_email,omitempty"`
	AcmeCA      string `json:"acme_ca,omitempty"`
}

type PollNet struct {
	KeepAliveInterval Duration `json:"keep_alive_interval"`
}

type Logging struct {
	Level  string `json:"level,omitempty"`
	Format string `json:"format,omitempty"`
	File   string `json:"file,omitempty"`
}

type Database struct {
	Type            string   `json:"type,omitempty"`
	Url             string   `json:"url,omitempty"`
	MaxOpenConns    int      `json:"max_open_conns,omitempty"`
	MaxIdleConns    int      `json:"max_idle_conns,omitempty"`
	ConnMaxLifetime Duration `json:"conn_max_life_time,omitempty"`
	ConnMaxIdleTime Duration `json:"conn_max_idle_time,omitempty"`
}

type Keys struct {
	ControlKey       string `json:"control_key,omitempty"`
	LegacyControlKey string `json:"legacy_control_key,omitempty"`
	SystemAdminKey   string `json:"system_admin_key,omitempty"`
}

type Auth struct {
	Provider          AuthProvider      `json:"provider,omitempty"`
	SystemAdminPolicy SystemAdminPolicy `json:"system_admins"`
	Organizations     Organizations     `json:"organizations,omitempty"`
	// ServiceTokens are static bearer tokens granting system-admin to
	// non-interactive callers (an identity provider syncing tailnets, a
	// reconciliation job). Unlike system admin keys they need no client-side
	// sealing, so any HTTP client can use them.
	ServiceTokens []ServiceToken `json:"service_tokens,omitempty"`
}

const (
	// ServiceTokenPrefix marks a static service token; the interceptor never
	// looks such a value up in the database.
	ServiceTokenPrefix = "svc_"
	// minServiceTokenSecretLength is the minimum length of the part after the
	// prefix; 32 characters of a random alphabet is comfortably beyond brute
	// force.
	minServiceTokenSecretLength = 32
)

// ServiceToken names a static credential; the name shows up as the audit actor
// (service:<name>) so tokens can be told apart and rotated individually.
type ServiceToken struct {
	Name  string `json:"name"`
	Token string `json:"token"`
}

// Organizations enables organization-scoped tailnets. When a claim is
// configured, every OIDC identity is resolved to a single organization and a
// tailnet carrying an organization is only ever offered to identities of that
// same organization, regardless of its IAM policy.
type Organizations struct {
	// Claim is the OIDC claim (id_token first, then userinfo) holding the
	// organization identifier. Setting it turns organization scoping on.
	Claim string `json:"claim,omitempty"`
	// RolesClaim is the claim holding the identity's role identifiers within
	// the organization.
	RolesClaim string `json:"roles_claim,omitempty"`
	// AdminRoles lists the role values that grant tailnet-admin on the
	// organization's tailnets.
	AdminRoles []string `json:"admin_roles,omitempty"`
	// Required rejects logins whose identity carries no organization claim.
	Required bool `json:"required,omitempty"`
}

func (o Organizations) Enabled() bool {
	return o.Claim != ""
}

type AuthProvider struct {
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"additional_scopes" `
	// UsernameClaim names the claim used as an identity's login name in the
	// Tailscale client. Defaults to "preferred_username"; the email is used
	// when the claim is absent. Identity, IAM policies and audit matching are
	// unaffected -- this only changes the label users see.
	UsernameClaim string `json:"username_claim,omitempty"`
}

// Tailnets holds deployment-level defaults applied to tailnets and machines.
type Tailnets struct {
	// MachineKeyExpiry is how long a machine's node key stays valid before
	// the machine must re-authenticate.
	MachineKeyExpiry Duration `json:"machine_key_expiry,omitempty"`
	// MachineAuthorization enables machine authorization on newly created
	// tailnets when the create request does not enable it itself.
	MachineAuthorization bool `json:"machine_authorization,omitempty"`
	// DefaultACLPolicy is an optional HuJSON ACL policy applied to newly
	// created tailnets when the create request carries none; when empty the
	// built-in allow-all default is used.
	DefaultACLPolicy string `json:"default_acl_policy,omitempty"`
}

type DNS struct {
	MagicDNSSuffix string      `json:"magic_dns_suffix"`
	Provider       DNSProvider `json:"provider,omitempty"`
}

type DNSProvider struct {
	Name          string          `json:"name"`
	PluginPath    string          `json:"plugin_path"`
	Zone          string          `json:"zone"`
	Configuration json.RawMessage `json:"config"`
}

type SystemAdminPolicy struct {
	Subs    []string `json:"subs,omitempty"`
	Emails  []string `json:"emails,omitempty"`
	Filters []string `json:"filters,omitempty"`
}

type DERP struct {
	Server  DERPServer `json:"server,omitempty"`
	Sources []string   `json:"sources,omitempty"`
}

type DERPServer struct {
	Disabled   bool   `json:"disabled,omitempty"`
	RegionID   int    `json:"region_id,omitempty"`
	RegionCode string `json:"region_code,omitempty"`
	RegionName string `json:"region_name,omitempty"`
}

func (c *Config) Validate() (*Config, error) {
	if c.Tailnets.DefaultACLPolicy != "" {
		if _, err := domain.ParseHuJson[domain.ACLPolicy](c.Tailnets.DefaultACLPolicy); err != nil {
			return nil, fmt.Errorf("tailnets.default_acl_policy is not a valid ACL policy: %w", err)
		}
	}

	if err := validateServiceTokens(c.Auth.ServiceTokens); err != nil {
		return nil, err
	}

	publicWebUrl, webHost, webPort, err := validatePublicAddr(c.PublicAddr)
	if err != nil {
		return nil, fmt.Errorf("web public addr: %w", err)
	}

	c.PublicUrl = publicWebUrl
	c.derpHost = webHost
	c.derpPort = webPort

	if !c.DERP.Server.Disabled {
		_, stunHost, stunPort, err := validatePublicAddr(c.StunPublicAddr)
		if err != nil {
			return nil, fmt.Errorf("stun public addr: %w", err)
		}

		c.stunHost = stunHost
		c.stunPort = stunPort
	}

	return c, nil
}

func validateServiceTokens(tokens []ServiceToken) error {
	names := map[string]struct{}{}
	values := map[string]struct{}{}
	for i, st := range tokens {
		if strings.TrimSpace(st.Name) == "" {
			return fmt.Errorf("auth.service_tokens[%d]: name is required", i)
		}
		if _, dup := names[st.Name]; dup {
			return fmt.Errorf("auth.service_tokens: duplicate name %q", st.Name)
		}
		names[st.Name] = struct{}{}

		if !strings.HasPrefix(st.Token, ServiceTokenPrefix) {
			return fmt.Errorf("auth.service_tokens[%s]: token must start with %q", st.Name, ServiceTokenPrefix)
		}
		if len(st.Token)-len(ServiceTokenPrefix) < minServiceTokenSecretLength {
			return fmt.Errorf("auth.service_tokens[%s]: token must have at least %d characters after the %q prefix", st.Name, minServiceTokenSecretLength, ServiceTokenPrefix)
		}
		if _, dup := values[st.Token]; dup {
			return fmt.Errorf("auth.service_tokens[%s]: token is already used by another service", st.Name)
		}
		values[st.Token] = struct{}{}
	}
	return nil
}

func (c *Config) CreateUrl(format string, a ...interface{}) string {
	path := fmt.Sprintf(format, a...)
	u := url.URL{
		Scheme: c.PublicUrl.Scheme,
		Host:   c.PublicUrl.Host,
		Path:   path,
	}
	return u.String()
}

func (c *Config) ReadServerKeys(defaultKeys *domain.ControlKeys) (*ServerKeys, error) {
	keys := &ServerKeys{
		ControlKey:       defaultKeys.ControlKey,
		LegacyControlKey: defaultKeys.LegacyControlKey,
	}

	if len(c.Keys.SystemAdminKey) != 0 {
		systemAdminKey, err := key.ParsePrivateKey(c.Keys.SystemAdminKey)
		if err != nil {
			return nil, fmt.Errorf("error reading system admin key: %v", err)
		}

		keys.SystemAdminKey = systemAdminKey
	}

	if len(c.Keys.ControlKey) != 0 {
		controlKey, err := util.ParseMachinePrivateKey(c.Keys.ControlKey)
		if err != nil {
			return nil, fmt.Errorf("error reading control key: %v", err)
		}
		keys.ControlKey = *controlKey
	}

	if len(c.Keys.LegacyControlKey) != 0 {
		legacyControlKey, err := util.ParseMachinePrivateKey(c.Keys.LegacyControlKey)
		if err != nil {
			return nil, fmt.Errorf("error reading legacy control key: %v", err)
		}
		keys.LegacyControlKey = *legacyControlKey
	}

	return keys, nil
}

func (c *Config) DefaultDERPMap() *tailcfg.DERPMap {
	if c.derpHost == c.stunHost {
		return &tailcfg.DERPMap{
			Regions: map[int]*tailcfg.DERPRegion{
				c.DERP.Server.RegionID: {
					RegionID:   c.DERP.Server.RegionID,
					RegionCode: c.DERP.Server.RegionCode,
					RegionName: c.DERP.Server.RegionName,
					Nodes: []*tailcfg.DERPNode{
						{
							RegionID: c.DERP.Server.RegionID,
							Name:     "ionscale",
							HostName: c.derpHost,
							DERPPort: c.derpPort,
							STUNPort: c.stunPort,
						},
					},
				},
			},
		}
	}

	return &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			c.DERP.Server.RegionID: {
				RegionID:   c.DERP.Server.RegionID,
				RegionCode: c.DERP.Server.RegionCode,
				RegionName: c.DERP.Server.RegionName,
				Nodes: []*tailcfg.DERPNode{
					{
						RegionID: c.DERP.Server.RegionID,
						Name:     "stun",
						HostName: c.stunHost,
						STUNOnly: true,
						STUNPort: c.stunPort,
					},
					{
						RegionID: c.DERP.Server.RegionID,
						Name:     "derp",
						HostName: c.derpHost,
						DERPPort: c.derpPort,
						STUNPort: -1,
					},
				},
			},
		},
	}
}

type Duration time.Duration

func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*d = Duration(value)
		return nil
	case string:
		tmp, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = Duration(tmp)
		return nil
	default:
		return fmt.Errorf("invalid duration")
	}
}

// Match ${VAR:default} syntax for variables with default values
var optionalEnvRegex = regexp.MustCompile(`\${([a-zA-Z0-9_]+):([^}]*)}`)

// Match ${VAR} syntax (without default) - these are required
var requiredEnvRegex = regexp.MustCompile(`\${([a-zA-Z0-9_]+)}`)

func expandEnvVars(config []byte) ([]byte, error) {
	var result = config
	var missingVars []string

	result = optionalEnvRegex.ReplaceAllFunc(result, func(match []byte) []byte {
		parts := optionalEnvRegex.FindSubmatch(match)
		envVar := string(parts[1])
		defaultValue := parts[2]

		envValue := os.Getenv(envVar)
		if envValue != "" {
			return []byte(envValue)
		}
		return defaultValue
	})

	result = requiredEnvRegex.ReplaceAllFunc(result, func(match []byte) []byte {
		parts := requiredEnvRegex.FindSubmatch(match)
		envVar := string(parts[1])
		envValue := os.Getenv(envVar)

		if envValue == "" {
			missingVars = append(missingVars, envVar)
			return match
		}

		return []byte(envValue)
	})

	if len(missingVars) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missingVars, ", "))
	}

	return result, nil
}
