package config

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tempFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	// Write test configuration
	yamlContent := `
public_addr: "ionscale.localtest.me:443"
stun_public_addr: "ionscale.localtest.me:3478"

database:
  type: ${DB_TYPE:sqlite}
  url: ${DB_URL}
  max_open_conns: ${DB_MAX_OPEN_CONNS:5}
  conn_max_life_time: ${DB_CONN_MAX_LIFE_TIME:5s}
`
	if _, err := tempFile.Write([]byte(yamlContent)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tempFile.Close()

	t.Run("With DB_URL set", func(t *testing.T) {
		require.NoError(t, os.Setenv("DB_URL", "./ionscale.db"))

		config, err := LoadConfig(tempFile.Name())
		require.NoError(t, err)

		require.Equal(t, "sqlite", config.Database.Type)
		require.Equal(t, "./ionscale.db", config.Database.Url)
		require.Equal(t, 5, config.Database.MaxOpenConns)
	})

	t.Run("Without required DB_URL", func(t *testing.T) {
		require.NoError(t, os.Unsetenv("DB_URL"))

		_, err := LoadConfig(tempFile.Name())
		require.Error(t, err)
	})
}

func TestExpandEnvVars(t *testing.T) {
	// Setup test environment variables
	require.NoError(t, os.Setenv("TEST_VAR", "test_value"))
	require.NoError(t, os.Setenv("PORT", "9090"))

	// Ensure TEST_DEFAULT is not set
	require.NoError(t, os.Unsetenv("TEST_DEFAULT"))

	tests := []struct {
		name        string
		input       []byte
		expected    []byte
		expectError bool
	}{
		{
			name:        "Braced variable",
			input:       []byte("Port: ${PORT}"),
			expected:    []byte("Port: 9090"),
			expectError: false,
		},
		{
			name:        "Default value used",
			input:       []byte("Default: ${TEST_DEFAULT:fallback}"),
			expected:    []byte("Default: fallback"),
			expectError: false,
		},
		{
			name:        "Default value not used when env var exists",
			input:       []byte("Not default: ${PORT:8080}"),
			expected:    []byte("Not default: 9090"),
			expectError: false,
		},
		{
			name:        "Multiple replacements",
			input:       []byte("Config: ${TEST_VAR} ${PORT} ${TEST_DEFAULT:default}"),
			expected:    []byte("Config: test_value 9090 default"),
			expectError: false,
		},
		{
			name:        "Missing required variable",
			input:       []byte("Required: ${MISSING_VAR}"),
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Mixed variables with one missing",
			input:       []byte("Mixed: ${TEST_VAR} ${MISSING_VAR} ${TEST_DEFAULT:default}"),
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := expandEnvVars(tt.input)

			// Check error expectation
			if tt.expectError && err == nil {
				t.Errorf("expandEnvVars() expected error but got none")
				return
			}
			if !tt.expectError && err != nil {
				t.Errorf("expandEnvVars() got unexpected error: %v", err)
				return
			}

			// If we expected an error, don't check the result further
			if tt.expectError {
				return
			}

			// Check result
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("expandEnvVars() got = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestLoadConfigOrganizations(t *testing.T) {
	tempFile, err := os.CreateTemp("", "config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	yamlContent := `
public_addr: "ionscale.localtest.me:443"
stun_public_addr: "ionscale.localtest.me:3478"

auth:
  organizations:
    claim: "org"
    roles_claim: "roles"
    admin_roles: ["admin"]
    required: true
`
	_, err = tempFile.Write([]byte(yamlContent))
	require.NoError(t, err)
	tempFile.Close()

	config, err := LoadConfig(tempFile.Name())
	require.NoError(t, err)

	orgs := config.Auth.Organizations
	require.True(t, orgs.Enabled())
	require.Equal(t, "org", orgs.Claim)
	require.Equal(t, "roles", orgs.RolesClaim)
	require.Equal(t, []string{"admin"}, orgs.AdminRoles)
	require.True(t, orgs.Required)

	require.False(t, Organizations{}.Enabled())
}

func TestLoadConfigTailnetDefaults(t *testing.T) {
	tempFile, err := os.CreateTemp("", "config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	yamlContent := `
public_addr: "ionscale.localtest.me:443"
stun_public_addr: "ionscale.localtest.me:3478"

tailnets:
  machine_key_expiry: 24h
  machine_authorization: true
  default_acl_policy: |
    {
      "acls": [
        { "action": "accept", "src": ["*"], "dst": ["*:*"] }
      ]
    }
`
	_, err = tempFile.Write([]byte(yamlContent))
	require.NoError(t, err)
	tempFile.Close()

	config, err := LoadConfig(tempFile.Name())
	require.NoError(t, err)

	require.Equal(t, 24*time.Hour, config.Tailnets.MachineKeyExpiry.Std())
	require.Equal(t, 24*time.Hour, MachineKeyExpiry())
	require.True(t, config.Tailnets.MachineAuthorization)
	require.NotEmpty(t, config.Tailnets.DefaultACLPolicy)
}

func TestLoadConfigTailnetDefaultsInvalidACL(t *testing.T) {
	tempFile, err := os.CreateTemp("", "config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	yamlContent := `
public_addr: "ionscale.localtest.me:443"
stun_public_addr: "ionscale.localtest.me:3478"

tailnets:
  default_acl_policy: "{ not valid hujson !"
`
	_, err = tempFile.Write([]byte(yamlContent))
	require.NoError(t, err)
	tempFile.Close()

	_, err = LoadConfig(tempFile.Name())
	require.Error(t, err)
}

func TestMachineKeyExpiryDefault(t *testing.T) {
	tempFile, err := os.CreateTemp("", "config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	yamlContent := `
public_addr: "ionscale.localtest.me:443"
stun_public_addr: "ionscale.localtest.me:3478"
`
	_, err = tempFile.Write([]byte(yamlContent))
	require.NoError(t, err)
	tempFile.Close()

	_, err = LoadConfig(tempFile.Name())
	require.NoError(t, err)
	require.Equal(t, 180*24*time.Hour, MachineKeyExpiry())
}

func TestValidateServiceTokens(t *testing.T) {
	valid := "svc_" + "0123456789abcdef0123456789abcdef"

	cases := []struct {
		name   string
		tokens []ServiceToken
		ok     bool
	}{
		{name: "none", tokens: nil, ok: true},
		{name: "valid", tokens: []ServiceToken{{Name: "lok", Token: valid}}, ok: true},
		{name: "two", tokens: []ServiceToken{{Name: "lok", Token: valid}, {Name: "ci", Token: valid + "x"}}, ok: true},
		{name: "missing name", tokens: []ServiceToken{{Name: " ", Token: valid}}, ok: false},
		{name: "duplicate name", tokens: []ServiceToken{{Name: "lok", Token: valid}, {Name: "lok", Token: valid + "x"}}, ok: false},
		{name: "duplicate token", tokens: []ServiceToken{{Name: "lok", Token: valid}, {Name: "ci", Token: valid}}, ok: false},
		{name: "wrong prefix", tokens: []ServiceToken{{Name: "lok", Token: "sk_0123456789abcdef0123456789abcdef"}}, ok: false},
		{name: "too short", tokens: []ServiceToken{{Name: "lok", Token: "svc_short"}}, ok: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateServiceTokens(tc.tokens)
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestLoadConfigServiceTokens(t *testing.T) {
	tempFile, err := os.CreateTemp("", "config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	require.NoError(t, os.Setenv("IONSCALE_LOK_SERVICE_TOKEN", "svc_0123456789abcdef0123456789abcdef"))
	defer os.Unsetenv("IONSCALE_LOK_SERVICE_TOKEN")

	yamlContent := `
public_addr: "ionscale.localtest.me:443"
stun_public_addr: "ionscale.localtest.me:3478"

auth:
  service_tokens:
    - name: lok
      token: ${IONSCALE_LOK_SERVICE_TOKEN}
`
	_, err = tempFile.Write([]byte(yamlContent))
	require.NoError(t, err)
	tempFile.Close()

	config, err := LoadConfig(tempFile.Name())
	require.NoError(t, err)
	require.Len(t, config.Auth.ServiceTokens, 1)
	require.Equal(t, "lok", config.Auth.ServiceTokens[0].Name)
	require.Equal(t, "svc_0123456789abcdef0123456789abcdef", config.Auth.ServiceTokens[0].Token)
}
