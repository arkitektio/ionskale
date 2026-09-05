package mapping

import (
	"testing"

	"github.com/jsiebens/ionscale/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToDNSConfigExtraRecords(t *testing.T) {
	tailnet := &domain.Tailnet{Name: "net"}
	machine := &domain.Machine{Name: "m1"}

	cfg := &domain.DNSConfig{
		MagicDNS: false,
		ExtraRecords: []domain.DNSRecord{
			{Name: "svc.example.com", Value: "100.64.0.5"},
			{Name: "v6.example.com", Type: "AAAA", Value: "fd7a::1"},
		},
	}

	dns := ToDNSConfig(machine, tailnet, cfg)

	require.Len(t, dns.ExtraRecords, 2)
	assert.Equal(t, "svc.example.com", dns.ExtraRecords[0].Name)
	assert.Equal(t, "100.64.0.5", dns.ExtraRecords[0].Value)
	assert.Equal(t, "AAAA", dns.ExtraRecords[1].Type)

	// each record name gets an empty route so the OS asks the MagicDNS
	// resolver for it even when MagicDNS proxying is off
	require.NotNil(t, dns.Routes)
	route, ok := dns.Routes["svc.example.com"]
	require.True(t, ok)
	assert.Nil(t, route)
	_, ok = dns.Routes["v6.example.com"]
	assert.True(t, ok)
}

func TestToDNSConfigWithoutRoutesLeavesRoutesUnset(t *testing.T) {
	tailnet := &domain.Tailnet{Name: "net"}
	machine := &domain.Machine{Name: "m1"}

	dns := ToDNSConfig(machine, tailnet, &domain.DNSConfig{MagicDNS: true})

	assert.Empty(t, dns.ExtraRecords)
	assert.Nil(t, dns.Routes)
	assert.True(t, dns.Proxied)
}

func TestToDNSConfigUserRouteWinsOverRecordRoute(t *testing.T) {
	tailnet := &domain.Tailnet{Name: "net"}
	machine := &domain.Machine{Name: "m1"}

	cfg := &domain.DNSConfig{
		Routes:       map[string][]string{"example.com": {"10.0.0.53"}},
		ExtraRecords: []domain.DNSRecord{{Name: "example.com", Value: "100.64.0.5"}},
	}

	dns := ToDNSConfig(machine, tailnet, cfg)
	require.Len(t, dns.Routes["example.com"], 1)
	assert.Equal(t, "10.0.0.53", dns.Routes["example.com"][0].Addr)
}
