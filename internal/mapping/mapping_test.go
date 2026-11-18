package mapping

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/jsiebens/ionscale/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
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

// A machine's peers are told the capability version its client speaks: a
// tailscale client uses peer relays only with a node it knows to (121).
func TestToNodeTellsTheCapabilityVersion(t *testing.T) {
	tailnet := &domain.Tailnet{Name: "net", IAMPolicy: domain.NewHuJSON(&domain.IAMPolicy{})}
	nodeKey := "nodekey:" + strings.Repeat("11", 32)
	machineKey := "mkey:" + strings.Repeat("22", 32)
	ipv4, ipv6 := netip.MustParseAddr("100.64.0.7"), netip.MustParseAddr("fd7a:115c:a1e0::7")
	machine := func(capVer uint32) *domain.Machine {
		return &domain.Machine{
			ID: 7, Name: "m1", NodeKey: nodeKey, MachineKey: machineKey,
			IPv4: domain.IP{Addr: &ipv4}, IPv6: domain.IP{Addr: &ipv6},
			Tailnet: *tailnet, CapVer: capVer,
		}
	}
	noRoutes := func(*domain.Machine) []netip.Prefix { return nil }

	node, _, err := ToNode(130, machine(142), tailnet, nil, true, true, noRoutes)
	require.NoError(t, err)
	assert.Equal(t, tailcfg.CapabilityVersion(142), node.Cap)

	// Not polled since the version is kept: left out, not claimed.
	node, _, err = ToNode(130, machine(0), tailnet, nil, true, true, noRoutes)
	require.NoError(t, err)
	assert.Zero(t, node.Cap)
}
