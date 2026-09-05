package service

import (
	"testing"

	"github.com/bufbuild/connect-go"
	api "github.com/jsiebens/ionscale/pkg/gen/ionscale/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateDNSConfigExtraRecords(t *testing.T) {
	cases := []struct {
		name   string
		record *api.DNSRecord
		ok     bool
	}{
		{name: "untyped v4", record: &api.DNSRecord{Name: "svc.example.com", Value: "100.64.0.5"}, ok: true},
		{name: "untyped v6", record: &api.DNSRecord{Name: "svc.example.com.", Value: "fd7a:115c:a1e0::1"}, ok: true},
		{name: "A v4", record: &api.DNSRecord{Name: "svc.example.com", Type: "A", Value: "100.64.0.5"}, ok: true},
		{name: "lowercase type", record: &api.DNSRecord{Name: "svc.example.com", Type: "aaaa", Value: "fd7a::1"}, ok: true},
		{name: "A with v6", record: &api.DNSRecord{Name: "svc.example.com", Type: "A", Value: "fd7a::1"}, ok: false},
		{name: "AAAA with v4", record: &api.DNSRecord{Name: "svc.example.com", Type: "AAAA", Value: "100.64.0.5"}, ok: false},
		{name: "unsupported type", record: &api.DNSRecord{Name: "svc.example.com", Type: "CNAME", Value: "100.64.0.5"}, ok: false},
		{name: "not an ip", record: &api.DNSRecord{Name: "svc.example.com", Value: "example.com"}, ok: false},
		{name: "empty name", record: &api.DNSRecord{Name: "", Value: "100.64.0.5"}, ok: false},
		{name: "bad name", record: &api.DNSRecord{Name: "not a host name", Value: "100.64.0.5"}, ok: false},
	}

	require.NoError(t, validateDNSConfig(nil))
	require.NoError(t, validateDNSConfig(&api.DNSConfig{MagicDns: true}))

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDNSConfig(&api.DNSConfig{ExtraRecords: []*api.DNSRecord{tc.record}})
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestSetDNSConfigExtraRecordsRoundTrip(t *testing.T) {
	svc, repo := newTestService(t)

	tailnet := newTestTailnet(t, repo, "net", "")

	resp, err := svc.SetDNSConfig(systemAdminCtx(), connect.NewRequest(&api.SetDNSConfigRequest{
		TailnetId: tailnet.ID,
		Config: &api.DNSConfig{
			MagicDns: true,
			ExtraRecords: []*api.DNSRecord{
				{Name: "svc.example.com", Value: "100.64.0.5"},
				{Name: "v6.example.com", Type: "aaaa", Value: "fd7a::1"},
			},
		},
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Config.ExtraRecords, 2)
	assert.Equal(t, "svc.example.com", resp.Msg.Config.ExtraRecords[0].Name)
	assert.Equal(t, "AAAA", resp.Msg.Config.ExtraRecords[1].Type)

	// records are persisted and read back
	get, err := svc.GetDNSConfig(systemAdminCtx(), connect.NewRequest(&api.GetDNSConfigRequest{TailnetId: tailnet.ID}))
	require.NoError(t, err)
	require.Len(t, get.Msg.Config.ExtraRecords, 2)

	// changing only the records is not short-circuited as "no change"
	resp, err = svc.SetDNSConfig(systemAdminCtx(), connect.NewRequest(&api.SetDNSConfigRequest{
		TailnetId: tailnet.ID,
		Config:    &api.DNSConfig{MagicDns: true},
	}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Config.ExtraRecords)

	// invalid records are rejected
	_, err = svc.SetDNSConfig(systemAdminCtx(), connect.NewRequest(&api.SetDNSConfigRequest{
		TailnetId: tailnet.ID,
		Config:    &api.DNSConfig{ExtraRecords: []*api.DNSRecord{{Name: "svc.example.com", Value: "nope"}}},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}
