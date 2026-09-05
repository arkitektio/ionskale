package mapping

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jsiebens/ionscale/internal/config"
	"github.com/jsiebens/ionscale/internal/core"
	"github.com/jsiebens/ionscale/internal/database"
	"github.com/jsiebens/ionscale/internal/domain"
	"github.com/jsiebens/ionscale/internal/util"
	"github.com/jsiebens/ionscale/pkg/client/ionscale"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func newTestRepository(t *testing.T) domain.Repository {
	t.Helper()
	util.EnsureIDProvider()
	cfg := &config.Database{Type: "sqlite", Url: filepath.Join(t.TempDir(), "test.db") + "?_pragma=foreign_keys(ON)"}
	_, repo, err := database.OpenDB(cfg, zap.NewNop())
	require.NoError(t, err)
	return repo
}

func newMapperTailnet(t *testing.T, repo domain.Repository, machineAuthorization bool) (*domain.Tailnet, *domain.User) {
	t.Helper()
	ctx := context.Background()
	tailnet := &domain.Tailnet{
		ID:                          util.NextID(),
		Name:                        "net",
		IAMPolicy:                   domain.NewHuJSON(&domain.IAMPolicy{}),
		ACLPolicy:                   domain.NewHuJSON(&domain.ACLPolicy{ACLPolicy: ionscale.ACLPolicy{ACLs: []ionscale.ACLEntry{{Action: "accept", Source: []string{"*"}, Destination: []string{"*:*"}}}}}),
		MachineAuthorizationEnabled: machineAuthorization,
	}
	require.NoError(t, repo.SaveTailnet(ctx, tailnet))
	account, _, err := repo.GetOrCreateAccount(ctx, "sub", "", "john@example.com")
	require.NoError(t, err)
	user, _, err := repo.GetOrCreateUserWithAccount(ctx, tailnet, account)
	require.NoError(t, err)
	return tailnet, user
}

func newMapperMachine(t *testing.T, repo domain.Repository, tailnet *domain.Tailnet, user *domain.User, ip string, authorized bool, expiresAt time.Time) *domain.Machine {
	t.Helper()
	addr := netip.MustParseAddr(ip)
	addr6 := netip.MustParseAddr("fd7a:115c:a1e0::" + ip[len("100.64.0."):])
	m := &domain.Machine{
		ID:         util.NextID(),
		Name:       "m-" + ip,
		NodeKey:    key.NewNode().Public().String(),
		MachineKey: key.NewMachine().Public().String(),
		IPv4:       domain.IP{Addr: &addr},
		IPv6:       domain.IP{Addr: &addr6},
		UserID:     user.ID,
		TailnetID:  tailnet.ID,
		Authorized: authorized,
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  expiresAt.UTC(),
	}
	require.NoError(t, repo.SaveMachine(context.Background(), m))
	return m
}

func peerIDs(nodes []*tailcfg.Node) []tailcfg.NodeID {
	var ids []tailcfg.NodeID
	for _, n := range nodes {
		ids = append(ids, n.ID)
	}
	return ids
}

func TestPollNetMapperHidesQuarantinedPeers(t *testing.T) {
	repo := newTestRepository(t)
	tailnet, user := newMapperTailnet(t, repo, true)
	sm := core.NewPollMapSessionManager()

	future := time.Now().Add(time.Hour)
	self := newMapperMachine(t, repo, tailnet, user, "100.64.0.1", true, future)
	healthy := newMapperMachine(t, repo, tailnet, user, "100.64.0.2", true, future)
	expired := newMapperMachine(t, repo, tailnet, user, "100.64.0.3", true, time.Now().Add(-time.Minute))
	unauthorized := newMapperMachine(t, repo, tailnet, user, "100.64.0.4", false, future)

	mapper := NewPollNetMapper(&tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion}, self.ID, repo, sm)
	resp, err := mapper.CreateMapResponse(context.Background(), false)
	require.NoError(t, err)

	assert.ElementsMatch(t, []tailcfg.NodeID{tailcfg.NodeID(healthy.ID)}, peerIDs(resp.Peers))
	assert.NotContains(t, peerIDs(resp.Peers), tailcfg.NodeID(expired.ID))
	assert.NotContains(t, peerIDs(resp.Peers), tailcfg.NodeID(unauthorized.ID))
	require.NotEmpty(t, resp.PacketFilter)
	// the packet filter only grants access to the healthy peer's address
	for _, rule := range resp.PacketFilter {
		assert.NotContains(t, rule.SrcIPs, "100.64.0.3/32")
		assert.NotContains(t, rule.SrcIPs, "100.64.0.4/32")
	}
	assert.False(t, resp.Node.Expired)
}

func TestPollNetMapperQuarantinedSelfSeesNothing(t *testing.T) {
	repo := newTestRepository(t)
	tailnet, user := newMapperTailnet(t, repo, false)
	sm := core.NewPollMapSessionManager()

	future := time.Now().Add(time.Hour)
	self := newMapperMachine(t, repo, tailnet, user, "100.64.0.1", true, future)
	newMapperMachine(t, repo, tailnet, user, "100.64.0.2", true, future)

	mapper := NewPollNetMapper(&tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion}, self.ID, repo, sm)

	// while healthy the peer is visible
	resp, err := mapper.CreateMapResponse(context.Background(), false)
	require.NoError(t, err)
	require.Len(t, resp.Peers, 1)
	require.NotEmpty(t, resp.PacketFilter)

	// the key expires: the next delta removes the peer and closes the filter
	self.ExpiresAt = time.Now().Add(-time.Minute).UTC()
	require.NoError(t, repo.SaveMachine(context.Background(), self))

	resp, err = mapper.CreateMapResponse(context.Background(), true)
	require.NoError(t, err)
	assert.True(t, resp.Node.Expired)
	assert.Empty(t, resp.PeersChanged)
	assert.Len(t, resp.PeersRemoved, 1, "the previously synced peer must be removed")
	assert.NotNil(t, resp.PacketFilter, "an explicit empty filter, not 'unchanged'")
	assert.Empty(t, resp.PacketFilter)
	assert.Nil(t, resp.SSHPolicy)
}

func TestPollNetMapperExpiredPeerIsRemovedOnDelta(t *testing.T) {
	repo := newTestRepository(t)
	tailnet, user := newMapperTailnet(t, repo, false)
	sm := core.NewPollMapSessionManager()

	future := time.Now().Add(time.Hour)
	self := newMapperMachine(t, repo, tailnet, user, "100.64.0.1", true, future)
	peer := newMapperMachine(t, repo, tailnet, user, "100.64.0.2", true, future)

	mapper := NewPollNetMapper(&tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion}, self.ID, repo, sm)
	resp, err := mapper.CreateMapResponse(context.Background(), false)
	require.NoError(t, err)
	require.Len(t, resp.Peers, 1)

	peer.ExpiresAt = time.Now().Add(-time.Minute).UTC()
	require.NoError(t, repo.SaveMachine(context.Background(), peer))

	resp, err = mapper.CreateMapResponse(context.Background(), true)
	require.NoError(t, err)
	assert.Empty(t, resp.PeersChanged)
	assert.Equal(t, []tailcfg.NodeID{tailcfg.NodeID(peer.ID)}, resp.PeersRemoved)
	assert.Empty(t, resp.PacketFilter)
}

func TestListMachinesExpiredBetween(t *testing.T) {
	repo := newTestRepository(t)
	tailnet, user := newMapperTailnet(t, repo, false)
	ctx := context.Background()

	now := time.Now().UTC()
	inWindow := newMapperMachine(t, repo, tailnet, user, "100.64.0.1", true, now.Add(-30*time.Second))
	newMapperMachine(t, repo, tailnet, user, "100.64.0.2", true, now.Add(-10*time.Minute))
	newMapperMachine(t, repo, tailnet, user, "100.64.0.3", true, now.Add(time.Hour))
	disabled := newMapperMachine(t, repo, tailnet, user, "100.64.0.4", true, now.Add(-30*time.Second))
	disabled.KeyExpiryDisabled = true
	require.NoError(t, repo.SaveMachine(ctx, disabled))

	machines, err := repo.ListMachinesExpiredBetween(ctx, now.Add(-time.Minute), now)
	require.NoError(t, err)
	require.Len(t, machines, 1)
	assert.Equal(t, inWindow.ID, machines[0].ID)
}
