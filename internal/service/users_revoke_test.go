package service

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/bufbuild/connect-go"
	"github.com/jsiebens/ionscale/internal/config"
	"github.com/jsiebens/ionscale/internal/core"
	"github.com/jsiebens/ionscale/internal/database"
	"github.com/jsiebens/ionscale/internal/domain"
	"github.com/jsiebens/ionscale/internal/util"
	api "github.com/jsiebens/ionscale/pkg/gen/ionscale/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newTestService(t *testing.T) (*Service, domain.Repository) {
	t.Helper()
	util.EnsureIDProvider()
	dir := t.TempDir()
	cfg := &config.Database{Type: "sqlite", Url: filepath.Join(dir, "test.db") + "?_pragma=foreign_keys(ON)"}
	_, repo, err := database.OpenDB(cfg, zap.NewNop())
	require.NoError(t, err)
	svc := NewService(&config.Config{}, nil, nil, repo, core.NewPollMapSessionManager())
	return svc, repo
}

func systemAdminCtx() context.Context {
	return context.WithValue(context.Background(), principalKey, domain.Principal{SystemRole: domain.SystemRoleAdmin})
}

func newTestTailnet(t *testing.T, repo domain.Repository, name, org string) *domain.Tailnet {
	t.Helper()
	tailnet := &domain.Tailnet{
		ID:           util.NextID(),
		Name:         name,
		Organization: org,
		IAMPolicy:    domain.NewHuJSON(&domain.IAMPolicy{}),
		ACLPolicy:    domain.NewHuJSON(&domain.ACLPolicy{}),
	}
	require.NoError(t, repo.SaveTailnet(context.Background(), tailnet))
	return tailnet
}

func newTestMachine(t *testing.T, repo domain.Repository, tailnet *domain.Tailnet, user *domain.User, ip string) *domain.Machine {
	t.Helper()
	addr := netip.MustParseAddr(ip)
	m := &domain.Machine{
		ID:        util.NextID(),
		Name:      "m-" + ip,
		IPv4:      domain.IP{Addr: &addr},
		UserID:    user.ID,
		TailnetID: tailnet.ID,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}
	require.NoError(t, repo.SaveMachine(context.Background(), m))
	return m
}

func TestRevokeAccountScopedToOrganization(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := context.Background()

	orgTailnet := newTestTailnet(t, repo, "org-net", "42")
	otherOrgTailnet := newTestTailnet(t, repo, "other-net", "7")

	// The same subject in two organizations is two accounts, since accounts are
	// keyed on (external id, organization).
	orgAccount, _, err := repo.GetOrCreateAccount(ctx, "sub1", "42", "john@example.com")
	require.NoError(t, err)
	otherAccount, _, err := repo.GetOrCreateAccount(ctx, "sub1", "7", "john@example.com")
	require.NoError(t, err)
	require.NotEqual(t, orgAccount.ID, otherAccount.ID)

	orgUser, _, err := repo.GetOrCreateUserWithAccount(ctx, orgTailnet, orgAccount)
	require.NoError(t, err)
	otherUser, _, err := repo.GetOrCreateUserWithAccount(ctx, otherOrgTailnet, otherAccount)
	require.NoError(t, err)

	newTestMachine(t, repo, orgTailnet, orgUser, "100.64.0.1")
	newTestMachine(t, repo, otherOrgTailnet, otherUser, "100.64.0.2")

	_, apiKey := domain.CreateApiKey(orgTailnet, orgUser, nil)
	require.NoError(t, repo.SaveApiKey(ctx, apiKey))
	_, authKey := domain.CreateAuthKey(orgTailnet, orgUser, false, false, nil, nil)
	require.NoError(t, repo.SaveAuthKey(ctx, authKey))

	resp, err := svc.RevokeAccount(systemAdminCtx(), connect.NewRequest(&api.RevokeAccountRequest{ExternalId: "sub1", Organization: "42"}))
	require.NoError(t, err)
	assert.Equal(t, []uint64{orgTailnet.ID}, resp.Msg.TailnetIds)

	// everything in the org tailnet is gone
	gone, err := repo.GetUser(ctx, orgUser.ID)
	require.NoError(t, err)
	assert.Nil(t, gone)
	machines, err := repo.ListMachineByTailnet(ctx, orgTailnet.ID)
	require.NoError(t, err)
	assert.Empty(t, machines)
	authKeys, err := repo.ListAuthKeys(ctx, orgTailnet.ID)
	require.NoError(t, err)
	assert.Empty(t, authKeys)

	// the other organization's tailnet is untouched
	kept, err := repo.GetUser(ctx, otherUser.ID)
	require.NoError(t, err)
	require.NotNil(t, kept)
	otherMachines, err := repo.ListMachineByTailnet(ctx, otherOrgTailnet.ID)
	require.NoError(t, err)
	assert.Len(t, otherMachines, 1)
}

func TestRevokeAccountAllTailnets(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := context.Background()

	a := newTestTailnet(t, repo, "net-a", "42")
	b := newTestTailnet(t, repo, "net-b", "")

	// Two accounts for one subject: revoking without an organization must reach
	// across all of them, not just the one that happens to be found first.
	accountA, _, err := repo.GetOrCreateAccount(ctx, "sub1", "42", "john@example.com")
	require.NoError(t, err)
	accountB, _, err := repo.GetOrCreateAccount(ctx, "sub1", "", "john@example.com")
	require.NoError(t, err)

	userA, _, err := repo.GetOrCreateUserWithAccount(ctx, a, accountA)
	require.NoError(t, err)
	userB, _, err := repo.GetOrCreateUserWithAccount(ctx, b, accountB)
	require.NoError(t, err)

	resp, err := svc.RevokeAccount(systemAdminCtx(), connect.NewRequest(&api.RevokeAccountRequest{ExternalId: "sub1"}))
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint64{a.ID, b.ID}, resp.Msg.TailnetIds)

	for _, id := range []uint64{userA.ID, userB.ID} {
		u, err := repo.GetUser(ctx, id)
		require.NoError(t, err)
		assert.Nil(t, u)
	}
}

func TestRevokeAccountAuthz(t *testing.T) {
	svc, _ := newTestService(t)

	// no principal -> permission denied
	_, err := svc.RevokeAccount(context.Background(), connect.NewRequest(&api.RevokeAccountRequest{ExternalId: "sub1"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	// unknown account -> not found
	_, err = svc.RevokeAccount(systemAdminCtx(), connect.NewRequest(&api.RevokeAccountRequest{ExternalId: "nope"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	// missing external id -> invalid argument
	_, err = svc.RevokeAccount(systemAdminCtx(), connect.NewRequest(&api.RevokeAccountRequest{}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestCreateTailnetRejectsDuplicateOrganization(t *testing.T) {
	svc, repo := newTestService(t)

	newTestTailnet(t, repo, "existing", "42")

	_, err := svc.CreateTailnet(systemAdminCtx(), connect.NewRequest(&api.CreateTailnetRequest{Name: "another", Organization: "42"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))

	// a different organization is fine
	resp, err := svc.CreateTailnet(systemAdminCtx(), connect.NewRequest(&api.CreateTailnetRequest{Name: "another", Organization: "7"}))
	require.NoError(t, err)
	assert.Equal(t, "7", resp.Msg.Tailnet.Organization)
}

func TestListTailnetsOrgFilterRequiresSystemAdmin(t *testing.T) {
	svc, repo := newTestService(t)

	newTestTailnet(t, repo, "org-net", "42")
	newTestTailnet(t, repo, "other-net", "7")

	_, err := svc.ListTailnets(context.Background(), connect.NewRequest(&api.ListTailnetsRequest{Organization: "42"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	resp, err := svc.ListTailnets(systemAdminCtx(), connect.NewRequest(&api.ListTailnetsRequest{Organization: "42"}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Tailnet, 1)
	assert.Equal(t, "org-net", resp.Msg.Tailnet[0].Name)
}
