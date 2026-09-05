package service

import (
	"context"
	"testing"

	"github.com/bufbuild/connect-go"
	"github.com/jsiebens/ionscale/internal/domain"
	api "github.com/jsiebens/ionscale/pkg/gen/ionscale/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func tailnetAdminCtx(t *testing.T, repo domain.Repository, tailnet *domain.Tailnet) context.Context {
	t.Helper()
	account, _, err := repo.GetOrCreateAccount(context.Background(), "admin-"+tailnet.Name, tailnet.Organization, "admin@example.com")
	require.NoError(t, err)
	user, _, err := repo.GetOrCreateUserWithAccount(context.Background(), tailnet, account)
	require.NoError(t, err)
	return context.WithValue(context.Background(), principalKey, domain.Principal{User: user, UserRole: domain.UserRoleAdmin})
}

func TestGetTailnetByOrganization(t *testing.T) {
	svc, repo := newTestService(t)

	orgTailnet := newTestTailnet(t, repo, "org-net", "42")
	newTestTailnet(t, repo, "other-net", "7")

	resp, err := svc.GetTailnetByOrganization(systemAdminCtx(), connect.NewRequest(&api.GetTailnetByOrganizationRequest{Organization: "42"}))
	require.NoError(t, err)
	assert.Equal(t, orgTailnet.ID, resp.Msg.Tailnet.Id)
	assert.Equal(t, "org-net", resp.Msg.Tailnet.Name)
	assert.Equal(t, "42", resp.Msg.Tailnet.Organization)
	// the full tailnet is returned, not the list summary
	require.NotNil(t, resp.Msg.Tailnet.DnsConfig)
	assert.NotEmpty(t, resp.Msg.Tailnet.DnsConfig.MagicDnsSuffix)

	_, err = svc.GetTailnetByOrganization(systemAdminCtx(), connect.NewRequest(&api.GetTailnetByOrganizationRequest{Organization: "nope"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	_, err = svc.GetTailnetByOrganization(systemAdminCtx(), connect.NewRequest(&api.GetTailnetByOrganizationRequest{}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	// tailnet admins cannot enumerate organizations
	_, err = svc.GetTailnetByOrganization(tailnetAdminCtx(t, repo, orgTailnet), connect.NewRequest(&api.GetTailnetByOrganizationRequest{Organization: "42"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestCreateTailnetDuplicateNameIsAlreadyExists(t *testing.T) {
	svc, repo := newTestService(t)

	existing := newTestTailnet(t, repo, "existing", "")

	_, err := svc.CreateTailnet(systemAdminCtx(), connect.NewRequest(&api.CreateTailnetRequest{Name: "existing"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))
	// the message carries the id so a JSON client can recover without details
	assert.Contains(t, err.Error(), existing.Name)

	_, err = svc.CreateTailnet(systemAdminCtx(), connect.NewRequest(&api.CreateTailnetRequest{}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestUpdateTailnetPartialFlags(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := context.Background()

	tailnet := newTestTailnet(t, repo, "net", "")
	tailnet.SSHEnabled = true
	tailnet.FileSharingEnabled = true
	require.NoError(t, repo.SaveTailnet(ctx, tailnet))

	// flipping one flag leaves the others untouched
	resp, err := svc.UpdateTailnet(systemAdminCtx(), connect.NewRequest(&api.UpdateTailnetRequest{
		TailnetId:                   tailnet.ID,
		MachineAuthorizationEnabled: proto.Bool(true),
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Tailnet.MachineAuthorizationEnabled)
	assert.True(t, resp.Msg.Tailnet.SshEnabled)
	assert.True(t, resp.Msg.Tailnet.FileSharingEnabled)
	assert.False(t, resp.Msg.Tailnet.ServiceCollectionEnabled)

	// an explicit false still turns a flag off
	resp, err = svc.UpdateTailnet(systemAdminCtx(), connect.NewRequest(&api.UpdateTailnetRequest{
		TailnetId:  tailnet.ID,
		SshEnabled: proto.Bool(false),
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Tailnet.SshEnabled)
	assert.True(t, resp.Msg.Tailnet.MachineAuthorizationEnabled)
}

func TestUpdateTailnetRename(t *testing.T) {
	svc, repo := newTestService(t)

	tailnet := newTestTailnet(t, repo, "old-name", "42")
	newTestTailnet(t, repo, "taken", "")

	// rename requires system admin
	_, err := svc.UpdateTailnet(tailnetAdminCtx(t, repo, tailnet), connect.NewRequest(&api.UpdateTailnetRequest{TailnetId: tailnet.ID, Name: "new-name"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	// but a tailnet admin may still update the tailnet without renaming
	_, err = svc.UpdateTailnet(tailnetAdminCtx(t, repo, tailnet), connect.NewRequest(&api.UpdateTailnetRequest{TailnetId: tailnet.ID, Name: "old-name", SshEnabled: proto.Bool(true)}))
	require.NoError(t, err)

	// collisions are AlreadyExists
	_, err = svc.UpdateTailnet(systemAdminCtx(), connect.NewRequest(&api.UpdateTailnetRequest{TailnetId: tailnet.ID, Name: "taken"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))

	resp, err := svc.UpdateTailnet(systemAdminCtx(), connect.NewRequest(&api.UpdateTailnetRequest{TailnetId: tailnet.ID, Name: "new-name"}))
	require.NoError(t, err)
	assert.Equal(t, "new-name", resp.Msg.Tailnet.Name)
	assert.Equal(t, "42", resp.Msg.Tailnet.Organization)
	assert.Contains(t, resp.Msg.Tailnet.DnsConfig.MagicDnsSuffix, "new-name.")
	// the ssh flag set earlier survived the rename
	assert.True(t, resp.Msg.Tailnet.SshEnabled)

	byOrg, err := svc.GetTailnetByOrganization(systemAdminCtx(), connect.NewRequest(&api.GetTailnetByOrganizationRequest{Organization: "42"}))
	require.NoError(t, err)
	assert.Equal(t, "new-name", byOrg.Msg.Tailnet.Name)
}

func TestListUsersExternalID(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := context.Background()

	tailnet := newTestTailnet(t, repo, "net", "42")
	account, _, err := repo.GetOrCreateAccount(ctx, "sub-123", "42", "john@example.com")
	require.NoError(t, err)
	_, _, err = repo.GetOrCreateUserWithAccount(ctx, tailnet, account)
	require.NoError(t, err)
	// service users are never listed
	_, _, err = repo.GetOrCreateServiceUser(ctx, tailnet)
	require.NoError(t, err)

	resp, err := svc.ListUsers(systemAdminCtx(), connect.NewRequest(&api.ListUsersRequest{TailnetId: tailnet.ID}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Users, 1)
	assert.Equal(t, "sub-123", resp.Msg.Users[0].ExternalId)
}
