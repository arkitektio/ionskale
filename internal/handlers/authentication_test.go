package handlers

import (
	"testing"

	"github.com/jsiebens/ionscale/internal/auth"
	"github.com/jsiebens/ionscale/internal/config"
	"github.com/jsiebens/ionscale/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func orgConfig() config.Organizations {
	return config.Organizations{
		Claim:      "org",
		RolesClaim: "roles",
		AdminRoles: []string{"admin"},
	}
}

func tailnetWithPolicy(t *testing.T, org string, policy *domain.IAMPolicy) domain.Tailnet {
	t.Helper()
	if policy == nil {
		policy = &domain.IAMPolicy{}
	}
	return domain.Tailnet{
		ID:           1,
		Name:         "test",
		Organization: org,
		IAMPolicy:    domain.NewHuJSON(policy),
	}
}

func TestOrgTailnetAdmitsSameOrg(t *testing.T) {
	user := &auth.User{ID: "sub1", Name: "john@example.com", Org: "7", Attr: map[string]interface{}{}}
	tailnet := tailnetWithPolicy(t, "7", nil)

	ok, err := tailnetAccessible(orgConfig(), tailnet, user)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestOrgTailnetRejectsOtherOrgEvenWithWildcardPolicy(t *testing.T) {
	user := &auth.User{ID: "sub1", Name: "john@example.com", Org: "8", Attr: map[string]interface{}{}}
	tailnet := tailnetWithPolicy(t, "7", &domain.IAMPolicy{Filters: []string{"*"}})

	ok, err := tailnetAccessible(orgConfig(), tailnet, user)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestOrgTailnetRejectsUserWithoutOrg(t *testing.T) {
	user := &auth.User{ID: "sub1", Name: "john@example.com", Attr: map[string]interface{}{}}
	tailnet := tailnetWithPolicy(t, "7", nil)

	ok, err := tailnetAccessible(orgConfig(), tailnet, user)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestOrgTailnetHiddenWhenOrgScopingDisabled(t *testing.T) {
	user := &auth.User{ID: "sub1", Name: "john@example.com", Org: "7", Attr: map[string]interface{}{}}
	tailnet := tailnetWithPolicy(t, "7", nil)

	ok, err := tailnetAccessible(config.Organizations{}, tailnet, user)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestOrgTailnetPolicyRestrictsWithinOrg(t *testing.T) {
	tailnet := tailnetWithPolicy(t, "7", &domain.IAMPolicy{Emails: []string{"jane@example.com"}})

	jane := &auth.User{ID: "sub2", Name: "jane@example.com", Org: "7", Attr: map[string]interface{}{}}
	ok, err := tailnetAccessible(orgConfig(), tailnet, jane)
	require.NoError(t, err)
	assert.True(t, ok)

	john := &auth.User{ID: "sub1", Name: "john@example.com", Org: "7", Attr: map[string]interface{}{}}
	ok, err = tailnetAccessible(orgConfig(), tailnet, john)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestOrgLessTailnetKeepsIAMPolicySemanticsForOrgLessUsers(t *testing.T) {
	tailnet := tailnetWithPolicy(t, "", &domain.IAMPolicy{Emails: []string{"john@example.com"}})

	john := &auth.User{ID: "sub1", Name: "john@example.com", Attr: map[string]interface{}{}}
	ok, err := tailnetAccessible(orgConfig(), tailnet, john)
	require.NoError(t, err)
	assert.True(t, ok)

	jane := &auth.User{ID: "sub2", Name: "jane@example.com", Attr: map[string]interface{}{}}
	ok, err = tailnetAccessible(orgConfig(), tailnet, jane)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestOrgUserNeverSeesOrgLessTailnets(t *testing.T) {
	// a membership maps to exactly one tailnet: an identity carrying an
	// organization is excluded from org-less tailnets even when the IAM
	// policy would admit it
	tailnet := tailnetWithPolicy(t, "", &domain.IAMPolicy{Emails: []string{"john@example.com"}})

	john := &auth.User{ID: "sub1", Name: "john@example.com", Org: "7", Attr: map[string]interface{}{}}
	ok, err := tailnetAccessible(orgConfig(), tailnet, john)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestOrgLessTailnetEmptyPolicyAdmitsNobody(t *testing.T) {
	tailnet := tailnetWithPolicy(t, "", nil)

	john := &auth.User{ID: "sub1", Name: "john@example.com", Attr: map[string]interface{}{}}
	ok, err := tailnetAccessible(orgConfig(), tailnet, john)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestOrgRolesFilterExpression(t *testing.T) {
	// bexpr filters can match on the hoisted roles attribute within an org
	tailnet := tailnetWithPolicy(t, "7", &domain.IAMPolicy{Filters: []string{`roles contains "operator"`}})

	operator := &auth.User{ID: "sub1", Name: "john@example.com", Org: "7", Attr: map[string]interface{}{"roles": []string{"operator"}}}
	ok, err := tailnetAccessible(orgConfig(), tailnet, operator)
	require.NoError(t, err)
	assert.True(t, ok)

	member := &auth.User{ID: "sub2", Name: "jane@example.com", Org: "7", Attr: map[string]interface{}{"roles": []string{}}}
	ok, err = tailnetAccessible(orgConfig(), tailnet, member)
	require.NoError(t, err)
	assert.False(t, ok)
}
