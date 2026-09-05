package service

import (
	"context"
	"strings"
	"testing"

	"github.com/jsiebens/ionscale/internal/config"
	"github.com/jsiebens/ionscale/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testServiceTokenLok   = "svc_" + "lok-0123456789abcdef0123456789abcdef"
	testServiceTokenOther = "svc_" + "other-0123456789abcdef0123456789abcd"
)

func testServiceTokens() *serviceTokens {
	return newServiceTokens([]config.ServiceToken{
		{Name: "lok", Token: testServiceTokenLok},
		{Name: "other", Token: testServiceTokenOther},
	})
}

func TestServiceTokenLookup(t *testing.T) {
	tokens := testServiceTokens()

	name, ok := tokens.lookup(testServiceTokenLok)
	require.True(t, ok)
	assert.Equal(t, "lok", name)

	name, ok = tokens.lookup(testServiceTokenOther)
	require.True(t, ok)
	assert.Equal(t, "other", name)

	// prefix matches and near misses are rejected
	_, ok = tokens.lookup(testServiceTokenLok[:len(testServiceTokenLok)-1])
	assert.False(t, ok)
	_, ok = tokens.lookup(testServiceTokenLok + "x")
	assert.False(t, ok)
	_, ok = tokens.lookup("")
	assert.False(t, ok)

	// no tokens configured at all
	var none *serviceTokens
	_, ok = none.lookup(testServiceTokenLok)
	assert.False(t, ok)
}

func TestExchangeServiceToken(t *testing.T) {
	_, repo := newTestService(t)
	ctx := context.Background()
	tokens := testServiceTokens()

	principal := exchangeToken(ctx, nil, tokens, repo, testServiceTokenLok)
	require.NotNil(t, principal)
	assert.True(t, principal.IsSystemAdmin())
	assert.Equal(t, "lok", principal.ServiceName)
	assert.Nil(t, principal.User)

	// an unknown svc_ token is rejected outright and never falls through to
	// the api key lookup
	assert.Nil(t, exchangeToken(ctx, nil, tokens, repo, "svc_"+strings.Repeat("z", 40)))
	assert.Nil(t, exchangeToken(ctx, nil, newServiceTokens(nil), repo, testServiceTokenLok))

	// other credentials are still refused when they do not exist
	assert.Nil(t, exchangeToken(ctx, nil, tokens, repo, "not-a-token"))
	assert.Nil(t, exchangeToken(ctx, nil, tokens, repo, ""))
}

func TestServiceTokenPrincipalIsNotATailnetUser(t *testing.T) {
	p := domain.Principal{SystemRole: domain.SystemRoleAdmin, ServiceName: "lok"}
	assert.True(t, p.IsSystemAdmin())
	assert.Nil(t, p.User)
}
