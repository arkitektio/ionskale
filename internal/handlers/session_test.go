package handlers

import (
	"testing"
	"time"

	"github.com/jsiebens/ionscale/internal/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthSessionRoundTrip(t *testing.T) {
	k := key.NewServerKey()

	session := &authSession{
		Flow:        AuthFlowClient,
		Key:         "abcd1234",
		AccountID:   42,
		SystemAdmin: true,
		TailnetIDs:  []uint64{1, 2, 3},
		ExpiresAt:   time.Now().Add(time.Minute),
	}

	sealed, err := sealAuthSession(k, session)
	require.NoError(t, err)

	opened, err := openAuthSession(k, sealed)
	require.NoError(t, err)

	assert.Equal(t, session.Flow, opened.Flow)
	assert.Equal(t, session.Key, opened.Key)
	assert.Equal(t, session.AccountID, opened.AccountID)
	assert.Equal(t, session.SystemAdmin, opened.SystemAdmin)
	assert.Equal(t, session.TailnetIDs, opened.TailnetIDs)
}

func TestAuthSessionRejectsExpired(t *testing.T) {
	k := key.NewServerKey()

	sealed, err := sealAuthSession(k, &authSession{
		Flow:      AuthFlowClient,
		Key:       "abcd1234",
		AccountID: 42,
		ExpiresAt: time.Now().Add(-time.Second),
	})
	require.NoError(t, err)

	_, err = openAuthSession(k, sealed)
	assert.Error(t, err)
}

func TestAuthSessionRejectsMissingOrTampered(t *testing.T) {
	k := key.NewServerKey()

	_, err := openAuthSession(k, "")
	assert.Error(t, err)

	_, err = openAuthSession(k, "not-a-session")
	assert.Error(t, err)

	sealed, err := sealAuthSession(k, &authSession{
		Flow:      AuthFlowClient,
		Key:       "abcd1234",
		AccountID: 42,
		ExpiresAt: time.Now().Add(time.Minute),
	})
	require.NoError(t, err)

	// sealed with a different server key
	otherKey := key.NewServerKey()
	_, err = openAuthSession(otherKey, sealed)
	assert.Error(t, err)
}

func TestAuthSessionAllowsTailnet(t *testing.T) {
	session := &authSession{TailnetIDs: []uint64{1, 5}}

	assert.True(t, session.allowsTailnet(1))
	assert.True(t, session.allowsTailnet(5))
	assert.False(t, session.allowsTailnet(2))
	assert.False(t, session.allowsTailnet(0))
}
