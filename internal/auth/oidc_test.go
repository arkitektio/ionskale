package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookupClaimPrefersEarlierSources(t *testing.T) {
	token := map[string]interface{}{"org": "1"}
	userinfo := map[string]interface{}{"org": "2", "extra": "x"}

	assert.Equal(t, "1", claimAsString(lookupClaim("org", token, userinfo)))
	assert.Equal(t, "x", claimAsString(lookupClaim("extra", token, userinfo)))
	assert.Nil(t, lookupClaim("missing", token, userinfo))
	assert.Nil(t, lookupClaim("", token, userinfo))
}

func TestClaimAsString(t *testing.T) {
	assert.Equal(t, "7", claimAsString("7"))
	assert.Equal(t, "7", claimAsString(float64(7)))
	assert.Equal(t, "true", claimAsString(true))
	assert.Equal(t, "", claimAsString(nil))
	assert.Equal(t, "", claimAsString([]interface{}{"a"}))
}

func TestClaimAsStringSlice(t *testing.T) {
	assert.Equal(t, []string{"admin", "member"}, claimAsStringSlice([]interface{}{"admin", "member"}))
	assert.Equal(t, []string{"admin"}, claimAsStringSlice("admin"))
	assert.Equal(t, []string{"a", "b"}, claimAsStringSlice([]string{"a", "b"}))
	assert.Nil(t, claimAsStringSlice(nil))
	assert.Nil(t, claimAsStringSlice(42))
}
