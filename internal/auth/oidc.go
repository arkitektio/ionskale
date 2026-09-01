package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/jsiebens/ionscale/internal/config"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// defaultUsernameClaim is the standard OIDC claim carrying a human-readable
// handle; providers that omit it fall back to the email.
const defaultUsernameClaim = "preferred_username"

// ErrOrganizationRequired is returned when organizations.required is set and an
// identity arrives without an organization claim. Callers match on it to show
// the identity a page explaining why it was refused.
var ErrOrganizationRequired = errors.New("identity is missing the required organization claim")

type OIDCProvider struct {
	clientID      string
	clientSecret  string
	scopes        []string
	organizations config.Organizations
	usernameClaim string
	provider      *oidc.Provider
	verifier      *oidc.IDTokenVerifier
}

func NewOIDCProvider(c *config.AuthProvider, organizations config.Organizations) (*OIDCProvider, error) {
	defaultScopes := []string{oidc.ScopeOpenID, "email", "profile"}
	provider, err := oidc.NewProvider(context.Background(), c.Issuer)
	if err != nil {
		return nil, err
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: c.ClientID, SkipClientIDCheck: c.ClientID == ""})

	usernameClaim := c.UsernameClaim
	if usernameClaim == "" {
		usernameClaim = defaultUsernameClaim
	}

	return &OIDCProvider{
		clientID:      c.ClientID,
		clientSecret:  c.ClientSecret,
		scopes:        append(defaultScopes, c.Scopes...),
		organizations: organizations,
		usernameClaim: usernameClaim,
		provider:      provider,
		verifier:      verifier,
	}, nil
}

func (p *OIDCProvider) GetLoginURL(redirectURI, state, nonce, codeVerifier string) string {
	oauth2Config := oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     p.provider.Endpoint(),
		Scopes:       p.scopes,
	}

	// nonce and PKCE are not optional in practice: providers may require both
	// for the authorization code flow, and sending them is strictly safer.
	// S256ChallengeOption derives the challenge and sets code_challenge_method.
	return oauth2Config.AuthCodeURL(state,
		oauth2.ApprovalForce,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(codeVerifier),
	)
}

func (p *OIDCProvider) Exchange(redirectURI, code, codeVerifier, nonce string) (*User, error) {
	oauth2Config := oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     p.provider.Endpoint(),
		Scopes:       p.scopes,
	}

	oauth2Token, err := oauth2Config.Exchange(context.Background(), code, oauth2.VerifierOption(codeVerifier))

	if err != nil {
		return nil, err
	}

	// Extract the ID Token from OAuth2 token.
	rawIdToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || strings.TrimSpace(rawIdToken) == "" {
		return nil, fmt.Errorf("id_token missing")
	}

	// Parse and verify ID Token payload.
	idToken, err := p.verifier.Verify(context.Background(), rawIdToken)
	if err != nil {
		return nil, err
	}

	// Binds the id_token to this specific authorization request.
	if idToken.Nonce != nonce {
		return nil, fmt.Errorf("id_token nonce does not match the authentication request")
	}

	sub, email, tokenClaims, err := p.getTokenClaims(idToken)
	if err != nil {
		return nil, err
	}

	userInfoClaims, err := p.getUserInfoClaims(oauth2Config, oauth2Token)
	if err != nil {
		return nil, err
	}

	if sub == "" {
		return nil, fmt.Errorf("id_token is missing a sub claim")
	}

	var domain string
	if i := strings.LastIndex(email, "@"); i > 0 && i < len(email)-1 {
		domain = email[i+1:]
	}

	name := email
	if name == "" {
		name = sub
	}

	user := &User{
		ID:       sub,
		Name:     name,
		Username: claimAsString(lookupClaim(p.usernameClaim, tokenClaims, userInfoClaims)),
		Attr: map[string]interface{}{
			"email":    email,
			"domain":   domain,
			"token":    tokenClaims,
			"userinfo": userInfoClaims,
		},
	}
	user.Attr["username"] = user.Username

	if p.organizations.Enabled() {
		user.Org = claimAsString(lookupClaim(p.organizations.Claim, tokenClaims, userInfoClaims))
		if p.organizations.RolesClaim != "" {
			user.Roles = claimAsStringSlice(lookupClaim(p.organizations.RolesClaim, tokenClaims, userInfoClaims))
		}
		if p.organizations.Required && user.Org == "" {
			return nil, fmt.Errorf("%w %q", ErrOrganizationRequired, p.organizations.Claim)
		}
		user.Attr["org"] = user.Org
		user.Attr["roles"] = user.Roles
	}

	return user, nil
}

// lookupClaim resolves a claim by name, preferring earlier sources (id_token
// claims before userinfo claims).
func lookupClaim(name string, sources ...map[string]interface{}) interface{} {
	if name == "" {
		return nil
	}
	for _, source := range sources {
		if v, ok := source[name]; ok && v != nil {
			return v
		}
	}
	return nil
}

func claimAsString(v interface{}) string {
	switch value := v.(type) {
	case string:
		return value
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(value)
	default:
		return ""
	}
}

func claimAsStringSlice(v interface{}) []string {
	var result []string
	switch value := v.(type) {
	case []interface{}:
		for _, e := range value {
			if s := claimAsString(e); s != "" {
				result = append(result, s)
			}
		}
	case []string:
		result = append(result, value...)
	case string:
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func (p *OIDCProvider) getTokenClaims(idToken *oidc.IDToken) (string, string, map[string]interface{}, error) {
	var raw = make(map[string]interface{})
	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}

	// Extract default claims.
	if err := idToken.Claims(&claims); err != nil {
		return "", "", nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}

	// Extract raw claims.
	if err := idToken.Claims(&raw); err != nil {
		return "", "", nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}

	return claims.Sub, claims.Email, raw, nil
}

func (p *OIDCProvider) getUserInfoClaims(config oauth2.Config, token *oauth2.Token) (map[string]interface{}, error) {
	var raw = make(map[string]interface{})

	source := config.TokenSource(context.Background(), token)

	info, err := p.provider.UserInfo(context.Background(), source)
	if err != nil {
		return nil, err
	}

	if err := info.Claims(&raw); err != nil {
		return nil, fmt.Errorf("failed to parse user info claims: %v", err)
	}

	return raw, nil
}
