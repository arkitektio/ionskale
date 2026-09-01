package auth

type Provider interface {
	// GetLoginURL builds the authorization request. nonce and codeVerifier are
	// per-request secrets carried in the sealed OAuth state; the verifier is
	// sent as an S256 code_challenge and replayed at Exchange.
	GetLoginURL(redirectURI, state, nonce, codeVerifier string) string
	Exchange(redirectURI, code, codeVerifier, nonce string) (*User, error)
}

type User struct {
	ID   string
	Name string
	// Username is the identity's human-readable handle, from the configured
	// username claim. Empty when the provider does not send one.
	Username string
	// Org is the organization identifier resolved from the configured
	// organization claim; empty when organization scoping is disabled or the
	// identity carries no organization.
	Org string
	// Roles are the identity's role identifiers within its organization.
	Roles []string
	Attr  map[string]interface{}
}

// LoginName is what a Tailscale client shows for this identity: the username
// when the provider supplies one, otherwise the email that Name carries.
// Name stays the email so IAM policies keep matching on it.
func (u *User) LoginName() string {
	if u.Username != "" {
		return u.Username
	}
	return u.Name
}
