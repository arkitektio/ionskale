package auth

type Provider interface {
	GetLoginURL(redirectURI, state string) string
	Exchange(redirectURI, code string) (*User, error)
}

type User struct {
	ID   string
	Name string
	// Org is the organization identifier resolved from the configured
	// organization claim; empty when organization scoping is disabled or the
	// identity carries no organization.
	Org string
	// Roles are the identity's role identifiers within its organization.
	Roles []string
	Attr  map[string]interface{}
}
