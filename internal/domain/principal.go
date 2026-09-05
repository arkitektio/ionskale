package domain

type Principal struct {
	SystemRole SystemRole
	User       *User
	UserRole   UserRole
	// ServiceName is set when the caller authenticated with a static service
	// token; such principals are system admins acting on behalf of a service.
	ServiceName string
}

func (p Principal) IsSystemAdmin() bool {
	return p.SystemRole.IsAdmin()
}

func (p Principal) IsTailnetAdmin(tailnetID uint64) bool {
	return p.User.TailnetID == tailnetID && p.UserRole.IsAdmin()
}

func (p Principal) IsTailnetMember(tailnetID uint64) bool {
	return p.User.TailnetID == tailnetID
}

func (p Principal) UserMatches(userID uint64) bool {
	return p.User.ID == userID
}
