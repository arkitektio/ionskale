// Package audit emits structured audit events for security-relevant actions:
// logins, tailnet lifecycle, policy changes, key issuance and revocations.
// Events are logged at Info level on a dedicated "audit" logger so they can be
// filtered or shipped separately (e.g. with logging.format: json).
package audit

import (
	"github.com/jsiebens/ionscale/internal/domain"
	"go.uber.org/zap"
)

func Log(event string, fields ...zap.Field) {
	zap.L().Named("audit").Info(event, fields...)
}

// Actor describes the principal performing an audited action.
func Actor(p domain.Principal) zap.Field {
	if p.User != nil {
		return zap.String("actor", p.User.Name)
	}
	if p.IsSystemAdmin() {
		return zap.String("actor", "system-admin")
	}
	return zap.String("actor", "anonymous")
}

func Tailnet(t *domain.Tailnet) []zap.Field {
	if t == nil {
		return nil
	}
	fields := []zap.Field{zap.Uint64("tailnet_id", t.ID), zap.String("tailnet", t.Name)}
	if t.Organization != "" {
		fields = append(fields, zap.String("org", t.Organization))
	}
	return fields
}
