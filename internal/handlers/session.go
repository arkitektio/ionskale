package handlers

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/jsiebens/ionscale/internal/key"
	"github.com/mr-tron/base58"
)

const authSessionLifetime = 15 * time.Minute

// authSession captures the outcome of a verified OIDC exchange so that the
// subsequent form POST (tailnet selection / system-admin continuation) cannot
// escalate beyond what the identity was actually granted. It is sealed with a
// server-held key and handed to the browser as an opaque token; the final
// authorization decision in EndAuth is made against the sealed contents, never
// against client-supplied identifiers.
type authSession struct {
	Flow          AuthFlow  `json:"flow"`
	Key           string    `json:"key"`
	AccountID     uint64    `json:"aid"`
	SystemAdmin   bool      `json:"sad"`
	TailnetIDs    []uint64  `json:"tids"`
	AdminTailnets []uint64  `json:"atids,omitempty"`
	ExpiresAt     time.Time `json:"exp"`
}

func (s *authSession) allowsTailnet(id uint64) bool {
	for _, t := range s.TailnetIDs {
		if t == id {
			return true
		}
	}
	return false
}

func sealAuthSession(k key.ServerPrivate, s *authSession) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return base58.FastBase58Encoding(k.Seal(b)), nil
}

func openAuthSession(k key.ServerPrivate, raw string) (*authSession, error) {
	if raw == "" {
		return nil, errors.New("missing auth session")
	}
	decoded, err := base58.FastBase58Decoding(raw)
	if err != nil {
		return nil, errors.New("invalid auth session")
	}
	plain, ok := k.Open(decoded)
	if !ok {
		return nil, errors.New("invalid auth session")
	}
	session := &authSession{}
	if err := json.Unmarshal(plain, session); err != nil {
		return nil, errors.New("invalid auth session")
	}
	if session.ExpiresAt.IsZero() || time.Now().After(session.ExpiresAt) {
		return nil, errors.New("auth session expired")
	}
	return session, nil
}
