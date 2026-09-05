package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"github.com/bufbuild/connect-go"
	"github.com/jsiebens/ionscale/internal/config"
	"github.com/jsiebens/ionscale/internal/domain"
	"github.com/jsiebens/ionscale/internal/key"
	"github.com/jsiebens/ionscale/internal/token"
	"go.uber.org/zap"
	"strings"
)

var (
	errInvalidToken = connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid token"))
)

const (
	principalKey = "principalKay"
)

func CurrentPrincipal(ctx context.Context) domain.Principal {
	p := ctx.Value(principalKey)
	if p == nil {
		return domain.Principal{SystemRole: domain.SystemRoleNone, UserRole: domain.UserRoleNone}
	}
	return p.(domain.Principal)
}

// serviceTokens holds the configured static service tokens, keyed by the
// sha256 of their value so lookups compare fixed-size digests in constant time.
type serviceTokens struct {
	entries []serviceTokenEntry
}

type serviceTokenEntry struct {
	name   string
	digest [sha256.Size]byte
}

func newServiceTokens(tokens []config.ServiceToken) *serviceTokens {
	s := &serviceTokens{}
	for _, t := range tokens {
		s.entries = append(s.entries, serviceTokenEntry{name: t.Name, digest: sha256.Sum256([]byte(t.Token))})
	}
	return s
}

// lookup returns the service name for a presented token, or false when no
// configured token matches. Every entry is compared so timing does not reveal
// which (if any) token matched.
func (s *serviceTokens) lookup(value string) (string, bool) {
	if s == nil {
		return "", false
	}
	digest := sha256.Sum256([]byte(value))
	name, found := "", false
	for _, e := range s.entries {
		if subtle.ConstantTimeCompare(digest[:], e.digest[:]) == 1 {
			name, found = e.name, true
		}
	}
	return name, found
}

func AuthenticationInterceptor(systemAdminKey *key.ServerPrivate, repository domain.Repository, tokens []config.ServiceToken) connect.UnaryInterceptorFunc {
	svcTokens := newServiceTokens(tokens)
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			name := req.Spec().Procedure

			if strings.HasSuffix(name, "/GetVersion") {
				return next(ctx, req)
			}

			authorizationHeader := req.Header().Get("Authorization")
			bearerToken := strings.TrimPrefix(authorizationHeader, "Bearer ")

			if principal := exchangeToken(ctx, systemAdminKey, svcTokens, repository, bearerToken); principal != nil {
				return next(context.WithValue(ctx, principalKey, *principal), req)
			}

			return nil, errInvalidToken
		}
	}
}

func exchangeToken(ctx context.Context, systemAdminKey *key.ServerPrivate, svcTokens *serviceTokens, repository domain.Repository, value string) *domain.Principal {
	if len(value) == 0 {
		return nil
	}

	if systemAdminKey != nil && token.IsSystemAdminToken(value) {
		_, err := token.ParseSystemAdminToken(*systemAdminKey, value)
		if err == nil {
			return &domain.Principal{SystemRole: domain.SystemRoleAdmin}
		}
	}

	// service tokens are only ever matched against the configuration; a
	// svc_-prefixed value that does not match is rejected without touching
	// the database
	if strings.HasPrefix(value, config.ServiceTokenPrefix) {
		if name, ok := svcTokens.lookup(value); ok {
			return &domain.Principal{SystemRole: domain.SystemRoleAdmin, ServiceName: name}
		}
		return nil
	}

	apiKey, err := repository.LoadApiKey(ctx, value)
	if err == nil && apiKey != nil {
		user := apiKey.User
		tailnet := apiKey.Tailnet
		role := tailnet.IAMPolicy.Get().GetRole(user)

		return &domain.Principal{User: &apiKey.User, SystemRole: domain.SystemRoleNone, UserRole: role}
	}

	systemApiKey, err := repository.LoadSystemApiKey(ctx, value)
	if err == nil && systemApiKey != nil {
		return &domain.Principal{SystemRole: domain.SystemRoleAdmin}
	}

	return nil
}

func NewErrorInterceptor() *ErrorInterceptor {
	return &ErrorInterceptor{}
}

type ErrorInterceptor struct {
}

func (e *ErrorInterceptor) handleError(err error) error {
	if err == nil {
		return err
	}

	switch err.(type) {
	case *connect.Error:
		return err
	default:
		return connect.NewError(connect.CodeInternal, fmt.Errorf("internal server error"))
	}
}

func (e *ErrorInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
		response, err := next(ctx, request)
		return response, e.handleError(err)
	}
}

func (e *ErrorInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return next(ctx, spec)
	}
}

func (e *ErrorInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		err := next(ctx, conn)
		return e.handleError(err)
	}
}

func logError(err error) error {
	zap.L().WithOptions(zap.AddCallerSkip(1)).Error("error processing request", zap.Error(err))
	return err
}
