package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jsiebens/ionscale/internal/addr"
	"github.com/jsiebens/ionscale/internal/audit"
	"github.com/jsiebens/ionscale/internal/auth"
	tpl "github.com/jsiebens/ionscale/internal/templates"
	"github.com/labstack/echo/v4/middleware"
	"github.com/mr-tron/base58"
	"go.uber.org/zap"
	"tailscale.com/tailcfg"

	"github.com/jsiebens/ionscale/internal/config"
	"github.com/jsiebens/ionscale/internal/domain"
	"github.com/jsiebens/ionscale/internal/key"
	"github.com/jsiebens/ionscale/internal/util"
	"github.com/labstack/echo/v4"
	"tailscale.com/util/dnsname"
)

func NewAuthenticationHandlers(
	config *config.Config,
	authProvider auth.Provider,
	systemIAMPolicy *domain.IAMPolicy,
	sessionKey key.ServerPrivate,
	repository domain.Repository) *AuthenticationHandlers {

	return &AuthenticationHandlers{
		config:          config,
		authProvider:    authProvider,
		repository:      repository,
		systemIAMPolicy: systemIAMPolicy,
		sessionKey:      sessionKey,
	}
}

type AuthenticationHandlers struct {
	repository      domain.Repository
	authProvider    auth.Provider
	config          *config.Config
	systemIAMPolicy *domain.IAMPolicy
	sessionKey      key.ServerPrivate
}

type AuthInput struct {
	Key     string   `param:"key"`
	Flow    AuthFlow `param:"flow"`
	AuthKey string   `query:"ak" form:"ak"`
	Oidc    bool     `query:"oidc" form:"oidc"`
}

type EndAuthForm struct {
	AccountID     uint64 `form:"aid"`
	TailnetID     uint64 `form:"tid"`
	AsSystemAdmin bool   `form:"sad"`
	AuthKey       string `form:"ak"`
	State         string `form:"state"`
	Session       string `form:"sid"`
}

type oauthState struct {
	Key       string
	Flow      AuthFlow
	ExpiresAt time.Time
	// Nonce and CodeVerifier are generated per authorization request and
	// replayed at the callback to bind the id_token and the code exchange to
	// it. Safe to keep here: the state blob is sealed with a server-held key.
	Nonce        string
	CodeVerifier string
}

type AuthFlow string

const (
	AuthFlowMachineRegistration = "r"
	AuthFlowClient              = "c"
	AuthFlowSSHCheckFlow        = "s"
)

func (h *AuthenticationHandlers) StartAuth(c echo.Context) error {
	ctx := c.Request().Context()

	var input AuthInput
	if err := c.Bind(&input); err != nil {
		return logError(err)
	}

	// machine registration auth flow
	if input.Flow == AuthFlowMachineRegistration {
		req, err := h.repository.GetRegistrationRequestByKey(ctx, input.Key)
		if err != nil || req == nil {
			return logError(err)
		}

		if input.Oidc && h.authProvider != nil {
			goto startOidc
		}

		if input.AuthKey != "" {
			return h.endMachineRegistrationFlow(c, EndAuthForm{AuthKey: input.AuthKey}, req)
		}

		// with an OIDC provider configured, skip the login chooser and go
		// straight to the identity provider; auth keys are still accepted via
		// `tailscale up --authkey` or the `ak` query parameter
		if h.authProvider != nil {
			goto startOidc
		}

		csrf := c.Get(middleware.DefaultCSRFConfig.ContextKey).(string)
		return c.Render(http.StatusOK, "", tpl.Auth(false, csrf))
	}

	// cli auth flow
	if input.Flow == AuthFlowClient {
		if s, err := h.repository.GetAuthenticationRequest(ctx, input.Key); err != nil || s == nil {
			return logError(err)
		}
	}

	// ssh check auth flow
	if input.Flow == AuthFlowSSHCheckFlow {
		if s, err := h.repository.GetSSHActionRequest(ctx, input.Key); err != nil || s == nil {
			return logError(err)
		}
	}

	if h.authProvider == nil {
		return logError(fmt.Errorf("unable to start auth flow as no auth provider is configured"))
	}

startOidc:

	state, nonce, codeVerifier, err := h.createState(input.Flow, input.Key)
	if err != nil {
		return logError(err)
	}

	redirectUrl := h.authProvider.GetLoginURL(h.config.CreateUrl("/a/callback"), state, nonce, codeVerifier)

	return c.Redirect(http.StatusFound, redirectUrl)
}

func (h *AuthenticationHandlers) ProcessAuth(c echo.Context) error {
	ctx := c.Request().Context()

	var input AuthInput
	if err := c.Bind(&input); err != nil {
		return logError(err)
	}

	req, err := h.repository.GetRegistrationRequestByKey(ctx, input.Key)
	if err != nil || req == nil {
		return logError(err)
	}

	if input.AuthKey != "" {
		return h.endMachineRegistrationFlow(c, EndAuthForm{AuthKey: input.AuthKey}, req)
	}

	if input.Oidc {
		state, nonce, codeVerifier, err := h.createState(input.Flow, input.Key)
		if err != nil {
			return logError(err)
		}

		redirectUrl := h.authProvider.GetLoginURL(h.config.CreateUrl("/a/callback"), state, nonce, codeVerifier)

		return c.Redirect(http.StatusFound, redirectUrl)
	}

	return c.Redirect(http.StatusFound, fmt.Sprintf("/a/%s/%s", input.Flow, input.Key))
}

func (h *AuthenticationHandlers) Callback(c echo.Context) error {
	ctx := c.Request().Context()

	// The provider reports a failed authorization by redirecting back here with
	// an error parameter and no code. Without this check the empty code was fed
	// to the token endpoint, and its "invalid code" reply surfaced as an opaque
	// 500 that hid the provider's actual complaint.
	if e := c.QueryParam("error"); e != "" {
		zap.L().Error("authentication provider returned an error",
			zap.String("error", e),
			zap.String("error_description", c.QueryParam("error_description")))
		return c.Redirect(http.StatusFound, "/a/error?e=idp")
	}

	code := c.QueryParam("code")
	state, err := h.readState(c.QueryParam("state"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid state parameter")
	}

	user, err := h.exchangeUser(code, state.CodeVerifier, state.Nonce)
	if err != nil {
		// This one is a policy decision, not a broken exchange: the identity
		// authenticated fine but carries no organization. It has a page that
		// explains that, and reaching it beats a bare 500.
		if errors.Is(err, auth.ErrOrganizationRequired) {
			return c.Redirect(http.StatusFound, "/a/error?e=ua-org-required")
		}
		return logError(err)
	}

	account, _, err := h.repository.GetOrCreateAccount(ctx, user.ID, user.Org, user.LoginName())
	if err != nil {
		return logError(err)
	}

	if err := h.repository.SetAccountLastAuthenticated(ctx, account.ID); err != nil {
		return logError(err)
	}

	if state.Flow == AuthFlowSSHCheckFlow {
		sshActionReq, err := h.repository.GetSSHActionRequest(ctx, state.Key)
		if err != nil || sshActionReq == nil {
			return c.Redirect(http.StatusFound, "/a/error?e=ua")
		}

		machine, err := h.repository.GetMachine(ctx, sshActionReq.SrcMachineID)
		if err != nil || sshActionReq == nil {
			return logError(err)
		}

		if !machine.HasTags() && machine.User.AccountID != nil && *machine.User.AccountID == account.ID {
			sshActionReq.Action = "accept"

			err := h.repository.Transaction(func(rp domain.Repository) error {
				if err := rp.SetUserLastAuthenticated(ctx, machine.UserID, time.Now().UTC()); err != nil {
					return err
				}
				if err := rp.SaveSSHActionRequest(ctx, sshActionReq); err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				return logError(err)
			}

			return c.Redirect(http.StatusFound, "/a/success")
		}

		sshActionReq.Action = "reject"
		if err := h.repository.SaveSSHActionRequest(ctx, sshActionReq); err != nil {
			return logError(err)
		}
		return c.Redirect(http.StatusFound, "/a/error?e=nmo")
	}

	if err := h.syncOrgRoles(ctx, user); err != nil {
		return logError(err)
	}

	tailnets, err := h.listAvailableTailnets(ctx, user)
	if err != nil {
		return logError(err)
	}

	csrf := c.Get(middleware.DefaultCSRFConfig.ContextKey).(string)

	if state.Flow == AuthFlowMachineRegistration {
		if len(tailnets) == 0 {
			audit.Log("login.refused", zap.String("actor", user.Name), zap.String("org", user.Org), zap.String("flow", "machine"))
			registrationRequest, err := h.repository.GetRegistrationRequestByKey(ctx, state.Key)
			if err == nil && registrationRequest != nil {
				registrationRequest.Error = "unauthorized"
				_ = h.repository.SaveRegistrationRequest(ctx, registrationRequest)
			}
			return c.Redirect(http.StatusFound, "/a/error?e="+h.denialCode(ctx, user))
		}

		if len(tailnets) == 1 {
			req, err := h.repository.GetRegistrationRequestByKey(ctx, state.Key)
			if err != nil {
				return logError(err)
			}
			if req == nil {
				return logError(fmt.Errorf("invalid registration key"))
			}
			return h.endMachineRegistrationFlow(c, EndAuthForm{AccountID: account.ID, TailnetID: tailnets[0].ID}, req)
		}

		session, err := h.createSession(state, account.ID, false, tailnets)
		if err != nil {
			return logError(err)
		}

		return c.Render(http.StatusOK, "", tpl.Tailnets(session, false, tailnets, csrf))
	}

	if state.Flow == AuthFlowClient {
		isSystemAdmin, err := h.isSystemAdmin(user)
		if err != nil {
			return logError(err)
		}

		if !isSystemAdmin && len(tailnets) == 0 {
			audit.Log("login.refused", zap.String("actor", user.Name), zap.String("org", user.Org), zap.String("flow", "cli"))
			req, err := h.repository.GetAuthenticationRequest(ctx, state.Key)
			if err == nil && req != nil {
				req.Error = "unauthorized"
				_ = h.repository.SaveAuthenticationRequest(ctx, req)
			}
			return c.Redirect(http.StatusFound, "/a/error?e="+h.denialCode(ctx, user))
		}

		// with exactly one tailnet and no system-admin continuation to offer,
		// there is nothing to choose: finish the login right away
		if !isSystemAdmin && len(tailnets) == 1 {
			req, err := h.repository.GetAuthenticationRequest(ctx, state.Key)
			if err != nil {
				return logError(err)
			}
			if req == nil {
				return logError(fmt.Errorf("invalid authentication key"))
			}
			return h.endCliAuthenticationFlow(c, EndAuthForm{AccountID: account.ID, TailnetID: tailnets[0].ID}, req)
		}

		session, err := h.createSession(state, account.ID, isSystemAdmin, tailnets)
		if err != nil {
			return logError(err)
		}

		return c.Render(http.StatusOK, "", tpl.Tailnets(session, isSystemAdmin, tailnets, csrf))
	}

	return echo.NewHTTPError(http.StatusNotFound)
}

func (h *AuthenticationHandlers) createSession(state *oauthState, accountID uint64, isSystemAdmin bool, tailnets []domain.Tailnet) (string, error) {
	session := &authSession{
		Flow:        state.Flow,
		Key:         state.Key,
		AccountID:   accountID,
		SystemAdmin: isSystemAdmin,
		ExpiresAt:   time.Now().Add(authSessionLifetime),
	}
	for _, t := range tailnets {
		session.TailnetIDs = append(session.TailnetIDs, t.ID)
	}
	return sealAuthSession(h.sessionKey, session)
}

func (h *AuthenticationHandlers) EndAuth(c echo.Context) error {
	ctx := c.Request().Context()

	var form EndAuthForm
	if err := c.Bind(&form); err != nil {
		return logError(err)
	}

	state, err := h.readState(form.State)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid state parameter")
	}

	// The identity and its grants are taken from the sealed session created
	// after the OIDC exchange; the raw form values only select among them.
	session, err := openAuthSession(h.sessionKey, form.Session)
	if err != nil {
		return echo.NewHTTPError(http.StatusForbidden, "Invalid or expired session")
	}

	if session.Flow != state.Flow || session.Key != state.Key {
		return echo.NewHTTPError(http.StatusForbidden, "Session does not match this authentication flow")
	}

	// No interactive flow submits an auth key to this endpoint; drop it so the
	// selection below is always validated against the session.
	form.AuthKey = ""

	form.AccountID = session.AccountID
	if form.AsSystemAdmin && !session.SystemAdmin {
		return echo.NewHTTPError(http.StatusForbidden, "Not a system admin")
	}
	if !form.AsSystemAdmin && !session.allowsTailnet(form.TailnetID) {
		return echo.NewHTTPError(http.StatusForbidden, "Not a member of the selected tailnet")
	}

	if state.Flow == AuthFlowMachineRegistration {
		req, err := h.repository.GetRegistrationRequestByKey(ctx, state.Key)
		if err != nil || req == nil {
			return logError(err)
		}

		return h.endMachineRegistrationFlow(c, form, req)
	}

	if state.Flow == AuthFlowClient {
		req, err := h.repository.GetAuthenticationRequest(ctx, state.Key)
		if err != nil || req == nil {
			return logError(err)
		}

		return h.endCliAuthenticationFlow(c, form, req)
	}

	return echo.NewHTTPError(http.StatusBadRequest, "Invalid state parameter")
}

func (h *AuthenticationHandlers) Success(c echo.Context) error {
	s := c.QueryParam("s")
	switch s {
	case "nma":
		return c.Render(http.StatusOK, "", tpl.NewMachine())
	}
	return c.Render(http.StatusOK, "", tpl.Success())
}

func (h *AuthenticationHandlers) Error(c echo.Context) error {
	e := c.QueryParam("e")
	switch e {
	case "iak":
		return c.Render(http.StatusForbidden, "", tpl.InvalidAuthKey())
	case "ua":
		return c.Render(http.StatusForbidden, "", tpl.Unauthorized())
	case "ua-none":
		return c.Render(http.StatusForbidden, "", tpl.NoNetworks())
	case "ua-org":
		return c.Render(http.StatusForbidden, "", tpl.NoNetworkForOrganization())
	case "ua-org-required":
		return c.Render(http.StatusForbidden, "", tpl.OrganizationRequired())
	case "ua-policy":
		return c.Render(http.StatusForbidden, "", tpl.NotOnAccessPolicy())
	case "idp":
		return c.Render(http.StatusForbidden, "", tpl.ProviderRejected())
	case "nto":
		return c.Render(http.StatusForbidden, "", tpl.NotTagOwner())
	case "nmo":
		return c.Render(http.StatusForbidden, "", tpl.NotMachineOwner())
	}
	return c.Render(http.StatusOK, "", tpl.Error())
}

func (h *AuthenticationHandlers) endCliAuthenticationFlow(c echo.Context, form EndAuthForm, req *domain.AuthenticationRequest) error {
	ctx := c.Request().Context()

	account, err := h.repository.GetAccount(ctx, form.AccountID)
	if err != nil {
		return logError(err)
	}

	// continue as system admin?
	if form.AsSystemAdmin {
		expiresAt := time.Now().Add(24 * time.Hour)
		token, apiKey := domain.CreateSystemApiKey(account, &expiresAt)
		req.Token = token

		err := h.repository.Transaction(func(rp domain.Repository) error {
			if err := rp.SaveSystemApiKey(ctx, apiKey); err != nil {
				return logError(err)
			}
			if err := rp.SaveAuthenticationRequest(ctx, req); err != nil {
				return logError(err)
			}
			return nil
		})
		if err != nil {
			return logError(err)
		}
		audit.Log("login.system_admin", zap.String("actor", account.LoginName), zap.Uint64("account_id", account.ID))
		return c.Redirect(http.StatusFound, "/a/success")
	}

	tailnet, err := h.repository.GetTailnet(ctx, form.TailnetID)
	if err != nil {
		return logError(err)
	}

	user, _, err := h.repository.GetOrCreateUserWithAccount(ctx, tailnet, account)
	if err != nil {
		return logError(err)
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	token, apiKey := domain.CreateApiKey(tailnet, user, &expiresAt)
	req.Token = token
	req.TailnetID = &tailnet.ID

	err = h.repository.Transaction(func(rp domain.Repository) error {
		if err := rp.SetUserLastAuthenticated(ctx, user.ID, time.Now().UTC()); err != nil {
			return err
		}
		if err := rp.SaveApiKey(ctx, apiKey); err != nil {
			return err
		}
		if err := rp.SaveAuthenticationRequest(ctx, req); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return logError(err)
	}

	audit.Log("login.cli", append(audit.Tailnet(tailnet), zap.String("actor", user.Name))...)

	return c.Redirect(http.StatusFound, "/a/success")
}

func (h *AuthenticationHandlers) endMachineRegistrationFlow(c echo.Context, form EndAuthForm, registrationRequest *domain.RegistrationRequest) error {
	ctx := c.Request().Context()

	req := tailcfg.RegisterRequest(registrationRequest.Data)
	machineKey := registrationRequest.MachineKey
	nodeKey := req.NodeKey.String()

	var tailnet *domain.Tailnet
	var user *domain.User
	var ephemeral bool
	var tags = []string{}
	var authorized = false

	if form.AuthKey != "" {
		authKey, err := h.repository.LoadAuthKey(ctx, form.AuthKey)
		if err != nil {
			return logError(err)
		}

		if authKey == nil {

			registrationRequest.Authenticated = false
			registrationRequest.Error = "invalid auth key"

			if err := h.repository.SaveRegistrationRequest(ctx, registrationRequest); err != nil {
				return logError(err)
			}

			return c.Redirect(http.StatusFound, "/a/error?e=iak")
		}

		tailnet = &authKey.Tailnet
		user = &authKey.User
		tags = authKey.Tags
		ephemeral = authKey.Ephemeral
		authorized = authKey.PreAuthorized
	} else {
		selectedTailnet, err := h.repository.GetTailnet(ctx, form.TailnetID)
		if err != nil {
			return logError(err)
		}

		account, err := h.repository.GetAccount(ctx, form.AccountID)
		if err != nil {
			return logError(err)
		}

		selectedUser, _, err := h.repository.GetOrCreateUserWithAccount(ctx, selectedTailnet, account)
		if err != nil {
			return logError(err)
		}

		user = selectedUser
		tailnet = selectedTailnet
		ephemeral = false
	}

	if err := tailnet.ACLPolicy.Get().CheckTagOwners(registrationRequest.Data.Hostinfo.RequestTags, user); err != nil {
		registrationRequest.Authenticated = false
		registrationRequest.Error = err.Error()
		if err := h.repository.SaveRegistrationRequest(ctx, registrationRequest); err != nil {
			return logError(err)
		}
		return c.Redirect(http.StatusFound, "/a/error?e=nto")
	}

	autoAllowIPs := tailnet.ACLPolicy.Get().FindAutoApprovedIPs(req.Hostinfo.RoutableIPs, tags, user)

	var m *domain.Machine

	m, err := h.repository.GetMachineByKeyAndUser(ctx, machineKey, user.ID)
	if err != nil {
		return logError(err)
	}

	now := time.Now().UTC()

	if m == nil {
		registeredTags := tags
		advertisedTags := domain.SanitizeTags(req.Hostinfo.RequestTags)
		tags := append(registeredTags, advertisedTags...)

		sanitizeHostname := dnsname.SanitizeHostname(req.Hostinfo.Hostname)
		nameIdx, err := h.repository.GetNextMachineNameIndex(ctx, tailnet.ID, sanitizeHostname)
		if err != nil {
			return logError(err)
		}

		m = &domain.Machine{
			ID:                util.NextID(),
			Name:              sanitizeHostname,
			NameIdx:           nameIdx,
			UseOSHostname:     true,
			MachineKey:        machineKey,
			NodeKey:           nodeKey,
			Ephemeral:         ephemeral || req.Ephemeral,
			RegisteredTags:    registeredTags,
			Tags:              domain.SanitizeTags(tags),
			AutoAllowIPs:      autoAllowIPs,
			CreatedAt:         now,
			ExpiresAt:         now.Add(config.MachineKeyExpiry()).UTC(),
			KeyExpiryDisabled: len(tags) != 0,
			Authorized:        !tailnet.MachineAuthorizationEnabled || authorized,

			User:      *user,
			UserID:    user.ID,
			Tailnet:   *tailnet,
			TailnetID: tailnet.ID,
		}

		ipv4, ipv6, err := addr.SelectIP(checkIP(ctx, h.repository.CountMachinesWithIPv4))
		if err != nil {
			return logError(err)
		}
		m.IPv4 = domain.IP{Addr: ipv4}
		m.IPv6 = domain.IP{Addr: ipv6}
	} else {
		registeredTags := tags
		advertisedTags := domain.SanitizeTags(req.Hostinfo.RequestTags)
		tags := append(registeredTags, advertisedTags...)

		sanitizeHostname := dnsname.SanitizeHostname(req.Hostinfo.Hostname)
		if m.UseOSHostname && m.Name != sanitizeHostname {
			nameIdx, err := h.repository.GetNextMachineNameIndex(ctx, tailnet.ID, sanitizeHostname)
			if err != nil {
				return logError(err)
			}
			m.Name = sanitizeHostname
			m.NameIdx = nameIdx
		}
		m.NodeKey = nodeKey
		m.Ephemeral = ephemeral || req.Ephemeral
		m.RegisteredTags = registeredTags
		m.Tags = domain.SanitizeTags(tags)
		m.AutoAllowIPs = autoAllowIPs
		m.UserID = user.ID
		m.User = *user
		m.TailnetID = tailnet.ID
		m.Tailnet = *tailnet
		m.ExpiresAt = now.Add(config.MachineKeyExpiry()).UTC()
	}

	applyTailnetLockRegistration(c, h.repository, tailnet.ID, m, &req)

	err = h.repository.Transaction(func(rp domain.Repository) error {
		registrationRequest.Authenticated = true
		registrationRequest.Error = ""
		registrationRequest.UserID = user.ID

		if err := rp.SetUserLastAuthenticated(ctx, m.UserID, time.Now().UTC()); err != nil {
			return err
		}

		if err := rp.SaveMachine(ctx, m); err != nil {
			return err
		}

		if err := rp.SaveRegistrationRequest(ctx, registrationRequest); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return logError(err)
	}

	audit.Log("machine.registered", append(audit.Tailnet(tailnet),
		zap.String("actor", user.Name),
		zap.String("machine", m.Name),
		zap.Uint64("machine_id", m.ID),
		zap.Bool("via_auth_key", form.AuthKey != ""),
		zap.Bool("authorized", m.Authorized))...)

	if m.Authorized {
		return c.Redirect(http.StatusFound, "/a/success")
	} else {
		return c.Redirect(http.StatusFound, "/a/success?s=nma")
	}
}

func (h *AuthenticationHandlers) isSystemAdmin(u *auth.User) (bool, error) {
	return h.systemIAMPolicy.EvaluatePolicy(&domain.Identity{UserID: u.ID, Email: u.Name, Attr: u.Attr})
}

func (h *AuthenticationHandlers) listAvailableTailnets(ctx context.Context, u *auth.User) ([]domain.Tailnet, error) {
	var result = []domain.Tailnet{}
	orgs := h.config.Auth.Organizations
	tailnets, err := h.repository.ListTailnets(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range tailnets {
		approved, err := tailnetAccessible(orgs, t, u)
		if err != nil {
			return nil, err
		}
		if approved {
			result = append(result, t)
		}
	}
	return result, nil
}

// denialCode works out why listAvailableTailnets came back empty, so the error
// page can say something more useful than "not authorized". It returns one of a
// fixed set of codes: the reason travels through a redirect, and a closed enum
// keeps arbitrary text off the page.
//
// The branches mirror tailnetAccessible below, in the same order.
func (h *AuthenticationHandlers) denialCode(ctx context.Context, u *auth.User) string {
	orgs := h.config.Auth.Organizations

	tailnets, err := h.repository.ListTailnets(ctx)
	if err != nil {
		return "ua"
	}

	// Nothing to be a member of yet.
	if len(tailnets) == 0 {
		return "ua-none"
	}

	if orgs.Enabled() {
		// An identity without an organization can only ever reach tailnets that
		// are themselves unbound, and those are hidden once scoping is on.
		if u.Org == "" {
			return "ua-org-required"
		}
		// Some tailnet is in the identity's organization, so the boundary held
		// and an IAM policy did the rejecting.
		for _, t := range tailnets {
			if t.Organization == u.Org {
				return "ua-policy"
			}
		}
		return "ua-org"
	}

	// No scoping: every tailnet was evaluated, so every policy said no.
	return "ua-policy"
}

// tailnetAccessible decides whether an authenticated identity may enter a
// tailnet. A tailnet bound to an organization is a hard boundary: identities
// of other organizations never see it, regardless of its IAM policy. Within
// the organization, a non-empty IAM policy further restricts access; an empty
// one admits every member of the organization. The boundary cuts both ways:
// an identity carrying an organization only ever sees its organization's
// tailnets, so a membership maps to exactly one tailnet.
func tailnetAccessible(orgs config.Organizations, t domain.Tailnet, u *auth.User) (bool, error) {
	identity := &domain.Identity{UserID: u.ID, Email: u.Name, Attr: u.Attr}

	if t.Organization != "" {
		if !orgs.Enabled() || u.Org == "" || t.Organization != u.Org {
			return false, nil
		}
		policy := t.IAMPolicy.Get()
		if isEmptyIAMPolicy(policy) {
			return true, nil
		}
		return policy.EvaluatePolicy(identity)
	}

	if orgs.Enabled() && u.Org != "" {
		return false, nil
	}

	return t.IAMPolicy.Get().EvaluatePolicy(identity)
}

func isEmptyIAMPolicy(p *domain.IAMPolicy) bool {
	return len(p.Subs) == 0 && len(p.Emails) == 0 && len(p.Filters) == 0
}

// syncOrgRoles reflects the identity's organization roles into the IAM
// policies of its organization's tailnets, so that admin role claims from the
// identity provider translate into tailnet-admin permissions.
func (h *AuthenticationHandlers) syncOrgRoles(ctx context.Context, u *auth.User) error {
	orgs := h.config.Auth.Organizations
	if !orgs.Enabled() || orgs.RolesClaim == "" || u.Org == "" {
		return nil
	}

	isAdmin := false
	for _, role := range u.Roles {
		for _, adminRole := range orgs.AdminRoles {
			if role == adminRole {
				isAdmin = true
			}
		}
	}

	tailnets, err := h.repository.ListTailnetsByOrganization(ctx, u.Org)
	if err != nil {
		return err
	}

	for _, t := range tailnets {
		policy := t.IAMPolicy.Get()
		current, hasRole := policy.Roles[u.Name]

		var updated *domain.IAMPolicy
		if isAdmin && current != domain.UserRoleAdmin {
			updated = &domain.IAMPolicy{Subs: policy.Subs, Emails: policy.Emails, Filters: policy.Filters, Roles: map[string]domain.UserRole{}}
			for k, v := range policy.Roles {
				updated.Roles[k] = v
			}
			updated.Roles[u.Name] = domain.UserRoleAdmin
		}
		if !isAdmin && hasRole && current == domain.UserRoleAdmin {
			updated = &domain.IAMPolicy{Subs: policy.Subs, Emails: policy.Emails, Filters: policy.Filters, Roles: map[string]domain.UserRole{}}
			for k, v := range policy.Roles {
				updated.Roles[k] = v
			}
			delete(updated.Roles, u.Name)
		}

		if updated != nil {
			t := t
			t.IAMPolicy = domain.NewHuJSON(updated)
			if err := h.repository.SaveTailnet(ctx, &t); err != nil {
				return err
			}
		}
	}

	return nil
}

func (h *AuthenticationHandlers) exchangeUser(code, codeVerifier, nonce string) (*auth.User, error) {
	redirectUrl := h.config.CreateUrl("/a/callback")

	user, err := h.authProvider.Exchange(redirectUrl, code, codeVerifier, nonce)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// The OAuth state is sealed with a server-held key so it cannot be forged or
// tampered with while it travels through the identity provider redirect.
// Returns the sealed state, plus the nonce and PKCE code verifier it carries.
func (h *AuthenticationHandlers) createState(flow AuthFlow, key string) (string, string, string, error) {
	// 64 chars from the unreserved alphabet: a valid PKCE code_verifier
	// (RFC 7636 allows 43-128) and ample entropy for a nonce.
	nonce := util.RandStringBytes(64)
	codeVerifier := util.RandStringBytes(64)

	stateMap := oauthState{
		Key:          key,
		Flow:         flow,
		ExpiresAt:    time.Now().Add(authSessionLifetime),
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
	}
	marshal, err := json.Marshal(&stateMap)
	if err != nil {
		return "", "", "", err
	}
	return base58.FastBase58Encoding(h.sessionKey.Seal(marshal)), nonce, codeVerifier, nil
}

func (h *AuthenticationHandlers) readState(s string) (*oauthState, error) {
	decodedState, err := base58.FastBase58Decoding(s)
	if err != nil {
		return nil, err
	}

	plain, ok := h.sessionKey.Open(decodedState)
	if !ok {
		return nil, fmt.Errorf("invalid state")
	}

	var state = &oauthState{}
	if err := json.Unmarshal(plain, state); err != nil {
		return nil, err
	}

	if state.ExpiresAt.IsZero() || time.Now().After(state.ExpiresAt) {
		return nil, fmt.Errorf("state expired")
	}

	return state, nil
}
