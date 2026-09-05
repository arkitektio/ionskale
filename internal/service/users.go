package service

import (
	"context"
	"fmt"
	"github.com/bufbuild/connect-go"
	"github.com/jsiebens/ionscale/internal/audit"
	"github.com/jsiebens/ionscale/internal/domain"
	api "github.com/jsiebens/ionscale/pkg/gen/ionscale/v1"
	"go.uber.org/zap"
)

func (s *Service) ListUsers(ctx context.Context, req *connect.Request[api.ListUsersRequest]) (*connect.Response[api.ListUsersResponse], error) {
	principal := CurrentPrincipal(ctx)

	tailnet, err := s.repository.GetTailnet(ctx, req.Msg.TailnetId)
	if err != nil {
		return nil, logError(err)
	}

	if tailnet == nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("tailnet not found"))
	}

	if !principal.IsSystemAdmin() && !principal.IsTailnetAdmin(tailnet.ID) {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("permission denied"))
	}

	users, err := s.repository.ListUsers(ctx, tailnet.ID)
	if err != nil {
		return nil, logError(err)
	}

	resp := &api.ListUsersResponse{}
	for _, u := range users {
		resp.Users = append(resp.Users, &api.User{
			Id:   u.ID,
			Name: u.Name,
			Role: string(tailnet.IAMPolicy.Get().GetRole(u)),
		})
	}

	return connect.NewResponse(resp), nil
}

func (s *Service) DeleteUser(ctx context.Context, req *connect.Request[api.DeleteUserRequest]) (*connect.Response[api.DeleteUserResponse], error) {
	principal := CurrentPrincipal(ctx)

	if !principal.IsSystemAdmin() && principal.UserMatches(req.Msg.UserId) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("unable to delete yourself"))
	}

	user, err := s.repository.GetUser(ctx, req.Msg.UserId)
	if err != nil {
		return nil, logError(err)
	}

	if user == nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("user not found"))
	}

	if !principal.IsSystemAdmin() && !principal.IsTailnetAdmin(user.TailnetID) {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("permission denied"))
	}

	if user.UserType == domain.UserTypeService {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("unable delete service account"))
	}

	err = s.repository.Transaction(func(tx domain.Repository) error {
		if err := tx.DeleteMachineByUser(ctx, req.Msg.UserId); err != nil {
			return err
		}

		if err := tx.DeleteApiKeysByUser(ctx, req.Msg.UserId); err != nil {
			return err
		}

		if err := tx.DeleteAuthKeysByUser(ctx, req.Msg.UserId); err != nil {
			return err
		}

		if err := tx.DeleteUser(ctx, req.Msg.UserId); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, logError(err)
	}

	audit.Log("user.deleted", audit.Actor(principal), zap.String("user", user.Name), zap.Uint64("user_id", user.ID), zap.Uint64("tailnet_id", user.TailnetID))

	s.sessionManager.NotifyAll(user.TailnetID)

	return connect.NewResponse(&api.DeleteUserResponse{}), nil
}

// RevokeAccount removes every per-tailnet user of an account — machines, api
// keys and auth keys included — optionally restricted to tailnets bound to
// one organization. It is meant to be called by the identity provider's
// backend the moment a membership is revoked, instead of waiting for machine
// keys to expire.
//
// The call is idempotent: an account that never logged in, or that was already
// revoked, yields an empty response rather than an error, so callers can retry
// blindly and revoke on every membership removal without checking first.
func (s *Service) RevokeAccount(ctx context.Context, req *connect.Request[api.RevokeAccountRequest]) (*connect.Response[api.RevokeAccountResponse], error) {
	principal := CurrentPrincipal(ctx)
	if !principal.IsSystemAdmin() {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("permission denied"))
	}

	if req.Msg.ExternalId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("external_id is required"))
	}

	// One subject can now hold an account per organization. Revoking is a
	// security action, so it covers all of them: leaving the same person live
	// on another organization's network would be a surprising default.
	accounts, err := s.repository.ListAccountsByExternalID(ctx, req.Msg.ExternalId)
	if err != nil {
		return nil, logError(err)
	}
	if len(accounts) == 0 {
		audit.Log("account.revoked", audit.Actor(principal), zap.String("external_id", req.Msg.ExternalId), zap.String("org", req.Msg.Organization), zap.Bool("noop", true))
		return connect.NewResponse(&api.RevokeAccountResponse{}), nil
	}

	var users domain.Users
	for _, account := range accounts {
		accountUsers, err := s.repository.ListUsersByAccount(ctx, account.ID)
		if err != nil {
			return nil, logError(err)
		}
		users = append(users, accountUsers...)
	}

	var revoke []domain.User
	for _, u := range users {
		if u.UserType == domain.UserTypeService {
			continue
		}
		if req.Msg.Organization != "" && u.Tailnet.Organization != req.Msg.Organization {
			continue
		}
		revoke = append(revoke, u)
	}

	// collect the affected tailnets before deleting; the user rows are gone
	// afterwards
	tailnetIDs := make([]uint64, 0, len(revoke))
	for _, u := range revoke {
		tailnetIDs = append(tailnetIDs, u.TailnetID)
	}

	err = s.repository.Transaction(func(tx domain.Repository) error {
		for _, u := range revoke {
			if err := tx.DeleteMachineByUser(ctx, u.ID); err != nil {
				return err
			}
			if err := tx.DeleteApiKeysByUser(ctx, u.ID); err != nil {
				return err
			}
			if err := tx.DeleteAuthKeysByUser(ctx, u.ID); err != nil {
				return err
			}
			if err := tx.DeleteUser(ctx, u.ID); err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return nil, logError(err)
	}

	audit.Log("account.revoked", audit.Actor(principal), zap.String("external_id", req.Msg.ExternalId), zap.String("org", req.Msg.Organization), zap.Uint64s("tailnet_ids", tailnetIDs))

	for _, tailnetID := range tailnetIDs {
		s.sessionManager.NotifyAll(tailnetID)
	}

	return connect.NewResponse(&api.RevokeAccountResponse{TailnetIds: tailnetIDs}), nil
}
