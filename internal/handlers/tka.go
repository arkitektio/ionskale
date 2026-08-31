package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"sync"

	"github.com/jsiebens/ionscale/internal/audit"
	"github.com/jsiebens/ionscale/internal/core"
	"github.com/jsiebens/ionscale/internal/domain"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

// tkaLocks serializes tailnet-lock state mutations per tailnet: tka.Authority
// has no internal locking and Inform mutates in place. Package-level because
// a fresh handler set is created per noise connection.
var tkaLocks = struct {
	sync.Mutex
	m map[uint64]*sync.Mutex
}{m: map[uint64]*sync.Mutex{}}

func tkaLock(tailnetID uint64) *sync.Mutex {
	tkaLocks.Lock()
	defer tkaLocks.Unlock()
	l, ok := tkaLocks.m[tailnetID]
	if !ok {
		l = &sync.Mutex{}
		tkaLocks.m[tailnetID] = l
	}
	return l
}

func NewTKAHandlers(
	machineKey key.MachinePublic,
	repository domain.Repository,
	sessionManager core.PollMapSessionManager) *TKAHandlers {
	return &TKAHandlers{
		machineKey:     machineKey,
		repository:     repository,
		sessionManager: sessionManager,
	}
}

type TKAHandlers struct {
	machineKey     key.MachinePublic
	repository     domain.Repository
	sessionManager core.PollMapSessionManager
}

// caller resolves the requesting node from its node key; every TKA request
// carries one. The machine key is authenticated by the noise tunnel.
func (h *TKAHandlers) caller(c echo.Context, nodeKey key.NodePublic) (*domain.Machine, error) {
	ctx := c.Request().Context()
	m, err := h.repository.GetMachineByKeys(ctx, h.machineKey.String(), nodeKey.String())
	if err != nil {
		return nil, logError(err)
	}
	if m == nil {
		return nil, echo.NewHTTPError(http.StatusForbidden, "unknown node")
	}
	return m, nil
}

func (h *TKAHandlers) InitBegin(c echo.Context) error {
	ctx := c.Request().Context()

	req := &tailcfg.TKAInitBeginRequest{}
	if err := c.Bind(req); err != nil {
		return logError(err)
	}

	m, err := h.caller(c, req.NodeKey)
	if err != nil {
		return err
	}

	if !m.Tailnet.TailnetLockEnabled {
		return echo.NewHTTPError(http.StatusForbidden, "tailnet lock is not enabled for this tailnet")
	}

	mu := tkaLock(m.TailnetID)
	mu.Lock()
	defer mu.Unlock()

	state, err := h.repository.GetTailnetTKAState(ctx, m.TailnetID)
	if err != nil {
		return logError(err)
	}
	if state.Enabled {
		return echo.NewHTTPError(http.StatusBadRequest, "tailnet key authority is already initialized")
	}

	var genesis tka.AUM
	if err := genesis.Unserialize(req.GenesisAUM); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid genesis AUM: %v", err))
	}

	// Validate the genesis against a scratch store before accepting it.
	if _, err := tka.Bootstrap(&tka.Mem{}, genesis); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid genesis AUM: %v", err))
	}

	machines, err := h.repository.ListMachineByTailnet(ctx, m.TailnetID)
	if err != nil {
		return logError(err)
	}

	resp := &tailcfg.TKAInitBeginResponse{}
	for _, machine := range machines {
		info := tailcfg.TKASignInfo{NodeID: tailcfg.NodeID(machine.ID)}
		if err := info.NodePublic.UnmarshalText([]byte(machine.NodeKey)); err != nil {
			return logError(err)
		}
		if machine.NLKey != "" {
			var nlKey key.NLPublic
			if err := nlKey.UnmarshalText([]byte(machine.NLKey)); err == nil {
				info.RotationPubkey = nlKey.Verifier()
			}
		}
		resp.NeedSignatures = append(resp.NeedSignatures, info)
	}

	state.PendingGenesis = req.GenesisAUM
	if err := h.repository.SaveTailnetTKAState(ctx, state); err != nil {
		return logError(err)
	}

	return c.JSON(http.StatusOK, resp)
}

func (h *TKAHandlers) InitFinish(c echo.Context) error {
	ctx := c.Request().Context()

	req := &tailcfg.TKAInitFinishRequest{}
	if err := c.Bind(req); err != nil {
		return logError(err)
	}

	m, err := h.caller(c, req.NodeKey)
	if err != nil {
		return err
	}

	if !m.Tailnet.TailnetLockEnabled {
		return echo.NewHTTPError(http.StatusForbidden, "tailnet lock is not enabled for this tailnet")
	}

	mu := tkaLock(m.TailnetID)
	mu.Lock()
	defer mu.Unlock()

	state, err := h.repository.GetTailnetTKAState(ctx, m.TailnetID)
	if err != nil {
		return logError(err)
	}
	if state.Enabled {
		return echo.NewHTTPError(http.StatusBadRequest, "tailnet key authority is already initialized")
	}
	if len(state.PendingGenesis) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "no pending tailnet key authority initialization; call /tka/init/begin first")
	}

	var genesis tka.AUM
	if err := genesis.Unserialize(state.PendingGenesis); err != nil {
		return logError(err)
	}

	authority, err := tka.Bootstrap(&tka.Mem{}, genesis)
	if err != nil {
		return logError(err)
	}

	// Every node must be signed before the authority goes live: the moment
	// TKAInfo is advertised, clients drop unsigned peers.
	machines, err := h.repository.ListMachineByTailnet(ctx, m.TailnetID)
	if err != nil {
		return logError(err)
	}

	type signedMachine struct {
		machine   domain.Machine
		signature tkatype.MarshaledSignature
	}
	var signed []signedMachine
	for _, machine := range machines {
		sig, ok := req.Signatures[tailcfg.NodeID(machine.ID)]
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("missing signature for node %s", machine.CompleteName()))
		}
		var nodeKey key.NodePublic
		if err := nodeKey.UnmarshalText([]byte(machine.NodeKey)); err != nil {
			return logError(err)
		}
		if err := authority.NodeKeyAuthorized(nodeKey, sig); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid signature for node %s: %v", machine.CompleteName(), err))
		}
		signed = append(signed, signedMachine{machine: machine, signature: sig})
	}

	err = h.repository.Transaction(func(tx domain.Repository) error {
		// A previous, disabled authority (or stale state) is wiped so the
		// chonk is empty for Bootstrap.
		if err := tx.DeleteTKAByTailnet(ctx, m.TailnetID); err != nil {
			return err
		}

		txAuthority, err := tka.Bootstrap(tx.TKAChonk(ctx, m.TailnetID), genesis)
		if err != nil {
			return err
		}

		for _, s := range signed {
			s.machine.KeySignature = []byte(s.signature)
			if err := tx.SaveMachine(ctx, &s.machine); err != nil {
				return err
			}
		}

		newState, err := tx.GetTailnetTKAState(ctx, m.TailnetID)
		if err != nil {
			return err
		}
		newState.Enabled = true
		newState.Disabled = false
		newState.Head = marshalAUMHash(txAuthority.Head())
		newState.PendingGenesis = nil
		newState.DisablementSecret = nil
		newState.SupportDisablement = req.SupportDisablement
		return tx.SaveTailnetTKAState(ctx, newState)
	})
	if err != nil {
		return logError(err)
	}

	audit.Log("tailnet_lock.initialized", append(audit.Tailnet(&m.Tailnet), zap.String("actor", m.User.Name), zap.Int("signed_nodes", len(signed)))...)

	h.sessionManager.NotifyAll(m.TailnetID)

	return c.JSON(http.StatusOK, &tailcfg.TKAInitFinishResponse{})
}

func (h *TKAHandlers) Bootstrap(c echo.Context) error {
	ctx := c.Request().Context()

	req := &tailcfg.TKABootstrapRequest{}
	if err := c.Bind(req); err != nil {
		return logError(err)
	}

	m, err := h.caller(c, req.NodeKey)
	if err != nil {
		return err
	}

	state, err := h.repository.GetTailnetTKAState(ctx, m.TailnetID)
	if err != nil {
		return logError(err)
	}

	resp := &tailcfg.TKABootstrapResponse{}

	switch {
	case state.Enabled:
		chonk := h.repository.TKAChonk(ctx, m.TailnetID)
		ancestor, err := chonk.LastActiveAncestor()
		if err != nil {
			return logError(err)
		}
		if ancestor == nil {
			return logError(fmt.Errorf("tailnet %d: enabled TKA has no last active ancestor", m.TailnetID))
		}
		genesis, err := chonk.AUM(*ancestor)
		if err != nil {
			return logError(err)
		}
		resp.GenesisAUM = genesis.Serialize()

	case state.Disabled:
		resp.DisablementSecret = state.DisablementSecret

	default:
		return echo.NewHTTPError(http.StatusBadRequest, "tailnet key authority is not initialized")
	}

	return c.JSON(http.StatusOK, resp)
}

func (h *TKAHandlers) SyncOffer(c echo.Context) error {
	req := &tailcfg.TKASyncOfferRequest{}
	if err := c.Bind(req); err != nil {
		return logError(err)
	}

	m, err := h.caller(c, req.NodeKey)
	if err != nil {
		return err
	}

	mu := tkaLock(m.TailnetID)
	mu.Lock()
	defer mu.Unlock()

	authority, chonk, err := h.openAuthority(c, m.TailnetID)
	if err != nil {
		return err
	}

	controlOffer, err := authority.SyncOffer(chonk)
	if err != nil {
		return logError(err)
	}

	remoteOffer, err := parseSyncOffer(req.Head, req.Ancestors)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid sync offer: %v", err))
	}

	missing, err := authority.MissingAUMs(chonk, remoteOffer)
	if err != nil && err != tka.ErrNoIntersection {
		return logError(err)
	}

	resp := &tailcfg.TKASyncOfferResponse{Head: marshalAUMHash(controlOffer.Head)}
	for _, ancestor := range controlOffer.Ancestors {
		resp.Ancestors = append(resp.Ancestors, marshalAUMHash(ancestor))
	}
	for _, aum := range missing {
		resp.MissingAUMs = append(resp.MissingAUMs, aum.Serialize())
	}

	return c.JSON(http.StatusOK, resp)
}

func (h *TKAHandlers) SyncSend(c echo.Context) error {
	ctx := c.Request().Context()

	req := &tailcfg.TKASyncSendRequest{}
	if err := c.Bind(req); err != nil {
		return logError(err)
	}

	m, err := h.caller(c, req.NodeKey)
	if err != nil {
		return err
	}

	mu := tkaLock(m.TailnetID)
	mu.Lock()
	defer mu.Unlock()

	authority, chonk, err := h.openAuthority(c, m.TailnetID)
	if err != nil {
		return err
	}

	if len(req.MissingAUMs) > 0 {
		var updates []tka.AUM
		for _, raw := range req.MissingAUMs {
			var aum tka.AUM
			if err := aum.Unserialize(raw); err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid AUM: %v", err))
			}
			updates = append(updates, aum)
		}

		if err := authority.Inform(chonk, updates); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("applying AUMs: %v", err))
		}

		state, err := h.repository.GetTailnetTKAState(ctx, m.TailnetID)
		if err != nil {
			return logError(err)
		}
		newHead := marshalAUMHash(authority.Head())
		if state.Head != newHead {
			state.Head = newHead
			if err := h.repository.SaveTailnetTKAState(ctx, state); err != nil {
				return logError(err)
			}

			audit.Log("tailnet_lock.updated", append(audit.Tailnet(&m.Tailnet), zap.String("actor", m.User.Name), zap.String("head", newHead))...)

			h.sessionManager.NotifyAll(m.TailnetID)
		}
	}

	return c.JSON(http.StatusOK, &tailcfg.TKASyncSendResponse{Head: marshalAUMHash(authority.Head())})
}

func (h *TKAHandlers) Disable(c echo.Context) error {
	ctx := c.Request().Context()

	req := &tailcfg.TKADisableRequest{}
	if err := c.Bind(req); err != nil {
		return logError(err)
	}

	m, err := h.caller(c, req.NodeKey)
	if err != nil {
		return err
	}

	mu := tkaLock(m.TailnetID)
	mu.Lock()
	defer mu.Unlock()

	authority, _, err := h.openAuthority(c, m.TailnetID)
	if err != nil {
		return err
	}

	if !authority.ValidDisablement(req.DisablementSecret) {
		return echo.NewHTTPError(http.StatusForbidden, "invalid disablement secret")
	}

	state, err := h.repository.GetTailnetTKAState(ctx, m.TailnetID)
	if err != nil {
		return logError(err)
	}
	state.Enabled = false
	state.Disabled = true
	state.DisablementSecret = req.DisablementSecret
	if err := h.repository.SaveTailnetTKAState(ctx, state); err != nil {
		return logError(err)
	}

	audit.Log("tailnet_lock.disabled", append(audit.Tailnet(&m.Tailnet), zap.String("actor", m.User.Name))...)

	h.sessionManager.NotifyAll(m.TailnetID)

	return c.JSON(http.StatusOK, &tailcfg.TKADisableResponse{})
}

func (h *TKAHandlers) SubmitSignature(c echo.Context) error {
	ctx := c.Request().Context()

	req := &tailcfg.TKASubmitSignatureRequest{}
	if err := c.Bind(req); err != nil {
		return logError(err)
	}

	m, err := h.caller(c, req.NodeKey)
	if err != nil {
		return err
	}

	mu := tkaLock(m.TailnetID)
	mu.Lock()
	defer mu.Unlock()

	authority, _, err := h.openAuthority(c, m.TailnetID)
	if err != nil {
		return err
	}

	var nks tka.NodeKeySignature
	if err := nks.Unserialize(req.Signature); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid signature: %v", err))
	}

	var targetKey key.NodePublic
	if err := targetKey.UnmarshalBinary(nks.Pubkey); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid signature pubkey: %v", err))
	}

	if err := authority.NodeKeyAuthorized(targetKey, req.Signature); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("signature not authorized: %v", err))
	}

	target, err := h.repository.GetMachineByNodeKey(ctx, m.TailnetID, targetKey.String())
	if err != nil {
		return logError(err)
	}
	if target == nil {
		return echo.NewHTTPError(http.StatusNotFound, "no node with the signed node key found in this tailnet")
	}

	target.KeySignature = []byte(req.Signature)
	if err := h.repository.SaveMachine(ctx, target); err != nil {
		return logError(err)
	}

	audit.Log("tailnet_lock.node_signed", append(audit.Tailnet(&m.Tailnet), zap.String("actor", m.User.Name), zap.String("machine", target.CompleteName()), zap.Uint64("machine_id", target.ID))...)

	h.sessionManager.NotifyAll(m.TailnetID)

	return c.JSON(http.StatusOK, &tailcfg.TKASubmitSignatureResponse{})
}

func (h *TKAHandlers) AffectedSigs(c echo.Context) error {
	ctx := c.Request().Context()

	req := &tailcfg.TKASignaturesUsingKeyRequest{}
	if err := c.Bind(req); err != nil {
		return logError(err)
	}

	m, err := h.caller(c, req.NodeKey)
	if err != nil {
		return err
	}

	signatures, err := h.repository.ListMachineKeySignaturesByTailnet(ctx, m.TailnetID)
	if err != nil {
		return logError(err)
	}

	resp := &tailcfg.TKASignaturesUsingKeyResponse{}
	for _, raw := range signatures {
		var nks tka.NodeKeySignature
		if err := nks.Unserialize(raw); err != nil {
			continue
		}
		keyID, err := nks.UnverifiedAuthorizingKeyID()
		if err != nil {
			continue
		}
		if bytes.Equal(keyID, req.KeyID) {
			resp.Signatures = append(resp.Signatures, tkatype.MarshaledSignature(raw))
		}
	}

	return c.JSON(http.StatusOK, resp)
}

// openAuthority loads the tailnet's active authority; the caller must hold
// the tailnet's TKA lock.
func (h *TKAHandlers) openAuthority(c echo.Context, tailnetID uint64) (*tka.Authority, tka.Chonk, error) {
	ctx := c.Request().Context()

	state, err := h.repository.GetTailnetTKAState(ctx, tailnetID)
	if err != nil {
		return nil, nil, logError(err)
	}
	if !state.Enabled {
		return nil, nil, echo.NewHTTPError(http.StatusBadRequest, "tailnet key authority is not initialized")
	}

	chonk := h.repository.TKAChonk(ctx, tailnetID)
	authority, err := tka.Open(chonk)
	if err != nil {
		return nil, nil, logError(err)
	}
	return authority, chonk, nil
}

func marshalAUMHash(h tka.AUMHash) string {
	text, err := h.MarshalText()
	if err != nil {
		return ""
	}
	return string(text)
}

func parseSyncOffer(head string, ancestors []string) (tka.SyncOffer, error) {
	var offer tka.SyncOffer
	if err := offer.Head.UnmarshalText([]byte(head)); err != nil {
		return tka.SyncOffer{}, err
	}
	for _, a := range ancestors {
		var hash tka.AUMHash
		if err := hash.UnmarshalText([]byte(a)); err != nil {
			return tka.SyncOffer{}, err
		}
		offer.Ancestors = append(offer.Ancestors, hash)
	}
	return offer, nil
}

// applyTailnetLockRegistration copies tailnet-lock material from a register
// request onto a machine: the node's network-lock public key and, when the
// tailnet's key authority is active and the signature verifies, its node-key
// signature. Invalid signatures are ignored rather than failing registration —
// the node simply stays unsigned until a valid signature is submitted.
func applyTailnetLockRegistration(c echo.Context, repository domain.Repository, tailnetID uint64, m *domain.Machine, req *tailcfg.RegisterRequest) {
	ctx := c.Request().Context()

	if !req.NLKey.IsZero() {
		if text, err := req.NLKey.MarshalText(); err == nil {
			m.NLKey = string(text)
		}
	}

	if len(req.NodeKeySignature) == 0 {
		return
	}

	state, err := repository.GetTailnetTKAState(ctx, tailnetID)
	if err != nil || !state.Enabled {
		return
	}

	authority, err := tka.Open(repository.TKAChonk(ctx, tailnetID))
	if err != nil {
		return
	}

	if err := authority.NodeKeyAuthorized(req.NodeKey, req.NodeKeySignature); err != nil {
		return
	}

	m.KeySignature = []byte(req.NodeKeySignature)
}

// tailnetLockRotationSignature returns the stored node-key signature of the
// machine previously registered with this machine key, when the node is
// re-registering under an active key authority with a rotated node key and no
// signature of its own. The client answers by re-registering with a
// re-signed rotation signature (tka.ResignNKS).
func tailnetLockRotationSignature(c echo.Context, repository domain.Repository, machineKey string, req *tailcfg.RegisterRequest) tkatype.MarshaledSignature {
	ctx := c.Request().Context()

	if len(req.NodeKeySignature) > 0 {
		return nil
	}

	old, err := repository.GetMachineByMachineKey(ctx, machineKey)
	if err != nil || old == nil || len(old.KeySignature) == 0 {
		return nil
	}

	state, err := repository.GetTailnetTKAState(ctx, old.TailnetID)
	if err != nil || !state.Enabled {
		return nil
	}

	return tkatype.MarshaledSignature(old.KeySignature)
}
