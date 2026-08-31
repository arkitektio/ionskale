package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/jsiebens/ionscale/internal/config"
	"github.com/jsiebens/ionscale/internal/core"
	"github.com/jsiebens/ionscale/internal/database"
	"github.com/jsiebens/ionscale/internal/domain"
	"github.com/jsiebens/ionscale/internal/util"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

type tkaTestEnv struct {
	t       *testing.T
	repo    domain.Repository
	echo    *echo.Echo
	tailnet *domain.Tailnet

	nlPriv            key.NLPrivate
	disablementSecret []byte
}

func newTKATestEnv(t *testing.T) *tkaTestEnv {
	t.Helper()
	util.EnsureIDProvider()
	dir := t.TempDir()
	cfg := &config.Database{Type: "sqlite", Url: filepath.Join(dir, "test.db") + "?_pragma=foreign_keys(ON)"}
	_, repo, err := database.OpenDB(cfg, zap.NewNop())
	require.NoError(t, err)

	tailnet := &domain.Tailnet{
		ID:                 util.NextID(),
		Name:               "locknet",
		TailnetLockEnabled: true,
		IAMPolicy:          domain.NewHuJSON(&domain.IAMPolicy{}),
		ACLPolicy:          domain.NewHuJSON(&domain.ACLPolicy{}),
	}
	require.NoError(t, repo.SaveTailnet(context.Background(), tailnet))

	e := echo.New()
	e.Binder = JsonBinder{}

	secret := make([]byte, 32)
	_, err = rand.Read(secret)
	require.NoError(t, err)

	return &tkaTestEnv{
		t:                 t,
		repo:              repo,
		echo:              e,
		tailnet:           tailnet,
		nlPriv:            key.NewNLPrivate(),
		disablementSecret: secret,
	}
}

// newMachine registers a machine in the test tailnet. Every machine gets its
// own machine key, mirroring the per-noise-connection handler construction.
func (env *tkaTestEnv) newMachine(name string) (*domain.Machine, key.NodePrivate, *TKAHandlers) {
	env.t.Helper()
	ctx := context.Background()

	user, _, err := env.repo.GetOrCreateServiceUser(ctx, env.tailnet)
	require.NoError(env.t, err)

	machinePriv := key.NewMachine()
	nodePriv := key.NewNode()

	nlKeyText, err := env.nlPriv.Public().MarshalText()
	require.NoError(env.t, err)

	m := &domain.Machine{
		ID:         util.NextID(),
		Name:       name,
		MachineKey: machinePriv.Public().String(),
		NodeKey:    nodePriv.Public().String(),
		NLKey:      string(nlKeyText),
		UserID:     user.ID,
		TailnetID:  env.tailnet.ID,
	}
	require.NoError(env.t, env.repo.SaveMachine(ctx, m))

	handlers := NewTKAHandlers(machinePriv.Public(), env.repo, core.NewPollMapSessionManager())
	return m, nodePriv, handlers
}

// call performs a GET-with-JSON-body request, matching the tailscale client's
// noise RPC convention, and decodes a JSON response on HTTP 200.
func (env *tkaTestEnv) call(handler echo.HandlerFunc, reqBody interface{}, respBody interface{}) error {
	env.t.Helper()
	raw, err := json.Marshal(reqBody)
	require.NoError(env.t, err)

	req := httptest.NewRequest("GET", "/", bytes.NewReader(raw))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := env.echo.NewContext(req, rec)

	if err := handler(c); err != nil {
		return err
	}
	if respBody != nil {
		require.NoError(env.t, json.Unmarshal(rec.Body.Bytes(), respBody))
	}
	return nil
}

func (env *tkaTestEnv) genesis() tka.AUM {
	env.t.Helper()
	state := tka.State{
		Keys:               []tka.Key{{Kind: tka.Key25519, Votes: 2, Public: env.nlPriv.Public().Verifier()}},
		DisablementSecrets: [][]byte{tka.DisablementKDF(env.disablementSecret)},
	}
	_, genesis, err := tka.Create(&tka.Mem{}, state, env.nlPriv)
	require.NoError(env.t, err)
	return genesis
}

func signNodeKeyInfo(t *testing.T, info tailcfg.TKASignInfo, signer key.NLPrivate) tkatype.MarshaledSignature {
	t.Helper()
	p, err := info.NodePublic.MarshalBinary()
	require.NoError(t, err)
	sig := tka.NodeKeySignature{
		SigKind:        tka.SigDirect,
		KeyID:          signer.KeyID(),
		Pubkey:         p,
		WrappingPubkey: info.RotationPubkey,
	}
	sig.Signature, err = signer.SignNKS(sig.SigHash())
	require.NoError(t, err)
	return sig.Serialize()
}

// initLock walks the full init/begin + init/finish flow as the client does.
func (env *tkaTestEnv) initLock(nodePriv key.NodePrivate, handlers *TKAHandlers) tka.AUM {
	env.t.Helper()
	genesis := env.genesis()

	var beginResp tailcfg.TKAInitBeginResponse
	require.NoError(env.t, env.call(handlers.InitBegin, &tailcfg.TKAInitBeginRequest{
		NodeKey:    nodePriv.Public(),
		GenesisAUM: genesis.Serialize(),
	}, &beginResp))

	signatures := make(map[tailcfg.NodeID]tkatype.MarshaledSignature)
	for _, info := range beginResp.NeedSignatures {
		signatures[info.NodeID] = signNodeKeyInfo(env.t, info, env.nlPriv)
	}

	require.NoError(env.t, env.call(handlers.InitFinish, &tailcfg.TKAInitFinishRequest{
		NodeKey:    nodePriv.Public(),
		Signatures: signatures,
	}, &tailcfg.TKAInitFinishResponse{}))

	return genesis
}

func TestTKAInitFlow(t *testing.T) {
	env := newTKATestEnv(t)
	ctx := context.Background()

	m1, node1, h1 := env.newMachine("one")
	m2, _, _ := env.newMachine("two")

	env.initLock(node1, h1)

	state, err := env.repo.GetTailnetTKAState(ctx, env.tailnet.ID)
	require.NoError(t, err)
	assert.True(t, state.Enabled)
	assert.NotEmpty(t, state.Head)
	assert.Empty(t, state.PendingGenesis)

	for _, id := range []uint64{m1.ID, m2.ID} {
		m, err := env.repo.GetMachine(ctx, id)
		require.NoError(t, err)
		assert.NotEmpty(t, m.KeySignature, "machine %d must be signed after init", id)
	}

	// the authority reopens from the database
	authority, err := tka.Open(env.repo.TKAChonk(ctx, env.tailnet.ID))
	require.NoError(t, err)
	text, err := authority.Head().MarshalText()
	require.NoError(t, err)
	assert.Equal(t, state.Head, string(text))
}

func TestTKAInitFinishRefusesMissingSignatures(t *testing.T) {
	env := newTKATestEnv(t)

	_, node1, h1 := env.newMachine("one")
	env.newMachine("two")

	genesis := env.genesis()

	var beginResp tailcfg.TKAInitBeginResponse
	require.NoError(t, env.call(h1.InitBegin, &tailcfg.TKAInitBeginRequest{
		NodeKey:    node1.Public(),
		GenesisAUM: genesis.Serialize(),
	}, &beginResp))
	require.Len(t, beginResp.NeedSignatures, 2)

	// sign only the first node: enabling now would lock out the second
	signatures := map[tailcfg.NodeID]tkatype.MarshaledSignature{
		beginResp.NeedSignatures[0].NodeID: signNodeKeyInfo(t, beginResp.NeedSignatures[0], env.nlPriv),
	}

	err := env.call(h1.InitFinish, &tailcfg.TKAInitFinishRequest{
		NodeKey:    node1.Public(),
		Signatures: signatures,
	}, nil)
	require.Error(t, err)

	state, err := env.repo.GetTailnetTKAState(context.Background(), env.tailnet.ID)
	require.NoError(t, err)
	assert.False(t, state.Enabled)
}

func TestTKAInitRefusedWithoutFeatureFlag(t *testing.T) {
	env := newTKATestEnv(t)
	ctx := context.Background()

	env.tailnet.TailnetLockEnabled = false
	require.NoError(t, env.repo.SaveTailnet(ctx, env.tailnet))

	_, node1, h1 := env.newMachine("one")

	genesis := env.genesis()
	err := env.call(h1.InitBegin, &tailcfg.TKAInitBeginRequest{
		NodeKey:    node1.Public(),
		GenesisAUM: genesis.Serialize(),
	}, nil)
	require.Error(t, err)
}

func TestTKASyncAndInteractiveSend(t *testing.T) {
	env := newTKATestEnv(t)

	_, node1, h1 := env.newMachine("one")
	genesis := env.initLock(node1, h1)

	// simulate the client's local authority, bootstrapped from genesis
	clientChonk := &tka.Mem{}
	clientAuthority, err := tka.Bootstrap(clientChonk, genesis)
	require.NoError(t, err)

	// offer: heads are in sync right after init
	clientOffer, err := clientAuthority.SyncOffer(clientChonk)
	require.NoError(t, err)
	offerReq := &tailcfg.TKASyncOfferRequest{NodeKey: node1.Public(), Head: marshalAUMHash(clientOffer.Head)}
	for _, a := range clientOffer.Ancestors {
		offerReq.Ancestors = append(offerReq.Ancestors, marshalAUMHash(a))
	}
	var offerResp tailcfg.TKASyncOfferResponse
	require.NoError(t, env.call(h1.SyncOffer, offerReq, &offerResp))
	assert.Equal(t, marshalAUMHash(clientAuthority.Head()), offerResp.Head)
	assert.Empty(t, offerResp.MissingAUMs)

	// interactive send: `tailscale lock add` — client builds AUMs locally
	// and control's response head must equal the last submitted AUM hash
	otherKey := key.NewNLPrivate()
	builder := clientAuthority.NewUpdater(env.nlPriv)
	require.NoError(t, builder.AddKey(tka.Key{Kind: tka.Key25519, Votes: 1, Public: otherKey.Public().Verifier()}))
	aums, err := builder.Finalize(clientChonk)
	require.NoError(t, err)
	require.NoError(t, clientAuthority.Inform(clientChonk, aums))

	sendReq := &tailcfg.TKASyncSendRequest{
		NodeKey:     node1.Public(),
		Head:        marshalAUMHash(clientAuthority.Head()),
		Interactive: true,
	}
	for i := range aums {
		sendReq.MissingAUMs = append(sendReq.MissingAUMs, aums[i].Serialize())
	}
	var sendResp tailcfg.TKASyncSendResponse
	require.NoError(t, env.call(h1.SyncSend, sendReq, &sendResp))
	assert.Equal(t, marshalAUMHash(aums[len(aums)-1].Hash()), sendResp.Head)

	// control state advanced and persisted
	state, err := env.repo.GetTailnetTKAState(context.Background(), env.tailnet.ID)
	require.NoError(t, err)
	assert.Equal(t, sendResp.Head, state.Head)
}

func TestTKASubmitSignature(t *testing.T) {
	env := newTKATestEnv(t)
	ctx := context.Background()

	_, node1, h1 := env.newMachine("one")
	env.initLock(node1, h1)

	// a new, unsigned machine joins after the lock is enabled
	m3, node3, _ := env.newMachine("three")
	m3.KeySignature = nil
	require.NoError(t, env.repo.SaveMachine(ctx, m3))

	p, err := node3.Public().MarshalBinary()
	require.NoError(t, err)
	sig := tka.NodeKeySignature{SigKind: tka.SigDirect, KeyID: env.nlPriv.KeyID(), Pubkey: p}
	sig.Signature, err = env.nlPriv.SignNKS(sig.SigHash())
	require.NoError(t, err)

	require.NoError(t, env.call(h1.SubmitSignature, &tailcfg.TKASubmitSignatureRequest{
		NodeKey:   node1.Public(),
		Signature: sig.Serialize(),
	}, &tailcfg.TKASubmitSignatureResponse{}))

	updated, err := env.repo.GetMachine(ctx, m3.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, updated.KeySignature)

	// a signature from an untrusted key is refused
	rogue := key.NewNLPrivate()
	rogueSig := tka.NodeKeySignature{SigKind: tka.SigDirect, KeyID: rogue.KeyID(), Pubkey: p}
	rogueSig.Signature, err = rogue.SignNKS(rogueSig.SigHash())
	require.NoError(t, err)
	err = env.call(h1.SubmitSignature, &tailcfg.TKASubmitSignatureRequest{
		NodeKey:   node1.Public(),
		Signature: rogueSig.Serialize(),
	}, nil)
	require.Error(t, err)
}

func TestTKABootstrapAndDisable(t *testing.T) {
	env := newTKATestEnv(t)
	ctx := context.Background()

	_, node1, h1 := env.newMachine("one")
	genesis := env.initLock(node1, h1)

	// bootstrap serves the genesis AUM while enabled
	var bsResp tailcfg.TKABootstrapResponse
	require.NoError(t, env.call(h1.Bootstrap, &tailcfg.TKABootstrapRequest{NodeKey: node1.Public()}, &bsResp))
	assert.Equal(t, []byte(genesis.Serialize()), []byte(bsResp.GenesisAUM))

	// wrong disablement secret is refused
	err := env.call(h1.Disable, &tailcfg.TKADisableRequest{
		NodeKey:           node1.Public(),
		DisablementSecret: []byte("wrong-secret-wrong-secret-wrong!"),
	}, nil)
	require.Error(t, err)

	// correct secret disables the authority
	require.NoError(t, env.call(h1.Disable, &tailcfg.TKADisableRequest{
		NodeKey:           node1.Public(),
		DisablementSecret: env.disablementSecret,
	}, &tailcfg.TKADisableResponse{}))

	state, err := env.repo.GetTailnetTKAState(ctx, env.tailnet.ID)
	require.NoError(t, err)
	assert.False(t, state.Enabled)
	assert.True(t, state.Disabled)

	// bootstrap now serves the disablement secret
	var bsResp2 tailcfg.TKABootstrapResponse
	require.NoError(t, env.call(h1.Bootstrap, &tailcfg.TKABootstrapRequest{NodeKey: node1.Public()}, &bsResp2))
	assert.Equal(t, env.disablementSecret, bsResp2.DisablementSecret)

	// and the lock can be re-initialized afterwards
	env.initLock(node1, h1)
	state, err = env.repo.GetTailnetTKAState(ctx, env.tailnet.ID)
	require.NoError(t, err)
	assert.True(t, state.Enabled)
	assert.False(t, state.Disabled)
}
