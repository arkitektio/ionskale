package domain

import (
	"context"
	"errors"
	"os"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"tailscale.com/tka"
)

// TKAAum stores one Authority Update Message of a tailnet's key authority
// chain. The hash and previous-hash are stored in their AUMHash.MarshalText
// form; Data holds the CBOR serialization (tka.AUM.Serialize).
type TKAAum struct {
	TailnetID uint64 `gorm:"primaryKey;autoIncrement:false"`
	Hash      string `gorm:"primaryKey"`
	PrevHash  string `gorm:"index"`
	Data      []byte
	CreatedAt time.Time
}

// TailnetTKAState tracks the tailnet-lock lifecycle of one tailnet.
//
// Enabled means the key authority is active: map responses carry TKAInfo and
// clients enforce node-key signatures. Disabled means the authority existed
// and was shut down with a disablement secret; clients still running the
// authority are told to fetch the secret and disable themselves.
type TailnetTKAState struct {
	TailnetID          uint64 `gorm:"primaryKey;autoIncrement:false"`
	Enabled            bool
	Disabled           bool
	Head               string
	LastActiveAncestor string
	// PendingGenesis holds the serialized genesis AUM between the
	// /tka/init/begin and /tka/init/finish RPCs.
	PendingGenesis []byte
	// DisablementSecret is the secret that disabled the authority, served to
	// clients via /tka/bootstrap so they can verify and disable locally.
	DisablementSecret []byte
	// SupportDisablement is an optional extra disablement secret submitted at
	// init/finish (tailscale lock init --gen-disablement-for-support).
	SupportDisablement []byte
	UpdatedAt          time.Time
}

type TKARepository interface {
	GetTailnetTKAState(ctx context.Context, tailnetID uint64) (*TailnetTKAState, error)
	SaveTailnetTKAState(ctx context.Context, state *TailnetTKAState) error
	DeleteTKAByTailnet(ctx context.Context, tailnetID uint64) error
	ListMachineKeySignaturesByTailnet(ctx context.Context, tailnetID uint64) ([][]byte, error)
	TKAChonk(ctx context.Context, tailnetID uint64) tka.Chonk
}

func (r *repository) GetTailnetTKAState(ctx context.Context, tailnetID uint64) (*TailnetTKAState, error) {
	var state TailnetTKAState
	tx := r.withContext(ctx).Take(&state, "tailnet_id = ?", tailnetID)

	if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
		return &TailnetTKAState{TailnetID: tailnetID}, nil
	}

	if tx.Error != nil {
		return nil, tx.Error
	}

	return &state, nil
}

func (r *repository) SaveTailnetTKAState(ctx context.Context, state *TailnetTKAState) error {
	return r.withContext(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(state).Error
}

func (r *repository) DeleteTKAByTailnet(ctx context.Context, tailnetID uint64) error {
	if err := r.withContext(ctx).Where("tailnet_id = ?", tailnetID).Delete(&TKAAum{}).Error; err != nil {
		return err
	}
	return r.withContext(ctx).Where("tailnet_id = ?", tailnetID).Delete(&TailnetTKAState{}).Error
}

func (r *repository) ListMachineKeySignaturesByTailnet(ctx context.Context, tailnetID uint64) ([][]byte, error) {
	var signatures [][]byte
	tx := r.withContext(ctx).
		Model(&Machine{}).
		Where("tailnet_id = ? AND key_signature IS NOT NULL AND length(key_signature) > 0", tailnetID).
		Pluck("key_signature", &signatures)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return signatures, nil
}

// TKAChonk returns a tka.Chonk backed by the tka_aums table, scoped to one
// tailnet. Thread-safety is provided by the database.
func (r *repository) TKAChonk(ctx context.Context, tailnetID uint64) tka.Chonk {
	return &tkaChonk{ctx: ctx, repository: r, tailnetID: tailnetID}
}

type tkaChonk struct {
	ctx        context.Context
	repository *repository
	tailnetID  uint64
}

func hashToString(h tka.AUMHash) string {
	text, err := h.MarshalText()
	if err != nil {
		// MarshalText on an AUMHash cannot fail.
		panic(err)
	}
	return string(text)
}

func (c *tkaChonk) AUM(hash tka.AUMHash) (tka.AUM, error) {
	var row TKAAum
	tx := c.repository.withContext(c.ctx).Take(&row, "tailnet_id = ? AND hash = ?", c.tailnetID, hashToString(hash))
	if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
		return tka.AUM{}, os.ErrNotExist
	}
	if tx.Error != nil {
		return tka.AUM{}, tx.Error
	}
	var aum tka.AUM
	if err := aum.Unserialize(row.Data); err != nil {
		return tka.AUM{}, err
	}
	return aum, nil
}

func (c *tkaChonk) ChildAUMs(prevAUMHash tka.AUMHash) ([]tka.AUM, error) {
	var rows []TKAAum
	tx := c.repository.withContext(c.ctx).Find(&rows, "tailnet_id = ? AND prev_hash = ?", c.tailnetID, hashToString(prevAUMHash))
	if tx.Error != nil {
		return nil, tx.Error
	}
	return decodeAUMs(rows)
}

func (c *tkaChonk) CommitVerifiedAUMs(updates []tka.AUM) error {
	if len(updates) == 0 {
		return nil
	}
	rows := make([]TKAAum, 0, len(updates))
	now := time.Now().UTC()
	for _, aum := range updates {
		var prevHash string
		if parent, ok := aum.Parent(); ok {
			prevHash = hashToString(parent)
		}
		rows = append(rows, TKAAum{
			TailnetID: c.tailnetID,
			Hash:      hashToString(aum.Hash()),
			PrevHash:  prevHash,
			Data:      aum.Serialize(),
			CreatedAt: now,
		})
	}
	return c.repository.withContext(c.ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error
}

func (c *tkaChonk) Heads() ([]tka.AUM, error) {
	var rows []TKAAum
	tx := c.repository.withContext(c.ctx).
		Where("tailnet_id = ?", c.tailnetID).
		Where("hash NOT IN (?)", c.repository.withContext(c.ctx).
			Model(&TKAAum{}).
			Select("prev_hash").
			Where("tailnet_id = ? AND prev_hash != ''", c.tailnetID)).
		Find(&rows)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return decodeAUMs(rows)
}

func (c *tkaChonk) SetLastActiveAncestor(hash tka.AUMHash) error {
	state, err := c.repository.GetTailnetTKAState(c.ctx, c.tailnetID)
	if err != nil {
		return err
	}
	state.LastActiveAncestor = hashToString(hash)
	return c.repository.SaveTailnetTKAState(c.ctx, state)
}

func (c *tkaChonk) LastActiveAncestor() (*tka.AUMHash, error) {
	state, err := c.repository.GetTailnetTKAState(c.ctx, c.tailnetID)
	if err != nil {
		return nil, err
	}
	if state.LastActiveAncestor == "" {
		return nil, nil
	}
	var hash tka.AUMHash
	if err := hash.UnmarshalText([]byte(state.LastActiveAncestor)); err != nil {
		return nil, err
	}
	return &hash, nil
}

func decodeAUMs(rows []TKAAum) ([]tka.AUM, error) {
	var aums []tka.AUM
	for _, row := range rows {
		var aum tka.AUM
		if err := aum.Unserialize(row.Data); err != nil {
			return nil, err
		}
		aums = append(aums, aum)
	}
	return aums, nil
}
