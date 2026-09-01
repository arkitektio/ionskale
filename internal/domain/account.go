package domain

import (
	"context"
	"errors"
	"github.com/jsiebens/ionscale/internal/util"
	"gorm.io/gorm"
	"time"
)

type AccountRepository interface {
	GetAccount(ctx context.Context, accountID uint64) (*Account, error)
	GetAccountByExternalID(ctx context.Context, externalID string) (*Account, error)
	GetOrCreateAccount(ctx context.Context, externalID, loginName string) (*Account, bool, error)
	SetAccountLastAuthenticated(ctx context.Context, accountID uint64) error
}

type Account struct {
	ID         uint64 `gorm:"primary_key"`
	ExternalID string
	LoginName  string
}

func (r *repository) GetOrCreateAccount(ctx context.Context, externalID, loginName string) (*Account, bool, error) {
	account := &Account{}
	id := util.NextID()

	tx := r.withContext(ctx).
		Where(Account{ExternalID: externalID}).
		Attrs(Account{ID: id, LoginName: loginName}).
		FirstOrCreate(account)

	if tx.Error != nil {
		return nil, false, tx.Error
	}

	created := account.ID == id

	// The login name is a label the identity provider owns, so it can change
	// between logins -- a renamed user, or a claim that only became available
	// later. Attrs above applies on insert only, so an existing account would
	// otherwise keep its first-ever label forever.
	if !created && loginName != "" && account.LoginName != loginName {
		if err := r.withContext(ctx).Model(account).Update("login_name", loginName).Error; err != nil {
			return nil, false, err
		}
		account.LoginName = loginName
	}

	return account, created, nil
}

func (r *repository) GetAccount(ctx context.Context, id uint64) (*Account, error) {
	var account Account
	tx := r.withContext(ctx).Take(&account, "id = ?", id)

	if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if tx.Error != nil {
		return nil, tx.Error
	}

	return &account, nil
}

func (r *repository) GetAccountByExternalID(ctx context.Context, externalID string) (*Account, error) {
	var account Account
	tx := r.withContext(ctx).Take(&account, "external_id = ?", externalID)

	if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if tx.Error != nil {
		return nil, tx.Error
	}

	return &account, nil
}

func (r *repository) SetAccountLastAuthenticated(ctx context.Context, accountID uint64) error {
	now := time.Now().UTC()
	tx := r.withContext(ctx).
		Model(Account{}).
		Where("id = ?", accountID).
		Updates(map[string]interface{}{"last_authenticated": &now})

	if tx.Error != nil {
		return tx.Error
	}

	return nil
}
