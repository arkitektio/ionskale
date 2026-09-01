package migration

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Accounts become organization-scoped: the identity provider's subject is no
// longer unique on its own, since the same human can be a member of several
// organizations and each membership is its own identity.
//
// Existing accounts predate the column, so their organization is recovered from
// the tailnets their users already belong to. That is unambiguous as long as an
// account's users all sit in tailnets of one organization, which is what the
// one-tailnet-per-organization rule guarantees. An account that somehow spans
// two is left empty and logged rather than guessed at -- picking one would
// silently strand the user's other tailnet.
func m202609011200_account_organization() *gormigrate.Migration {
	return &gormigrate.Migration{
		ID: "202609011200",
		Migrate: func(db *gorm.DB) error {
			type Account struct {
				Organization string
			}

			if err := db.AutoMigrate(&Account{}); err != nil {
				return err
			}

			type accountOrg struct {
				AccountID uint64
				Orgs      string
			}

			var rows []accountOrg
			// GROUP_CONCAT over DISTINCT organizations per account: one value
			// means unambiguous, more than one means we must not guess.
			if err := db.Raw(`
				SELECT u.account_id AS account_id,
				       GROUP_CONCAT(DISTINCT t.organization) AS orgs
				FROM users u
				JOIN tailnets t ON t.id = u.tailnet_id
				WHERE u.account_id IS NOT NULL
				GROUP BY u.account_id
			`).Scan(&rows).Error; err != nil {
				return err
			}

			for _, row := range rows {
				if row.Orgs == "" {
					continue
				}
				// GROUP_CONCAT separates with "," — its presence means the
				// account's users span more than one organization.
				if containsComma(row.Orgs) {
					zap.L().Warn("account spans multiple organizations; leaving its organization empty",
						zap.Uint64("account_id", row.AccountID),
						zap.String("organizations", row.Orgs))
					continue
				}
				if err := db.Exec(
					"UPDATE accounts SET organization = ? WHERE id = ?", row.Orgs, row.AccountID,
				).Error; err != nil {
					return err
				}
			}

			return nil
		},
		Rollback: func(db *gorm.DB) error {
			return db.Migrator().DropColumn(&struct {
				Organization string
			}{}, "organization")
		},
	}
}

func containsComma(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			return true
		}
	}
	return false
}
