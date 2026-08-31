package migration

import (
	"time"

	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func m202608312000_tailnet_lock() *gormigrate.Migration {
	return &gormigrate.Migration{
		ID: "202608312000",
		Migrate: func(db *gorm.DB) error {
			type Tailnet struct {
				TailnetLockEnabled bool
			}

			type Machine struct {
				NLKey        string
				KeySignature []byte
			}

			type TKAAum struct {
				TailnetID uint64 `gorm:"primaryKey;autoIncrement:false"`
				Hash      string `gorm:"primaryKey"`
				PrevHash  string `gorm:"index"`
				Data      []byte
				CreatedAt time.Time
			}

			type TailnetTKAState struct {
				TailnetID          uint64 `gorm:"primaryKey;autoIncrement:false"`
				Enabled            bool
				Disabled           bool
				Head               string
				LastActiveAncestor string
				PendingGenesis     []byte
				DisablementSecret  []byte
				SupportDisablement []byte
				UpdatedAt          time.Time
			}

			return db.AutoMigrate(
				&Tailnet{},
				&Machine{},
				&TKAAum{},
				&TailnetTKAState{},
			)
		},
		Rollback: nil,
	}
}
