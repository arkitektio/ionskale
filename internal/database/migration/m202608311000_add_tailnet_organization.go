package migration

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func m202608311000_add_tailnet_organization() *gormigrate.Migration {
	return &gormigrate.Migration{
		ID: "202608311000",
		Migrate: func(db *gorm.DB) error {
			type Tailnet struct {
				Organization string `gorm:"index"`
			}

			return db.AutoMigrate(&Tailnet{})
		},
		Rollback: nil,
	}
}
