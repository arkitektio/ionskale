package migration

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// The capability version a machine's client speaks, for its peers
// (tailcfg.Node.Cap). 0 until the machine has polled again.
func m202611181200_machine_cap_ver() *gormigrate.Migration {
	return &gormigrate.Migration{
		ID: "202611181200",
		Migrate: func(db *gorm.DB) error {
			type Machine struct {
				CapVer uint32
			}

			return db.AutoMigrate(&Machine{})
		},
		Rollback: nil,
	}
}
