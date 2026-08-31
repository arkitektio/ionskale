package database_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jsiebens/ionscale/internal/config"
	"github.com/jsiebens/ionscale/internal/database"
	"github.com/jsiebens/ionscale/internal/domain"
	"github.com/jsiebens/ionscale/internal/util"
	"go.uber.org/zap"
)

func TestMigrateAndOrgQuery(t *testing.T) {
	util.EnsureIDProvider()
	dir := t.TempDir()
	cfg := &config.Database{Type: "sqlite", Url: filepath.Join(dir, "test.db") + "?_pragma=foreign_keys(ON)"}
	_, repo, err := database.OpenDB(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tn := &domain.Tailnet{ID: util.NextID(), Name: "orgnet", Organization: "42", IAMPolicy: domain.NewHuJSON(&domain.IAMPolicy{})}
	if err := repo.SaveTailnet(ctx, tn); err != nil {
		t.Fatal(err)
	}
	got, err := repo.ListTailnetsByOrganization(ctx, "42")
	if err != nil || len(got) != 1 || got[0].Name != "orgnet" {
		t.Fatalf("org query failed: %v %v", got, err)
	}
	none, err := repo.ListTailnetsByOrganization(ctx, "7")
	if err != nil || len(none) != 0 {
		t.Fatalf("expected empty, got %v %v", none, err)
	}
}
