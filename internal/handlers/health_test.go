package handlers

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/jsiebens/ionscale/internal/config"
	"github.com/jsiebens/ionscale/internal/database"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestHealth(t *testing.T) {
	cfg := &config.Database{Type: "sqlite", Url: filepath.Join(t.TempDir(), "test.db")}
	db, _, err := database.OpenDB(cfg, zap.NewNop())
	require.NoError(t, err)

	e := echo.New()
	e.GET("/healthz", Health(db))

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())

	// a database that cannot be reached is reported as unavailable
	require.NoError(t, db.Close())
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHttpsRedirectSkipsHealth(t *testing.T) {
	skipper := httpsRedirectSkipper(config.Tls{ForceHttps: true})

	e := echo.New()
	probe := e.NewContext(httptest.NewRequest(http.MethodGet, "/healthz", nil), httptest.NewRecorder())
	assert.True(t, skipper(probe))

	other := e.NewContext(httptest.NewRequest(http.MethodGet, "/version", nil), httptest.NewRecorder())
	assert.False(t, skipper(other))
}
