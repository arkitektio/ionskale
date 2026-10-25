package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jsiebens/ionscale/internal/config"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	tkey "tailscale.com/types/key"
)

// A page on another origin (a browser client) may read the public keys.
func TestKeyAllowsAnyOrigin(t *testing.T) {
	e := echo.New()
	e.GET("/key", KeyHandler(&config.ServerKeys{
		ControlKey:       tkey.NewMachine(),
		LegacyControlKey: tkey.NewMachine(),
	}))
	req := httptest.NewRequest(http.MethodGet, "/key?v=142", nil)
	req.Header.Set("Origin", "https://app.example")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, rec.Body.String(), "publicKey")
}
