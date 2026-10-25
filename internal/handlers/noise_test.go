package handlers

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"tailscale.com/control/controlbase"
	"tailscale.com/types/key"
)

// The WebSocket form of the Noise upgrade (what a browser uses): every
// connection lasts, its HTTP/2 answered after a pause. Served like the
// HTTP upgrade, about one connection in seven was closed at the handover
// to HTTP/2, and all of them when the handler returned.
func TestNoiseUpgradeOverWebSocket(t *testing.T) {
	controlKey := key.NewMachine()
	h := NewNoiseHandlers(controlKey, func(peer key.MachinePublic) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, peer.String())
		})
	})
	e := echo.New()
	e.POST("/ts2021", h.Upgrade)
	e.GET("/ts2021", h.Upgrade)
	// As the server runs it: under h2c.
	srv := httptest.NewServer(h2c.NewHandler(e, &http2.Server{}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := 0; i < 50; i++ {
		machine := key.NewMachine()
		init, cont, err := controlbase.ClientDeferred(machine, controlKey.Public(), 106)
		require.NoError(t, err)

		u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ts2021?X-Tailscale-Handshake=" +
			url.QueryEscape(base64.StdEncoding.EncodeToString(init))
		ws, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{
			Subprotocols: []string{"tailscale-control-protocol"},
		})
		require.NoError(t, err, "connection %d", i)
		conn, err := cont(ctx, websocket.NetConn(ctx, ws, websocket.MessageBinary))
		require.NoError(t, err, "connection %d", i)

		client, err := (&http2.Transport{}).NewClientConn(conn)
		require.NoError(t, err, "connection %d", i)
		for j := 0; j < 2; j++ {
			time.Sleep(10 * time.Millisecond)
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://control/whoami", nil)
			resp, err := client.RoundTrip(req)
			require.NoError(t, err, "connection %d, request %d", i, j)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, machine.Public().String(), string(body))
		}
		_ = conn.Close()
	}
}
