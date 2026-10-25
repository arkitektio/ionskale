package handlers

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"tailscale.com/derp"
	"tailscale.com/types/key"
)

// DERP over WebSocket (what a browser uses): two clients joined that way
// relay a packet, after a pause, both ways.
func TestDERPOverWebSocket(t *testing.T) {
	h := NewDERPHandler()
	e := echo.New()
	e.GET("/derp", h.Handler)
	srv := httptest.NewServer(h2c.NewHandler(e, &http2.Server{}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	join := func() (*derp.Client, key.NodePublic) {
		k := key.NewNode()
		ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/derp", &websocket.DialOptions{
			Subprotocols: []string{"derp"},
		})
		require.NoError(t, err)
		nc := websocket.NetConn(ctx, ws, websocket.MessageBinary)
		brw := bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc))
		c, err := derp.NewClient(k, nc, brw, t.Logf)
		require.NoError(t, err)
		return c, k.Public()
	}
	a, aKey := join()
	b, bKey := join()
	time.Sleep(50 * time.Millisecond)

	recv := func(c *derp.Client) derp.ReceivedPacket {
		for {
			m, err := c.Recv()
			require.NoError(t, err)
			if p, ok := m.(derp.ReceivedPacket); ok {
				return p
			}
		}
	}
	require.NoError(t, a.Send(bKey, []byte("to b")))
	p := recv(b)
	assert.Equal(t, aKey, p.Source)
	assert.Equal(t, "to b", string(p.Data))
	require.NoError(t, b.Send(aKey, []byte("to a")))
	p = recv(a)
	assert.Equal(t, bKey, p.Source)
	assert.Equal(t, "to a", string(p.Data))
}

// Without the subprotocol it is the HTTP upgrade's handler, as before.
func TestDERPWithoutTheSubprotocolIsNotWebSocket(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/derp", nil)
	r.Header.Set("Upgrade", "WebSocket")
	assert.False(t, isDERPWebSocket(r))
	r.Header.Set("Sec-Websocket-Protocol", "derp")
	assert.True(t, isDERPWebSocket(r))
}
