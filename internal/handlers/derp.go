package handlers

import (
	"bufio"
	"fmt"
	"github.com/coder/websocket"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"net/http"
	"strings"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/wsconn"
	"tailscale.com/types/key"
)

func NewDERPHandler() *DERPHandlers {
	logger := zap.L().Named("derp")
	return &DERPHandlers{
		s: derp.NewServer(key.NewNode(), func(format string, args ...any) {
			logger.Debug(fmt.Sprintf(format, args...))
		}),
	}
}

type DERPHandlers struct {
	s *derp.Server
}

func (h *DERPHandlers) Handler(c echo.Context) error {
	w, r := c.Response(), c.Request()
	if isDERPWebSocket(r) {
		h.serveWebSocket(w, r)
		return nil
	}
	derphttp.Handler(h.s).ServeHTTP(w, r)
	return nil
}

// isDERPWebSocket tells a WebSocket client (a browser) from the HTTP
// upgrade: early Tailscale versions sent "Upgrade: WebSocket" but spoke
// DERP's own framing, so the "derp" subprotocol decides.
func isDERPWebSocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(r.Header.Get("Sec-Websocket-Protocol"), "derp")
}

// serveWebSocket is DERP over WebSocket, as tailscale's derper serves it
// (cmd/derper/websocket.go, BSD-3-Clause, Tailscale Inc & AUTHORS). It
// returns when the connection ends: the connection lives as long as the
// request's context.
func (h *DERPHandlers) serveWebSocket(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:   []string{"derp"},
		OriginPatterns: []string{"*"},
		// WireGuard messages do not compress (and Safari's compression is broken).
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		zap.L().Named("derp").Debug("websocket accept failed", zap.Error(err))
		return
	}
	defer c.Close(websocket.StatusInternalError, "closing")
	if c.Subprotocol() != "derp" {
		c.Close(websocket.StatusPolicyViolation, "client must speak the derp subprotocol")
		return
	}
	wc := wsconn.NetConn(r.Context(), c, websocket.MessageBinary, r.RemoteAddr)
	brw := bufio.NewReadWriter(bufio.NewReader(wc), bufio.NewWriter(wc))
	h.s.Accept(r.Context(), wc, brw, r.RemoteAddr)
}

func (h *DERPHandlers) LatencyCheck(c echo.Context) error {
	return c.String(http.StatusOK, "")
}

func (h *DERPHandlers) DebugTraffic(c echo.Context) error {
	h.s.ServeDebugTraffic(c.Response(), c.Request())
	return nil
}

func (h *DERPHandlers) DebugCheck(c echo.Context) error {
	if err := h.s.ConsistencyCheck(); err != nil {
		return err
	}

	return c.String(http.StatusOK, "DERP Server ConsistencyCheck okay")
}
